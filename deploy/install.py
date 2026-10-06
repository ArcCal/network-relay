#!/usr/bin/env python3
"""Debian 12/13 deployment using only Python's standard library and system tools."""

import argparse
import base64
import copy
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import fcntl
import hmac
import getpass
import importlib.util
import json
import os
from pathlib import Path
import platform
import pwd
import plistlib
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import tomllib
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parent.parent
ETC = Path('/etc/network-relay')
CONFIG = ETC / 'relay.toml'
# What the installation was set up with: domain, port and user name. No secret.
STATE = ETC / 'install.json'
# Earlier versions kept the device profile here, password included, and
# read the installation's identity back from it.
LEGACY_PROFILE = ETC / 'device.mobileconfig'
BINARY = Path('/usr/local/bin/network-relay')
UNIT = Path('/etc/systemd/system/network-relay.service')
SYSCTL = Path('/etc/sysctl.d/99-network-relay.conf')
HOOK = Path('/etc/letsencrypt/renewal-hooks/deploy/network-relay')
# The relay runs as this user; it reads the configuration and the TLS key
# through its group.
SERVICE_USER = 'network-relay'
# Copies of certbot's certificate and key that the service user can read.
TLS = ETC / 'tls'
CERTS = Path('/etc/letsencrypt/live')
SITE = Path('/var/www/relay')
UDP_TEMPLATE = '/.well-known/masque/udp/{target_host}/{target_port}/'
# A fresh VPS often runs unattended-upgrades right after boot; wait for its
# dpkg lock instead of failing.
APT = ['apt-get', '-o', 'DPkg::Lock::Timeout=1800']
SUPPORTED_DEBIAN = ('12', '13')
PROFILE_NAME = 'Selected domains — everything else direct'
MAX_PROFILE_BYTES = 16 << 20
MAX_DEVICE_PROFILE_BYTES = 524288
PROFILE_SPEC = importlib.util.spec_from_file_location('relay_profile_rules', Path(__file__).with_name('global-profile.py'))
RULES = importlib.util.module_from_spec(PROFILE_SPEC)
PROFILE_SPEC.loader.exec_module(RULES)


@dataclass(frozen=True)
class Identity:
    domain: str
    port: int
    user: str
    # None for an installation whose password the installer never kept.
    password: str | None = field(repr=False)


def domain_name(value):
    value = value.removesuffix('.').lower()
    if (len(value) > 253 or '.' not in value
            or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                   for label in value.split('.'))):
        raise ValueError(f'Invalid domain name: {value!r}')
    try:
        import ipaddress
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('Use a domain name, not an IP address.')


def validate_identity(identity):
    domain_name(identity.domain)
    if not 1 <= identity.port <= 65535:
        raise ValueError('The port must be between 1 and 65535.')
    if not re.fullmatch(r'[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}', identity.user):
        raise ValueError('The user name may contain only letters, digits, underscores, dots and hyphens, '
                         'and must not start with a dot.')
    if identity.password is not None and (len(identity.password) < 12
                                          or any(ord(c) < 32 or ord(c) == 127 for c in identity.password)):
        raise ValueError('The password must be at least 12 characters and contain no control characters.')
    return identity


def load_domains(path):
    domains = []
    seen = set()
    with Path(path).open('rb') as stream:
        raw = stream.read((16 << 20) + 1)
    if len(raw) > 16 << 20:
        raise ValueError('The domain list is larger than 16 MiB.')
    for line in raw.decode('utf-8').splitlines():
        value = line.split('#', 1)[0].strip()
        if value:
            value = domain_name(value)
            if value not in seen:
                domains.append(value)
                seen.add(value)
    if not domains:
        raise ValueError('The domain list must not be empty; Apple treats an empty list as matching all traffic.')
    return domains


def read_profile(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(MAX_PROFILE_BYTES + 1)
    if len(raw) > MAX_PROFILE_BYTES:
        raise ValueError('The profile is larger than 16 MiB.')
    profile = plistlib.loads(raw)
    payloads = profile.get('PayloadContent', [])
    if len(payloads) != 1 or payloads[0].get('PayloadType') != 'com.apple.relay.managed':
        raise ValueError('Expected an unsigned mobileconfig with exactly one Network Relay payload.')
    payload = payloads[0]
    relays = payload.get('Relays', [])
    if len(relays) != 1:
        raise ValueError('The installer needs a profile with a single relay hop.')
    relay = relays[0]
    urls = [relay[key] for key in ('HTTP2RelayURL', 'HTTP3RelayURL') if key in relay]
    if not urls or len(set(urls)) != 1:
        raise ValueError('HTTP/2 and HTTP/3 must use the same relay URL.')
    url = urlsplit(urls[0])
    if (url.scheme != 'https' or url.username or url.password or url.query or url.fragment
            or url.path != UDP_TEMPLATE):
        raise ValueError("The profile must use HTTPS and the project's default CONNECT-UDP template.")
    if any(key in relay for key in ('PayloadCertificateUUID', 'RawPublicKeys')):
        raise ValueError('This installer uses a public CA and password authentication.')
    authorization = relay.get('AdditionalHTTPHeaderFields', {}).get('Authorization', '')
    scheme, _, value = authorization.partition(' ')
    if scheme.lower() != 'basic':
        raise ValueError('The profile has no Basic authorization header.')
    try:
        user, password = base64.b64decode(value, validate=True).decode().split(':', 1)
    except (ValueError, UnicodeError) as error:
        raise ValueError('The Basic credentials in the profile are invalid.') from error
    domains = payload.get('MatchDomains', [])
    if not isinstance(domains, list) or not domains:
        raise ValueError('The profile must have a non-empty MatchDomains, or it would relay all traffic.')
    for domain in domains:
        if '.' not in domain and RULES.LABEL.fullmatch(domain.lower()) and not domain.isdigit():
            continue  # Explicit top-level suffixes from a domain payload are valid matches.
        domain_name(domain)
    identity = validate_identity(Identity(domain_name(url.hostname or ''),
                                          443 if url.port is None else url.port, user, password))
    return identity, raw


def read_state(path):
    data = json.loads(Path(path).read_text())
    return validate_identity(Identity(domain_name(data['domain']), int(data['port']), str(data['user']), None))


def render_state(identity):
    return (json.dumps({'domain': identity.domain, 'port': identity.port, 'user': identity.user}, indent=2)
            + '\n').encode()


def service_ids():
    """User and group ID of the service account."""
    entry = pwd.getpwnam(SERVICE_USER)
    return entry.pw_uid, entry.pw_gid


def ensure_service_user():
    if run(['id', '-u', SERVICE_USER], capture=True, check=False).returncode:
        run(['useradd', '--system', '--user-group', '--no-create-home', '--home-dir', '/nonexistent',
             '--shell', '/usr/sbin/nologin', SERVICE_USER])


def require_readable(paths):
    """External certificate files must be readable by the service user."""
    for path in paths:
        if run(['runuser', '-u', SERVICE_USER, '--', 'test', '-r', path], check=False).returncode:
            raise ValueError(f'The relay runs as user {SERVICE_USER} and cannot read {path}. Let it read the file '
                             f'(for example: chgrp {SERVICE_USER} {path} && chmod g+r {path}, with the directories '
                             'above it searchable), then run the installer again.')


def certificate_updates(lineage):
    """Stages certbot's pair for validation and transactional installation;
    deploy/certbot-hook.sh updates the service-readable copies on renewal."""
    gid = service_ids()[1]
    TLS.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(TLS, 0 if os.geteuid() == 0 else -1, gid)
    os.chmod(TLS, 0o750)
    updates = {TLS / name: ((lineage / name).read_bytes(), 0o640, gid)
               for name in ('fullchain.pem', 'privkey.pem')}
    updates[TLS / 'source'] = (f'{lineage}\n'.encode(), 0o644, None)
    return updates


def retarget_tls(config_data, old, new):
    """Points [tls] of an installer-written configuration from `old` to `new`."""
    text = config_data.decode()
    current = tomllib.loads(text)['tls']
    if (Path(current['cert']), Path(current['key'])) != tuple(old):
        raise ValueError(f'Could not find the expected TLS paths in {CONFIG}.')
    # TOML permits either quote style and comments. A textual JSON-string
    # replacement rejected otherwise valid edited configurations on upgrade.
    in_tls, replaced, lines = False, set(), []
    for line in text.splitlines(keepends=True):
        if line.lstrip().startswith('['):
            try:
                in_tls = tomllib.loads(line) == {'tls': {}}
            except tomllib.TOMLDecodeError:
                in_tls = False
        match = re.match(r'''^(\s*)(cert|key|"cert"|"key"|'cert'|'key')\s*=''', line) if in_tls else None
        if match:
            key = match.group(2).strip('"\'')
            line = f'{match.group(1)}{key} = {json.dumps(str(new[0 if key == "cert" else 1]))}\n'
            replaced.add(key)
        lines.append(line)
    text = ''.join(lines)
    if replaced != {'cert', 'key'}:
        raise ValueError(f'Could not locate the TLS path assignments in {CONFIG}.')
    tls = tomllib.loads(text)['tls']
    if (Path(tls['cert']), Path(tls['key'])) != tuple(new):
        raise ValueError(f'Could not update [tls] in {CONFIG}.')
    return text.encode()


def reset_user_hash(config_data, user, password_hash):
    """Change only the named user's hash, preserving other users and hand edits."""
    original = tomllib.loads(config_data.decode())
    users = [entry for entry in original.get('user', []) if entry.get('name') == user]
    if len(users) != 1:
        raise ValueError(f'Expected exactly one configured user named {user!r}; refusing password reset.')
    lines = config_data.decode().splitlines(keepends=True)
    starts = []
    for index, line in enumerate(lines):
        if not line.lstrip().startswith('['):
            continue
        try:
            is_user = tomllib.loads(line) == {'user': [{}]}
        except tomllib.TOMLDecodeError:
            is_user = False
        starts.append((index, is_user))
    changed = False
    for offset, (start, is_user) in enumerate(starts):
        if not is_user:
            continue
        end = starts[offset + 1][0] if offset + 1 < len(starts) else len(lines)
        block = lines[start:end]
        if tomllib.loads(''.join(block))['user'][0].get('name') != user:
            continue
        replacement = f'password_hash = {json.dumps(password_hash)}\n'
        for index, line in enumerate(block):
            if re.match(r'''^\s*(password_hash|"password_hash"|'password_hash')\s*=''', line):
                block[index] = replacement
                break
        else:
            if block and not block[-1].endswith('\n'):
                block[-1] += '\n'
            block.append(replacement)
        lines[start:end] = block
        changed = True
        break
    result = ''.join(lines).encode()
    expected = copy.deepcopy(original)
    next(entry for entry in expected['user'] if entry.get('name') == user)['password_hash'] = password_hash
    if not changed or tomllib.loads(result.decode()) != expected:
        raise ValueError('Could not safely update the user password hash; no installed file was changed.')
    return result


def atomic_write(path, data, mode=0o600, group=None, owner=None):
    path = Path(path)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError(f'Refusing to overwrite a non-regular file: {path}')
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.network-relay-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            if group is not None or owner is not None:
                os.fchown(stream.fileno(), -1 if owner is None else owner, -1 if group is None else group)
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def run(args, *, capture=False, input=None, check=True, timeout=1800, env=None):
    return subprocess.run([str(arg) for arg in args], input=input, text=True, check=check,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None, timeout=timeout, env=env)


def render_config(identity, password_hash, cert, key, site=SITE):
    # JSON strings are valid TOML basic strings for these validated ASCII values.
    quote = json.dumps
    text = (f'listen = {quote(f"[::]:{identity.port}")}\n\n[tls]\n'
            f'cert = {quote(str(cert))}\nkey = {quote(str(key))}\n\n'
            f'[web]\nroot = {quote(str(site))}\n\n'
            '# Destination restrictions retain the program defaults.\n[relay]\n'
            f'udp_template = {quote(UDP_TEMPLATE)}\n\n[[user]]\n'
            f'name = {quote(identity.user)}\npassword_hash = {quote(password_hash)}\n')
    tomllib.loads(text)
    return text.encode()


def build_binary(args):
    if args.binary:
        binary = args.binary.resolve(strict=True)
        run([binary, '--version'])
        return binary
    if not (REPO / 'Cargo.lock').is_file():
        raise ValueError('Download and extract the complete source ZIP, or pass a built program with --binary.')
    env = os.environ.copy()
    # Keep caches out of the source ZIP and avoid modifying shell profiles.
    env['CARGO_HOME'] = '/var/cache/network-relay/cargo'
    env['RUSTUP_HOME'] = '/opt/network-relay/rustup'
    cargo_bin = Path(env['CARGO_HOME']) / 'bin'
    env['PATH'] = str(cargo_bin) + os.pathsep + env.get('PATH', '')
    rustup = cargo_bin / 'rustup'
    if not rustup.exists():
        with tempfile.TemporaryDirectory(prefix='network-relay-rust-') as directory:
            installer = Path(directory) / 'rustup-init.sh'
            run(['curl', '--proto', '=https', '--tlsv1.2', '--fail', '--show-error', '--location',
                 '--retry', '3', 'https://sh.rustup.rs', '--output', installer])
            run(['sh', installer, '-y', '--no-modify-path', '--profile', 'minimal',
                 '--default-toolchain', 'stable'], env=env)
    else:
        run([rustup, 'toolchain', 'install', 'stable', '--profile', 'minimal'], env=env)
    # Reduce peak build memory on small VPSes; this does not alter protocol behavior.
    env['CARGO_BUILD_JOBS'] = str(args.jobs)
    env['CARGO_PROFILE_RELEASE_LTO'] = 'false'
    env['CARGO_PROFILE_RELEASE_CODEGEN_UNITS'] = '8'
    env['CARGO_TARGET_DIR'] = '/var/cache/network-relay/target'
    run([cargo_bin / 'cargo', '+stable', 'build', '--locked', '--release', '--bins',
         '--manifest-path', REPO / 'Cargo.toml'], env=env, timeout=7200)
    return Path(env['CARGO_TARGET_DIR']) / 'release/network-relay'


def port_available(port, allowed_pid=0):
    for protocol in ('-ltnp', '-lunp'):
        listeners = run(['ss', '-H', protocol, f'sport = :{port}'], capture=True).stdout.splitlines()
        for listener in listeners:
            pids = re.findall(r'pid=(\d+)', listener)
            if not pids or any(int(pid) != allowed_pid for pid in pids):
                raise ValueError(f'Port {port} is already in use by another service; '
                                 f'the installer will not stop it: {listener}')


def preflight():
    if os.geteuid() != 0:
        raise ValueError('Run this installer as root.')
    os_release = platform.freedesktop_os_release()
    # Debian 12 has everything the installer needs too: Python 3.11
    # (tomllib), apt with DPkg::Lock::Timeout, certbot and systemd.
    if (os_release.get('ID') != 'debian' or os_release.get('VERSION_ID') not in SUPPORTED_DEBIAN
            or platform.machine() != 'x86_64'):
        raise ValueError('This installer supports only Debian 12/13 x86_64.')
    if not Path('/run/systemd/system').is_dir():
        raise ValueError('A VPS booted with systemd is required.')


def certificate_paths(args, identity, existing_config):
    """Returns (cert, key, automated, migrate_from) for this run.

    An automated certificate is certbot's, copied to TLS for the service
    user. An existing installation keeps the certificate it was set up with,
    so an upgrade without --cert/--key does not switch to certbot, and a
    different --cert/--key is refused rather than silently ignored. One that
    used certbot's files directly, as root, moves to the copies:
    `migrate_from` names the paths to replace in its configuration. Given
    paths are kept as given, not resolved: Let's Encrypt's live/ files are
    symlinks that move to the newest archive/ file on renewal.
    """
    automated = (TLS / 'fullchain.pem', TLS / 'privkey.pem')
    legacy = (CERTS / identity.domain / 'fullchain.pem', CERTS / identity.domain / 'privkey.pem')
    given = None
    if args.cert:
        given = tuple(Path(os.path.abspath(p)) for p in (args.cert, args.key))
        for path in given:
            if not path.is_file():
                raise ValueError(f'Certificate file not found: {path}')
    if existing_config is not None:
        tls = tomllib.loads(existing_config.decode())['tls']
        current = (Path(tls['cert']), Path(tls['key']))
        if given and given != current:
            raise ValueError(f'The existing installation uses {current[0]} and {current[1]}, not the given '
                             f'--cert/--key. To change the certificate, edit [tls] in {CONFIG}, run '
                             'systemctl restart network-relay, then run this installer without --cert/--key.')
        if current == legacy:
            return (*automated, True, legacy)
        return (*current, current == automated, None)
    if given:
        return (*given, False, None)
    return (*automated, True, None)


def install(args):
    preflight()
    if args.binary is None:
        return _install(args)
    if not args.binary.is_file():
        raise ValueError(f'Prebuilt program not found: {args.binary}. Upload the extracted Linux x86_64 '
                         'network-relay binary there, or use --binary /path/network-relay. '
                         'Source compilation requires explicit --build-from-source.')
    source = args.binary.resolve(strict=True)
    if args.profile_out and args.profile_out.resolve() == source:
        raise ValueError('The device profile must not overwrite the source binary.')
    # Uploads may lose executable permissions, and /tmp may be mounted noexec.
    # Use a private snapshot on the installation filesystem for every CLI step.
    BINARY.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.network-relay-install-', dir=BINARY.parent) as directory:
        binary = Path(directory) / 'network-relay'
        shutil.copyfile(source, binary)
        with binary.open('rb') as stream:
            header = stream.read(20)
        if (len(header) != 20 or header[:6] != b'\x7fELF\x02\x01'
                or int.from_bytes(header[18:20], 'little') != 62):
            raise ValueError('Expected an extracted Linux x86_64 ELF binary, not an archive or ARM build.')
        binary.chmod(0o700)
        staged = argparse.Namespace(**vars(args))
        staged.binary = binary
        return _install(staged)


def profile_domains(args, identity):
    domains = load_domains(args.domains or REPO / 'deploy/domains/google-ai-social.txt')
    for label, disabled, path, url, parse in (
        ('gfwlist', args.no_gfwlist, args.gfwlist_file, args.gfwlist_url,
         lambda text: RULES.extract_gfwlist(text)[0]),
    ):
        if disabled:
            continue
        print(f'Loading {label}: {path or url}', flush=True)
        if path:
            with path.open('rb') as stream:
                raw = RULES.read_bounded(stream)
        else:
            try:
                with RULES.urllib.request.urlopen(url, timeout=60) as stream:
                    raw = RULES.read_bounded(stream)
            except OSError as error:
                raise ValueError(f'Could not download {label}: {error}. No partial profile will be generated; '
                                 'retry or supply a downloaded list file.') from error
        text = RULES.decode_gfwlist(raw) if label == 'gfwlist' else raw.decode('utf-8')
        extracted = parse(text)
        if not extracted:
            raise ValueError(f'{label} contains no convertible domains; refusing a partial profile.')
        domains += extracted
        print(f'{label}: {len(extracted)} extracted domains.', flush=True)
        if label == 'gfwlist':
            for name, count in RULES.extract_gfwlist(text)[1].items():
                print(f'  {name}: {count}', flush=True)
    suffixes = (REPO / 'deploy/domains/public-suffix-icann.dat').read_text()
    domains = RULES.collapse([d for d in RULES.root_domains(domains, suffixes)
                             if d != identity.domain and d != 'adult' and not d.endswith('.adult')])
    if not domains:
        raise ValueError('No matched domains remain; refusing an all-traffic profile.')
    print(f'Combined routing list: {len(domains)} unique root domains; the relay domain is excluded.', flush=True)
    return domains


def refresh_credentials(identity):
    # A previous one-time delivery file may still exist. Reuse its secret without
    # printing it; otherwise ask locally, never reset the existing account.
    paths = list((SITE / '.publish').glob('*.mobileconfig'))
    private_profile = ETC / f'profile-{identity.user}.mobileconfig'
    if private_profile.is_file():
        paths.append(private_profile)
    for path in sorted(paths, key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            candidate = read_profile(path)[0]
        except (ValueError, OSError, plistlib.InvalidFileException):
            continue
        if (candidate.domain, candidate.port, candidate.user) == (identity.domain, identity.port, identity.user):
            print('Reusing credentials from the previous device profile.', flush=True)
            return candidate
    if not sys.stdin.isatty():
        raise ValueError('Profile refresh needs the existing password. Run interactively or pass '
                         '--profile /path/original.mobileconfig --refresh-profile.')
    return validate_identity(replace(identity, password=getpass.getpass('Existing relay password (unchanged): ')))


def verify_refresh_credentials(identity):
    # A local, verified-TLS CONNECT tests authentication without external targets.
    context = ssl.create_default_context()
    context.set_alpn_protocols(['http/1.1'])
    basic = base64.b64encode(f'{identity.user}:{identity.password}'.encode()).decode()
    with socket.create_connection(('127.0.0.1', identity.port), timeout=10) as connection:
        with context.wrap_socket(connection, server_hostname=identity.domain) as tls:
            tls.sendall(('CONNECT 127.0.0.1:25 HTTP/1.1\r\nHost: 127.0.0.1:25\r\n'
                         f'Authorization: Basic {basic}\r\n\r\n').encode())
            with tls.makefile('rb') as stream:
                status = stream.readline(1024).split()
    if len(status) < 2 or status[1] not in (b'200', b'403', b'502', b'504'):
        raise ValueError('The existing relay did not authenticate the supplied profile password; '
                         'no account or profile was changed. Ensure it is running and use its current password.')


def _install(args):
    existing = CONFIG.exists()
    if STATE.exists():
        installed = read_state(STATE)
    elif LEGACY_PROFILE.exists():
        installed = read_profile(LEGACY_PROFILE)[0]
    else:
        installed = None
    if existing and installed is None:
        raise ValueError('Found an existing manual installation; refusing to overwrite it. '
                         'Back it up and follow the update steps in docs/deploy-debian13.md.')
    if args.profile:
        identity = read_profile(args.profile)[0]
        if args.domain and domain_name(args.domain) != identity.domain:
            raise ValueError('--domain does not match the server domain in the profile.')
        if ((args.user is not None and args.user != identity.user)
                or (args.port is not None and args.port != identity.port)):
            raise ValueError('--user/--port do not match the profile.')
        if args.domains and not args.refresh_profile:
            raise ValueError('--profile already carries its domain rules; --domains cannot be used with it.')
    elif existing:
        identity = installed
        if ((args.domain and domain_name(args.domain) != identity.domain)
                or (args.user is not None and args.user != identity.user)
                or (args.port is not None and args.port != identity.port)):
            raise ValueError('The existing installation has a different domain, port or user name; '
                             'refusing to overwrite it.')
    else:
        domain = args.domain
        if not domain and sys.stdin.isatty():
            domain = input('Relay domain (must already resolve to this VPS): ').strip()
        identity = validate_identity(Identity(domain_name(domain or ''), 443 if args.port is None else args.port,
                                              args.user or 'iphone', secrets.token_urlsafe(24)))
    # A new account gets a profile for its devices; an upgrade leaves both alone.
    new_account = not existing
    generate_profile = (new_account and args.profile is None) or args.refresh_profile or args.reset_password
    if args.reset_password:
        identity = replace(identity, password=secrets.token_urlsafe(24))
    elif existing and generate_profile:
        if identity.password is None:
            identity = refresh_credentials(identity)
        verify_refresh_credentials(identity)
    if existing and (installed.domain, installed.port, installed.user) != (
            identity.domain, identity.port, identity.user):
        raise ValueError('The existing installation has a different domain, port or user name; '
                         'refusing to overwrite it.')
    if (existing and args.profile and installed.password is not None
            and not hmac.compare_digest(installed.password.encode(), identity.password.encode())):
        raise ValueError("The profile's password differs from the existing installation's; "
                         'the existing account will not be reset automatically.')
    cert, key, automated_cert, migrate_from = certificate_paths(args, identity,
                                                                CONFIG.read_bytes() if existing else None)
    if identity.port == 80 and automated_cert:
        raise ValueError('Automatic certificate renewal needs TCP 80 to itself; '
                         'choose another port for the relay (default 443).')

    print(f'Deploying {identity.domain}:{identity.port}, user {identity.user}; the password is not printed.',
          flush=True)
    print('Cloud firewall and DNS must be ready: TCP 80 and the relay port on TCP/UDP; '
          'Cloudflare set to DNS only.', flush=True)
    env = os.environ.copy()
    env['DEBIAN_FRONTEND'] = 'noninteractive'
    print('Waiting for any automatic system updates to finish first (up to 30 minutes).', flush=True)
    run(APT + ['update'], env=env)
    packages = ['curl', 'ca-certificates', 'certbot', 'iproute2', 'procps']
    if args.binary is None:
        packages += ['build-essential', 'pkg-config', 'git']
    run(APT + ['install', '-y', '--no-install-recommends'] + packages, env=env)
    domains = profile_domains(args, identity) if generate_profile else None
    ensure_service_user()
    if not automated_cert:
        require_readable((cert, key))
    main_pid = run(['systemctl', 'show', 'network-relay.service', '-p', 'MainPID', '--value'],
                   capture=True, check=False).stdout.strip()
    port_available(identity.port, int(main_pid or 0))
    try:
        addresses = socket.getaddrinfo(identity.domain, identity.port, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise ValueError('The relay domain does not resolve; '
                         'point its DNS A/AAAA records at this VPS first.') from error
    print('The domain currently resolves to: ' + ', '.join(sorted({item[4][0] for item in addresses})), flush=True)
    if shutil.which('ufw'):
        status = run(['ufw', 'status'], capture=True).stdout
        if re.search(r'^Status: active$', status, re.MULTILINE):
            for rule in ('80/tcp', f'{identity.port}/tcp', f'{identity.port}/udp'):
                run(['ufw', 'allow', rule])

    binary = build_binary(args)
    if automated_cert:
        port_available(80)
        command = ['certbot', 'certonly', '--standalone', '--non-interactive', '--agree-tos',
                   '--keep-until-expiring', '--cert-name', identity.domain, '-d', identity.domain]
        command += ['--email', args.email] if args.email else ['--register-unsafely-without-email']
        run(command, timeout=600)
        run(['systemctl', 'enable', '--now', 'certbot.timer'])

    uid, gid = service_ids()
    root = 0 if os.geteuid() == 0 else -1
    ETC.mkdir(mode=0o750, parents=True, exist_ok=True)
    # Readable by the service's group: the configuration and the TLS copies;
    # install.json and the backups stay root's.
    os.chown(ETC, root, gid)
    os.chmod(ETC, 0o750)
    certificates = certificate_updates(CERTS / identity.domain) if automated_cert else {}
    SITE.mkdir(mode=0o755, parents=True, exist_ok=True)
    if not (SITE / 'index.html').exists():
        atomic_write(SITE / 'index.html', b'<!doctype html><title>Welcome</title><h1>Welcome</h1>\n', 0o644)
    # One-time profile links: written by `profile --publish`, read by the relay.
    publish = SITE / '.publish'
    publish.mkdir(mode=0o700, exist_ok=True)
    os.chown(publish, uid, gid)
    with tempfile.TemporaryDirectory(prefix='.install-', dir=ETC) as directory:
        staging = Path(directory)
        if not existing or args.reset_password:
            # A generated password is a long random secret, which a fast
            # hash protects as well as a slow one does a chosen password,
            # and which then costs the server almost nothing to check.
            command = [binary, 'passwd', '--name', identity.user, '--stdin']
            if args.profile is None:
                command.append('--fast-hash')
            result = run(command, input=identity.password + '\n', capture=True)
            password_hash = tomllib.loads(result.stdout)['user'][0]['password_hash']
        if existing:
            config_data = CONFIG.read_bytes()
            if args.reset_password:
                config_data = reset_user_hash(config_data, identity.user, password_hash)
            if migrate_from:
                config_data = retarget_tls(config_data, migrate_from, (cert, key))
        else:
            config_data = render_config(identity, password_hash, cert, key, SITE)
        candidate = staging / 'relay.toml'
        validation_data = config_data
        if certificates:
            staged_cert, staged_key = staging / 'fullchain.pem', staging / 'privkey.pem'
            atomic_write(staged_cert, certificates[cert][0])
            atomic_write(staged_key, certificates[key][0])
            validation_data = retarget_tls(config_data, (cert, key), (staged_cert, staged_key))
        atomic_write(candidate, validation_data)
        run([binary, 'serve', '--config', candidate, '--check'])
        profile = None
        if generate_profile:
            # Generate before committing the account. A generation failure must
            # not leave a running account whose only password dies with us.
            command = [binary, 'profile', '--host', identity.domain, '--port', str(identity.port),
                       '--user', identity.user, '--name', PROFILE_NAME,
                       '--exclude-domain', identity.domain, '--ui-toggle-enabled', 'true',
                       '--match-domain', 'example.invalid']
            staged_profile = staging / 'device.mobileconfig'
            run(command + ['--out', staged_profile], input=identity.password + '\n', capture=True)
            data = RULES.profile_with_domains(staged_profile.read_bytes(), domains)
            if len(data) >= MAX_DEVICE_PROFILE_BYTES:
                raise ValueError(f'The single device profile is {len(data)} bytes, exceeding the iPhone '
                                 '524288-byte limit. No account or profile was changed.')
            profile_path = args.profile_out or publish / f'{secrets.token_urlsafe(18)}.mobileconfig'
            file_delivery = bool(args.profile_out)
            profile = (Path(os.path.abspath(profile_path)), data,
                       None if file_delivery else uid, None if file_delivery else gid)
        apply_install(binary, config_data, render_state(identity), identity, automated_cert=automated_cert,
                      profile=profile, certificates=certificates)

    print('\nInstallation complete.', flush=True)
    if args.reset_password and existing:
        print('The installer account now has a new random password. Other accounts are unchanged. '
              'Install the new device profile; previous profiles for this account no longer authenticate.', flush=True)
    if generate_profile:
        hand_over_profile(identity, profile[0], profile[2] is None)
    elif existing:
        print('The account and its devices are unchanged. To set up another device, see '
              '"Another device" in docs/deploy-debian13.md.', flush=True)
    if LEGACY_PROFILE.exists():
        print(f'An earlier version of this installer kept the device profile, password included, in '
              f'{LEGACY_PROFILE}. It is no longer used; once your devices have it, delete it: '
              f'rm {LEGACY_PROFILE}', flush=True)
    if identity.password is None:
        print('The installer does not keep the password, so it cannot test the relay with it. Test it with: '
              f'network-relay check --server {identity.domain} --port {identity.port} --user {identity.user}',
              flush=True)
        return 0
    print('Checking the TCP/UDP relay over all three HTTP versions from this machine; '
          'access from the internet still has to be confirmed from a device.', flush=True)
    result = run([BINARY, 'check', '--server', identity.domain, '--address', '127.0.0.1',
                  '--port', str(identity.port), '--user', identity.user],
                 input=identity.password + '\n', check=False, timeout=300)
    if result.returncode:
        print('The service is running, but the network self-check had failures. '
              'See the errors above and journalctl -u network-relay.', file=sys.stderr)
        return 2
    return 0


def hand_over_profile(identity, published, out):
    """Gives the new account's device profile to the administrator without
    leaving the password on the server: a link that works once, or a file
    where they asked for one."""
    if out:
        print(f'Device profile: {published} (contains the password, mode 600). Install it on the iPhone, iPad or '
              'Mac, then delete it.', flush=True)
        return
    port = '' if identity.port == 443 else f':{identity.port}'
    print('Within 15 minutes, open this link in Safari on the iPhone, iPad or Mac and install the profile. '
          'The link works once; the password is not stored anywhere else on this server:', flush=True)
    print(f'\n    https://{identity.domain}{port}/{published.name}\n', flush=True)
    print(f'If it expires, or for a Mac without Safari access, delete {published} and run the installer\'s '
          'profile step by hand: see "Another device" in docs/deploy-debian13.md.', flush=True)


def apply_install(binary, config_data, state_data, identity, *, automated_cert, profile=None, certificates=None):
    backup = ETC / 'backups' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    backup.mkdir(mode=0o700, parents=True)
    was_active = run(['systemctl', 'is-active', '--quiet', 'network-relay'], check=False).returncode == 0
    was_enabled = run(['systemctl', 'is-enabled', '--quiet', 'network-relay'], check=False).returncode == 0
    sysctl_values = []
    old_sysctl = {}
    for name in ('net.core.rmem_max', 'net.core.wmem_max'):
        current = run(['sysctl', '-n', name], capture=True, check=False).stdout.strip()
        if current:
            old_sysctl[name] = int(current)
        sysctl_values.append(f'{name} = {max(int(current or 0), 8388608)}\n')
    gid = service_ids()[1]
    updates = {
        BINARY: (binary.read_bytes(), 0o755, None),
        CONFIG: (config_data, 0o640, gid),
        STATE: (state_data, 0o600, None),
        UNIT: ((REPO / 'deploy/network-relay.service').read_bytes(), 0o644, None),
        SYSCTL: (''.join(sysctl_values).encode(), 0o644, None),
    }
    if automated_cert:
        updates[HOOK] = ((REPO / 'deploy/certbot-hook.sh').read_bytes(), 0o755, None)
    updates.update(certificates or {})
    if profile is not None:
        path, data, owner, group = profile
        if path in updates or path in (HOOK, LEGACY_PROFILE) or path == binary.resolve():
            raise ValueError('The device profile must not overwrite an installed service file or the source binary.')
        updates[path] = (data, 0o600, group)
    snapshots = {}
    metadata = {}
    for index, path in enumerate(updates):
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise ValueError(f'Refusing to replace a non-regular installed file: {path}')
        saved = backup / str(index)
        if path.exists():
            metadata[path] = path.stat()
            shutil.copy2(path, saved)
            snapshots[path] = saved
        else:
            snapshots[path] = None
    atomic_write(backup / 'manifest.json', json.dumps({str(k): str(v) if v else None for k, v in snapshots.items()},
                                                     indent=2).encode())
    try:
        for path, (data, mode, group) in updates.items():
            owner = profile[2] if profile is not None and path == profile[0] else None
            atomic_write(path, data, mode, group, owner)
        if run(['sysctl', '-p', SYSCTL], check=False).returncode:
            print('Could not raise the UDP buffer limits (some VPSes restrict sysctl); '
                  'keeping the current kernel settings.', file=sys.stderr)
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', 'network-relay'])
        run(['systemctl', 'restart', 'network-relay'])
        for attempt in range(20):
            # Any HTTP answer over TLS shows the relay is up; the website is
            # optional, so its status (404 without [web]) does not matter.
            result = run(['curl', '--silent', '--show-error', '--output', '/dev/null', '--max-time', '2',
                          '--noproxy', '*',
                          '--resolve', f'{identity.domain}:{identity.port}:127.0.0.1',
                          f'https://{identity.domain}:{identity.port}/'], capture=True, check=False)
            if result.returncode == 0:
                break
            time.sleep(.5)
        else:
            raise RuntimeError('Local HTTPS startup check failed; restoring the previous installation.')
        print(f'Service started; files from before the installation are backed up in {backup}', flush=True)
    except BaseException:
        run(['systemctl', 'stop', 'network-relay'], check=False)
        if not was_enabled:
            run(['systemctl', 'disable', 'network-relay'], check=False)
        for path, saved in snapshots.items():
            if saved:
                previous = metadata[path]
                atomic_write(path, saved.read_bytes(), previous.st_mode & 0o777, previous.st_gid, previous.st_uid)
            elif path.exists():
                path.unlink()
        for name, value in old_sysctl.items():
            run(['sysctl', '-w', f'{name}={value}'], check=False)
        run(['systemctl', 'daemon-reload'], check=False)
        if was_active:
            run(['systemctl', 'start', 'network-relay'], check=False)
        raise


def main():
    parser = argparse.ArgumentParser(description='Install or update Network Relay on Debian 12/13 x64 and hand '
                                                 'over a mobileconfig that relays selected domains.')
    parser.add_argument('--profile', type=Path, help='import the server address and credentials from an existing '
                        'mobileconfig; recommended when one was provided')
    parser.add_argument('--domain', help='relay domain; required without --profile, '
                        'asked for in the terminal if omitted')
    parser.add_argument('--email', help='Let’s Encrypt account email; '
                        'without it the account is registered with no email')
    parser.add_argument('--user', help='user name for a new installation, default iphone')
    parser.add_argument('--port', type=int, help='listening port, default 443')
    parser.add_argument('--domains', type=Path,
                        help='base domain list, default Google/AI/X; merged with gfwlist, normalized to roots')
    parser.add_argument('--refresh-profile', action='store_true',
                        help='generate an updated device profile for an existing account, keeping its password')
    parser.add_argument('--reset-password', action='store_true',
                        help='replace this installation account password with a random one and generate a new profile; '
                             'other users are preserved')
    gfw = parser.add_mutually_exclusive_group()
    gfw.add_argument('--gfwlist-file', type=Path, help='use a downloaded gfwlist instead of fetching it')
    gfw.add_argument('--no-gfwlist', action='store_true', help='explicitly omit gfwlist')
    parser.add_argument('--gfwlist-url', default=RULES.GFWLIST_URL)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--binary', type=Path,
                      help='prebuilt Linux x86_64 program, default /tmp/network-relay; never falls back to compilation')
    mode.add_argument('--build-from-source', action='store_const', dest='binary', const=None,
                      help='explicitly compile the downloaded source instead of installing a prebuilt program')
    parser.set_defaults(binary=Path('/tmp/network-relay'))
    parser.add_argument('--jobs', type=int, default=1, help='parallel build jobs, default 1 to reduce memory use')
    parser.add_argument('--cert', type=Path,
                        help='use an existing certificate instead of obtaining one from Let’s Encrypt')
    parser.add_argument('--key', type=Path, help='private key for --cert')
    parser.add_argument('--profile-out', type=Path,
                        help='for a new installation, write the device profile (with its password) to this file '
                             'instead of publishing it once on the website')
    args = parser.parse_args()
    if args.reset_password and args.profile:
        parser.error('--reset-password generates new credentials and cannot be combined with --profile.')
    if bool(args.cert) != bool(args.key) or not 1 <= args.jobs <= 128:
        parser.error('--cert and --key must be given together, and --jobs must be between 1 and 128.')
    try:
        preflight()
        with open('/run/lock/network-relay-install.lock', 'w') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError('Another installation is already running.') from None
            return install(args)
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'Installation not completed: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
