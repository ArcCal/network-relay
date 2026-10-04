#!/usr/bin/env python3
"""Debian 12/13 deployment using only Python's standard library and system tools."""

import argparse
import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import fcntl
import hmac
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import secrets
import shutil
import socket
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
CERTS = Path('/etc/letsencrypt/live')
SITE = Path('/var/www/relay')
UDP_TEMPLATE = '/.well-known/masque/udp/{target_host}/{target_port}/'
# A fresh VPS often runs unattended-upgrades right after boot; wait for its
# dpkg lock instead of failing.
APT = ['apt-get', '-o', 'DPkg::Lock::Timeout=1800']
SUPPORTED_DEBIAN = ('12', '13')
PROFILE_NAME = 'Google / AI / X — everything else direct'


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
    for line in Path(path).read_text().splitlines():
        value = line.split('#', 1)[0].strip()
        if value:
            value = domain_name(value)
            if value not in domains:
                domains.append(value)
    if not domains:
        raise ValueError('The domain list must not be empty; Apple treats an empty list as matching all traffic.')
    return domains


def read_profile(path):
    with Path(path).open('rb') as stream:
        raw = stream.read((1 << 20) + 1)
    if len(raw) > 1 << 20:
        raise ValueError('The profile is larger than 1 MiB.')
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


def atomic_write(path, data, mode=0o600):
    path = Path(path)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError(f'Refusing to overwrite a non-regular file: {path}')
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.network-relay-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
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
    """Returns (cert, key, automated) for this run.

    An existing installation keeps the certificate it was set up with, so an
    upgrade without --cert/--key does not switch to certbot, and a different
    --cert/--key is refused rather than silently ignored. Paths are kept as
    given, not resolved: Let's Encrypt's live/ files are symlinks that move
    to the newest archive/ file on renewal.
    """
    automated = (CERTS / identity.domain / 'fullchain.pem', CERTS / identity.domain / 'privkey.pem')
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
        return (*current, current == automated)
    if given:
        return (*given, False)
    return (*automated, True)


def install(args):
    preflight()
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
        if args.domains:
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
    domains = load_domains(args.domains or REPO / 'deploy/domains/google-ai-social.txt') if new_account else None
    if existing and (installed.domain, installed.port, installed.user) != (
            identity.domain, identity.port, identity.user):
        raise ValueError('The existing installation has a different domain, port or user name; '
                         'refusing to overwrite it.')
    if (existing and args.profile and installed.password is not None
            and not hmac.compare_digest(installed.password.encode(), identity.password.encode())):
        raise ValueError("The profile's password differs from the existing installation's; "
                         'the existing account will not be reset automatically.')
    cert, key, automated_cert = certificate_paths(args, identity, CONFIG.read_bytes() if existing else None)
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
    run(APT + ['install', '-y', '--no-install-recommends', 'build-essential', 'pkg-config',
         'git', 'curl', 'ca-certificates', 'certbot', 'iproute2', 'procps'], env=env)
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

    ETC.mkdir(mode=0o700, parents=True, exist_ok=True)
    SITE.mkdir(mode=0o755, parents=True, exist_ok=True)
    if not (SITE / 'index.html').exists():
        atomic_write(SITE / 'index.html', b'<!doctype html><title>Welcome</title><h1>Welcome</h1>\n', 0o644)
    with tempfile.TemporaryDirectory(prefix='.install-', dir=ETC) as directory:
        staging = Path(directory)
        if existing:
            config_data = CONFIG.read_bytes()
        else:
            # A generated password is a long random secret, which a fast
            # hash protects as well as a slow one does a chosen password,
            # and which then costs the server almost nothing to check.
            command = [binary, 'passwd', '--name', identity.user, '--stdin']
            if args.profile is None:
                command.append('--fast-hash')
            result = run(command, input=identity.password + '\n', capture=True)
            password_hash = tomllib.loads(result.stdout)['user'][0]['password_hash']
            config_data = render_config(identity, password_hash, cert, key, SITE)
        candidate = staging / 'relay.toml'
        atomic_write(candidate, config_data)
        run([binary, 'serve', '--config', candidate, '--check'])
        apply_install(binary, config_data, render_state(identity), identity, automated_cert=automated_cert)

    print('\nInstallation complete.', flush=True)
    if new_account and args.profile is None:
        try:
            hand_over_profile(binary, identity, domains, args.profile_out)
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            # The relay runs; only the hand-over failed, and the password is
            # gone with this process. A new one is quickly made by hand.
            print(f'The relay is installed, but its device profile could not be handed over ({error}). '
                  'Create a new password and profile as in "Another device" in docs/deploy-debian13.md.',
                  file=sys.stderr)
            return 2
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


def hand_over_profile(binary, identity, domains, out):
    """Gives the new account's device profile to the administrator without
    leaving the password on the server: a link that works once, or a file
    where they asked for one."""
    command = [binary, 'profile', '--host', identity.domain, '--port', str(identity.port),
               '--user', identity.user, '--name', PROFILE_NAME]
    for domain in domains:
        command.extend(['--match-domain', domain])
    if out:
        run(command + ['--out', out], input=identity.password + '\n', capture=True)
        print(f'Device profile: {out} (contains the password, mode 600). Install it on the iPhone, iPad or '
              'Mac, then delete it.', flush=True)
        return
    result = run(command + ['--publish', '--config', CONFIG], input=identity.password + '\n', capture=True)
    written = re.search(r'^Wrote (.+)$', result.stdout, re.MULTILINE)
    if not written:
        raise RuntimeError('Could not publish the device profile; create one with network-relay profile.')
    published = Path(written.group(1))
    run(['systemctl', 'reload', 'network-relay'])
    port = '' if identity.port == 443 else f':{identity.port}'
    print('Within 15 minutes, open this link in Safari on the iPhone, iPad or Mac and install the profile. '
          'The link works once; the password is not stored anywhere else on this server:', flush=True)
    print(f'\n    https://{identity.domain}{port}/{published.name}\n', flush=True)
    print(f'If it expires, or for a Mac without Safari access, delete {published} and run the installer\'s '
          'profile step by hand: see "Another device" in docs/deploy-debian13.md.', flush=True)


def apply_install(binary, config_data, state_data, identity, *, automated_cert):
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
    updates = {
        BINARY: (binary.read_bytes(), 0o755),
        CONFIG: (config_data, 0o600),
        STATE: (state_data, 0o600),
        UNIT: ((REPO / 'deploy/network-relay.service').read_bytes(), 0o644),
        SYSCTL: (''.join(sysctl_values).encode(), 0o644),
    }
    if automated_cert:
        updates[HOOK] = (b'#!/bin/sh\nif systemctl is-active --quiet network-relay; then\n'
                         b'    systemctl reload network-relay\nfi\n', 0o755)
    snapshots = {}
    for index, path in enumerate(updates):
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise ValueError(f'Refusing to replace a non-regular installed file: {path}')
        saved = backup / str(index)
        if path.exists():
            shutil.copy2(path, saved)
            snapshots[path] = saved
        else:
            snapshots[path] = None
    atomic_write(backup / 'manifest.json', json.dumps({str(k): str(v) if v else None for k, v in snapshots.items()},
                                                     indent=2).encode())
    try:
        for path, (data, mode) in updates.items():
            atomic_write(path, data, mode)
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
                atomic_write(path, saved.read_bytes(), saved.stat().st_mode & 0o777)
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
                        help='domain list for a newly generated profile, default the Google/AI/X preset')
    parser.add_argument('--binary', type=Path,
                        help='install this prebuilt program instead of building the downloaded source')
    parser.add_argument('--jobs', type=int, default=1, help='parallel build jobs, default 1 to reduce memory use')
    parser.add_argument('--cert', type=Path,
                        help='use an existing certificate instead of obtaining one from Let’s Encrypt')
    parser.add_argument('--key', type=Path, help='private key for --cert')
    parser.add_argument('--profile-out', type=Path,
                        help='for a new installation, write the device profile (with its password) to this file '
                             'instead of publishing it once on the website')
    args = parser.parse_args()
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
