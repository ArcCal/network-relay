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
PROFILE = ETC / 'device.mobileconfig'
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


@dataclass(frozen=True)
class Identity:
    domain: str
    port: int
    user: str
    password: str = field(repr=False)


def domain_name(value):
    value = value.removesuffix('.').lower()
    if (len(value) > 253 or '.' not in value
            or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                   for label in value.split('.'))):
        raise ValueError(f'无效域名：{value!r}')
    try:
        import ipaddress
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('请使用域名，而不是 IP 地址。')


def validate_identity(identity):
    domain_name(identity.domain)
    if not 1 <= identity.port <= 65535:
        raise ValueError('端口必须在 1–65535 之间。')
    if not re.fullmatch(r'[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}', identity.user):
        raise ValueError('用户名只能包含字母、数字、下划线、点、连字符，且不能以点开头。')
    if len(identity.password) < 12 or any(ord(c) < 32 or ord(c) == 127 for c in identity.password):
        raise ValueError('密码至少 12 个字符，且不能包含控制字符。')
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
        raise ValueError('分流域名表不能为空，否则 Apple 会匹配全部流量。')
    return domains


def read_profile(path):
    with Path(path).open('rb') as stream:
        raw = stream.read((1 << 20) + 1)
    if len(raw) > 1 << 20:
        raise ValueError('描述文件超过 1 MiB。')
    profile = plistlib.loads(raw)
    payloads = profile.get('PayloadContent', [])
    if len(payloads) != 1 or payloads[0].get('PayloadType') != 'com.apple.relay.managed':
        raise ValueError('需要仅包含一个 Network Relay 负载的未签名 mobileconfig。')
    payload = payloads[0]
    relays = payload.get('Relays', [])
    if len(relays) != 1:
        raise ValueError('安装脚本需要单跳中继描述文件。')
    relay = relays[0]
    urls = [relay[key] for key in ('HTTP2RelayURL', 'HTTP3RelayURL') if key in relay]
    if not urls or len(set(urls)) != 1:
        raise ValueError('HTTP/2 和 HTTP/3 必须使用同一个中继 URL。')
    url = urlsplit(urls[0])
    if (url.scheme != 'https' or url.username or url.password or url.query or url.fragment
            or url.path != UDP_TEMPLATE):
        raise ValueError('描述文件须使用 HTTPS 和项目默认的 CONNECT-UDP 模板。')
    if any(key in relay for key in ('PayloadCertificateUUID', 'RawPublicKeys')):
        raise ValueError('此安装流程使用公共 CA 和密码认证。')
    authorization = relay.get('AdditionalHTTPHeaderFields', {}).get('Authorization', '')
    scheme, _, value = authorization.partition(' ')
    if scheme.lower() != 'basic':
        raise ValueError('描述文件缺少 Basic 认证头。')
    try:
        user, password = base64.b64decode(value, validate=True).decode().split(':', 1)
    except (ValueError, UnicodeError) as error:
        raise ValueError('描述文件中的 Basic 凭据无效。') from error
    domains = payload.get('MatchDomains', [])
    if not isinstance(domains, list) or not domains:
        raise ValueError('描述文件必须包含非空 MatchDomains，不能意外启用全局代理。')
    for domain in domains:
        domain_name(domain)
    identity = validate_identity(Identity(domain_name(url.hostname or ''),
                                          443 if url.port is None else url.port, user, password))
    return identity, raw


def atomic_write(path, data, mode=0o600):
    path = Path(path)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError(f'拒绝覆盖非普通文件：{path}')
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
        raise ValueError('请下载完整源码 ZIP 并解压，或使用 --binary 指定已编译的程序。')
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
                raise ValueError(f'端口 {port} 已被其他服务占用；脚本不会停止它：{listener}')


def preflight():
    if os.geteuid() != 0:
        raise ValueError('请用 root 运行此安装脚本。')
    os_release = platform.freedesktop_os_release()
    # Debian 12 has everything the installer needs too: Python 3.11
    # (tomllib), apt with DPkg::Lock::Timeout, certbot and systemd.
    if (os_release.get('ID') != 'debian' or os_release.get('VERSION_ID') not in SUPPORTED_DEBIAN
            or platform.machine() != 'x86_64'):
        raise ValueError('只支持 Debian 12/13 x86_64。')
    if not Path('/run/systemd/system').is_dir():
        raise ValueError('需要由 systemd 启动的 VPS。')


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
                raise ValueError(f'证书文件不存在：{path}')
    if existing_config is not None:
        tls = tomllib.loads(existing_config.decode())['tls']
        current = (Path(tls['cert']), Path(tls['key']))
        if given and given != current:
            raise ValueError(f'已有安装使用的证书是 {current[0]} 和 {current[1]}，与 --cert/--key 不同。'
                             f'要更换证书，请先编辑 {CONFIG} 的 [tls] 并 systemctl restart network-relay，'
                             '再不带 --cert/--key 运行本脚本。')
        return (*current, current == automated)
    if given:
        return (*given, False)
    return (*automated, True)


def install(args):
    preflight()
    existing = CONFIG.exists()
    old_identity = read_profile(PROFILE)[0] if PROFILE.exists() else None
    if existing and old_identity is None:
        raise ValueError('发现已有手工安装配置，拒绝覆盖。请备份并按 docs/deploy-debian13.md 的更新步骤处理。')
    imported = args.profile or (PROFILE if existing else None)
    if imported:
        identity, profile_data = read_profile(imported)
        if args.domain and domain_name(args.domain) != identity.domain:
            raise ValueError('--domain 与描述文件中的服务器域名不一致。')
        if ((args.user is not None and args.user != identity.user)
                or (args.port is not None and args.port != identity.port)):
            raise ValueError('--user/--port 与描述文件不一致。')
        if args.domains:
            raise ValueError('--profile 已带有分流规则，不能同时指定 --domains。')
    else:
        domain = args.domain
        if not domain and sys.stdin.isatty():
            domain = input('中继域名（必须已解析到这台 VPS）：').strip()
        identity = validate_identity(Identity(domain_name(domain or ''), 443 if args.port is None else args.port,
                                              args.user or 'iphone', secrets.token_urlsafe(24)))
        profile_data = None
    domains = load_domains(args.domains or REPO / 'deploy/domains/google-ai-social.txt')
    if existing and (old_identity.domain, old_identity.port, old_identity.user) != (
            identity.domain, identity.port, identity.user):
        raise ValueError('已有安装的域名、端口和用户名不同，拒绝自动覆盖。')
    if existing and not hmac.compare_digest(old_identity.password.encode(), identity.password.encode()):
        raise ValueError('提供的描述文件密码与已有安装不同；不会自动重置已有账号。')
    cert, key, automated_cert = certificate_paths(args, identity, CONFIG.read_bytes() if existing else None)
    if identity.port == 80 and automated_cert:
        raise ValueError('自动证书续期需要独占 TCP 80，请为中继选择其他端口（默认 443）。')

    print(f'部署 {identity.domain}:{identity.port}，账号 {identity.user}；密码不会打印。', flush=True)
    print('云防火墙/DNS 需已就绪：TCP 80、TCP/UDP 中继端口；Cloudflare 使用仅 DNS。', flush=True)
    env = os.environ.copy()
    env['DEBIAN_FRONTEND'] = 'noninteractive'
    print('如系统正在自动更新，会等待它完成（最多 30 分钟）。', flush=True)
    run(APT + ['update'], env=env)
    run(APT + ['install', '-y', '--no-install-recommends', 'build-essential', 'pkg-config',
         'git', 'curl', 'ca-certificates', 'certbot', 'iproute2', 'procps'], env=env)
    main_pid = run(['systemctl', 'show', 'network-relay.service', '-p', 'MainPID', '--value'],
                   capture=True, check=False).stdout.strip()
    port_available(identity.port, int(main_pid or 0))
    try:
        addresses = socket.getaddrinfo(identity.domain, identity.port, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise ValueError('中继域名无法解析，请先把 DNS A/AAAA 记录指向 VPS。') from error
    print('域名当前地址：' + ', '.join(sorted({item[4][0] for item in addresses})), flush=True)
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
        if profile_data is None:
            generated = staging / 'device.mobileconfig'
            command = [binary, 'profile', '--host', identity.domain, '--port', str(identity.port),
                       '--user', identity.user, '--name', 'Google / AI / X — 其他直连', '--out', generated]
            for domain in domains:
                command.extend(['--match-domain', domain])
            run(command, input=identity.password + '\n', capture=True)
            profile_data = generated.read_bytes()
        if existing:
            config_data = CONFIG.read_bytes()
        else:
            result = run([binary, 'passwd', '--name', identity.user, '--stdin'],
                         input=identity.password + '\n', capture=True)
            password_hash = tomllib.loads(result.stdout)['user'][0]['password_hash']
            config_data = render_config(identity, password_hash, cert, key, SITE)
        candidate = staging / 'relay.toml'
        atomic_write(candidate, config_data)
        run([binary, 'serve', '--config', candidate, '--check'])
        apply_install(binary, config_data, profile_data, identity, automated_cert=automated_cert)

    print(f'\n安装完成。设备描述文件：{PROFILE}（含密码，权限 600，不会公开到网站）。', flush=True)
    print('开始从本机检查三种 HTTP 版本的 TCP/UDP 中继；公网入口仍需从设备验证。', flush=True)
    result = run([BINARY, 'check', '--server', identity.domain, '--address', '127.0.0.1',
                  '--port', str(identity.port), '--user', identity.user],
                 input=identity.password + '\n', check=False, timeout=300)
    if result.returncode:
        print('服务已运行，但联网自检有失败。请查看上面的错误及 journalctl -u network-relay。', file=sys.stderr)
        return 2
    return 0


def apply_install(binary, config_data, profile_data, identity, *, automated_cert):
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
        PROFILE: (profile_data, 0o600),
        UNIT: ((REPO / 'deploy/network-relay.service').read_bytes(), 0o644),
        SYSCTL: (''.join(sysctl_values).encode(), 0o644),
    }
    if automated_cert:
        updates[HOOK] = (b'#!/bin/sh\nif systemctl is-active --quiet network-relay; then\n'
                         b'    systemctl reload network-relay\nfi\n', 0o755)
    snapshots = {}
    for index, path in enumerate(updates):
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise ValueError(f'拒绝替换非普通安装文件：{path}')
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
            print('无法调整 UDP 缓冲区（部分 VPS 限制 sysctl），继续使用内核现有设置。', file=sys.stderr)
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
            raise RuntimeError('本机 HTTPS 启动检查失败，正在恢复原安装。')
        print(f'服务已启动，安装前文件备份：{backup}', flush=True)
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
    parser = argparse.ArgumentParser(description='安装/更新 Debian 12/13 x64 Network Relay，并生成按域名分流的 mobileconfig。')
    parser.add_argument('--profile', type=Path, help='导入已有 mobileconfig 的服务器地址和凭据；推荐使用随交付提供的文件')
    parser.add_argument('--domain', help='中继域名；未导入 profile 时必需，不写则在终端询问')
    parser.add_argument('--email', help='Let’s Encrypt 账户邮箱；不写则注册无邮箱账户')
    parser.add_argument('--user', help='新安装的用户名，默认 iphone')
    parser.add_argument('--port', type=int, help='监听端口，默认 443')
    parser.add_argument('--domains', type=Path, help='新生成 profile 使用的域名列表，默认 Google/AI/X 预设')
    parser.add_argument('--binary', type=Path, help='安装指定预编译程序；默认从下载的源码编译')
    parser.add_argument('--jobs', type=int, default=1, help='编译并发数，默认 1 以减少内存使用')
    parser.add_argument('--cert', type=Path, help='使用现有证书；默认自动申请 Let’s Encrypt')
    parser.add_argument('--key', type=Path, help='与 --cert 配套的私钥')
    args = parser.parse_args()
    if bool(args.cert) != bool(args.key) or not 1 <= args.jobs <= 128:
        parser.error('--cert/--key 必须一起提供，--jobs 必须在 1–128 之间。')
    try:
        preflight()
        with open('/run/lock/network-relay-install.lock', 'w') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError('另一个安装进程正在运行。') from None
            return install(args)
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'安装未完成：{error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
