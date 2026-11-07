#!/usr/bin/env python3
"""Regenerate an HTTP/2-only, selected-domain Apple profile from an installed relay.

Run as root from a complete ArcCal/network-relay checkout. The original
/etc/network-relay/relay/device.mobileconfig is read, never modified. Live
GFWList and all 18 blackmatrix7 Clash lists are downloaded on EVERY run;
repo deploy/global-profile.py supplies the project's reviewed parsers and
ICANN registered-root deduplication. No packages, server settings, certificates,
accounts, passwords or systemd services are changed.

Example:
  sudo python3 generate-network-relay-global-mobileconfig.py \
      --domains /root/my-domains.txt --domains /root/more-domains.txt

The output contains the installed profile's Basic authentication credential.
Keep it private; an empty match list is always refused. UIToggleEnabled=false
suppresses the Settings toggle on supported Apple OS releases (26+), but it
cannot stop a user from removing the configuration profile.
"""

from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import os
from pathlib import Path
import plistlib
import re
import stat
import sys
import tempfile
import urllib.request
from urllib.parse import urlsplit
import uuid

ROOT = Path(__file__).resolve().parent
RULES_SCRIPT = ROOT / 'deploy/global-profile.py'
SOURCE_PROFILE = Path('/etc/network-relay/relay/device.mobileconfig')
DEFAULT_OUTPUT = Path('/etc/network-relay/relay/device-global.mobileconfig')
PROFILE_LIMIT = 524288
SERVICE_BASE = 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash'


def load_rules():
    if not RULES_SCRIPT.is_file():
        raise ValueError('Complete network-relay checkout required: missing deploy/global-profile.py')
    spec = importlib.util.spec_from_file_location('relay_global_rules', RULES_SCRIPT)
    if spec is None or spec.loader is None:
        raise ValueError('Could not load the repository domain-list converter.')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_private_profile(path: Path) -> dict:
    meta = path.lstat()
    if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_nlink != 1
            or meta.st_mode & 0o077):
        raise ValueError('Installed profile must be a root-owned, single-link, root-only regular file.')
    if meta.st_size > PROFILE_LIMIT:
        raise ValueError('Installed profile exceeds the supported 512 KiB limit.')
    profile = plistlib.loads(path.read_bytes())
    if not isinstance(profile, dict):
        raise ValueError('Installed profile is not an Apple configuration dictionary.')
    contents = profile.get('PayloadContent')
    if (not isinstance(contents, list) or len(contents) != 1
            or not isinstance(contents[0], dict)
            or contents[0].get('PayloadType') != 'com.apple.relay.managed'):
        raise ValueError('Expected exactly one installed Apple Network Relay payload.')
    payload = contents[0]
    relays = payload.get('Relays')
    if not isinstance(relays, list) or len(relays) != 1 or not isinstance(relays[0], dict):
        raise ValueError('Expected one relay connection in the installed profile.')
    relay = relays[0]
    url = relay.get('HTTP2RelayURL') or relay.get('HTTP3RelayURL')
    if not isinstance(url, str):
        raise ValueError('The installed profile has no HTTP/2 or HTTP/3 relay URL.')
    parts = urlsplit(url)
    if (parts.scheme != 'https' or not parts.hostname or parts.username or parts.password
            or parts.query or parts.fragment or not parts.path.startswith('/')):
        raise ValueError('The installed relay URL must be a plain HTTPS URI template.')
    headers = relay.get('AdditionalHTTPHeaderFields')
    authorization = headers.get('Authorization') if isinstance(headers, dict) else None
    if not isinstance(authorization, str) or not authorization.startswith('Basic '):
        raise ValueError('The installed profile has no Basic authentication credentials.')
    try:
        decoded = base64.b64decode(authorization[6:], validate=True).decode('utf-8')
        user, password = decoded.split(':', 1)
    except (ValueError, UnicodeError) as error:
        raise ValueError('Invalid Basic authorization data in the installed profile.') from error
    if not user or not password:
        raise ValueError('The installed profile has an empty username or password.')
    for key in ('MatchDomains', 'ExcludedDomains'):
        value = payload.get(key, [])
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ValueError(f'Invalid {key} in the installed profile.')
    # Do not display decoded credentials, even in debug/error messages.
    return profile


def download(url: str, rules) -> bytes:
    request = urllib.request.Request(url, headers={
        'User-Agent': 'network-relay-global-profile/1.0',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
    })
    with urllib.request.urlopen(request, timeout=60) as response:
        return rules.read_bounded(response)


def collect_domains(rules, installed: dict, additional_files: list[Path]) -> tuple[list[str], dict]:
    payload = installed['PayloadContent'][0]
    existing = list(payload.get('MatchDomains', []))
    custom = []
    for file in additional_files:
        added = rules.load_domain_file(file)
        custom.extend(added)
        print(f'Custom list {file}: {len(added)} valid domains', flush=True)

    print('Fetching latest GFWList...', flush=True)
    gfw_text = rules.decode_gfwlist(download(rules.GFWLIST_URL, rules))
    gfw_domains, gfw_stats = rules.extract_gfwlist(gfw_text)
    if not gfw_domains:
        raise ValueError('GFWList contains no convertible domains; refusing partial output.')
    print(f'GFWList: {len(gfw_domains)} domains', flush=True)

    names = rules.SERVICE_RULE_NAMES

    def fetch_service(name: str):
        url = f'{SERVICE_BASE}/{name}/{name}.yaml'
        try:
            raw = download(url, rules)
            return name, rules.extract_clash_domains(raw.decode('utf-8'))
        except (OSError, ValueError, UnicodeError) as error:
            raise ValueError(f'Cannot fetch/parse blackmatrix7 {name}: {error}') from error

    print(f'Fetching {len(names)} latest blackmatrix7 lists...', flush=True)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(fetch_service, names))
    service_domains = []
    for name, (domains, dropped) in results:
        service_domains.extend(domains)
        print(f'  {name}: {len(domains)} domains' +
              (f' (unsupported rules omitted: {sum(dropped.values())})' if dropped else ''), flush=True)

    relay = payload['Relays'][0]
    host = urlsplit(relay.get('HTTP2RelayURL') or relay['HTTP3RelayURL']).hostname
    merged = existing + custom + gfw_domains + service_domains
    # Reuse the repository's ICANN suffix normalization and parent-domain collapse.
    normalized = rules.normalized_domains(merged, host.lower())
    if not normalized:
        raise ValueError('No match domains remained; an empty list would relay all traffic.')
    stats = {'original': len(existing), 'custom': len(custom), 'gfwlist': len(gfw_domains),
             'blackmatrix7': len(service_domains), 'merged': len(merged), 'final': len(normalized),
             'gfw_omissions': gfw_stats}
    return normalized, stats


def build_profile(original: dict, domains: list[str]) -> bytes:
    if not domains:
        raise ValueError('Refusing an empty MatchDomains list (it would match all traffic).')
    profile = original.copy()
    payload = original['PayloadContent'][0].copy()
    relay = payload['Relays'][0].copy()
    http2 = relay.get('HTTP2RelayURL') or relay.get('HTTP3RelayURL')
    relay['HTTP2RelayURL'] = http2
    relay.pop('HTTP3RelayURL', None)  # HTTP/2 only, even if the seed enabled QUIC.
    payload['Relays'] = [relay]
    payload['MatchDomains'] = domains
    payload['UIToggleEnabled'] = False  # iOS/macOS 26+: no on/off toggle in Settings.
    host = urlsplit(http2).hostname.lower()
    exclusions = list(payload.get('ExcludedDomains', []))
    if host not in {d.lower().rstrip('.') for d in exclusions}:
        exclusions.append(host)  # Never redirect the relay's own address through itself.
    payload['ExcludedDomains'] = exclusions
    profile['PayloadContent'] = [payload]
    # Give the derived profile a distinct identity from the original installer
    # profile, preserving its service URL and credential bytes unchanged.
    base_id = profile.get('PayloadIdentifier')
    payload_id = payload.get('PayloadIdentifier')
    if not isinstance(base_id, str) or not isinstance(payload_id, str):
        raise ValueError('Installed profile lacks its payload identifiers.')
    profile['PayloadIdentifier'] = base_id + '.global'
    payload['PayloadIdentifier'] = payload_id + '.global'
    profile['PayloadUUID'] = str(uuid.uuid4()).upper()
    payload['PayloadUUID'] = str(uuid.uuid4()).upper()
    label = f'{host} — Global domains (HTTP/2)'
    profile['PayloadDisplayName'] = label
    payload['PayloadDisplayName'] = label
    description = f'Routes {len(domains)} selected root domains and subdomains using HTTP/2.'
    profile['PayloadDescription'] = description
    payload['PayloadDescription'] = description
    # Follow the existing global-profile.py compact-XML convention to stay
    # within Apple's 512 KiB per-profile bound.
    data = re.sub(rb'>\s+<', b'><', plistlib.dumps(profile, sort_keys=False))
    if len(data) >= PROFILE_LIMIT:
        raise ValueError(f'Generated profile is {len(data)} bytes (limit: {PROFILE_LIMIT - 1}); '
                         'reduce custom lists or adjust the routing scope.')
    check = plistlib.loads(data)['PayloadContent'][0]
    if (check['Relays'][0].get('HTTP3RelayURL') is not None or
            check['UIToggleEnabled'] is not False or not check.get('MatchDomains')):
        raise ValueError('Generated profile failed HTTP/2-only and routing validation.')
    return data


def save_private(path: Path, original_path: Path, content: bytes) -> None:
    parent = path.parent
    folder = parent.lstat()
    if (not stat.S_ISDIR(folder.st_mode) or folder.st_uid != 0
            or folder.st_mode & 0o077):
        raise ValueError('Output parent must be a root-owned, root-only directory (0700).')
    # Never replace the installer's original profile, even via an alias.
    if path.resolve() == original_path.resolve():
        raise ValueError('Refusing to overwrite the original installed profile.')
    try:
        old = path.lstat()
    except FileNotFoundError:
        old = None
    if old and (not stat.S_ISREG(old.st_mode) or old.st_uid != 0 or old.st_nlink != 1):
        raise ValueError('Refusing to replace a linked or non-root-owned output file.')
    if old and old.st_mode & 0o077:
        raise ValueError('Existing output is not root-only; inspect it before replacement.')
    if old and (old.st_dev, old.st_ino) == (original_path.stat().st_dev, original_path.stat().st_ino):
        raise ValueError('Output file is linked to the installed profile.')
    fd, temp_name = tempfile.mkstemp(prefix='.network-relay-global-', dir=parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--domains', type=Path, action='append', default=[], metavar='FILE',
                        help='additional plain hostname list (repeatable; one domain per line, # comments)')
    parser.add_argument('--out', type=Path, default=DEFAULT_OUTPUT,
                        help=f'output file (default {DEFAULT_OUTPUT})')
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error('Run as root to read the private installed device profile.')
    try:
        rules = load_rules()
        installed = read_private_profile(SOURCE_PROFILE)
        domains, counts = collect_domains(rules, installed, args.domains)
        data = build_profile(installed, domains)
        save_private(args.out, SOURCE_PROFILE, data)
    except (OSError, ValueError, plistlib.InvalidFileException) as error:
        parser.exit(1, f'Error: {error}\n')
    print(f'Saved {args.out}: {counts["final"]} distinct root domains, {len(data)} bytes (mode 0600).')
    print('Sources: original seed {original}, custom {custom}, GFWList {gfwlist}, '
          'blackmatrix7 {blackmatrix7} (before deduplication).'.format(**counts))
    print('HTTP/2 only; Settings toggle disabled on Apple OS 26+ (profile removal is still possible).')
    print('The file contains the existing client password. Transfer privately; do not publish it.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
