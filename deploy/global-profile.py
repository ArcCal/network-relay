#!/usr/bin/env python3
"""Builds one root-domain mobileconfig from service lists, gfwlist and eighteen Clash lists.

Uses the standard library and the prebuilt `network-relay profile` command.
The gfwlist and eighteen blackmatrix7 service lists are downloaded when this runs.
The output contains deduplicated registered roots and stays below 524288 bytes. Only host names can be
expressed in Apple's MatchDomains, so regular expressions, IP addresses and
exception rules in the list are dropped, and a rule limited to a URL path
relays its whole domain.
"""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import getpass
import ipaddress
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import plistlib
import tempfile
import urllib.request

REPO = Path(__file__).resolve().parent.parent
DOMAINS = REPO / 'deploy/domains'
GFWLIST_URL = 'https://raw.githubusercontent.com/gfwlist/gfwlist/refs/heads/master/list.txt'
PROXY_LIST_URL = 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt'
LABEL = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')
MAX_LIST_BYTES = 16 << 20
MAX_DEVICE_PROFILE_BYTES = 524288
SERVICE_RULE_NAMES = ('Cloudflare', 'Gemini', 'OpenAI', 'Anthropic', 'Google', 'GitHub', 'Twitter', 'Jsdelivr', 'Pandora', 'Spotify', 'Reddit', 'Discord', 'iCloudPrivateRelay', 'Claude', 'AppleNews', 'AppleProxy', 'TikTok', 'TigerFintech')
SERVICE_RULE_URLS = {
    name: f'https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/{name}/{name}.yaml'
    for name in SERVICE_RULE_NAMES
}
SERVICE_RULE_URLS['Spotify'] = 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Spotify/Spotify.yaml'


def read_bounded(stream):
    raw = stream.read(MAX_LIST_BYTES + 1)
    if len(raw) > MAX_LIST_BYTES:
        raise ValueError('The domain list exceeds 16 MiB.')
    return raw


def clean_host(host):
    """A lower-case DNS name the profile accepts, or None (IP addresses, odd characters)."""
    host = host.strip().lower().strip('.')
    if '.' not in host or len(host) > 253:
        return None
    try:
        ipaddress.ip_address(host.strip('[]'))
        return None
    except ValueError:
        pass
    if not all(LABEL.match(label) for label in host.split('.')) or host.rsplit('.', 1)[1].isdigit():
        return None
    return host


def load_domain_file(path):
    domains = []
    seen = set()
    with Path(path).open('rb') as stream:
        text = read_bounded(stream).decode('utf-8')
    for line in text.splitlines():
        host = clean_host(line.split('#', 1)[0])
        if host and host not in seen:
            domains.append(host)
            seen.add(host)
    return domains


def decode_gfwlist(raw):
    """The official list is base64; some mirrors publish the plain AutoProxy text."""
    text = raw.decode('utf-8', 'replace')
    if text.lstrip().startswith('['):
        return text
    return base64.b64decode(raw).decode('utf-8', 'replace')


def extract_gfwlist(text):
    """Returns (domains, statistics) from AutoProxy rules."""
    hosts, stats = set(), {}

    def count(name):
        stats[name] = stats.get(name, 0) + 1

    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in '![':
            continue
        if line.startswith('@@'):
            count('exception rules ignored')
            continue
        if line.startswith('/') and line.endswith('/') and len(line) > 1:
            count('regular expressions dropped')
            continue
        match = (re.match(r'^\|\|([^/^*?:|]+)(.*)$', line) or re.match(r'^\|?https?://([^/^*?:|]+)(.*)$', line)
                 or re.match(r'^\.?([A-Za-z0-9.-]+)()$', line))
        host = clean_host(match.group(1)) if match else None
        if not host:
            count('IP addresses and other patterns dropped')
            continue
        if match.group(2).strip('^/ '):
            count('path-limited rules widened to their domain')
        hosts.add(host)
    return sorted(hosts), stats


def collapse(domains):
    """Drops names whose parent domain is also listed; a parent matches its subdomains."""
    wanted = set(domains)
    return sorted(d for d in wanted if not any('.'.join(d.split('.')[i:]) in wanted for i in range(1, d.count('.') + 1)))


def build_domains(services, gfwlist_text):
    gfw, stats = extract_gfwlist(gfwlist_text) if gfwlist_text is not None else ([], {})
    return collapse(set(services) | set(gfw)), stats


def extract_proxy_domains(text):
    """Read the domain payload format published by Loyalsoldier, without a YAML dependency."""
    domains = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line == 'payload:':
            continue
        if not line.startswith('- '):
            raise ValueError('Unexpected proxy.txt format: expected a domain payload list.')
        value = line[2:].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if value.startswith('+.'):
            value = value[2:]
        host = clean_host(value)
        if host is None and LABEL.fullmatch(value.lower()) and not value.isdigit():
            host = value.lower()  # Explicit TLD rules such as '+.adult' retain their scope.
        if host is None:
            raise ValueError(f'Cannot convert proxy.txt rule to an Apple domain: {value!r}')
        domains.add(host)
    if not domains:
        raise ValueError('The proxy.txt domain payload is empty.')
    return sorted(domains)


def extract_clash_domains(text):
    """Read classical Clash payloads; domain rules only, with reported omissions."""
    domains, stats = set(), {}
    payload = False
    unsupported = {'DOMAIN-KEYWORD', 'DOMAIN-REGEX', 'DOMAIN-WILDCARD',
                   'IP-CIDR', 'IP-CIDR6', 'IP-ASN', 'PROCESS-NAME', 'PROCESS-PATH'}
    for line in text.splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        if line == 'payload:' and not payload:
            payload = True
            continue
        if not payload or not line.startswith('- '):
            raise ValueError('Unexpected Clash YAML format: expected a classical payload list.')
        value = line[2:].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        fields = [field.strip() for field in value.split(',')]
        kind = fields[0]
        if kind in ('DOMAIN', 'DOMAIN-SUFFIX'):
            host = clean_host(fields[1]) if len(fields) == 2 else None
            if host is None:
                raise ValueError(f'Invalid Clash domain rule: {value!r}')
            domains.add(host)
        elif kind in unsupported and len(fields) >= 2:
            stats[kind] = stats.get(kind, 0) + 1
        else:
            raise ValueError(f'Unrecognized Clash rule: {value!r}')
    if not domains:
        raise ValueError('The Clash payload contains no convertible domains.')
    return sorted(domains), stats


def load_service_rules(directory=None):
    """Load all eighteen sources, refusing an incomplete set on any failure."""
    def load(name):
        source = Path(directory) / f'{name}.yaml' if directory is not None else SERVICE_RULE_URLS[name]
        print(f'Loading {name}: {source}', flush=True)
        try:
            request = urllib.request.Request(source, headers={'Cache-Control': 'no-cache', 'Pragma': 'no-cache'}) \
                if isinstance(source, str) else None
            with (source.open('rb') if isinstance(source, Path)
                  else urllib.request.urlopen(request, timeout=60)) as stream:
                return extract_clash_domains(read_bounded(stream).decode('utf-8'))
        except (OSError, ValueError) as error:
            raise ValueError(f'Could not load {name}: {error}. No partial profile will be generated.') from error
    domains = []
    with ThreadPoolExecutor(max_workers=min(4, len(SERVICE_RULE_NAMES))) as pool:
        results = list(pool.map(load, SERVICE_RULE_NAMES))
    for name, (extracted, stats) in zip(SERVICE_RULE_NAMES, results):
        domains.extend(extracted)
        print(f'{name}: {len(extracted)} domain rules.', flush=True)
        for kind, count in stats.items():
            print(f'  {kind}: {count} rules omitted (not representable by MatchDomains).', flush=True)
    return domains


def add_service_rule_arguments(parser):
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--rules-dir', type=Path,
                      help='directory containing all eighteen service YAML files, instead of downloading them')
    mode.add_argument('--no-service-rules', action='store_true', help='explicitly omit the eighteen service lists')


def profile_with_domains(raw, domains):
    """Keep the binary's profile format, replacing a small seed list with the full list.

    This avoids ARG_MAX and the binary's verbose per-domain description. Compact
    XML keeps the single device profile small; callers enforce the iPhone limit.
    """
    if not domains:
        raise ValueError('An empty Apple match list would relay all traffic.')
    profile = plistlib.loads(raw)
    payload = profile['PayloadContent'][0]
    payload['MatchDomains'] = domains
    description = f'Relays {len(domains)} selected domains and their subdomains; other traffic is unchanged.'
    profile['PayloadDescription'] = description
    payload['PayloadDescription'] = description
    return re.sub(rb'>\s+<', b'><', plistlib.dumps(profile, sort_keys=False))


def root_domains(domains, suffix_text):
    """Registered roots using ICANN suffixes, deliberately ignoring private tenant suffixes."""
    exact, wildcard, exceptions = set(), set(), set()
    for line in suffix_text.splitlines():
        rule = line.strip()
        if not rule or rule.startswith('//'):
            continue
        target = exceptions if rule.startswith('!') else wildcard if rule.startswith('*.') else exact
        rule = rule.removeprefix('!').removeprefix('*.')
        target.add(rule.encode('idna').decode('ascii').lower())
    if not exact:
        raise ValueError('The bundled public suffix table is empty.')
    roots = set()
    for domain in domains:
        labels = domain.split('.')
        suffix_length = 1  # The PSL default rule is '*'.
        for index in range(len(labels)):
            suffix = '.'.join(labels[index:])
            if suffix in exceptions:
                suffix_length = len(labels) - index - 1
                break
            if suffix in exact or (index + 1 < len(labels) and '.'.join(labels[index + 1:]) in wildcard):
                suffix_length = max(suffix_length, len(labels) - index)
        # If a source explicitly lists a public suffix, preserve its stated scope;
        # never derive co.uk from an ordinary host under example.co.uk.
        roots.add('.'.join(labels[-min(len(labels), suffix_length + 1):]))
    return sorted(roots)


def normalized_domains(domains, relay_host):
    suffixes = (DOMAINS / 'public-suffix-icann.dat').read_text()
    return collapse([d for d in root_domains([d for d in domains if d != relay_host], suffixes)
                     if d != relay_host and d != 'adult' and not d.endswith('.adult')])


def find_binary(given):
    candidates = [given] if given else [REPO / 'target/release/network-relay', shutil.which('network-relay')]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    raise SystemExit('network-relay program not found: run cargo build --release first, '
                     'or pass it with --binary.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--host', required=True, help='relay domain')
    parser.add_argument('--user', required=True)
    parser.add_argument('--password', help='prompted for if omitted (recommended: it stays out of the shell history)')
    parser.add_argument('--port', type=int, default=443)
    parser.add_argument('--out', type=Path, help='default: <host>-<user>.mobileconfig')
    parser.add_argument('--name', help='name shown in Settings')
    parser.add_argument('--services', type=Path, action='append',
                        help='domain list file, repeatable; '
                        'default domains/google-ai-social.txt and domains/global-services.txt')
    gfw = parser.add_mutually_exclusive_group()
    gfw.add_argument('--gfwlist-file', type=Path, help='use an already downloaded gfwlist instead of downloading it')
    gfw.add_argument('--no-gfwlist', action='store_true', help='use only the service lists, without the gfwlist')
    parser.add_argument('--gfwlist-url', default=GFWLIST_URL)
    add_service_rule_arguments(parser)
    parser.add_argument('--ui-toggle-enabled', choices=['true', 'false'], default='true',
                        help='whether the relay can be turned off in Settings (iOS/macOS 26+), default true: '
                        'with false, an unreachable relay breaks every listed domain until the profile is removed')
    parser.add_argument('--allow-dns-failover', choices=['true', 'false'],
                        help='omitted by default, leaving the system default (off)')
    parser.add_argument('--binary', type=Path, help='network-relay program, default target/release or PATH')
    args = parser.parse_args(argv)

    services = []
    for path in args.services or [DOMAINS / 'google-ai-social.txt', DOMAINS / 'global-services.txt']:
        services += load_domain_file(path)
    gfwlist_text = None
    if args.gfwlist_file:
        with args.gfwlist_file.open('rb') as stream:
            gfwlist_text = decode_gfwlist(read_bounded(stream))
    elif not args.no_gfwlist:
        with urllib.request.urlopen(args.gfwlist_url, timeout=60) as response:
            gfwlist_text = decode_gfwlist(read_bounded(response))
    domains, stats = build_domains(services, gfwlist_text)
    if gfwlist_text is not None and not extract_gfwlist(gfwlist_text)[0]:
        raise ValueError('gfwlist contains no convertible domains; refusing a partial profile.')
    if not args.no_service_rules:
        domains += load_service_rules(args.rules_dir)
    host = args.host.lower().removesuffix('.')
    domains = normalized_domains(domains, host)
    if not domains:
        raise ValueError('No matched domains remain; an empty Apple match list would relay all traffic.')

    password = args.password or getpass.getpass('Password: ')
    out = args.out or Path(f'{host}-{args.user}.mobileconfig')
    command = [str(find_binary(args.binary)), 'profile', '--host', host, '--user', args.user, '--port', str(args.port),
               '--ui-toggle-enabled', args.ui_toggle_enabled, '--exclude-domain', host,
               '--match-domain', 'example.invalid', '--no-http3']
    if args.name:
        command += ['--name', args.name]
    if args.allow_dns_failover:
        command += ['--allow-dns-failover', args.allow_dns_failover]
    # The password goes through standard input, not the process list.
    if out.is_symlink() or (out.exists() and not out.is_file()):
        raise ValueError('Refusing to overwrite a non-regular profile file.')
    with tempfile.TemporaryDirectory(prefix='.relay-profile-', dir=out.parent) as directory:
        candidate = Path(directory) / 'device.mobileconfig'
        subprocess.run(command + ['--out', str(candidate)], input=password + '\n', text=True,
                       check=True, stdout=subprocess.DEVNULL)
        data = profile_with_domains(candidate.read_bytes(), domains)
        if len(data) >= MAX_DEVICE_PROFILE_BYTES:
            raise ValueError(f'The single profile is {len(data)} bytes, exceeding the iPhone 524288-byte limit.')
        candidate.write_bytes(data)
        candidate.chmod(0o600)
        os.replace(candidate, out)
    print(f'Wrote {out} (contains the password, mode 600; delete it after installing): '
          f'{len(domains)} matched domains, {host} excluded.')
    for name, number in stats.items():
        print(f'  gfwlist: {name}: {number}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
