#!/usr/bin/env python3
"""Package a prebuilt-binary installer or a complete source-compiling installer."""

import argparse
import base64
import gzip
import hashlib
import io
import os
from pathlib import Path
import tarfile
import textwrap

ROOT = Path(__file__).resolve().parent.parent
FILES = (
    'deploy/install-debian13.sh', 'deploy/install-from-source.sh', 'deploy/install.py', 'deploy/global-profile.py',
    'deploy/network-relay.service', 'deploy/certbot-hook.sh',
    'deploy/domains/google-ai-social.txt', 'deploy/domains/public-suffix-icann.dat',
    'deploy/domains/LICENSE.domain-list-community', 'deploy/domains/README.md',
    'docs/deploy-debian13.md',
    'tools/fresh-build-source.sh',
    'tools/linux-build-memory.sh',
    'tools/run-build-child.sh',
)


def package(out, source=False):
    files = list(FILES)
    if source:
        files += ['Cargo.toml', 'Cargo.lock', 'deploy/relay.example.toml']
        files += sorted(str(p.relative_to(ROOT)) for p in (ROOT / 'src').rglob('*.rs'))
        files += sorted(str(p.relative_to(ROOT)) for p in (ROOT / 'vendor').rglob('*') if p.is_file())
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        for relative in files:
            data = (ROOT / relative).read_bytes()
            entry = tarfile.TarInfo(relative)
            entry.size = len(data)
            entry.mode = 0o644
            archive.addfile(entry, io.BytesIO(data))
    compressed = bytearray(gzip.compress(stream.getvalue(), mtime=0))
    compressed[9] = 255  # Stable gzip OS byte across Python 3.12 and 3.13.
    payload = '\n'.join(textwrap.wrap(base64.b64encode(compressed).decode(), 76))
    script = '''#!/usr/bin/env bash
# Debian 12/13 x86_64: upload /tmp/network-relay, then sudo bash this script.
# Includes deployment files and ICANN suffixes; downloads gfwlist and eighteen service lists.
set -Eeuo pipefail
if [[ ${1:-} != --help && ${1:-} != -h && $EUID != 0 ]]; then
    echo 'Run this script with sudo bash /tmp/network-relay-install.sh.' >&2
    exit 1
fi
'''
    if not source:
        script += '''for option in "$@"; do
    if [[ $option == --build-from-source ]]; then
        echo 'This script installs prebuilt binaries only; use the installer in the full source tree to compile from source.' >&2
        exit 1
    fi
done
'''
    script += '''
bundle_dir=$(mktemp -d "/tmp/network-relay-installer-$(date +%Y%m%d-%H%M%S).XXXXXX")
trap 'rm -rf -- "$bundle_dir"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
base64 --decode <<'NETWORK_RELAY_DEPLOYMENT_BUNDLE' | tar -xz -C "$bundle_dir"
''' + payload + '''
NETWORK_RELAY_DEPLOYMENT_BUNDLE
'''
    entry = 'install-from-source.sh' if source else 'install-debian13.sh'
    script += f'bash "$bundle_dir/deploy/{entry}" "$@"' + ('' if source else ' --refresh-profile') + '\n'
    if source:
        script = script.replace('# Debian 12/13 x86_64: upload /tmp/network-relay, then sudo bash this script.',
                                '# Debian 12/13 x86_64: download current complete source and compile on the VPS.')
        script = script.replace('/tmp/network-relay-install.sh', '/tmp/network-relay-install-from-source.sh')
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(script)
    out.chmod(0o755)
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    out.with_name(out.name + '.sha256').write_text(f'{digest}  {out.name}\n')
    mode = 'source compilation on VPS' if source else 'no compiler required'
    print(f'Wrote {out}: {out.stat().st_size} bytes; {len(files)} bundled files; {mode}.')


def open_dirs(*roots):
    """Leave the source and artifact folders, and every folder below them, open to all users."""
    for root in roots:
        for folder, _, _ in os.walk(root):
            try:
                os.chmod(folder, 0o777)
            except OSError:
                pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--source', action='store_true', help='bundle Rust sources and compile on the VPS')
    args = parser.parse_args()
    out = args.out or Path('dist/network-relay-install-from-source.sh' if args.source else 'dist/network-relay-install.sh')
    package(out, args.source)
    open_dirs(ROOT, out.resolve().parent)
