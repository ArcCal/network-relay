#!/usr/bin/env python3
"""Package a prebuilt-binary installer or a complete source-compiling installer."""

import argparse
import base64
import gzip
import hashlib
import io
import os
from pathlib import Path
import secrets
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


def check_output(path):
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError(f'Refusing a linked or non-regular package output: {path}')


def create_output_directory(parent):
    """Bound every new parent's mode without widening existing directories."""
    missing = []
    current = parent
    while not current.exists():
        missing.append(current)
        current = current.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o755, exist_ok=True)


def atomic_write(path, data, mode, *, force_mode=False):
    check_output(path)
    temporary = path.parent / ('.relay-installer-' + secrets.token_hex(16))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, mode)
    try:
        try:
            # Keep ownership if constructing the buffered stream fails.
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                if force_mode:
                    os.fchmod(stream.fileno(), mode)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(fd)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def package(out, source=False):
    checksum = out.with_name(out.name + '.sha256')
    for path in (out, checksum):
        check_output(path)
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
    create_output_directory(out.parent)
    data = script.encode()
    digest = hashlib.sha256(data).hexdigest()
    checksum_mode = checksum.stat().st_mode & 0o777 if checksum.exists() else 0o644
    atomic_write(out, data, 0o755, force_mode=True)
    atomic_write(checksum, f'{digest}  {out.name}\n'.encode(), checksum_mode, force_mode=checksum.exists())
    mode = 'source compilation on VPS' if source else 'no compiler required'
    print(f'Wrote {out}: {out.stat().st_size} bytes; {len(files)} bundled files; {mode}.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--source', action='store_true', help='bundle Rust sources and compile on the VPS')
    args = parser.parse_args()
    out = args.out or Path('dist/network-relay-install-from-source.sh' if args.source else 'dist/network-relay-install.sh')
    package(out, args.source)
