#!/usr/bin/env python3
"""Package the deployment files as a standalone Bash installer, without compiling Rust."""

import argparse
import base64
import gzip
import hashlib
import io
from pathlib import Path
import tarfile
import textwrap

ROOT = Path(__file__).resolve().parent.parent
FILES = (
    'deploy/install-debian13.sh', 'deploy/install.py', 'deploy/global-profile.py',
    'deploy/network-relay.service', 'deploy/certbot-hook.sh',
    'deploy/domains/google-ai-social.txt', 'deploy/domains/public-suffix-icann.dat',
    'deploy/domains/LICENSE.domain-list-community', 'deploy/domains/README.md',
    'docs/deploy-debian13.md',
)


def package(out):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        for relative in FILES:
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
# Includes deployment files and ICANN suffixes; downloads gfwlist only.
set -Eeuo pipefail
if [[ ${1:-} != --help && ${1:-} != -h && $EUID != 0 ]]; then
    echo '请使用 sudo bash /tmp/network-relay-install.sh 运行。' >&2
    exit 1
fi
for option in "$@"; do
    if [[ $option == --build-from-source ]]; then
        echo '此脚本仅安装预编译二进制；源码编译请使用完整源码中的安装器。' >&2
        exit 1
    fi
done
bundle_dir=$(mktemp -d "${TMPDIR:-/tmp}/network-relay-installer.XXXXXX")
trap 'rm -rf -- "$bundle_dir"' EXIT
base64 --decode <<'NETWORK_RELAY_DEPLOYMENT_BUNDLE' | tar -xz -C "$bundle_dir"
''' + payload + '''
NETWORK_RELAY_DEPLOYMENT_BUNDLE
bash "$bundle_dir/deploy/install-debian13.sh" "$@" --refresh-profile
'''
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(script)
    out.chmod(0o755)
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    out.with_name(out.name + '.sha256').write_text(f'{digest}  {out.name}\n')
    print(f'Wrote {out}: {out.stat().st_size} bytes; {len(FILES)} deployment files; no compiler required.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=Path('dist/network-relay-install.sh'))
    package(parser.parse_args().out)
