#!/usr/bin/env bash
# Run from the deployment bundle or source ZIP; defaults to /tmp/network-relay.
set -Eeuo pipefail
unset CDPATH
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ ${1:-} == --help || ${1:-} == -h ]]; then
    exec python3 "$script_dir/install.py" --help
fi
[[ $EUID == 0 ]] || { echo 'Run as root: sudo bash deploy/install-debian13.sh ...' >&2; exit 1; }
# shellcheck source=/etc/os-release
source /etc/os-release
[[ $ID == debian && ($VERSION_ID == 12 || $VERSION_ID == 13) && $(uname -m) == x86_64 ]] || {
    echo 'This script supports only Debian 12/13 x86_64.' >&2; exit 1;
}
[[ -d /run/systemd/system ]] || { echo 'A Debian VPS booted with systemd is required.' >&2; exit 1; }
if ! command -v python3 >/dev/null; then
    # Wait for unattended-upgrades on a freshly booted VPS instead of failing.
    apt-get -o DPkg::Lock::Timeout=1800 update
    DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=1800 install -y --no-install-recommends python3
fi
exec python3 "$script_dir/install.py" "$@"
