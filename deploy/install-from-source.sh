#!/usr/bin/env bash
# Download current source, compile, obtain/renew certificates and generate a profile.
set -Eeuo pipefail
unset CDPATH
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
bash "$script_dir/install-debian13.sh" "$@" --build-from-source --refresh-profile
