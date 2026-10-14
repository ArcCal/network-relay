#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/env.sh"
cd "$CF_RELAY_ROOT"
cargo build --locked --release --bin network-relay-cf-masque "$@"
printf 'Built project: %s\n' "$CF_RELAY_ROOT"
