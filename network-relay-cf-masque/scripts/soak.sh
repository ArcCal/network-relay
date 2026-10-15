#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/env.sh"
cd "$CF_RELAY_ROOT"
# The runner verifies immutable clients and all finite packet-backed targets
# before copying a fixed executable and starting the real-time soak.
exec python3 scripts/test-matrix.py --soak-seconds "${SOAK_SECONDS:-3900}"
