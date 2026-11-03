#!/usr/bin/env bash
# The interoperability tests against a real Xray-core server. Pass the
# binary in XRAY_BIN, or have Go installed: Xray-core is then built from
# its source at XRAY_TAG (Go verifies modules against its checksum
# database). A missing binary is a failure, not a skip.
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
XRAY_TAG=${XRAY_TAG:-v26.10.31}
if [[ -z ${XRAY_BIN:-} ]]; then
    command -v go >/dev/null || { echo 'Set XRAY_BIN to an Xray-core binary, or install Go to build one.' >&2; exit 1; }
    source_dir=target/xray-src
    if [[ ! -d $source_dir/.git ]]; then
        git clone --quiet --depth 1 --branch "$XRAY_TAG" https://github.com/XTLS/Xray-core.git "$source_dir"
    fi
    (cd "$source_dir" && GOTOOLCHAIN=auto GOFLAGS=-mod=readonly go build -trimpath -o ../xray ./main)
    XRAY_BIN=$PWD/target/xray
fi
export XRAY_BIN
"$XRAY_BIN" version | head -n 1
cargo test --locked --test xray_interop -- --ignored --test-threads=1
