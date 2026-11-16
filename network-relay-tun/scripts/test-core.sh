#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
# Keep downloads and compilation independent of sibling projects.
export CARGO_HOME="$root/.cargo"
export CARGO_TARGET_DIR="$root/target"
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4}
cargo test --locked --manifest-path "$root/Core/Cargo.toml" "$@"
