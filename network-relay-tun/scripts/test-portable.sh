#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
export CARGO_HOME="$root/.cargo"
export CARGO_TARGET_DIR="$root/target"
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4}
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
python3 "$root/tests/test_isolation.py"
bash -n "$root/build-macos.sh" "$root/scripts/install-helper.sh" "$root/scripts/uninstall-helper.sh"
# Keep these sequential. Different dependency graphs must not replace artifacts
# while rustdoc is reading them from the shared project-local target directory.
cargo test --locked --manifest-path "$root/Core/Cargo.toml"
cargo test --locked --manifest-path "$root/Host/Cargo.toml"
cargo test --locked --manifest-path "$root/TunEngine/Cargo.toml" --tests
cargo test --locked --manifest-path "$root/TunEngine/Cargo.toml" -p ipstack --lib
cargo test --locked --manifest-path "$root/TunEngine/Cargo.toml" -p tun2proxy --lib
