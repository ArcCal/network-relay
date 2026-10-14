#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/env.sh"
cd "$CF_RELAY_ROOT"
python3 scripts/prepare-client-tests.py
python3 scripts/verify-provenance.py
cargo test --locked --workspace --all-features -- --test-threads=1
cargo clippy --locked --workspace --all-targets --all-features --no-deps -- -D warnings
# Preserve immutable vendored protocol/client source snapshots byte for byte.
for CF_RELAY_PACKAGE in network-relay-cf-masque relay-frontend warp-masque-egress; do
  cargo fmt --package "$CF_RELAY_PACKAGE" --check
done
cargo test --locked --manifest-path vendor/h3/Cargo.toml --all-features
cargo test --locked --manifest-path vendor/h3-quinn/Cargo.toml --all-features
cargo check --locked --manifest-path examples/reuse/Cargo.toml
