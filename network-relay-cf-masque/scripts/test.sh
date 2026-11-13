#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/env.sh"
cd "$CF_RELAY_ROOT"
python3 scripts/verify-smoltcp.py --test
python3 scripts/prepare-client-tests.py
cargo test --locked --workspace --all-features -- --test-threads=1
cargo clippy --locked --workspace --all-targets --all-features --no-deps -- -D warnings
for CF_RELAY_PACKAGE in network-relay-cf-masque warp-masque-egress; do
  cargo fmt --package "$CF_RELAY_PACKAGE" --check
done
cargo check --locked --manifest-path examples/reuse/Cargo.toml
# The relay, its vendored h3 and the tests both servers share are network-relay's.
(cd .. && cargo test --locked && NETWORK_RELAY_TEST_EGRESS=loopback cargo test --locked --test in_process)
