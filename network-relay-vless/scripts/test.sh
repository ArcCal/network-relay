#!/usr/bin/env bash
# Formatting, lints and the tests that need no VLESS server.
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
