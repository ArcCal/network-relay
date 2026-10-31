#!/usr/bin/env bash
# Source this file before building or running project tests.
CF_RELAY_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export CARGO_HOME="$CF_RELAY_ROOT/.build/cargo-home"
export CARGO_TARGET_DIR="$CF_RELAY_ROOT/target"
unset CARGO_BUILD_TARGET
export TMPDIR="$CF_RELAY_ROOT/target/test-runtime"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}"
mkdir -p "$CARGO_HOME" "$CARGO_TARGET_DIR" "$TMPDIR"
