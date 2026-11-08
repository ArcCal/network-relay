#!/usr/bin/env bash
set -euo pipefail
unset CDPATH
for CF_BUILD_ARG in "$@"; do
    case $CF_BUILD_ARG in
        -h|--help) cargo build --help; exit ;;
        --manifest-path|--manifest-path=*|--target-dir|--target-dir=*|--build-dir|--build-dir=*|--config|--config=*)
            printf 'Source and cache path overrides are not supported: %s\n' "$CF_BUILD_ARG" >&2
            exit 2 ;;
    esac
done
CF_BUILD_ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
# The helper re-executes a child; its cross-process environment is tested separately.
# shellcheck source=/dev/null
source "$CF_BUILD_ROOT/../tools/fresh-build-source.sh"
relay_require_fresh_source "$CF_BUILD_ROOT/.." network-relay-cf-masque/scripts/build.sh "$@"
# Retain caller configuration before the project test environment is loaded.
export RELAY_BUILD_ORIGINAL_CARGO_HOME=${RELAY_BUILD_ORIGINAL_CARGO_HOME:-${CARGO_HOME:-$HOME/.cargo}}
# shellcheck source=network-relay-cf-masque/scripts/env.sh
# shellcheck disable=SC1091
source "$CF_BUILD_ROOT/scripts/env.sh"
CF_CARGO_ARGS=(build --locked --release --bin network-relay-cf-masque)
CF_TARGETS=("")
CF_TARGET_INDEX=0
CF_BUILD_JOBS=$CARGO_BUILD_JOBS
while (( $# )); do
    case $1 in
        --target)
            [[ $# -ge 2 ]] || { printf 'Pass a value to --target.\n' >&2; exit 2; }
            CF_TARGETS[CF_TARGET_INDEX]=$2; CF_TARGET_INDEX=$((CF_TARGET_INDEX + 1))
            CF_CARGO_ARGS+=("$1" "$2"); shift ;;
        --target=*)
            CF_TARGETS[CF_TARGET_INDEX]=${1#--target=}; CF_TARGET_INDEX=$((CF_TARGET_INDEX + 1))
            CF_CARGO_ARGS+=("$1") ;;
        --jobs|-j)
            [[ $# -ge 2 ]] || { printf 'Pass a value to --jobs.\n' >&2; exit 2; }
            CF_BUILD_JOBS=$2; shift ;;
        --jobs=*) CF_BUILD_JOBS=${1#--jobs=} ;;
        -j?*) CF_BUILD_JOBS=${1#-j} ;;
        *) CF_CARGO_ARGS+=("$1") ;;
    esac
    shift
done
if [[ $(uname -s) == Linux ]]; then
    CF_BUILD_JOBS=$(relay_build_memory_jobs "$CF_BUILD_JOBS") || exit 1
fi
CF_BUILD_WORK=${RELAY_BUILD_WORK_ROOT:-"$CF_BUILD_ROOT/.build-work"}
mkdir -p -- "$CF_BUILD_WORK"
export RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-stable}
if (( CF_TARGET_INDEX )); then
    relay_prepare_build_environment "$CF_BUILD_WORK" "${CF_TARGETS[@]}"
else
    relay_prepare_build_environment "$CF_BUILD_WORK"
fi
export CARGO_TARGET_DIR="$RELAY_BUILD_WORK_ROOT/rust-cf-target"
CF_BUILD_OUTPUT=$CF_RELAY_ROOT
[[ -z ${RELAY_BUILD_OUTPUT_ROOT:-} ]] || CF_BUILD_OUTPUT="$RELAY_BUILD_OUTPUT_ROOT/network-relay-cf-masque"
cd "$CF_RELAY_ROOT"
if [[ $RELAY_REUSE_RUST_TOOLCHAIN != 1 ]]; then
    rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal
    if (( CF_TARGET_INDEX )); then rustup target add --toolchain "$RUSTUP_TOOLCHAIN" "${CF_TARGETS[@]}"; fi
fi
cargo "${CF_CARGO_ARGS[@]}" --jobs "$CF_BUILD_JOBS"
for CF_TARGET in "${CF_TARGETS[@]}"; do
    CF_TARGET=${CF_TARGET##*/}; CF_TARGET=${CF_TARGET%.json}
    CF_TARGET=${CF_TARGET:+$CF_TARGET/}
    mkdir -p -- "$CF_BUILD_OUTPUT/target/${CF_TARGET}release"
    install -m 755 "$CARGO_TARGET_DIR/${CF_TARGET}release/network-relay-cf-masque" \
        "$CF_BUILD_OUTPUT/target/${CF_TARGET}release/network-relay-cf-masque"
done
printf 'Built project: %s\nArtifacts: %s/target\n' "$CF_RELAY_ROOT" "$CF_BUILD_OUTPUT"
