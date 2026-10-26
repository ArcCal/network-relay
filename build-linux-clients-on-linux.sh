#!/usr/bin/env bash
# Run on Linux only; build Linux headless clients for amd64 and arm64.
# Sourcing defines helpers without installing tools or building products.

lc_usage() {
    cat <<'HELP'
Usage: bash build-linux-clients-on-linux.sh [--repo DIR] [--output DIR]
                                           [--jobs N] [--check]
                                           [--install-deps | --no-install-deps]

Run ONLY on Linux and build the headless Network Relay RS client for BOTH
Linux amd64 (x64) and arm64. No macOS files, GUI apps or servers are built.
Supported hosts: Debian 13 x64; Ubuntu 26.04 x64 or arm64.

  --repo DIR       persistent main checkout (default: ~/network-relay or
                   NETWORK_RELAY_SRC); clone if absent, otherwise pull --ff-only
  --output DIR     new or empty artifact directory (default: a new directory
                   under the current working directory)
  --jobs N         Rust compilation parallelism (default: 2)
  Dependencies     install missing build prerequisites automatically (default)
  --install-deps   also refresh/install the apt prerequisite package set
  --no-install-deps
                   require existing build tools and Rust targets; install none
  --check          inspect host/tools offline without installing or building

Every build executes this script from the freshly fetched main commit and
uses a private committed source snapshot. Local commits are refused; dirty
and untracked caller files are preserved and never built. Git credentials or
NETWORK_RELAY_TOKEN must allow reading ArcCal/network-relay. An existing gh
login is used without changing global Git configuration.

Rust 1.99.0 (or RUSTUP_TOOLCHAIN), Zig and cargo-zigbuild produce static musl
executables named network-relay-rs-linux-amd64 and -arm64. Both architectures
are inspected; native files also run --version and --help. SHA256SUMS,
MANIFEST.txt and logs stay with the artifacts. Failed builds keep .work.
No client is installed or connected and no system proxy settings are changed.
HELP
}

lc_die() { printf 'build-linux-clients-on-linux: %s\n' "$*" >&2; exit 1; }

lc_value() { [[ $# -ge 2 && -n $2 && $2 != --* ]] || lc_die "Pass a value to $1."; }

lc_physical_dir() { REPLY=$(cd -P -- "$1" && printf '%s/' "$PWD"); REPLY=${REPLY%/}; }

lc_empty_dir() {
    local entries
    [[ -r $1 && -x $1 ]] || return 1
    entries=$(ls -A -- "$1" && printf '.') || return 1
    [[ $entries == . ]]
}

lc_host() {
    [[ $(uname -s) == Linux && -r /etc/os-release ]] || lc_die 'A supported Linux VPS is required.'
    # This file is the operating system's trusted platform description.
    # shellcheck disable=SC1091
    source /etc/os-release
    case ${ID:-}:${VERSION_ID:-}:$(uname -m) in
        debian:13:x86_64) platform=debian-13-amd64; host_arch=amd64 ;;
        ubuntu:26.04:x86_64) platform=ubuntu-26.04-amd64; host_arch=amd64 ;;
        ubuntu:26.04:aarch64|ubuntu:26.04:arm64) platform=ubuntu-26.04-arm64; host_arch=arm64 ;;
        *) lc_die 'Supported hosts: Debian 13 x64, Ubuntu 26.04 x64 or Ubuntu 26.04 arm64.' ;;
    esac
}

lc_check_tools() {
    local missing=0 tool targets triple
    for tool in git curl cc pkg-config file sha256sum rustup rustc cargo zig cargo-zigbuild readelf; do
        if command -v "$tool" >/dev/null; then printf '  %s: available\n' "$tool";
        else printf '  %s: missing\n' "$tool" >&2; missing=1; fi
    done
    if command -v rustup >/dev/null; then
        if ! rustup which --toolchain "${RUSTUP_TOOLCHAIN:-1.99.0}" rustc >/dev/null 2>&1; then
            printf '  Rust toolchain %s: missing\n' "${RUSTUP_TOOLCHAIN:-1.99.0}" >&2
            missing=1
        else
            targets=$(rustup target list --installed --toolchain "${RUSTUP_TOOLCHAIN:-1.99.0}") || missing=1
            for triple in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
                if ! grep -Fxq "$triple" <<< "${targets:-}"; then
                    printf '  Rust target %s: missing\n' "$triple" >&2; missing=1
                fi
            done
        fi
    fi
    return "$missing"
}

lc_install_system() {
    local apt_command=(apt-get)
    if (( EUID != 0 )); then
        command -v sudo >/dev/null || lc_die '--install-deps requires root or sudo.'
        apt_command=(sudo apt-get)
    fi
    "${apt_command[@]}" update
    "${apt_command[@]}" install -y --no-install-recommends \
        build-essential pkg-config ca-certificates curl git file binutils python3-venv
}

lc_ensure_system() {
    local tool missing=0 needs_python=0
    for tool in git curl cc pkg-config file sha256sum readelf; do
        if ! command -v "$tool" >/dev/null; then
            printf 'Missing system prerequisite: %s\n' "$tool"
            missing=1
        fi
    done
    [[ -s /etc/ssl/certs/ca-certificates.crt ]] || missing=1
    if ! command -v zig >/dev/null; then
        needs_python=1
        if ! command -v python3 >/dev/null || ! python3 -c 'import ensurepip, venv' >/dev/null 2>&1; then
            printf 'Missing Python venv support for the Zig installer.\n'
            missing=1
        fi
    fi
    (( missing )) || return 0
    (( install_deps )) || lc_die 'Missing system prerequisites and --no-install-deps was selected.'
    lc_install_system
    for tool in git curl cc pkg-config file sha256sum readelf; do
        command -v "$tool" >/dev/null || lc_die "System package installation did not provide $tool."
    done
    [[ -s /etc/ssl/certs/ca-certificates.crt ]] || lc_die 'System CA certificates are unavailable.'
    if (( needs_python )); then
        python3 -c 'import ensurepip, venv' >/dev/null 2>&1 || lc_die 'Python venv support is unavailable after package installation.'
    fi
}

lc_install_rustup() {
    local installer
    if ! command -v rustup >/dev/null; then
        (( install_deps )) || lc_die 'Missing rustup; use --install-deps.'
        installer=$(mktemp)
        curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs -o "$installer" || {
            rm -f -- "$installer"; lc_die 'Cannot download rustup.';
        }
        sh "$installer" -y --profile minimal --default-toolchain none --no-modify-path || {
            rm -f -- "$installer"; lc_die 'Cannot install rustup.';
        }
        rm -f -- "$installer"
    fi
}

lc_remote_git() {
    # A signed-in gh session can read private sources without global Git changes.
    # Existing credential helpers remain available before this fallback helper.
    if command -v gh >/dev/null; then
        GIT_TERMINAL_PROMPT=0 git -c 'credential.helper=!gh auth git-credential' "$@"
    else
        GIT_TERMINAL_PROMPT=0 git "$@"
    fi
}

lc_token_git() {
    local token=${NETWORK_RELAY_TOKEN:-} header
    [[ -n $token ]] || { printf 'Configure Git credentials or NETWORK_RELAY_TOKEN.\n' >&2; return 1; }
    header=$(printf 'x-access-token:%s' "$token" | base64 | tr -d '\n') || return
    GIT_TERMINAL_PROMPT=0 GIT_CONFIG_COUNT=2 \
        GIT_CONFIG_KEY_0=credential.helper GIT_CONFIG_VALUE_0='' \
        GIT_CONFIG_KEY_1=http.https://github.com/.extraheader \
        GIT_CONFIG_VALUE_1="Authorization: Basic $header" git "$@"
}

lc_update_checkout() {
    local actual_root remote selected_branch fetched has_repo=0
    while [[ $checkout == */ && $checkout != / ]]; do checkout=${checkout%/}; done
    if [[ -e $checkout || -L $checkout ]]; then
        if [[ -d $checkout && -e $checkout/.git ]]; then has_repo=1;
        elif [[ ! -d $checkout || -L $checkout ]] || ! lc_empty_dir "$checkout"; then
            lc_die "Existing path is not a Git checkout: $checkout"
        fi
    fi
    if (( has_repo )); then
        lc_physical_dir "$checkout"; checkout=$REPLY
        actual_root=$(git -C "$checkout" rev-parse --show-toplevel && printf '.') || lc_die 'Cannot inspect checkout root.'
        actual_root=${actual_root%.}; actual_root=${actual_root%$'\n'}
        [[ $actual_root == "$checkout" ]] || lc_die 'Select the repository root.'
        remote=$(git -C "$checkout" config --get remote.origin.url) || lc_die 'Cannot read origin.'
        case $remote in
            https://github.com/ArcCal/network-relay|https://github.com/ArcCal/network-relay.git|git@github.com:ArcCal/network-relay.git|ssh://git@github.com/ArcCal/network-relay.git) ;;
            *) lc_die 'origin must point to ArcCal/network-relay on GitHub.' ;;
        esac
        selected_branch=$(git -C "$checkout" symbolic-ref --short HEAD) || lc_die 'Use a main checkout, not detached HEAD.'
        [[ $selected_branch == main ]] || lc_die 'Use a main checkout; other branches are left unchanged.'
        printf '==> Updating existing checkout with pull --ff-only\n'
        if ! lc_remote_git -C "$checkout" pull --ff-only origin main; then
            lc_token_git -C "$checkout" pull --ff-only origin main || lc_die 'Cannot fast-forward checkout.'
        fi
        fetched=$(git -C "$checkout" rev-parse --verify FETCH_HEAD) || lc_die 'Cannot identify fetched commit.'
    else
        printf '==> Cloning ArcCal/network-relay\n'
        if ! lc_remote_git clone --depth 1 --single-branch --branch main -- https://github.com/ArcCal/network-relay.git "$checkout"; then
            if [[ -e $checkout || -L $checkout ]]; then
                if [[ ! -d $checkout || -L $checkout ]] || ! lc_empty_dir "$checkout"; then
                    lc_die 'Clone failed; existing destination preserved.'
                fi
            fi
            lc_token_git clone --depth 1 --single-branch --branch main -- https://github.com/ArcCal/network-relay.git "$checkout" || lc_die 'Cannot clone checkout.'
        fi
        lc_physical_dir "$checkout"; checkout=$REPLY
        fetched=$(git -C "$checkout" rev-parse --verify refs/remotes/origin/main) || lc_die 'Cannot identify cloned commit.'
    fi
    root_commit=$(git -C "$checkout" rev-parse --verify HEAD) || lc_die 'Cannot identify checkout commit.'
    [[ $root_commit == "$fetched" ]] || lc_die 'Local commits differ from fetched main; no local files were reset.'
}

lc_prepare_rust() {
    rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal
    rustup target add --toolchain "$RUSTUP_TOOLCHAIN" x86_64-unknown-linux-musl aarch64-unknown-linux-musl
    rustc --version
}

lc_prepare_cross_tools() {
    if ! command -v zig >/dev/null; then
        (( install_deps )) || lc_die 'Install Zig or use --install-deps.'
        python3 -m venv "$work/zig-venv"
        "$work/zig-venv/bin/python" -m pip install --only-binary=:all: ziglang==0.14.1
        local zig_binary
        zig_binary=$("$work/zig-venv/bin/python" -c 'import pathlib, ziglang; print(pathlib.Path(ziglang.__file__).parent / "zig")')
        mkdir -p -- "$work/tools/bin"
        ln -s -- "$zig_binary" "$work/tools/bin/zig"
    fi
    if ! command -v cargo-zigbuild >/dev/null; then
        (( install_deps )) || lc_die 'Install cargo-zigbuild or use --install-deps.'
        cargo install --locked --version 0.24.0 --jobs "$jobs" --root "$work/tools" cargo-zigbuild
    fi
    zig version
    cargo-zigbuild --version
}

lc_run() {
    local name=$1 status
    shift
    printf '==> %s\n' "$name"
    set +e
    ( set -euo pipefail; "$@" ) > "$output/logs/$name.log" 2>&1
    status=$?
    set -e
    if (( status )); then
        printf '    FAILED (exit %s); log: %s/logs/%s.log\n' "$status" "$output" "$name" >&2
        tail -n 20 "$output/logs/$name.log" >&2
        failures=$((failures + 1))
    else printf '    ok\n'; fi
    return 0
}

lc_build_rust() {
    local manifest=$1 target_dir=$2 triple=$3
    shift 3
    cd -- "$(dirname -- "$manifest")"
    cargo zigbuild --locked --release --manifest-path "$manifest" \
        --target "$triple" --target-dir "$target_dir" --jobs "$jobs" "$@"
}

lc_collect() {
    local source=$1 arch=$2 description headers
    [[ -f $source && -s $source && -x $source ]] || lc_die "Missing executable: $source"
    description=$(LC_ALL=C file -b -- "$source")
    case $arch in
        amd64) [[ $description == ELF* && $description == *x86-64* ]] ;;
        arm64) [[ $description == ELF* && $description == *aarch64* ]] ;;
        *) false ;;
    esac || lc_die "Wrong architecture: $description"
    headers=$(LC_ALL=C readelf -l -d -- "$source")
    [[ $description == *static* && $headers != *INTERP* && $headers != *NEEDED* ]] ||
        lc_die "Artifact must be static: $source"
    if [[ $arch == "$host_arch" ]]; then
        "$source" --version
        "$source" --help
    fi
    install -m 755 -- "$source" "$output/network-relay-rs-linux-$arch"
}

lc_main() {
    checkout=${NETWORK_RELAY_SRC:-"$HOME/network-relay"}
    # 2: install missing prerequisites; 1: additionally refresh apt; 0: opt out.
    output=; jobs=2; install_deps=2
    local check_only=0
    while (( $# )); do
        case $1 in
            -h|--help) lc_usage; return ;;
            --repo) lc_value "$@"; checkout=$2; shift 2 ;;
            --output) lc_value "$@"; output=$2; shift 2 ;;
            --jobs) lc_value "$@"; jobs=$2; shift 2 ;;
            --install-deps) install_deps=1; shift ;;
            --no-install-deps) install_deps=0; shift ;;
            --check) check_only=1; shift ;;
            *) lc_usage >&2; lc_die "Unknown argument: $1" ;;
        esac
    done
    [[ $jobs =~ ^[1-9][0-9]*$ ]] || lc_die '--jobs must be a positive integer.'
    (( ! check_only || install_deps != 1 )) || lc_die '--check and --install-deps conflict.'
    lc_host
    export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
    if (( check_only )); then
        printf 'Build host: %s; targets: linux-amd64, linux-arm64 (static)\n' "$platform"
        lc_check_tools
        return
    fi
    (( install_deps != 1 )) || lc_install_system
    if ! command -v git >/dev/null; then
        (( install_deps )) || lc_die 'Missing git and --no-install-deps was selected.'
        lc_install_system
    fi
    lc_update_checkout
    stage=$(mktemp -d /tmp/network-relay-linux-clients.XXXXXX) || lc_die 'Cannot create private workspace.'
    trap 'status=$?; if (( status )); then printf "Update failed (exit %s). Work: %s\n" "$status" "$stage" >&2; fi' EXIT
    printf '%s\n' "$root_commit" > "$stage/.owner"
    git -C "$checkout" show "$root_commit:build-linux-clients-on-linux.sh" > "$stage/driver.sh" || lc_die 'Cannot load newest committed script.'
    [[ -s $stage/driver.sh ]] || lc_die 'Newest build script is empty.'
    exec "$BASH" "$stage/driver.sh" --build-updated "$checkout" "$stage" "$output" "$root_commit" "$jobs" "$install_deps" --deps-policy-v2
}

# Sourcing is reserved for read-only helper tests.
[[ ${BASH_SOURCE[0]} == "$0" ]] || return 0
set -euo pipefail
unset CDPATH
# Parse the complete conditional before pull can replace the running file.
if [[ ${1:-} != --build-updated ]]; then lc_main "$@"; exit; fi
[[ $# == 8 && ${8:-} == --deps-policy-v2 ]] || lc_die 'Invalid internal build invocation.'
checkout=$2; stage=$3; output=$4; root_commit=$5; jobs=$6; install_deps=$7
[[ $root_commit =~ ^[0-9a-f]{40}$ && $jobs =~ ^[1-9][0-9]*$ &&
   ( $install_deps == 0 || $install_deps == 1 || $install_deps == 2 ) ]] || lc_die 'Invalid build options.'
[[ ${stage##*/} == network-relay-linux-clients.* && -d $stage && ! -L $stage &&
   -f $stage/.owner && ! -L $stage/.owner && $(cat "$stage/.owner") == "$root_commit" ]] || lc_die 'Invalid private workspace.'
trap 'status=$?; if (( status )); then printf "Build incomplete (exit %s). Work: %s; artifacts/logs: %s\n" "$status" "$stage" "${output:-not created}" >&2; fi' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
lc_host
printf 'Build host: %s; targets: linux-amd64, linux-arm64 (static headless clients)\n' "$platform"
export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
while [[ $output == */ && $output != / ]]; do output=${output%/}; done
if [[ -z $output ]]; then
    stamp=$(date -u +%Y%m%d-%H%M%S)
    output=$(mktemp -d "$PWD/network-relay-linux-clients-$platform-$stamp.XXXXXX")
elif [[ -e $output || -L $output ]]; then
    if [[ ! -d $output || -L $output ]] || ! lc_empty_dir "$output"; then lc_die '--output must be a new or empty directory.'; fi
else
    mkdir -p -- "$output"
fi
lc_physical_dir "$output"; output=$REPLY
[[ $output/ != "$stage/"* && $stage/ != "$output/"* ]] || lc_die 'Output and work directories cannot overlap.'
work=$stage
repo="$work/network-relay-src"
mkdir -m 700 -- "$output/logs"
ln -s -- "$work" "$output/.work"
printf 'Artifacts: %s\nPersistent checkout: %s\nWork directory: %s\n' "$output" "$checkout" "$work"
failures=0
export RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-1.99.0}
export APP_SOURCE_REVISION="$root_commit"
APP_BUILD_TIME=$(date -u +%FT%TZ)
export APP_BUILD_TIME
# Explicit targets and empty encoded flags prevent ambient host-specific builds.
unset CARGO_BUILD_TARGET CARGO_TARGET_DIR RUSTFLAGS
export CARGO_ENCODED_RUSTFLAGS=''
export PATH="$work/tools/bin:$PATH"
lc_run system-prerequisites lc_ensure_system
(( failures == 0 )) || lc_die 'Cannot prepare system prerequisites.'
if (( install_deps )); then lc_run bootstrap-rustup lc_install_rustup;
else lc_run installed-prerequisites lc_check_tools; fi
(( failures == 0 )) || lc_die 'Build prerequisites are unavailable.'
for tool in rustup rustc cargo; do command -v "$tool" >/dev/null || lc_die "Missing tool after bootstrap: $tool"; done
lc_snapshot() {
    git clone --no-hardlinks --no-checkout -- "$checkout" "$repo"
    git -C "$repo" checkout --detach "$root_commit"
}
lc_run source-network-relay lc_snapshot
if (( install_deps )); then lc_run toolchain-rust lc_prepare_rust;
else lc_run toolchain-rust rustc --version; fi
lc_run toolchain-cross lc_prepare_cross_tools
(( failures == 0 )) || lc_die "$failures source/toolchain step(s) failed."
for arch in amd64 arm64; do
    case $arch in amd64) triple=x86_64-unknown-linux-musl ;; arm64) triple=aarch64-unknown-linux-musl ;; esac
    lc_run "build-network-relay-rs-$arch" lc_build_rust "$repo/network-relay-rs/Cargo.toml" "$work/rust-client" "$triple" --bin network-relay-rs
    lc_run "verify-network-relay-rs-$arch" lc_collect "$work/rust-client/$triple/release/network-relay-rs" "$arch"
done
(( failures == 0 )) || lc_die "$failures step(s) failed; see $output/logs."
lc_manifest() {
    local built rust_version commit arch description
    built=$(date -u +%FT%TZ)
    rust_version=$(rustc --version)
    commit=$(git -C "$repo" rev-parse --verify HEAD)
    [[ $commit == "$root_commit" ]] || lc_die 'Source revision changed.'
    git -C "$repo" diff --quiet HEAD -- || lc_die 'Build changed tracked sources.'
    printf 'Build host: %s\nTargets: linux-amd64, linux-arm64 (static musl headless clients)\nBuilt: %s\nRust: %s\n' "$platform" "$built" "$rust_version"
    printf 'Source: ArcCal/network-relay\nBranch: main\nCommit: %s\n' "$commit"
    for arch in amd64 arm64; do
        description=$(LC_ALL=C file -b -- "$output/network-relay-rs-linux-$arch")
        printf 'network-relay-rs-linux-%s: %s\n' "$arch" "$description"
    done
}
lc_run manifest lc_manifest
(( failures == 0 )) || lc_die 'Manifest verification failed.'
cp -- "$output/logs/manifest.log" "$output/MANIFEST.txt"
lc_checksums() (
    cd -- "$output" || exit
    sha256sum -- network-relay-rs-linux-amd64 network-relay-rs-linux-arm64 MANIFEST.txt > SHA256SUMS || exit
    sha256sum --check SHA256SUMS || exit
)
lc_run checksums lc_checksums
(( failures == 0 )) || lc_die 'Checksum generation or verification failed.'
rm -f -- "$output/.work"
rm -rf -- "${work:?}"
trap - EXIT
printf '\nLinux headless clients built for amd64 and arm64.\nArtifacts: %s\n' "$output"
