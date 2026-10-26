#!/usr/bin/env bash
# Build Network Relay servers for Linux amd64 and arm64 from current GitHub sources.
# Also sourceable by the macOS all-target builder; sourcing defines functions only.

lr_usage() {
    cat <<'HELP'
Usage: bash build-servers-linux.sh [--repo DIR] [--output DIR] [--jobs N]
                                   [--install-deps | --no-install-deps] [--check]

Build all three servers for BOTH Linux amd64 (x64) and arm64 on every run:
  ArcCal/network-relay: network-relay
  ArcCal/network-relay/network-relay-cf-masque: network-relay-cf-masque
  ArcCal/caddy-network-relay: caddy-network-relay, including Cloudflare DNS

Supported hosts: Debian 13 x64; Ubuntu 26.04 x64 or arm64.
Rust binaries use static musl via Zig; Go uses CGO_ENABLED=0.
All six files are named SOFTWARE-linux-ARCH and inspected for architecture
and static linking. Native executables also run version/module smoke checks.

  --repo DIR       persistent network-relay checkout (default: ~/network-relay,
                   or NETWORK_RELAY_SRC). Existing main checkouts run
                   pull --ff-only origin main; missing checkouts are cloned.
  --output DIR     new or empty artifact directory (default: ./relay-servers-*)
  --jobs N         Cargo and Go parallelism (default: 2)
  Dependencies    install missing build prerequisites automatically (default).
                   Uses root or sudo only when system packages are missing.
  --install-deps   also refresh/install the apt prerequisite package set
  --no-install-deps
                   require existing build tools and Rust targets; install none
  --check          inspect host/tools without network access or filesystem changes

The newest committed script handles each build. Local commits are refused;
uncommitted files are preserved and never used as build inputs. The two Rust
servers use the same committed private snapshot. Caddy uses current main;
caddy-dns/cloudflare uses current master. Fetched commits are fixed for this
run and recorded in MANIFEST.txt. Credentials must allow both private repos.
Optional NETWORK_RELAY_TOKEN / CADDY_NETWORK_RELAY_TOKEN provide read tokens.
Rust defaults to 1.99.0; Go defaults to go1.27.2+auto (honors module requirements).

Any failed source, build, verification or checksum step fails the run.
Successful runs retain six binaries, logs, MANIFEST.txt and SHA256SUMS;
only their private work directory is removed. Failed runs retain .work.
No server installation or service configuration is performed.
HELP
}
lr_die() { printf 'build-servers-linux: %s\n' "$*" >&2; exit 1; }
lr_value() { [[ $# -ge 2 && -n $2 && $2 != --* ]] || lr_die "Pass a value to $1."; }
lr_physical_dir() { REPLY=$(cd -P -- "$1" && printf '%s/' "$PWD"); REPLY=${REPLY%/}; }
lr_empty_dir() {
    local entries
    [[ -r $1 && -x $1 ]] || return 1
    entries=$(ls -A -- "$1" && printf '.') || return 1
    [[ $entries == . ]]
}
lr_host() {
    [[ $(uname -s) == Linux && -r /etc/os-release ]] || lr_die 'A supported Linux VPS is required.'
    # This file is the operating system's trusted platform description.
    # shellcheck disable=SC1091
    source /etc/os-release
    case ${ID:-}:${VERSION_ID:-}:$(uname -m) in
        debian:13:x86_64) platform=debian-13-amd64; host_arch=amd64 ;;
        ubuntu:26.04:x86_64) platform=ubuntu-26.04-amd64; host_arch=amd64 ;;
        ubuntu:26.04:aarch64|ubuntu:26.04:arm64) platform=ubuntu-26.04-arm64; host_arch=arm64 ;;
        *) lr_die 'Supported hosts: Debian 13 x64, Ubuntu 26.04 x64 or Ubuntu 26.04 arm64.' ;;
    esac
}
lr_check_tools() {
    local missing=0 tool targets triple
    for tool in git curl cc pkg-config file sha256sum rustup rustc cargo go zig cargo-zigbuild readelf; do
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
lr_install_system() {
    local apt_command=(apt-get)
    if (( EUID != 0 )); then
        command -v sudo >/dev/null || lr_die '--install-deps requires root or sudo.'
        apt_command=(sudo apt-get)
    fi
    "${apt_command[@]}" update
    "${apt_command[@]}" install -y --no-install-recommends \
        build-essential pkg-config ca-certificates curl git file golang-go binutils python3-venv
}
lr_ensure_system() {
    local tool missing=0 needs_python=0
    for tool in git curl cc pkg-config file sha256sum go readelf; do
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
    (( install_deps )) || lr_die 'Missing system prerequisites and --no-install-deps was selected.'
    lr_install_system
    for tool in git curl cc pkg-config file sha256sum go readelf; do
        command -v "$tool" >/dev/null || lr_die "System package installation did not provide $tool."
    done
    [[ -s /etc/ssl/certs/ca-certificates.crt ]] || lr_die 'System CA certificates are unavailable.'
    if (( needs_python )); then
        python3 -c 'import ensurepip, venv' >/dev/null 2>&1 || lr_die 'Python venv support is unavailable after package installation.'
    fi
}
lr_install_rustup() {
    local installer
    if ! command -v rustup >/dev/null; then
        (( install_deps )) || lr_die 'Missing rustup; use --install-deps.'
        installer=$(mktemp)
        curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs -o "$installer" || {
            rm -f -- "$installer"; lr_die 'Cannot download rustup.';
        }
        sh "$installer" -y --profile minimal --default-toolchain none --no-modify-path || {
            rm -f -- "$installer"; lr_die 'Cannot install rustup.';
        }
        rm -f -- "$installer"
    fi
}
lr_remote_git() {
    # A signed-in gh session can read private sources without global Git changes.
    # Existing credential helpers remain available before this fallback helper.
    if command -v gh >/dev/null; then
        GIT_TERMINAL_PROMPT=0 git -c 'credential.helper=!gh auth git-credential' "$@"
    else
        GIT_TERMINAL_PROMPT=0 git "$@"
    fi
}
lr_token_git() {
    local token=${NETWORK_RELAY_TOKEN:-} header
    [[ -n $token ]] || { printf 'Configure Git credentials or NETWORK_RELAY_TOKEN.\n' >&2; return 1; }
    header=$(printf 'x-access-token:%s' "$token" | base64 | tr -d '\n') || return
    GIT_TERMINAL_PROMPT=0 GIT_CONFIG_COUNT=2 \
        GIT_CONFIG_KEY_0=credential.helper GIT_CONFIG_VALUE_0='' \
        GIT_CONFIG_KEY_1=http.https://github.com/.extraheader \
        GIT_CONFIG_VALUE_1="Authorization: Basic $header" git "$@"
}
lr_update_checkout() {
    local actual_root remote selected_branch fetched has_repo=0
    while [[ $checkout == */ && $checkout != / ]]; do checkout=${checkout%/}; done
    if [[ -e $checkout || -L $checkout ]]; then
        if [[ -d $checkout && -e $checkout/.git ]]; then has_repo=1;
        elif [[ ! -d $checkout || -L $checkout ]] || ! lr_empty_dir "$checkout"; then
            lr_die "Existing path is not a Git checkout: $checkout"
        fi
    fi
    if (( has_repo )); then
        lr_physical_dir "$checkout"; checkout=$REPLY
        actual_root=$(git -C "$checkout" rev-parse --show-toplevel && printf '.') || lr_die 'Cannot inspect checkout root.'
        actual_root=${actual_root%.}; actual_root=${actual_root%$'\n'}
        [[ $actual_root == "$checkout" ]] || lr_die 'Select the repository root.'
        remote=$(git -C "$checkout" config --get remote.origin.url) || lr_die 'Cannot read origin.'
        case $remote in
            https://github.com/ArcCal/network-relay|https://github.com/ArcCal/network-relay.git|git@github.com:ArcCal/network-relay.git|ssh://git@github.com/ArcCal/network-relay.git) ;;
            *) lr_die 'origin must point to ArcCal/network-relay on GitHub.' ;;
        esac
        selected_branch=$(git -C "$checkout" symbolic-ref --short HEAD) || lr_die 'Use a main checkout, not detached HEAD.'
        [[ $selected_branch == main ]] || lr_die 'Use a main checkout; other branches are left unchanged.'
        printf '==> Updating existing checkout with pull --ff-only\n'
        if ! lr_remote_git -C "$checkout" pull --ff-only origin main; then
            lr_token_git -C "$checkout" pull --ff-only origin main || lr_die 'Cannot fast-forward checkout.'
        fi
        fetched=$(git -C "$checkout" rev-parse --verify FETCH_HEAD) || lr_die 'Cannot identify fetched commit.'
    else
        printf '==> Cloning ArcCal/network-relay\n'
        if ! lr_remote_git clone --depth 1 --single-branch --branch main -- https://github.com/ArcCal/network-relay.git "$checkout"; then
            if [[ -e $checkout || -L $checkout ]]; then
                if [[ ! -d $checkout || -L $checkout ]] || ! lr_empty_dir "$checkout"; then
                    lr_die 'Clone failed; existing destination preserved.'
                fi
            fi
            lr_token_git clone --depth 1 --single-branch --branch main -- https://github.com/ArcCal/network-relay.git "$checkout" || lr_die 'Cannot clone checkout.'
        fi
        lr_physical_dir "$checkout"; checkout=$REPLY
        fetched=$(git -C "$checkout" rev-parse --verify refs/remotes/origin/main) || lr_die 'Cannot identify cloned commit.'
    fi
    root_commit=$(git -C "$checkout" rev-parse --verify HEAD) || lr_die 'Cannot identify checkout commit.'
    [[ $root_commit == "$fetched" ]] || lr_die 'Local commits differ from fetched main; no local files were reset.'
}
lr_clone_repo() {
    local name=$1 destination=$2 token_name=$3 token header
    if lr_remote_git clone --depth 1 --branch main --single-branch -- "https://github.com/ArcCal/$name.git" "$destination"; then return 0; fi
    token=${!token_name:-}
    [[ -n $token ]] || { printf 'Configure Git credentials or %s for ArcCal/%s.\n' "$token_name" "$name" >&2; return 1; }
    header=$(printf 'x-access-token:%s' "$token" | base64 | tr -d '\n')
    # The caller only supplies fresh paths in its owned private workspace.
    rm -rf -- "${destination:?}"
    GIT_TERMINAL_PROMPT=0 GIT_CONFIG_COUNT=2 \
        GIT_CONFIG_KEY_0=credential.helper GIT_CONFIG_VALUE_0='' \
        GIT_CONFIG_KEY_1=http.https://github.com/.extraheader \
        GIT_CONFIG_VALUE_1="Authorization: Basic $header" \
        git clone --depth 1 --branch main --single-branch -- "https://github.com/ArcCal/$name.git" "$destination"
}
lr_prepare_rust() {
    rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal
    rustup target add --toolchain "$RUSTUP_TOOLCHAIN" x86_64-unknown-linux-musl aarch64-unknown-linux-musl
    rustc --version
}
lr_prepare_cross_tools() {
    if ! command -v zig >/dev/null; then
        (( install_deps )) || lr_die 'Install Zig or use --install-deps.'
        python3 -m venv "$work/zig-venv"
        "$work/zig-venv/bin/python" -m pip install --only-binary=:all: ziglang==0.14.1
        local zig_binary
        zig_binary=$("$work/zig-venv/bin/python" -c 'import pathlib, ziglang; print(pathlib.Path(ziglang.__file__).parent / "zig")')
        mkdir -p -- "$work/tools/bin"
        ln -s -- "$zig_binary" "$work/tools/bin/zig"
    fi
    if ! command -v cargo-zigbuild >/dev/null; then
        (( install_deps )) || lr_die 'Install cargo-zigbuild or use --install-deps.'
        cargo install --locked --version 0.24.0 --jobs "$jobs" --root "$work/tools" cargo-zigbuild
    fi
    zig version
    cargo-zigbuild --version
}
lr_run() {
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
lr_build_rust() {
    local manifest=$1 target_dir=$2 triple=$3
    shift 3
    cd -- "$(dirname -- "$manifest")"
    cargo zigbuild --locked --release --manifest-path "$manifest" \
        --target "$triple" --target-dir "$target_dir" --jobs "$jobs" "$@"
}
lr_prepare_caddy() {
    local build_mod="$caddy_src/build-plugins.mod" build_sum="$caddy_src/build-plugins.sum"
    local plugin_import="$caddy_src/cmd/caddy/cloudflare_dns_build.go" path go_version
    [[ -f $caddy_src/go.mod && -f $caddy_src/go.sum && -d $caddy_src/cmd/caddy &&
       -d $caddy_src/third_party/x-net && -d $caddy_src/third_party/quic-go ]] ||
        lr_die 'Complete caddy-network-relay source is required.'
    [[ -f $cloudflare_src/go.mod ]] || lr_die 'Cloudflare DNS plugin source is required.'
    grep -Eq 'ID:[[:space:]]*"network_relay"' "$caddy_src/app.go"
    grep -Eq 'ID:[[:space:]]*"http\.handlers\.network_relay"' "$caddy_src/handler.go"
    grep -Eq 'ID:[[:space:]]*"dns\.providers\.cloudflare"' "$cloudflare_src/cloudflare.go"
    cd -- "$caddy_src"
    export GOWORK=off GOFLAGS='' GOOS=linux GOARCH="$host_arch" GOAMD64=v1 GOARM64=v8.0 CGO_ENABLED=0
    # Alternate module files keep tracked source and the reviewed transport
    # replacements intact while adding the freshly fetched DNS plugin.
    for path in "$build_mod" "$build_sum" "$plugin_import"; do
        [[ ! -e $path && ! -L $path ]] || lr_die "Build overlay already exists: $path"
    done
    cp -- go.mod "$build_mod"
    cp -- go.sum "$build_sum"
    printf 'package main\n\nimport _ "github.com/caddy-dns/cloudflare"\n' > "$plugin_import"
    go version
    go_version=$(go env GOVERSION)
    # The manifest only states Go 1.26.0; the transport's reviewed toolchain
    # requirement is stricter and must also apply to an explicit override.
    if [[ $go_version =~ ^go1\.26\.([0-9]+)$ ]]; then
        (( 10#${BASH_REMATCH[1]} >= 9 )) || lr_die 'Caddy requires Go 1.26.9 or Go 1.27.2 or newer.'
    elif [[ $go_version =~ ^go1\.27\.([0-9]+)$ ]]; then
        (( 10#${BASH_REMATCH[1]} >= 2 )) || lr_die 'Caddy requires Go 1.26.9 or Go 1.27.2 or newer.'
    elif [[ $go_version =~ ^go1\.([0-9]+)(\.[0-9]+)?$ ]]; then
        (( 10#${BASH_REMATCH[1]} > 27 )) || lr_die 'Caddy requires Go 1.26.9 or Go 1.27.2 or newer.'
    else
        lr_die "Unrecognized release Go toolchain: $go_version"
    fi
    # A sibling path keeps the caller's username/output path out of Go build info.
    go mod edit -modfile "$build_mod" \
        -replace github.com/caddy-dns/cloudflare=../cloudflare-src
    go get -modfile "$build_mod" github.com/caddy-dns/cloudflare@v0.0.0
}
lr_build_caddy() {
    local arch=$1
    cd -- "$caddy_src"
    export GOWORK=off GOFLAGS='' GOOS=linux GOARCH="$arch" GOAMD64=v1 GOARM64=v8.0 CGO_ENABLED=0
    go build -modfile "$caddy_src/build-plugins.mod" -mod=readonly -tags http2legacy -trimpath -p "$jobs" \
        -o "$work/caddy-network-relay-$arch" ./cmd/caddy
}
lr_check_replacement() {
    local info=$1 module=$2 replacement=$3
    awk -F '\t' -v module="$module" -v replacement="$replacement" '
        ($2 == "dep" || $2 == "mod") && $3 == module { pending=1; next }
        pending { if ($2 == "=>" && $3 == replacement) found=1; pending=0 }
        END { exit !found }
    ' <<< "$info"
}

lr_collect() {
    local source=$1 name=$2 arch=$3 description modules module info headers
    [[ -f $source && -s $source && -x $source ]] || lr_die "Missing executable: $source"
    description=$(LC_ALL=C file -b -- "$source")
    case $arch in
        amd64) [[ $description == *ELF* && $description == *x86-64* ]] ;;
        arm64) [[ $description == *ELF* && $description == *aarch64* ]] ;;
    esac || lr_die "Wrong architecture: $description"
    headers=$(LC_ALL=C readelf -l -d -- "$source")
    [[ $description == *static* && $headers != *INTERP* && $headers != *NEEDED* ]] ||
        lr_die "Artifact must be static: $source"
    if [[ $name == caddy-network-relay ]]; then
        info=$(go version -m "$source")
        grep -Eq '^[[:space:]]*path[[:space:]]+github\.com/arccal/caddy-network-relay/cmd/caddy$' <<< "$info"
        grep -Eq "^[[:space:]]*build[[:space:]]+GOARCH=$arch$" <<< "$info"
        grep -Eq '^[[:space:]]*build[[:space:]]+CGO_ENABLED=0$' <<< "$info"
        lr_check_replacement "$info" github.com/caddy-dns/cloudflare ../cloudflare-src
        lr_check_replacement "$info" golang.org/x/net ./third_party/x-net
        lr_check_replacement "$info" github.com/quic-go/quic-go ./third_party/quic-go
    fi
    # Foreign executables cannot run directly on the host. Their ELF headers
    # and Go build metadata are still mandatory checks.
    if [[ $arch == "$host_arch" ]]; then
        if [[ $name == caddy-network-relay ]]; then
            "$source" version
            modules=$("$source" list-modules)
            for module in network_relay http.handlers.network_relay dns.providers.cloudflare; do
                grep -Fxq -- "$module" <<< "$modules" || lr_die "Missing Caddy module: $module"
            done
        else
            "$source" --version
        fi
    fi
    install -m 755 -- "$source" "$output/$name-linux-$arch"
}
lr_main() {
    checkout=${NETWORK_RELAY_SRC:-"$HOME/network-relay"}
    # 2: install missing prerequisites; 1: additionally refresh apt; 0: opt out.
    output=; jobs=2; install_deps=2
    local check_only=0
    while (( $# )); do
        case $1 in
            -h|--help) lr_usage; return ;;
            --repo) lr_value "$@"; checkout=$2; shift 2 ;;
            --output) lr_value "$@"; output=$2; shift 2 ;;
            --jobs) lr_value "$@"; jobs=$2; shift 2 ;;
            --install-deps) install_deps=1; shift ;;
            --no-install-deps) install_deps=0; shift ;;
            --check) check_only=1; shift ;;
            *) lr_usage >&2; lr_die "Unknown argument: $1" ;;
        esac
    done
    [[ $jobs =~ ^[1-9][0-9]*$ ]] || lr_die '--jobs must be a positive integer.'
    (( ! check_only || install_deps != 1 )) || lr_die '--check and --install-deps conflict.'
    lr_host
    export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
    if (( check_only )); then
        printf 'Build host: %s; targets: linux-amd64, linux-arm64 (static)\n' "$platform"
        lr_check_tools
        return
    fi
    (( install_deps != 1 )) || lr_install_system
    if ! command -v git >/dev/null; then
        (( install_deps )) || lr_die 'Missing git and --no-install-deps was selected.'
        lr_install_system
    fi
    lr_update_checkout
    stage=$(mktemp -d /tmp/relay-servers.XXXXXX) || lr_die 'Cannot create private workspace.'
    trap 'status=$?; if (( status )); then printf "Update failed (exit %s). Work: %s\n" "$status" "$stage" >&2; fi' EXIT
    printf '%s\n' "$root_commit" > "$stage/.owner"
    git -C "$checkout" show "$root_commit:build-servers-linux.sh" > "$stage/driver.sh" || lr_die 'Cannot load newest committed script.'
    [[ -s $stage/driver.sh ]] || lr_die 'Newest build script is empty.'
    exec "$BASH" "$stage/driver.sh" --build-updated "$checkout" "$stage" "$output" "$root_commit" "$jobs" "$install_deps" --deps-policy-v2
}

# Sourcing provides the portable build helpers without inspecting or changing a host.
[[ ${BASH_SOURCE[0]} == "$0" ]] || return 0
set -euo pipefail
unset CDPATH
# Parse the complete conditional before pull can replace the running input file.
if [[ ${1:-} != --build-updated ]]; then lr_main "$@"; exit; fi
[[ $# == 7 || ( $# == 8 && ${8:-} == --deps-policy-v2 ) ]] || lr_die 'Invalid internal build invocation.'
checkout=$2; stage=$3; output=$4; root_commit=$5; jobs=$6; install_deps=$7
[[ $jobs =~ ^[1-9][0-9]*$ && ( $install_deps == 0 || $install_deps == 1 || $install_deps == 2 ) ]] || lr_die 'Invalid build options.'
# Published launchers used seven arguments and passed 0 for an ordinary run.
# Upgrade that old default too; only the versioned protocol can request opt-out.
if [[ $# == 7 && $install_deps == 0 ]]; then install_deps=2; fi
[[ ${stage##*/} == relay-servers.* && -d $stage && ! -L $stage && -f $stage/.owner && ! -L $stage/.owner &&
   $(cat "$stage/.owner") == "$root_commit" ]] || lr_die 'Invalid private workspace.'
trap 'status=$?; if (( status )); then printf "Build incomplete (exit %s). Work: %s; artifacts/logs: %s\n" "$status" "$stage" "$output" >&2; fi' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
lr_host
printf 'Build host: %s; targets: linux-amd64, linux-arm64 (static)\n' "$platform"
export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
while [[ $output == */ && $output != / ]]; do output=${output%/}; done
if [[ -z $output ]]; then
    stamp=$(date -u +%Y%m%d-%H%M%S)
    output=$(mktemp -d "$PWD/relay-servers-$platform-$stamp.XXXXXX")
elif [[ -e $output || -L $output ]]; then
    if [[ ! -d $output || -L $output ]] || ! lr_empty_dir "$output"; then
        lr_die '--output must be a new or empty directory.'
    fi
else
    mkdir -p -- "$output"
fi
lr_physical_dir "$output"; output=$REPLY
[[ $output/ != "$stage/"* && $stage/ != "$output/"* ]] || lr_die 'Output and work directories cannot overlap.'
work=$stage
repo="$work/network-relay-src"
caddy_src="$work/caddy-network-relay-src"
cloudflare_src="$work/cloudflare-src"
mkdir -m 700 -- "$output/logs"
ln -s -- "$work" "$output/.work"
printf 'Artifacts: %s\nPersistent checkout: %s\nWork directory: %s\n' "$output" "$checkout" "$work"
failures=0
export RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-1.99.0}
if (( install_deps )); then
    export GOTOOLCHAIN=${GOTOOLCHAIN:-go1.27.2+auto}
else
    export GOTOOLCHAIN=${GOTOOLCHAIN:-local}
fi
lr_run system-prerequisites lr_ensure_system
(( failures == 0 )) || lr_die 'Cannot prepare system prerequisites.'
if (( install_deps )); then
    lr_run bootstrap-rustup lr_install_rustup
else
    lr_run installed-prerequisites lr_check_tools
fi
(( failures == 0 )) || lr_die 'Build prerequisites are unavailable.'
for tool in rustup rustc cargo; do command -v "$tool" >/dev/null || lr_die "Missing required tool after bootstrap: $tool"; done
lr_snapshot() {
    git clone --no-hardlinks --no-checkout -- "$checkout" "$repo"
    git -C "$repo" checkout --detach "$root_commit"
}
lr_run source-network-relay lr_snapshot
lr_run source-caddy-network-relay lr_clone_repo caddy-network-relay "$caddy_src" CADDY_NETWORK_RELAY_TOKEN
lr_run source-cloudflare env GIT_TERMINAL_PROMPT=0 git clone --depth 1 --branch master --single-branch -- \
    https://github.com/caddy-dns/cloudflare.git "$cloudflare_src"
export GOWORK=off GOFLAGS='' GOAMD64=v1 GOARM64=v8.0
unset GOOS GOARCH CARGO_BUILD_TARGET RUSTFLAGS
export CARGO_ENCODED_RUSTFLAGS=''
export PATH="$work/tools/bin:$PATH"
if (( install_deps )); then
    lr_run toolchain-rust lr_prepare_rust
else
    lr_run toolchain-rust rustc --version
fi
lr_run toolchain-cross lr_prepare_cross_tools
(( failures == 0 )) || lr_die "$failures source/toolchain step(s) failed."
lr_run prepare-caddy lr_prepare_caddy
(( failures == 0 )) || lr_die 'Cannot prepare Caddy dependencies.'
for arch in amd64 arm64; do
    case $arch in
        amd64) triple=x86_64-unknown-linux-musl ;;
        arm64) triple=aarch64-unknown-linux-musl ;;
    esac
    lr_run "build-network-relay-$arch" lr_build_rust "$repo/Cargo.toml" "$work/rust-main" "$triple" --bin network-relay
    lr_run "build-cf-masque-$arch" lr_build_rust "$repo/network-relay-cf-masque/Cargo.toml" "$work/rust-cf" "$triple" --bin network-relay-cf-masque
    lr_run "build-caddy-network-relay-$arch" lr_build_caddy "$arch"
    lr_run "verify-network-relay-$arch" lr_collect "$work/rust-main/$triple/release/network-relay" network-relay "$arch"
    lr_run "verify-network-relay-cf-masque-$arch" lr_collect "$work/rust-cf/$triple/release/network-relay-cf-masque" network-relay-cf-masque "$arch"
    lr_run "verify-caddy-network-relay-$arch" lr_collect "$work/caddy-network-relay-$arch" caddy-network-relay "$arch"
done
(( failures == 0 )) || lr_die "$failures step(s) failed; see $output/logs."
lr_write_manifest() {
    local source commit branch fetched program arch description built rust_version
    built=$(date -u +%FT%TZ)
    rust_version=$(rustc --version)
    printf 'Build host: %s\nTargets: linux-amd64, linux-arm64 (static musl Rust, CGO-disabled Go)\nBuilt: %s\n' "$platform" "$built"
    printf 'Rust: %s\nGo selection: %s\n' "$rust_version" "$GOTOOLCHAIN"
    for source in "$repo" "$caddy_src" "$cloudflare_src"; do
        commit=$(git -C "$source" rev-parse --verify HEAD)
        if [[ $source == "$repo" ]]; then branch=main; fetched=$root_commit;
        else branch=$(git -C "$source" symbolic-ref --short HEAD); fetched=$(git -C "$source" rev-parse --verify "refs/remotes/origin/$branch"); fi
        [[ $fetched == "$commit" ]] || lr_die "Source commit changed: $source"
        git -C "$source" diff --quiet HEAD -- || lr_die "Build changed tracked sources: $source"
        printf 'Source: %s\nBranch: %s\nCommit: %s\n' "${source##*/}" "$branch" "$commit"
    done
    for arch in amd64 arm64; do
        for program in network-relay network-relay-cf-masque caddy-network-relay; do
            description=$(LC_ALL=C file -b -- "$output/$program-linux-$arch")
            printf '%s: %s\n' "$program-linux-$arch" "$description"
        done
    done
}
lr_run manifest lr_write_manifest
(( failures == 0 )) || lr_die 'Manifest verification failed.'
# Run manifest generation in its own error-enabled step, then publish the log.
cp -- "$output/logs/manifest.log" "$output/MANIFEST.txt"
lr_checksums() (
    cd -- "$output" || exit
    artifact_files=()
    for arch in amd64 arm64; do
        for program in network-relay network-relay-cf-masque caddy-network-relay; do artifact_files+=("$program-linux-$arch"); done
    done
    sha256sum -- "${artifact_files[@]}" MANIFEST.txt > SHA256SUMS || exit
    sha256sum --check SHA256SUMS || exit
)
lr_run checksums lr_checksums
(( failures == 0 )) || lr_die 'Checksum generation or verification failed.'
rm -f -- "$output/.work"
rm -rf -- "${work:?}"
trap - EXIT
printf '\nAll three servers built for amd64 and arm64.\nBoth architectures inspected; native executables also smoke-tested.\nArtifacts: %s\n' "$output"
