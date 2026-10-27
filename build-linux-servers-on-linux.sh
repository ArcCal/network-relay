#!/usr/bin/env bash
# Build Network Relay servers for Linux amd64 and arm64 from current GitHub sources.
# Also sourceable by the macOS all-target builder; sourcing defines functions only.

lr_usage() {
    cat <<'HELP'
Usage: bash build-linux-servers-on-linux.sh [--repo DIR] [--output DIR] [--jobs N]
                                   [--install-deps | --no-install-deps] [--check]

Build both servers for BOTH Linux amd64 (x64) and arm64 on every run:
  ArcCal/network-relay: network-relay
  ArcCal/caddy-network-relay: caddy-network-relay, including Cloudflare DNS

Supported hosts: Debian 13 and Ubuntu 26.04, on x64 or arm64.
Rust binaries use static musl via Zig; Go uses CGO_ENABLED=0.
All four files are named SOFTWARE-linux-ARCH and inspected for architecture
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
uncommitted files are preserved and never used as build inputs. The Rust
server uses a committed private snapshot. Caddy uses current main;
caddy-dns/cloudflare uses its pinned v0.2.4 release. Fetched commits are fixed for this
run and recorded in MANIFEST.txt. Credentials must allow both private repos.
Optional NETWORK_RELAY_TOKEN / CADDY_NETWORK_RELAY_TOKEN provide read tokens.
Rust defaults to 1.99.1; Go defaults to go1.27.3+auto (honors module requirements).

Any failed source, build, verification or checksum step fails the run.
Successful runs retain four binaries, logs, MANIFEST.txt and SHA256SUMS;
only their private work directory is removed. Failed runs retain .work.
Network steps are retried. Debian 13 keeps /tmp in memory; when it is too small,
temporary files go to ~/.cache instead. Free disk space is checked first.
No server installation or service configuration is performed.
HELP
}
# The reviewed caddy-dns/cloudflare release built into Caddy, and its commit.
LR_CLOUDFLARE_DNS_TAG=v0.2.4
LR_CLOUDFLARE_DNS_COMMIT=a8737d095ad5a48ca031cea6ab704057dbc2d250
lr_die() { printf 'build-linux-servers-on-linux: %s\n' "$*" >&2; exit 1; }
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
        debian:13:aarch64|debian:13:arm64) platform=debian-13-arm64; host_arch=arm64 ;;
        ubuntu:26.04:x86_64) platform=ubuntu-26.04-amd64; host_arch=amd64 ;;
        ubuntu:26.04:aarch64|ubuntu:26.04:arm64) platform=ubuntu-26.04-arm64; host_arch=arm64 ;;
        *) lr_die 'Supported hosts: Debian 13 or Ubuntu 26.04 on x64 or arm64.' ;;
    esac
}
lr_check_tools() {
    local missing=0 tool targets triple
    for tool in git curl cc pkg-config file sha256sum rustup rustc cargo go zig cargo-zigbuild readelf; do
        if command -v "$tool" >/dev/null; then printf '  %s: available\n' "$tool";
        else printf '  %s: missing\n' "$tool" >&2; missing=1; fi
    done
    if command -v rustup >/dev/null; then
        if ! rustup which --toolchain "${RUSTUP_TOOLCHAIN:-1.99.1}" rustc >/dev/null 2>&1; then
            printf '  Rust toolchain %s: missing\n' "${RUSTUP_TOOLCHAIN:-1.99.1}" >&2
            missing=1
        else
            targets=$(rustup target list --installed --toolchain "${RUSTUP_TOOLCHAIN:-1.99.1}") || missing=1
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
        command -v sudo >/dev/null || lr_die 'Installing missing system packages needs administrator rights. Run this script again with sudo, or ask an administrator to run it once.'
        apt_command=(sudo apt-get)
    fi
    # apt retries interrupted downloads itself.
    "${apt_command[@]}" -o Acquire::Retries=3 update
    "${apt_command[@]}" -o Acquire::Retries=3 install -y --no-install-recommends \
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
        curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 5 https://sh.rustup.rs -o "$installer" || {
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
# Run a network command up to three times, 5 and then 15 seconds apart.
lr_retry() {
    local attempt
    for attempt in 1 2 3; do
        "$@" && return 0
        [[ $attempt == 3 ]] && break
        printf 'Network step failed (attempt %s of 3); retrying in %s seconds.\n' "$attempt" "$((attempt * 10 - 5))" >&2
        sleep "$((attempt * 10 - 5))"
    done
    return 1
}
# Explain a problem the user has to fix, one line per argument, then stop.
lr_explain() {
    printf '\n' >&2
    printf '%s\n' "$@" >&2
    printf '\n' >&2
    exit 1
}
# Plain-language help after GitHub could not be reached or read.
lr_access_help() {
    printf '\nCould not download %s from GitHub.\n' "$1" >&2
    printf 'Check that this computer is online. The repository is private, so Git must be signed in.\n' >&2
    if ! command -v gh >/dev/null; then
        printf 'Install the GitHub CLI (gh), run "gh auth login"%s, then run this script again.\n' "${2:+, or set $2 to a GitHub token}" >&2
    elif ! gh auth status >/dev/null 2>&1; then
        printf 'Sign in by running "gh auth login", then run this script again.\n' >&2
    else
        printf 'Your GitHub account may lack access to %s; check it, then run this script again.\n' "$1" >&2
    fi
}
# Run Git against GitHub with retries, then once with the optional token.
lr_github() {
    lr_retry lr_remote_git "$@" && return 0
    [[ -n ${NETWORK_RELAY_TOKEN:-} ]] || return 1
    printf 'Trying once more with NETWORK_RELAY_TOKEN.\n' >&2
    lr_token_git "$@"
}
# Print local edits that an update to $2 would overwrite, one per line.
lr_blocking_changes() {
    local incoming line path
    incoming=$(git -C "$1" -c core.quotePath=false diff --name-only HEAD "$2" --) || return 0
    git -C "$1" -c core.quotePath=false status --porcelain --untracked-files=all |
        while IFS= read -r line; do
            path=${line:3}
            path=${path##* -> }
            if grep -Fxq -- "$path" <<< "$incoming"; then printf '  %s\n' "$path"; fi
        done
}
lr_update_checkout() {
    local actual_root remote selected_branch fetched has_repo=0 ahead behind blocked script fresh
    printf -v script '%q' "$0"
    printf -v fresh '%q' "$HOME/network-relay-build"
    while [[ $checkout == */ && $checkout != / ]]; do checkout=${checkout%/}; done
    if [[ -e $checkout || -L $checkout ]]; then
        if [[ -d $checkout && -e $checkout/.git ]]; then has_repo=1;
        elif [[ ! -d $checkout || -L $checkout ]] || ! lr_empty_dir "$checkout"; then
            lr_explain "$checkout already exists, but it is not a Git copy of ArcCal/network-relay." \
                'Nothing in it was changed. Rename or move that folder, or build in a new folder:' \
                "  bash $script --repo $fresh"
        fi
    fi
    if (( has_repo )); then
        lr_physical_dir "$checkout"; checkout=$REPLY
        actual_root=$(git -C "$checkout" rev-parse --show-toplevel && printf '.') || lr_die 'Cannot inspect checkout root.'
        actual_root=${actual_root%.}; actual_root=${actual_root%$'\n'}
        [[ $actual_root == "$checkout" ]] ||
            lr_explain "$checkout is inside the Git repository $actual_root; select the top folder of the copy." \
                'Nothing was changed. Pass that folder with --repo DIR, or build in a new folder:' \
                "  bash $script --repo $fresh"
        remote=$(git -C "$checkout" config --get remote.origin.url) || remote='no origin'
        # GitHub owner and repository names are case-insensitive.
        case $(printf '%s' "$remote" | tr '[:upper:]' '[:lower:]') in
            https://github.com/arccal/network-relay|https://github.com/arccal/network-relay.git|git@github.com:arccal/network-relay.git|ssh://git@github.com/arccal/network-relay.git) ;;
            *) lr_explain "$checkout is a Git copy of $remote, not of ArcCal/network-relay." \
                   'Nothing was changed. Choose the right folder with --repo DIR, or build in a new folder:' \
                   "  bash $script --repo $fresh" ;;
        esac
        selected_branch=$(git -C "$checkout" symbolic-ref --short -q HEAD) || selected_branch=
        if [[ $selected_branch != main ]]; then
            lr_explain "$checkout is ${selected_branch:+on branch \"$selected_branch\", }not on the main branch, which the build uses." \
                'Your branch and files were left unchanged. Switch back to main and run this script again:' \
                "  git -C $(printf '%q' "$checkout") switch main" \
                'or leave this copy as it is and build in a new folder:' \
                "  bash $script --repo $fresh"
        fi
        printf '==> Updating existing checkout with pull --ff-only\n'
        if ! lr_github -C "$checkout" fetch origin main; then
            lr_access_help ArcCal/network-relay NETWORK_RELAY_TOKEN
            lr_die 'Could not check for updates; no local files were changed.'
        fi
        fetched=$(git -C "$checkout" rev-parse --verify FETCH_HEAD) || lr_die 'Cannot identify fetched commit.'
        ahead=$(git -C "$checkout" rev-list --count "$fetched..HEAD") || lr_die 'Cannot compare the checkout with GitHub.'
        if (( ahead )); then
            lr_explain "Your copy at $checkout has $ahead commit(s) that are not on GitHub's main branch" \
                "(your own commits, or main was rewritten on GitHub). The build always uses GitHub's main," \
                'and updating could lose or mix in that work, so nothing was changed.' \
                'Build in a new folder instead; this copy stays exactly as it is:' \
                "  bash $script --repo $fresh"
        fi
        behind=$(git -C "$checkout" rev-list --count "HEAD..$fetched") || lr_die 'Cannot compare the checkout with GitHub.'
        if (( behind )); then
            blocked=$(lr_blocking_changes "$checkout" "$fetched")
            if [[ -n $blocked ]]; then
                lr_explain "These files in $checkout were changed on this computer, and the update changes them too:" \
                    "$blocked" \
                    'Updating would overwrite your changes, so nothing was changed. Either build in a new folder' \
                    '(this copy stays exactly as it is):' \
                    "  bash $script --repo $fresh" \
                    'or set your changes aside, run this script, and then bring them back:' \
                    "  git -C $(printf '%q' "$checkout") stash push --include-untracked" \
                    "  bash $script" \
                    "  git -C $(printf '%q' "$checkout") stash pop"
            fi
            if ! lr_remote_git -C "$checkout" pull --ff-only origin main ||
                { [[ -n ${NETWORK_RELAY_TOKEN:-} ]] && lr_token_git -C "$checkout" pull --ff-only origin main; }; then
                lr_explain "Git could not update $checkout (its message is above). Your files were left as they were." \
                    'Run this script again in a few minutes, or build in a new folder:' \
                    "  bash $script --repo $fresh"
            fi
            fetched=$(git -C "$checkout" rev-parse --verify FETCH_HEAD) || lr_die 'Cannot identify fetched commit.'
        else
            printf 'Already up to date.\n'
        fi
        if [[ -n $(git -C "$checkout" status --porcelain) ]]; then
            printf 'Your uncommitted changes in %s were kept; the build does not use them.\n' "$checkout"
        fi
    else
        printf '==> Cloning ArcCal/network-relay\n'
        if ! lr_github clone --depth 1 --single-branch --branch main -- https://github.com/ArcCal/network-relay.git "$checkout"; then
            lr_access_help ArcCal/network-relay NETWORK_RELAY_TOKEN
            lr_die 'Could not download the source code; nothing was changed.'
        fi
        lr_physical_dir "$checkout"; checkout=$REPLY
        fetched=$(git -C "$checkout" rev-parse --verify refs/remotes/origin/main) || lr_die 'Cannot identify cloned commit.'
    fi
    root_commit=$(git -C "$checkout" rev-parse --verify HEAD) || lr_die 'Cannot identify checkout commit.'
    [[ $root_commit == "$fetched" ]] || lr_die 'Local commits differ from fetched main; no local files were reset.'
}
lr_clone_repo() {
    local name=$1 destination=$2 token_name=$3 token header
    if lr_retry lr_remote_git clone --depth 1 --branch main --single-branch -- "https://github.com/ArcCal/$name.git" "$destination"; then return 0; fi
    token=${!token_name:-}
    [[ -n $token ]] || { lr_access_help "ArcCal/$name" "$token_name"; return 1; }
    header=$(printf 'x-access-token:%s' "$token" | base64 | tr -d '\n')
    # The caller only supplies fresh paths in its owned private workspace.
    rm -rf -- "${destination:?}"
    GIT_TERMINAL_PROMPT=0 GIT_CONFIG_COUNT=2 \
        GIT_CONFIG_KEY_0=credential.helper GIT_CONFIG_VALUE_0='' \
        GIT_CONFIG_KEY_1=http.https://github.com/.extraheader \
        GIT_CONFIG_VALUE_1="Authorization: Basic $header" \
        git clone --depth 1 --branch main --single-branch -- "https://github.com/ArcCal/$name.git" "$destination" ||
        { lr_access_help "ArcCal/$name" "$token_name"; return 1; }
}
# Rust comes from static.rust-lang.org; explain a download that keeps failing.
lr_rust_help() {
    printf '\nCould not download Rust %s from static.rust-lang.org.\n' "$RUSTUP_TOOLCHAIN" >&2
    printf 'This is a network problem on this computer, not a problem with the build.\n' >&2
    printf 'Check the internet connection. If a VPN, proxy or firewall is in use, make sure it\n' >&2
    printf 'allows static.rust-lang.org (or turn it off). Then run this script again.\n' >&2
    return 1
}
lr_prepare_rust() {
    lr_retry rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal || lr_rust_help
    lr_retry rustup target add --toolchain "$RUSTUP_TOOLCHAIN" x86_64-unknown-linux-musl aarch64-unknown-linux-musl || lr_rust_help
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
    # The first go command may download the selected Go toolchain.
    lr_retry go version
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
    lr_retry go get -modfile "$build_mod" github.com/caddy-dns/cloudflare@v0.0.0
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
# Free space, in KiB, on the filesystem holding $1 or its nearest existing parent.
lr_free_kib() {
    local dir=$1
    while [[ ! -d $dir ]]; do dir=$(dirname -- "$dir"); done
    df -Pk -- "$dir" | awk 'NR == 2 { print $4 }'
}
# Mount point of the filesystem holding $1 or its nearest existing parent.
lr_mount_of() {
    local dir=$1
    while [[ ! -d $dir ]]; do dir=$(dirname -- "$dir"); done
    df -Pk -- "$dir" | awk 'NR == 2 { print $6 }'
}
lr_gib() { awk -v k="$1" 'BEGIN { printf "%.1f", k / 1048576 }'; }
# Choose where temporary build files go before any long step starts, and check
# that the build tools fit in the home folder. Debian 13 keeps /tmp in memory,
# which can be too small, so the home folder's cache is the fallback.
lr_work_parent() {
    local work_gib=3 tools_gib=1 candidate need home_free tmp_free
    # A first build also installs the Rust toolchain and Go and fills their caches.
    if ! compgen -G "${RUSTUP_HOME:-$HOME/.rustup}/toolchains/${RUSTUP_TOOLCHAIN:-1.99.1}-*" >/dev/null; then
        tools_gib=5
    fi
    home_free=$(lr_free_kib "$HOME")
    for candidate in /tmp "$HOME/.cache"; do
        need=$work_gib
        if [[ $(lr_mount_of "$candidate") == "$(lr_mount_of "$HOME")" ]]; then need=$((need + tools_gib)); fi
        if (( $(lr_free_kib "$candidate") >= need * 1048576 && home_free >= tools_gib * 1048576 )); then
            REPLY=$candidate
            return 0
        fi
    done
    tmp_free=$(lr_free_kib /tmp)
    lr_explain 'There is not enough free disk space to build.' \
        "The build needs about $work_gib GB for temporary files and $tools_gib GB for its tools, but only" \
        "$(lr_gib "$tmp_free") GB is free in /tmp and $(lr_gib "$home_free") GB in your home folder." \
        'Free up space (for example by deleting old build output folders) or use a larger disk,' \
        'then run this script again.'
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
    lr_work_parent
    mkdir -p -- "$REPLY" || lr_die "Cannot create $REPLY."
    stage=$(mktemp -d "$REPLY/relay-servers.XXXXXX") || lr_die 'Cannot create private workspace.'
    if [[ $REPLY != /tmp ]]; then
        # Compilers and Go also write temporary files; keep them off the small /tmp.
        mkdir -- "$stage/tmp"
        export TMPDIR="$stage/tmp"
        printf 'Temporary build files go to %s because /tmp is too small.\n' "$stage"
    fi
    trap 'status=$?; if (( status )); then printf "Update failed (exit %s). Work: %s\n" "$status" "$stage" >&2; fi' EXIT
    printf '%s\n' "$root_commit" > "$stage/.owner"
    git -C "$checkout" show "$root_commit:build-linux-servers-on-linux.sh" > "$stage/driver.sh" || lr_die 'Cannot load newest committed script.'
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
    output=$(mktemp -d "$PWD/relay-servers-$platform-$stamp.XXXXXX") ||
        lr_explain "Cannot create the output folder in $PWD (this folder is not writable)." \
            'Run the script from your home folder (cd ~) or choose a folder with --output DIR.'
    # mktemp creates mode 700; artifacts get ordinary permissions for sharing and sync.
    chmod -- "$(printf '%o' $((0777 & ~$(umask))))" "$output"
elif [[ -e $output || -L $output ]]; then
    if [[ ! -d $output || -L $output ]] || ! lr_empty_dir "$output"; then
        lr_die '--output must be a new or empty directory.'
    fi
else
    mkdir -p -- "$output" || lr_explain "Cannot create the output folder $output." \
        'Choose a folder you can write to with --output DIR, for example one in your home folder.'
fi
lr_physical_dir "$output"; output=$REPLY
[[ $output/ != "$stage/"* && $stage/ != "$output/"* ]] || lr_die 'Output and work directories cannot overlap.'
work=$stage
repo="$work/network-relay-src"
caddy_src="$work/caddy-network-relay-src"
cloudflare_src="$work/cloudflare-src"
mkdir -- "$output/logs"
ln -s -- "$work" "$output/.work"
printf 'Artifacts: %s\nPersistent checkout: %s\nWork directory: %s\n' "$output" "$checkout" "$work"
failures=0
export RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-1.99.1}
if (( install_deps )); then
    export GOTOOLCHAIN=${GOTOOLCHAIN:-go1.27.3+auto}
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
lr_clone_cloudflare() {
    lr_retry env GIT_TERMINAL_PROMPT=0 git clone --depth 1 --branch "$LR_CLOUDFLARE_DNS_TAG" --single-branch -- \
        https://github.com/caddy-dns/cloudflare.git "$cloudflare_src"
    [[ $(git -C "$cloudflare_src" rev-parse --verify HEAD) == "$LR_CLOUDFLARE_DNS_COMMIT" ]] ||
        lr_die "caddy-dns/cloudflare $LR_CLOUDFLARE_DNS_TAG is not the reviewed commit."
}
lr_run source-cloudflare lr_clone_cloudflare
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
    lr_run "build-caddy-network-relay-$arch" lr_build_caddy "$arch"
    lr_run "verify-network-relay-$arch" lr_collect "$work/rust-main/$triple/release/network-relay" network-relay "$arch"
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
        elif [[ $source == "$cloudflare_src" ]]; then branch=$LR_CLOUDFLARE_DNS_TAG; fetched=$LR_CLOUDFLARE_DNS_COMMIT;
        else branch=$(git -C "$source" symbolic-ref --short HEAD); fetched=$(git -C "$source" rev-parse --verify "refs/remotes/origin/$branch"); fi
        [[ $fetched == "$commit" ]] || lr_die "Source commit changed: $source"
        git -C "$source" diff --quiet HEAD -- || lr_die "Build changed tracked sources: $source"
        printf 'Source: %s\nBranch: %s\nCommit: %s\n' "${source##*/}" "$branch" "$commit"
    done
    for arch in amd64 arm64; do
        for program in network-relay caddy-network-relay; do
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
        for program in network-relay caddy-network-relay; do artifact_files+=("$program-linux-$arch"); done
    done
    sha256sum -- "${artifact_files[@]}" MANIFEST.txt > SHA256SUMS || exit
    sha256sum --check SHA256SUMS || exit
)
lr_run checksums lr_checksums
(( failures == 0 )) || lr_die 'Checksum generation or verification failed.'
rm -f -- "$output/.work"
rm -rf -- "${work:?}"
trap - EXIT
printf '\nBoth servers built for amd64 and arm64.\nBoth architectures inspected; native executables also smoke-tested.\nArtifacts: %s\n' "$output"
