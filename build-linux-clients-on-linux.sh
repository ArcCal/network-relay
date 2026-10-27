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
Supported hosts: Debian 13 and Ubuntu 26.04, on x64 or arm64.

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

Rust 1.99.1 (or RUSTUP_TOOLCHAIN), Zig and cargo-zigbuild produce static musl
executables named network-relay-rs-linux-amd64 and -arm64. Both architectures
are inspected; native files also run --version and --help. SHA256SUMS,
MANIFEST.txt and logs stay with the artifacts. Failed builds keep .work.
Afterwards every folder in the checkout and the artifacts is mode 777.
Network steps are retried. Debian 13 keeps /tmp in memory; when it is too small,
temporary files go to ~/.cache instead. Free disk space is checked first.
No client is installed or connected and no system proxy settings are changed.
HELP
}

lc_die() { printf 'build-linux-clients-on-linux: %s\n' "$*" >&2; exit 1; }
# Leave the source and artifact folders, and every folder below them, open to all users.
lc_open_dirs() {
    local dir
    for dir in "$@"; do
        [[ -n $dir && -d $dir && ! -L $dir ]] || continue
        find "$dir" -type d -exec chmod 777 {} + 2>/dev/null || true
    done
}

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
        debian:13:aarch64|debian:13:arm64) platform=debian-13-arm64; host_arch=arm64 ;;
        ubuntu:26.04:x86_64) platform=ubuntu-26.04-amd64; host_arch=amd64 ;;
        ubuntu:26.04:aarch64|ubuntu:26.04:arm64) platform=ubuntu-26.04-arm64; host_arch=arm64 ;;
        *) lc_die 'Supported hosts: Debian 13 or Ubuntu 26.04 on x64 or arm64.' ;;
    esac
}

lc_check_tools() {
    local missing=0 tool targets triple
    for tool in git curl cc pkg-config file sha256sum rustup rustc cargo zig cargo-zigbuild readelf; do
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

lc_install_system() {
    local apt_command=(apt-get)
    if (( EUID != 0 )); then
        command -v sudo >/dev/null || lc_die 'Installing missing system packages needs administrator rights. Run this script again with sudo, or ask an administrator to run it once.'
        apt_command=(sudo apt-get)
    fi
    # apt retries interrupted downloads itself.
    "${apt_command[@]}" -o Acquire::Retries=3 update
    "${apt_command[@]}" -o Acquire::Retries=3 install -y --no-install-recommends \
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
        curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 5 https://sh.rustup.rs -o "$installer" || {
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

# Run a network command up to three times, 5 and then 15 seconds apart.
lc_retry() {
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
lc_explain() {
    printf '\n' >&2
    printf '%s\n' "$@" >&2
    printf '\n' >&2
    exit 1
}
# Plain-language help after GitHub could not be reached or read.
lc_access_help() {
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
lc_github() {
    lc_retry lc_remote_git "$@" && return 0
    [[ -n ${NETWORK_RELAY_TOKEN:-} ]] || return 1
    printf 'Trying once more with NETWORK_RELAY_TOKEN.\n' >&2
    lc_token_git "$@"
}
# Print local edits that an update to $2 would overwrite, one per line.
lc_blocking_changes() {
    local incoming line path
    incoming=$(git -C "$1" -c core.quotePath=false diff --name-only HEAD "$2" --) || return 0
    git -C "$1" -c core.quotePath=false status --porcelain --untracked-files=all |
        while IFS= read -r line; do
            path=${line:3}
            path=${path##* -> }
            if grep -Fxq -- "$path" <<< "$incoming"; then printf '  %s\n' "$path"; fi
        done
}
lc_update_checkout() {
    local actual_root remote selected_branch fetched has_repo=0 ahead behind blocked script fresh
    printf -v script '%q' "$0"
    printf -v fresh '%q' "$HOME/network-relay-build"
    while [[ $checkout == */ && $checkout != / ]]; do checkout=${checkout%/}; done
    if [[ -e $checkout || -L $checkout ]]; then
        if [[ -d $checkout && -e $checkout/.git ]]; then has_repo=1;
        elif [[ ! -d $checkout || -L $checkout ]] || ! lc_empty_dir "$checkout"; then
            lc_explain "$checkout already exists, but it is not a Git copy of ArcCal/network-relay." \
                'Nothing in it was changed. Rename or move that folder, or build in a new folder:' \
                "  bash $script --repo $fresh"
        fi
    fi
    if (( has_repo )); then
        lc_physical_dir "$checkout"; checkout=$REPLY
        actual_root=$(git -C "$checkout" rev-parse --show-toplevel && printf '.') || lc_die 'Cannot inspect checkout root.'
        actual_root=${actual_root%.}; actual_root=${actual_root%$'\n'}
        [[ $actual_root == "$checkout" ]] ||
            lc_explain "$checkout is inside the Git repository $actual_root; select the top folder of the copy." \
                'Nothing was changed. Pass that folder with --repo DIR, or build in a new folder:' \
                "  bash $script --repo $fresh"
        remote=$(git -C "$checkout" config --get remote.origin.url) || remote='no origin'
        # GitHub owner and repository names are case-insensitive.
        case $(printf '%s' "$remote" | tr '[:upper:]' '[:lower:]') in
            https://github.com/arccal/network-relay|https://github.com/arccal/network-relay.git|git@github.com:arccal/network-relay.git|ssh://git@github.com/arccal/network-relay.git) ;;
            *) lc_explain "$checkout is a Git copy of $remote, not of ArcCal/network-relay." \
                   'Nothing was changed. Choose the right folder with --repo DIR, or build in a new folder:' \
                   "  bash $script --repo $fresh" ;;
        esac
        selected_branch=$(git -C "$checkout" symbolic-ref --short -q HEAD) || selected_branch=
        if [[ $selected_branch != main ]]; then
            lc_explain "$checkout is ${selected_branch:+on branch \"$selected_branch\", }not on the main branch, which the build uses." \
                'Your branch and files were left unchanged. Switch back to main and run this script again:' \
                "  git -C $(printf '%q' "$checkout") switch main" \
                'or leave this copy as it is and build in a new folder:' \
                "  bash $script --repo $fresh"
        fi
        printf '==> Updating existing checkout with pull --ff-only\n'
        if ! lc_github -C "$checkout" fetch origin main; then
            lc_access_help ArcCal/network-relay NETWORK_RELAY_TOKEN
            lc_die 'Could not check for updates; no local files were changed.'
        fi
        fetched=$(git -C "$checkout" rev-parse --verify FETCH_HEAD) || lc_die 'Cannot identify fetched commit.'
        ahead=$(git -C "$checkout" rev-list --count "$fetched..HEAD") || lc_die 'Cannot compare the checkout with GitHub.'
        if (( ahead )); then
            lc_explain "Your copy at $checkout has $ahead commit(s) that are not on GitHub's main branch" \
                "(your own commits, or main was rewritten on GitHub). The build always uses GitHub's main," \
                'and updating could lose or mix in that work, so nothing was changed.' \
                'Build in a new folder instead; this copy stays exactly as it is:' \
                "  bash $script --repo $fresh"
        fi
        behind=$(git -C "$checkout" rev-list --count "HEAD..$fetched") || lc_die 'Cannot compare the checkout with GitHub.'
        if (( behind )); then
            blocked=$(lc_blocking_changes "$checkout" "$fetched")
            if [[ -n $blocked ]]; then
                lc_explain "These files in $checkout were changed on this computer, and the update changes them too:" \
                    "$blocked" \
                    'Updating would overwrite your changes, so nothing was changed. Either build in a new folder' \
                    '(this copy stays exactly as it is):' \
                    "  bash $script --repo $fresh" \
                    'or set your changes aside, run this script, and then bring them back:' \
                    "  git -C $(printf '%q' "$checkout") stash push --include-untracked" \
                    "  bash $script" \
                    "  git -C $(printf '%q' "$checkout") stash pop"
            fi
            if ! lc_remote_git -C "$checkout" pull --ff-only origin main ||
                { [[ -n ${NETWORK_RELAY_TOKEN:-} ]] && lc_token_git -C "$checkout" pull --ff-only origin main; }; then
                lc_explain "Git could not update $checkout (its message is above). Your files were left as they were." \
                    'Run this script again in a few minutes, or build in a new folder:' \
                    "  bash $script --repo $fresh"
            fi
            fetched=$(git -C "$checkout" rev-parse --verify FETCH_HEAD) || lc_die 'Cannot identify fetched commit.'
        else
            printf 'Already up to date.\n'
        fi
        if [[ -n $(git -C "$checkout" status --porcelain) ]]; then
            printf 'Your uncommitted changes in %s were kept; the build does not use them.\n' "$checkout"
        fi
    else
        printf '==> Cloning ArcCal/network-relay\n'
        if ! lc_github clone --depth 1 --single-branch --branch main -- https://github.com/ArcCal/network-relay.git "$checkout"; then
            lc_access_help ArcCal/network-relay NETWORK_RELAY_TOKEN
            lc_die 'Could not download the source code; nothing was changed.'
        fi
        lc_physical_dir "$checkout"; checkout=$REPLY
        fetched=$(git -C "$checkout" rev-parse --verify refs/remotes/origin/main) || lc_die 'Cannot identify cloned commit.'
    fi
    root_commit=$(git -C "$checkout" rev-parse --verify HEAD) || lc_die 'Cannot identify checkout commit.'
    [[ $root_commit == "$fetched" ]] || lc_die 'Local commits differ from fetched main; no local files were reset.'
}

# Rust comes from static.rust-lang.org; explain a download that keeps failing.
lc_rust_help() {
    printf '\nCould not download Rust %s from static.rust-lang.org.\n' "$RUSTUP_TOOLCHAIN" >&2
    printf 'This is a network problem on this computer, not a problem with the build.\n' >&2
    printf 'Check the internet connection. If a VPN, proxy or firewall is in use, make sure it\n' >&2
    printf 'allows static.rust-lang.org (or turn it off). Then run this script again.\n' >&2
    return 1
}
lc_prepare_rust() {
    lc_retry rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal || lc_rust_help
    lc_retry rustup target add --toolchain "$RUSTUP_TOOLCHAIN" x86_64-unknown-linux-musl aarch64-unknown-linux-musl || lc_rust_help
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

# Free space, in KiB, on the filesystem holding $1 or its nearest existing parent.
lc_free_kib() {
    local dir=$1
    while [[ ! -d $dir ]]; do dir=$(dirname -- "$dir"); done
    df -Pk -- "$dir" | awk 'NR == 2 { print $4 }'
}
# Mount point of the filesystem holding $1 or its nearest existing parent.
lc_mount_of() {
    local dir=$1
    while [[ ! -d $dir ]]; do dir=$(dirname -- "$dir"); done
    df -Pk -- "$dir" | awk 'NR == 2 { print $6 }'
}
lc_gib() { awk -v k="$1" 'BEGIN { printf "%.1f", k / 1048576 }'; }
# Choose where temporary build files go before any long step starts, and check
# that the build tools fit in the home folder. Debian 13 keeps /tmp in memory,
# which can be too small, so the home folder's cache is the fallback.
lc_work_parent() {
    local work_gib=2 tools_gib=1 candidate need home_free tmp_free
    # A first build also installs the Rust toolchain and fills their caches.
    if ! compgen -G "${RUSTUP_HOME:-$HOME/.rustup}/toolchains/${RUSTUP_TOOLCHAIN:-1.99.1}-*" >/dev/null; then
        tools_gib=2
    fi
    home_free=$(lc_free_kib "$HOME")
    for candidate in /tmp "$HOME/.cache"; do
        need=$work_gib
        if [[ $(lc_mount_of "$candidate") == "$(lc_mount_of "$HOME")" ]]; then need=$((need + tools_gib)); fi
        if (( $(lc_free_kib "$candidate") >= need * 1048576 && home_free >= tools_gib * 1048576 )); then
            REPLY=$candidate
            return 0
        fi
    done
    tmp_free=$(lc_free_kib /tmp)
    lc_explain 'There is not enough free disk space to build.' \
        "The build needs about $work_gib GB for temporary files and $tools_gib GB for its tools, but only" \
        "$(lc_gib "$tmp_free") GB is free in /tmp and $(lc_gib "$home_free") GB in your home folder." \
        'Free up space (for example by deleting old build output folders) or use a larger disk,' \
        'then run this script again.'
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
    trap 'lc_open_dirs "$checkout"' EXIT
    lc_update_checkout
    lc_work_parent
    mkdir -p -- "$REPLY" || lc_die "Cannot create $REPLY."
    stage=$(mktemp -d "$REPLY/network-relay-linux-clients.XXXXXX") || lc_die 'Cannot create private workspace.'
    if [[ $REPLY != /tmp ]]; then
        # Compilers and Go also write temporary files; keep them off the small /tmp.
        mkdir -- "$stage/tmp"
        export TMPDIR="$stage/tmp"
        printf 'Temporary build files go to %s because /tmp is too small.\n' "$stage"
    fi
    trap 'status=$?; if (( status )); then printf "Update failed (exit %s). Work: %s\n" "$status" "$stage" >&2; fi; lc_open_dirs "$checkout" "$stage"' EXIT
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
trap 'status=$?; if (( status )); then printf "Build incomplete (exit %s). Work: %s; artifacts/logs: %s\n" "$status" "$stage" "${output:-not created}" >&2; fi; lc_open_dirs "$checkout" "$output" "$stage"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
lc_host
printf 'Build host: %s; targets: linux-amd64, linux-arm64 (static headless clients)\n' "$platform"
export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
while [[ $output == */ && $output != / ]]; do output=${output%/}; done
if [[ -z $output ]]; then
    stamp=$(date -u +%Y%m%d-%H%M%S)
    output=$(mktemp -d "$PWD/network-relay-linux-clients-$platform-$stamp.XXXXXX") ||
        lc_explain "Cannot create the output folder in $PWD (this folder is not writable)." \
            'Run the script from your home folder (cd ~) or choose a folder with --output DIR.'
    # mktemp creates mode 700; artifacts get ordinary permissions for sharing and sync.
    chmod -- "$(printf '%o' $((0777 & ~$(umask))))" "$output"
elif [[ -e $output || -L $output ]]; then
    if [[ ! -d $output || -L $output ]] || ! lc_empty_dir "$output"; then lc_die '--output must be a new or empty directory.'; fi
else
    mkdir -p -- "$output" || lc_explain "Cannot create the output folder $output." \
        'Choose a folder you can write to with --output DIR, for example one in your home folder.'
fi
lc_physical_dir "$output"; output=$REPLY
[[ $output/ != "$stage/"* && $stage/ != "$output/"* ]] || lc_die 'Output and work directories cannot overlap.'
work=$stage
repo="$work/network-relay-src"
mkdir -- "$output/logs"
ln -s -- "$work" "$output/.work"
printf 'Artifacts: %s\nPersistent checkout: %s\nWork directory: %s\n' "$output" "$checkout" "$work"
failures=0
export RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-1.99.1}
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
printf '\nLinux headless clients built for amd64 and arm64.\nArtifacts: %s\n' "$output"
