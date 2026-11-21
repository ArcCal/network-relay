#!/usr/bin/env bash
# Download current source, then build the independent Network Relay GUI apps.
# All A && B || die guards intentionally reject failure of either predicate.
# shellcheck disable=SC2015
set -euo pipefail
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    # New artifacts may be shared, but never writable by other users.
    # Respect a caller's stricter umask and preserve all existing directory modes.
    umask "$(printf '%03o' "$(( $(umask) | 0022 ))")"
fi

# BEGIN SHARED BUILD CHILD RUNNER
relay_build_group_active() {
    ps -A -o pgid= -o stat= | awk -v group="$1" '
        $1 == group && $2 !~ /^Z/ { active = 1 }
        END { exit !active }'
}

relay_build_terminal_group() {
    PYTHONDONTWRITEBYTECODE=1 python3 - "$1" <<'PY'
import os
import signal
import sys

signal.signal(signal.SIGTTOU, signal.SIG_IGN)
try:
    fd = os.open('/dev/tty', os.O_RDWR)
    try:
        if sys.argv[1] == 'get':
            print(os.tcgetpgrp(fd))
        else:
            os.tcsetpgrp(fd, int(sys.argv[1]))
    finally:
        os.close(fd)
except OSError:
    sys.exit(1)
PY
}

relay_stop_build_child() {
    local child=${1:-} group=${2:-} wait_cleanup=${3:-0} child_signal=${4-TERM} attempt
    [[ $child =~ ^[1-9][0-9]*$ ]] || return 0
    if [[ $group == "$child" ]]; then
        if [[ -n $child_signal ]]; then kill -"$child_signal" -- "-$group" 2>/dev/null || true; fi
        # A terminal reader can have stopped before foreground ownership moved.
        # Let it handle the pending signal and finish any installer rollback.
        kill -CONT -- "-$group" 2>/dev/null || true
        if (( wait_cleanup )); then
            # Installers may be restoring a live deployment. Do not kill their
            # rollback or delete their source while that cleanup is running.
            while relay_build_group_active "$group"; do sleep 0.1; done
            return 0
        fi
        for ((attempt = 0; attempt < 10; attempt++)); do
            relay_build_group_active "$group" || return 0
            sleep 0.1
        done
        kill -KILL -- "-$group" 2>/dev/null || true
    else
        if [[ -n $child_signal ]]; then kill -"$child_signal" "$child" 2>/dev/null || true; fi
        kill -CONT "$child" 2>/dev/null || true
    fi
}

relay_run_build_child() {
    local relay_child_pid='' relay_child_group='' relay_child_status=0 relay_child_interrupted=0
    local relay_child_monitor=0 relay_child_actual relay_child_int relay_child_term relay_child_hup relay_child_wait=0
    local relay_child_tty='' relay_child_parent_group relay_child_final_signal=TERM
    if [[ ${1:-} == --wait-for-cleanup ]]; then relay_child_wait=1; shift; fi
    [[ $# -gt 0 ]] || return 2
    if ! command -v ps >/dev/null || ! ps -A -o pgid= -o stat= >/dev/null 2>&1; then
        printf 'Build process cleanup requires ps (procps on Linux).\n' >&2
        return 125
    fi
    if { : </dev/tty; } 2>/dev/null; then
        if ! command -v python3 >/dev/null; then
            printf 'Interactive build process cleanup requires Python 3.\n' >&2
            return 125
        fi
        relay_child_tty=$(relay_build_terminal_group get) || return 125
        relay_child_parent_group=$(ps -o pgid= -p "$$") || return 125
        relay_child_parent_group=${relay_child_parent_group//[[:space:]]/}
        # A deliberately backgrounded build must not take the user's terminal.
        [[ $relay_child_tty == "$relay_child_parent_group" ]] || relay_child_tty=''
    fi
    relay_child_int=$(trap -p INT)
    relay_child_term=$(trap -p TERM)
    relay_child_hup=$(trap -p HUP)
    case $- in *m*) relay_child_monitor=1 ;; esac
    trap 'relay_child_interrupted=130; trap "" INT TERM HUP; relay_stop_build_child "$relay_child_pid" "$relay_child_group" "$relay_child_wait"' INT
    trap 'relay_child_interrupted=143; trap "" INT TERM HUP; relay_stop_build_child "$relay_child_pid" "$relay_child_group" "$relay_child_wait"' TERM
    trap 'relay_child_interrupted=129; trap "" INT TERM HUP; relay_stop_build_child "$relay_child_pid" "$relay_child_group" "$relay_child_wait"' HUP
    # Job control creates a group distinct from the caller. Disable it inside
    # the runner so cargo, rustc and their children stay in that owned group.
    set -m
    (
        set +m
        trap - EXIT INT TERM HUP
        "$@"
    ) &
    relay_child_pid=$! relay_child_group=$!
    (( relay_child_monitor )) || set +m
    relay_child_actual=$(ps -o pgid= -p "$relay_child_pid" 2>/dev/null) || relay_child_actual=''
    relay_child_actual=${relay_child_actual//[[:space:]]/}
    if [[ -n $relay_child_actual && $relay_child_actual != "$relay_child_pid" ]]; then
        # Never send a group signal unless this is the group we just created.
        relay_child_group=''
        relay_child_interrupted=125
        relay_stop_build_child "$relay_child_pid" ''
    fi
    if (( relay_child_interrupted )); then
        relay_stop_build_child "$relay_child_pid" "$relay_child_group" "$relay_child_wait"
    fi
    if [[ -n $relay_child_tty && -n $relay_child_group && $relay_child_interrupted == 0 ]]; then
        if ! relay_build_terminal_group "$relay_child_group" && relay_build_group_active "$relay_child_group"; then
            relay_child_interrupted=125
            relay_stop_build_child "$relay_child_pid" "$relay_child_group" "$relay_child_wait"
        fi
        kill -CONT -- "-$relay_child_group" 2>/dev/null || true
    fi
    if wait "$relay_child_pid"; then relay_child_status=0; else relay_child_status=$?; fi
    # A command can exit before a helper it spawned. Stop those helpers before
    # its caller removes sources/caches, and reap our direct child after signals.
    if (( relay_child_wait && !relay_child_interrupted )) &&
       [[ $relay_child_status == 129 || $relay_child_status == 130 || $relay_child_status == 143 ]]; then
        # A terminal signal already reached the foreground group. Do not send
        # a second signal while a surviving installer is restoring deployment.
        relay_child_final_signal=''
    fi
    relay_stop_build_child "$relay_child_pid" "$relay_child_group" "$relay_child_wait" "$relay_child_final_signal"
    wait "$relay_child_pid" 2>/dev/null || true
    [[ -z $relay_child_tty ]] || relay_build_terminal_group "$relay_child_tty" || true
    trap - INT TERM HUP
    [[ -z $relay_child_int ]] || eval "$relay_child_int"
    [[ -z $relay_child_term ]] || eval "$relay_child_term"
    [[ -z $relay_child_hup ]] || eval "$relay_child_hup"
    if (( relay_child_interrupted )); then return "$relay_child_interrupted"; fi
    return "$relay_child_status"
}
# END SHARED BUILD CHILD RUNNER

unset CDPATH
# Find tools from rustup and Homebrew even if this shell has not loaded them yet.
for rg_path in /opt/homebrew/bin "${CARGO_HOME:-$HOME/.cargo}/bin"; do
    if [[ -d $rg_path && :$PATH: != *:"$rg_path":* ]]; then PATH="$rg_path:$PATH"; fi
done
export PATH

rg_die() { printf 'build-macos-gui-clients-on-macos: %s\n' "$*" >&2; exit 1; }
rg_cleanup_sources() {
    local directory
    for directory in "${checkout:-}" "${work:-}"; do
        case $directory in
            /tmp/network-relay-*|/private/tmp/network-relay-*|/tmp/relay-mac-*|/private/tmp/relay-mac-*)
                [[ ! -L $directory ]] || continue
                find -P "$directory" -type d -exec chmod u+rwx {} + 2>/dev/null || true
                rm -rf -- "$directory" ;;
        esac
    done
    if [[ ${rg_work_link_created:-0} == 1 ]]; then rm -f -- "$output/.work"; fi
}
rg_dir() { REPLY=$(cd -P -- "$1" && printf '%s/' "$PWD"); REPLY=${REPLY%/}; }
rg_empty() {
    local entries
    [[ -r $1 && -x $1 ]] || return 1
    entries=$(ls -A -- "$1" && printf '.') || return 1
    [[ $entries == . ]]
}
rg_remote_git() {
    # Use an existing gh login without changing global Git configuration.
    if command -v gh >/dev/null; then
        GIT_TERMINAL_PROMPT=0 git -c protocol.file.allow=never -c 'credential.helper=!gh auth git-credential' "$@"
    else
        GIT_TERMINAL_PROMPT=0 git -c protocol.file.allow=never "$@"
    fi
}
rg_usage() {
    cat <<'HELP'
Usage: bash build-macos-gui-clients-on-macos.sh [--repo DIR] [--output DIR] [--jobs N]

Build Network Relay NF, RS and Tun, including their original tests,
ad-hoc signatures and ZIPs. Requires an Apple silicon Mac, macOS 27+, the
macOS 27+ Xcode SDK with XCTest, Rust/rustup, and Git access to the repository.
No Linux servers, Go, Zig or unrelated applications are built.

  --repo DIR    accepted for compatibility; local checkouts are never reused
                (NETWORK_RELAY_SRC is likewise ignored).
  --output DIR  new or empty artifact directory; existing files are preserved.
                Default: a unique folder under ~/Desktop/Network-Relay-Builds
                or NETWORK_RELAY_BUILD_ROOT.
  --jobs N      Cargo compilation jobs (default: 2).

Every run downloads complete main sources, including Git history, into a new
/tmp/network-relay-YYYYMMDD-HHMMSS.RANDOM directory and executes the newly
fetched script. Local checkouts are left untouched. Builds and signing use /tmp.
App names include the software, macOS and arm64. Logs, source revisions and
SHA256SUMS are kept with the artifacts. Temporary work is removed on every exit.
Existing folder modes are preserved; new artifact folders are at most 755, subject to your umask.
Temporary source and work are removed on exit.
RUSTUP_TOOLCHAIN defaults to 1.99.1. Existing local checkouts are never deleted.
HELP
}
# Use an Xcode with the macOS 27 SDK, including one installed as Xcode-beta.app.
rg_select_xcode() {
    local app sdk
    [[ -z ${DEVELOPER_DIR:-} ]] || return 0
    for app in /Applications/Xcode.app /Applications/Xcode*.app; do
        [[ -d $app/Contents/Developer ]] || continue
        sdk=$(DEVELOPER_DIR=$app/Contents/Developer xcrun --sdk macosx --show-sdk-version 2>/dev/null) || continue
        if [[ ${sdk%%.*} =~ ^[0-9]+$ ]] && (( ${sdk%%.*} >= 27 )); then
            export DEVELOPER_DIR=$app/Contents/Developer
            return 0
        fi
    done
}
# Install rustup for this user when Rust is missing, as the Linux builders do.
rg_rustup() {
    local installer
    command -v rustup >/dev/null && return 0
    printf '==> Rust is not installed; installing rustup for this user account\n'
    (
        installer=$(mktemp "/tmp/relay-rustup-$(date +%Y%m%d-%H%M%S).XXXXXX") || exit 1
        trap 'rm -f -- "$installer"' EXIT
        curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 5 https://sh.rustup.rs -o "$installer" &&
            sh "$installer" -y --profile minimal --default-toolchain none --no-modify-path
    ) || return 1
    export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"

}
rg_host() {
    local version sdk tool
    [[ $(uname -s) == Darwin && $(uname -m) == arm64 ]] || rg_die 'An Apple silicon Mac is required.'
    version=$(sw_vers -productVersion)
    [[ ${version%%.*} =~ ^[0-9]+$ ]] && (( ${version%%.*} >= 27 )) || rg_die 'macOS 27 or newer is required. Update macOS in System Settings > General > Software Update, then run this script again.'
    git --version >/dev/null 2>&1 || rg_die "Apple's developer tools are missing, so Git cannot run. Install Xcode 27 from the App Store and open it once (or run: xcode-select --install), then run this script again."
    rg_select_xcode
    sdk=$(xcrun --sdk macosx --show-sdk-version 2>/dev/null) || sdk=
    [[ ${sdk%%.*} =~ ^[0-9]+$ ]] && (( ${sdk%%.*} >= 27 )) || rg_die "Xcode 27 with the macOS 27 SDK is required. Install or update Xcode from the App Store, open it once to finish its setup, then run this script again."
    xcrun --sdk macosx --find xctest >/dev/null 2>&1 || rg_die 'Xcode with XCTest is required. Open Xcode once so it can finish installing its components, then run this script again.'
    rg_rustup || rg_die 'Rust could not be installed automatically. Check the internet connection, or install it from https://rustup.rs, then run this script again.'
    for tool in git rustup rustc cargo swift swiftc sips iconutil otool file codesign ditto plutil xattr unzip shasum find xargs mktemp install; do
        command -v "$tool" >/dev/null || rg_die "Missing required tool: $tool. It is part of macOS and Xcode; install Xcode 27 from the App Store, open it once, then run this script again."
    done
}
# Run a network command up to three times, 5 and then 15 seconds apart.
rg_retry() {
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
rg_explain() {
    printf '\n' >&2
    printf '%s\n' "$@" >&2
    printf '\n' >&2
    exit 1
}
# Plain-language help after GitHub could not be reached or read.
rg_access_help() {
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
rg_github() {
    rg_retry rg_remote_git "$@" && return 0
    return 1
}
# Always download into a new temporary checkout; local paths are never inputs.
rg_update() {
    if [[ -n $checkout ]]; then
        printf 'Ignoring --repo/NETWORK_RELAY_SRC: every build uses fresh remote sources.\n'
    fi
    checkout=$(mktemp -d "/tmp/network-relay-$(date +%Y%m%d-%H%M%S).XXXXXX")
    printf '==> Cloning latest complete ArcCal/network-relay main into %s\n' "$checkout"
    if relay_run_build_child rg_github clone --recurse-submodules --branch main -- https://github.com/ArcCal/network-relay.git "$checkout"; then :; else
        local clone_status=$?
        case $clone_status in 129|130|143) exit "$clone_status" ;; esac
        rg_access_help ArcCal/network-relay
        rg_die 'Could not download current sources; no local checkout will be used.'
    fi
    rg_dir "$checkout"; checkout=$REPLY
    # shellcheck disable=SC1091
    source "$checkout/tools/fresh-build-source.sh"
    relay_mark_fresh_source "$checkout"
    root_commit=$(git -C "$checkout" rev-parse --verify refs/remotes/origin/main) || rg_die 'Cannot identify cloned main commit.'
    [[ $(git -C "$checkout" rev-parse --verify HEAD) == "$root_commit" ]] || rg_die 'Cloned checkout does not match main.'
}
rg_main() {
    checkout=${NETWORK_RELAY_SRC:-}
    output=; jobs=2
    while (( $# )); do
        case $1 in
            -h|--help) rg_usage; return ;;
            --repo|--output|--jobs)
                [[ $# -ge 2 && -n $2 && $2 != --* ]] || rg_die "Pass a value to $1."
                case $1 in --repo) checkout=$2 ;; --output) output=$2 ;; --jobs) jobs=$2 ;; esac
                shift 2 ;;
            *) rg_usage >&2; rg_die "Unknown argument: $1" ;;
        esac
    done
    [[ $jobs =~ ^[1-9][0-9]*$ ]] || rg_die '--jobs must be a positive integer.'
    work=$(mktemp -d "/tmp/relay-mac-$(date +%Y%m%d-%H%M%S).XXXXXX")
    trap rg_cleanup_sources EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
trap 'exit 129' HUP
    trap 'exit 129' HUP
    mkdir -m 700 -- "$work/tmp"
    export TMPDIR="$work/tmp"
    relay_run_build_child rg_host
    rg_update
    trap 'status=$?; if (( status )); then printf "Update failed (exit %s). Temporary work will be removed.\n" "$status" >&2; fi; rg_cleanup_sources' EXIT
    printf '%s\n' "$root_commit" > "$work/.owner"
    git -C "$checkout" show "$root_commit:build-macos-gui-clients-on-macos.sh" > "$work/driver.sh" || rg_die 'Cannot load the latest GUI script.'
    [[ -s $work/driver.sh ]] || rg_die 'The latest GUI script is empty.'
    relay_run_build_child --wait-for-cleanup "$BASH" "$work/driver.sh" --build-updated "$checkout" "$work" "$output" "$root_commit" gui "$jobs"
}
# Public invocations bootstrap once before loading the downloaded engine.
if [[ ${1:-} != --build-updated ]]; then rg_main "$@"; exit; fi

[[ $# == 7 ]] || rg_die 'Invalid internal invocation.'
checkout=$2; work=$3; output=$4; root_commit=$5; mode=$6; jobs=$7
[[ $mode == gui || $mode == all ]] && [[ $jobs =~ ^[1-9][0-9]*$ && $root_commit =~ ^[0-9a-f]{40}$ ]] || rg_die 'Invalid build selection.'
[[ ( $work == /tmp/relay-mac-* || $work == /private/tmp/relay-mac-* ) && -d $work && ! -L $work && -f $work/.owner && ! -L $work/.owner &&
   $(cat "$work/.owner") == "$root_commit" ]] || rg_die 'Invalid private workspace.'
# shellcheck disable=SC1091
source "$checkout/tools/fresh-build-source.sh"
relay_source_is_current "$checkout" || rg_die 'The internal source handoff is not from this build invocation.'
repo="$work/sources/network-relay"
logs=
rg_work_link_created=0
trap 'status=$?; if (( status )); then printf "Build failed (exit %s). Artifacts/logs: %s\nTemporary source and work will be removed.\n" "$status" "${output:-not created}" >&2; fi; rg_cleanup_sources' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
mkdir -p -- "$work/tmp"
export TMPDIR="$work/tmp"
rg_host
while [[ $output != / && $output == */ ]]; do output=${output%/}; done
if [[ -z $output ]]; then
    parent=${NETWORK_RELAY_BUILD_ROOT:-"$HOME/Desktop/Network-Relay-Builds"}
    mkdir -p -- "$parent"
    stem=macos-gui; [[ $mode != all ]] || stem=all
    output=$(mktemp -d "$parent/network-relay-$stem-$(date -u +%Y%m%d-%H%M%S).XXXXXX")
    # mktemp creates mode 700; artifacts get ordinary permissions for sharing and sync.
    chmod -- "$(printf '%o' $((0755 & ~$(umask))))" "$output"
elif [[ -e $output || -L $output ]]; then
    [[ -d $output && ! -L $output ]] && rg_empty "$output" || rg_die '--output must be new or empty, and not a symlink.'
else
    mkdir -p -- "$output"
fi
rg_dir "$output"; output=$REPLY
[[ $output/ != "$work/"* && $work/ != "$output/"* ]] || rg_die 'Output and work directories cannot overlap.'
logs="$output/logs"
mkdir -- "$logs"
mkdir -m 700 -- "$work/sources"
ln -s -- "$work" "$output/.work"
rg_work_link_created=1
printf 'Artifacts: %s\nTemporary checkout: %s\nPrivate workspace: %s\nSource commit: %s\n' "$output" "$checkout" "$work" "$root_commit"
# Check free space before any long step. These are estimates from the Linux
# builds of the same code: about 6 GB for the apps, 10 GB with every target.
rg_space_gib=6; [[ $mode != all ]] || rg_space_gib=10
rg_free_kib=$(df -Pk -- "$work" | awk 'NR == 2 { print $4 }')
if (( rg_free_kib < rg_space_gib * 1048576 )); then
    rg_die "Not enough free disk space: the build needs about $rg_space_gib GB, but only $(awk -v k="$rg_free_kib" 'BEGIN { printf "%.1f", k / 1048576 }') GB is free. Empty the Trash or delete old build folders, then run this script again."
fi

rg_failures=0
rg_step() {
    local name=$1 status
    shift
    printf '==> %s\n' "$name"
    set +e
    ( set -euo pipefail; relay_run_build_child "$@" ) > "$logs/$name.log" 2>&1
    status=$?
    set -e
    case $status in 129|130|143) exit "$status" ;; esac
    if (( status )); then
        rg_failures=$((rg_failures + 1))
        printf '    FAILED (exit %s); log: %s/%s.log\n' "$status" "$logs" "$name" >&2
        tail -n 20 "$logs/$name.log" >&2
    else
        printf '    ok\n'
    fi
}
rg_require() { (( rg_failures == 0 )) || rg_die "$rg_failures step(s) failed; temporary sources will be removed; logs remain with the artifacts."; }
rg_snapshot() {
    git clone --no-hardlinks --no-checkout -- "$checkout" "$repo"
    git -C "$repo" checkout --detach "$root_commit"
}
rg_clone() {
    rg_retry rg_remote_git clone --recurse-submodules --branch "$3" -- "https://github.com/$1.git" "$2" ||
        { rg_access_help "$1"; return 1; }
}
rg_step source-network-relay rg_snapshot
rg_require
relay_mark_fresh_source "$repo"
caddy_src="$work/sources/caddy-network-relay-src"
cloudflare_src="$work/sources/cloudflare-src"
if [[ $mode == all ]]; then
    rg_require
    # The Linux entry pins the reviewed Cloudflare DNS plugin release.
    # shellcheck disable=SC1091
    source "$repo/build-linux-servers-on-linux.sh"
    rg_step source-caddy-network-relay rg_clone ArcCal/caddy-network-relay "$caddy_src" main
    rg_step source-cloudflare rg_clone caddy-dns/cloudflare "$cloudflare_src" "$LR_CLOUDFLARE_DNS_TAG"
fi
rg_require
caddy_commit=; cloudflare_commit=
if [[ $mode == all ]]; then
    caddy_commit=$(git -C "$caddy_src" rev-parse HEAD)
    cloudflare_commit=$(git -C "$cloudflare_src" rev-parse HEAD)
    [[ $cloudflare_commit == "$LR_CLOUDFLARE_DNS_COMMIT" ]] ||
        rg_die "caddy-dns/cloudflare $LR_CLOUDFLARE_DNS_TAG is not the reviewed commit."
fi
# Discard ambient build flags without discarding proxy or registry credentials.
while IFS='=' read -r key _value; do
    case $key in
        CARGO_TARGET_DIR|CARGO_BUILD_TARGET|CARGO_BUILD_RUSTFLAGS|CARGO_TARGET_*|CARGO_PROFILE_*|RUSTFLAGS|RUSTDOCFLAGS|CARGO_ENCODED_RUSTFLAGS|CC|CXX|AR|LD|CC_*|CXX_*|AR_*|CFLAGS*|CXXFLAGS*|CPPFLAGS*|LDFLAGS|SDKROOT|MACOSX_DEPLOYMENT_TARGET|GOOS|GOARCH|GOAMD64|GOARM64|GOFLAGS|CGO_*) unset "$key" ;;
    esac
done < <(env)
export RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-1.99.1}
export CARGO_BUILD_JOBS="$jobs" CARGO_ENCODED_RUSTFLAGS=''
if [[ $mode == all ]]; then
    relay_prepare_build_environment "$work" aarch64-apple-darwin x86_64-unknown-linux-musl aarch64-unknown-linux-musl
else
    relay_prepare_build_environment "$work" aarch64-apple-darwin
fi
export HOMEBREW_CACHE="$work/homebrew-cache" HOMEBREW_LOGS="$work/homebrew-logs" HOMEBREW_TEMP="$work/tmp"
export COPYFILE_DISABLE=1
export GOTOOLCHAIN=${GOTOOLCHAIN:-go1.27.4+auto} GOWORK=off GOFLAGS='' GOAMD64=v1 GOARM64=v8.0
rg_attributes() { find -P "$1" \( -type f -o -type d \) -exec xattr -c {} +; }
# Rust comes from static.rust-lang.org; explain a download that keeps failing.
rg_rust_help() {
    printf '\nCould not download Rust %s from static.rust-lang.org.\n' "$RUSTUP_TOOLCHAIN" >&2
    printf 'This is a network problem on this computer, not a problem with the build.\n' >&2
    printf 'Check the internet connection. If a VPN, proxy or firewall is in use, make sure it\n' >&2
    printf 'allows static.rust-lang.org (or turn it off). Then run this script again.\n' >&2
    return 1
}
rg_rust() {
    [[ ${RELAY_REUSE_RUST_TOOLCHAIN:-0} != 1 ]] || return 0
    rg_retry rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal || rg_rust_help
    rg_retry rustup target add --toolchain "$RUSTUP_TOOLCHAIN" aarch64-apple-darwin || rg_rust_help
    if [[ $mode == all ]]; then
        rg_retry rustup target add --toolchain "$RUSTUP_TOOLCHAIN" x86_64-unknown-linux-musl aarch64-unknown-linux-musl || rg_rust_help
    fi
}
rg_cross_tools() {
    if ! command -v zig >/dev/null; then command -v brew >/dev/null || rg_die 'Install Homebrew from https://brew.sh (or Zig), then run this script again.'; rg_retry brew install zig; fi
    if ! command -v cargo-zigbuild >/dev/null; then cargo install --locked cargo-zigbuild; fi
    if ! command -v go >/dev/null; then command -v brew >/dev/null || rg_die 'Install Homebrew from https://brew.sh (or Go), then run this script again.'; rg_retry brew install go; fi
    zig version
    cargo-zigbuild --version
    go version
}
rg_step toolchain-rust rg_rust
if [[ $mode == all ]]; then rg_step toolchain-cross rg_cross_tools; fi
rg_require
rg_step source-attributes rg_attributes "$repo"
rg_require
rg_build_app() { cd -- "$repo"; "$BASH" "$repo/$1/build-macos.sh"; }
rg_step macos-network-relay-nf rg_build_app network-relay-nf
rg_step macos-network-relay-rs rg_build_app network-relay-rs
rg_step macos-network-relay-tun rg_build_app network-relay-tun

rg_replacement() {
    awk -F '\t' -v module="$2" -v replacement="$3" '
        ($2 == "dep" || $2 == "mod") && $3 == module { pending=1; next }
        pending { if ($2 == "=>" && $3 == replacement) found=1; pending=0 }
        END { exit !found }
    ' <<< "$1"
}
rg_binary() {
    local source=$1 name=$2 arch=$3 description info
    [[ -f $source && -s $source && -x $source ]] || rg_die "Missing executable: $source"
    description=$(LC_ALL=C file -b -- "$source")
    case $arch in
        amd64) [[ $description == ELF* && $description == *x86-64* && $description == *static* ]] ;;
        arm64) [[ $description == ELF* && $description == *aarch64* && $description == *static* ]] ;;
        *) false ;;
    esac || rg_die "Expected a static Linux $arch executable: $source ($description)"
    if [[ $name == caddy-network-relay ]]; then
        info=$(go version -m "$source")
        grep -Eq '^[[:space:]]*path[[:space:]]+github\.com/arccal/caddy-network-relay/cmd/caddy$' <<< "$info"
        rg_replacement "$info" github.com/caddy-dns/cloudflare ../cloudflare-src
        rg_replacement "$info" golang.org/x/net ./third_party/x-net
        rg_replacement "$info" github.com/quic-go/quic-go ./third_party/quic-go
    fi
    install -m 755 -- "$source" "$output/$name-linux-$arch"
}
rg_servers() {
    # Reuse the Linux entry's build recipes, including its Caddy patch overlay.
    # shellcheck disable=SC1091
    source "$repo/build-linux-servers-on-linux.sh"
    # Read by the sourced Caddy helper.
    # shellcheck disable=SC2034
    host_arch=arm64
    lr_prepare_caddy
    local arch triple
    for arch in amd64 arm64; do
        case $arch in amd64) triple=x86_64-unknown-linux-musl ;; arm64) triple=aarch64-unknown-linux-musl ;; esac
        lr_build_rust "$repo/Cargo.toml" "$work/rust-main" "$triple" --bin network-relay
        lr_build_rust "$repo/network-relay-cf-masque/Cargo.toml" "$work/rust-cf" "$triple" --bin network-relay-cf-masque
        lr_build_rust "$repo/network-relay-vless/Cargo.toml" "$work/rust-vless" "$triple" --bin network-relay-vless
        lr_build_rust "$repo/network-relay-rs/Cargo.toml" "$work/rust-rs" "$triple" --bin network-relay-rs
        lr_build_caddy "$arch"
        rg_binary "$work/rust-main/$triple/release/network-relay" network-relay "$arch"
        rg_binary "$work/rust-cf/$triple/release/network-relay-cf-masque" network-relay-cf-masque "$arch"
        rg_binary "$work/rust-vless/$triple/release/network-relay-vless" network-relay-vless "$arch"
        rg_binary "$work/rust-rs/$triple/release/network-relay-rs" network-relay-rs "$arch"
        rg_binary "$work/caddy-network-relay-$arch" caddy-network-relay "$arch"
    done
}
rg_app() {
    local source=$1 name=$2 executable description
    [[ -d $source && ! -L $source ]] || rg_die "Missing application: $source"
    executable=$(plutil -extract CFBundleExecutable raw "$source/Contents/Info.plist")
    [[ -n $executable && $executable != */* && -f $source/Contents/MacOS/$executable ]] || rg_die "Missing application executable: $source"
    description=$(LC_ALL=C file -b -- "$source/Contents/MacOS/$executable")
    [[ $description == *Mach-O*arm64* ]] || rg_die "Wrong application architecture: $source"
    codesign --verify --deep --strict "$source"
    ditto --norsrc --noextattr --noqtn "$source" "$output/$name"
    rg_attributes "$output/$name"
    codesign --verify --deep --strict "$output/$name"
}
rg_zip() (
    local directory=$1 prefix=$2
    shopt -s nullglob
    archives=("$directory/$prefix"-*-macos-arm64.zip)
    [[ ${#archives[@]} == 1 && -f ${archives[0]} && -s ${archives[0]} ]] || rg_die "Expected one $prefix ZIP in $directory"
    unzip -tq "${archives[0]}" || exit
    cp -- "${archives[0]}" "$output/" || exit
)
rg_mac_cli() {
    local source="$RELAY_BUILD_WORK_ROOT/rust-rs-target/aarch64-apple-darwin/release/network-relay-rs" description
    [[ -s $source && -x $source ]] || rg_die 'Missing Mac Rust command-line client.'
    description=$(LC_ALL=C file -b -- "$source")
    [[ $description == *Mach-O*arm64* ]] || rg_die 'Wrong Mac command-line client architecture.'
    # Sign in the private build tree before exporting to Desktop/iCloud.
    rg_attributes "$source"
    codesign --force --sign - "$source"
    codesign --verify --strict "$source"
    install -m 755 -- "$source" "$output/network-relay-rs-macos-arm64"
    rg_attributes "$output/network-relay-rs-macos-arm64"
    codesign --verify --strict "$output/network-relay-rs-macos-arm64"
    "$output/network-relay-rs-macos-arm64" --version
    "$output/network-relay-rs-macos-arm64" --help
}
rg_step collect-nf-app rg_app "$repo/network-relay-nf/dist/Network Relay NF.app" network-relay-nf-macos-arm64.app
rg_step collect-rs-app rg_app "$repo/network-relay-rs/dist/Network Relay RS.app" network-relay-rs-macos-arm64.app
rg_step collect-tun-app rg_app "$repo/network-relay-tun/dist/Network Relay Tun.app" network-relay-tun-macos-arm64.app
rg_step collect-nf-zip rg_zip "$repo/network-relay-nf/dist" NetworkRelayNF
rg_step collect-rs-zip rg_zip "$repo/network-relay-rs/dist" NetworkRelayRS
rg_step collect-tun-zip rg_zip "$repo/network-relay-tun/dist" NetworkRelayTun
if [[ $mode == all ]]; then rg_step collect-macos-rust-cli rg_mac_cli; fi
# Export successful Mac products before an independent Linux build can fail.
if [[ $mode == all ]]; then rg_step linux-servers-both-architectures rg_servers; fi
rg_require
rg_source_record() {
    [[ $(git -C "$1" rev-parse HEAD) == "$3" ]] || rg_die "Source revision changed: $2"
    git -C "$1" diff --quiet HEAD -- || rg_die "Tracked source changed: $2"
    printf 'Source: %s\nCommit: %s\n' "$2" "$3"
}
rg_manifest() {
    local built host rust_version
    built=$(date -u +%FT%TZ)
    host=$(uname -mrs)
    rust_version=$(rustc --version)
    {
        printf 'Built: %s\nHost: %s\nRust: %s\nSelection: %s\n' "$built" "$host" "$rust_version" "$mode"
        rg_source_record "$repo" ArcCal/network-relay "$root_commit"
        if [[ $mode == all ]]; then
            rg_source_record "$caddy_src" ArcCal/caddy-network-relay "$caddy_commit"
            rg_source_record "$cloudflare_src" caddy-dns/cloudflare "$cloudflare_commit"
            printf 'Linux: static amd64/arm64; architecture and Go build information inspected, not executed on this Mac.\n'
            printf 'VLESS: network-relay-vless-linux-amd64 and network-relay-vless-linux-arm64.\n'
            printf 'Rust CLI: Linux amd64/arm64 and macOS arm64; native Mac --help/--version checked.\n'
        fi
        printf 'Mac: NF, RS and Tun original client tests, bundle architecture and strict signatures checked.\n'
    } > "$output/MANIFEST.txt"
}
rg_checksums() (
    cd -- "$output" || exit
    local expected=(network-relay-nf-macos-arm64.app network-relay-rs-macos-arm64.app network-relay-tun-macos-arm64.app NetworkRelayNF-*-macos-arm64.zip NetworkRelayRS-*-macos-arm64.zip NetworkRelayTun-*-macos-arm64.zip MANIFEST.txt)
    if [[ $mode == all ]]; then
        expected+=(network-relay-linux-amd64 network-relay-linux-arm64 network-relay-cf-masque-linux-amd64 network-relay-cf-masque-linux-arm64 network-relay-vless-linux-amd64 network-relay-vless-linux-arm64 caddy-network-relay-linux-amd64 caddy-network-relay-linux-arm64 network-relay-rs-linux-amd64 network-relay-rs-linux-arm64 network-relay-rs-macos-arm64)
    fi
    find -P "${expected[@]}" -type f -print0 | xargs -0 shasum -a 256 > "$logs/checksums.part" || exit
    [[ -s $logs/checksums.part ]] || rg_die 'Checksum manifest is empty.'
    mv -- "$logs/checksums.part" SHA256SUMS || exit
    shasum -a 256 --check SHA256SUMS || exit
)
rg_step manifest rg_manifest
rg_require
rg_step checksums rg_checksums
rg_require
rg_cleanup() { relay_remove_build_work "${work:?}"; rm -f -- "$output/.work"; }
rg_step cleanup rg_cleanup
rg_require
printf '\nAll selected builds and artifact checks passed.\nArtifacts: %s\n' "$output"
