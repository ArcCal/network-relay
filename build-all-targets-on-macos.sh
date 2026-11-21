#!/usr/bin/env bash
# Download the latest source before building Linux servers and macOS GUI clients.
set -euo pipefail
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    # New artifacts may be shared, but never writable by other users.
    # Respect a caller's stricter umask and preserve all existing directory modes.
    umask "$(printf '%03o' "$(( $(umask) | 0022 ))")"
fi
unset CDPATH

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

# Find tools from rustup and Homebrew even if this shell has not loaded them yet.
for path_entry in /opt/homebrew/bin "${CARGO_HOME:-$HOME/.cargo}/bin"; do
    if [[ -d $path_entry && :$PATH: != *:"$path_entry":* ]]; then PATH="$path_entry:$PATH"; fi
done
export PATH

usage() {
    cat <<'HELP'
Usage: bash build-all-targets-on-macos.sh [--repo DIR] [--output DIR] [--jobs N]

Build network-relay, network-relay-cf-masque, network-relay-vless and Caddy
Network Relay for Linux x64 and arm64, plus the NF, RS and Tun macOS applications.
Also build the Rust RS command-line client for Linux x64, Linux arm64 and
macOS arm64.
The Caddy executable includes the Cloudflare DNS plugin.
Requires an Apple silicon Mac, macOS 27+ and an Xcode macOS 27+ SDK.

  --repo DIR    accepted for compatibility; local checkouts are never reused
                (NETWORK_RELAY_SRC is likewise ignored)
  --output DIR  new or empty artifact directory (default:
                ~/Desktop/YYYYMMDD-HHMMSS, using local time)
  --jobs N      Rust compilation jobs (default: 2)
  --help        show this help

Every run downloads a complete main checkout from GitHub into a new
/tmp/network-relay-YYYYMMDD-HHMMSS.RANDOM directory, including Git history.
Always execute the latest committed scripts. Local checkouts and their edits
are left untouched. Git credentials must allow reading both repositories.
Compilation, caches and signing use a separate private /tmp workspace,
removed on success or failure.
Existing folder modes are preserved; new artifact folders are at most 755, subject to your umask.
Temporary source and work are removed on exit.
HELP
}
die() { printf 'build-all-targets-on-macos: %s\n' "$*" >&2; exit 1; }
physical_dir() { REPLY=$(cd -P -- "$1" && printf '%s/' "$PWD"); REPLY=${REPLY%/}; }
remote_git() {
    if command -v gh >/dev/null 2>&1; then
        GIT_TERMINAL_PROMPT=0 git -c protocol.file.allow=never -c 'credential.helper=!gh auth git-credential' "$@"
    else
        GIT_TERMINAL_PROMPT=0 git -c protocol.file.allow=never "$@"
    fi
}
empty_dir() {
    local entries
    [[ -r $1 && -x $1 ]] || return 1
    entries=$(ls -A -- "$1" && printf '.') || return 1
    [[ $entries == . ]]
}
# Run a network command up to three times, 5 and then 15 seconds apart.
retry() {
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
explain() {
    printf '\n' >&2
    printf '%s\n' "$@" >&2
    printf '\n' >&2
    exit 1
}
# Plain-language help after GitHub could not be reached or read.
access_help() {
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
github() {
    retry remote_git "$@" && return 0
    return 1
}
# Always download into a new temporary checkout; local paths are never inputs.
update_checkout() {
    if [[ -n $repo ]]; then
        printf 'Ignoring --repo/NETWORK_RELAY_SRC: every build uses fresh remote sources.\n'
    fi
    repo=$(mktemp -d "/tmp/network-relay-$(date +%Y%m%d-%H%M%S).XXXXXX")
    relay_checkout=$repo
    printf '==> Cloning latest complete ArcCal/network-relay main into %s\n' "$repo"
    if relay_run_build_child github clone --recurse-submodules --branch main -- https://github.com/ArcCal/network-relay.git "$repo"; then :; else
        local clone_status=$?
        case $clone_status in 129|130|143) exit "$clone_status" ;; esac
        access_help ArcCal/network-relay
        die 'Could not download current sources; no local checkout will be used.'
    fi
    physical_dir "$repo"; repo=$REPLY
    # shellcheck disable=SC1091
    source "$repo/tools/fresh-build-source.sh"
    relay_mark_fresh_source "$repo"
    commit=$(git -C "$repo" rev-parse --verify refs/remotes/origin/main) || die 'Cannot identify cloned main commit.'
    [[ $(git -C "$repo" rev-parse --verify HEAD) == "$commit" ]] || die 'Cloned checkout does not match main.'
}
# Called indirectly by EXIT traps.
# shellcheck disable=SC2317,SC2329
report_failure() {
    local relay_exit_status=$?
    if (( relay_exit_status )); then
        printf 'Build/update failed (exit %s). Temporary source and work will be removed.\n' "$relay_exit_status" >&2
    fi
    cleanup_temporary
}
# Only directories allocated by this invocation are eligible for removal.
cleanup_temporary() {
    local directory
    for directory in "${relay_checkout:-}" "${build_work:-}"; do
        case $directory in
            /tmp/network-relay-*|/private/tmp/network-relay-*|/tmp/relay-mac-*|/private/tmp/relay-mac-*)
                [[ ! -L $directory ]] || continue
                find -P "$directory" -type d -exec chmod u+rwx {} + 2>/dev/null || true
                rm -rf -- "$directory" ;;
        esac
    done
}
# Use an Xcode with the macOS 27 SDK, including one installed as Xcode-beta.app.
select_xcode() {
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
check_host() {
    local version sdk tool
    [[ $(uname -s) == Darwin && $(uname -m) == arm64 ]] || die 'An Apple silicon Mac is required.'
    for tool in git sw_vers xcrun mktemp; do
        command -v "$tool" >/dev/null || die "Missing required tool: $tool. Install Xcode 27 from the App Store, open it once, then run this script again."
    done
    git --version >/dev/null 2>&1 || die "Apple's developer tools are missing, so Git cannot run. Install Xcode 27 from the App Store and open it once (or run: xcode-select --install), then run this script again."
    version=$(sw_vers -productVersion)
    [[ ${version%%.*} =~ ^[0-9]+$ ]] || die 'Cannot determine the macOS version.'
    (( ${version%%.*} >= 27 )) || die 'macOS 27 or newer is required. Update macOS in System Settings > General > Software Update, then run this script again.'
    select_xcode
    sdk=$(xcrun --sdk macosx --show-sdk-version 2>/dev/null) || sdk=
    [[ ${sdk%%.*} =~ ^[0-9]+$ ]] || die "Xcode 27 with the macOS 27 SDK is required. Install or update Xcode from the App Store, open it once to finish its setup, then run this script again."
    (( ${sdk%%.*} >= 27 )) || die "Xcode 27 with the macOS 27 SDK is required. Install or update Xcode from the App Store, open it once to finish its setup, then run this script again."
}
build_updated() {
    local repo=$1 commit=$4 jobs=$5
    build_work=$2 relay_checkout=$1
    [[ $commit =~ ^[0-9a-f]{40}$ && $jobs =~ ^[1-9][0-9]*$ ]] || die 'Invalid internal build arguments.'
    [[ ( $build_work == /tmp/relay-mac-* || $build_work == /private/tmp/relay-mac-* ) && -d $build_work && ! -L $build_work &&
       -f $build_work/.owner && ! -L $build_work/.owner &&
       $(cat "$build_work/.owner") == "$commit" ]] || die 'Invalid private build workspace.'
    trap report_failure EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    # shellcheck disable=SC1091
    source "$repo/tools/fresh-build-source.sh"
    relay_source_is_current "$repo" || die 'The internal source handoff is not from this build invocation.'
    git -C "$repo" show "$commit:build-macos-gui-clients-on-macos.sh" > "$build_work/gui-driver.sh"
    [[ -s $build_work/gui-driver.sh ]] || die 'Updated macOS build engine is missing.'
    relay_run_build_child --wait-for-cleanup "$BASH" "$build_work/gui-driver.sh" --build-updated \
        "$repo" "$build_work" "$3" "$commit" all "$jobs"
}
main() {
    if [[ ${1:-} == --build-updated ]]; then
        [[ $# == 6 ]] || die 'Invalid internal build invocation.'
        build_updated "$2" "$3" "$4" "$5" "$6"
        return
    fi
    local repo=${NETWORK_RELAY_SRC:-} output='' jobs=2
    local commit parent
    while (( $# )); do
        case $1 in
            -h|--help) usage; return ;;
            --repo|--output|--jobs)
                [[ $# -ge 2 && -n $2 && $2 != --* ]] || die "Pass a value to $1."
                case $1 in
                    --repo) repo=$2 ;;
                    --output) output=$2 ;;
                    --jobs) jobs=$2 ;;
                esac
                shift 2 ;;
            *) die "Unknown argument: $1" ;;
        esac
    done
    [[ $jobs =~ ^[1-9][0-9]*$ ]] || die '--jobs must be a positive integer.'
    check_host
    relay_checkout=
    trap cleanup_temporary EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    update_checkout
    relay_checkout=$repo
    if [[ -z $output ]]; then
        parent=${NETWORK_RELAY_BUILD_ROOT:-"$HOME/Desktop"}
        mkdir -p -- "$parent"
        output="$parent/$(date +%Y%m%d-%H%M%S)"
        mkdir -- "$output" || die 'Timestamped output directory already exists or cannot be created; use --output DIR.'
    fi
    build_work=$(mktemp -d "/tmp/relay-mac-$(date +%Y%m%d-%H%M%S).XXXXXX")
    trap report_failure EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    printf '%s\n' "$commit" > "$build_work/.owner"
    git -C "$repo" show "$commit:build-all-targets-on-macos.sh" > "$build_work/driver.sh"
    [[ -s $build_work/driver.sh ]] || die 'Updated all-target build script is missing.'
    relay_run_build_child --wait-for-cleanup "$BASH" "$build_work/driver.sh" --build-updated \
        "$repo" "$build_work" "$output" "$commit" "$jobs"
}
# Bootstrap once, then run the downloaded build engine.
main "$@"; exit
