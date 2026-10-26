#!/usr/bin/env bash
# Update the entry script before building Linux servers and macOS GUI clients.
set -euo pipefail
unset CDPATH

usage() {
    cat <<'HELP'
Usage: bash build-all-targets.sh [--repo DIR] [--output DIR] [--jobs N]

Build network-relay, network-relay-cf-masque and Caddy Network Relay for
Linux x64 and arm64, plus the Network Relay NF and RS macOS applications.
Also build the Rust RS command-line client for Linux x64, Linux arm64 and
macOS arm64.
The Caddy executable includes the Cloudflare DNS plugin.
Requires an Apple silicon Mac, macOS 27+ and an Xcode macOS 27+ SDK.

  --repo DIR    persistent checkout (default: NETWORK_RELAY_SRC or
                ~/network-relay)
  --output DIR  new or empty artifact directory (default: a unique directory
                under ~/Desktop/Network-Relay-Builds)
  --jobs N      Rust compilation jobs (default: 2)
  --help        show this help

First run clones ArcCal/network-relay. Each later run updates main with
pull --ff-only origin main and executes the latest committed scripts.
Local commits are refused. Uncommitted files are preserved and are never
used as build inputs. Git credentials must allow reading both repositories.
Compilation and signing use a private /private/tmp workspace.
HELP
}
die() { printf 'build-all-targets: %s\n' "$*" >&2; exit 1; }
physical_dir() { REPLY=$(cd -P -- "$1" && printf '%s/' "$PWD"); REPLY=${REPLY%/}; }
remote_git() {
    if command -v gh >/dev/null 2>&1; then
        GIT_TERMINAL_PROMPT=0 git -c 'credential.helper=!gh auth git-credential' "$@"
    else
        GIT_TERMINAL_PROMPT=0 git "$@"
    fi
}
# Called indirectly by EXIT traps.
# shellcheck disable=SC2317,SC2329
report_failure() {
    local relay_exit_status=$?
    if (( relay_exit_status )); then
        printf 'Build/update failed (exit %s). Work retained: %s\n' \
            "$relay_exit_status" "${build_work:-not created}" >&2
    fi
}
check_host() {
    local version sdk tool
    [[ $(uname -s) == Darwin && $(uname -m) == arm64 ]] || die 'An Apple silicon Mac is required.'
    for tool in git sw_vers xcrun mktemp; do
        command -v "$tool" >/dev/null || die "Missing required tool: $tool"
    done
    version=$(sw_vers -productVersion)
    [[ ${version%%.*} =~ ^[0-9]+$ ]] || die 'Cannot determine the macOS version.'
    (( ${version%%.*} >= 27 )) || die 'macOS 27 or newer is required.'
    if [[ -z ${DEVELOPER_DIR:-} && -d /Applications/Xcode.app/Contents/Developer ]]; then
        export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
    fi
    sdk=$(xcrun --sdk macosx --show-sdk-version)
    [[ ${sdk%%.*} =~ ^[0-9]+$ ]] || die 'An Xcode macOS 27+ SDK is required.'
    (( ${sdk%%.*} >= 27 )) || die 'An Xcode macOS 27+ SDK is required.'
}
build_updated() {
    local repo=$1 commit=$4 jobs=$5
    build_work=$2
    [[ $commit =~ ^[0-9a-f]{40}$ && $jobs =~ ^[1-9][0-9]*$ ]] || die 'Invalid internal build arguments.'
    [[ ${build_work##*/} == relay-mac.* && -d $build_work && ! -L $build_work &&
       -f $build_work/.owner && ! -L $build_work/.owner &&
       $(cat "$build_work/.owner") == "$commit" ]] || die 'Invalid private build workspace.'
    trap report_failure EXIT
    git -C "$repo" show "$commit:build-macos-gui.sh" > "$build_work/gui-driver.sh"
    [[ -s $build_work/gui-driver.sh ]] || die 'Updated macOS build engine is missing.'
    exec "$BASH" "$build_work/gui-driver.sh" --build-updated \
        "$repo" "$build_work" "$3" "$commit" all "$jobs"
}
main() {
    if [[ ${1:-} == --build-updated ]]; then
        [[ $# == 6 ]] || die 'Invalid internal build invocation.'
        build_updated "$2" "$3" "$4" "$5" "$6"
        return
    fi
    local repo=${NETWORK_RELAY_SRC:-"$HOME/network-relay"} output='' jobs=2
    local remote branch commit fetched root entries clone_needed=1
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
    while [[ $repo != / && $repo == */ ]]; do repo=${repo%/}; done
    check_host
    if [[ -e $repo || -L $repo ]]; then
        [[ -d $repo ]] || die "Existing path is not a repository directory: $repo"
        if [[ -e $repo/.git ]]; then
            physical_dir "$repo"; repo=$REPLY
            root=$(git -C "$repo" rev-parse --show-toplevel && printf '.')
            root=${root%$'\n'.}
            [[ $root == "$repo" ]] || die 'The selected directory must be the repository root.'
            remote=$(git -C "$repo" config --get remote.origin.url) || die 'The checkout has no origin remote.'
            case $remote in
                https://github.com/ArcCal/network-relay|https://github.com/ArcCal/network-relay.git|git@github.com:ArcCal/network-relay.git|ssh://git@github.com/ArcCal/network-relay.git) ;;
                *) die 'origin must point to ArcCal/network-relay on GitHub.' ;;
            esac
            branch=$(git -C "$repo" symbolic-ref --short HEAD) || die 'Use a main checkout; detached HEAD is left unchanged.'
            [[ $branch == main ]] || die 'Use a main checkout; other branches are left unchanged.'
            printf '==> Updating existing checkout with pull --ff-only\n'
            remote_git -C "$repo" pull --ff-only origin main
            fetched=$(git -C "$repo" rev-parse --verify FETCH_HEAD)
            clone_needed=0
        else
            [[ ! -L $repo ]] || die 'An empty checkout destination cannot be a symbolic link.'
            entries=$(ls -A -- "$repo" && printf '.') || die 'Cannot inspect checkout destination.'
            [[ $entries == . ]] || die "Existing nonempty directory is not a Git checkout: $repo"
        fi
    fi
    if (( clone_needed )); then
        printf '==> Cloning ArcCal/network-relay\n'
        remote_git clone --single-branch --branch main -- \
            https://github.com/ArcCal/network-relay.git "$repo"
        physical_dir "$repo"; repo=$REPLY
        fetched=$(git -C "$repo" rev-parse --verify refs/remotes/origin/main)
    fi
    commit=$(git -C "$repo" rev-parse --verify HEAD)
    [[ $commit == "$fetched" ]] || die 'Local commits differ from fetched main; no local files were reset.'
    build_work=$(mktemp -d /private/tmp/relay-mac.XXXXXX)
    trap report_failure EXIT
    printf '%s\n' "$commit" > "$build_work/.owner"
    git -C "$repo" show "$commit:build-all-targets.sh" > "$build_work/driver.sh"
    [[ -s $build_work/driver.sh ]] || die 'Updated all-target build script is missing.'
    exec "$BASH" "$build_work/driver.sh" --build-updated \
        "$repo" "$build_work" "$output" "$commit" "$jobs"
}
# Parse this line before an in-place pull can replace the original script file.
main "$@"; exit
