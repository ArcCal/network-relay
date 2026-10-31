#!/usr/bin/env bash
# Update the entry script before building Linux servers and macOS GUI clients.
set -euo pipefail
unset CDPATH
# Find tools from rustup and Homebrew even if this shell has not loaded them yet.
for path_entry in /opt/homebrew/bin "${CARGO_HOME:-$HOME/.cargo}/bin"; do
    if [[ -d $path_entry && :$PATH: != *:"$path_entry":* ]]; then PATH="$path_entry:$PATH"; fi
done
export PATH

usage() {
    cat <<'HELP'
Usage: bash build-all-targets-on-macos.sh [--repo DIR] [--output DIR] [--jobs N]

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
Afterwards every folder in the checkout and the artifacts is mode 777.
HELP
}
die() { printf 'build-all-targets-on-macos: %s\n' "$*" >&2; exit 1; }
physical_dir() { REPLY=$(cd -P -- "$1" && printf '%s/' "$PWD"); REPLY=${REPLY%/}; }
remote_git() {
    if command -v gh >/dev/null 2>&1; then
        GIT_TERMINAL_PROMPT=0 git -c 'credential.helper=!gh auth git-credential' "$@"
    else
        GIT_TERMINAL_PROMPT=0 git "$@"
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
# Print local edits that an update to $2 would overwrite, one per line.
blocking_changes() {
    local incoming line path
    incoming=$(git -C "$1" -c core.quotePath=false diff --name-only HEAD "$2" --) || return 0
    git -C "$1" -c core.quotePath=false status --porcelain --untracked-files=all |
        while IFS= read -r line; do
            path=${line:3}
            path=${path##* -> }
            if grep -Fxq -- "$path" <<< "$incoming"; then printf '  %s\n' "$path"; fi
        done
}
update_checkout() {
    local actual_root remote selected_branch fetched has_repo=0 ahead behind blocked script fresh
    printf -v script '%q' "$0"
    printf -v fresh '%q' "$HOME/network-relay-build"
    while [[ $repo == */ && $repo != / ]]; do repo=${repo%/}; done
    if [[ -e $repo || -L $repo ]]; then
        if [[ -d $repo && -e $repo/.git ]]; then has_repo=1;
        elif [[ ! -d $repo || -L $repo ]] || ! empty_dir "$repo"; then
            explain "$repo already exists, but it is not a Git copy of ArcCal/network-relay." \
                'Nothing in it was changed. Rename or move that folder, or build in a new folder:' \
                "  bash $script --repo $fresh"
        fi
    fi
    if (( has_repo )); then
        physical_dir "$repo"; repo=$REPLY
        actual_root=$(git -C "$repo" rev-parse --show-toplevel && printf '.') || die 'Cannot inspect checkout root.'
        actual_root=${actual_root%.}; actual_root=${actual_root%$'\n'}
        [[ $actual_root == "$repo" ]] ||
            explain "$repo is inside the Git repository $actual_root; select the top folder of the copy." \
                'Nothing was changed. Pass that folder with --repo DIR, or build in a new folder:' \
                "  bash $script --repo $fresh"
        remote=$(git -C "$repo" config --get remote.origin.url) || remote='no origin'
        # GitHub owner and repository names are case-insensitive.
        case $(printf '%s' "$remote" | tr '[:upper:]' '[:lower:]') in
            https://github.com/arccal/network-relay|https://github.com/arccal/network-relay.git|git@github.com:arccal/network-relay.git|ssh://git@github.com/arccal/network-relay.git) ;;
            *) explain "$repo is a Git copy of $remote, not of ArcCal/network-relay." \
                   'Nothing was changed. Choose the right folder with --repo DIR, or build in a new folder:' \
                   "  bash $script --repo $fresh" ;;
        esac
        selected_branch=$(git -C "$repo" symbolic-ref --short -q HEAD) || selected_branch=
        if [[ $selected_branch != main ]]; then
            explain "$repo is ${selected_branch:+on branch \"$selected_branch\", }not on the main branch, which the build uses." \
                'Your branch and files were left unchanged. Switch back to main and run this script again:' \
                "  git -C $(printf '%q' "$repo") switch main" \
                'or leave this copy as it is and build in a new folder:' \
                "  bash $script --repo $fresh"
        fi
        printf '==> Updating existing checkout with pull --ff-only\n'
        if ! github -C "$repo" fetch origin main; then
            access_help ArcCal/network-relay
            die 'Could not check for updates; no local files were changed.'
        fi
        fetched=$(git -C "$repo" rev-parse --verify FETCH_HEAD) || die 'Cannot identify fetched commit.'
        ahead=$(git -C "$repo" rev-list --count "$fetched..HEAD") || die 'Cannot compare the checkout with GitHub.'
        if (( ahead )); then
            explain "Your copy at $repo has $ahead commit(s) that are not on GitHub's main branch" \
                "(your own commits, or main was rewritten on GitHub). The build always uses GitHub's main," \
                'and updating could lose or mix in that work, so nothing was changed.' \
                'Build in a new folder instead; this copy stays exactly as it is:' \
                "  bash $script --repo $fresh"
        fi
        behind=$(git -C "$repo" rev-list --count "HEAD..$fetched") || die 'Cannot compare the checkout with GitHub.'
        if (( behind )); then
            blocked=$(blocking_changes "$repo" "$fetched")
            if [[ -n $blocked ]]; then
                explain "These files in $repo were changed on this computer, and the update changes them too:" \
                    "$blocked" \
                    'Updating would overwrite your changes, so nothing was changed. Either build in a new folder' \
                    '(this copy stays exactly as it is):' \
                    "  bash $script --repo $fresh" \
                    'or set your changes aside, run this script, and then bring them back:' \
                    "  git -C $(printf '%q' "$repo") stash push --include-untracked" \
                    "  bash $script" \
                    "  git -C $(printf '%q' "$repo") stash pop"
            fi
            if ! remote_git -C "$repo" pull --ff-only origin main; then
                explain "Git could not update $repo (its message is above). Your files were left as they were." \
                    'Run this script again in a few minutes, or build in a new folder:' \
                    "  bash $script --repo $fresh"
            fi
            fetched=$(git -C "$repo" rev-parse --verify FETCH_HEAD) || die 'Cannot identify fetched commit.'
        else
            printf 'Already up to date.\n'
        fi
        if [[ -n $(git -C "$repo" status --porcelain) ]]; then
            printf 'Your uncommitted changes in %s were kept; the build does not use them.\n' "$repo"
        fi
    else
        printf '==> Cloning ArcCal/network-relay\n'
        if ! github clone --single-branch --branch main -- https://github.com/ArcCal/network-relay.git "$repo"; then
            access_help ArcCal/network-relay
            die 'Could not download the source code; nothing was changed.'
        fi
        physical_dir "$repo"; repo=$REPLY
        fetched=$(git -C "$repo" rev-parse --verify refs/remotes/origin/main) || die 'Cannot identify cloned commit.'
    fi
    commit=$(git -C "$repo" rev-parse --verify HEAD) || die 'Cannot identify checkout commit.'
    [[ $commit == "$fetched" ]] || die 'Local commits differ from fetched main; no local files were reset.'
}
# Called indirectly by EXIT traps.
# shellcheck disable=SC2317,SC2329
report_failure() {
    local relay_exit_status=$?
    if (( relay_exit_status )); then
        printf 'Build/update failed (exit %s). Work retained: %s\n' \
            "$relay_exit_status" "${build_work:-not created}" >&2
    fi
    open_dirs
}
# Leave the source folder, and every folder below it, open to all users.
# shellcheck disable=SC2317,SC2329
open_dirs() {
    local dir
    for dir in "${relay_checkout:-}" "${build_work:-}"; do
        [[ -n $dir && -d $dir && ! -L $dir ]] || continue
        find "$dir" -type d -exec chmod 777 {} + 2>/dev/null || true
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
    [[ ${build_work##*/} == relay-mac.* && -d $build_work && ! -L $build_work &&
       -f $build_work/.owner && ! -L $build_work/.owner &&
       $(cat "$build_work/.owner") == "$commit" ]] || die 'Invalid private build workspace.'
    trap report_failure EXIT
    git -C "$repo" show "$commit:build-macos-gui-clients-on-macos.sh" > "$build_work/gui-driver.sh"
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
    local commit
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
    relay_checkout=$repo
    trap open_dirs EXIT
    update_checkout
    relay_checkout=$repo
    build_work=$(mktemp -d /private/tmp/relay-mac.XXXXXX)
    trap report_failure EXIT
    printf '%s\n' "$commit" > "$build_work/.owner"
    git -C "$repo" show "$commit:build-all-targets-on-macos.sh" > "$build_work/driver.sh"
    [[ -s $build_work/driver.sh ]] || die 'Updated all-target build script is missing.'
    exec "$BASH" "$build_work/driver.sh" --build-updated \
        "$repo" "$build_work" "$output" "$commit" "$jobs"
}
# Parse this line before an in-place pull can replace the original script file.
main "$@"; exit
