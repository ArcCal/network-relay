#!/usr/bin/env bash
# Shared source bootstrap; sourcing this file does not start a build.

relay_source_die() { printf 'fresh-build-source: %s\n' "$*" >&2; exit 1; }

relay_source_root() { (unset CDPATH; cd -P -- "$1" && pwd); }

relay_source_local_git() { env -u CF_API_TOKEN git "$@"; }

relay_remove_build_work() {
    local directory
    for directory in "$@"; do
        [[ -d $directory && ! -L $directory && -O $directory ]] || continue
        # Go module cache directories may be read-only. Never follow toolchain
        # links into a caller's existing installation when making work writable.
        find -P "$directory" -type d -exec chmod u+w {} + 2>/dev/null || true
        rm -rf -- "${directory:?}"
    done
}

relay_build_disk_backed() {
    local kind
    [[ $(uname -s) == Linux ]] || return 0
    kind=$(df -PT -- "$1" | awk 'NR == 2 { print $2 }') || return 1
    [[ -n $kind && $kind != tmpfs && $kind != ramfs ]]
}

relay_build_work_parent() {
    local need=${1:-3145728} directory free
    for directory in /tmp /var/tmp "$HOME" "$PWD"; do
        [[ -d $directory && -w $directory ]] || continue
        relay_build_disk_backed "$directory" || continue
        free=$(df -Pk -- "$directory" | awk 'NR == 2 { print $4 }') || continue
        if [[ $free =~ ^[0-9]+$ ]] && (( free >= need )); then
            printf '%s\n' "$directory"
            return 0
        fi
    done
    printf 'A writable disk-backed directory with at least %s KiB free is required for temporary build work.\n' "$need" >&2
    return 1
}

relay_prepare_swift() {
    if [[ -z ${RELAY_BUILD_SWIFT_BINARY:-} ]]; then
        RELAY_BUILD_SWIFT_BINARY=$(command -v swift) || return 0
        export RELAY_BUILD_SWIFT_BINARY
    fi
    cat > "$RELAY_BUILD_WORK_ROOT/tools/bin/swift" <<'SWIFT'
#!/usr/bin/env bash
set -euo pipefail
case ${1:-} in
    build|test|package|run)
        args=("$1" --cache-path "$RELAY_BUILD_WORK_ROOT/swift-cache"
              --config-path "$RELAY_BUILD_WORK_ROOT/swift-config"
              --security-path "$RELAY_BUILD_WORK_ROOT/swift-security")
        shift
        while (( $# )); do
            case $1 in
                --cache-path|--config-path|--security-path)
                    [[ $# -ge 2 ]] || { printf 'Missing SwiftPM cache option value.\n' >&2; exit 2; }
                    shift 2 ;;
                --cache-path=*|--config-path=*|--security-path=*) shift ;;
                *) args+=("$1"); shift ;;
            esac
        done
        exec "$RELAY_BUILD_SWIFT_BINARY" "${args[@]}"
        ;;
    *) exec "$RELAY_BUILD_SWIFT_BINARY" "$@" ;;
esac
SWIFT
    chmod 700 "$RELAY_BUILD_WORK_ROOT/tools/bin/swift"
}

relay_source_ancestor() {
    local owner=$1 current=$$
    [[ $owner =~ ^[1-9][0-9]*$ ]] || return 1
    while [[ $current =~ ^[1-9][0-9]*$ ]]; do
        [[ $current != "$owner" ]] || return 0
        [[ $current != 1 ]] || return 1
        current=$(ps -o ppid= -p "$current" 2>/dev/null) || return 1
        current=${current//[[:space:]]/}
    done
    return 1
}

relay_source_valid_root() {
    local root=$1 temporary changes
    temporary=$(relay_source_root /tmp) || return 1
    [[ $root == "$temporary/"* && -O $root && ! -L $root && -d $root/.git && ! -L $root/.git ]] || return 1
    [[ $(relay_source_local_git -C "$root" rev-parse --show-toplevel) == "$root" ]] || return 1
    changes=$(relay_source_local_git -C "$root" status --porcelain --untracked-files=no) || return 1
    [[ -z $changes ]]
}

# Isolate caches without changing HOME or the user's installed toolchain.
# The caller owns WORK_ROOT and removes it on every exit.
relay_prepare_build_environment() {
    local work=$1 requested rustup_command rustc_binary installed target ready=1 name
    shift
    work=$(relay_source_root "$work") || relay_source_die 'Cannot resolve private build work.'
    [[ -O $work && ! -L $work ]] || relay_source_die 'Build work must be an owned private directory.'
    export RELAY_BUILD_WORK_ROOT=$work
    export RELAY_BUILD_ORIGINAL_CARGO_HOME=${RELAY_BUILD_ORIGINAL_CARGO_HOME:-${CARGO_HOME:-$HOME/.cargo}}
    export RELAY_BUILD_ORIGINAL_RUSTUP_HOME=${RELAY_BUILD_ORIGINAL_RUSTUP_HOME:-${RUSTUP_HOME:-$HOME/.rustup}}
    requested=${RELAY_BUILD_RUST_TOOLCHAIN:-${RUSTUP_TOOLCHAIN:-stable}}
    export RELAY_BUILD_RUST_TOOLCHAIN=$requested
    # Before isolating rustup, check the actual existing standard libraries.
    rustup_command=$(command -v rustup) || ready=0
    if (( ready )); then
        rustc_binary=$(RUSTUP_HOME="$RELAY_BUILD_ORIGINAL_RUSTUP_HOME" "$rustup_command" which --toolchain "$requested" rustc 2>/dev/null) || ready=0
    fi
    if (( ready )); then
        installed=$(relay_source_root "$(dirname -- "$rustc_binary")/..") || ready=0
        [[ -x $installed/bin/rustc && -x $installed/bin/cargo ]] || ready=0
        for target in "$@"; do
            compgen -G "$installed/lib/rustlib/$target/lib/libstd-*.rlib" >/dev/null || ready=0
        done
    fi
    export CARGO_HOME="$work/cargo-home" RUSTUP_HOME="$work/rustup-home"
    export CARGO_TARGET_DIR="$work/target" CARGO_INSTALL_ROOT="$work/tools"
    export TMPDIR="$work/tmp" XDG_CACHE_HOME="$work/cache" PIP_CACHE_DIR="$work/pip-cache"
    export ZIG_GLOBAL_CACHE_DIR="$work/zig-global-cache" ZIG_LOCAL_CACHE_DIR="$work/zig-local-cache"
    export GOCACHE="$work/go-cache" GOPATH="$work/go" GOMODCACHE="$work/go/pkg/mod" GOTMPDIR="$work/go-tmp"
    export GOENV=off GOWORK=off TEST_TELEMETRY_DIR="$work/go-telemetry"
    export SCCACHE_DIR="$work/sccache" CCACHE_DIR="$work/ccache" CCACHE_TEMPDIR="$work/tmp"
    export CLANG_MODULE_CACHE_PATH="$work/clang-cache" SWIFTPM_MODULECACHE_OVERRIDE="$work/swift-module-cache"
    export PYTHONPYCACHEPREFIX="$work/python-cache"
    export RUSTC_WRAPPER='' RUSTC_WORKSPACE_WRAPPER=''
    export RUSTFLAGS='' CARGO_ENCODED_RUSTFLAGS='' RUSTDOCFLAGS='' CARGO_ENCODED_RUSTDOCFLAGS=''
    unset RUSTC RUSTDOC CARGO_BUILD_RUSTC CARGO_BUILD_RUSTDOC
    for name in ${!CARGO_TARGET_@}; do
        [[ $name != *_RUSTFLAGS ]] || unset "$name"
    done
    mkdir -p -- "$CARGO_HOME" "$RUSTUP_HOME" "$TMPDIR" "$GOTMPDIR" "$work/tools/bin"
    # Credentials may be reused privately. Global configuration is not copied:
    # path/source overrides could otherwise inject an old local source tree.
    for name in credentials credentials.toml; do
        if [[ -f $RELAY_BUILD_ORIGINAL_CARGO_HOME/$name && ! -e $CARGO_HOME/$name ]]; then
            cp -- "$RELAY_BUILD_ORIGINAL_CARGO_HOME/$name" "$CARGO_HOME/$name"
            chmod 600 "$CARGO_HOME/$name"
        fi
    done
    relay_prepare_swift
    export PATH="$work/tools/bin:$CARGO_HOME/bin:$PATH"
    unset GOCACHEPROG
    if (( ready )); then
        if [[ ! -L $RUSTUP_HOME/toolchains/relay-existing ||
              $(relay_source_root "$RUSTUP_HOME/toolchains/relay-existing") != "$installed" ]]; then
            "$rustup_command" toolchain link relay-existing "$installed" || relay_source_die 'Cannot select the existing Rust toolchain.'
        fi
        export RUSTUP_TOOLCHAIN=relay-existing RELAY_REUSE_RUST_TOOLCHAIN=1
    else
        export RUSTUP_TOOLCHAIN=$requested RELAY_REUSE_RUST_TOOLCHAIN=0
    fi
}

relay_mark_fresh_source() {
    local root marker commit
    root=$(relay_source_root "$1") || relay_source_die 'Cannot resolve the downloaded source directory.'
    relay_source_valid_root "$root" || relay_source_die 'Only a clean, owned source clone under /tmp can be handed to a build.'
    commit=$(relay_source_local_git -C "$root" rev-parse --verify HEAD) || relay_source_die 'Cannot identify downloaded source.'
    marker=$(mktemp "$root/.git/relay-build-source.XXXXXX") || relay_source_die 'Cannot mark the downloaded source.'
    printf '%s\n%s\n' "$$" "$commit" > "$marker" || relay_source_die 'Cannot write source ownership.'
    export RELAY_FRESH_SOURCE_ROOT=$root RELAY_FRESH_SOURCE_MARKER=$marker RELAY_FRESH_SOURCE_COMMIT=$commit
    unset RELAY_BUILD_OUTPUT_ROOT
}

relay_source_is_current() {
    local root=$1 marker=${RELAY_FRESH_SOURCE_MARKER:-} owner commit
    [[ $root == "${RELAY_FRESH_SOURCE_ROOT:-}" && $marker == "$root/.git/relay-build-source."* &&
       -f $marker && ! -L $marker && -O $marker ]] || return 1
    relay_source_valid_root "$root" || return 1
    { IFS= read -r owner; IFS= read -r commit; } < "$marker" || return 1
    [[ $commit == "${RELAY_FRESH_SOURCE_COMMIT:-}" && $(relay_source_local_git -C "$root" rev-parse --verify HEAD) == "$commit" ]] || return 1
    relay_source_ancestor "$owner"
}

relay_source_git() {
    if command -v gh >/dev/null; then
        env -u CF_API_TOKEN GIT_TERMINAL_PROMPT=0 git -c protocol.file.allow=never -c 'credential.helper=!gh auth git-credential' "$@"
    else
        env -u CF_API_TOKEN GIT_TERMINAL_PROMPT=0 git -c protocol.file.allow=never "$@"
    fi
}

relay_source_clone() {
    local destination=$1 attempt header
    for attempt in 1 2 3; do
        rm -rf -- "${destination:?}"
        if relay_source_git clone --recurse-submodules --branch main -- https://github.com/ArcCal/network-relay.git "$destination"; then
            return 0
        fi
        [[ $attempt == 3 ]] || sleep "$((attempt * 10 - 5))"
    done
    [[ -n ${NETWORK_RELAY_TOKEN:-} ]] || return 1
    header=$(printf 'x-access-token:%s' "$NETWORK_RELAY_TOKEN" | base64 | tr -d '\n') || return 1
    rm -rf -- "${destination:?}"
    GIT_TERMINAL_PROMPT=0 GIT_CONFIG_COUNT=2 \
        GIT_CONFIG_KEY_0=credential.helper GIT_CONFIG_VALUE_0='' \
        GIT_CONFIG_KEY_1=http.https://github.com/.extraheader \
        GIT_CONFIG_VALUE_1="Authorization: Basic $header" \
        env -u CF_API_TOKEN git -c protocol.file.allow=never clone --recurse-submodules --branch main -- https://github.com/ArcCal/network-relay.git "$destination"
}

relay_require_fresh_source() {
    local root relative=$2
    root=$(relay_source_root "$1") || relay_source_die 'Cannot resolve the caller source directory.'
    shift 2
    [[ $relative != /* && $relative != ../* && $relative != */../* && $relative != *$'\n'* ]] ||
        relay_source_die 'Invalid build entry path.'
    if [[ $(uname -s) == Linux ]]; then
        # shellcheck source=tools/linux-build-memory.sh
        # shellcheck disable=SC1091
        source "$(dirname -- "${BASH_SOURCE[0]}")/linux-build-memory.sh"
        CARGO_BUILD_JOBS=$(relay_build_memory_jobs "${CARGO_BUILD_JOBS:-3}") || exit 1
        export CARGO_BUILD_JOBS
    fi
    if relay_source_is_current "$root"; then return 0; fi
    # The resource owner stays in this shell so a targeted signal cannot leave
    # an anonymous bootstrap subshell running after its caller has exited.
    # shellcheck source=tools/run-build-child.sh
    # shellcheck disable=SC1091
    source "$(dirname -- "${BASH_SOURCE[0]}")/run-build-child.sh"
    local stage source status work
    stage=$(mktemp -d "/tmp/network-relay-$(date +%Y%m%d-%H%M%S).XXXXXX") || exit 1
    work=
    trap 'relay_remove_build_work "$work" "$stage"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    source="$stage/network-relay"
    printf 'Downloading complete current source into %s\n' "$source"
    status=0
    relay_run_build_child relay_source_clone "$source" || status=$?
    (( status == 0 )) || exit "$status"
    relay_mark_fresh_source "$source"
    export RELAY_BUILD_OUTPUT_ROOT=$root
    work=$(relay_build_work_parent 3145728) || exit 1
    if [[ $work != /tmp ]]; then
        work=$(mktemp -d "$work/network-relay-build-work.$(date +%Y%m%d-%H%M%S).XXXXXX") || exit 1
    else
        work="$stage/work"
        mkdir -- "$work" || exit 1
    fi
    export RELAY_BUILD_WORK_ROOT=$work
    status=0
    case $relative in
        deploy/install-*.sh|install-network-relay-native-build-cloudflare-dns.sh)
            relay_run_build_child --wait-for-cleanup "$BASH" "$source/$relative" "$@" || status=$? ;;
        *) relay_run_build_child "$BASH" "$source/$relative" "$@" || status=$? ;;
    esac
    exit "$status"
}
