#!/usr/bin/env bash
# Update the checkout, then build the two independent Network Relay GUI apps.
# All A && B || die guards intentionally reject failure of either predicate.
# shellcheck disable=SC2015
set -euo pipefail
unset CDPATH

rg_die() { printf 'build-macos-gui: %s\n' "$*" >&2; exit 1; }
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
        GIT_TERMINAL_PROMPT=0 git -c 'credential.helper=!gh auth git-credential' "$@"
    else
        GIT_TERMINAL_PROMPT=0 git "$@"
    fi
}
rg_usage() {
    cat <<'HELP'
Usage: bash build-macos-gui.sh [--repo DIR] [--output DIR] [--jobs N]

Build Network Relay NF and Network Relay RS, including their original tests,
ad-hoc signatures and ZIPs. Requires an Apple silicon Mac, macOS 27+, the
macOS 27+ Xcode SDK with XCTest, Rust/rustup, and Git access to the repository.
No Linux servers, Go, Zig or unrelated applications are built.

  --repo DIR    persistent main checkout (default: ~/network-relay or
                NETWORK_RELAY_SRC). Clone if absent; otherwise pull --ff-only.
  --output DIR  new or empty artifact directory; existing files are preserved.
                Default: a unique folder under ~/Desktop/Network-Relay-Builds
                or NETWORK_RELAY_BUILD_ROOT.
  --jobs N      Cargo compilation jobs (default: 2).

Every run executes the newly fetched, committed script and builds a private
snapshot. Local commits are refused; dirty/untracked files are preserved and
never used as build inputs. Sources, builds and signing use /private/tmp.
App names include the software, macOS and arm64. Logs, source revisions and
SHA256SUMS are kept with the artifacts. Failed builds keep their workspace.
RUSTUP_TOOLCHAIN defaults to 1.99.0. Existing checkouts are never deleted.
HELP
}
rg_host() {
    local version sdk tool
    [[ $(uname -s) == Darwin && $(uname -m) == arm64 ]] || rg_die 'An Apple silicon Mac is required.'
    version=$(sw_vers -productVersion)
    [[ ${version%%.*} =~ ^[0-9]+$ ]] && (( ${version%%.*} >= 27 )) || rg_die 'macOS 27 or newer is required.'
    if [[ -z ${DEVELOPER_DIR:-} && -d /Applications/Xcode.app/Contents/Developer ]]; then
        export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
    fi
    sdk=$(xcrun --sdk macosx --show-sdk-version)
    [[ ${sdk%%.*} =~ ^[0-9]+$ ]] && (( ${sdk%%.*} >= 27 )) || rg_die 'Select an Xcode macOS 27 or newer SDK.'
    xcrun --sdk macosx --find xctest >/dev/null || rg_die 'Xcode with XCTest is required.'
    for tool in git rustup rustc cargo swift swiftc sips iconutil otool file codesign ditto plutil xattr unzip shasum find xargs mktemp install; do
        command -v "$tool" >/dev/null || rg_die "Missing required tool: $tool"
    done
}
rg_update() {
    local remote selected actual fetched has_repo=0
    while [[ $checkout != / && $checkout == */ ]]; do checkout=${checkout%/}; done
    if [[ -e $checkout || -L $checkout ]]; then
        if [[ -d $checkout && -e $checkout/.git ]]; then
            has_repo=1
        else
            [[ -d $checkout && ! -L $checkout ]] && rg_empty "$checkout" || rg_die "Existing path is not a Git checkout: $checkout"
        fi
    fi
    if (( has_repo )); then
        rg_dir "$checkout"; checkout=$REPLY
        actual=$(git -C "$checkout" rev-parse --show-toplevel && printf '.') || rg_die 'Cannot inspect the checkout.'
        actual=${actual%.}; actual=${actual%$'\n'}
        [[ $actual == "$checkout" ]] || rg_die 'Select the repository root.'
        remote=$(git -C "$checkout" config --get remote.origin.url) || rg_die 'Cannot read origin.'
        case $remote in
            https://github.com/ArcCal/network-relay|https://github.com/ArcCal/network-relay.git|git@github.com:ArcCal/network-relay.git|ssh://git@github.com/ArcCal/network-relay.git) ;;
            *) rg_die 'origin must point to ArcCal/network-relay on GitHub.' ;;
        esac
        selected=$(git -C "$checkout" symbolic-ref --short HEAD) || rg_die 'Use a main branch checkout.'
        [[ $selected == main ]] || rg_die 'Other branches are preserved; select a main checkout.'
        printf '==> Updating existing checkout with pull --ff-only\n'
        rg_remote_git -C "$checkout" pull --ff-only origin main || rg_die 'Cannot fast-forward the checkout; local files were preserved.'
        fetched=$(git -C "$checkout" rev-parse --verify FETCH_HEAD)
    else
        printf '==> Cloning ArcCal/network-relay\n'
        rg_remote_git clone --depth 1 --single-branch --branch main -- https://github.com/ArcCal/network-relay.git "$checkout" || rg_die 'Cannot clone network-relay; configure Git credentials for this repository.'
        rg_dir "$checkout"; checkout=$REPLY
        fetched=$(git -C "$checkout" rev-parse --verify refs/remotes/origin/main)
    fi
    root_commit=$(git -C "$checkout" rev-parse --verify HEAD)
    [[ $root_commit == "$fetched" ]] || rg_die 'Local commits differ from fetched main; no local files were reset.'
}
rg_main() {
    checkout=${NETWORK_RELAY_SRC:-"$HOME/network-relay"}
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
    rg_host
    rg_update
    work=$(mktemp -d /private/tmp/relay-mac.XXXXXX)
    trap 'status=$?; if (( status )); then printf "Update failed (exit %s). Work: %s\n" "$status" "$work" >&2; fi' EXIT
    printf '%s\n' "$root_commit" > "$work/.owner"
    git -C "$checkout" show "$root_commit:build-macos-gui.sh" > "$work/driver.sh" || rg_die 'Cannot load the latest GUI script.'
    [[ -s $work/driver.sh ]] || rg_die 'The latest GUI script is empty.'
    exec "$BASH" "$work/driver.sh" --build-updated "$checkout" "$work" "$output" "$root_commit" gui "$jobs"
}
# Parse this whole block before pull can replace the file being interpreted.
if [[ ${1:-} != --build-updated ]]; then rg_main "$@"; exit; fi

[[ $# == 7 ]] || rg_die 'Invalid internal invocation.'
checkout=$2; work=$3; output=$4; root_commit=$5; mode=$6; jobs=$7
[[ $mode == gui || $mode == all ]] && [[ $jobs =~ ^[1-9][0-9]*$ && $root_commit =~ ^[0-9a-f]{40}$ ]] || rg_die 'Invalid build selection.'
[[ ${work##*/} == relay-mac.* && -d $work && ! -L $work && -f $work/.owner && ! -L $work/.owner &&
   $(cat "$work/.owner") == "$root_commit" ]] || rg_die 'Invalid private workspace.'
repo="$work/sources/network-relay"
logs=
trap 'status=$?; if (( status )); then printf "Build failed (exit %s). Work: %s\nArtifacts/logs: %s\n" "$status" "$work" "${output:-not created}" >&2; fi' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
rg_host
while [[ $output != / && $output == */ ]]; do output=${output%/}; done
if [[ -z $output ]]; then
    parent=${NETWORK_RELAY_BUILD_ROOT:-"$HOME/Desktop/Network-Relay-Builds"}
    mkdir -p -- "$parent"
    stem=macos-gui; [[ $mode != all ]] || stem=all
    output=$(mktemp -d "$parent/network-relay-$stem-$(date -u +%Y%m%d-%H%M%S).XXXXXX")
elif [[ -e $output || -L $output ]]; then
    [[ -d $output && ! -L $output ]] && rg_empty "$output" || rg_die '--output must be new or empty, and not a symlink.'
else
    mkdir -p -- "$output"
fi
rg_dir "$output"; output=$REPLY
[[ $output/ != "$work/"* && $work/ != "$output/"* ]] || rg_die 'Output and work directories cannot overlap.'
logs="$output/logs"
mkdir -m 700 -- "$logs" "$work/sources" "$work/tmp"
ln -s -- "$work" "$output/.work"
printf 'Artifacts: %s\nPersistent checkout: %s\nPrivate workspace: %s\nSource commit: %s\n' "$output" "$checkout" "$work" "$root_commit"

rg_failures=0
rg_step() {
    local name=$1 status
    shift
    printf '==> %s\n' "$name"
    set +e
    ( set -euo pipefail; "$@" ) > "$logs/$name.log" 2>&1
    status=$?
    set -e
    if (( status )); then
        rg_failures=$((rg_failures + 1))
        printf '    FAILED (exit %s); log: %s/%s.log\n' "$status" "$logs" "$name" >&2
        tail -n 20 "$logs/$name.log" >&2
    else
        printf '    ok\n'
    fi
}
rg_require() { (( rg_failures == 0 )) || rg_die "$rg_failures step(s) failed; sources and logs were retained."; }
rg_snapshot() {
    git clone --no-hardlinks --no-checkout -- "$checkout" "$repo"
    git -C "$repo" checkout --detach "$root_commit"
}
rg_clone() { rg_remote_git clone --depth 1 --single-branch --branch "$3" -- "https://github.com/$1.git" "$2"; }
rg_step source-network-relay rg_snapshot
caddy_src="$work/sources/caddy-network-relay-src"
cloudflare_src="$work/sources/cloudflare-src"
if [[ $mode == all ]]; then
    rg_step source-caddy-network-relay rg_clone ArcCal/caddy-network-relay "$caddy_src" main
    rg_step source-cloudflare rg_clone caddy-dns/cloudflare "$cloudflare_src" master
fi
rg_require
caddy_commit=; cloudflare_commit=
if [[ $mode == all ]]; then
    caddy_commit=$(git -C "$caddy_src" rev-parse HEAD)
    cloudflare_commit=$(git -C "$cloudflare_src" rev-parse HEAD)
fi
# Discard ambient build flags without discarding proxy or registry credentials.
while IFS='=' read -r key _value; do
    case $key in
        CARGO_TARGET_DIR|CARGO_BUILD_TARGET|CARGO_BUILD_RUSTFLAGS|CARGO_TARGET_*|CARGO_PROFILE_*|RUSTFLAGS|RUSTDOCFLAGS|CARGO_ENCODED_RUSTFLAGS|CC|CXX|AR|LD|CC_*|CXX_*|AR_*|CFLAGS*|CXXFLAGS*|CPPFLAGS*|LDFLAGS|SDKROOT|MACOSX_DEPLOYMENT_TARGET|GOOS|GOARCH|GOAMD64|GOARM64|GOFLAGS|CGO_*) unset "$key" ;;
    esac
done < <(env)
export RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-1.99.0}
export CARGO_BUILD_JOBS="$jobs" CARGO_ENCODED_RUSTFLAGS=''
export COPYFILE_DISABLE=1 TMPDIR="$work/tmp/"
export GOTOOLCHAIN=${GOTOOLCHAIN:-go1.27.2+auto} GOWORK=off GOFLAGS='' GOAMD64=v1 GOARM64=v8.0
rg_attributes() { find -P "$1" \( -type f -o -type d \) -exec xattr -c {} +; }
rg_rust() {
    rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal
    rustup target add --toolchain "$RUSTUP_TOOLCHAIN" aarch64-apple-darwin
    if [[ $mode == all ]]; then
        rustup target add --toolchain "$RUSTUP_TOOLCHAIN" x86_64-unknown-linux-musl aarch64-unknown-linux-musl
    fi
}
rg_cross_tools() {
    if ! command -v zig >/dev/null; then command -v brew >/dev/null || rg_die 'Install Zig or Homebrew.'; brew install zig; fi
    if ! command -v cargo-zigbuild >/dev/null; then cargo install --locked cargo-zigbuild; fi
    if ! command -v go >/dev/null; then command -v brew >/dev/null || rg_die 'Install Go or Homebrew.'; brew install go; fi
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
    source "$repo/build-servers-linux.sh"
    # Read by the sourced Caddy helper.
    # shellcheck disable=SC2034
    host_arch=arm64
    lr_prepare_caddy
    local arch triple
    for arch in amd64 arm64; do
        case $arch in amd64) triple=x86_64-unknown-linux-musl ;; arm64) triple=aarch64-unknown-linux-musl ;; esac
        lr_build_rust "$repo/Cargo.toml" "$work/rust-main" "$triple" --bin network-relay
        lr_build_rust "$repo/network-relay-cf-masque/Cargo.toml" "$work/rust-cf" "$triple" --bin network-relay-cf-masque
        lr_build_rust "$repo/network-relay-rs/Cargo.toml" "$work/rust-rs" "$triple" --bin network-relay-rs
        lr_build_caddy "$arch"
        rg_binary "$work/rust-main/$triple/release/network-relay" network-relay "$arch"
        rg_binary "$work/rust-cf/$triple/release/network-relay-cf-masque" network-relay-cf-masque "$arch"
        rg_binary "$work/rust-rs/$triple/release/network-relay-rs" network-relay-rs "$arch"
        rg_binary "$work/caddy-network-relay-$arch" caddy-network-relay "$arch"
    done
}
if [[ $mode == all ]]; then rg_step linux-servers-both-architectures rg_servers; fi
rg_require

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
    local source="$repo/network-relay-rs/build/target/aarch64-apple-darwin/release/network-relay-rs" description
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
rg_step collect-nf-zip rg_zip "$repo/network-relay-nf/dist" NetworkRelayNF
rg_step collect-rs-zip rg_zip "$repo/network-relay-rs/dist" NetworkRelayRS
if [[ $mode == all ]]; then rg_step collect-macos-rust-cli rg_mac_cli; fi
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
            printf 'Rust CLI: Linux amd64/arm64 and macOS arm64; native Mac --help/--version checked.\n'
        fi
        printf 'Mac: original client tests, bundle architecture and strict signatures checked.\n'
    } > "$output/MANIFEST.txt"
}
rg_checksums() (
    cd -- "$output" || exit
    local expected=(network-relay-nf-macos-arm64.app network-relay-rs-macos-arm64.app NetworkRelayNF-*-macos-arm64.zip NetworkRelayRS-*-macos-arm64.zip MANIFEST.txt)
    if [[ $mode == all ]]; then
        expected+=(network-relay-linux-amd64 network-relay-linux-arm64 network-relay-cf-masque-linux-amd64 network-relay-cf-masque-linux-arm64 caddy-network-relay-linux-amd64 caddy-network-relay-linux-arm64 network-relay-rs-linux-amd64 network-relay-rs-linux-arm64 network-relay-rs-macos-arm64)
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
rg_cleanup() { rm -rf -- "${work:?}"; rm -f -- "$output/.work"; }
rg_step cleanup rg_cleanup
rg_require
printf '\nAll selected builds and artifact checks passed.\nArtifacts: %s\n' "$output"
