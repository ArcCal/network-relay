#!/bin/bash
# Fresh-source builds of ArcCal's VPN applications on Apple silicon.
# Compatible with Apple's system Bash 3.2. Sourceable for orchestration tests.

say() { printf '\n%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; return 1; }

usage() {
    cat <<'EOF'
Usage: bash build-all-macos.sh [--jobs N] [--output-parent DIRECTORY]
                               [--no-bootstrap] [--plan] [--help]

Default: install missing build tools, authenticate GitHub if needed, clone
five private repositories into a NEW directory, and build every product.
Servers: Linux amd64 + arm64. GUI: macOS arm64.
Headless clients: Linux amd64 + macOS arm64.
Password utilities: both Linux architectures + macOS arm64.

--jobs N                  Cargo compilation jobs (default: 2).
--output-parent DIRECTORY Parent of the new build directory (default: ~/Projects).
--no-bootstrap            Require installed tools; do not install/update them.
--plan                    Print the complete build plan; make no changes.

The complete GUI set requires macOS 27 for the current IETF Masque recipe,
plus a macOS 27+ SDK. NF requires macOS 27+; other app requirements vary.
Missing SDK/XCTest tools trigger an Xcode installation from the App Store.
Apple may require sign-in, license acceptance or administrator authentication.
Unsupported app jobs fail explicitly; other jobs still run. Any failure
makes the final exit status nonzero. Existing source folders are not reused.
EOF
}

sanitize_build_env() {
    local key _value
    while IFS='=' read -r key _value; do
        case "$key" in
            CARGO_HOME|CARGO_TARGET_DIR|CARGO_BUILD_*|CARGO_PROFILE_*|CARGO_TARGET_*|\
            CARGO_ENCODED_RUSTFLAGS|RUSTFLAGS|RUSTDOCFLAGS|RUSTUP_TOOLCHAIN|\
            CC|CXX|AR|LD|CFLAGS|CPPFLAGS|CXXFLAGS|LDFLAGS|\
            CC_*|CXX_*|AR_*|CFLAGS_*|CXXFLAGS_*|\
            SDKROOT|MACOSX_DEPLOYMENT_TARGET|IPHONEOS_DEPLOYMENT_TARGET|\
            GOOS|GOARCH|GOAMD64|GOARM64|GOARM|GOFLAGS|GOWORK|GOTOOLCHAIN|\
            CGO_ENABLED|CGO_CFLAGS|CGO_CPPFLAGS|CGO_CXXFLAGS|CGO_LDFLAGS)
                unset "$key"
                ;;
        esac
    done < <(env)
    export RUSTUP_TOOLCHAIN=stable
    export CARGO_BUILD_JOBS="${BUILD_JOBS:-2}"
    export CARGO_NET_RETRY=5
    export CARGO_NET_GIT_FETCH_WITH_CLI=true
    export CARGO_HTTP_MULTIPLEXING=false
    export GOTOOLCHAIN=auto GOWORK=off
}

ensure_homebrew() {
    local installer
    if [[ ! -x /opt/homebrew/bin/brew ]]; then
        installer=$(mktemp -t arccal-homebrew)
        curl --fail --show-error --location --retry 5 --retry-delay 2 \
            https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh -o "$installer"
        /bin/bash "$installer"
        rm -f "$installer"
    fi
    eval "$(/opt/homebrew/bin/brew shellenv)"
}

apple_sdk_ready() {
    local version
    xcrun --find clang >/dev/null 2>&1 || return 1
    xcrun --find swift >/dev/null 2>&1 || return 1
    version=$(xcrun --sdk macosx --show-sdk-version 2>/dev/null) || return 1
    SDK_MAJOR=${version%%.*}
    [[ $SDK_MAJOR =~ ^[0-9]+$ && $SDK_MAJOR -ge 27 ]] || return 1
    # The original app recipes run XCTest. Do not silently skip their tests
    # when a CLT-only installation provides the SDK but lacks the test runner.
    xcrun --sdk macosx --find xctest >/dev/null 2>&1 || return 1
    if [[ ${DEVELOPER_DIR:-} == */Contents/Developer ]]; then
        xcodebuild -checkFirstLaunchStatus >/dev/null 2>&1 || return 1
    fi
}

initialize_xcode() {
    [[ ${DEVELOPER_DIR:-} == */Contents/Developer ]] || return 0
    if ! xcodebuild -checkFirstLaunchStatus >/dev/null 2>&1; then
        say 'Completing Xcode first-run components; macOS may request your administrator password.'
        sudo env DEVELOPER_DIR="$DEVELOPER_DIR" xcodebuild -runFirstLaunch || return 1
    fi
}

install_xcode_sdk() {
    local _reply
    say 'Installing/updating Xcode from the Mac App Store for the macOS 27+ SDK and XCTest.'
    say 'Sign in to the App Store if prompted. Xcode is a large download; keep this Terminal open.'
    brew list --versions mas >/dev/null 2>&1 || brew install mas
    # This obtains Apple's free Xcode app, including on an account that has
    # never acquired it. --force also replaces an outdated installed version.
    if ! mas get --force 497799835; then
        say 'The App Store command needs attention; finish the Xcode download in the App Store window.'
    fi
    if [[ -d /Applications/Xcode.app/Contents/Developer ]]; then
        export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
        initialize_xcode || true
    fi
    if apple_sdk_ready; then return 0; fi
    open 'macappstore://itunes.apple.com/app/id497799835' || true
    if [[ -d /Applications/Xcode.app ]]; then open /Applications/Xcode.app || true; fi
    say 'Install/update Xcode 27+ in the App Store, then open Xcode and finish its license/component setup.'
    if [[ ! -t 0 ]]; then
        die 'Apple sign-in/setup needs an interactive Terminal. Finish it, then rerun this script.'
        return 1
    fi
    read -r -p 'Press Return after Xcode installation and setup have finished: ' _reply
    if [[ -d /Applications/Xcode.app/Contents/Developer ]]; then
        export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
    fi
    initialize_xcode || true
    apple_sdk_ready || { die 'macOS 27+ SDK/XCTest is still unavailable. Finish Xcode setup, then rerun this script.'; return 1; }
}

prepare_apple_tools() {
    local bootstrap=${1:-1} _reply selected
    MACOS_MAJOR=$(sw_vers -productVersion | cut -d. -f1)
    [[ $MACOS_MAJOR =~ ^[0-9]+$ ]] || { die 'Cannot determine macOS version.'; return 1; }
    if [[ -z ${DEVELOPER_DIR:-} ]]; then
        if [[ -d /Applications/Xcode.app/Contents/Developer ]]; then
            export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
        else
            selected=$(xcode-select -p 2>/dev/null || true)
            [[ -z $selected ]] || export DEVELOPER_DIR="$selected"
        fi
    fi
    if ! apple_sdk_ready; then
        [[ $bootstrap == 1 ]] || { die '--no-bootstrap requires an installed macOS 27+ SDK and XCTest.'; return 1; }
        initialize_xcode || true
        if ! apple_sdk_ready; then
            # Homebrew's official installer bootstraps CLT on a fresh Mac.
            ensure_homebrew
            if ! xcrun --find clang >/dev/null 2>&1 || ! xcrun --find swift >/dev/null 2>&1; then
                xcode-select --install || true
                if [[ ! -t 0 ]]; then
                    die 'Finish installing Apple Command Line Tools, then rerun this script in Terminal.'
                    return 1
                fi
                read -r -p 'Press Return after the Apple Command Line Tools installer finishes: ' _reply
                if ! xcrun --find clang >/dev/null 2>&1 || ! xcrun --find swift >/dev/null 2>&1; then
                    die 'Apple Command Line Tools are still unavailable.'
                    return 1
                fi
            fi
            install_xcode_sdk
        fi
    fi
    say "Apple build tools ready: host macOS $MACOS_MAJOR; SDK $SDK_MAJOR; XCTest available."
    if [[ $MACOS_MAJOR != 27 ]]; then
        say 'The IETF Masque job will enforce its existing macOS 27 host requirement.'
    fi
}

install_tools() {
    local installer package
    ensure_homebrew
    for package in go zig gh; do
        if ! brew list --versions "$package" >/dev/null 2>&1; then
            brew install "$package"
        fi
    done
    if ! command -v rustup >/dev/null 2>&1; then
        installer=$(mktemp -t arccal-rustup)
        curl --fail --show-error --location --retry 5 --retry-delay 2 \
            https://sh.rustup.rs -o "$installer"
        /bin/sh "$installer" -y --profile minimal --default-toolchain stable --no-modify-path
        rm -f "$installer"
    fi
    rustup toolchain install stable --profile minimal
    cargo install --locked cargo-zigbuild
}

check_tools() {
    local tool major minor
    for tool in git gh cargo rustc rustup zig cargo-zigbuild go file shasum \
                swift swiftc xcrun plutil codesign ditto sips iconutil; do
        command -v "$tool" >/dev/null 2>&1 || { die "Missing tool: $tool"; return 1; }
    done
    major=$(rustc --version | awk '{split($2,v,"."); print v[1]}')
    minor=$(rustc --version | awk '{split($2,v,"."); print v[2]}')
    [[ $major -gt 1 || ( $major -eq 1 && $minor -ge 99 ) ]] || {
        die 'Current CF server sources require Rust 1.99 or newer. Update stable with rustup.'
        return 1
    }
    rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl aarch64-apple-darwin
    if ! gh auth status --hostname github.com >/dev/null 2>&1; then
        gh auth login --hostname github.com --git-protocol https --web
    fi
}

run_job() {
    local id status log
    id=$1
    shift
    if [[ ${PLAN_ONLY:-0} == 1 ]]; then
        printf '%-36s' "$id"
        printf ' %q' "$@"
        printf '\n'
        return 0
    fi
    log="$LOGS/$id.log"
    say "=== $id ==="
    # Never invoke a build function in an if/! condition: that disables its
    # errexit behavior. This independent subshell must stop on the FIRST error.
    set +e
    (
        set -euo pipefail
        sanitize_build_env
        "$@"
    ) 2>&1 | tee "$log"
    status=$?
    set -e
    if [[ $status -eq 0 ]]; then
        printf '%s\tPASS\t%s\n' "$id" "$log" >> "$BUILD_RESULTS"
    else
        JOB_FAILURES=$((JOB_FAILURES + 1))
        printf '%s\tFAIL(%s)\t%s\n' "$id" "$status" "$log" >> "$BUILD_RESULTS"
        printf 'FAILED: %s; continuing. Log: %s\n' "$id" "$log" >&2
    fi
}

clone_repo() {
    local name destination partial attempt revision
    name=$1
    destination="$SOURCES/$name"
    partial="$SOURCES/.$name.partial"
    [[ ! -e $destination && ! -e $partial ]] || { die "Source destination already exists: $destination"; return 1; }
    for attempt in 1 2 3; do
        if git -c http.version=HTTP/1.1 -c credential.helper= \
            -c 'credential.helper=!gh auth git-credential' \
            clone --depth 1 --single-branch --branch main --no-tags \
            "https://github.com/ArcCal/$name.git" "$partial"; then
            mv "$partial" "$destination"
            revision=$(git -C "$destination" rev-parse HEAD)
            printf '%s\t%s\n' "$name" "$revision" >> "$SOURCE_REVISIONS"
            return 0
        fi
        # This path was checked absent above and is owned by this clone job.
        rm -rf "$partial"
        printf 'Clone attempt %s/3 failed for %s.\n' "$attempt" "$name" >&2
        [[ $attempt -eq 3 ]] || sleep "$((attempt * 2))"
    done
    die "Cannot clone ArcCal/$name; check GitHub access and network."
}

source_dir() {
    [[ -d $SOURCES/$1/.git ]] || { die "Missing complete source checkout: $1"; return 1; }
    printf '%s\n' "$SOURCES/$1"
}

verify_binary() {
    local binary platform description
    binary=$1
    platform=$2
    [[ -s $binary && -x $binary ]] || { die "Missing executable: $binary"; return 1; }
    description=$(file -b "$binary")
    printf '%s: %s\n' "$binary" "$description"
    case "$platform" in
        linux-amd64)
            [[ $description == ELF* && $description == *x86-64* && $description == *static* ]] || \
                { die "Expected a static Linux x64 executable: $binary"; return 1; } ;;
        linux-arm64)
            [[ $description == ELF* && $description == *aarch64* && $description == *static* ]] || \
                { die "Expected a static Linux arm64 executable: $binary"; return 1; } ;;
        macos-arm64)
            [[ $description == *Mach-O* && $description == *arm64* ]] || \
                { die "Expected a macOS arm64 executable: $binary"; return 1; } ;;
        *) die "Unknown artifact platform: $platform"; return 1 ;;
    esac
}

build_rust() {
    local repo subdir target package directory platform binary
    repo=$1; subdir=$2; target=$3; package=$4
    shift 4
    directory=$(source_dir "$repo")
    [[ -z $subdir ]] || directory="$directory/$subdir"
    cd "$directory"
    [[ -f Cargo.toml && -f Cargo.lock ]] || { die "Missing Cargo manifest/lock: $directory"; return 1; }
    local args=(--locked --release --target "$target")
    [[ -z $package ]] || args+=(-p "$package")
    for binary in "$@"; do args+=(--bin "$binary"); done
    case "$target" in
        x86_64-unknown-linux-musl) platform=linux-amd64; cargo zigbuild "${args[@]}" ;;
        aarch64-unknown-linux-musl) platform=linux-arm64; cargo zigbuild "${args[@]}" ;;
        aarch64-apple-darwin)
            platform=macos-arm64
            export MACOSX_DEPLOYMENT_TARGET=27.0
            cargo build "${args[@]}"
            ;;
        *) die "Unexpected Rust target: $target"; return 1 ;;
    esac
    for binary in "$@"; do verify_binary "target/$target/release/$binary" "$platform"; done
    for binary in "$@"; do
        if [[ $platform == macos-arm64 ]]; then
            cp "target/$target/release/$binary" "$OUT/$platform/bin/$binary"
        else
            cp "target/$target/release/$binary" "$OUT/$platform/$binary"
        fi
    done
}

build_go() {
    local repo arch tags name directory toolchain
    repo=$1; arch=$2; tags=$3; name=$4
    directory=$(source_dir "$repo")
    cd "$directory"
    toolchain=$(awk '$1 == "toolchain" { print $2; exit }' go.mod)
    export GOTOOLCHAIN=${toolchain:-auto}
    go version
    export CGO_ENABLED=0 GOOS=linux GOARCH="$arch"
    if [[ $arch == amd64 ]]; then export GOAMD64=v1; else export GOARM64=v8.0; fi
    local args=(-mod=readonly -trimpath -ldflags '-s -w')
    [[ -z $tags ]] || args+=(-tags "$tags")
    go build "${args[@]}" -o "$OUT/linux-$arch/$name" ./cmd/caddy
    verify_binary "$OUT/linux-$arch/$name" "linux-$arch"
}

build_app() {
    local repo recipe relative name minimum exact directory bundle executable destination
    repo=$1; recipe=$2; relative=$3; name=$4; minimum=$5; exact=${6:-0}
    [[ $MACOS_MAJOR -ge $minimum ]] || { die "$name requires macOS $minimum or newer."; return 1; }
    if [[ $exact == 1 && $MACOS_MAJOR != "$minimum" ]]; then
        die "$name's current build recipe requires macOS $minimum exactly."
        return 1
    fi
    if [[ $minimum -ge 27 && $SDK_MAJOR -lt 27 ]]; then
        die "$name requires macOS SDK 27 or newer. Select Xcode 27+ and rerun."
        return 1
    fi
    directory=$(source_dir "$repo")
    cd "$directory"
    # Preserve each app's own target locations, tests, deployment target,
    # helper packaging and ad-hoc signing. Do not replace its build recipe.
    /bin/bash "$recipe"
    bundle="$directory/$relative"
    [[ -d $bundle ]] || { die "Build did not produce $bundle"; return 1; }
    executable=$(plutil -extract CFBundleExecutable raw -o - "$bundle/Contents/Info.plist")
    verify_binary "$bundle/Contents/MacOS/$executable" macos-arm64
    codesign --verify --strict "$bundle"
    destination="$OUT/macos-arm64/apps/$name.app"
    ditto "$bundle" "$destination"
    codesign --verify --strict "$destination"
    ditto -c -k --sequesterRsrc --keepParent "$destination" "$destination.zip"
}

audit_outputs() {
    local arch binary name repo
    for arch in amd64 arm64; do
        for binary in caddy-masque caddy-network-relay masque-server network-relay \
                      masque-vpn-cf-masque masque-passwd masque-cf-passwd; do
            verify_binary "$OUT/linux-$arch/$binary" "linux-$arch"
        done
    done
    for binary in masque-client cf-masque; do verify_binary "$OUT/linux-amd64/$binary" linux-amd64; done
    for binary in masque-client cf-masque masque-passwd masque-cf-passwd; do
        verify_binary "$OUT/macos-arm64/bin/$binary" macos-arm64
    done
    for name in 'IETF Masque' 'Masque NF' 'Masque VPN Mac' 'Masque VPN Killswitch' \
                'Network Relay NF' 'Network Relay RS' 'Cloudflare Masque'; do
        [[ -d $OUT/macos-arm64/apps/$name.app && -s $OUT/macos-arm64/apps/$name.app.zip ]] || \
            { die "Missing app/archive: $name"; return 1; }
    done
    for repo in masque-vpn network-relay caddy-masque caddy-network-relay cf-masque; do
        git -C "$SOURCES/$repo" diff --exit-code HEAD --
    done
}

schedule_builds() {
    local repo arch target
    for repo in masque-vpn network-relay caddy-masque caddy-network-relay cf-masque; do
        run_job "clone-$repo" clone_repo "$repo"
    done
    for arch in amd64 arm64; do
        if [[ $arch == amd64 ]]; then target=x86_64-unknown-linux-musl; else target=aarch64-unknown-linux-musl; fi
        if [[ $arch == amd64 ]]; then
            run_job "masque-$arch" build_rust masque-vpn '' "$target" masque-vpn masque-server masque-passwd masque-client
        else
            run_job "masque-$arch" build_rust masque-vpn '' "$target" masque-vpn masque-server masque-passwd
        fi
        run_job "relay-$arch" build_rust network-relay '' "$target" '' network-relay
        run_job "masque-cf-$arch" build_rust masque-vpn masque-vpn-cf-masque "$target" '' masque-vpn-cf-masque masque-cf-passwd
        run_job "caddy-masque-$arch" build_go caddy-masque "$arch" '' caddy-masque
        run_job "caddy-relay-$arch" build_go caddy-network-relay "$arch" http2legacy caddy-network-relay
    done
    run_job cf-client-amd64 build_rust cf-masque '' x86_64-unknown-linux-musl '' cf-masque
    run_job masque-cli-mac build_rust masque-vpn '' aarch64-apple-darwin masque-vpn masque-client masque-passwd
    run_job cf-cli-mac build_rust cf-masque '' aarch64-apple-darwin '' cf-masque
    run_job masque-cf-passwd-mac build_rust masque-vpn masque-vpn-cf-masque aarch64-apple-darwin '' masque-cf-passwd
    run_job app-ietf-masque build_app masque-vpn macos/build-app.sh 'dist/IETF Masque.app' 'IETF Masque' 27 1
    run_job app-masque-nf build_app masque-vpn masque-nf/build-macos.sh 'masque-nf/dist/Masque NF.app' 'Masque NF' 27
    run_job app-masque-mac build_app masque-vpn masque-vpn-mac/build-macos.sh 'masque-vpn-mac/dist/Masque VPN Mac.app' 'Masque VPN Mac' 14
    run_job app-masque-killswitch build_app masque-vpn masque-vpn-killswitch/build-macos.sh 'masque-vpn-killswitch/dist/Masque VPN Killswitch.app' 'Masque VPN Killswitch' 14
    run_job app-relay-nf build_app network-relay network-relay-nf/build-macos.sh 'network-relay-nf/dist/Network Relay NF.app' 'Network Relay NF' 27
    run_job app-relay-rs build_app network-relay network-relay-rs/build-macos.sh 'network-relay-rs/dist/Network Relay RS.app' 'Network Relay RS' 27
    run_job app-cf-masque build_app cf-masque macos/build-app.sh 'macos/dist/Cloudflare Masque.app' 'Cloudflare Masque' 13
    run_job output-audit audit_outputs
}

write_checksums() {
    (
        cd "$OUT"
        # The output file is explicitly excluded from the input list.
        # shellcheck disable=SC2094
        find . -type f ! -name SHA256SUMS -print0 |
            while IFS= read -r -d '' file; do shasum -a 256 "$file"; done > SHA256SUMS
    )
}

write_tool_versions() {
    date -u '+Started: %Y-%m-%dT%H:%M:%SZ'
    sw_vers
    xcrun --sdk macosx --show-sdk-version
    rustc --version
    cargo --version
    zig version
    # The version flag belongs to the standalone command, not its build
    # subcommand. `cargo zigbuild --version` is rejected by cargo-zigbuild.
    cargo-zigbuild --version
    go version
    swift --version
}

main() {
    BUILD_JOBS=2
    OUTPUT_PARENT="$HOME/Projects"
    local bootstrap=1
    PLAN_ONLY=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --jobs) [[ $# -ge 2 ]] || { usage; return 2; }; BUILD_JOBS=$2; shift 2 ;;
            --output-parent) [[ $# -ge 2 ]] || { usage; return 2; }; OUTPUT_PARENT=$2; shift 2 ;;
            --no-bootstrap) bootstrap=0; shift ;;
            --plan) PLAN_ONLY=1; shift ;;
            --help|-h) usage; return 0 ;;
            *) usage; die "Unknown argument: $1"; return 2 ;;
        esac
    done
    [[ $BUILD_JOBS =~ ^[1-9][0-9]*$ ]] || { die '--jobs must be a positive integer.'; return 2; }
    if [[ $PLAN_ONLY == 1 ]]; then
        say 'Build plan only: no installation, downloads or compilation.'
        schedule_builds
        return 0
    fi
    [[ $(uname -s) == Darwin && $(uname -m) == arm64 ]] || { die 'Run this script on an Apple silicon Mac.'; return 1; }
    [[ $EUID -ne 0 ]] || { die 'Run as your normal macOS user, without sudo.'; return 1; }
    export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/opt/homebrew/sbin:$PATH"
    sanitize_build_env
    prepare_apple_tools "$bootstrap"
    if [[ $bootstrap == 1 ]]; then install_tools; fi
    check_tools
    mkdir -p "$OUTPUT_PARENT"
    OUTPUT_PARENT=$(cd "$OUTPUT_PARENT" && pwd -P)
    BUILD_ROOT=$(mktemp -d "$OUTPUT_PARENT/vpn-build-$(date +%Y%m%d-%H%M%S)-XXXXXX")
    SOURCES="$BUILD_ROOT/sources"
    OUT="$BUILD_ROOT/out"
    LOGS="$BUILD_ROOT/logs"
    BUILD_RESULTS="$BUILD_ROOT/BUILD-RESULTS.tsv"
    SOURCE_REVISIONS="$BUILD_ROOT/SOURCE-REVISIONS.tsv"
    JOB_FAILURES=0
    mkdir -p "$SOURCES" "$LOGS" "$OUT/linux-amd64" "$OUT/linux-arm64" \
        "$OUT/macos-arm64/bin" "$OUT/macos-arm64/apps"
    printf 'job\tresult\tlog\n' > "$BUILD_RESULTS"
    printf 'repository\tcommit\n' > "$SOURCE_REVISIONS"
    say "Fresh build directory: $BUILD_ROOT"
    # Keep failures visible before any build jobs have started, and preserve
    # the failing probe's exit status through the pipeline.
    write_tool_versions 2>&1 | tee "$BUILD_ROOT/TOOL-VERSIONS.txt"
    say 'Source downloads are full working trees of main; history is shallow. GitHub may ask you to sign in.'
    schedule_builds
    cp "$SOURCE_REVISIONS" "$OUT/SOURCE-REVISIONS.tsv"
    cp "$BUILD_RESULTS" "$OUT/BUILD-RESULTS.tsv"
    write_checksums
    say "Output: $OUT"
    cat "$BUILD_RESULTS"
    printf '\nResults: %s\nSources: %s\nLogs: %s\n' "$BUILD_RESULTS" "$SOURCE_REVISIONS" "$LOGS"
    if [[ $JOB_FAILURES -ne 0 ]]; then
        printf '\nINCOMPLETE: %s jobs failed. Successfully built artifacts are retained.\n' "$JOB_FAILURES" >&2
        return 1
    fi
    say 'All requested artifacts built and checked. Linux binaries were cross-compiled, not executed on this Mac.'
    open "$OUT" || true
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -euo pipefail
    main "$@"
fi
