#!/usr/bin/env bash
# Build the independent Rust application without changing another project.
set -euo pipefail
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    # New artifacts may be shared, but never writable by other users.
    # Respect a caller's stricter umask and preserve all existing directory modes.
    umask "$(printf '%03o' "$(( $(umask) | 0022 ))")"
fi
unset CDPATH CARGO_BUILD_TARGET

RS_BUILD_ARGS=(network-relay-rs/build-macos.sh "$@")
RS_SIGN=adhoc
if [[ ${1:-} == --unsigned ]]; then
    RS_SIGN=none
    shift
elif [[ ${1:-} == --sign ]]; then
    [[ $# -ge 2 ]] || { echo 'Usage: build-macos.sh [--unsigned | --sign IDENTITY]' >&2; exit 2; }
    RS_SIGN=$2
    shift 2
fi
[[ $# == 0 ]] || { echo 'Usage: build-macos.sh [--unsigned | --sign IDENTITY]' >&2; exit 2; }

if [[ $(uname -s) != Darwin || $(uname -m) != arm64 ]]; then
    echo 'Build Network Relay RS on an Apple silicon Mac with macOS 27 or newer.' >&2
    exit 1
fi
RS_OS_MAJOR=$(sw_vers -productVersion | cut -d. -f1)
[[ $RS_OS_MAJOR -ge 27 ]] || { echo 'macOS 27 or newer is required.' >&2; exit 1; }
# Find tools from rustup and Homebrew even if this shell has not loaded them yet.
for RS_PATH in /opt/homebrew/bin "${CARGO_HOME:-$HOME/.cargo}/bin"; do
    if [[ -d $RS_PATH && :$PATH: != *:"$RS_PATH":* ]]; then PATH="$RS_PATH:$PATH"; fi
done
export PATH
for RS_TOOL in cargo rustup xcrun plutil sips iconutil codesign ditto shasum otool; do
    command -v "$RS_TOOL" >/dev/null && continue
    case $RS_TOOL in
        cargo|rustup) echo "Required tool is missing: $RS_TOOL. Install Rust from https://rustup.rs, then run this script again." >&2 ;;
        *) echo "Required tool is missing: $RS_TOOL. Install Xcode 27 from the App Store and open it once, then run this script again." >&2 ;;
    esac
    exit 1
done
xcrun --sdk macosx --show-sdk-path >/dev/null 2>&1 || {
    echo 'The macOS SDK is unavailable. Install Xcode 27 from the App Store and open it once, then run this script again.' >&2
    exit 1
}

RS_ROOT=$(cd "$(dirname "$0")" && pwd)
# The helper re-executes a child; its cross-process environment is tested separately.
# shellcheck source=/dev/null
source "$RS_ROOT/../tools/fresh-build-source.sh"
relay_require_fresh_source "$RS_ROOT/.." "${RS_BUILD_ARGS[@]}"
RS_OUTPUT_ROOT=$RS_ROOT
[[ -z ${RELAY_BUILD_OUTPUT_ROOT:-} ]] || RS_OUTPUT_ROOT="$RELAY_BUILD_OUTPUT_ROOT/network-relay-rs"
RS_WORK=${RELAY_BUILD_WORK_ROOT:-"$RS_ROOT/.build-work"}
mkdir -p -- "$RS_WORK"
export RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-stable}
relay_prepare_build_environment "$RS_WORK" aarch64-apple-darwin
cd -- "$RS_ROOT"
RS_VERSION=$(tr -d '[:space:]' < "$RS_ROOT/VERSION")
RS_SOURCE=$(git -C "$RS_ROOT" rev-parse HEAD 2>/dev/null || printf 'Unknown')
if [[ $RS_SOURCE != Unknown ]] && [[ -n $(git -C "$RS_ROOT" status --porcelain -- .) ]]; then
    RS_SOURCE="$RS_SOURCE-dirty"
fi
export RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-stable}
export MACOSX_DEPLOYMENT_TARGET=27.0
# Keep the application independent even when the invoking shell has a parent
# project's CARGO_TARGET_DIR setting.
export CARGO_TARGET_DIR="$RELAY_BUILD_WORK_ROOT/rust-rs-target"
APP_BUILD_TIME=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
export APP_BUILD_TIME
export APP_SOURCE_REVISION="$RS_SOURCE"
RS_TARGET=aarch64-apple-darwin
if [[ $RELAY_REUSE_RUST_TOOLCHAIN != 1 ]]; then
    rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal
    rustup target add --toolchain "$RUSTUP_TOOLCHAIN" "$RS_TARGET"
fi
cargo test --locked -p network-relay-rs -p network-relay-rs-core --manifest-path "$RS_ROOT/Cargo.toml"
cargo build --locked --release --target "$RS_TARGET" --bin network-relay-rs --manifest-path "$RS_ROOT/Cargo.toml"
RS_LINKS=$(otool -L "$CARGO_TARGET_DIR/$RS_TARGET/release/network-relay-rs")
if [[ $RS_LINKS == *'/Network.framework/'* ]]; then
    echo 'Unexpected Network.framework link in the independent Rust application.' >&2
    exit 1
fi

mkdir -p "$RS_OUTPUT_ROOT/dist"
RS_STAGE=$(mktemp -d "$RS_WORK/rs-bundle.XXXXXX")
trap 'rm -rf "$RS_STAGE"' EXIT
RS_APP="$RS_STAGE/Network Relay RS.app"
mkdir -p "$RS_APP/Contents/MacOS" "$RS_APP/Contents/Resources"
cp "$CARGO_TARGET_DIR/$RS_TARGET/release/network-relay-rs" "$RS_APP/Contents/MacOS/network-relay-rs"
sed "s/@VERSION@/$RS_VERSION/g" "$RS_ROOT/Info.plist.in" > "$RS_APP/Contents/Info.plist"
plutil -insert NetworkRelayRSBuildAt -string "$APP_BUILD_TIME" "$RS_APP/Contents/Info.plist"
plutil -insert NetworkRelayRSSourceRevision -string "$APP_SOURCE_REVISION" "$RS_APP/Contents/Info.plist"
plutil -insert NetworkRelayRSCoreVersion -string "$RS_VERSION (Rust HTTP CONNECT / CONNECT-UDP)" "$RS_APP/Contents/Info.plist"

RS_ICONS="$RS_STAGE/AppIcon.iconset"
mkdir -p "$RS_ICONS"
for RS_SIZE in 16 32 128 256 512; do
    sips -z "$RS_SIZE" "$RS_SIZE" "$RS_ROOT/AppIcon.png" --out "$RS_ICONS/icon_${RS_SIZE}x${RS_SIZE}.png" >/dev/null
    sips -z "$((RS_SIZE * 2))" "$((RS_SIZE * 2))" "$RS_ROOT/AppIcon.png" --out "$RS_ICONS/icon_${RS_SIZE}x${RS_SIZE}@2x.png" >/dev/null
done
iconutil -c icns "$RS_ICONS" -o "$RS_APP/Contents/Resources/AppIcon.icns"
plutil -lint "$RS_APP/Contents/Info.plist"
if [[ $RS_SIGN != none ]]; then
    RS_IDENTITY=$RS_SIGN
    [[ $RS_IDENTITY != adhoc ]] || RS_IDENTITY=-
    codesign --force --sign "$RS_IDENTITY" "$RS_APP"
    codesign --verify --strict --verbose=2 "$RS_APP"
fi

RS_OUTPUT="$RS_OUTPUT_ROOT/dist/Network Relay RS.app"
rm -rf "$RS_OUTPUT"
mv "$RS_APP" "$RS_OUTPUT"
RS_ZIP="NetworkRelayRS-$RS_VERSION-macos-arm64.zip"
ditto -c -k --keepParent "$RS_OUTPUT" "$RS_OUTPUT_ROOT/dist/$RS_ZIP"
(cd "$RS_OUTPUT_ROOT/dist" && shasum -a 256 "$RS_ZIP" > "$RS_ZIP.sha256")
install -m 755 "$CARGO_TARGET_DIR/$RS_TARGET/release/network-relay-rs" "$RS_OUTPUT_ROOT/dist/network-relay-rs"
echo "Built $RS_OUTPUT"
echo "Archive: $RS_OUTPUT_ROOT/dist/$RS_ZIP"
echo "Source: $APP_SOURCE_REVISION; built: $APP_BUILD_TIME"
