#!/usr/bin/env bash
# Independent native app. No existing project or system configuration is changed.
set -euo pipefail
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    # New artifacts may be shared, but never writable by other users.
    # Respect a caller's stricter umask and preserve all existing directory modes.
    umask "$(printf '%03o' "$(( $(umask) | 0022 ))")"
fi
unset CDPATH CARGO_BUILD_TARGET
# Find tools from rustup and Homebrew even if this shell has not loaded them yet.
for NF_PATH in /opt/homebrew/bin "${CARGO_HOME:-$HOME/.cargo}/bin"; do
    if [[ -d $NF_PATH && :$PATH: != *:"$NF_PATH":* ]]; then PATH="$NF_PATH:$PATH"; fi
done
export PATH
if [[ $(uname -s) != Darwin || $(uname -m) != arm64 ]]; then
    echo 'Build Network Relay NF on an Apple silicon Mac with macOS 27 or newer.' >&2
    exit 1
fi
if [[ $(sw_vers -productVersion | cut -d. -f1) -lt 27 ]] ||
   [[ $(xcrun --sdk macosx --show-sdk-version | cut -d. -f1) -lt 27 ]]; then
    echo 'macOS 27 and an Xcode macOS 27 or newer SDK are required. Install or update Xcode from the App Store and open it once, then run this script again.' >&2
    exit 1
fi
for NF_TOOL in rustup cargo swift; do
    command -v "$NF_TOOL" >/dev/null && continue
    case $NF_TOOL in
        swift) echo 'Required tool is missing: swift. Install Xcode 27 from the App Store and open it once, then run this script again.' >&2 ;;
        *) echo "Required tool is missing: $NF_TOOL. Install Rust from https://rustup.rs, then run this script again." >&2 ;;
    esac
    exit 1
done
NF_ROOT=$(cd "$(dirname "$0")" && pwd)
# The helper re-executes a child; its cross-process environment is tested separately.
# shellcheck source=/dev/null
source "$NF_ROOT/../tools/fresh-build-source.sh"
relay_require_fresh_source "$NF_ROOT/.." network-relay-nf/build-macos.sh "$@"
NF_OUTPUT_ROOT=$NF_ROOT
[[ -z ${RELAY_BUILD_OUTPUT_ROOT:-} ]] || NF_OUTPUT_ROOT="$RELAY_BUILD_OUTPUT_ROOT/network-relay-nf"
NF_WORK=${RELAY_BUILD_WORK_ROOT:-"$NF_ROOT/.build-work"}
mkdir -p -- "$NF_WORK"
export RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-stable}
relay_prepare_build_environment "$NF_WORK" aarch64-apple-darwin
cd -- "$NF_ROOT"
NF_VERSION=$(tr -d '[:space:]' < "$NF_ROOT/VERSION")
NF_SOURCE=$(git -C "$NF_ROOT" rev-parse HEAD 2>/dev/null || printf 'Unknown')
if [[ $NF_SOURCE != Unknown ]] && [[ -n $(git -C "$NF_ROOT" status --porcelain -- .) ]]; then
    NF_SOURCE="$NF_SOURCE-dirty"
fi
export RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-stable}
export MACOSX_DEPLOYMENT_TARGET=27.0
export CARGO_TARGET_DIR="$RELAY_BUILD_WORK_ROOT/rust-nf-target"
mkdir -p "$CARGO_TARGET_DIR"
CARGO_TARGET_DIR=$(cd -- "$CARGO_TARGET_DIR" && pwd)
export CARGO_PROFILE_RELEASE_STRIP=true
NF_TARGET=aarch64-apple-darwin
if [[ $RELAY_REUSE_RUST_TOOLCHAIN != 1 ]]; then
    rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal
    rustup target add --toolchain "$RUSTUP_TOOLCHAIN" "$NF_TARGET"
fi
NF_SWIFT_FLAGS=(--scratch-path "$NF_WORK/swift-nf-build")
# All tests run before the production library is built without dev-dependencies.
cargo test --locked --manifest-path "$NF_ROOT/Core/Cargo.toml"
cargo build --locked --release --lib --target "$NF_TARGET" --manifest-path "$NF_ROOT/Core/Cargo.toml"
NF_LIB="$CARGO_TARGET_DIR/$NF_TARGET/release"
cd "$NF_ROOT/App"
swift test "${NF_SWIFT_FLAGS[@]}" --jobs 4 --arch arm64 -Xlinker -L -Xlinker "$NF_LIB"
swift build "${NF_SWIFT_FLAGS[@]}" -c release --jobs 4 --arch arm64 -Xlinker -L -Xlinker "$NF_LIB"
NF_BIN=$(swift build "${NF_SWIFT_FLAGS[@]}" -c release --arch arm64 --show-bin-path)
bash "$NF_ROOT/scripts/test-native.sh" "$NF_LIB"
mkdir -p "$NF_OUTPUT_ROOT/dist"
NF_STAGE=$(mktemp -d "$NF_WORK/nf-bundle.XXXXXX")
trap 'rm -rf "$NF_STAGE"' EXIT
NF_APP="$NF_STAGE/Network Relay NF.app"
mkdir -p "$NF_APP/Contents/MacOS" "$NF_APP/Contents/Resources"
cp "$NF_BIN/NetworkRelayNF" "$NF_APP/Contents/MacOS/NetworkRelayNF"
sed "s/@VERSION@/$NF_VERSION/g" "$NF_ROOT/Info.plist.in" > "$NF_APP/Contents/Info.plist"
plutil -insert NetworkRelayNFCoreVersion -string "$NF_VERSION (Rust HTTP CONNECT / CONNECT-UDP)" "$NF_APP/Contents/Info.plist"
plutil -insert NetworkRelayNFBuildAt -string "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$NF_APP/Contents/Info.plist"
plutil -insert NetworkRelayNFSourceRevision -string "$NF_SOURCE" "$NF_APP/Contents/Info.plist"
NF_ICONS="$NF_STAGE/AppIcon.iconset"
mkdir -p "$NF_ICONS"
for size in 16 32 128 256 512; do
    sips -z "$size" "$size" "$NF_ROOT/AppIcon.png" --out "$NF_ICONS/icon_${size}x${size}.png" >/dev/null
    sips -z "$((size * 2))" "$((size * 2))" "$NF_ROOT/AppIcon.png" --out "$NF_ICONS/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$NF_ICONS" -o "$NF_APP/Contents/Resources/AppIcon.icns"
plutil -lint "$NF_APP/Contents/Info.plist"
codesign --force --sign - "$NF_APP"
codesign --verify --strict --verbose=2 "$NF_APP"
rm -rf "$NF_OUTPUT_ROOT/dist/Network Relay NF.app"
mv "$NF_APP" "$NF_OUTPUT_ROOT/dist/Network Relay NF.app"
NF_ZIP="NetworkRelayNF-$NF_VERSION-macos-arm64.zip"
cd "$NF_OUTPUT_ROOT/dist"
rm -f "$NF_ZIP"
ditto -c -k --keepParent 'Network Relay NF.app' "$NF_ZIP"
shasum -a 256 "$NF_ZIP" > "$NF_ZIP.sha256"
echo "Built $NF_OUTPUT_ROOT/dist/$NF_ZIP"
