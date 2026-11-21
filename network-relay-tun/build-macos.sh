#!/usr/bin/env bash
set -euo pipefail
umask 077
root=$(cd -- "$(dirname -- "$0")" && pwd)
if [[ $(uname -s) != Darwin || $(uname -m) != arm64 ]]; then
    echo 'Build on Apple Silicon macOS 27 or newer with Xcode 27.' >&2; exit 1
fi
if [[ $(sw_vers -productVersion | cut -d. -f1) -lt 27 || $(xcrun --sdk macosx --show-sdk-version | cut -d. -f1) -lt 27 ]]; then
    echo 'macOS 27 and Xcode macOS SDK 27 or newer are required.' >&2; exit 1
fi
for tool in cargo swift python3; do command -v "$tool" >/dev/null; done
export CARGO_HOME="$root/.cargo"
export CARGO_TARGET_DIR="$root/target"
export MACOSX_DEPLOYMENT_TARGET=27.0
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4}
mkdir -p "$root/.build" "$root/dist"
cargo test --locked --manifest-path "$root/Core/Cargo.toml"
cargo test --locked --manifest-path "$root/Host/Cargo.toml"
cargo test --locked --manifest-path "$root/TunEngine/Cargo.toml" --tests
cargo test --locked --manifest-path "$root/TunEngine/Cargo.toml" -p ipstack --lib
cargo test --locked --manifest-path "$root/TunEngine/Cargo.toml" -p tun2proxy --lib
python3 "$root/tests/test_isolation.py"
cargo build --locked --release --target aarch64-apple-darwin --manifest-path "$root/Host/Cargo.toml"
cargo build --locked --release --target aarch64-apple-darwin --manifest-path "$root/TunEngine/Cargo.toml"
cargo build --locked --release --lib --target aarch64-apple-darwin --manifest-path "$root/Core/Cargo.toml"
lib="$CARGO_TARGET_DIR/aarch64-apple-darwin/release"
swift test --package-path "$root/App" --scratch-path "$root/.build/swift" --jobs 4 -Xlinker -L -Xlinker "$lib"
swift build --package-path "$root/App" --scratch-path "$root/.build/swift" -c release --jobs 4 -Xlinker -L -Xlinker "$lib"
bin=$(swift build --package-path "$root/App" --scratch-path "$root/.build/swift" -c release --show-bin-path)
stage=$(mktemp -d "$root/.build/bundle.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT
app="$stage/Network Relay Tun.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources" "$app/Contents/Helpers"
cp "$lib/network-relay-tun-host" "$app/Contents/Helpers/network-relay-tun-host"
cp "$lib/network-relay-tun-engine" "$app/Contents/Helpers/packet-worker"
# Shell scripts are sealed resources; Helpers contains signed Mach-O tools only.
cp "$root/scripts/install-helper.sh" "$app/Contents/Resources/install-helper.sh"
cp "$root/scripts/uninstall-helper.sh" "$app/Contents/Resources/uninstall-helper.sh"
codesign --force --sign - "$app/Contents/Helpers/network-relay-tun-host"
codesign --force --sign - "$app/Contents/Helpers/packet-worker"
cp "$bin/NetworkRelayTun" "$app/Contents/MacOS/NetworkRelayTun"
version=$(tr -d '[:space:]' < "$root/VERSION")
sed "s/@VERSION@/$version/g" "$root/Info.plist.in" > "$app/Contents/Info.plist"
plutil -insert NetworkRelayTunCoreVersion -string "$version (Rust HTTP CONNECT / CONNECT-UDP)" "$app/Contents/Info.plist"
plutil -insert NetworkRelayTunBuildAt -string "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$app/Contents/Info.plist"
icons="$stage/AppIcon.iconset"
mkdir -p "$icons"
for size in 16 32 128 256 512; do
    sips -z "$size" "$size" "$root/AppIcon.png" --out "$icons/icon_${size}x${size}.png" >/dev/null
    sips -z "$((size * 2))" "$((size * 2))" "$root/AppIcon.png" --out "$icons/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$icons" -o "$app/Contents/Resources/AppIcon.icns"
plutil -lint "$app/Contents/Info.plist"
codesign --force --sign - "$app"
codesign --verify --strict "$app"
archive="NetworkRelayTun-$version-macos-arm64.zip"
ditto -c -k --keepParent "$app" "$stage/$archive"
unzip -tq "$stage/$archive"
# Replace only this project's generated bundle after successful verification.
rm -rf -- "$root/dist/Network Relay Tun.app"
mv -- "$app" "$root/dist/Network Relay Tun.app"
mv -f -- "$stage/$archive" "$root/dist/$archive"
echo "Built $root/dist/Network Relay Tun.app and $archive; native acceptance is required before production use."
