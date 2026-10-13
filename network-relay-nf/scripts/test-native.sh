#!/usr/bin/env bash
# Invoked by build-macos.sh after the native product is built.
set -euo pipefail
NF_ROOT=$(cd "$(dirname "$0")/.." && pwd)
NF_LIB=${1:?Pass the Rust static-library directory}
mkdir -p "$NF_ROOT/build"
NF_MODULES=$(mktemp -d "$NF_ROOT/build/native-smoke-modules.XXXXXX")
trap 'rm -rf "$NF_MODULES"' EXIT
NF_SDK=$(xcrun --sdk macosx --show-sdk-path)
# Build from source into our own directory. SwiftPM may use either its native
# layout or Xcode's Products/Release layout; neither is a public module API.
cp "$NF_ROOT/App/Sources/NetworkRelayNFBridge/include/NetworkRelayNFBridge.h" "$NF_MODULES/"
cat > "$NF_MODULES/module.modulemap" <<'MAP'
module NetworkRelayNFBridge {
    header "NetworkRelayNFBridge.h"
    export *
}
MAP
xcrun swiftc -parse-as-library -swift-version 5 -O \
    -target arm64-apple-macosx27.0 -sdk "$NF_SDK" \
    -whole-module-optimization -emit-object -emit-module \
    -module-name NetworkRelayNFModel \
    -emit-module-path "$NF_MODULES/NetworkRelayNFModel.swiftmodule" \
    "$NF_ROOT/App/Sources/NetworkRelayNFModel/"*.swift \
    -o "$NF_MODULES/NetworkRelayNFModel.o"
xcrun swiftc -parse-as-library -swift-version 5 -O \
    -target arm64-apple-macosx27.0 -sdk "$NF_SDK" \
    -I "$NF_MODULES" \
    -Xcc "-fmodule-map-file=$NF_MODULES/module.modulemap" \
    -L "$NF_LIB" -lnetwork_relay_nf_core -framework Network -framework Security \
    "$NF_MODULES/NetworkRelayNFModel.o" \
    "$NF_ROOT/App/Sources/NetworkRelayNF/NativeClient.swift" \
    "$NF_ROOT/Tests/NativeSmoke.swift" \
    "$NF_ROOT/Tests/NativeCloseChecks.swift" \
    -o "$NF_ROOT/build/native-smoke"
"$NF_ROOT/build/native-smoke"
