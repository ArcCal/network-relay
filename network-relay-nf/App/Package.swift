// swift-tools-version:5.9
import PackageDescription

var targets: [Target] = [
    .target(name: "NetworkRelayNFModel"),
    .testTarget(name: "NetworkRelayNFModelTests", dependencies: ["NetworkRelayNFModel"], resources: [.copy("Fixtures")]),
]
// Linux can run the portable model tests; the product itself is macOS only.
#if os(macOS)
targets += [
    .target(name: "NetworkRelayNFBridge", publicHeadersPath: "include"),
    .executableTarget(name: "NetworkRelayNF", dependencies: ["NetworkRelayNFModel", "NetworkRelayNFBridge"], linkerSettings: [
        .linkedLibrary("network_relay_nf_core"), .linkedFramework("Network"), .linkedFramework("Security"),
    ]),
]
#endif
let package = Package(name: "NetworkRelayNF", platforms: [.macOS("27.0")], targets: targets)
