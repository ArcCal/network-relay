// swift-tools-version:5.9
import PackageDescription

var targets: [Target] = [
    .target(name: "NetworkRealyNFModel"),
    .testTarget(name: "NetworkRealyNFModelTests", dependencies: ["NetworkRealyNFModel"], resources: [.copy("Fixtures")]),
]
// Linux can run the portable model tests; the product itself is macOS only.
#if os(macOS)
targets += [
    .target(name: "NetworkRealyNFBridge", publicHeadersPath: "include"),
    .executableTarget(name: "NetworkRealyNF", dependencies: ["NetworkRealyNFModel", "NetworkRealyNFBridge"], linkerSettings: [
        .linkedLibrary("network_realy_nf_core"), .linkedFramework("Network"), .linkedFramework("Security"),
    ]),
]
#endif
let package = Package(name: "NetworkRealyNF", platforms: [.macOS("27.0")], targets: targets)
