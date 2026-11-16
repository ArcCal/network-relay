// swift-tools-version:5.9
import PackageDescription

var targets: [Target] = [
    .target(name: "NetworkRelayTunModel"),
    .testTarget(name: "NetworkRelayTunModelTests", dependencies: ["NetworkRelayTunModel"], resources: [.copy("Fixtures")]),
]
// Linux can run the portable model tests; the product itself is macOS only.
#if os(macOS)
targets += [
    .target(name: "NetworkRelayTunBridge", publicHeadersPath: "include"),
    .executableTarget(name: "NetworkRelayTun", dependencies: ["NetworkRelayTunModel", "NetworkRelayTunBridge"], linkerSettings: [
        .linkedLibrary("network_relay_tun_core"), .linkedFramework("Network"), .linkedFramework("Security"),
    ]),
]
#endif
let package = Package(name: "NetworkRelayTun", platforms: [.macOS("27.0")], targets: targets)
