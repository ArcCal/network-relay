#!/usr/bin/env python3
"""Check the actual path observer with a controlled Network.framework substitute.

This verifies callback filtering and lifetime with controlled path equality,
not native macOS path delivery or Apple's treatment of every metadata change.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


NETWORK = r"""import Dispatch

public struct NWPath: Equatable, Sendable {
    public var status: String
    public var interface: String
    public var address: String
    public var gateway: String
    public var wrapper: Int
    public init(status: String = "satisfied", interface: String = "en0",
                address: String = "192.0.2.1", gateway: String = "192.0.2.254", wrapper: Int = 0) {
        self.status = status; self.interface = interface
        self.address = address; self.gateway = gateway; self.wrapper = wrapper
    }
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.status == rhs.status && lhs.interface == rhs.interface &&
        lhs.address == rhs.address && lhs.gateway == rhs.gateway
    }
}

public final class NWPathMonitor {
    public static var latest: NWPathMonitor?
    public var pathUpdateHandler: (@Sendable (NWPath) -> Void)?
    public private(set) var cancelled = false
    private var queue: DispatchQueue?
    public init() { Self.latest = self }
    public func start(queue: DispatchQueue) { self.queue = queue; deliver(NWPath()) }
    public func deliver(_ path: NWPath) {
        queue?.sync { pathUpdateHandler?(path) }
    }
    public func cancel() { cancelled = true; pathUpdateHandler = nil }
}
"""

HARNESS = r"""import Foundation
import Network

@main struct Check {
    @MainActor static func main() async throws {
        var changes = 0
        var observer: NetworkChanges? = NetworkChanges { changes += 1 }
        weak var weakObserver = observer
        let native = NWPathMonitor.latest!
        func settle() async throws { try await Task.sleep(nanoseconds: 20_000_000) }
        try await settle()
        precondition(changes == 0, "initial snapshot must not restart")

        for wrapper in 1...20 { native.deliver(NWPath(wrapper: wrapper)) }
        try await settle()
        precondition(changes == 0, "equivalent snapshots must not restart")

        var path = NWPath(address: "192.0.2.2")
        native.deliver(path)
        try await settle()
        precondition(changes == 1, "same-interface address changes must be delivered")
        for wrapper in 21...40 { path.wrapper = wrapper; native.deliver(path) }
        try await settle()
        precondition(changes == 1, "a new equal baseline must suppress duplicate deliveries")

        path.gateway = "192.0.2.253"
        native.deliver(path)
        try await settle()
        precondition(changes == 2, "same-interface gateway changes must be delivered")
        path.interface = "en1"
        native.deliver(path)
        try await settle()
        precondition(changes == 3, "interface changes must be delivered")
        path.status = "unsatisfied"
        native.deliver(path)
        try await settle()
        precondition(changes == 4, "path loss must be delivered")
        native.deliver(path)
        try await settle()
        precondition(changes == 4, "duplicate unavailable snapshots must be suppressed")
        path.status = "satisfied"
        native.deliver(path)
        try await settle()
        precondition(changes == 5, "path restoration must be delivered")

        // Queue a main-actor delivery, then destroy the observer before yielding.
        path.address = "192.0.2.3"
        native.deliver(path)
        observer = nil
        precondition(weakObserver == nil && native.cancelled, "observer must cancel without retaining itself")
        weakObserver = nil
        try await settle()
        precondition(changes == 5, "queued callbacks must not survive observer destruction")
        native.deliver(NWPath())
        try await settle()
        precondition(changes == 5, "cancelled monitors must not deliver")
        print("PASS actual NF observer: equal snapshots, address/gateway/interface changes, loss/restoration and queued cancellation; Network.framework is stubbed")
    }
}
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--swiftc", default="swiftc", help="Swift compiler executable")
    args = parser.parse_args()
    compiler = shutil.which(args.swiftc)
    if compiler is None:
        parser.error("swiftc was not found; install Swift or pass --swiftc PATH")
    source = Path(__file__).resolve().parents[1] / "App/Sources/NetworkRelayNF/NetworkChanges.swift"
    with tempfile.TemporaryDirectory(prefix="network-relay-nf-path-") as folder:
        build = Path(folder)
        environment = os.environ.copy()
        flags = ["-swift-version", "5", "-warnings-as-errors", "-module-cache-path", str(build / "cache")]
        library = build / ("libNetwork.dylib" if os.uname().sysname == "Darwin" else "libNetwork.so")
        (build / "Network.swift").write_text(NETWORK)
        subprocess.run([
            compiler, *flags, "-emit-library", "-emit-module", "-module-name", "Network",
            "-emit-module-path", str(build / "Network.swiftmodule"),
            str(build / "Network.swift"), "-o", str(library),
        ], env=environment, check=True)
        (build / "Harness.swift").write_text(HARNESS)
        executable = build / "path-check"
        subprocess.run([
            compiler, *flags, "-I", str(build), "-L", str(build), "-lNetwork",
            "-Xlinker", "-rpath", "-Xlinker", str(build),
            str(source), str(build / "Harness.swift"), "-o", str(executable),
        ], env=environment, check=True)
        subprocess.run([str(executable)], env=environment, check=True)


if __name__ == "__main__":
    main()
