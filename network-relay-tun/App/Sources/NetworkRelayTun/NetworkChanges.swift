import Foundation
import Network

/// One application-lifetime observer, independent of each relay connection.
final class NetworkChanges {
    // The default path can become our utun as soon as its routes are added.
    // Scope observations to the underlying uplinks before comparing paths.
    private let monitor = NWPathMonitor(prohibitedInterfaceTypes: [.other, .loopback])
    private let queue = DispatchQueue(label: "com.arccal.network-relay-tun.path")
    private var previousPath: String?

    func physicalInterface(named name: String) -> NWInterface? {
        monitor.currentPath.availableInterfaces.first {
            $0.name == name && [.wifi, .wiredEthernet, .cellular].contains($0.type)
        }
    }

    init(_ changed: @escaping @MainActor () -> Void) {
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            // The first delivery describes the initial path, not a switch.
            // Ignore changes caused solely by our own utun capture routes.
            // The privileged heartbeat separately checks physical gateways.
            let physical = path.availableInterfaces.filter { $0.type == .wifi || $0.type == .wiredEthernet || $0.type == .cellular }
                .map { "\($0.name):\($0.index)" }.joined(separator: ",")
            let signature = "\(path.status):\(physical)"
            let previous = previousPath
            previousPath = signature
            // Compare the native path, not just its interface or availability.
            guard let previous, previous != signature else { return }
            Task { @MainActor [weak self] in
                guard let self else { return }
                withExtendedLifetime(self) { changed() }
            }
        }
        monitor.start(queue: queue)
    }
    deinit { monitor.cancel() }
}
