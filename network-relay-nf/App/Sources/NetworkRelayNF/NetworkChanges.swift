import Foundation
import Network

/// One application-lifetime observer, independent of each relay connection.
final class NetworkChanges {
    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "com.arccal.network-relay-nf.path")
    private var initialized = false

    init(_ changed: @escaping @MainActor () -> Void) {
        monitor.pathUpdateHandler = { [weak self] _ in
            guard let self else { return }
            // The first delivery describes the initial path, not a switch.
            guard initialized else { initialized = true; return }
            Task { @MainActor in changed() }
        }
        monitor.start(queue: queue)
    }
    deinit { monitor.cancel() }
}
