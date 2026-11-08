import Foundation
import Network

/// One application-lifetime observer, independent of each relay connection.
final class NetworkChanges {
    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "com.arccal.network-relay-nf.path")
    private var previousPath: NWPath?

    init(_ changed: @escaping @MainActor () -> Void) {
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            // The first delivery describes the initial path, not a switch.
            let previous = previousPath
            previousPath = path
            // Compare the native path, not just its interface or availability.
            guard let previous, previous != path else { return }
            Task { @MainActor [weak self] in
                guard let self else { return }
                withExtendedLifetime(self) { changed() }
            }
        }
        monitor.start(queue: queue)
    }
    deinit { monitor.cancel() }
}
