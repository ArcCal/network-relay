import Foundation
import Network
import SystemConfiguration

/// The Network.framework interface object pins IPv6 sockets. The physical
/// service configuration stays independent of our split routes and DNS entry.
final class NetworkChanges {
    private let monitor = NWPathMonitor(prohibitedInterfaceTypes: [.other, .loopback])
    private let queue = DispatchQueue(label: "com.arccal.network-relay-tun.path")
    private let store: SCDynamicStore?

    func physicalInterface(named name: String) -> NWInterface? {
        monitor.currentPath.availableInterfaces.first {
            $0.name == name && [.wifi, .wiredEthernet, .cellular].contains($0.type)
        }
    }

    init(_ changed: @escaping @MainActor () -> Void) {
        let observer = PhysicalServices(changed)
        var context = SCDynamicStoreContext(version: 0, info: Unmanaged.passUnretained(observer).toOpaque(),
            retain: { pointer in _ = Unmanaged<PhysicalServices>.fromOpaque(pointer).retain(); return pointer },
            release: { pointer in Unmanaged<PhysicalServices>.fromOpaque(pointer).release() }, copyDescription: nil)
        let session = SCDynamicStoreCreate(nil, "Network Relay Tun uplink" as CFString, { store, _, pointer in
            guard let pointer else { return }
            Unmanaged<PhysicalServices>.fromOpaque(pointer).takeUnretainedValue().update(store)
        }, &context)
        store = session
        let observing = session.map {
            SCDynamicStoreSetNotificationKeys($0, PhysicalServices.keys, PhysicalServices.patterns) &&
                SCDynamicStoreSetDispatchQueue($0, queue)
        } ?? false
        if !observing { monitor.pathUpdateHandler = { _ in observer.update(session) } }
        queue.async { observer.update(session) }
        monitor.start(queue: queue)
    }

    deinit {
        monitor.cancel()
        if let store { SCDynamicStoreSetDispatchQueue(store, nil) }
    }
}

private final class PhysicalServices {
    static let keys = ["Setup:/Network/Global/IPv4"] as CFArray
    static let patterns = ["State:/Network/Service/[^/]+/IPv[46]"] as CFArray
    private let changed: @MainActor () -> Void
    private var previous: [PhysicalUplink]?

    init(_ changed: @escaping @MainActor () -> Void) { self.changed = changed }

    func update(_ store: SCDynamicStore?) {
        guard let next = PhysicalUplink.current(store) else { return }
        let prior = previous
        previous = next
        guard let prior, prior != next else { return }
        Task { @MainActor [changed] in changed() }
    }
}

struct PhysicalUplink: Equatable {
    let service: String
    let family: String
    let interface: String
    let addresses: [String]
    let router: String?
    let signature: String?

    static func current(_ store: SCDynamicStore?) -> [Self]? {
        guard let records = SCDynamicStoreCopyMultiple(store, PhysicalServices.keys, PhysicalServices.patterns) as? [String: [String: Any]],
              let devices = SCNetworkInterfaceCopyAll() as? [SCNetworkInterface] else { return nil }
        let types: [CFString] = [kSCNetworkInterfaceTypeEthernet, kSCNetworkInterfaceTypeIEEE80211, kSCNetworkInterfaceTypeWWAN,
                                 kSCNetworkInterfaceTypeBond, kSCNetworkInterfaceTypeVLAN, kSCNetworkInterfaceTypeFireWire]
        let names = Set(devices.compactMap { device -> String? in
            guard let kind = SCNetworkInterfaceGetInterfaceType(device), types.contains(where: { CFEqual($0, kind) }) else { return nil }
            return SCNetworkInterfaceGetBSDName(device) as String?
        })
        return from(records, physicalNames: names)
    }

    static func from(_ records: [String: [String: Any]], physicalNames: Set<String>) -> [Self] {
        let order = records["Setup:/Network/Global/IPv4"]?["ServiceOrder"] as? [String] ?? []
        let active = records.compactMap { key, values -> Self? in
            let path = key.split(separator: "/")
            guard path.count == 5, path[0] == "State:", path[1] == "Network", path[2] == "Service",
                  path[4] == "IPv4" || path[4] == "IPv6", let name = values["InterfaceName"] as? String,
                  physicalNames.contains(name), let addresses = values["Addresses"] as? [String], !addresses.isEmpty else { return nil }
            return Self(service: String(path[3]), family: String(path[4]), interface: name, addresses: addresses.sorted(),
                        router: values["Router"] as? String, signature: values["NetworkSignature"] as? String)
        }
        func preference(_ entry: Self) -> (Int, String, String) {
            (order.firstIndex(of: entry.service) ?? Int.max, entry.service, entry.family)
        }
        return active.sorted { preference($0) < preference($1) }
    }
}
