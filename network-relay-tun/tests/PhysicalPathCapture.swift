import Foundation

/// Run an actual capture while observing the same physical path as the app.
@main
struct PhysicalPathCapture {
    @MainActor static func main() async {
        do { try await observeCapture() }
        catch {
            FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8))
            exit(1)
        }
    }

    @MainActor private static func observeCapture() async throws {
        try checkServiceChanges()
        let arguments = Array(CommandLine.arguments.dropFirst())
        guard arguments.count >= 2 else { throw ProbeFailure("Missing physical interface or test command") }
        var changes = 0
        let monitor = NetworkChanges { changes += 1 }
        let deadline = ProcessInfo.processInfo.systemUptime + 10
        while monitor.physicalInterface(named: arguments[0]) == nil {
            if ProcessInfo.processInfo.systemUptime >= deadline {
                throw ProbeFailure("The physical uplink was unavailable before capture")
            }
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        guard let initial = PhysicalUplink.current(nil), initial.contains(where: { $0.interface == arguments[0] }) else {
            throw ProbeFailure("The runner has no active physical IP service for its relay route")
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = Array(arguments.dropFirst())
        let status = try await withCheckedThrowingContinuation { (result: CheckedContinuation<Int32, Error>) in
            process.terminationHandler = { child in result.resume(returning: child.terminationStatus) }
            do { try process.run() }
            catch { process.terminationHandler = nil; result.resume(throwing: error) }
        }
        try await Task.sleep(nanoseconds: 500_000_000)
        guard status == 0 else { throw ProbeFailure("Packet capture test exited with status \(status)") }
        guard monitor.physicalInterface(named: arguments[0]) != nil, PhysicalUplink.current(nil) == initial, changes == 0 else {
            throw ProbeFailure("Capture changed the reported physical path \(changes) time(s)")
        }
        print("Physical uplink stayed available through capture and restoration")
    }

    private static func checkServiceChanges() throws {
        let order = "Setup:/Network/Global/IPv4"
        let wifi = "State:/Network/Service/wifi/IPv4"
        let wired = "State:/Network/Service/wired/IPv6"
        var records: [String: [String: Any]] = [
            order: ["ServiceOrder": ["wifi", "wired"]],
            wifi: ["InterfaceName": "en1", "Addresses": ["192.0.2.2"], "Router": "192.0.2.1"],
            wired: ["InterfaceName": "en0", "Addresses": ["2001:db8::2", "2001:db8::3"]]
        ]
        func read() -> [PhysicalUplink] { PhysicalUplink.from(records, physicalNames: ["en0", "en1"]) }
        let start = read()
        guard start.map(\.interface) == ["en1", "en0"] else { throw ProbeFailure("Physical service order was lost") }
        records["State:/Network/Service/tunnel/IPv4"] = ["InterfaceName": "utun8", "Addresses": ["198.18.0.1"]]
        records["State:/Network/Service/tunnel/DNS"] = ["ServerAddresses": ["192.0.2.53"]]
        records[wired]?["Addresses"] = ["2001:db8::3", "2001:db8::2"]
        guard read() == start else { throw ProbeFailure("Tunnel or address ordering affected physical services") }
        records[order]?["ServiceOrder"] = ["wired", "wifi"]
        guard read().first?.interface == "en0" else { throw ProbeFailure("Changed service preference was missed") }
        records[order]?["ServiceOrder"] = ["wifi", "wired"]
        records[wifi]?["Router"] = "192.0.2.254"
        guard read() != start else { throw ProbeFailure("Gateway replacement was missed") }
        records.removeValue(forKey: wifi)
        guard read().map(\.interface) == ["en0"] else { throw ProbeFailure("Lost uplink was missed") }
    }

    private struct ProbeFailure: LocalizedError {
        let errorDescription: String?
        init(_ description: String) { errorDescription = description }
    }
}
