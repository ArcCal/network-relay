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
        guard monitor.physicalInterface(named: arguments[0]) != nil, changes == 0 else {
            throw ProbeFailure("Capture changed the reported physical path \(changes) time(s)")
        }
        print("Physical uplink stayed available through capture and restoration")
    }

    private struct ProbeFailure: LocalizedError {
        let errorDescription: String?
        init(_ description: String) { errorDescription = description }
    }
}
