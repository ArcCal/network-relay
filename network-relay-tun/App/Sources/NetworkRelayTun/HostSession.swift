import Foundation
import Darwin
import NetworkRelayTunModel

struct HostStatus: Decodable {
    let state: String
    let interface: String?
    let lease: String?
    let ipv6_uplink: String?
}
struct HostReply: Decodable {
    let ok: Bool
    let status: HostStatus
    let error: String
    let version: String
    let control_revision: UInt32?
    let retry_endpoint: Bool?
    let capture_changed: Bool?
}

struct EndpointFailure: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

struct CaptureChanged: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

/// One serialized control connection owns one capture lease. No relay password
/// or arbitrary command is sent to the privileged helper.
final class HostSession: @unchecked Sendable {
    private let queue = DispatchQueue(label: "com.arccal.network-relay-tun.host")
    private var process: Process?
    private var input: FileHandle?
    private var output: FileHandle?
    static func checkInstalledFiles(bundled: URL, installed: URL) throws {
        let files = FileManager.default
        for name in ["network-relay-tun-host", "packet-worker"] {
            let source = bundled.appendingPathComponent(name).path
            let target = installed.appendingPathComponent(name).path
            guard files.isExecutableFile(atPath: source), files.isExecutableFile(atPath: target),
                  files.contentsEqual(atPath: source, andPath: target) else {
                throw NativeError("The installed network helper is missing or differs from this app. Click Install / Update Helper.")
            }
        }
    }

    /// Recovery stays available with an older daemon. New capture requires
    /// both the installed binaries and the protocol of the running process.
    func checkCompatibility() async throws {
        try await Task.detached {
            try Self.checkInstalledFiles(bundled: Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers"),
                installed: URL(fileURLWithPath: "/Library/Application Support/NetworkRelayTun"))
        }.value
        let reply = try await request(["operation": "status"])
        guard reply.control_revision == 2 else {
            throw NativeError("The running network helper is incompatible with this app. Click Install / Update Helper.")
        }
    }

    func request(_ object: [String: Any]) async throws -> HostReply {
        let data = try JSONSerialization.data(withJSONObject: object)
        guard data.count < 4096 else { throw NativeError("Host request is too large.") }
        return try await withCheckedThrowingContinuation { continuation in
            queue.async { [self] in
                do {
                    if process == nil {
                        let executable = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/network-relay-tun-host")
                        guard FileManager.default.isExecutableFile(atPath: executable.path) else { throw NativeError("The bundled network helper is missing.") }
                        let child = Process(); child.executableURL = executable; child.arguments = ["control"]
                        let stdin = Pipe(), stdout = Pipe()
                        // A missing or crashed helper must produce a catchable write
                        // error, not SIGPIPE termination of the entire GUI process.
                        guard fcntl(stdin.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1) != -1 else {
                            throw NativeError("Cannot protect the helper control pipe against SIGPIPE.")
                        }
                        child.standardInput = stdin; child.standardOutput = stdout; child.standardError = FileHandle.nullDevice
                        try child.run()
                        process = child; input = stdin.fileHandleForWriting; output = stdout.fileHandleForReading
                    }
                    try input?.write(contentsOf: data + Data([10]))
                    var reply = Data()
                    while reply.count <= 4096 {
                        guard let byte = try output?.read(upToCount: 1), !byte.isEmpty else {
                            throw NativeError("Network helper connection ended. Install the helper or use Recover Network.")
                        }
                        if byte[0] == 10 { break }
                        reply.append(byte)
                    }
                    guard reply.count <= 4096 else { throw NativeError("Invalid network helper reply.") }
                    let result = try JSONDecoder().decode(HostReply.self, from: reply)
                    if !result.ok, result.retry_endpoint == true { throw EndpointFailure(message: result.error) }
                    if !result.ok, result.capture_changed == true { throw CaptureChanged(message: result.error) }
                    guard result.ok else { throw NativeError(result.error) }
                    continuation.resume(returning: result)
                } catch { continuation.resume(throwing: error) }
            }
        }
    }
    func stop() async throws {
        let current = try await request(["operation": "status"])
        let restored: HostReply
        if let value = current.status.lease {
            restored = try await request(["operation": "stop", "lease": value])
        } else if current.status.state != "idle" {
            restored = try await request(["operation": "recover"])
        } else { restored = current }
        guard restored.status.state == "idle" else { throw NativeError("Network recovery remains incomplete.") }
        close()
    }
    func close() {
        queue.async { [self] in
            try? input?.close(); try? output?.close()
            input = nil; output = nil
            if process?.isRunning == true { process?.terminate() }
            process = nil
        }
    }
}
