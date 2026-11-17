import Foundation
import Darwin
import NetworkRelayTunModel

struct HostStatus: Decodable {
    let state: String
    let interface: String?
    let lease: String?
}
struct HostReply: Decodable {
    let ok: Bool
    let status: HostStatus
    let error: String
    let version: String
}

/// One serialized control connection owns one capture lease. No relay password
/// or arbitrary command is sent to the privileged helper.
final class HostSession: @unchecked Sendable {
    private let queue = DispatchQueue(label: "com.arccal.network-relay-tun.host")
    private var process: Process?
    private var input: FileHandle?
    private var output: FileHandle?
    private var lease: String?

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
                    if let value = result.status.lease { lease = value }
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
            input = nil; output = nil; lease = nil
            if process?.isRunning == true { process?.terminate() }
            process = nil
        }
    }
    static func endpoint(_ settings: Settings) throws -> String {
        if !settings.serverIP.isEmpty {
            var address = in_addr()
            guard inet_pton(AF_INET, settings.serverIP, &address) == 1 else {
                throw NativeError("Global TUN currently needs an IPv4 relay endpoint. IPv6 destination traffic is supported through that relay.")
            }
            return settings.serverIP
        }
        guard let host = URLComponents(string: "https://" + settings.domain)?.host else { throw NativeError("Invalid relay domain.") }
        var hints = addrinfo(); hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM
        var result: UnsafeMutablePointer<addrinfo>?
        let code = getaddrinfo(host, nil, &hints, &result)
        guard code == 0, let first = result else { throw NativeError("Cannot resolve the relay's IPv4 bootstrap address.") }
        defer { freeaddrinfo(result) }
        var text = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        let address = first.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
        var addressCopy = address
        guard inet_ntop(AF_INET, &addressCopy, &text, socklen_t(text.count)) != nil else { throw NativeError("Invalid resolved relay address.") }
        return String(cString: text)
    }
}
