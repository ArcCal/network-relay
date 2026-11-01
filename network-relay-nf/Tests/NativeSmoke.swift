// Real Network.framework + production protocol core. No remote server,
// certificates, administrator rights or system configuration are required.
import Foundation
import Network
import Darwin
import NetworkRelayNFModel

private let socketQueue = DispatchQueue(label: "com.arccal.network-relay-nf.smoke")
private struct CheckError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

@MainActor
private func waitFor(_ message: String, _ condition: () -> Bool) async throws {
    let deadline = ProcessInfo.processInfo.systemUptime + 8
    while !condition() {
        if ProcessInfo.processInfo.systemUptime > deadline { throw CheckError("Timed out: \(message)") }
        try await Task.sleep(nanoseconds: 20_000_000)
    }
}

@MainActor
private final class Instance {
    private(set) var client: NativeClient!
    var logs: [String] = []
    var port: UInt16?
    var exitCode: Int32?
    var error: String?
    var connected = false
    init(port: UInt16 = 0, serverPort: UInt16) throws {
        let configuration = """
        uri_template = "https://127.0.0.1:\(serverPort)/.well-known/masque/udp/{target_host}/{target_port}/"
        server_name = "nf.test.invalid"
        username = "native-smoke"
        password = "test-only-secret"
        mode = "socks"
        transport = "h2"
        [socks]
        listen = ["127.0.0.1:\(port)"]
        """
        client = try NativeClient(configuration: configuration, level: .normal) { [weak self] event in
            guard let self else { return }
            switch event {
            case .log(let lines):
                logs.append(contentsOf: lines)
                for line in lines {
                    let prefix = "TCP listener ready on 127.0.0.1:"
                    if let range = line.range(of: prefix) {
                        self.port = UInt16(line[range.upperBound...].prefix(while: { $0.isNumber }))
                    }
                }
            case .connected: connected = true
            case .reconnecting: break
            case .traffic, .trafficUnavailable: break
            case .exited(let code, let why): exitCode = code; error = why
            }
        }
    }
    func ready() async throws {
        try await waitFor("native listener ready or explicit failure") { port != nil || exitCode != nil }
        guard port != nil, exitCode == nil else { throw CheckError(error ?? "Listener failed") }
        guard !connected else { throw CheckError("An unavailable server was reported as Connected") }
    }
    func stop() async throws {
        client.stop()
        try await waitFor("native instance exits after cancellation") { exitCode != nil }
        guard exitCode == 0 else { throw CheckError(error ?? "Cancellation did not exit cleanly") }
    }
}

@MainActor
private final class BoundListener {
    let native: NWListener
    var port: UInt16?
    var error: String?
    var cancelled = false
    var accepted: [NWConnection] = []
    init(holdConnections: Bool = false) throws {
        let parameters = NWParameters(tls: nil, tcp: NWProtocolTCP.Options())
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        native = try NWListener(using: parameters)
        native.stateUpdateHandler = { [weak self] state in
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                switch state {
                case .ready: port = native.port?.rawValue
                case .failed(let why): error = String(describing: why)
                case .cancelled: cancelled = true
                default: break
                }
            }
        }
        native.newConnectionHandler = { [weak self] connection in
            if holdConnections {
                DispatchQueue.main.async { self?.accepted.append(connection) }
                connection.start(queue: socketQueue) // no reply: controlled initialization wait
            } else { connection.cancel() }
        }
        native.start(queue: socketQueue)
    }
    func ready() async throws -> UInt16 {
        try await waitFor("test listener binding") { port != nil || error != nil }
        guard let port else { throw CheckError(error ?? "No bound port") }
        return port
    }
    func stop() async throws {
        for connection in accepted { connection.stateUpdateHandler = nil; connection.cancel() }
        native.cancel()
        try await waitFor("test listener cancellation") { cancelled }
    }
}

@MainActor
private final class StreamFinish {
    let native: NWConnection
    var result: Data?
    var error: String?
    init(port: UInt16) {
        native = NWConnection(host: .ipv4(.loopback), port: .init(rawValue: port)!, using: .tcp)
        native.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            if case .ready = state {
                Self.readUntilEOF(native, data: Data()) { [weak self] data, error in
                    DispatchQueue.main.async { [weak self] in self?.result = data; self?.error = error }
                }
            } else if case .failed(let error) = state {
                DispatchQueue.main.async { self.error = String(describing: error) }
            }
        }
        native.start(queue: socketQueue)
    }
    private nonisolated static func readUntilEOF(_ connection: NWConnection, data: Data, completion: @escaping (Data?, String?) -> Void) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { chunk, _, final, error in
            if let error { completion(nil, String(describing: error)); return }
            var all = data
            if let chunk { all.append(chunk) }
            if final { completion(all, nil) }
            else { readUntilEOF(connection, data: all, completion: completion) }
        }
    }
    func check() async throws {
        defer { native.cancel() }
        try await waitFor("real native payload then TCP FIN") { result != nil || error != nil }
        guard result == Data("native-half-close".utf8) else { throw CheckError(error ?? "Payload or native FIN missing") }
    }
}

@MainActor
private final class SocksGreeting {
    let native: NWConnection
    var response: Data?
    var error: String?
    init(port: UInt16) {
        native = NWConnection(host: .ipv4(.loopback), port: .init(rawValue: port)!, using: .tcp)
        native.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            if case .ready = state {
                native.send(content: Data([5, 1, 0]), completion: .contentProcessed { [weak self] error in
                    guard let self else { return }
                    if let error { DispatchQueue.main.async { self.error = String(describing: error) }; return }
                    native.receive(minimumIncompleteLength: 2, maximumLength: 2) { [weak self] data, _, _, error in
                        DispatchQueue.main.async { [weak self] in
                            if let error { self?.error = String(describing: error) }
                            else { self?.response = data ?? Data() }
                        }
                    }
                })
            } else if case .failed(let error) = state {
                DispatchQueue.main.async { self.error = String(describing: error) }
            }
        }
        native.start(queue: socketQueue)
    }
    func check() async throws {
        defer { native.cancel() }
        try await waitFor("real local SOCKS5 greeting") { response != nil || error != nil }
        guard response == Data([5, 0]) else { throw CheckError(error ?? "Wrong SOCKS5 greeting reply") }
    }
}

@main
private struct NativeSmoke {
    @MainActor static func main() async {
        if CommandLine.arguments.contains("--close-checks") {
            do { try await NativeCloseChecks.run() }
            catch { fputs("Native close checks FAILED: \(error)\n", stderr); exit(1) }
            return
        }
        var instances: [Instance] = []
        var blocker: BoundListener?
        defer {
            for instance in instances { instance.client.stop() }
            blocker?.native.cancel()
        }
        do {
            let waitingServer = try BoundListener(holdConnections: true)
            defer { waitingServer.native.cancel(); for peer in waitingServer.accepted { peer.cancel() } }
            let serverPort = try await waitingServer.ready()
            // Real binding errors, rather than a guessed process/port check.
            let reserved = try BoundListener(); blocker = reserved
            let occupiedPort = try await reserved.ready()
            let collision = try Instance(port: occupiedPort, serverPort: serverPort); instances.append(collision)
            try await waitFor("occupied port reports a fatal error") { collision.exitCode != nil }
            guard collision.exitCode == 1, collision.error != nil, collision.port == nil else {
                throw CheckError("Occupied port was not reported as a failed listener")
            }
            try await reserved.stop(); blocker = nil
            print("PASS: actual occupied-port failure")

            // Exercise the same send helper used by native WRITE/FIN events.
            let closing = try BoundListener(); blocker = closing
            closing.native.newConnectionHandler = { connection in
                DispatchQueue.main.async { closing.accepted.append(connection) }
                connection.stateUpdateHandler = { state in
                    if case .ready = state {
                        NativeClient.sendStream(connection, data: Data("native-half-close".utf8), final: false) { error in
                            if error == nil { NativeClient.sendStream(connection, data: Data(), final: true) { _ in } }
                        }
                    }
                }
                connection.start(queue: socketQueue)
            }
            let closingPort = try await closing.ready()
            try await StreamFinish(port: closingPort).check()
            try await closing.stop(); blocker = nil
            print("PASS: real native write preserves payload and sends FIN")

            let first = try Instance(serverPort: serverPort); instances.append(first); try await first.ready()
            let second = try Instance(serverPort: serverPort); instances.append(second); try await second.ready()
            guard let firstPort = first.port, let secondPort = second.port, firstPort != secondPort else {
                throw CheckError("Native instances did not bind distinct ephemeral ports")
            }
            try await SocksGreeting(port: firstPort).check()
            try await SocksGreeting(port: secondPort).check()
            print("PASS: real local TCP receive/send and SOCKS5 handshake")

            second.client.setLogLevel(.everything)
            second.client.setLogLevel(.errors)
            try await first.stop()
            try await SocksGreeting(port: secondPort).check()
            guard second.exitCode == nil else { throw CheckError("Stopping one instance stopped another") }
            let bindings = second.logs.filter { $0.contains("TCP listener ready on") }.count
            guard bindings == 1 else { throw CheckError("Log level change restarted the native listener") }
            print("PASS: instance isolation and live log-level changes")

            try await second.stop()
            let replacement = try Instance(port: secondPort, serverPort: serverPort); instances.append(replacement)
            try await replacement.ready()
            try await replacement.stop()
            print("PASS: cancellation releases the listener for immediate reuse")

            let initializing = try Instance(serverPort: serverPort); instances.append(initializing)
            try await initializing.stop()
            guard instances.allSatisfy({ !$0.logs.joined(separator: "\n").contains("test-only-secret") }) else {
                throw CheckError("A server password appeared in logs")
            }
            print("PASS: cancellation during initialization and no secret in recorded logs")
            try await waitingServer.stop()
            print("Native lifecycle checks passed. Remote TLS/QUIC interoperability is a separate check.")
        } catch {
            for instance in instances { instance.client.stop() }
            blocker?.native.cancel()
            fputs("Native lifecycle checks FAILED: \(error)\n", stderr)
            exit(1)
        }
    }
}
