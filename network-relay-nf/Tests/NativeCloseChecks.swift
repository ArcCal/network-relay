// Optional real Network.framework close checks. These use only loopback and
// production sendStream; they do not reproduce the complete SOCKS relay.
import Foundation
import Network

@MainActor
enum NativeCloseChecks {
    private static let queue = DispatchQueue(label: "com.arccal.network-relay-nf.close-checks")
    private struct Failure: Error, CustomStringConvertible { let description: String }

    @MainActor private final class End {
        let native: NWConnection
        var ready = false
        var cancelled = false
        var received = Data()
        var eof = false
        var payloadSent = false
        var finCompleted = false
        var errors: [String] = []
        init(_ native: NWConnection) { self.native = native }
    }

    @MainActor private final class Pair {
        let listener: NWListener
        var port: UInt16?
        var listenerError: String?
        var listenerCancelled = false
        var client: End?
        var server: End?

        init() throws {
            let parameters = NWParameters(tls: nil, tcp: NWProtocolTCP.Options())
            parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
            listener = try NWListener(using: parameters)
            listener.stateUpdateHandler = { [weak self] state in
                DispatchQueue.main.async { [weak self] in
                    guard let self else { return }
                    switch state {
                    case .ready: port = listener.port?.rawValue
                    case .failed(let why): listenerError = String(describing: why)
                    case .cancelled: listenerCancelled = true
                    default: break
                    }
                }
            }
            listener.newConnectionHandler = { [weak self] native in
                DispatchQueue.main.async { [weak self] in
                    guard let self, server == nil else { native.cancel(); return }
                    let end = End(native); server = end
                    Self.start(end)
                }
            }
            listener.start(queue: queue)
        }
        func connect() async throws {
            try await wait("loopback listener ready") { port != nil || listenerError != nil }
            guard let port else { throw Failure(description: listenerError ?? "No loopback port") }
            let end = End(NWConnection(host: .ipv4(.loopback), port: .init(rawValue: port)!, using: .tcp))
            client = end; Self.start(end)
            try await wait("both loopback connections ready") { client?.ready == true && server?.ready == true }
            Self.read(client!); Self.read(server!)
        }
        private static func start(_ end: End) {
            end.native.stateUpdateHandler = { [weak end] state in
                DispatchQueue.main.async { [weak end] in
                    guard let end else { return }
                    switch state {
                    case .ready: end.ready = true
                    case .failed(let error): end.errors.append("state: \(error)")
                    case .cancelled: end.cancelled = true
                    default: break
                    }
                }
            }
            end.native.start(queue: queue)
        }
        private static func read(_ end: End) {
            end.native.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak end] data, _, complete, error in
                DispatchQueue.main.async { [weak end] in
                    guard let end else { return }
                    if let data { end.received.append(data) }
                    end.eof = complete
                    if let error { end.errors.append("receive: \(error)") }
                    if !complete && error == nil { read(end) }
                }
            }
        }
        static func sendAndFinish(_ end: End, payload: Data) {
            NativeClient.sendStream(end.native, data: payload, final: false) { [weak end] error in
                DispatchQueue.main.async { [weak end] in
                    guard let end else { return }
                    if let error { end.errors.append("payload send: \(error)"); return }
                    end.payloadSent = true
                    NativeClient.sendStream(end.native, data: Data(), final: true) { [weak end] error in
                        DispatchQueue.main.async { [weak end] in
                            guard let end else { return }
                            end.finCompleted = true
                            if let error { end.errors.append("FIN completion: \(error)") }
                        }
                    }
                }
            }
        }
        func stop() {
            client?.native.cancel(); server?.native.cancel(); listener.cancel()
        }
        func stopAndWait() async throws {
            stop()
            try await wait("all loopback resources cancelled") {
                listenerCancelled && client?.cancelled == true && server?.cancelled == true
            }
        }
    }

    private static func wait(_ description: String, _ condition: () -> Bool) async throws {
        let deadline = ProcessInfo.processInfo.systemUptime + 8
        while !condition() {
            if ProcessInfo.processInfo.systemUptime > deadline { throw Failure(description: "Timed out: \(description)") }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
    }

    static func run() async throws {
        for order in ["client-first", "server-first", "simultaneous"] {
            let pair = try Pair()
            defer { pair.stop() }
            try await pair.connect()
            let client = pair.client!, server = pair.server!
            let clientPayload = Data((0..<100_013).map { UInt8($0 % 251) })
            let serverPayload = Data((0..<131_119).map { UInt8(($0 + 37) % 251) })
            do {
                if order == "client-first" {
                    Pair.sendAndFinish(client, payload: clientPayload)
                    try await wait("client FIN received before delayed response") { server.eof && client.finCompleted }
                    try await Task.sleep(nanoseconds: 30_000_000)
                    Pair.sendAndFinish(server, payload: serverPayload)
                } else if order == "server-first" {
                    Pair.sendAndFinish(server, payload: serverPayload)
                    try await wait("server FIN received before continuing client send") { client.eof && server.finCompleted }
                    Pair.sendAndFinish(client, payload: clientPayload)
                } else {
                    Pair.sendAndFinish(client, payload: clientPayload)
                    Pair.sendAndFinish(server, payload: serverPayload)
                }
                try await wait("\(order) full payloads, both EOFs and FIN completions") {
                    client.eof && server.eof && client.finCompleted && server.finCompleted
                }
            } catch {
                throw Failure(description: "\(order): \(error); client received=\(client.received.count), EOF=\(client.eof), FIN completed=\(client.finCompleted); server received=\(server.received.count), EOF=\(server.eof), FIN completed=\(server.finCompleted); errors=\(client.errors + server.errors)")
            }
            guard client.payloadSent, server.payloadSent,
                  client.received == serverPayload, server.received == clientPayload else {
                throw Failure(description: "\(order): bidirectional payload mismatch; errors=\(client.errors + server.errors)")
            }
            // Keep errors visible even if both complete buffers and EOFs were
            // observed. This does not classify real SOCKS errors as harmless.
            for error in client.errors { print("OBSERVATION: \(order), client: \(error)") }
            for error in server.errors { print("OBSERVATION: \(order), server: \(error)") }
            print("PASS: \(order), complete payloads 100013/131119 bytes, both EOFs and FIN callbacks")
            try await pair.stopAndWait()
        }
        print("Native loopback close checks passed. Full SOCKS relay and real server behavior are separate checks.")
    }
}
