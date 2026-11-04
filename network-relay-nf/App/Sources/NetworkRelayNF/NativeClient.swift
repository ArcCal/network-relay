import Foundation
import Network
import Security
import Darwin
import NetworkRelayNFBridge
import NetworkRelayNFModel

enum NativeUpdate {
    case log([String])
    case connected
    case reconnecting(String)
    case traffic(TrafficSnapshot)
    case trafficUnavailable
    case exited(Int32, String?)
}

/// Owns one protocol-core instance and only this instance's native resources.
/// All Network.framework callbacks and FFI inputs run on `queue`. Event polling
/// blocks a separate queue; destruction occurs only after callbacks are invalidated.
final class NativeClient {
    private let queue = DispatchQueue(label: "com.arccal.network-relay-nf.network")
    private let pollQueue = DispatchQueue(label: "com.arccal.network-relay-nf.events")
    private var handle: OpaquePointer?
    private var connections: [UInt64: Connection] = [:]
    private var listeners: [UInt64: Listener] = [:]
    private var closingListeners: [UInt64: NWListener] = [:]
    private var pendingExit: (Int32, String?)?
    private var groups: [UInt64: Group] = [:]
    private var pendingConnections: [ObjectIdentifier: (UInt64, NWConnection)] = [:]
    private var level: LogLevel
    private var logTimer: DispatchSourceTimer?
    private var lastTrafficAt = ProcessInfo.processInfo.systemUptime
    private var trafficUnavailable = false
    private var pendingLogs: [String] = []
    private let runID: String
    private let update: @MainActor (NativeUpdate) -> Void

    private final class TrustResult { var rejected = false }
    private final class Connection {
        let native: NWConnection
        let parent: UInt64
        let trust: TrustResult?
        var reading = false
        var eof = false
        init(_ native: NWConnection, parent: UInt64 = 0, trust: TrustResult? = nil) {
            self.native = native; self.parent = parent; self.trust = trust
        }
    }
    private final class Listener {
        let native: NWListener
        let address: Address
        let udp: Bool
        var peers: [String: NWConnection] = [:]
        init(_ native: NWListener, address: Address, udp: Bool) {
            self.native = native; self.address = address; self.udp = udp
        }
    }
    private final class Group {
        let native: NWConnectionGroup
        let trust: TrustResult
        var datagrams: NWConnection?
        var ready = false
        var reported = false
        init(_ native: NWConnectionGroup, trust: TrustResult) { self.native = native; self.trust = trust }
    }
    private struct Options: Decodable {
        let host: String
        let port: UInt16
        let server_name: String
        let alpn: [String]
    }
    private struct Ready: Encodable {
        var alpn = ""
        var local = ""
        var peer = ""
        var stream_id: UInt64 = 0
        var max_datagram = 0
    }
    private struct Event {
        let kind: UInt32
        let id: UInt64
        let token: UInt64
        let flags: UInt64
        let data: Data
        init(_ value: NfEvent) {
            kind = value.kind; id = value.id; token = value.token; flags = value.flags
            data = value.len == 0 ? Data() : Data(bytes: value.data!, count: value.len)
        }
    }
    /// Core-generated socket strings contain literal addresses, never names.
    private struct Address {
        let host: String
        let port: UInt16
        init?(_ text: String) {
            if text.hasPrefix("["), let close = text.firstIndex(of: "]") {
                let suffix = text[text.index(after: close)...]
                guard suffix.hasPrefix(":"), let port = UInt16(suffix.dropFirst()) else { return nil }
                host = String(text[text.index(after: text.startIndex)..<close]); self.port = port
            } else {
                guard let colon = text.lastIndex(of: ":"), let port = UInt16(text[text.index(after: colon)...]) else { return nil }
                host = String(text[..<colon]); self.port = port
            }
            guard IPv4Address(host) != nil || IPv6Address(host) != nil else { return nil }
        }
        var endpoint: NWEndpoint { .hostPort(host: .init(host), port: .init(rawValue: port)!) }
        static func text(_ endpoint: NWEndpoint?) -> String {
            guard case let .hostPort(host, port) = endpoint else { return "" }
            let name: String
            switch host {
            case .ipv4(let address): name = numeric(address.rawValue, family: AF_INET)
            case .ipv6(let address): name = numeric(address.rawValue, family: AF_INET6)
            case .name(let value, _): name = value
            @unknown default: return ""
            }
            return name.contains(":") ? "[\(name)]:\(port.rawValue)" : "\(name):\(port.rawValue)"
        }
        private static func numeric(_ bytes: Data, family: Int32) -> String {
            var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            let result = bytes.withUnsafeBytes { raw in inet_ntop(family, raw.baseAddress, &output, socklen_t(output.count)) }
            return result == nil ? "" : String(cString: output)
        }
    }

    init(configuration: String, level: LogLevel, id: UUID = UUID(), update: @escaping @MainActor (NativeUpdate) -> Void) throws {
        self.level = level; self.update = update; runID = String(id.uuidString.prefix(8))
        guard let core = configuration.withCString({ nf_start($0, level.nativeValue) }) else {
            throw NativeError("The native protocol core rejected the configuration.")
        }
        handle = core
        queue.async { [self] in
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now() + .milliseconds(100), repeating: .milliseconds(100))
            timer.setEventHandler { [weak self] in
                guard let self else { return }
                flushLogs()
                if handle != nil, !trafficUnavailable,
                   ProcessInfo.processInfo.systemUptime - lastTrafficAt > 3 {
                    trafficUnavailable = true
                    notify(.trafficUnavailable)
                }
            }
            logTimer = timer; timer.resume()
        }
        // This worker keeps the instance alive until the protocol runtime exits.
        pollQueue.async { [self] in
            while let pointer = nf_next_event(core) {
                let event = Event(pointer.pointee)
                nf_free_event(pointer)
                queue.sync { consume(event) }
                if event.kind == 99 { break }
            }
            queue.sync {
                invalidate()
                flushLogs()
            }
            nf_destroy(core)
        }
    }

    func stop() { queue.async { [self] in if let handle { nf_stop(handle) } } }
    func setLogLevel(_ new: LogLevel) {
        queue.async { [self] in
            level = new
            if let handle { nf_log_level(handle, new.nativeValue) }
            log("INFO", "Log level changed to \(new.title)")
        }
    }
    private func notify(_ value: NativeUpdate) { DispatchQueue.main.async { [update] in update(value) } }
    private func log(_ severity: String, _ text: String) {
        if (severity == "DEBUG" && level.nativeValue < 3) || (severity == "TRACE" && level.nativeValue < 4) { return }
        appendLog("\(ISO8601DateFormatter().string(from: Date())) \(severity) native: \(text)")
    }
    private func appendLog(_ text: String) {
        appendClientLog(text.split(whereSeparator: \.isNewline).map { "\($0) [run=\(runID)]" }, to: &pendingLogs)
    }
    private func flushLogs() {
        guard !pendingLogs.isEmpty else { return }
        let lines = pendingLogs; pendingLogs.removeAll(keepingCapacity: true)
        notify(.log(lines))
    }
    @discardableResult
    private func input(_ kind: UInt32, _ id: UInt64, token: UInt64 = 0, flags: UInt64 = 0, data: Data = Data()) -> Bool {
        guard let handle else { return false }
        return data.withUnsafeBytes { bytes in
            nf_input(handle, kind, id, token, flags, bytes.bindMemory(to: UInt8.self).baseAddress, data.count)
        }
    }
    private func ready(_ id: UInt64, _ ready: Ready) {
        guard let data = try? JSONEncoder().encode(ready) else { fail(id, message: "Invalid native connection metadata"); return }
        input(101, id, data: data)
    }
    private func failureFlag(_ error: NWError, trust: TrustResult? = nil) -> UInt64 {
        if trust?.rejected == true { return 1 }
        switch error {
        case .tls: return 1
        case .posix(.EADDRINUSE): return 2
        case .posix(.ETIMEDOUT): return 3
        case .posix(.EMFILE), .posix(.ENFILE): return 5
        default: return 4
        }
    }
    private func fail(_ id: UInt64, error: NWError) {
        let trust = connections[id]?.trust ?? groups[id]?.trust
        let flags = failureFlag(error, trust: trust)
        fail(id, message: flags == 1 ? "TLS certificate or secure handshake validation failed: \(error)" : String(describing: error), flags: flags)
    }
    private func fail(_ id: UInt64, message: String, flags: UInt64 = 4) {
        guard handle != nil else { return }
        input(104, id, flags: flags, data: Data(message.utf8))
        // A QUIC group failure ends every stream; keep it at default levels
        // so the first failing native object is identifiable.
        log(groups[id] == nil ? "DEBUG" : "WARN", "Resource \(id) failed: \(message)")
        close(id)
    }

    private func consume(_ event: Event) {
        guard handle != nil else { return }
        if event.kind < 20 {
            log("TRACE", "Native I/O request kind=\(event.kind) resource=\(event.id) bytes=\(event.data.count)")
        }
        switch event.kind {
        case 1, 2:
            do {
                let options = try JSONDecoder().decode(Options.self, from: event.data)
                if event.kind == 1 { openTCP(event.id, options) } else { openQUIC(event.id, options) }
            } catch { fail(event.id, message: "Invalid native connection options") }
        case 3: openStream(event.id, parent: event.token, unidirectional: event.flags == 1)
        case 4: write(event)
        case 5: read(event.id, maximum: Int(min(event.flags, 65536)))
        case 6: sendDatagram(event)
        case 7: close(event.id, code: event.flags)
        case 8, 9:
            guard let address = Address(String(decoding: event.data, as: UTF8.self)) else {
                fail(event.id, message: "Invalid literal listener address"); return
            }
            listen(event.id, address, udp: event.kind == 9)
        case 10: sendUDP(event)
        case 20: appendLog(String(decoding: event.data, as: UTF8.self))
        case 21:
            flushLogs()
            if event.flags == 1 { notify(.connected) }
            else { notify(.reconnecting(String(decoding: event.data, as: UTF8.self))) }
        case 22:
            guard let sample = TrafficSnapshot(uploadBytes: event.id, downloadBytes: event.token, elapsedData: event.data) else {
                trafficUnavailable = true
                notify(.trafficUnavailable)
                return
            }
            lastTrafficAt = ProcessInfo.processInfo.systemUptime
            trafficUnavailable = false
            notify(.traffic(sample))
        case 99:
            flushLogs()
            let error = event.data.isEmpty ? nil : String(decoding: event.data, as: UTF8.self)
            invalidate()
            pendingExit = (Int32(event.flags), error)
            reportExitAfterListenerCancellation()
        default: break
        }
    }

    private func configureTLS(_ options: sec_protocol_options_t, name: String, trustResult: TrustResult) {
        sec_protocol_options_set_min_tls_protocol_version(options, .TLSv13)
        name.withCString { sec_protocol_options_set_tls_server_name(options, $0) }
        // Apple performs the handshake and trust evaluation. Certificate-chain
        // downloads and online revocation checks must not make hidden direct I/O.
        sec_protocol_options_set_verify_block(options, { _, trust, complete in
            let value = sec_trust_copy_ref(trust).takeRetainedValue()
            var policies = [SecPolicyCreateSSL(true, name as CFString)]
            if let revocation = SecPolicyCreateRevocation(kSecRevocationUseAnyAvailableMethod | kSecRevocationNetworkAccessDisabled) {
                policies.append(revocation)
            }
            let policiesOK = SecTrustSetPolicies(value, policies as CFArray) == errSecSuccess
            let fetchOK = SecTrustSetNetworkFetchAllowed(value, false) == errSecSuccess
            var error: CFError?
            let valid = policiesOK && fetchOK && SecTrustEvaluateWithError(value, &error)
            trustResult.rejected = !valid
            complete(valid)
        }, queue)
    }
    private func openTCP(_ id: UInt64, _ options: Options) {
        log("DEBUG", "Native TLS opening resource=\(id) host=\(options.host) port=\(options.port) certificateName=\(options.server_name) ALPN=\(options.alpn.joined(separator: ","))")
        let tls = NWProtocolTLS.Options()
        let trust = TrustResult()
        configureTLS(tls.securityProtocolOptions, name: options.server_name, trustResult: trust)
        for alpn in options.alpn { alpn.withCString { sec_protocol_options_add_tls_application_protocol(tls.securityProtocolOptions, $0) } }
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true; tcp.connectionTimeout = 10; tcp.connectionDropTime = 30
        tcp.enableKeepalive = true; tcp.keepaliveIdle = 60; tcp.keepaliveInterval = 10; tcp.keepaliveCount = 3
        let parameters = NWParameters(tls: tls, tcp: tcp)
        parameters.preferNoProxies = true
        let connection = NWConnection(host: .init(options.host), port: .init(rawValue: options.port)!, using: parameters)
        connections[id] = Connection(connection, trust: trust)
        start(connection, id: id) { [weak self] in
            guard let self else { return }
            var metadata = readyMetadata(connection)
            if let tls = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata,
               let protocolName = sec_protocol_metadata_copy_negotiated_protocol(tls.securityProtocolMetadata) {
                defer { free(UnsafeMutableRawPointer(mutating: protocolName)) }
                metadata.alpn = String(cString: protocolName)
            }
            ready(id, metadata)
            log("DEBUG", "Native TLS connection ready, ALPN \(metadata.alpn)")
        }
    }
    private func start(_ connection: NWConnection, id: UInt64, onReady: @escaping () -> Void) {
        connection.stateUpdateHandler = { [weak self, weak connection] state in
            guard let self, let connection, connections[id]?.native === connection, handle != nil else { return }
            switch state {
            case .ready: onReady()
            case .failed(let error): fail(id, error: error)
            case .cancelled: fail(id, message: "Native connection was cancelled")
            case .waiting(let error): log("DEBUG", "Native connection waiting: \(error)")
            default: break
            }
        }
        connection.start(queue: queue)
    }
    private func readyMetadata(_ connection: NWConnection) -> Ready {
        var metadata = Ready(local: Address.text(connection.currentPath?.localEndpoint), peer: Address.text(connection.endpoint))
        if let quic = connection.metadata(definition: NWProtocolQUIC.definition) as? NWProtocolQUIC.Metadata {
            metadata.stream_id = quic.streamIdentifier
            metadata.alpn = quic.negotiatedALPN ?? ""
        }
        return metadata
    }

    private func openQUIC(_ id: UInt64, _ options: Options) {
        log("DEBUG", "Native QUIC opening resource=\(id) host=\(options.host) port=\(options.port) certificateName=\(options.server_name) ALPN=\(options.alpn.joined(separator: ","))")
        let quic = NWProtocolQUIC.Options(alpn: options.alpn)
        let trust = TrustResult()
        configureTLS(quic.securityProtocolOptions, name: options.server_name, trustResult: trust)
        // A relay that crashes or restarts sends no CONNECTION_CLOSE and its new
        // process cannot reset this connection, so only the idle timeout ends
        // it; until then new flows are sent on it and fail. With the 10-second
        // keep-alive below, a dead connection ends within 40 seconds, as in RS.
        quic.idleTimeout = 30_000 // Network.framework uses milliseconds: 30 seconds.
        quic.initialMaxData = 5 << 20
        quic.initialMaxStreamDataBidirectionalLocal = 2 << 20
        quic.initialMaxStreamDataBidirectionalRemote = 2 << 20
        quic.initialMaxStreamDataUnidirectional = 64 << 10
        quic.initialMaxStreamsUnidirectional = 100
        quic.initialMaxStreamsBidirectional = 100
        quic.maxDatagramFrameSize = 0
        quic.maxUDPPayloadSize = 1472
        let parameters = NWParameters(quic: quic)
        parameters.preferNoProxies = true
        let endpoint = NWEndpoint.hostPort(host: .init(options.host), port: .init(rawValue: options.port)!)
        let native = NWConnectionGroup(with: NWMultiplexGroup(to: endpoint), using: parameters)
        let group = Group(native, trust: trust); groups[id] = group
        native.newConnectionHandler = { [weak self, weak group] connection in
            guard let self, let group, groups[id] === group, handle != nil else { connection.cancel(); return }
            acceptStream(connection, parent: id)
        }
        native.stateUpdateHandler = { [weak self, weak group] state in
            guard let self, let group, groups[id] === group, handle != nil else { return }
            switch state {
            case .ready: prepareDatagrams(id, group)
            case .failed(let error): fail(id, error: error)
            case .cancelled: fail(id, message: "Native QUIC group was cancelled")
            case .waiting(let error): log("DEBUG", "Native QUIC waiting: \(error)")
            default: break
            }
        }
        native.start(queue: queue)
    }
    private func prepareDatagrams(_ id: UInt64, _ group: Group) {
        guard !group.ready else { return }
        group.ready = true
        guard let negotiated = group.native.metadata(definition: NWProtocolQUIC.definition) as? NWProtocolQUIC.Metadata,
              negotiated.negotiatedALPN == "h3" else {
            fail(id, message: "Native QUIC did not negotiate h3"); return
        }
        // The group object owns a bidirectional stream without exposing I/O
        // on it; record its identifier to correlate with peer stream events.
        log("DEBUG", "Native QUIC group ready resource=\(id) groupSID=\(negotiated.streamIdentifier)")
        // CONNECT-UDP permits DATAGRAM Capsules without QUIC DATAGRAMs.
        // Do not extract a datagram connection before the first request:
        // that path is implicated in Masque NF's unresolved native H3 issue.
        group.reported = true
        ready(id, Ready(alpn: "h3"))
        log("DEBUG", "Native QUIC ready; HTTP/3 UDP uses DATAGRAM Capsules")
    }
    private func openStream(_ id: UInt64, parent: UInt64, unidirectional: Bool) {
        guard let group = groups[parent] else { fail(id, message: "Native QUIC group is closed"); return }
        let options = NWProtocolQUIC.Options()
        options.direction = unidirectional ? .unidirectional : .bidirectional
        guard let connection = group.native.extract(connectionTo: nil, using: options) else {
            fail(id, message: "Network.framework could not open the QUIC stream"); return
        }
        connections[id] = Connection(connection, parent: parent)
        start(connection, id: id) { [weak self] in
            guard let self else { return }
            guard let metadata = connection.metadata(definition: NWProtocolQUIC.definition) as? NWProtocolQUIC.Metadata else {
                fail(id, message: "Native QUIC stream metadata unavailable"); return
            }
            metadata.keepAlive = .seconds(10)
            log("DEBUG", "Native QUIC stream resource=\(id) parent=\(parent) SID=\(metadata.streamIdentifier) requestedDirection=\(unidirectional ? "uni" : "bidi")")
            ready(id, readyMetadata(connection))
        }
    }
    private func acceptStream(_ connection: NWConnection, parent: UInt64) {
        guard retainPending(connection, parent: parent) else { return }
        connection.stateUpdateHandler = { [weak self, weak connection] state in
            guard let self, let connection, pendingConnections[ObjectIdentifier(connection)] != nil else { return }
            guard groups[parent] != nil, let handle else { removePending(connection); connection.cancel(); return }
            if case .ready = state {
                let metadata = readyMetadata(connection)
                guard metadata.stream_id < (UInt64(1) << 62), let data = try? JSONEncoder().encode(metadata) else { removePending(connection); connection.cancel(); return }
                let id = data.withUnsafeBytes { bytes in
                    nf_accept(handle, parent, metadata.stream_id, bytes.bindMemory(to: UInt8.self).baseAddress, data.count)
                }
                guard id != 0 else { removePending(connection); connection.cancel(); return }
                connections[id] = Connection(connection, parent: parent)
                log("DEBUG", "Native QUIC inbound stream resource=\(id) parent=\(parent) SID=\(metadata.stream_id)")
                removePending(connection)
                // It is already started; replace the handler without restarting.
                connection.stateUpdateHandler = { [weak self, weak connection] state in
                    guard let self, let connection, connections[id]?.native === connection else { return }
                    if case .failed(let error) = state { fail(id, error: error) }
                }
            } else if case .failed = state { removePending(connection); connection.cancel() }
        }
        connection.start(queue: queue)
    }
    private func receiveDatagrams(_ id: UInt64, _ group: Group, _ connection: NWConnection) {
        connection.receiveMessage { [weak self, weak group, weak connection] data, _, _, error in
            guard let self, let group, let connection, groups[id] === group, group.datagrams === connection, handle != nil else { return }
            if let error { fail(id, error: error); return }
            if let data { _ = input(105, id, data: data) } // bounded unreliable datagram queue
            receiveDatagrams(id, group, connection)
        }
    }
    private func sendDatagram(_ event: Event) {
        guard let group = groups[event.id], let connection = group.datagrams else {
            fail(event.id, message: "Native QUIC DATAGRAM channel is unavailable"); return
        }
        if let metadata = connection.metadata(definition: NWProtocolQUIC.definition) as? NWProtocolQUIC.Metadata,
           event.data.count > metadata.usableDatagramFrameSize {
            fail(event.id, message: "Native QUIC path can no longer carry this CONNECT / CONNECT-UDP datagram; reconnect required")
            return
        }
        connection.send(content: event.data, completion: .contentProcessed { [weak self, weak group] error in
            guard let self, let group, groups[event.id] === group else { return }
            if let error { fail(event.id, error: error) }
        })
    }

    private func write(_ event: Event) {
        guard let entry = connections[event.id] else {
            input(103, event.id, token: event.token, flags: 4, data: Data("Native stream is closed".utf8)); return
        }
        Self.sendStream(entry.native, data: event.data, final: event.flags == 1) { [weak self, weak entry] error in
            guard let self, let entry, connections[event.id] === entry else { return }
            if let error { fail(event.id, error: error) }
            else { input(103, event.id, token: event.token) }
        }
    }
    // isComplete terminates a message; finalMessage terminates a TCP/QUIC
    // stream. A normal completed send must never be mistaken for FIN.
    static func sendStream(_ connection: NWConnection, data: Data, final: Bool, completion: @escaping (NWError?) -> Void) {
        connection.send(content: data.isEmpty ? nil : data,
                        contentContext: final ? .finalMessage : .defaultMessage, isComplete: true,
                        completion: .contentProcessed(completion))
    }
    private func read(_ id: UInt64, maximum: Int) {
        guard let entry = connections[id] else { fail(id, message: "Native stream is closed"); return }
        guard !entry.reading else { fail(id, message: "Duplicate native stream read"); return }
        if entry.eof { input(102, id, flags: 1); return }
        entry.reading = true
        entry.native.receive(minimumIncompleteLength: 1, maximumLength: max(1, maximum)) { [weak self, weak entry] data, _, complete, error in
            guard let self, let entry, connections[id] === entry, let handle else { return }
            entry.reading = false
            if let error, failureFlag(error, trust: entry.trust) == 1 {
                fail(id, error: error); return
            }
            // Network.framework may return content and an error together.
            // Deliver that content first; Rust drains it before the error.
            if let data, !data.isEmpty {
                log("TRACE", "Native stream \(id) received \(data.count) bytes; final=\(complete)")
                let result = data.withUnsafeBytes { bytes in
                    nf_input_data(handle, id, bytes.bindMemory(to: UInt8.self).baseAddress, data.count)
                }
                switch result {
                case UInt32(NF_DATA_ACCEPTED.rawValue): break
                case UInt32(NF_DATA_CLOSED.rawValue):
                    // Rust removed the resource before its queued CLOSE reached
                    // this native queue. The original terminal result wins.
                    return
                case UInt32(NF_DATA_FULL.rawValue):
                    fail(id, message: "Native stream receive queue overflow"); return
                default:
                    fail(id, message: "Native stream receive data rejected"); return
                }
            }
            if let error { fail(id, error: error); return }
            entry.eof = complete
            if let data, !data.isEmpty { return }
            if complete { input(102, id, flags: 1) }
            else { read(id, maximum: maximum) }
        }
    }

    private func listen(_ id: UInt64, _ address: Address, udp: Bool) {
        do {
            let parameters: NWParameters
            if udp { parameters = NWParameters(dtls: nil, udp: NWProtocolUDP.Options()) }
            else {
                let tcp = NWProtocolTCP.Options(); tcp.noDelay = true
                parameters = NWParameters(tls: nil, tcp: tcp)
            }
            parameters.requiredLocalEndpoint = address.endpoint
            let native = try NWListener(using: parameters)
            let listener = Listener(native, address: address, udp: udp); listeners[id] = listener
            native.stateUpdateHandler = { [weak self, weak listener] state in
                guard let self, let listener, listeners[id] === listener, handle != nil else { return }
                switch state {
                case .ready:
                    guard let port = native.port else { fail(id, message: "Native listener has no port"); return }
                    let text = address.host.contains(":") ? "[\(address.host)]:\(port.rawValue)" : "\(address.host):\(port.rawValue)"
                    ready(id, Ready(local: text))
                    log("INFO", "SOCKS \(udp ? "UDP relay" : "TCP listener") ready on \(text)")
                case .failed(let error): fail(id, error: error)
                default: break
                }
            }
            native.newConnectionHandler = { [weak self, weak listener] connection in
                guard let self, let listener, listeners[id] === listener, handle != nil else { connection.cancel(); return }
                if udp { acceptUDP(connection, id: id, listener: listener) }
                else { acceptTCP(connection, parent: id) }
            }
            native.start(queue: queue)
        } catch let error as NWError { fail(id, error: error) }
        catch { fail(id, message: error.localizedDescription) }
    }
    private func acceptTCP(_ connection: NWConnection, parent: UInt64) {
        guard retainPending(connection, parent: parent) else { return }
        connection.stateUpdateHandler = { [weak self, weak connection] state in
            guard let self, let connection, pendingConnections[ObjectIdentifier(connection)] != nil else { return }
            guard listeners[parent] != nil, let handle else { removePending(connection); connection.cancel(); return }
            if case .ready = state {
                let metadata = readyMetadata(connection)
                guard !metadata.local.isEmpty, !metadata.peer.isEmpty, let data = try? JSONEncoder().encode(metadata) else { removePending(connection); connection.cancel(); return }
                let id = data.withUnsafeBytes { bytes in
                    nf_accept(handle, parent, 0, bytes.bindMemory(to: UInt8.self).baseAddress, data.count)
                }
                guard id != 0 else { removePending(connection); connection.cancel(); return }
                connections[id] = Connection(connection, parent: parent)
                removePending(connection)
                connection.stateUpdateHandler = { [weak self, weak connection] state in
                    guard let self, let connection, connections[id]?.native === connection else { return }
                    if case .failed(let error) = state { fail(id, error: error) }
                }
            } else if case .failed = state { removePending(connection); connection.cancel() }
        }
        connection.start(queue: queue)
    }
    private func acceptUDP(_ connection: NWConnection, id: UInt64, listener: Listener) {
        let peer = Address.text(connection.endpoint)
        guard !peer.isEmpty, listener.peers.count < 8, listener.peers[peer] == nil else { connection.cancel(); return }
        listener.peers[peer] = connection
        connection.stateUpdateHandler = { [weak self, weak listener, weak connection] state in
            guard let self, let listener, let connection, listeners[id] === listener, listener.peers[peer] === connection else { return }
            switch state {
            case .ready: receiveUDP(connection, id: id, listener: listener, peer: peer)
            case .failed, .cancelled: listener.peers.removeValue(forKey: peer)
            default: break
            }
        }
        connection.start(queue: queue)
    }
    private func receiveUDP(_ connection: NWConnection, id: UInt64, listener: Listener, peer: String) {
        connection.receiveMessage { [weak self, weak listener, weak connection] data, _, _, error in
            guard let self, let listener, let connection, listeners[id] === listener, listener.peers[peer] === connection, handle != nil else { return }
            if let error { log("DEBUG", "SOCKS UDP receive failed: \(error)"); listener.peers.removeValue(forKey: peer); connection.cancel(); return }
            if let data, data.count <= 65536 {
                let address = Data(peer.utf8)
                var packet = Data([UInt8(address.count >> 8), UInt8(address.count & 255)])
                packet.append(address); packet.append(data)
                _ = input(106, id, data: packet)
            }
            receiveUDP(connection, id: id, listener: listener, peer: peer)
        }
    }
    private func sendUDP(_ event: Event) {
        guard event.data.count >= 2, let listener = listeners[event.id], listener.udp else { return }
        let count = (Int(event.data[0]) << 8) | Int(event.data[1])
        guard count > 0, event.data.count >= count + 2 else { return }
        let peer = String(decoding: event.data[2..<(count + 2)], as: UTF8.self)
        // Responses only go back to a peer that sent to this relay. No target
        // connection can be created here; target traffic goes through CONNECT / CONNECT-UDP.
        guard let connection = listener.peers[peer] else { return }
        connection.send(content: Data(event.data[(count + 2)...]), completion: .contentProcessed { [weak self] error in
            if let error { self?.log("DEBUG", "SOCKS UDP response send failed: \(error)") }
        })
    }

    private func close(_ id: UInt64, code: UInt64 = 0) {
        for (key, pending) in pendingConnections.filter({ $0.value.0 == id }) {
            pendingConnections.removeValue(forKey: key)
            pending.1.stateUpdateHandler = nil; pending.1.cancel()
        }
        if let group = groups.removeValue(forKey: id) {
            group.native.stateUpdateHandler = nil; group.native.newConnectionHandler = nil
            if code != 0, let metadata = group.native.metadata(definition: NWProtocolQUIC.definition) as? NWProtocolQUIC.Metadata {
                // macOS 27 can dereference a nil reason while setting this
                // metadata. An empty reason preserves the protocol error code.
                metadata.applicationError = .init(code: code, reason: "")
            }
            group.datagrams?.stateUpdateHandler = nil; group.datagrams?.cancel(); group.native.cancel()
        }
        if let listener = listeners.removeValue(forKey: id) {
            let native = listener.native
            closingListeners[id] = native
            native.newConnectionHandler = nil
            native.stateUpdateHandler = { [weak self, weak native] state in
                guard let self, let native, closingListeners[id] === native else { return }
                if case .cancelled = state {
                    native.stateUpdateHandler = nil
                    closingListeners.removeValue(forKey: id)
                    reportExitAfterListenerCancellation()
                }
            }
            for peer in listener.peers.values { peer.stateUpdateHandler = nil; peer.cancel() }
            native.cancel()
        }
        let children = connections.compactMap { $0.value.parent == id ? $0.key : nil }
        for child in children { close(child, code: code) }
        if let connection = connections.removeValue(forKey: id) {
            connection.native.stateUpdateHandler = nil
            if code != 0, let metadata = connection.native.metadata(definition: NWProtocolQUIC.definition) as? NWProtocolQUIC.Metadata {
                metadata.streamApplicationErrorCode = code
                connection.native.cancel()
            } else if code != 0 {
                // The core aborts a TCP connection (such as a SOCKS client's
                // whose tunnel failed): disconnect at once, without the FIN
                // that would make cut-off data look complete.
                connection.native.forceCancel()
            } else {
                connection.native.cancel()
            }
        }
    }
    private func invalidate() {
        handle = nil
        logTimer?.cancel(); logTimer = nil
        for id in Array(groups.keys) { close(id) }
        for id in Array(listeners.keys) { close(id) }
        for id in Array(connections.keys) { close(id) }
        for pending in pendingConnections.values { pending.1.stateUpdateHandler = nil; pending.1.cancel() }
        pendingConnections.removeAll()
    }

    // Save-triggered reconnect must not race a still-bound old listener.
    // These callbacks carry no FFI handle and may complete after core destruction.
    private func reportExitAfterListenerCancellation() {
        guard closingListeners.isEmpty, let (code, error) = pendingExit else { return }
        pendingExit = nil
        notify(.exited(code, error))
    }

    private func retainPending(_ connection: NWConnection, parent: UInt64) -> Bool {
        guard pendingConnections.count < 512 else { connection.cancel(); return false }
        let key = ObjectIdentifier(connection)
        pendingConnections[key] = (parent, connection)
        queue.asyncAfter(deadline: .now() + 10) { [weak self, weak connection] in
            guard let self, let connection, pendingConnections[key] != nil else { return }
            pendingConnections.removeValue(forKey: key); connection.stateUpdateHandler = nil; connection.cancel()
        }
        return true
    }
    private func removePending(_ connection: NWConnection) { pendingConnections.removeValue(forKey: ObjectIdentifier(connection)) }
}

private struct NativeError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}
