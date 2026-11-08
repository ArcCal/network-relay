import AppKit
import Foundation
import NetworkRelayNFModel

/// Native, in-process SOCKS client. It never manages another application's
/// processes, helper, routing, DNS configuration, firewall or settings.
@MainActor
final class TunnelController: ObservableObject {
    static let shared = TunnelController()
    @Published private(set) var status: Status = .stopped
    @Published private(set) var configuration: Configuration
    @Published private(set) var log: [String] = []
    @Published private(set) var traffic = LiveTraffic()
    @Published private(set) var trafficNodeName: String?
    private var trafficServerID: UUID?
    private var client: NativeClient?
    private var generation = UUID()
    private var stopping = false
    private var restartAfterExit = false
    private var quitting = false
    private var eraseOnQuit = false
    private var networkChanges: NetworkChanges?
    private var retryTask: Task<Void, Never>?
    private var retryAt: TimeInterval?
    private var retryReason: String?
    private var retryDelay: TimeInterval = 1
    private var connectedSince: TimeInterval?

    private init() { configuration = Store.load() }
    var settings: Settings { configuration.settings }
    var isConfigured: Bool { (try? clientConfiguration(settings, password: configuration.password)) != nil }
    func launched() {
        if networkChanges == nil {
            networkChanges = NetworkChanges { [weak self] in self?.networkChanged() }
        }
        let information = AppInformation()
        let built = information.builtAt.map { ISO8601DateFormatter().string(from: $0) } ?? "Unknown"
        appendLog(["\(timestamp()) INFO app: Network Relay NF launched; Network.framework transport; app \(information.version); core \(information.coreVersion); built \(built); source \(information.sourceRevision)"])
        if configuration.connectOnLaunch {
            if isConfigured { connect() }
            else { appendLog(["\(timestamp()) WARN app: Launch connection skipped: complete the selected server settings first."]) }
        }
    }
    @discardableResult
    func save(_ new: Configuration, retryFailed: Bool = false, allowReconnect: Bool = true) throws -> Bool {
        try new.check()
        try Store.save(new)
        let reconnecting = adopt(new, retryFailed: retryFailed, allowReconnect: allowReconnect)
        appendLog(["\(timestamp()) INFO app: Settings saved\(reconnecting ? "; reconnecting with the changed parameters; existing proxy sessions will end" : "")"])
        return reconnecting
    }
    func use(_ id: UUID) {
        var new = configuration; new.selectedServerID = id
        guard new.selectedServer?.id != configuration.selectedServer?.id else { return }
        guard saveChoice(new) else { return }
        let reconnecting = adopt(new, retryFailed: true)
        appendLog(["\(timestamp()) INFO app: Server selected: \(new.selectedServer?.title ?? "none")\(reconnecting ? "; reconnecting; existing proxy sessions will end" : "")"])
    }
    func setLogLevel(_ level: LogLevel) {
        guard level != configuration.logLevel else { return }
        var new = configuration; new.logLevel = level
        guard saveChoice(new) else { return }
        adopt(new)
    }
    @discardableResult
    private func saveChoice(_ new: Configuration) -> Bool {
        do { try Store.save(new); return true }
        catch {
            appendLog(["\(timestamp()) ERROR app: Settings could not be saved: \(error.localizedDescription)"])
            return false
        }
    }
    @discardableResult
    private func adopt(_ new: Configuration, retryFailed: Bool = false, allowReconnect: Bool = true) -> Bool {
        let change = clientChange(from: configuration, to: new)
        let selectedChanged = configuration.selectedServer?.id != new.selectedServer?.id
        let levelChanged = configuration.logLevel != new.logLevel
        configuration = new
        if let id = trafficServerID, let server = new.servers.first(where: { $0.id == id }) {
            trafficNodeName = server.title
        }
        if levelChanged { client?.setLogLevel(new.logLevel) }
        guard !quitting else { return false }
        if !allowReconnect {
            cancelRetry()
            restartAfterExit = false
            stopClient()
            return false
        }
        if client == nil {
            if restartAfterExit {
                if change == .disconnect { disconnect(); return false }
                if change == .reconnect || selectedChanged {
                    cancelRetry(); restartAfterExit = false; connect()
                    return true
                }
            }
            if retryFailed, case .failed = status, change != .disconnect, change == .reconnect || selectedChanged {
                connect()
                return true
            }
            return false
        }
        // A choice made while an explicit Disconnect is finishing must
        // not request another connection. Pending automatic restarts may update it.
        guard !stopping || restartAfterExit else { return false }
        switch change {
        case .none: return false
        case .reconnect:
            cancelRetry()
            restartAfterExit = true
            stopClient()
            return true
        case .disconnect:
            cancelRetry()
            restartAfterExit = false
            stopClient()
            return false
        }
    }
    func toggle() { if client != nil || restartAfterExit { disconnect() } else { connect() } }
    func connect(resetRetry: Bool = true) {
        guard client == nil, !quitting else { return }
        cancelRetry(); restartAfterExit = false
        if resetRetry { retryDelay = 1 }
        connectedSince = nil
        clearTraffic()
        do {
            let input = try clientConfiguration(settings, password: configuration.password)
            let run = UUID(); generation = run
            status = .connecting; stopping = false
            trafficServerID = configuration.selectedServer?.id
            trafficNodeName = configuration.selectedServer?.title
            let server = configuration.selectedServer.map { $0.name.isEmpty ? $0.domain : $0.name } ?? ""
            appendLog(["\(timestamp()) INFO app: Connecting to \(server); SOCKS5 \(settings.proxyAddress); \(settings.transport.title) [run=\(run.uuidString.prefix(8))]"])
            client = try NativeClient(configuration: input, level: configuration.logLevel, id: run) { [weak self] update in
                guard let self, generation == run else { return }
                received(update)
            }
        } catch {
            clearTraffic()
            status = .failed(error.localizedDescription)
            appendLog(["\(timestamp()) ERROR app: \(error.localizedDescription)"])
        }
    }
    func disconnect() {
        cancelRetry()
        appendLog(["\(timestamp()) INFO app: Disconnect requested"])
        // An explicit Disconnect always cancels an earlier Save-triggered restart.
        restartAfterExit = false
        stopClient()
    }
    private func stopClient() {
        clearTraffic()
        guard let client else { status = .stopped; return }
        stopping = true
        client.stop()
    }
    /// AppKit waits asynchronously for this instance to release its sockets.
    func requestQuit() -> NSApplication.TerminateReply {
        cancelRetry()
        clearTraffic()
        appendLog(["\(timestamp()) INFO app: Quit requested"])
        restartAfterExit = false; quitting = true
        guard client != nil else {
            if eraseOnQuit { Store.eraseEverything() }
            return .terminateNow
        }
        stopClient()
        return .terminateLater
    }
    func stopForQuit() { cancelRetry(); clearTraffic(); restartAfterExit = false; quitting = true; client?.stop() }
    func eraseEverythingAndQuit() { eraseOnQuit = true; NSApp.terminate(nil) }

    private func received(_ update: NativeUpdate) {
        switch update {
        case .log(let lines): appendLog(lines)
        case .connected:
            if !stopping {
                cancelRetry(); restartAfterExit = false
                connectedSince = ProcessInfo.processInfo.systemUptime; status = .connected
            }
        case .reconnecting(let why):
            if !stopping {
                // A gateway/quota response proves the peer still answered.
                // Preserve admitted flows while the core retries that request.
                status = .reconnecting(why)
                if why.contains("relay refused the request with HTTP ") {
                    cancelRetry(); restartAfterExit = false
                } else if retryAt == nil {
                    // Give a probe-only stream reset time to recover without
                    // interrupting healthy SOCKS flows. Never wait indefinitely.
                    retryReason = why
                    retryAt = ProcessInfo.processInfo.systemUptime + 2
                    restartAfterExit = true
                    scheduleRetry()
                }
            }
        case .traffic(let sample):
            if !stopping, !quitting, trafficNodeName != nil { traffic.sample(sample) }
        case .trafficUnavailable:
            if !stopping, !quitting, trafficNodeName != nil { traffic.unavailable() }
        case .exited(let code, let error):
            // A terminal core exit during the probe grace period must remain
            // terminal, including authentication and certificate rejection.
            if !stopping { cancelRetry(); restartAfterExit = false }
            clearTraffic()
            client = nil
            generation = UUID()
            if stopping || code == 0 {
                status = .stopped
                appendLog(["\(timestamp()) INFO app: Disconnected"])
            } else {
                let message = error ?? "The native protocol core stopped (\(code))."
                status = .failed(message)
                appendLog(["\(timestamp()) ERROR app: \(message)"])
            }
            stopping = false
            if quitting {
                if eraseOnQuit { Store.eraseEverything() }
                NSApp.reply(toApplicationShouldTerminate: true)
            } else if restartAfterExit {
                if retryAt != nil {
                    status = .reconnecting(retryReason ?? "Opening a fresh relay connection")
                    scheduleRetry()
                } else {
                    restartAfterExit = false; connect()
                }
            }
        }
    }
    func networkChanged() {
        guard !quitting, status.isActive, !stopping || restartAfterExit else { return }
        retryDelay = 1
        reconnect("Network changed; opening a fresh relay connection", networkChange: true)
    }
    private func reconnect(_ reason: String, networkChange: Bool = false) {
        let now = ProcessInfo.processInfo.systemUptime
        if let since = connectedSince, now - since >= 30 { retryDelay = 1 }
        connectedSince = nil
        let delay = networkChange ? 1 : retryDelay
        if !networkChange { retryDelay = min(retryDelay * 2, 30) }
        let previousRetry = retryAt
        cancelRetry()
        retryReason = reason
        let deadline = now + delay
        retryAt = networkChange ? min(previousRetry ?? deadline, deadline) : deadline
        restartAfterExit = true
        if client != nil, !stopping { stopClient() }
        status = .reconnecting(reason)
        appendLog(["\(timestamp()) INFO app: Fresh relay connection in \(Int(delay))s; \(reason)"])
        if client == nil { scheduleRetry() }
    }
    private func cancelRetry() {
        retryTask?.cancel(); retryTask = nil
        retryAt = nil; retryReason = nil
    }
    private func scheduleRetry() {
        guard let retryAt else { return }
        let delay = max(0, retryAt - ProcessInfo.processInfo.systemUptime)
        retryTask = Task { [weak self] in
            do { try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000)) }
            catch { return }
            self?.retryIfDue()
        }
    }
    func retryIfDue(now: TimeInterval = ProcessInfo.processInfo.systemUptime) {
        guard !quitting, restartAfterExit, let retryAt, now >= retryAt else { return }
        if client != nil {
            if !stopping { reconnect(retryReason ?? "Opening a fresh relay connection") }
            return
        }
        cancelRetry(); restartAfterExit = false
        connect(resetRetry: false)
    }
    private func clearTraffic() {
        traffic.reset()
        trafficNodeName = nil
        trafficServerID = nil
    }
    private func appendLog(_ lines: [String]) {
        appendClientLog(lines, to: &log)
    }
    private func timestamp() -> String { ISO8601DateFormatter().string(from: Date()) }
}
