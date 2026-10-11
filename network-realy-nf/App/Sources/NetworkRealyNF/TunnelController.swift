import AppKit
import Foundation
import NetworkRealyNFModel

/// Native, in-process SOCKS client. It never manages another application's
/// processes, helper, routing, DNS configuration, firewall or settings.
@MainActor
final class TunnelController: ObservableObject {
    static let shared = TunnelController()
    @Published private(set) var status: Status = .stopped
    @Published private(set) var configuration: Configuration
    @Published private(set) var log: [String] = []
    private var client: NativeClient?
    private var generation = UUID()
    private var stopping = false
    private var restartAfterExit = false
    private var quitting = false
    private var eraseOnQuit = false

    private init() { configuration = Store.load() }
    var settings: Settings { configuration.settings }
    var isConfigured: Bool { (try? clientConfiguration(settings, password: configuration.password)) != nil }
    func launched() {
        appendLog(["\(timestamp()) INFO app: Network Realy NF launched; Network.framework transport"])
        if configuration.connectOnLaunch {
            if isConfigured { connect() }
            else { appendLog(["\(timestamp()) WARN app: Launch connection skipped: complete the selected server settings first."]) }
        }
    }
    @discardableResult
    func save(_ new: Configuration) throws -> Bool {
        try new.check()
        try Store.save(new)
        let reconnecting = adopt(new)
        appendLog(["\(timestamp()) INFO app: Settings saved\(reconnecting ? "; reconnecting with the changed parameters; existing proxy sessions will end" : "")"])
        return reconnecting
    }
    func use(_ id: UUID) {
        var new = configuration; new.selectedServerID = id
        guard new.selectedServer?.id != configuration.selectedServer?.id else { return }
        guard saveChoice(new) else { return }
        let reconnecting = adopt(new)
        appendLog(["\(timestamp()) INFO app: Server selected: \(new.selectedServer?.title ?? "none")\(reconnecting ? "; reconnecting; existing proxy sessions will end" : "")"])
    }
    func setLogLevel(_ level: LogLevel) {
        guard level != configuration.logLevel else { return }
        var new = configuration; new.logLevel = level
        saveChoice(new); adopt(new)
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
    private func adopt(_ new: Configuration) -> Bool {
        let change = clientChange(from: configuration, to: new)
        let levelChanged = configuration.logLevel != new.logLevel
        configuration = new
        if levelChanged { client?.setLogLevel(new.logLevel) }
        // A choice made while an explicit Disconnect is finishing must
        // not request another connection. Pending automatic restarts may update it.
        guard client != nil, !quitting, !stopping || restartAfterExit else { return false }
        switch change {
        case .none: return false
        case .reconnect:
            restartAfterExit = true
            stopClient()
            return true
        case .disconnect:
            restartAfterExit = false
            stopClient()
            return false
        }
    }
    func toggle() { if client != nil { disconnect() } else { connect() } }
    func connect() {
        guard client == nil, !quitting else { return }
        do {
            let input = try clientConfiguration(settings, password: configuration.password)
            let run = UUID(); generation = run
            status = .connecting; stopping = false
            let server = configuration.selectedServer.map { $0.name.isEmpty ? $0.domain : $0.name } ?? ""
            appendLog(["\(timestamp()) INFO app: Connecting to \(server); SOCKS5 \(settings.proxyAddress); \(settings.transport.title) [run=\(run.uuidString.prefix(8))]"])
            client = try NativeClient(configuration: input, level: configuration.logLevel, id: run) { [weak self] update in
                guard let self, generation == run else { return }
                received(update)
            }
        } catch {
            status = .failed(error.localizedDescription)
            appendLog(["\(timestamp()) ERROR app: \(error.localizedDescription)"])
        }
    }
    func disconnect() {
        appendLog(["\(timestamp()) INFO app: Disconnect requested"])
        // An explicit Disconnect always cancels an earlier Save-triggered restart.
        restartAfterExit = false
        stopClient()
    }
    private func stopClient() {
        guard let client else { status = .stopped; return }
        stopping = true
        client.stop()
    }
    /// AppKit waits asynchronously for this instance to release its sockets.
    func requestQuit() -> NSApplication.TerminateReply {
        appendLog(["\(timestamp()) INFO app: Quit requested"])
        restartAfterExit = false; quitting = true
        guard client != nil else {
            if eraseOnQuit { Store.eraseEverything() }
            return .terminateNow
        }
        stopClient()
        return .terminateLater
    }
    func stopForQuit() { restartAfterExit = false; quitting = true; client?.stop() }
    func eraseEverythingAndQuit() { eraseOnQuit = true; NSApp.terminate(nil) }

    private func received(_ update: NativeUpdate) {
        switch update {
        case .log(let lines): appendLog(lines)
        case .connected: if !stopping { status = .connected }
        case .reconnecting(let why): if !stopping { status = .reconnecting(why) }
        case .exited(let code, let error):
            client = nil
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
                restartAfterExit = false; connect()
            }
        }
    }
    private func appendLog(_ lines: [String]) {
        appendClientLog(lines, to: &log)
    }
    private func timestamp() -> String { ISO8601DateFormatter().string(from: Date()) }
}
