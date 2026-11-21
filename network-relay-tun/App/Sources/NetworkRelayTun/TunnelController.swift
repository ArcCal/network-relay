import AppKit
import Foundation
import Network
import NetworkRelayTunModel

/// Owns the complete independent application session. Network restoration is
/// awaited before native relay shutdown, replacement or application termination.
@MainActor
final class TunnelController: ObservableObject {
    static let shared = TunnelController()
    @Published private(set) var status: Status = .stopped
    @Published private(set) var configuration: Configuration
    @Published private(set) var log: [String] = []
    @Published private(set) var traffic = LiveTraffic()
    @Published private(set) var trafficNodeName: String?
    @Published private(set) var captureStatus = "Off"
    @Published private(set) var interfaceName: String?
    @Published private(set) var recoveryRequired = false
    @Published private(set) var globalTUN: Bool
    @Published private var checkingModeChange = false
    private var task: Task<Void, Never>?
    private var native: NativeClient?
    private var generation = UUID()
    private var nativeReady = false
    private var nativeExited = true
    private var nativeFailure: String?
    private var retryReason: String?
    private var retrySince: TimeInterval?
    private var host: HostSession?
    private var quitting = false
    private var eraseOnQuit = false
    private var restart = false
    private var networkChanges: NetworkChanges?

    private init() {
        configuration = Store.load()
        globalTUN = UserDefaults.standard.object(forKey: "GlobalTUN") as? Bool ?? true
    }
    var settings: Settings {
        var value = configuration.settings
        if globalTUN { value.listenAddress = "127.0.0.1" }
        return value
    }
    var isConfigured: Bool { (try? clientConfiguration(settings, password: configuration.password)) != nil }
    func launched() {
        networkChanges = NetworkChanges { [weak self] in self?.networkChanged() }
        record("Network Relay Tun launched; native Network.framework relay transport")
        if configuration.connectOnLaunch && isConfigured { connect() }
    }
    var canChangeGlobalTUN: Bool {
        !quitting && !recoveryRequired && !checkingModeChange &&
            (task == nil || (status == .connected && task?.isCancelled == false))
    }
    func setGlobalTUN(_ enabled: Bool) {
        guard enabled != globalTUN, canChangeGlobalTUN else { return }
        guard enabled, task != nil else { applyGlobalTUN(enabled); return }

        // Keep the working SOCKS session until we know the installed helper can serve us.
        let original = generation
        checkingModeChange = true
        Task {
            let control = HostSession()
            defer { control.close(); checkingModeChange = false }
            do {
                try await control.checkCompatibility()
            } catch {
                if generation == original, status == .connected, task?.isCancelled == false {
                    captureStatus = "Off. " + error.localizedDescription
                    record(error.localizedDescription, level: "ERROR")
                }
                return
            }
            guard generation == original, status == .connected, task?.isCancelled == false,
                  !quitting, !recoveryRequired else { return }
            applyGlobalTUN(true)
        }
    }
    private func applyGlobalTUN(_ enabled: Bool) {
        globalTUN = enabled
        UserDefaults.standard.set(enabled, forKey: "GlobalTUN")
        if let task {
            restart = true
            status = .connecting
            task.cancel()
        }
    }
    @discardableResult
    func save(_ new: Configuration, retryFailed: Bool = false, allowReconnect: Bool = true) throws -> Bool {
        try new.check(); try Store.save(new)
        let changed = clientChange(from: configuration, to: new) != .none
        let levelChanged = configuration.logLevel != new.logLevel
        configuration = new
        if levelChanged { native?.setLogLevel(new.logLevel) }
        if changed, task != nil {
            restart = allowReconnect; task?.cancel()
            record("Settings saved; restoring the current session before replacement")
            return allowReconnect
        }
        if retryFailed, case .failed = status, allowReconnect { connect(); return true }
        record("Settings saved")
        return false
    }
    func use(_ id: UUID) {
        var next = configuration; next.selectedServerID = id
        do { _ = try save(next, retryFailed: true) } catch { fail(error) }
    }
    func setLogLevel(_ level: LogLevel) {
        var next = configuration; next.logLevel = level
        do { _ = try save(next) } catch { fail(error) }
    }
    func toggle() { if task == nil { connect() } else { disconnect() } }
    func connect(resetRetry: Bool = true) {
        guard task == nil, !quitting else { return }
        do { _ = try clientConfiguration(settings, password: configuration.password) }
        catch { fail(error); return }
        restart = false
        status = .connecting
        task = Task { await runSession() }
    }
    private func runSession() async {
        var delay: UInt64 = 1
        var endpoints: ArraySlice<String> = []
        while !Task.isCancelled {
            var terminal = false
            var advance = false
            do {
                var selected = settings
                var relayInterface: NWInterface?
                var captureLease: String?
                if globalTUN {
                    captureStatus = "Preparing"
                    let control = HostSession()
                    do {
                        try await control.checkCompatibility()
                        try Task.checkCancellation()
                    } catch {
                        control.close()
                        throw error
                    }
                    host = control
                    _ = try await control.request(["operation": "recover"])
                    recoveryRequired = false
                    let bootstrapSettings = selected
                    if endpoints.isEmpty {
                        let resolved = try await Task.detached { try RelayEndpoints.resolve(bootstrapSettings) }.value
                        endpoints = resolved[...]
                    }
                    try Task.checkCancellation()
                    guard let endpoint = endpoints.popFirst() else { throw NativeError("No relay endpoint is available.") }
                    selected.serverIP = endpoint // Retain original domain for SNI and certificate trust.
                    let prepared = try await control.request(["operation": "prepare", "plan": [
                        "endpoints": [endpoint], "resolvers": ["1.1.1.1", "8.8.8.8"], "mtu": 1500, "socks_port": selected.port
                    ]])
                    guard let lease = prepared.status.lease, prepared.status.state == "prepared" else {
                        throw NativeError("Network helper did not return a prepared session.")
                    }
                    captureLease = lease
                    if endpoint.contains(":") {
                        guard let name = prepared.status.ipv6_uplink, let physical = networkChanges?.physicalInterface(named: name) else {
                            throw EndpointFailure(message: "The IPv6 relay's physical interface is unavailable.")
                        }
                        relayInterface = physical
                    }
                    interfaceName = prepared.status.interface
                    captureStatus = "Prepared; waiting for relay"
                }
                try Task.checkCancellation()
                let run = UUID(); generation = run
                nativeReady = false; nativeExited = false; nativeFailure = nil; retryReason = nil; retrySince = nil
                traffic.reset(); trafficNodeName = configuration.selectedServer?.title
                native = try NativeClient(configuration: clientConfiguration(selected, password: configuration.password), level: configuration.logLevel, id: run, relayInterface: relayInterface) { [weak self] update in
                    guard let self, generation == run else { return }
                    received(update)
                }
                let openingDeadline = ProcessInfo.processInfo.systemUptime + 35
                while !nativeReady {
                    try Task.checkCancellation()
                    if nativeExited { terminal = true; throw NativeError(nativeFailure ?? "Relay exited before readiness.") }
                    if !endpoints.isEmpty, let reason = retryReason { throw EndpointFailure(message: reason) }
                    guard ProcessInfo.processInfo.systemUptime < openingDeadline else { throw EndpointFailure(message: "Relay readiness timed out.") }
                    try await Task.sleep(nanoseconds: 100_000_000)
                }
                if let host, let lease = captureLease {
                    _ = try await host.request(["operation": "activate", "lease": lease])
                    captureStatus = "Capturing IPv4 and IPv6"
                }
                status = .connected
                record("System capture: \(captureStatus) [run=\(run.uuidString.prefix(8))]")
                endpoints = [] // Resolve again after a later physical path change.
                let connectedAt = ProcessInfo.processInfo.systemUptime
                while !Task.isCancelled {
                    if nativeExited { terminal = true; throw NativeError(nativeFailure ?? "Relay stopped.") }
                    if let retrySince, ProcessInfo.processInfo.systemUptime - retrySince >= 2 { throw NativeError(retryReason ?? "Relay connection needs replacement.") }
                    if let host, let lease = captureLease {
                        _ = try await host.request(["operation": "refresh", "lease": lease])
                    }
                    if ProcessInfo.processInfo.systemUptime - connectedAt >= 30 { delay = 1 }
                    try await Task.sleep(nanoseconds: 2_000_000_000)
                }
            } catch is CancellationError {
                // Explicit stop or configuration replacement; restore below.
            } catch {
                advance = error is EndpointFailure && !endpoints.isEmpty
                if !Task.isCancelled {
                    if advance { record("Relay address unavailable: \(error.localizedDescription)") }
                    else { fail(error) }
                }
                if (!advance && native == nil) || error is CaptureChanged || recoveryRequired { terminal = true }
            }
            await restore()
            if Task.isCancelled || terminal || recoveryRequired { break }
            if advance {
                status = .connecting
                continue
            }
            status = .reconnecting("Opening a fresh relay connection")
            do { try await Task.sleep(nanoseconds: delay * 1_000_000_000) } catch { break }
            delay = min(delay * 2, 30)
        }
        task = nil
        traffic.reset(); trafficNodeName = nil
        if !recoveryRequired {
            switch status {
            case .failed where !Task.isCancelled: break
            default: status = .stopped
            }
        }
        if quitting {
            if eraseOnQuit && !recoveryRequired { Store.eraseEverything() }
            NSApp.reply(toApplicationShouldTerminate: true)
        } else if restart && !recoveryRequired {
            restart = false; connect()
        }
    }
    private func restore() async {
        if host == nil && !recoveryRequired { captureStatus = "Off" }
        if let control = host {
            captureStatus = "Restoring network"
            do { try await control.stop(); captureStatus = "Off"; recoveryRequired = false; interfaceName = nil }
            catch { recoveryRequired = true; captureStatus = "Recovery required"; fail(error); control.close() }
            host = nil
        }
        native?.stop()
        let deadline = ProcessInfo.processInfo.systemUptime + 10
        while native != nil && !nativeExited && ProcessInfo.processInfo.systemUptime < deadline {
            await Task.detached { try? await Task.sleep(nanoseconds: 100_000_000) }.value
        }
        if native != nil && !nativeExited { recoveryRequired = true; fail(NativeError("Native transport shutdown timed out; quit before reconnecting.")) }
        native = nil; generation = UUID(); nativeReady = false
    }
    func disconnect() {
        restart = false
        if let task {
            task.cancel()
        } else if !recoveryRequired {
            status = .stopped
        }
        record("Disconnect requested; awaiting restoration")
    }
    func networkChanged() {
        guard task != nil, !quitting else { return }
        retryReason = "Physical network changed"; retrySince = ProcessInfo.processInfo.systemUptime - 2
    }
    func requestQuit() -> NSApplication.TerminateReply {
        quitting = true; restart = false
        guard task != nil else { if eraseOnQuit && !recoveryRequired { Store.eraseEverything() }; return .terminateNow }
        task?.cancel(); return .terminateLater
    }
    func stopForQuit() { quitting = true; restart = false; task?.cancel() }
    func eraseEverythingAndQuit() { eraseOnQuit = true; NSApp.terminate(nil) }
    func recoverNetwork() {
        guard task == nil else { return }
        Task {
            let control = HostSession()
            defer { control.close() }
            do { _ = try await control.request(["operation": "recover"]); recoveryRequired = false; captureStatus = "Off"; interfaceName = nil; status = .stopped }
            catch { recoveryRequired = true; fail(error) }
        }
    }
    func installHelper() {
        guard task == nil else { return }
        let script = Bundle.main.bundleURL.appendingPathComponent("Contents/Resources/install-helper.sh").path
        let command = "/bin/bash '" + script.replacingOccurrences(of: "'", with: "'\\''") + "' " + String(getuid())
        let escaped = command.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        Task {
            let error = await Task.detached { () -> String? in
                var error: NSDictionary?
                NSAppleScript(source: "do shell script \"\(escaped)\" with administrator privileges")?.executeAndReturnError(&error)
                return error.map { String(describing: $0) }
            }.value
            if let error { fail(NativeError(error)) } else { record("Network helper installation completed") }
        }
    }
    private func received(_ update: NativeUpdate) {
        switch update {
        case .log(let lines): appendClientLog(lines, to: &log)
        case .connected: nativeReady = true; retryReason = nil; retrySince = nil
        case .reconnecting(let reason):
            if !reason.contains("relay refused the request with HTTP ") { retryReason = reason; if retrySince == nil { retrySince = ProcessInfo.processInfo.systemUptime } }
        case .traffic(let sample): traffic.sample(sample)
        case .trafficUnavailable: traffic.unavailable()
        case .exited(let code, let message): nativeExited = true; nativeFailure = message ?? (code == 0 ? nil : "Relay process failed (\(code)).")
        }
    }
    private func fail(_ error: Error) { status = .failed(error.localizedDescription); record(error.localizedDescription, level: "ERROR") }
    private func record(_ text: String, level: String = "INFO") { appendClientLog(["\(ISO8601DateFormatter().string(from: Date())) \(level) app: \(text)"], to: &log) }
}
