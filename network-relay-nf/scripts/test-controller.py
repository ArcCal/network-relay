#!/usr/bin/env python3
"""Run the actual Swift controller with controlled platform, storage and client APIs.

The model and draft are compiled unchanged. The controller only loses its AppKit import.
This checks lifecycle decisions without claiming native macOS UI or networking.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

STUBS = r"""import Foundation
import NetworkRelayNFModel

protocol ObservableObject {}
@propertyWrapper
struct Published<Value> {
    var wrappedValue: Value
    init(wrappedValue: Value) { self.wrappedValue = wrappedValue }
}

enum HarnessError: Error { case startFailed, saveFailed }
final class NetworkChanges {
    init(_ changed: @escaping @MainActor () -> Void) {}
}
@MainActor
final class NativeClient {
    static var instances: [NativeClient] = []
    static var failNextStart = false
    static var attempts = 0
    let configuration: String
    let id: UUID
    let receive: (NativeUpdate) -> Void
    var stops = 0
    var exited = false
    init(configuration: String, level: LogLevel, id: UUID, update: @escaping (NativeUpdate) -> Void) throws {
        Self.attempts += 1
        if Self.failNextStart { Self.failNextStart = false; throw HarnessError.startFailed }
        self.configuration = configuration
        self.id = id
        self.receive = update
        Self.instances.append(self)
    }
    func stop() { stops += 1 }
    func setLogLevel(_ level: LogLevel) {}
    func emit(_ update: NativeUpdate) {
        if case .exited = update { exited = true }
        receive(update)
    }
}

@MainActor
enum Store {
    static var configuration = Configuration()
    static var failNextSave = false
    static func load() -> Configuration { configuration }
    static func save(_ new: Configuration) throws {
        if failNextSave { failNextSave = false; throw HarnessError.saveFailed }
        configuration = new
    }
    static func eraseEverything() {}
}
struct AppInformation {
    var builtAt: Date? { nil }
    var version: String { "harness" }
    var coreVersion: String { "stub" }
    var sourceRevision: String { "controller-under-test" }
}
enum NSApplication { enum TerminateReply { case terminateNow, terminateLater } }
@MainActor
final class StubApplication {
    func terminate(_ sender: Any?) {}
    func reply(toApplicationShouldTerminate: Bool) {}
}
@MainActor let NSApp = StubApplication()
"""

HARNESS = r"""import Foundation
import NetworkRelayNFModel

@main
struct Harness {
    @MainActor
    static func main() async throws {
        let first = Server(name: "First", domain: "first.test", username: "user", password: "password", transport: .h2)
        let second = Server(name: "Second", domain: "second.test", username: "user", password: "password", transport: .h2)
        let baseline = Configuration(servers: [first, second], selectedServerID: first.id)
        Store.configuration = baseline
        let controller = TunnelController.shared
        var passed = 0
        func check(_ condition: @autoclosure () -> Bool, _ message: String) {
            precondition(condition(), message)
        }
        func reset(_ configuration: Configuration? = nil) throws {
            controller.disconnect()
            for instance in NativeClient.instances where !instance.exited { instance.emit(.exited(0, nil)) }
            try controller.save(configuration ?? baseline)
            check(controller.status == .stopped, "reset must be stopped")
        }
        func start() -> NativeClient {
            controller.connect()
            check(controller.status == .connecting, "start must connect")
            return NativeClient.instances.last!
        }
        func fail() -> NativeClient {
            let old = start()
            old.emit(.exited(1, "terminal failure"))
            if case .failed = controller.status {} else { preconditionFailure("expected failed state") }
            return old
        }
        func pass(_ message: String) { passed += 1; print("PASS \(message)") }

        var draft = Draft(baseline)
        draft.addServer()
        let pendingID = draft.editing
        draft.servers[draft.servers.count - 1].name = "Unfinished"
        for _ in 0..<10 { draft.addServer() }
        check(draft.servers.count == baseline.servers.count + 1 && draft.editing == pendingID,
              "repeated Add must reuse one unsaved form")
        draft.editing = first.id
        draft.addServer()
        check(draft.editing == pendingID && draft.servers.last!.name == "Unfinished",
              "returning to Add must restore the draft without losing its fields")
        check(controller.configuration == baseline && Store.configuration == baseline,
              "Add must not save a server")
        var unsaved = baseline
        unsaved.servers = draft.servers
        do { try controller.save(unsaved); preconditionFailure("expected incomplete server rejection") }
        catch is ServerError {}
        check(controller.configuration == baseline && Store.configuration == baseline,
              "invalid Save must keep unfinished servers out of saved settings")
        draft.servers[draft.servers.count - 1] = Server(id: pendingID!, domain: "new.test", username: "user", password: "password")
        unsaved.servers = draft.servers
        Store.failNextSave = true
        do { try controller.save(unsaved); preconditionFailure("expected failed persistence") }
        catch HarnessError.saveFailed {}
        check(controller.configuration == baseline && Store.configuration == baseline,
              "failed Save must not publish a draft server")
        try controller.save(unsaved)
        check(controller.configuration.servers.count == baseline.servers.count + 1,
              "successful Save must publish the new server")
        var emptyDraft = Draft(Configuration())
        let initialID = emptyDraft.editing
        for _ in 0..<10 { emptyDraft.addServer() }
        check(emptyDraft.servers.count == 1 && emptyDraft.editing == initialID,
              "the initial empty form must also be reused")
        pass("new servers remain a single editable draft until a successful Save")

        try reset()
        let initially = NativeClient.attempts
        controller.use(second.id)
        var choice = controller.configuration
        choice.servers[1].transport = .http1
        try controller.save(choice, retryFailed: true)
        check(NativeClient.attempts == initially && controller.status == .stopped, "disconnected choices must stay off")
        pass("saved server and transport choices preserve explicit disconnected state")

        try reset()
        let oldFailure = fail()
        let beforeLeft = NativeClient.attempts
        controller.use(second.id)
        check(NativeClient.attempts == beforeLeft + 1 && controller.status == .connecting, "left choice must retry failed connection")
        check(controller.configuration.selectedServer?.id == second.id, "left choice must select second")
        oldFailure.emit(.connected)
        check(controller.status == .connecting, "old callback must not change new generation")
        pass("left node choice retries terminal failure and ignores stale callbacks")

        try reset()
        NativeClient.failNextStart = true
        controller.connect()
        if case .failed = controller.status {} else { preconditionFailure("expected initialization failure") }
        let beforeRight = NativeClient.attempts
        choice = controller.configuration
        choice.selectedServerID = second.id
        let retriedRight = try controller.save(choice, retryFailed: true)
        check(retriedRight, "right choice must report retry")
        check(NativeClient.attempts == beforeRight + 1 && controller.status == .connecting, "right choice must retry initialization failure")
        pass("right node choice retries failed client initialization")

        try reset()
        _ = fail()
        let beforeTransport = NativeClient.attempts
        choice = controller.configuration
        choice.servers[0].transport = .http1
        let retriedTransport = try controller.save(choice, retryFailed: true)
        check(retriedTransport, "transport choice must report retry")
        check(NativeClient.attempts == beforeTransport + 1 && controller.status == .connecting, "transport choice must retry terminal failure")
        check(NativeClient.instances.last!.configuration.contains("http/1.1"), "retry must use new transport")
        pass("transport choice retries terminal failure with selected transport")

        var duplicate = first
        duplicate.id = UUID()
        duplicate.name = "Equivalent"
        try reset(Configuration(servers: [first, duplicate], selectedServerID: first.id))
        _ = fail()
        let beforeEquivalent = NativeClient.attempts
        controller.use(duplicate.id)
        check(NativeClient.attempts == beforeEquivalent + 1 && controller.status == .connecting, "different equivalent node must retry")
        pass("different node UUID with equivalent settings retries failure")

        try reset()
        _ = fail()
        let beforeSave = NativeClient.attempts
        choice = controller.configuration
        choice.servers[0].transport = .http1
        try controller.save(choice)
        check(NativeClient.attempts == beforeSave, "ordinary save must not retry terminal failure")
        if case .failed = controller.status {} else { preconditionFailure("ordinary save must retain failed state") }
        pass("ordinary Save does not retry terminal failure")

        try reset()
        let disconnecting = start()
        let beforeDisconnect = NativeClient.attempts
        controller.disconnect()
        controller.use(second.id)
        choice = controller.configuration
        choice.servers[1].transport = .http1
        try controller.save(choice, retryFailed: true)
        disconnecting.emit(.exited(0, nil))
        check(NativeClient.attempts == beforeDisconnect && controller.status == .stopped, "choices during explicit Disconnect must not restart")
        pass("explicit Disconnect wins over choices while stopping")

        try reset()
        let rapidOld = start()
        let beforeRapid = NativeClient.attempts
        controller.use(second.id)
        choice = controller.configuration
        choice.servers[1].transport = .h3
        try controller.save(choice, retryFailed: true)
        check(NativeClient.attempts == beforeRapid, "restart must wait for old client exit")
        rapidOld.emit(.exited(0, nil))
        check(NativeClient.attempts == beforeRapid + 1, "rapid choices must schedule one new client")
        check(NativeClient.instances.last!.configuration.contains("transport = \"h3\""), "latest transport must win")
        pass("rapid choices wait for teardown and use latest selected settings")

        try reset()
        let pending = start()
        controller.use(second.id)
        let beforeCancel = NativeClient.attempts
        controller.disconnect()
        choice = controller.configuration
        choice.servers[1].transport = .h3
        try controller.save(choice, retryFailed: true)
        pending.emit(.exited(0, nil))
        check(NativeClient.attempts == beforeCancel && controller.status == .stopped, "Disconnect must cancel pending restart")
        pass("explicit Disconnect cancels already pending automatic restart")

        try reset()
        let importing = start()
        controller.use(second.id)
        let beforeImport = NativeClient.attempts
        let replacement = Server(name: "Imported", domain: "imported.test", username: "user", password: "password", transport: .h3)
        let imported = Configuration(servers: [replacement], selectedServerID: replacement.id)
        let prepared = imported.preparingConnectionSave(from: controller.configuration, importedServers: true)
        check(!prepared.allowReconnect, "replacement import must require Connect")
        try controller.save(prepared.configuration, allowReconnect: prepared.allowReconnect)
        importing.emit(.exited(0, nil))
        check(NativeClient.attempts == beforeImport && controller.status == .stopped, "import must cancel pending restart")
        controller.connect()
        check(NativeClient.attempts == beforeImport + 1, "explicit Connect must start imported node")
        pass("replacement import Save stops and cancels pending restart until Connect")

        try reset()
        let continuing = start()
        let beforeMerge = NativeClient.attempts
        var merged = controller.configuration
        merged.servers.append(replacement)
        merged.selectedServerID = replacement.id
        let retained = merged.preparingConnectionSave(from: controller.configuration, importedServers: true)
        check(retained.allowReconnect && retained.configuration.selectedServer?.id == first.id, "merge must preserve unchanged current node")
        try controller.save(retained.configuration, allowReconnect: retained.allowReconnect)
        check(NativeClient.attempts == beforeMerge && continuing.stops == 0, "merge must leave unchanged connection running")
        pass("importing added profiles preserves an unchanged existing connection")

        try reset()
        let portOld = start()
        let beforePortEdit = NativeClient.attempts
        var unrelatedImport = controller.configuration
        unrelatedImport.servers.append(replacement)
        unrelatedImport.servers[1].password = "inactive-imported-password"
        unrelatedImport.selectedServerID = replacement.id
        unrelatedImport.port = 1081
        let portPrepared = unrelatedImport.preparingConnectionSave(from: controller.configuration, importedServers: true)
        check(portPrepared.allowReconnect && portPrepared.configuration.selectedServer?.id == first.id,
              "unrelated import must preserve selected node and allow application port edit")
        let portRestart = try controller.save(portPrepared.configuration, allowReconnect: portPrepared.allowReconnect)
        check(portRestart && portOld.stops == 1 && NativeClient.attempts == beforePortEdit,
              "port change must retain ordinary restart after teardown")
        portOld.emit(.exited(0, nil))
        check(NativeClient.attempts == beforePortEdit + 1 && controller.configuration.selectedServer?.id == first.id,
              "application edit must restart original node")
        check(NativeClient.instances.last!.configuration.contains("127.0.0.1:1081"), "new listener port must apply")
        pass("unrelated imported server plus application port edit restarts the original node")

        try reset()
        let updating = start()
        let beforeUpdate = NativeClient.attempts
        var updated = controller.configuration
        updated.servers[0].password = "imported-password"
        updated.selectedServerID = second.id
        let held = updated.preparingConnectionSave(from: controller.configuration, importedServers: true)
        check(!held.allowReconnect, "imported active credentials must require Connect")
        check(held.configuration.selectedServer?.id == first.id, "changed import must retain previous selected node")
        try controller.save(held.configuration, allowReconnect: held.allowReconnect)
        updating.emit(.exited(0, nil))
        check(NativeClient.attempts == beforeUpdate && controller.status == .stopped, "active imported settings must stay stopped")
        pass("imported active profile update waits for explicit Connect")

        try reset()
        let saving = start()
        controller.use(second.id)
        let beforeDiskFailure = NativeClient.attempts
        let prior = controller.configuration
        let rejected = imported.preparingConnectionSave(from: prior, importedServers: true)
        Store.failNextSave = true
        do {
            try controller.save(rejected.configuration, allowReconnect: rejected.allowReconnect)
            preconditionFailure("expected disk save failure")
        } catch HarnessError.saveFailed {}
        check(controller.configuration == prior, "failed persistence must not adopt import")
        saving.emit(.exited(0, nil))
        check(NativeClient.attempts == beforeDiskFailure + 1, "failed persistence must retain previous pending restart")
        check(controller.configuration.selectedServer?.id == second.id, "previous intended node must survive failed save")
        pass("failed persistence preserves configuration and previous restart intent")

        try reset()
        let trafficOld = start()
        trafficOld.emit(.traffic(TrafficSnapshot(uploadBytes: 0, downloadBytes: 0, elapsedNanoseconds: 0)))
        trafficOld.emit(.traffic(TrafficSnapshot(uploadBytes: 1024, downloadBytes: 2048, elapsedNanoseconds: 1_000_000_000)))
        check(controller.traffic.state == .active && controller.traffic.uploadBytesPerSecond == 1024,
              "live traffic must publish one-second payload rates")
        check(controller.trafficNodeName == first.title, "traffic must name the actual run")
        controller.use(second.id)
        check(controller.trafficNodeName == nil && controller.traffic.uploadBytesPerSecond == 0,
              "pending node change must hide old traffic immediately")
        trafficOld.emit(.traffic(TrafficSnapshot(uploadBytes: 100_000, downloadBytes: 200_000, elapsedNanoseconds: 2_000_000_000)))
        check(controller.trafficNodeName == nil, "stopping traffic updates must be ignored")
        trafficOld.emit(.exited(0, nil))
        check(controller.trafficNodeName == second.title && controller.traffic.state == .idle,
              "a new run must establish a fresh traffic baseline")
        trafficOld.emit(.trafficUnavailable)
        trafficOld.emit(.traffic(TrafficSnapshot(uploadBytes: 100_000, downloadBytes: 200_000, elapsedNanoseconds: 3_000_000_000)))
        check(controller.traffic.state == .idle, "stale generation traffic must not affect the new run")
        pass("live traffic follows the actual run and ignores stopping or stale generations")

        let trafficCurrent = NativeClient.instances.last!
        let beforeTelemetryError = NativeClient.attempts
        trafficCurrent.emit(.trafficUnavailable)
        check(controller.traffic.state == .unavailable && controller.status == .connecting,
              "telemetry errors must leave the connection alone")
        check(NativeClient.attempts == beforeTelemetryError, "telemetry errors must not reconnect")
        trafficCurrent.emit(.traffic(TrafficSnapshot(uploadBytes: 0, downloadBytes: 0, elapsedNanoseconds: 0)))
        trafficCurrent.emit(.traffic(TrafficSnapshot(uploadBytes: 1000, downloadBytes: 2000, elapsedNanoseconds: 1_000_000_000)))
        check(controller.traffic.state == .active, "traffic must recover after a fresh baseline")
        trafficCurrent.emit(.exited(1, "terminal failure"))
        check(controller.trafficNodeName == nil && controller.traffic.uploadBytesPerSecond == 0,
              "terminal failure must hide traffic immediately")
        pass("telemetry failure is isolated and terminal client failure clears traffic")

        try reset()
        let handedOff = start()
        handedOff.emit(.connected)
        let beforeHandoff = NativeClient.attempts
        controller.networkChanged()
        check(handedOff.stops == 1 && controller.status.isActive,
              "network change must tear down the old core and show recovery")
        controller.retryIfDue(now: ProcessInfo.processInfo.systemUptime + 100)
        check(NativeClient.attempts == beforeHandoff, "must not overlap old and new listeners")
        handedOff.emit(.exited(0, nil))
        handedOff.emit(.connected)
        if case .reconnecting = controller.status {} else { preconditionFailure("stale ready callback revived old run") }
        controller.retryIfDue(now: ProcessInfo.processInfo.systemUptime + 100)
        check(NativeClient.attempts == beforeHandoff + 1 && NativeClient.instances.last!.id != handedOff.id,
              "network change must start a genuinely new core generation")
        pass("network handoff waits for teardown, ignores stale callbacks and starts a fresh generation")

        try reset()
        let timedOut = start()
        let beforeTimeout = NativeClient.attempts
        timedOut.emit(.reconnecting("transport timeout"))
        check(timedOut.stops == 0, "a probe stream may recover without disrupting other flows")
        controller.retryIfDue(now: ProcessInfo.processInfo.systemUptime + 3)
        check(timedOut.stops == 1, "retry status must discard old native resources")
        timedOut.emit(.exited(0, nil))
        controller.retryIfDue(now: ProcessInfo.processInfo.systemUptime + 100)
        check(NativeClient.attempts == beforeTimeout + 1, "retry must allocate a fresh core")
        let again = NativeClient.instances.last!
        again.emit(.reconnecting("transport timeout"))
        controller.retryIfDue(now: ProcessInfo.processInfo.systemUptime + 3)
        again.emit(.exited(0, nil))
        controller.retryIfDue(now: ProcessInfo.processInfo.systemUptime + 1)
        check(NativeClient.attempts == beforeTimeout + 1, "repeated failures need bounded backoff")
        controller.retryIfDue(now: ProcessInfo.processInfo.systemUptime + 100)
        check(NativeClient.attempts == beforeTimeout + 2, "backoff must still make another attempt")
        pass("retry indications rebuild native resources with backoff and real attempts")

        try reset()
        let cancelled = start()
        controller.networkChanged()
        controller.disconnect()
        controller.networkChanged()
        cancelled.emit(.exited(0, nil))
        let beforeCancelledRetry = NativeClient.attempts
        controller.retryIfDue(now: ProcessInfo.processInfo.systemUptime + 100)
        controller.networkChanged()
        check(NativeClient.attempts == beforeCancelledRetry && controller.status == .stopped,
              "manual Disconnect must cancel retries and ignore later path notifications")
        pass("manual Disconnect suppresses both pending retries and network callbacks")

        try reset()
        let choosing = start()
        controller.networkChanged()
        choosing.emit(.exited(0, nil))
        let beforeChoice = NativeClient.attempts
        var rightChoice = controller.configuration
        rightChoice.selectedServerID = second.id
        rightChoice.servers[1].transport = .http1
        try controller.save(rightChoice, retryFailed: true)
        check(NativeClient.attempts == beforeChoice + 1 && controller.configuration.selectedServer?.id == second.id,
              "right-side choices must supersede pending recovery immediately")
        check(NativeClient.instances.last!.configuration.contains("http/1.1"), "chosen transport must apply")
        pass("saved server and transport changes supersede pending recovery without waiting for Save")

        try reset()
        let busyGateway = start()
        let beforeGateway = NativeClient.attempts
        busyGateway.emit(.reconnecting("relay refused the request with HTTP 503 Service Unavailable"))
        controller.retryIfDue(now: ProcessInfo.processInfo.systemUptime + 100)
        check(busyGateway.stops == 0 && NativeClient.attempts == beforeGateway,
              "a responding gateway must keep existing flows while the core retries")
        controller.networkChanged()
        check(busyGateway.stops == 1, "a real path change must still replace that connection")
        pass("gateway/quota replies preserve active flows until an actual path change")

        try reset()
        let renewed = start()
        let beforeRenewed = NativeClient.attempts
        renewed.emit(.reconnecting("stream reset"))
        check(renewed.stops == 0, "an isolated probe reset must preserve active flows")
        renewed.emit(.connected)
        controller.retryIfDue(now: ProcessInfo.processInfo.systemUptime + 100)
        check(renewed.stops == 0 && NativeClient.attempts == beforeRenewed && controller.status == .connected,
              "a renewed probe must cancel full recovery")
        pass("a recovered probe preserves healthy flows and cancels its full-restart timer")

        try reset()
        let rejectedCore = start()
        let beforeRejected = NativeClient.attempts
        rejectedCore.emit(.reconnecting("temporary transport error"))
        rejectedCore.emit(.exited(1, "certificate rejected"))
        controller.retryIfDue(now: ProcessInfo.processInfo.systemUptime + 100)
        controller.networkChanged()
        if case .failed = controller.status {} else { preconditionFailure("terminal failure must remain visible") }
        check(NativeClient.attempts == beforeRejected, "a terminal exit must cancel probe recovery")
        pass("terminal core errors cancel the probe grace period instead of retrying")

        try reset()
        let scheduled = start()
        let beforeScheduled = NativeClient.attempts
        scheduled.emit(.reconnecting("transport timeout"))
        try await Task.sleep(nanoseconds: 2_100_000_000)
        check(scheduled.stops == 1 && NativeClient.attempts == beforeScheduled,
              "real timer must stop a stalled client and wait for listener teardown")
        scheduled.emit(.exited(0, nil))
        for _ in 0..<200 {
            if NativeClient.attempts > beforeScheduled { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        check(NativeClient.attempts == beforeScheduled + 1, "the real retry task must start a fresh core")
        pass("real retry timer starts a fresh instance after teardown without a manual retry call")

        try reset()
        let quittingClient = start()
        controller.networkChanged()
        quittingClient.emit(.exited(0, nil))
        let beforeQuit = NativeClient.attempts
        if case .terminateNow = controller.requestQuit() {} else { preconditionFailure("pending retry has no live core") }
        controller.retryIfDue(now: ProcessInfo.processInfo.systemUptime + 100)
        controller.networkChanged()
        try await Task.sleep(nanoseconds: 1_100_000_000)
        check(NativeClient.attempts == beforeQuit, "Quit must never revive a pending retry")
        pass("Quit cancels pending recovery")
        print("RESULT \(passed) controller scenarios passed; platform UI and network transport are stubbed")
    }
}
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--swiftc", default="swiftc", help="Swift compiler executable")
    args = parser.parse_args()
    compiler = shutil.which(args.swiftc)
    if compiler is None:
        parser.error("swiftc was not found; install Swift or pass --swiftc PATH")
    sources = Path(__file__).resolve().parents[1] / "App" / "Sources"
    controller = (sources / "NetworkRelayNF" / "TunnelController.swift").read_text()
    if controller.count("import AppKit\n") != 1:
        raise RuntimeError("Expected exactly one AppKit import in the controller")
    controller = controller.replace("import AppKit\n", "", 1)
    native = (sources / "NetworkRelayNF" / "NativeClient.swift").read_text()
    start = native.index("enum NativeUpdate {")
    native_update = native[start:native.index("\n}\n", start) + 3]
    app = (sources / "NetworkRelayNF" / "App.swift").read_text()
    start = app.index("struct Draft: Equatable {")
    draft = app[start:app.index("\nstruct SettingsForm:", start)]
    with tempfile.TemporaryDirectory(prefix="network-relay-nf-controller-") as folder:
        build = Path(folder)
        environment = os.environ.copy()
        environment.setdefault("CLANG_MODULE_CACHE_PATH", str(build / "clang-cache"))
        environment.setdefault("XDG_CACHE_HOME", str(build / "cache"))
        library = build / ("libNetworkRelayNFModel.dylib" if sys.platform == "darwin" else "libNetworkRelayNFModel.so")
        model = sorted((sources / "NetworkRelayNFModel").glob("*.swift"))
        subprocess.run([
            compiler, "-emit-library", "-emit-module", "-module-name", "NetworkRelayNFModel",
            "-emit-module-path", str(build / "NetworkRelayNFModel.swiftmodule"),
            *map(str, model), "-o", str(library),
        ], env=environment, check=True)
        (build / "Stubs.swift").write_text(STUBS + "\n" + native_update)
        (build / "TunnelController.swift").write_text(controller)
        (build / "Draft.swift").write_text("import Foundation\nimport NetworkRelayNFModel\n" + draft)
        (build / "Harness.swift").write_text(HARNESS)
        executable = build / "controller-check"
        subprocess.run([
            compiler, "-I", str(build), "-L", str(build), "-lNetworkRelayNFModel",
            "-Xlinker", "-rpath", "-Xlinker", str(build),
            str(build / "Stubs.swift"), str(build / "TunnelController.swift"), str(build / "Draft.swift"), str(build / "Harness.swift"),
            "-o", str(executable),
        ], env=environment, check=True)
        subprocess.run([str(executable)], env=environment, check=True)


if __name__ == "__main__":
    main()
