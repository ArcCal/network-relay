#!/usr/bin/env python3
"""Run the actual Swift controller with controlled platform, storage and client APIs.

The model is compiled unchanged. The controller only loses its AppKit import.
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
    static func main() throws {
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
        (build / "Harness.swift").write_text(HARNESS)
        executable = build / "controller-check"
        subprocess.run([
            compiler, "-I", str(build), "-L", str(build), "-lNetworkRelayNFModel",
            "-Xlinker", "-rpath", "-Xlinker", str(build),
            str(build / "Stubs.swift"), str(build / "TunnelController.swift"), str(build / "Harness.swift"),
            "-o", str(executable),
        ], env=environment, check=True)
        subprocess.run([str(executable)], env=environment, check=True)


if __name__ == "__main__":
    main()
