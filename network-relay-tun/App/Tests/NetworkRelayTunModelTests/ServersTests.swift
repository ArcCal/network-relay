import XCTest
@testable import NetworkRelayTunModel

/// Several servers, the one connected to, and switching between them.
final class ServersTests: XCTestCase {
    private let tokyo = Server(name: "Tokyo", domain: "vpn.example.com:8443", username: "macbook", password: "Zx9-kPq_4")
    private let frankfurt = Server(name: "Frankfurt", domain: "de.example.com", serverIP: "198.51.100.7", username: "macbook", password: "pw", transport: .h2)
    private var both: Configuration {
        Configuration(servers: [tokyo, frankfurt], selectedServerID: tokyo.id)
    }

    func testTheServerConnectedToIsTheChosenOneOrElseTheFirst() {
        var configuration = both
        XCTAssertEqual(configuration.selectedServer, tokyo)
        configuration.selectedServerID = frankfurt.id
        XCTAssertEqual(configuration.selectedServer, frankfurt)
        configuration.selectedServerID = UUID()
        XCTAssertEqual(configuration.selectedServer, tokyo, "a server no longer in the list")
        configuration.selectedServerID = nil
        XCTAssertEqual(configuration.selectedServer, tokyo)
        XCTAssertNil(Configuration().selectedServer)
    }

    func testSavingNewAndImportedServersKeepsAnUnchangedCurrentConnection() {
        let current = both
        var draft = current
        let added = Server(domain: "new.example.com", username: "user", password: "pw")
        draft.servers.append(added)
        draft.selectedServerID = added.id
        for imported in [false, true] {
            let saved = draft.preparingConnectionSave(from: current, importedServers: imported)
            XCTAssertEqual(saved.configuration.selectedServerID, tokyo.id)
            XCTAssertEqual(saved.configuration.servers, draft.servers)
            XCTAssertTrue(saved.allowReconnect)
        }
        draft.selectedServerID = frankfurt.id
        let imported = draft.preparingConnectionSave(from: current, importedServers: true)
        XCTAssertEqual(imported.configuration.selectedServerID, tokyo.id)
        XCTAssertTrue(imported.allowReconnect)
    }

    func testReplacingOrChangingTheImportedCurrentServerWaitsForConnect() {
        let current = both
        var replacement = Configuration(servers: [frankfurt], selectedServerID: frankfurt.id)
        XCTAssertFalse(replacement.preparingConnectionSave(from: current, importedServers: true).allowReconnect)
        replacement = current
        replacement.servers[0].password = "imported-password"
        replacement.selectedServerID = frankfurt.id
        let changed = replacement.preparingConnectionSave(from: current, importedServers: true)
        XCTAssertFalse(changed.allowReconnect)
        XCTAssertEqual(changed.configuration.selectedServerID, tokyo.id)
        replacement = current
        replacement.port = 1081
        XCTAssertTrue(replacement.preparingConnectionSave(from: current, importedServers: true).allowReconnect,
                      "Application edits retain their ordinary Save behavior")
        XCTAssertTrue(replacement.preparingConnectionSave(from: current, importedServers: false).allowReconnect,
                      "Ordinary edits still reconnect on Save")
        XCTAssertFalse(current.preparingConnectionSave(from: Configuration(), importedServers: false).allowReconnect,
                       "The first saved server waits for Connect")
    }

    func testImportingInactiveOrDisplayOnlyChangesKeepsTheCurrentConnection() {
        let current = both
        var draft = current
        draft.servers[0].name = "Renamed"
        draft.servers[1].password = "inactive-password"
        draft.logLevel = .detailed
        draft.port = 1081
        let saved = draft.preparingConnectionSave(from: current, importedServers: true)
        XCTAssertTrue(saved.allowReconnect)
        XCTAssertEqual(saved.configuration.selectedServerID, tokyo.id)
        XCTAssertEqual(clientChange(from: current, to: saved.configuration), .reconnect,
                       "The application port still applies on Save")
    }

    func testTheClientRunsWithTheServerConnectedToAndTheProxy() throws {
        // As the single server of 1.3 did: the same configuration file
        // network-relay-tun-core's own tests read.
        let url = try XCTUnwrap(Bundle.module.url(forResource: "domain-only", withExtension: "toml", subdirectory: "Fixtures"))
        let configuration = both
        XCTAssertEqual(try clientConfiguration(configuration.settings, password: configuration.password), try String(contentsOf: url, encoding: .utf8))
        var other = both
        other.selectedServerID = frankfurt.id
        other.port = 1081
        let text = try clientConfiguration(other.settings, password: other.password)
        XCTAssertTrue(text.contains("uri_template = \"https://198.51.100.7:443/"), text)
        XCTAssertTrue(text.contains("server_name = \"de.example.com\""), text)
        XCTAssertTrue(text.contains("transport = \"h2\""), text)
        XCTAssertTrue(text.contains("listen = [\"127.0.0.1:1081\"]"), text)
        XCTAssertEqual(other.settings.proxyAddress, "127.0.0.1:1081")
    }

    func testDeletingTheServerConnectedToMovesToItsNeighbor() {
        let paris = Server(name: "Paris", domain: "fr.example.com", username: "macbook", password: "pw")
        var configuration = Configuration(servers: [tokyo, frankfurt, paris], selectedServerID: frankfurt.id, port: 1081)
        configuration = configuration.removing(server: frankfurt.id)
        XCTAssertEqual(configuration.servers, [tokyo, paris])
        XCTAssertEqual(configuration.selectedServerID, paris.id)
        XCTAssertEqual(configuration.port, 1081, "application settings stay")
        configuration = configuration.removing(server: paris.id)
        XCTAssertEqual(configuration.selectedServerID, tokyo.id)
        configuration = configuration.removing(server: tokyo.id)
        XCTAssertTrue(configuration.servers.isEmpty)
        XCTAssertNil(configuration.selectedServerID)
        XCTAssertNoThrow(try configuration.check())
    }

    func testDeletingAnotherServerKeepsTheOneConnectedTo() {
        let configuration = Configuration(servers: [tokyo, frankfurt])
        XCTAssertEqual(configuration.removing(server: frankfurt.id).servers, [tokyo])
        XCTAssertEqual(configuration.removing(server: frankfurt.id).selectedServerID, tokyo.id)
        XCTAssertEqual(configuration.removing(server: tokyo.id).selectedServerID, frankfurt.id)
        var unchanged = configuration
        unchanged.selectedServerID = tokyo.id
        XCTAssertEqual(configuration.removing(server: UUID()), unchanged)
    }

    func testServersAreShownByTheirNameOrElseTheirDomain() {
        XCTAssertEqual(tokyo.title, "Tokyo")
        XCTAssertEqual(Server(name: "  ", domain: " vpn.example.com ").title, "vpn.example.com")
        XCTAssertEqual(Server().title, "New Server")
    }

    func testCheckingNamesTheServerThatIsWrong() {
        XCTAssertNoThrow(try both.check())
        XCTAssertNoThrow(try Configuration().check(), "no servers at all")
        var configuration = both
        configuration.servers[1].password = ""
        XCTAssertThrowsError(try configuration.check()) { error in
            XCTAssertEqual(error as? ServerError, ServerError(server: "Frankfurt", reason: .missingPassword))
            XCTAssertEqual(error.localizedDescription, "Frankfurt: Enter the password.")
        }
        configuration.servers.append(Server())
        configuration.servers[1].password = "pw"
        XCTAssertThrowsError(try configuration.check()) { error in
            XCTAssertEqual(error as? ServerError, ServerError(server: "New Server", reason: .missingDomain))
        }
        // The proxy first: it is not a server's.
        configuration.port = 0
        XCTAssertThrowsError(try configuration.check()) { XCTAssertEqual($0 as? SettingsError, .invalidPort) }
    }

    func testWhatARunningClientDoesWhenTheSettingsChange() {
        let old = both
        func change(_ edit: (inout Configuration) -> Void) -> ClientChange {
            var new = old
            edit(&new)
            return clientChange(from: old, to: new)
        }
        // Switching to another server: the reason there is a list.
        XCTAssertEqual(change { $0.selectedServerID = frankfurt.id }, .reconnect)
        XCTAssertEqual(change { $0.selectedServerID = tokyo.id }, .none)
        // What the client runs with.
        XCTAssertEqual(change { $0.servers[0].password = "new" }, .reconnect)
        XCTAssertEqual(change { $0.servers[0].transport = .h3 }, .reconnect)
        XCTAssertEqual(change { $0.servers[0].probeTarget = "9.9.9.9:53" }, .reconnect)
        XCTAssertEqual(change { $0.port = 1081 }, .reconnect)
        XCTAssertEqual(change { $0.listenAddress = "0.0.0.0" }, .reconnect)
        // What it does not run with.
        XCTAssertEqual(change { $0.servers[0].name = "Japan" }, .none)
        XCTAssertEqual(change { $0.servers[1].password = "new" }, .none, "another server")
        XCTAssertEqual(change { $0.servers[1].probeTarget = "9.9.9.9:53" }, .none, "another server's probe")
        XCTAssertEqual(change { $0.servers.append(Server(domain: "third.example.com")) }, .none)
        XCTAssertEqual(change { $0.connectOnLaunch = true }, .none)
        // The server connected to removed: on to the next one.
        XCTAssertEqual(change { $0.servers.removeFirst() }, .reconnect)
        XCTAssertEqual(change { $0.servers.removeAll() }, .disconnect)
        // The log: fewer lines are only shown fewer; more need the client.
        XCTAssertEqual(change { $0.logLevel = .errors }, .none)
        XCTAssertEqual(change { $0.logLevel = .warnings }, .none)
        XCTAssertEqual(change { $0.logLevel = .detailed }, .none)
        XCTAssertEqual(change { $0.logLevel = .everything }, .none)
    }

    func testProbeTargetSurvivesStorageExportAndCoreImport() throws {
        var configuration = both
        configuration.servers[0].probeTarget = "[2606:4700:4700::1111]:53"
        let stored = try JSONDecoder().decode(Configuration.self, from: JSONEncoder().encode(configuration))
        XCTAssertEqual(stored, configuration)
        XCTAssertEqual(stored.settings.probeTarget, configuration.servers[0].probeTarget)
        let core = try clientConfiguration(stored.settings, password: stored.password)
        XCTAssertTrue(core.contains("probe_target = \"[2606:4700:4700::1111]:53\""))
        XCTAssertEqual(try Configuration.importing(core).selectedServer?.probeTarget, configuration.servers[0].probeTarget)
        let exported = try Configuration.importing(configuration.exportedTOML(withPasswords: true))
        XCTAssertEqual(exported.servers, configuration.servers)
    }

    func testProbeTargetRejectsNamesZonesMissingPortsAndInvalidNumbers() throws {
        for target in ["example.com:53", "1.1.1.1", "1.1.1.1:0", "1.1.1.1:65536", "::1:53", "[fe80::1%en0]:53", "[1.1.1.1]:53", "[::1]", ""] {
            var settings = both.settings
            settings.probeTarget = target
            XCTAssertThrowsError(try clientConfiguration(settings, password: both.password), target) {
                XCTAssertEqual($0 as? SettingsError, .invalidProbeTarget)
            }
            XCTAssertThrowsError(try Configuration.importing("""
            [[server]]
            domain = "vpn.example.com"
            probe_target = \(tomlString(target))
            """), target)
        }
    }

    func testOlderSettingsKeepTheirProbeDefaultAndCredentials() throws {
        let old = try JSONDecoder().decode(Configuration.self, from: Data(#"{"settings":{"domain":"vpn.example.com","username":"macbook"},"password":"keep"}"#.utf8))
        XCTAssertEqual(old.selectedServer?.probeTarget, "1.1.1.1:53")
        XCTAssertEqual(old.password, "keep")
        let core = try clientConfiguration(old.settings, password: old.password)
        XCTAssertFalse(core.contains("probe_target"), "Default core configuration stays unchanged")
    }

}

final class LogLevelTests: XCTestCase {
    private let lines = [
        "error": "2026-10-03 15:00:00.000 -07:00 ERROR SOCKS5 proxy: listening on 127.0.0.1:1080: Address already in use (os error 48)",
        "warn": "2026-10-03 15:00:00.000 -07:00  WARN session failed: server closed the tunnel",
        "info": #"2026-10-03 15:00:00.000 -07:00  INFO tunnel up transport="HTTP/2" addresses=10.89.0.137/32 routes=8"#,
        "debug": "2026-10-03 15:00:00.000 -07:00 DEBUG SOCKS5 CONNECT 192.0.2.80:80 via Ok(10.89.0.137:80) client=127.0.0.1:50122",
        "trace": "2026-10-03 15:00:00.000 -07:00 TRACE native: Native stream 7 received 512 bytes",
    ]

    private func shown(_ level: LogLevel) -> Set<String> {
        Set(lines.filter { level.shows($0.value) }.keys)
    }

    func testEachLevelShowsItsLinesAndTheMoreImportantOnes() {
        XCTAssertEqual(shown(.errors), ["error"])
        XCTAssertEqual(shown(.warnings), ["error", "warn"])
        XCTAssertEqual(shown(.normal), ["error", "warn", "info"])
        XCTAssertEqual(shown(.detailed), ["error", "warn", "info", "debug"])
        XCTAssertEqual(shown(.everything), ["error", "warn", "info", "debug", "trace"])
    }

    func testLinesWithoutALevelAreAlwaysShown() {
        let others = [
            "—— starting network-relay-tun-core for Tokyo (vpn.example.com), SOCKS5 proxy on 127.0.0.1:1080 ——",
            "network-relay-tun-core: parsing the configuration on stdin: TOML error at line 1, column 1",
            "error: unexpected argument '--bogus' found",
            "  |",
            "",
        ]
        for level in LogLevel.allCases {
            for line in others {
                XCTAssertTrue(level.shows(line), "\(level): \(line)")
            }
        }
    }

    func testLevelPrefixUsesTheFirstOfFourWordsAndRequiresAMessage() {
        let cases: [(String, LogLevel)] = [
            ("  date zone source  TRACE   payload  ", .everything),
            ("stamp WARN DEBUG body", .warnings),
            ("DEBUG INFO", .detailed),
            ("one two three four TRACE payload", .errors),
            ("one two three DEBUG   ", .errors),
            ("TRACE\tpayload", .errors),
            ("tag\u{a0}DEBUG payload", .errors),
            ("tag \u{301}DEBUG payload", .errors),
            ("stamp INFO \u{1f680}", .normal),
            ("UNKNOWN payload", .errors),
        ]
        for (line, minimum) in cases {
            for setting in LogLevel.allCases {
                XCTAssertEqual(setting.shows(line), setting.nativeValue >= minimum.nativeValue, line)
            }
            var log = ["INFO kept"]
            appendClientLog([line], to: &log, limit: 1)
            XCTAssertEqual(log, minimum.nativeValue >= LogLevel.detailed.nativeValue ? ["INFO kept"] : [line])
        }
    }

    func testLogCollectionFiltersAndIndependentNativeLevels() {
        XCTAssertEqual(LogLevel.allCases.map(\.nativeValue), [0, 1, 2, 3, 4])
    }

    func testVerboseFloodKeepsConnectionAndErrorRecordsInOrder() {
        let start = "2026-10-10T02:40:00Z INFO app: Connected"
        let failure = "2026-10-10T02:40:33Z WARN core: Can't assign requested address"
        let recovery = "2026-10-10T02:40:34Z INFO core: tunnel up"
        var log: [String] = []
        appendClientLog([start], to: &log)
        for batch in 0..<10 {
            appendClientLog((0..<1000).map { "TRACE native: batch=\(batch) event=\($0)" }, to: &log)
            if batch == 4 { appendClientLog([failure, recovery], to: &log) }
        }
        XCTAssertEqual(log.count, 5000)
        XCTAssertEqual(log.filter { !$0.hasPrefix("TRACE") }, [start, failure, recovery])
        XCTAssertEqual(log.last, "TRACE native: batch=9 event=999")
    }

    func testLogTrimmingIsBoundedAndPreservesUnknownLinesAndChronology() {
        var log = ["INFO launch", "DEBUG old request", "unknown diagnostic", "TRACE old read"]
        appendClientLog(["WARN failure", "DEBUG new request", "INFO recovery"], to: &log, limit: 5)
        XCTAssertEqual(log, ["INFO launch", "unknown diagnostic", "WARN failure", "DEBUG new request", "INFO recovery"])
        appendClientLog(["ERROR fatal", "WARN later failure"], to: &log, limit: 5)
        XCTAssertEqual(log, ["unknown diagnostic", "WARN failure", "INFO recovery", "ERROR fatal", "WARN later failure"])
        var short = ["DEBUG keep", "INFO keep"]
        appendClientLog(["TRACE keep"], to: &short, limit: 5)
        XCTAssertEqual(short, ["DEBUG keep", "INFO keep", "TRACE keep"])
    }

    func testLevelsAreSavedByName() {
        XCTAssertEqual(LogLevel.allCases.map(\.rawValue), ["errors", "warnings", "normal", "detailed", "everything"])
        XCTAssertEqual(Set(LogLevel.allCases.map(\.title)).count, LogLevel.allCases.count)
    }
}
