import XCTest
@testable import NetworkRelayNFModel

final class TOMLTests: XCTestCase {
    func testWhatTheAppsFilesUse() throws {
        let document = try parseTOML(#"""
        # A comment, and blank lines.

        title = "basic \"string\" \\ \t \u00E9 \U0001F510"   # a comment after a value
        path = 'C:\literal\string'
        "quoted key" = 1
        number = -1_080
        plus = +7
        yes = true
        no = false
        list = [
            "1.1.1.1",  # a comment in an array
            "8.8.8.8",
        ]
        empty = []
        dotted.key = "x"
        point = { x = 1, y = "two", inner.z = false }

        [proxy]
        port = 1080

        [[server]]
        name = "Tokyo"

        [[server]]
        name = "Frankfurt"

        [server.extra]
        note = "in the last server"
        """#)
        XCTAssertEqual(document["title"], .string("basic \"string\" \\ \t é 🔐"))
        XCTAssertEqual(document["path"], .string(#"C:\literal\string"#))
        XCTAssertEqual(document["quoted key"], .integer(1))
        XCTAssertEqual(document["number"], .integer(-1080))
        XCTAssertEqual(document["plus"], .integer(7))
        XCTAssertEqual(document["yes"], .boolean(true))
        XCTAssertEqual(document["no"], .boolean(false))
        XCTAssertEqual(document["list"], .array([.string("1.1.1.1"), .string("8.8.8.8")]))
        XCTAssertEqual(document["empty"], .array([]))
        XCTAssertEqual(document["dotted"], .table(["key": .string("x")]))
        XCTAssertEqual(document["point"], .table(["x": .integer(1), "y": .string("two"), "inner": .table(["z": .boolean(false)])]))
        XCTAssertEqual(document["proxy"], .table(["port": .integer(1080)]))
        XCTAssertEqual(document["server"], .array([
            .table(["name": .string("Tokyo")]),
            .table(["name": .string("Frankfurt"), "extra": .table(["note": .string("in the last server")])]),
        ]))
    }

    func testWindowsLineEndsAndNoFinalNewline() throws {
        XCTAssertEqual(try parseTOML("a = 1\r\n[t]\r\nb = \"x\""), ["a": .integer(1), "t": .table(["b": .string("x")])])
        XCTAssertEqual(try parseTOML(""), [:])
    }

    func testMistakesAreShownWithTheirLine() {
        func error(_ text: String) -> TOMLError? {
            do {
                _ = try parseTOML(text)
                return nil
            } catch {
                return error as? TOMLError
            }
        }
        XCTAssertEqual(error("a = 1\na = 2")?.line, 2)
        XCTAssertEqual(error("a = 1\na = 2")?.message, "“a” is set twice")
        XCTAssertEqual(error("[t]\nx = 1\n[t]")?.line, 3)
        XCTAssertEqual(error("\n\na = \"open")?.line, 3)
        XCTAssertEqual(error("a = \"open\nb = 1")?.line, 1)
        XCTAssertEqual(error("a = 1.5")?.line, 1, "floats are not needed")
        XCTAssertEqual(error("a = 2026-10-04")?.line, 1, "nor dates")
        XCTAssertEqual(error("a = \"\"\"long\"\"\"")?.message, "multi-line strings are not supported")
        XCTAssertEqual(error(#"a = "\q""#)?.line, 1)
        XCTAssertEqual(error("a = \"tab\u{1}\"")?.line, 1)
        XCTAssertEqual(error("a =\nb = 1")?.line, 1)
        XCTAssertEqual(error("a = 1 2")?.line, 1)
        XCTAssertEqual(error("a = [1, 2")?.line, 1)
        XCTAssertEqual(error("= 1")?.line, 1)
        XCTAssertEqual(error("a = 1\n[a]")?.line, 2)
        XCTAssertEqual(error("a = 1\n[[a]]")?.line, 2)
        XCTAssertEqual(error("x = 1\n\n\ny = maybe")?.localizedDescription.hasPrefix("Line 4: "), true)
    }

    func testWhatTheAppWritesIsReadBackTheSame() throws {
        for text in ["plain", #"q"uote b\ack"#, "Grüße 🔐", "", "tab\tnew\nline\rcr", "nul\u{0} del\u{7F} bell\u{7}", "next line\u{85}"] {
            XCTAssertEqual(try parseTOML("k = \(tomlString(text))")["k"], .string(text), text)
        }
    }

    func testMasqueClientConfigurationsAreRead() throws {
        // The files network-relay-nf-core's own tests read, as the app writes them.
        for name in ["domain-only", "transport-h2", "with-ip"] {
            let url = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "toml", subdirectory: "Fixtures"))
            let document = try parseTOML(String(contentsOf: url, encoding: .utf8))
            XCTAssertEqual(document["mode"], .string("socks"), name)
            guard case .table(let socks)? = document["socks"], case .array(let listen)? = socks["listen"] else {
                return XCTFail(name)
            }
            XCTAssertEqual(listen.count, 1, name)
        }
    }
}

final class ExportImportTests: XCTestCase {
    private let tokyo = Server(
        name: "Tokyo", domain: "vpn.example.com:8443", serverIP: "203.0.113.5", username: "macbook", password: "p\"a\\ss wörd 🔐",
        transport: .h2)
    private let frankfurt = Server(domain: "de.example.com", username: "mac-2", password: "pw")
    private var configuration: Configuration {
        Configuration(
            servers: [tokyo, frankfurt], selectedServerID: frankfurt.id, listenAddress: "::1", port: 1081, connectOnLaunch: true,
            logLevel: .detailed)
    }

    /// The same servers and proxy, whatever the servers' IDs.
    private func assertSame(_ a: Configuration, _ b: Configuration, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(a.servers.count, b.servers.count, file: file, line: line)
        for (x, y) in zip(a.servers, b.servers) {
            XCTAssertTrue(x.isSame(as: y), "\(x) and \(y)", file: file, line: line)
        }
        XCTAssertEqual(a.servers.firstIndex { $0.id == a.selectedServer?.id }, b.servers.firstIndex { $0.id == b.selectedServer?.id }, file: file, line: line)
        XCTAssertEqual(a.listenAddress, b.listenAddress, file: file, line: line)
        XCTAssertEqual(a.port, b.port, file: file, line: line)
        XCTAssertEqual(a.connectOnLaunch, b.connectOnLaunch, file: file, line: line)
    }

    func testTheExportedFile() {
        XCTAssertEqual(configuration.exportedTOML(withPasswords: true), #"""
        # Network Relay NF settings. Import them in Network Relay NF with Settings → Import….
        # The file holds the passwords: keep it private.

        [proxy]
        listen_address = "::1"
        port = 1081
        connect_on_launch = true
        log_level = "detailed"

        [[server]]
        id = "\#(tokyo.id.uuidString)"
        name = "Tokyo"
        domain = "vpn.example.com:8443"
        ip = "203.0.113.5"
        username = "macbook"
        password = "p\"a\\ss wörd 🔐"
        transport = "h2"

        [[server]]
        id = "\#(frankfurt.id.uuidString)"
        domain = "de.example.com"
        username = "mac-2"
        password = "pw"
        transport = "auto"
        selected = true

        """#)
    }

    func testExportedSettingsAreImportedTheSame() throws {
        let imported = try Configuration.importing(configuration.exportedTOML(withPasswords: true))
        assertSame(imported, configuration)
        XCTAssertEqual(imported.logLevel, .detailed)
        XCTAssertEqual(imported.servers.map(\.id), configuration.servers.map(\.id), "IDs survive export and import")
        XCTAssertNoThrow(try imported.check())
    }

    func testThePasswordsCanBeLeftOut() throws {
        let text = configuration.exportedTOML(withPasswords: false)
        XCTAssertFalse(text.contains("password ="))
        XCTAssertFalse(text.contains("wörd"))
        XCTAssertTrue(text.contains("# The passwords are left out: enter them after importing."))
        let imported = try Configuration.importing(text)
        XCTAssertEqual(imported.servers.map(\.password), ["", ""])
        XCTAssertEqual(imported.servers.map(\.domain), ["vpn.example.com:8443", "de.example.com"])
        XCTAssertThrowsError(try imported.check()) { error in
            XCTAssertEqual(error as? ServerError, ServerError(server: "Tokyo", reason: .missingPassword))
        }
    }

    func testAFileWrittenByHand() throws {
        let imported = try Configuration.importing("""
        [[server]]
        domain = "a.example.com"
        username = "u"
        password = "pw"
        future_option = 1

        [[server]]
        name = "B"
        domain = "b.example.com"
        username = "u"
        password = "pw"
        selected = true

        [[server]]
        domain = "c.example.com"
        selected = true
        """)
        XCTAssertEqual(imported.servers.map(\.title), ["a.example.com", "B", "c.example.com"])
        XCTAssertEqual(imported.selectedServer?.title, "B", "the first one marked")
        XCTAssertEqual(imported.servers[0].transport, .auto)
        XCTAssertEqual(imported.listenAddress, "127.0.0.1", "no [proxy]: the defaults")
        XCTAssertEqual(imported.port, 1080)
        XCTAssertFalse(imported.connectOnLaunch)
        let none = try Configuration.importing("[[server]]\ndomain = \"a.example.com\"\n[[server]]\ndomain = \"b.example.com\"\n")
        XCTAssertEqual(none.selectedServer?.domain, "a.example.com", "none marked: the first")
    }

    func testAMasqueClientConfigurationBecomesAServer() throws {
        // What the app gives network-relay-nf-core is what it takes back, and so
        // is a configuration written for network-relay-nf-core by hand.
        let cases: [(Settings, String)] = [
            (Settings(domain: "vpn.example.com:8443", username: "macbook"), "Zx9-kPq_4"),
            (Settings(serverIP: "203.0.113.5", domain: "masque.example.com", username: "macbook", listenAddress: "::1", port: 1081), "p\"a\\ss word"),
            (Settings(serverIP: "2001:db8::5", domain: "vpn.example.com:8443", username: "u", listenAddress: "0.0.0.0", port: 1, transport: .http1), "pw"),
            (Settings(domain: "vpn.example.com", username: "u", transport: .h3), "pw"),
        ]
        for (settings, password) in cases {
            let imported = try Configuration.importing(try clientConfiguration(settings, password: password))
            XCTAssertEqual(imported.servers.count, 1)
            XCTAssertEqual(imported.settings, settings, "\(settings)")
            XCTAssertEqual(imported.password, password)
            XCTAssertEqual(imported.selectedServer?.name, "")
        }
        let url = try XCTUnwrap(Bundle.module.url(forResource: "with-ip", withExtension: "toml", subdirectory: "Fixtures"))
        let fixture = try Configuration.importing(String(contentsOf: url, encoding: .utf8))
        XCTAssertEqual(fixture.selectedServer?.domain, "masque.example.com")
        XCTAssertEqual(fixture.selectedServer?.serverIP, "203.0.113.5")
        XCTAssertEqual(fixture.settings.proxyAddress, "[::1]:1081")
        // One for TUN mode has no [socks]: the proxy keeps its defaults.
        let tun = try Configuration.importing("""
        uri_template = "https://vpn.example.com/.well-known/masque/udp/{target_host}/{target_port}/"
        username = "u"
        password = "pw"
        mode = "tun"
        """)
        XCTAssertEqual(tun.selectedServer?.domain, "vpn.example.com")
        XCTAssertEqual(tun.settings.proxyAddress, "127.0.0.1:1080")
    }

    func testObsoleteSocksAuthenticationOptionsAreIgnoredOnImport() throws {
        let settings = Settings(serverIP: "203.0.113.5", domain: "vpn.example.com:8443", username: "macbook", listenAddress: "::1", port: 1081, transport: .h3)
        let text = try clientConfiguration(settings, password: "test-password")
            + "gssapi_keytab = \"/private/socks.keytab\"\ngssapi_principals = [\"alice@EXAMPLE.COM\"]\n"
        let imported = try Configuration.importing(text)
        XCTAssertEqual(imported.settings, settings)
        XCTAssertEqual(imported.password, "test-password")
        XCTAssertFalse(imported.connectOnLaunch)
        XCTAssertFalse(imported.exportedTOML(withPasswords: true).contains("gssapi"))
        XCTAssertFalse(try clientConfiguration(imported.settings, password: imported.password).contains("gssapi"))
    }

    func testFilesThatCannotBeImportedAreExplained() {
        func error(_ text: String) -> String {
            do {
                _ = try Configuration.importing(text)
                return "imported"
            } catch {
                return error.localizedDescription
            }
        }
        XCTAssertEqual(error("[[server]]\ndomain = \"a\nb\""), "The file is not a TOML settings file. Line 2: the string does not end on its line")
        XCTAssertEqual(error(#"{"settings":{}}"#).hasPrefix("The file is not a TOML settings file. Line 1: "), true, "a settings.json")
        XCTAssertEqual(error("title = \"something else\""), "The file holds neither Network Relay NF settings nor a network-relay-nf-core configuration.")
        XCTAssertEqual(error("[proxy]\nport = 1080"), "The file has no server ([[server]]).")
        XCTAssertEqual(error("[proxy]\nport = \"1080\"\n[[server]]\ndomain = \"a.example.com\""), "“port” in [proxy] must be a whole number.")
        XCTAssertEqual(error("[[server]]\ndomain = \"a.example.com\"\n[[server]]\ndomain = 5"), "“domain” in server 2 must be a string in quotes.")
        XCTAssertEqual(
            error("[[server]]\ndomain = \"a.example.com\"\ntransport = \"quic\""),
            "“transport” in server 1 must be one of “auto”, “h3”, “h2”, “http/1.1”.")
        XCTAssertEqual(error("proxy = 1\n[[server]]\ndomain = \"a.example.com\""), "“proxy” must be a table ([proxy]).")
        XCTAssertEqual(
            error(#"uri_template = "https://vpn.example.com/custom/{target}/{ipproto}/""#),
            "Network Relay NF connects to servers at https://<domain>/.well-known/masque/udp/{target_host}/{target_port}/; "
                + "this configuration's uri_template is https://vpn.example.com/custom/{target}/{ipproto}/.")
    }

    func testAddingServersSkipsThoseInTheListAlready() throws {
        var mine = Configuration(servers: [tokyo], selectedServerID: tokyo.id)
        let file = try Configuration.importing(configuration.exportedTOML(withPasswords: true))
        XCTAssertEqual(mine.add(serversOf: file), 1, "Tokyo is there already")
        XCTAssertEqual(mine.servers.count, 2)
        XCTAssertEqual(mine.servers[0], tokyo, "kept as it was")
        XCTAssertTrue(mine.servers[1].isSame(as: frankfurt))
        XCTAssertEqual(mine.servers[1].id, file.servers[1].id, "the imported ID is kept")
        XCTAssertEqual(mine.selectedServer, tokyo, "the server connected to stays")
        XCTAssertEqual(mine.add(serversOf: file), 0, "twice: nothing more")
        XCTAssertEqual(mine.add(serversOf: try Configuration.importing(configuration.exportedTOML(withPasswords: false))), 0)
        XCTAssertEqual(mine.servers.map(\.password), [tokyo.password, frankfurt.password], "omitted passwords stay available")
    }

    func testServersAndApplicationSettingsTravelSeparately() throws {
        let servers = configuration.exportedTOML(withPasswords: false, scope: .servers)
        XCTAssertFalse(servers.contains("[proxy]"))
        XCTAssertFalse(servers.contains("log_level"))
        XCTAssertFalse(servers.contains("password ="))
        let base = Configuration(listenAddress: "192.168.1.10", port: 8090, logLevel: .errors)
        let importedServers = try Configuration.importing(servers, scope: .servers, preserving: base)
        XCTAssertEqual(importedServers.servers.map(\.id), configuration.servers.map(\.id))
        XCTAssertEqual(importedServers.listenAddress, base.listenAddress)
        XCTAssertEqual(importedServers.port, base.port)
        XCTAssertEqual(importedServers.logLevel, base.logLevel)

        let application = configuration.exportedTOML(withPasswords: true, scope: .application)
        XCTAssertFalse(application.contains("[[server]]"))
        XCTAssertFalse(application.contains(tokyo.domain))
        XCTAssertFalse(application.contains(tokyo.username))
        XCTAssertFalse(application.contains(tokyo.password))
        let importedApplication = try Configuration.importing(application, scope: .application, preserving: Configuration(servers: [tokyo]))
        XCTAssertEqual(importedApplication.servers, [tokyo])
        XCTAssertEqual(importedApplication.listenAddress, configuration.listenAddress)
        XCTAssertEqual(importedApplication.port, configuration.port)
        XCTAssertEqual(importedApplication.connectOnLaunch, configuration.connectOnLaunch)
        XCTAssertEqual(importedApplication.logLevel, configuration.logLevel)
        XCTAssertThrowsError(try Configuration.importing(application)) { XCTAssertEqual($0 as? ImportError, .noServers) }
        XCTAssertThrowsError(try Configuration.importing(servers, scope: .application)) { XCTAssertEqual($0 as? ImportError, .notSettings) }
    }

    func testMissingApplicationFieldsKeepTheirCurrentValues() throws {
        let partial = try Configuration.importing("[proxy]\nport = 8090", scope: .application, preserving: configuration)
        XCTAssertEqual(partial.servers, configuration.servers)
        XCTAssertEqual(partial.selectedServerID, configuration.selectedServerID)
        XCTAssertEqual(partial.listenAddress, "::1")
        XCTAssertEqual(partial.port, 8090)
        XCTAssertTrue(partial.connectOnLaunch)
        XCTAssertEqual(partial.logLevel, .detailed)
        let legacy = try Configuration.importing("[[server]]\ndomain = \"a.example.com\"", preserving: configuration)
        XCTAssertEqual(legacy.listenAddress, "::1")
        XCTAssertEqual(legacy.port, 1081)
        XCTAssertTrue(legacy.connectOnLaunch)
        XCTAssertEqual(legacy.logLevel, .detailed)
        XCTAssertThrowsError(try Configuration.importing("[proxy]", scope: .application)) { XCTAssertEqual($0 as? ImportError, .notSettings) }
    }

    func testScopesDoNotReadUnrelatedSettings() throws {
        let app = try Configuration.importing("[proxy]\nport = 8090\n[[server]]\nid = \"broken\"", scope: .application, preserving: configuration)
        XCTAssertEqual(app.servers, configuration.servers)
        XCTAssertEqual(app.port, 8090)
        let servers = try Configuration.importing("[proxy]\nport = \"broken\"\n[[server]]\ndomain = \"a.example.com\"", scope: .servers, preserving: configuration)
        XCTAssertEqual(servers.servers.count, 1)
        XCTAssertEqual(servers.port, configuration.port)
    }

    func testIDsPermitUpdatesWithoutDuplicatingOrLosingPasswords() {
        var mine = configuration
        var updated = tokyo
        updated.name = "Tokyo Updated"
        updated.transport = .h3
        updated.password = ""
        let third = Server(name: "Third", domain: "third.example.com", username: "u", password: "pw")
        let incoming = Configuration(servers: [updated, third], selectedServerID: third.id)
        XCTAssertEqual(mine.add(serversOf: incoming), 1)
        XCTAssertEqual(mine.servers.map(\.id), [tokyo.id, frankfurt.id, third.id])
        XCTAssertEqual(mine.servers[0].name, "Tokyo Updated")
        XCTAssertEqual(mine.servers[0].transport, .h3)
        XCTAssertEqual(mine.servers[0].password, tokyo.password)
        XCTAssertEqual(mine.selectedServerID, frankfurt.id, "Add keeps the current server")
        XCTAssertEqual(mine.add(serversOf: incoming, replacing: true), 0)
        XCTAssertEqual(mine.servers.map(\.id), [tokyo.id, third.id])
        XCTAssertEqual(mine.servers[0].password, tokyo.password)
        XCTAssertEqual(mine.selectedServerID, third.id, "Replace follows the file's server")
        var twin = tokyo
        twin.id = UUID()
        var withoutPassword = twin
        withoutPassword.password = ""
        var identicalProfiles = Configuration(servers: [tokyo, twin], selectedServerID: twin.id)
        XCTAssertEqual(identicalProfiles.add(serversOf: Configuration(servers: [withoutPassword])), 0)
        XCTAssertEqual(identicalProfiles.servers, [tokyo, twin], "UUID matching wins over an identical earlier profile")
    }

    func testLegacyMatchingKeepsPasswordsIDsAndReplacementSelection() {
        var a = tokyo
        var b = frankfurt
        a.id = UUID(); b.id = UUID()
        a.password = ""; b.password = ""
        let incoming = Configuration(servers: [b, a], selectedServerID: b.id)
        var mine = configuration
        XCTAssertEqual(mine.add(serversOf: incoming), 0)
        XCTAssertEqual(mine.servers, configuration.servers)
        XCTAssertEqual(mine.add(serversOf: incoming, replacing: true), 0)
        XCTAssertEqual(mine.servers, [frankfurt, tokyo])
        XCTAssertEqual(mine.selectedServerID, frankfurt.id, "the imported selection maps to its retained ID")
        for edit in ["name", "transport", "password"] {
            var different = tokyo
            different.id = UUID()
            if edit == "name" { different.name = "Another Profile" }
            if edit == "transport" { different.transport = .h3 }
            if edit == "password" { different.password = "another password" }
            var profiles = Configuration(servers: [tokyo])
            XCTAssertEqual(profiles.add(serversOf: Configuration(servers: [different])), 1, edit)
            XCTAssertEqual(profiles.servers.count, 2, edit)
        }
    }

    func testUpdatedIDsAndLegacyProfilesRemainDistinctInEitherOrder() throws {
        let updated = """
        [[server]]
        id = "\(tokyo.id.uuidString)"
        domain = "new.example.com"
        username = "new-user"
        password = "new-password"
        """
        var old = configuration
        old.selectedServerID = tokyo.id
        let legacy = old.exportedTOML(withPasswords: true, scope: .servers)
            .replacingOccurrences(of: "id = \(tomlString(tokyo.id.uuidString))\n", with: "")
        for text in [updated + "\n" + legacy, legacy + "\n" + updated] {
            let incoming = try Configuration.importing(text)
            for replacing in [false, true] {
                var mine = configuration
                XCTAssertEqual(mine.add(serversOf: incoming, replacing: replacing), 1)
                XCTAssertEqual(mine.servers.count, 3)
                XCTAssertEqual(mine.servers.first { $0.id == tokyo.id }?.domain, "new.example.com")
                XCTAssertEqual(mine.servers.filter { $0.domain == tokyo.domain }.count, 1)
                XCTAssertEqual(mine.selectedServer?.domain, replacing ? tokyo.domain : frankfurt.domain)
            }
        }
        let explicit = Configuration(servers: [tokyo]).exportedTOML(withPasswords: false, scope: .servers)
        let sameLegacy = explicit.replacingOccurrences(of: "id = \(tomlString(tokyo.id.uuidString))\n", with: "")
        for text in [explicit + "\n" + sameLegacy, sameLegacy + "\n" + explicit] {
            let incoming = try Configuration.importing(text)
            for replacing in [false, true] {
                var mine = configuration
                XCTAssertEqual(mine.add(serversOf: incoming, replacing: replacing), 0)
                XCTAssertEqual(mine.servers, replacing ? [tokyo] : configuration.servers, "identical UUID and legacy profiles still deduplicate")
                XCTAssertEqual(mine.selectedServer?.id, replacing ? tokyo.id : frankfurt.id)
            }
        }
    }

    func testInvalidIDsApplicationValuesAndClientListenersAreRejected() throws {
        for id in ["broken", "123"] {
            XCTAssertThrowsError(try Configuration.importing("[[server]]\nid = \"\(id)\"\ndomain = \"a.example.com\""))
        }
        let duplicate = "[[server]]\nid = \"\(tokyo.id.uuidString)\"\n[[server]]\nid = \"\(tokyo.id.uuidString)\""
        XCTAssertThrowsError(try Configuration.importing(duplicate))
        for fields in ["log_level = \"broken\"", "port = 0", "listen_address = \"not an IP\""] {
            XCTAssertThrowsError(try Configuration.importing("[proxy]\n" + fields, scope: .application))
        }
        let client = try clientConfiguration(Settings(domain: "vpn.example.com", username: "u"), password: "pw")
        for listen in ["garbage", "127.0.0.1:bad", "127.0.0.1:0", "127.0.0.1:65536", "::1:1080", "[::1]:bad"] {
            let broken = client.replacingOccurrences(of: "127.0.0.1:1080", with: listen)
            XCTAssertThrowsError(try Configuration.importing(broken), listen)
        }
        let serverOnly = try Configuration.importing(client.replacingOccurrences(of: "127.0.0.1:1080", with: "garbage"), scope: .servers, preserving: configuration)
        XCTAssertEqual(serverOnly.selectedServer?.domain, "vpn.example.com")
        XCTAssertEqual(serverOnly.port, configuration.port, "server-only import ignores unrelated listener values")
        XCTAssertThrowsError(try Configuration.importing(client.replacingOccurrences(of: "[\"127.0.0.1:1080\"]", with: "[]")))
        XCTAssertThrowsError(try Configuration.importing(client.replacingOccurrences(of: "[\"127.0.0.1:1080\"]", with: "[\"127.0.0.1:1080\", \"garbage\"]")))
        let application = try Configuration.importing(client, scope: .application, preserving: configuration)
        XCTAssertEqual(application.servers, configuration.servers)
        XCTAssertEqual(application.selectedServerID, configuration.selectedServerID)
        XCTAssertEqual(application.port, 1080)
        XCTAssertEqual(application.listenAddress, "127.0.0.1")
        XCTAssertThrowsError(try Configuration.importing(client.replacingOccurrences(of: "[socks]\nlisten = [\"127.0.0.1:1080\"]", with: ""), scope: .application)) {
            XCTAssertEqual($0 as? ImportError, .notSettings)
        }
    }
}
