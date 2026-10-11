import XCTest
@testable import NetworkRealyNFModel

/// The settings file in ~/Library/Application Support/IETFMasque, here in a
/// temporary folder.
final class SavedSettingsTests: XCTestCase {
    private var root: URL!
    private var folder: URL { root.appendingPathComponent("IETFMasque", isDirectory: true) }
    private var file: URL { folder.appendingPathComponent("settings.json") }

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("NetworkRealyNFModelTests-\(UUID().uuidString)", isDirectory: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: root)
    }

    private func permissions(_ url: URL) throws -> Int {
        let value = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions]
        return try XCTUnwrap(value as? NSNumber).intValue & 0o777
    }

    private func write(_ text: String) throws {
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        try Data(text.utf8).write(to: file)
    }

    private var files: [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: folder.path).sorted()) ?? []
    }

    /// Two servers, the second one connected to.
    private let tokyo = Server(name: "Tokyo", domain: "vpn.example.com:8443", serverIP: "203.0.113.5", username: "macbook", password: "p\"a\\ss wörd 🔐", transport: .h2)
    private let frankfurt = Server(name: "Frankfurt", domain: "de.example.com", username: "macbook", password: "other")
    private var two: Configuration {
        Configuration(
            servers: [tokyo, frankfurt], selectedServerID: frankfurt.id, listenAddress: "::1", port: 1081, connectOnLaunch: true,
            logLevel: .detailed)
    }

    /// The server a file of 1.3 or earlier describes.
    private func oneServer(
        domain: String = "vpn.example.com", username: String = "u", password: String = "pw", transport: Transport = .auto,
        connectOnLaunch: Bool = false
    ) -> Configuration {
        Configuration(
            servers: [Server(id: Server.firstID, domain: domain, username: username, password: password, transport: transport)],
            selectedServerID: Server.firstID, connectOnLaunch: connectOnLaunch)
    }

    func testNothingSavedMeansTheDefaults() {
        let nothing = Configuration.load(from: file)
        XCTAssertEqual(nothing, Configuration())
        XCTAssertEqual(nothing.servers, [])
        XCTAssertNil(nothing.selectedServer)
        XCTAssertEqual(nothing.settings, Settings())
        XCTAssertEqual(nothing.password, "")
        XCTAssertEqual(nothing.logLevel, .normal)
    }

    func testWhatIsSavedComesBackAndOnlyTheUserCanReadIt() throws {
        try two.save(to: file)
        XCTAssertEqual(Configuration.load(from: file), two)
        XCTAssertEqual(try permissions(file), 0o600)
        XCTAssertEqual(try permissions(folder), 0o700)
        XCTAssertEqual(files, ["settings.json"], "no temporary file is left")
    }

    func testSavingReplacesTheOldFileAndMakesItAndTheFolderPrivate() throws {
        // An old, longer file that others could read, in a folder others
        // could open, and a temporary file left by a crash.
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: folder.path)
        XCTAssertTrue(FileManager.default.createFile(
            atPath: file.path, contents: Data(String(repeating: "x", count: 10_000).utf8), attributes: [.posixPermissions: 0o644]))
        XCTAssertTrue(FileManager.default.createFile(atPath: file.path + ".new", contents: Data("junk".utf8)))
        let saved = oneServer()
        try saved.save(to: file)
        XCTAssertEqual(Configuration.load(from: file), saved, "nothing of the old file is left")
        XCTAssertEqual(try permissions(file), 0o600)
        XCTAssertEqual(try permissions(folder), 0o700)
        XCTAssertEqual(files, ["settings.json"])
        // And again, over the file just saved.
        var changed = saved
        changed.servers[0].password = "new"
        try changed.save(to: file)
        XCTAssertEqual(Configuration.load(from: file), changed)
    }

    func testAFileOf13AndEarlierBecomesOneServer() throws {
        // As 0.6.0 saved it, before the transport option.
        try write(#"{"settings":{"serverIP":"","domain":"vpn.example.com","username":"u","listenAddress":"127.0.0.1","port":1080,"connectOnLaunch":false},"password":"pw"}"#)
        XCTAssertEqual(Configuration.load(from: file), oneServer())
        // As 1.0 to 1.3 saved it.
        try write(#"{"settings":{"serverIP":"203.0.113.5","domain":"vpn.example.com:8443","username":"u","listenAddress":"::1","port":1081,"connectOnLaunch":true,"transport":"h3"},"password":"pw"}"#)
        let loaded = Configuration.load(from: file)
        XCTAssertEqual(loaded.servers, [Server(id: Server.firstID, domain: "vpn.example.com:8443", serverIP: "203.0.113.5", username: "u", password: "pw", transport: .h3)])
        XCTAssertEqual(loaded.selectedServer, loaded.servers.first)
        XCTAssertEqual(loaded.listenAddress, "::1")
        XCTAssertEqual(loaded.port, 1081)
        XCTAssertTrue(loaded.connectOnLaunch)
        XCTAssertEqual(loaded.logLevel, .normal)
        XCTAssertEqual(Configuration.load(from: file), loaded, "the same server every time the file is read")
        // It runs the client as that version did.
        XCTAssertEqual(
            try clientConfiguration(loaded.settings, password: loaded.password),
            try clientConfiguration(
                Settings(serverIP: "203.0.113.5", domain: "vpn.example.com:8443", username: "u", listenAddress: "::1", port: 1081, connectOnLaunch: true, transport: .h3),
                password: "pw"))
    }

    func testAnEarlierVersionStillReadsTheServerConnectedTo() throws {
        // Going back to 1.3 or earlier: they read `settings` and `password`
        // and see the server connected to; the others are only in the list.
        try two.save(to: file)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
        XCTAssertEqual(Set(object.keys), ["servers", "selectedServer", "logLevel", "settings", "password"])
        let settings = try XCTUnwrap(object["settings"] as? [String: Any])
        XCTAssertEqual(Set(settings.keys), ["serverIP", "domain", "username", "listenAddress", "port", "connectOnLaunch", "transport"])
        XCTAssertEqual(settings["domain"] as? String, "de.example.com")
        XCTAssertEqual(settings["port"] as? Int, 1081)
        XCTAssertEqual(object["password"] as? String, "other")
        XCTAssertEqual(object["selectedServer"] as? String, frankfurt.id.uuidString)
        XCTAssertEqual(object["logLevel"] as? String, "detailed")
        // What 1.3 made of it.
        struct Version13: Codable {
            var settings: Settings
            var password: String
        }
        let old = try JSONDecoder().decode(Version13.self, from: Data(contentsOf: file))
        XCTAssertEqual(old.settings, two.settings)
        XCTAssertEqual(old.password, "other")
        // And when 1.3 saves again, only that server is left.
        try JSONEncoder().encode(old).write(to: file)
        XCTAssertEqual(Configuration.load(from: file).servers.map(\.domain), ["de.example.com"])
    }

    func testWhatCanBeReadIsKept() throws {
        // A field of another type, a value this version does not know and
        // a field it has never heard of, as a later version might save.
        try write(#"{"settings":{"serverIP":"","domain":"vpn.example.com","username":"u","listenAddress":"127.0.0.1","port":"1080","connectOnLaunch":true,"transport":"h4","newOption":1},"password":"pw"}"#)
        XCTAssertEqual(Configuration.load(from: file), oneServer(connectOnLaunch: true))
        // Settings that cannot be read at all: the password is still kept.
        try write(#"{"settings":[1,2],"password":"pw"}"#)
        XCTAssertEqual(Configuration.load(from: file).servers.map(\.password), ["pw"])
        try write(#"{"settings":{"domain":"vpn.example.com"}}"#)
        XCTAssertEqual(Configuration.load(from: file).servers.map(\.domain), ["vpn.example.com"])
        for broken in ["", "not json", "[]", #"{"settings":"#] {
            try write(broken)
            XCTAssertEqual(Configuration.load(from: file), Configuration(), broken)
        }
        // In the list: a server that is not one is skipped, a field that
        // cannot be read takes its default, a server without an ID gets one.
        let id = UUID()
        try write("""
        {"servers":[{"id":"\(id.uuidString)","name":"A","domain":"a.example.com","username":"u","password":"pw","transport":"quic"},
        "not a server",{"domain":"b.example.com","username":7}],"selectedServer":"\(UUID().uuidString)","logLevel":"loud",
        "settings":{"listenAddress":"127.0.0.1","port":1090}}
        """)
        let loaded = Configuration.load(from: file)
        XCTAssertEqual(loaded.servers.count, 2)
        XCTAssertEqual(loaded.servers[0], Server(id: id, name: "A", domain: "a.example.com", username: "u", password: "pw"))
        XCTAssertEqual(loaded.servers[1].domain, "b.example.com")
        XCTAssertEqual(loaded.servers[1].username, "")
        XCTAssertNotEqual(loaded.servers[1].id, id)
        XCTAssertEqual(loaded.selectedServerID, id, "an unknown server connected to: the first")
        XCTAssertEqual(loaded.logLevel, .normal)
        XCTAssertEqual(loaded.port, 1090)
        // Two servers with the same ID, as a file edited by hand may have.
        try write(#"{"servers":[{"id":"\#(id.uuidString)","domain":"a.example.com"},{"id":"\#(id.uuidString)","domain":"b.example.com"}],"selectedServer":"\#(id.uuidString)"}"#)
        let twins = Configuration.load(from: file)
        XCTAssertEqual(Set(twins.servers.map(\.id)).count, 2)
        XCTAssertEqual(twins.selectedServer?.domain, "a.example.com")
        // An empty list stays empty.
        try write(#"{"servers":[],"settings":{"domain":"old.example.com","username":"u"},"password":"pw"}"#)
        XCTAssertEqual(Configuration.load(from: file).servers, [], "the list, not the copy for earlier versions, counts")
    }

    func testCloudflareSettingsOfEarly070BuildsAreIgnoredAndDropped() throws {
        // A device registered with Cloudflare WARP, from a build that had
        // the option: there is no server of its own to connect to, and the
        // next save removes the device's key from the file.
        try write(#"""
        {"settings":{"serverKind":"cloudflare","serverIP":"","domain":"","username":"","listenAddress":"127.0.0.1","port":1080,
        "connectOnLaunch":true,"transport":"h2","cloudflareIPv6":true,"cloudflare":{"device_id":"example-device-id","private_key":"SECRET-KEY",
        "endpoint_v4":"192.0.2.10:0"}},"password":""}
        """#)
        let loaded = Configuration.load(from: file)
        XCTAssertEqual(loaded, Configuration(connectOnLaunch: true))
        XCTAssertThrowsError(try clientConfiguration(loaded.settings, password: loaded.password)) { error in
            XCTAssertEqual(error as? SettingsError, .missingDomain)
        }
        try loaded.save(to: file)
        let text = try String(contentsOf: file, encoding: .utf8)
        XCTAssertFalse(text.contains("SECRET-KEY"))
        XCTAssertFalse(text.contains("cloudflare"))
        // Its own server settings, saved alongside, are kept.
        try write(#"{"settings":{"serverKind":"own","serverIP":"","domain":"vpn.example.com","username":"u","listenAddress":"127.0.0.1","port":1080,"connectOnLaunch":false,"transport":"auto","cloudflareIPv6":false},"password":"pw"}"#)
        XCTAssertEqual(Configuration.load(from: file), oneServer())
    }

    func testCFMasqueSettingsOf11To13AreIgnoredAndDropped() throws {
        // 1.1 to 1.3 could run cf-masque instead: the masque-vpn settings
        // saved alongside are kept, the protocol choice and the Cloudflare
        // device (its key included) are ignored, and the next save removes
        // them from the file.
        try write(#"""
        {"settings":{"protocol":"cf-masque","serverIP":"","domain":"vpn.example.com","username":"u","listenAddress":"127.0.0.1",
        "port":1080,"connectOnLaunch":true,"transport":"h3","cfMasque":{"privateKey":"SECRET-KEY","endpointV4":"192.0.2.10",
        "tunnelIPv4":"172.16.0.2","serverPort":443,"transport":"h2"}},"password":"pw"}
        """#)
        let loaded = Configuration.load(from: file)
        XCTAssertEqual(loaded, oneServer(transport: .h3, connectOnLaunch: true))
        XCTAssertTrue(try clientConfiguration(loaded.settings, password: loaded.password).contains("transport = \"h3\""))
        try loaded.save(to: file)
        let text = try String(contentsOf: file, encoding: .utf8)
        XCTAssertFalse(text.contains("SECRET-KEY"))
        XCTAssertFalse(text.contains("cfMasque"))
        XCTAssertFalse(text.contains("protocol"))
    }

    func testSavingWhereTheFolderCannotBeMadeFails() throws {
        // A file where the folder should be.
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        XCTAssertTrue(FileManager.default.createFile(atPath: folder.path, contents: Data()))
        XCTAssertThrowsError(try Configuration().save(to: file))
    }

    func testWritingPrivatelyLeavesTheFolderAsItIs() throws {
        // What Export writes: private, but in a folder the user chose,
        // whose permissions are not the app's to change.
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: root.path)
        let exported = root.appendingPathComponent("Network Realy NF Settings.toml")
        try writePrivately(Data("old, longer content".utf8), to: exported)
        try writePrivately(Data("new".utf8), to: exported)
        XCTAssertEqual(try String(contentsOf: exported, encoding: .utf8), "new")
        XCTAssertEqual(try permissions(exported), 0o600)
        XCTAssertEqual(try permissions(root), 0o755)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.path), ["Network Realy NF Settings.toml"])
    }
}
