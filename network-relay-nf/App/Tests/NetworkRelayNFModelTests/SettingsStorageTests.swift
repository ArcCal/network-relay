import XCTest
@testable import NetworkRelayNFModel

final class SettingsStorageTests: XCTestCase {
    private var root: URL!
    private var storage: SettingsStorage { SettingsStorage(applicationSupportDirectory: root) }

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("NetworkRelayNFStorageTests-\(UUID())", isDirectory: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: root)
    }

    private func configuration() -> Configuration {
        let first = Server(name: "First", domain: "first.example.com", username: "first", password: "first-password", transport: .h2)
        let selected = Server(name: "Selected", domain: "second.example.com:8443", serverIP: "203.0.113.5", username: "second", password: "p\"a\\ss wörd 🔐", transport: .h3)
        return Configuration(
            servers: [first, selected], selectedServerID: selected.id, listenAddress: "::1", port: 1081,
            connectOnLaunch: true, logLevel: .everything, gssapiKeytab: "/private/user.keytab", gssapiPrincipals: "client@EXAMPLE.COM")
    }

    func testNoInstallationReturnsTheDefaults() {
        XCTAssertEqual(storage.load(), Configuration())
        XCTAssertEqual(storage.folder.lastPathComponent, "NetworkRelayNF")
    }

    func testExistingInstallationKeepsAllSettingsWithoutChangingItsFile() throws {
        let saved = configuration()
        try saved.save(to: storage.legacySettingsFile)
        let original = try Data(contentsOf: storage.legacySettingsFile)
        XCTAssertEqual(storage.load(), saved)
        XCTAssertEqual(try Data(contentsOf: storage.legacySettingsFile), original)
        XCTAssertFalse(FileManager.default.fileExists(atPath: storage.folder.path))
    }

    func testCorrectedInstallationTakesPriorityOverFormerSettings() throws {
        let former = configuration()
        try former.save(to: storage.legacySettingsFile)
        var current = former
        current.selectedServerID = current.servers[0].id
        current.servers[0].password = "current-password"
        current.port = 1090
        try current.save(to: storage.settingsFile)
        XCTAssertEqual(storage.load(), current)
    }

    func testAnEmptyCorrectedInstallationDoesNotReviveFormerServers() throws {
        try configuration().save(to: storage.legacySettingsFile)
        try Configuration().save(to: storage.settingsFile)
        XCTAssertEqual(storage.load(), Configuration())
    }

    func testInvalidCorrectedSettingsDoNotFallBackToFormerCredentials() throws {
        try configuration().save(to: storage.legacySettingsFile)
        try FileManager.default.createDirectory(at: storage.folder, withIntermediateDirectories: true)
        try Data("not JSON".utf8).write(to: storage.settingsFile)
        XCTAssertEqual(storage.load(), Configuration())
    }

    func testFirstSaveWritesCorrectedPrivateSettingsAndKeepsTheFormerCopy() throws {
        let former = configuration()
        try former.save(to: storage.legacySettingsFile)
        let original = try Data(contentsOf: storage.legacySettingsFile)
        var saved = storage.load()
        saved.port = 1090
        try storage.save(saved)
        XCTAssertEqual(storage.load(), saved)
        XCTAssertEqual(Configuration.load(from: storage.settingsFile), saved)
        XCTAssertEqual(try Data(contentsOf: storage.legacySettingsFile), original)
        let attributes = try FileManager.default.attributesOfItem(atPath: storage.settingsFile.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        let directoryAttributes = try FileManager.default.attributesOfItem(atPath: storage.folder.path)
        XCTAssertEqual((directoryAttributes[.posixPermissions] as? NSNumber)?.intValue, 0o700)
    }

    func testErasingRemovesBothNamesWithoutChangingOtherApplications() throws {
        try configuration().save(to: storage.legacySettingsFile)
        try storage.save(configuration())
        let other = root.appendingPathComponent("NetworkRelayRS/settings.json")
        try configuration().save(to: other)
        let original = try Data(contentsOf: other)
        storage.eraseEverything()
        XCTAssertFalse(FileManager.default.fileExists(atPath: storage.folder.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: storage.legacyFolder.path))
        XCTAssertEqual(try Data(contentsOf: other), original)
        XCTAssertEqual(storage.load(), Configuration())
    }

    func testErasingAlsoRemovesAnInstallationThatHasNotSavedUnderTheCorrectedName() throws {
        try configuration().save(to: storage.legacySettingsFile)
        storage.eraseEverything()
        XCTAssertFalse(FileManager.default.fileExists(atPath: storage.legacyFolder.path))
        XCTAssertEqual(storage.load(), Configuration())
    }
}
