import Foundation
import XCTest
@testable import NetworkRelayTunModel

final class InputSafetyTests: XCTestCase {
    func testPrivateWriteLeavesUnrelatedStagingNameAlone() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let output = folder.appendingPathComponent("settings.json")
        let unrelated = folder.appendingPathComponent("settings.json.new")
        try Data("unrelated".utf8).write(to: unrelated)
        try writePrivately(Data("complete credentials".utf8), to: output)
        XCTAssertEqual(try Data(contentsOf: unrelated), Data("unrelated".utf8))
        XCTAssertEqual(try Data(contentsOf: output), Data("complete credentials".utf8))
        let attributes = try FileManager.default.attributesOfItem(atPath: output.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }

    func testPrivateWriteReplacesSymlinkWithoutWritingThroughIt() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let original = folder.appendingPathComponent("original")
        let output = folder.appendingPathComponent("export.toml")
        try Data("unchanged".utf8).write(to: original)
        try FileManager.default.createSymbolicLink(at: output, withDestinationURL: original)
        try writePrivately(Data("export".utf8), to: output)
        XCTAssertEqual(try Data(contentsOf: original), Data("unchanged".utf8))
        XCTAssertEqual(try Data(contentsOf: output), Data("export".utf8))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: folder.path).sorted(), ["export.toml", "original"])
    }

    func testFailedPrivateWriteRemovesItsTemporaryFile() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let output = folder.appendingPathComponent("directory")
        try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        XCTAssertThrowsError(try writePrivately(Data("secret".utf8), to: output))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: folder.path), ["directory"])
    }

    func testTOMLInputIsBoundedBeforeScalarExpansion() throws {
        XCTAssertEqual(try parseTOML("#" + String(repeating: " ", count: (4 << 20) - 1)), [:])
        XCTAssertThrowsError(try parseTOML("#" + String(repeating: " ", count: 4 << 20)))
        XCTAssertThrowsError(try parseTOML("#" + String(repeating: "x", count: (4 << 20) + 1)))
    }

    func testFileImportBoundsBytesAndPreservesUTF8Errors() throws {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: file) }
        let text = "[proxy]\nport = 1081\n"
        try Data(text.utf8).write(to: file)
        let imported = try Configuration.importing(readSettingsText(from: file), scope: .application)
        XCTAssertEqual(imported.port, 1081)
        try Data([0xff]).write(to: file)
        XCTAssertThrowsError(try readSettingsText(from: file))
        try Data().write(to: file)
        let handle = try FileHandle(forWritingTo: file)
        try handle.truncate(atOffset: 16 << 20)
        try handle.close()
        XCTAssertThrowsError(try readSettingsText(from: file)) { error in
            XCTAssertEqual((error as? TOMLError)?.message, "the settings file exceeds 4 MiB")
        }
    }

    func testTOMLRecursiveValuesAndDottedTablesAreBounded() throws {
        let modest = "x = " + String(repeating: "[", count: 32) + "0" + String(repeating: "]", count: 32)
        XCTAssertNoThrow(try parseTOML(modest))
        let deep = "x = " + String(repeating: "[", count: 128) + "0" + String(repeating: "]", count: 128)
        XCTAssertThrowsError(try parseTOML(deep))
        let path = Array(repeating: "table", count: 128).joined(separator: ".")
        XCTAssertThrowsError(try parseTOML("[" + path + "]"))
        XCTAssertThrowsError(try parseTOML(path + " = 1"))
        XCTAssertThrowsError(try parseTOML("x = {" + path + " = 1}"))
        let parent = Array(repeating: "parent", count: 40).joined(separator: ".")
        let child = Array(repeating: "child", count: 40).joined(separator: ".")
        XCTAssertThrowsError(try parseTOML("[" + parent + "]\n" + child + " = 1"))
    }
}
