import Foundation

/// The corrected application name uses a new settings directory. An existing
/// installation's settings are read from its former directory until the user
/// saves them under the corrected name.
public struct SettingsStorage {
    public static let bundleIdentifier = "com.arccal.network-relay-tun"
    /// Kept only to remove preferences belonging to this app's former name.
    public static let legacyBundleIdentifier = "com.arccal.network-realy-tun"

    public let folder: URL
    /// The misspelled name is retained only for existing installations.
    public let legacyFolder: URL

    public init(applicationSupportDirectory: URL) {
        folder = applicationSupportDirectory.appendingPathComponent("NetworkRelayTun", isDirectory: true)
        legacyFolder = applicationSupportDirectory.appendingPathComponent("NetworkRealyTun", isDirectory: true)
    }

    public var settingsFile: URL { folder.appendingPathComponent("settings.json") }
    public var legacySettingsFile: URL { legacyFolder.appendingPathComponent("settings.json") }

    public func load() -> Configuration {
        let file = FileManager.default.fileExists(atPath: settingsFile.path) ? settingsFile : legacySettingsFile
        return Configuration.load(from: file)
    }

    public func save(_ configuration: Configuration) throws {
        try configuration.save(to: settingsFile)
    }

    /// Both names identify this application. Leave other applications' data
    /// alone, including when only the former directory exists.
    public func eraseEverything() {
        for directory in [folder, legacyFolder] {
            try? FileManager.default.removeItem(at: directory)
        }
    }
}
