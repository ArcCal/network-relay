import Foundation
import NetworkRelayTunModel

/// This project never adopts, changes or removes another app's data.
enum Store {
    private static var storage: SettingsStorage {
        SettingsStorage(applicationSupportDirectory:
            FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0])
    }
    static var folder: URL { storage.folder }
    static func load() -> Configuration { storage.load() }
    static func save(_ configuration: Configuration) throws { try storage.save(configuration) }
    static func eraseEverything() {
        storage.eraseEverything()
        let fm = FileManager.default
        guard Bundle.main.bundleIdentifier == SettingsStorage.bundleIdentifier else { return }
        let library = fm.urls(for: .libraryDirectory, in: .userDomainMask)[0]
        for id in [SettingsStorage.bundleIdentifier, SettingsStorage.legacyBundleIdentifier] {
            UserDefaults.standard.removePersistentDomain(forName: id)
            for path in ["Preferences/\(id).plist", "Saved Application State/\(id).savedState", "Caches/\(id)", "HTTPStorages/\(id)", "WebKit/\(id)"] {
                try? fm.removeItem(at: library.appendingPathComponent(path))
            }
        }
    }
}
