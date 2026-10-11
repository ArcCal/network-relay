import Foundation
import NetworkRealyNFModel

/// This project never adopts, changes or removes another app's data.
enum Store {
    static var folder: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("NetworkRealyNF", isDirectory: true)
    }
    private static var settingsFile: URL { folder.appendingPathComponent("settings.json") }
    static func load() -> Configuration { Configuration.load(from: settingsFile) }
    static func save(_ configuration: Configuration) throws { try configuration.save(to: settingsFile) }
    static func eraseEverything() {
        let fm = FileManager.default
        try? fm.removeItem(at: folder)
        guard let id = Bundle.main.bundleIdentifier, id == "com.arccal.network-realy-nf" else { return }
        UserDefaults.standard.removePersistentDomain(forName: id)
        let library = fm.urls(for: .libraryDirectory, in: .userDomainMask)[0]
        for path in ["Preferences/\(id).plist", "Saved Application State/\(id).savedState", "Caches/\(id)", "HTTPStorages/\(id)", "WebKit/\(id)"] {
            try? fm.removeItem(at: library.appendingPathComponent(path))
        }
    }
}
