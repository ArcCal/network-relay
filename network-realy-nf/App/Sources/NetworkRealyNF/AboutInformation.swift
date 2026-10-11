import Foundation

/// Display metadata embedded in the app bundle; opening About runs no client.
struct AppInformation {
    let version: String
    let coreVersion: String
    let builtAt: Date?

    init(info: [String: Any] = Bundle.main.infoDictionary ?? [:]) {
        let appVersion = info["CFBundleShortVersionString"] as? String ?? ""
        let clientVersion = info["NetworkRealyNFCoreVersion"] as? String ?? ""
        version = appVersion.isEmpty ? "Unknown" : appVersion
        coreVersion = clientVersion.isEmpty ? "Unknown" : clientVersion
        // Local builds have a build timestamp, without claiming a release was published.
        guard let timestamp = info["NetworkRealyNFBuildAt"] as? String else {
            builtAt = nil
            return
        }
        let formatter = ISO8601DateFormatter()
        if let date = formatter.date(from: timestamp) {
            builtAt = date
        } else {
            formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            builtAt = formatter.date(from: timestamp)
        }
    }
}
