import Foundation

/// Display metadata embedded in the app bundle; opening About runs no client.
struct AppInformation {
    let version: String
    let coreVersion: String
    let sourceRevision: String
    let builtAt: Date?

    init(info: [String: Any] = Bundle.main.infoDictionary ?? [:]) {
        let appVersion = info["CFBundleShortVersionString"] as? String ?? ""
        let clientVersion = info["NetworkRelayNFCoreVersion"] as? String ?? ""
        coreVersion = clientVersion.isEmpty ? "Unknown" : clientVersion
        let source = info["NetworkRelayNFSourceRevision"] as? String ?? ""
        sourceRevision = source.isEmpty ? "Unknown" : source
        // Without a version, the commit identifies the build.
        version = appVersion.isEmpty ? sourceRevision : appVersion
        // Local builds have a build timestamp, without claiming a release was published.
        guard let timestamp = info["NetworkRelayNFBuildAt"] as? String else {
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

    /// The build time in local time, formatted as Network Relay RS shows it.
    var builtText: String {
        guard let builtAt else { return "Unknown" }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss xxx"
        return formatter.string(from: builtAt)
    }
}
