// Adapted from Masque NF; independent Network Relay NF copy.
import Foundation

/// Keep chronological order and a bounded buffer. Verbose I/O must not evict
/// earlier operation, connection and failure records while verbose lines remain.
public func appendClientLog(_ incoming: [String], to log: inout [String], limit: Int = 5000) {
    precondition(limit > 0)
    log.append(contentsOf: incoming)
    guard log.count > limit else { return }
    var excess = log.count - limit
    log = log.filter { line in
        guard excess > 0 else { return true }
        let level = messageLogLevel(line)
        if level == .detailed || level == .everything {
            excess -= 1
            return false
        }
        return true
    }
    // Important records are bounded too; once no verbose lines can be removed,
    // retain the latest important records rather than grow without limit.
    if excess > 0 { log.removeFirst(excess) }
}

/// The state the menu shows.
public enum Status: Equatable {
    /// Not running.
    case stopped
    /// Started, relay admission has not completed yet.
    case connecting
    /// The relay authenticated and admitted a request; destination access is unverified.
    case connected
    /// The tunnel went down; the client keeps retrying on its own.
    case reconnecting(String)
    /// The client stopped by itself.
    case failed(String)

    public var title: String {
        switch self {
        case .stopped: return "Not Connected"
        case .connecting: return "Connecting…"
        case .connected: return "Relay Connected"
        case .reconnecting: return "Connection Lost, Reconnecting…"
        case .failed: return "Connection Failed"
        }
    }

    /// Admission scope when connected, otherwise the recorded failure reason.
    public var detail: String? {
        switch self {
        case .connected: return "Relay authenticated; Internet access is not verified."
        case .reconnecting(let why), .failed(let why): return why
        default: return nil
        }
    }

    /// Whether the client is running.
    public var isActive: Bool {
        switch self {
        case .connecting, .connected, .reconnecting: return true
        case .stopped, .failed: return false
        }
    }
}

/// Read only the level prefix. Unclassified lines are visible at every setting.
private func messageLogLevel(_ line: String) -> LogLevel {
    var rest = line[...].drop(while: { $0 == " " })
    for _ in 0..<4 {
        guard let end = rest.firstIndex(of: " ") else { break }
        let field = rest[..<end]
        rest = rest[end...].drop(while: { $0 == " " })
        guard !rest.isEmpty else { break }
        switch field {
        case "ERROR": return .errors
        case "WARN": return .warnings
        case "INFO": return .normal
        case "DEBUG": return .detailed
        case "TRACE": return .everything
        default: continue
        }
    }
    return .errors
}

/// How much of the client's log the Log tab shows, and how much the client
/// writes.
public enum LogLevel: String, Codable, CaseIterable, Equatable {
    case errors
    case warnings
    case normal
    /// Also the protocol core's own debug messages, such as each connection
    /// through the proxy.
    case detailed
    /// Also native I/O metadata; never raw packet contents.
    case everything

    /// As shown in the menu.
    public var title: String {
        switch self {
        case .errors: return "Errors Only"
        case .warnings: return "Warnings and Errors"
        case .normal: return "Normal"
        case .detailed: return "Detailed"
        case .everything: return "Everything"
        }
    }

    /// Whether the Log tab shows a line. Lines without a level, such as the
    /// app's own and the errors the client prints before its log starts,
    /// are always shown.
    public func shows(_ line: String) -> Bool {
        self == .everything || messageLogLevel(line).nativeValue <= nativeValue
    }
}

public extension LogLevel {
    var nativeValue: UInt32 {
        switch self {
        case .errors: return 0
        case .warnings: return 1
        case .normal: return 2
        case .detailed: return 3
        case .everything: return 4
        }
    }
}
