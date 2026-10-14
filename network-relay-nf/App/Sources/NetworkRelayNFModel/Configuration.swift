// Adapted from Masque NF; independent Network Relay NF copy.
import Foundation

/// A server the app can connect to, with the account on it.
public struct Server: Codable, Equatable, Identifiable {
    public var id: UUID
    /// What the menus show, such as "Tokyo"; empty: the domain.
    public var name: String
    /// The server's domain, as in its certificate. May end in `:port`
    /// when the server does not listen on 443.
    public var domain: String
    /// The server's IP address. Empty: connect to the address the domain
    /// resolves to.
    public var serverIP: String
    public var username: String
    public var password: String
    /// Which HTTP version carries the tunnel.
    public var transport: Transport

    public init(
        id: UUID = UUID(), name: String = "", domain: String = "", serverIP: String = "", username: String = "",
        password: String = "", transport: Transport = .auto
    ) {
        self.id = id
        self.name = name
        self.domain = domain
        self.serverIP = serverIP
        self.username = username
        self.password = password
        self.transport = transport
    }

    /// The server a settings file from before the list of servers (1.3 and
    /// earlier) describes gets this ID, so it is the same every time the
    /// file is read.
    public static let firstID = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!

    /// As the menus show it.
    public var title: String {
        if !name.trimmed.isEmpty { return name.trimmed }
        if !domain.trimmed.isEmpty { return domain.trimmed }
        return "New Server"
    }

    /// The same server, but for its ID.
    public func isSame(as other: Server) -> Bool {
        var other = other
        other.id = id
        return self == other
    }

    private enum CodingKeys: String, CodingKey {
        case id, name, domain, serverIP, username, password, transport
    }

    /// A field that is missing or unreadable takes its default.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        func value<T: Decodable>(_ key: CodingKeys, _ fallback: T) -> T {
            (try? c.decodeIfPresent(T.self, forKey: key)) ?? fallback
        }
        id = value(.id, UUID())
        name = value(.name, "")
        domain = value(.domain, "")
        serverIP = value(.serverIP, "")
        username = value(.username, "")
        password = value(.password, "")
        transport = value(.transport, .auto)
    }
}

/// Everything the user sets up: the servers, the one connected to, the
/// proxy, and how much of the log to show.
public struct Configuration: Codable, Equatable {
    public var servers: [Server]
    /// The server connected to; the first one when nil or not in the list.
    public var selectedServerID: UUID?
    /// Where the SOCKS5 proxy listens.
    public var listenAddress: String
    public var port: Int
    /// Connect as soon as the app starts.
    public var connectOnLaunch: Bool
    public var logLevel: LogLevel

    public init(
        servers: [Server] = [], selectedServerID: UUID? = nil, listenAddress: String = "127.0.0.1", port: Int = 1080,
        connectOnLaunch: Bool = false, logLevel: LogLevel = .normal
    ) {
        self.servers = servers
        self.selectedServerID = selectedServerID
        self.listenAddress = listenAddress
        self.port = port
        self.connectOnLaunch = connectOnLaunch
        self.logLevel = logLevel
    }

    /// The server connected to.
    public var selectedServer: Server? {
        servers.first { $0.id == selectedServerID } ?? servers.first
    }

    /// What the protocol core runs with: the server connected to and the proxy.
    public var settings: Settings {
        settings(for: selectedServer ?? Server())
    }

    /// The password on the server connected to.
    public var password: String {
        selectedServer?.password ?? ""
    }

    /// The settings to connect to `server` with this proxy.
    public func settings(for server: Server) -> Settings {
        Settings(
            serverIP: server.serverIP, domain: server.domain, username: server.username, listenAddress: listenAddress,
            port: port, connectOnLaunch: connectOnLaunch, transport: server.transport)
    }

    /// Why the settings cannot be saved, if they cannot: the proxy first,
    /// then each server, named.
    public func check() throws {
        _ = try NetworkRelayNFModel.listenAddress(settings)
        for server in servers {
            do {
                _ = try clientConfiguration(settings(for: server), password: server.password)
            } catch let error as SettingsError {
                throw ServerError(server: server.title, reason: error)
            }
        }
    }

    // MARK: The settings file

    private enum CodingKeys: String, CodingKey {
        case servers, selectedServer, logLevel, settings, password
    }

    /// Reads the settings file of this version or of an earlier one. Up to
    /// 1.3 the file held one server: `settings` (the server and the proxy)
    /// and `password`. That server becomes the only one in the list. A
    /// field that is missing or unreadable takes its default, and the rest
    /// is kept (see `Settings.init(from:)`).
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let old = (try? c.decodeIfPresent(Settings.self, forKey: .settings)) ?? Settings()
        let oldPassword = (try? c.decodeIfPresent(String.self, forKey: .password)) ?? ""
        listenAddress = old.listenAddress
        port = old.port
        connectOnLaunch = old.connectOnLaunch
        logLevel = (try? c.decodeIfPresent(LogLevel.self, forKey: .logLevel)) ?? .normal
        if c.contains(.servers) {
            servers = ((try? c.decode([Lenient<Server>].self, forKey: .servers)) ?? []).compactMap(\.value)
        } else if !old.domain.trimmed.isEmpty || !old.username.trimmed.isEmpty || !oldPassword.isEmpty {
            servers = [Server(
                id: Server.firstID, domain: old.domain, serverIP: old.serverIP, username: old.username, password: oldPassword,
                transport: old.transport)]
        } else {
            servers = []
        }
        // Each server keeps its own ID, even in a file edited by hand.
        var seen = Set<UUID>()
        for index in servers.indices where !seen.insert(servers[index].id).inserted {
            servers[index].id = UUID()
            seen.insert(servers[index].id)
        }
        let selected = try? c.decodeIfPresent(UUID.self, forKey: .selectedServer)
        selectedServerID = servers.first { $0.id == selected }?.id ?? servers.first?.id
    }

    /// The list of servers, and also, for 1.3 and earlier, the server
    /// connected to in the form they read (`settings` and `password`), so
    /// that going back to an earlier version keeps it.
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(servers, forKey: .servers)
        try c.encodeIfPresent(selectedServer?.id, forKey: .selectedServer)
        try c.encode(logLevel, forKey: .logLevel)
        try c.encode(settings, forKey: .settings)
        try c.encode(password, forKey: .password)
    }

    /// What is saved in `file`; the defaults when nothing is.
    public static func load(from file: URL) -> Configuration {
        guard let data = try? Data(contentsOf: file),
              let saved = try? JSONDecoder().decode(Configuration.self, from: data) else {
            return Configuration()
        }
        return saved
    }

    /// Saves to `file`, which only the user can read, in a folder only the
    /// user can open.
    public func save(to file: URL) throws {
        let fm = FileManager.default
        let folder = file.deletingLastPathComponent()
        try fm.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        // Also when an older version or the user made the folder.
        try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: folder.path)
        try writePrivately(try JSONEncoder().encode(self), to: file)
    }


}

/// A server whose settings cannot be used, and why.
public struct ServerError: Error, Equatable, LocalizedError {
    /// The server's title.
    public var server: String
    public var reason: SettingsError

    public init(server: String, reason: SettingsError) {
        self.server = server
        self.reason = reason
    }

    public var errorDescription: String? {
        "\(server): \(reason.localizedDescription)"
    }
}

/// What a running client has to do when the settings change.
public enum ClientChange: Equatable {
    /// Nothing it runs with changed.
    case none
    /// Start it again with the new settings.
    case reconnect
    /// There is no server left to connect to.
    case disconnect
}

/// What changing the settings from `old` to `new` means for a running
/// client: a new server, account, transport or proxy address, reconnects; log detail, a server added to
/// the list, a name, or "connect when the app opens" does not.
public func clientChange(from old: Configuration, to new: Configuration) -> ClientChange {
    guard let after = try? clientConfiguration(new.settings, password: new.password) else {
        return .disconnect
    }
    let before = try? clientConfiguration(old.settings, password: old.password)
    return after == before ? .none : .reconnect
}

/// Writes `data` to `file`, readable only by the user: a new file, private
/// from the start, is written and then renamed over the old one, so a crash
/// or a full disk never leaves it half written.
public func writePrivately(_ data: Data, to file: URL) throws {
    let fm = FileManager.default
    let new = file.deletingLastPathComponent().appendingPathComponent(file.lastPathComponent + ".new")
    try? fm.removeItem(at: new)
    guard fm.createFile(atPath: new.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
        throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: new.path])
    }
    do {
        let handle = try FileHandle(forWritingTo: new)
        defer { try? handle.close() }
        try handle.write(contentsOf: data)
        try handle.synchronize()
        guard rename(new.path, file.path) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    } catch {
        try? fm.removeItem(at: new)
        throw error
    }
}

/// An element of a list that is skipped, rather than failing the whole
/// list, when it cannot be read.
private struct Lenient<T: Decodable>: Decodable {
    var value: T?

    init(from decoder: Decoder) throws {
        value = try? T(from: decoder)
    }
}
