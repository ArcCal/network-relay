// Adapted from Masque NF; independent Network Relay Tun copy.
import Foundation

// Export and Import: the servers and the proxy as a TOML file, to move
// them to another Mac, keep a copy, or give someone the servers (without
// the passwords). Servers and application settings can also travel separately.
//
//     # Network Relay Tun settings
//
//     [proxy]
//     listen_address = "127.0.0.1"
//     port = 1080
//     connect_on_launch = false
//
//     log_level = "normal"
//
//     [[server]]
//     id = "00000000-0000-0000-0000-000000000001"
//     name = "Tokyo"
//     domain = "vpn.example.com"
//     ip = "203.0.113.5"
//     username = "macbook"
//     password = "…"
//     transport = "auto"
//     selected = true
//
// Import also takes a network-relay-tun-core configuration (client.toml) and makes
// a server of it.

public enum TransferScope: Equatable {
    case all, servers, application
}

extension Configuration {
    /// The settings as Export writes them, with or without the passwords.
    public func exportedTOML(withPasswords: Bool, scope: TransferScope = .all) -> String {
        var lines = [
            "# Network Relay Tun settings. Import them in Network Relay Tun with Settings → Import….",
            scope == .application ? "# Application settings only; servers and passwords are left out."
                : (withPasswords ? "# The file holds the passwords: keep it private."
                    : "# The passwords are left out: enter them after importing."),
        ]
        if scope != .servers {
            lines += [
                "", "[proxy]", "listen_address = \(tomlString(listenAddress))", "port = \(port)",
                "connect_on_launch = \(connectOnLaunch)", "log_level = \(tomlString(logLevel.rawValue))",
            ]
        }
        let selected = selectedServer?.id
        for server in scope == .application ? [] : servers {
            lines += ["", "[[server]]", "id = \(tomlString(server.id.uuidString))"]
            if !server.name.isEmpty {
                lines.append("name = \(tomlString(server.name))")
            }
            lines.append("domain = \(tomlString(server.domain))")
            if !server.serverIP.isEmpty {
                lines.append("ip = \(tomlString(server.serverIP))")
            }
            lines.append("username = \(tomlString(server.username))")
            if withPasswords && !server.password.isEmpty {
                lines.append("password = \(tomlString(server.password))")
            }
            lines.append("transport = \(tomlString(server.transport.rawValue))")
            if server.probeTarget != Settings().probeTarget {
                lines.append("probe_target = \(tomlString(server.probeTarget))")
            }
            if server.id == selected {
                lines.append("selected = true")
            }
        }
        return lines.joined(separator: "\n") + "\n"
    }

    /// The settings in a file chosen for Import: one Export wrote, or a
    /// network-relay-tun-core configuration, which becomes one server (with the
    /// proxy of its `[socks]` section). Missing application fields keep their
    /// current values; older files without server IDs still work.
    public static func importing(
        _ text: String, scope: TransferScope = .all, preserving base: Configuration = Configuration()
    ) throws -> Configuration {
        let document: [String: TOMLValue]
        do {
            document = try parseTOML(text)
        } catch let error as TOMLError {
            throw ImportError.notTOML(error.localizedDescription)
        }
        if document["uri_template"] != nil && document["server"] == nil {
            return try importingClientConfiguration(document, scope: scope, preserving: base)
        }
        guard document["server"] != nil || document["proxy"] != nil else {
            throw ImportError.notSettings
        }
        var configuration = base
        let file = TableReader(document, where: "")
        var hasApplicationSettings = false
        if scope != .servers, let proxy = try file.table("proxy") {
            let reader = TableReader(proxy, where: "[proxy]")
            hasApplicationSettings = ["listen_address", "port", "connect_on_launch", "log_level"].contains { proxy[$0] != nil }
            configuration.listenAddress = try reader.string("listen_address") ?? configuration.listenAddress
            configuration.port = try reader.integer("port") ?? configuration.port
            configuration.connectOnLaunch = try reader.boolean("connect_on_launch") ?? configuration.connectOnLaunch
            if let level = try reader.string("log_level") {
                guard let level = LogLevel(rawValue: level) else {
                    throw ImportError.invalid("“log_level” in [proxy] must be one of " + LogLevel.allCases.map { "“\($0.rawValue)”" }.joined(separator: ", ") + ".")
                }
                configuration.logLevel = level
            }
            if proxy["listen_address"] != nil || proxy["port"] != nil {
                _ = try NetworkRelayTunModel.listenAddress(configuration.settings)
            }
        }
        if scope == .application {
            guard hasApplicationSettings else { throw ImportError.notSettings }
            return configuration
        }
        configuration.servers = []
        configuration.selectedServerID = nil
        var ids = Set<UUID>()
        for (index, table) in try file.tables("server").enumerated() {
            let reader = TableReader(table, where: "server \(index + 1)")
            var server = Server()
            if let id = try reader.string("id") {
                guard let id = UUID(uuidString: id), ids.insert(id).inserted else {
                    throw ImportError.invalid("“id” in server \(index + 1) must be a valid, unique UUID.")
                }
                server.id = id
            }
            server.name = try reader.string("name") ?? ""
            server.domain = try reader.string("domain") ?? ""
            server.serverIP = try reader.string("ip") ?? ""
            server.username = try reader.string("username") ?? ""
            server.password = try reader.string("password") ?? ""
            server.transport = try reader.transport("transport") ?? .auto
            server.probeTarget = try admissionProbeTarget(reader.string("probe_target") ?? Settings().probeTarget)
            configuration.servers.append(server)
            if try reader.boolean("selected") == true && configuration.selectedServerID == nil {
                configuration.selectedServerID = server.id
            }
        }
        guard !configuration.servers.isEmpty else {
            throw ImportError.noServers
        }
        configuration.selectedServerID = configuration.selectedServer?.id
        return configuration
    }

    /// A network-relay-tun-core configuration, as network-relay-tun-core reads it: the server
    /// is in `uri_template` (with `server_name` when it names an IP), and
    /// the proxy in `[socks]`.
    private static func importingClientConfiguration(
        _ document: [String: TOMLValue], scope: TransferScope, preserving base: Configuration
    ) throws -> Configuration {
        let file = TableReader(document, where: "")
        var configuration = base
        if scope != .application {
            guard let template = try file.string("uri_template") else {
                throw ImportError.notSettings
            }
            let prefix = "https://"
            let path = "/.well-known/masque/udp/{target_host}/{target_port}/"
            let authority = template.hasPrefix(prefix) && template.hasSuffix(path)
                ? String(template.dropFirst(prefix.count).dropLast(path.count)) : ""
            guard !authority.isEmpty, !authority.contains("/") else {
                throw ImportError.invalid(
                    "Network Relay Tun connects to servers at https://<domain>\(path); this configuration's uri_template is \(template).")
            }
            // `host`, `host:port`, `[v6]` or `[v6]:port`.
            var host = authority
            var port = ""
            if authority.hasPrefix("["), let end = authority.firstIndex(of: "]") {
                host = String(authority[authority.index(after: authority.startIndex)..<end])
                port = String(authority[authority.index(after: end)...])
            } else if let colon = authority.lastIndex(of: ":") {
                host = String(authority[..<colon])
                port = String(authority[colon...])
            }
            if port == ":443" {
                port = ""
            }
            var server = Server()
            if let name = try file.string("server_name") {
                server.domain = name + port
                server.serverIP = host
            } else {
                server.domain = host + port
            }
            server.username = try file.string("username") ?? ""
            server.password = try file.string("password") ?? ""
            server.transport = try file.transport("transport") ?? .auto
            server.probeTarget = try admissionProbeTarget(file.string("probe_target") ?? Settings().probeTarget)
            configuration.servers = [server]
            configuration.selectedServerID = server.id
        }
        if scope != .servers, let socks = try file.table("socks"), socks["listen"] != nil {
            let listens = try TableReader(socks, where: "[socks]").strings("listen")
            guard !listens.isEmpty else {
                throw ImportError.invalid("“listen” in [socks] must contain an IP address and port, such as 127.0.0.1:1080.")
            }
            for (index, listen) in listens.enumerated() {
                // `127.0.0.1:1080` or `[::1]:1080`; validate every address,
                // even though the app uses just the first listener.
                guard let colon = listen.lastIndex(of: ":"), let port = Int(listen[listen.index(after: colon)...]) else {
                    throw ImportError.invalid("“listen” in [socks] must contain an IP address and port, such as 127.0.0.1:1080.")
                }
                let host = String(listen[..<colon]).trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
                guard (try? NetworkRelayTunModel.listenAddress(Settings(listenAddress: host, port: port))) == listen else {
                    throw ImportError.invalid("“listen” in [socks] must contain an IP address and port, such as 127.0.0.1:1080.")
                }
                if index == 0 {
                    configuration.listenAddress = host
                    configuration.port = port
                }
            }
        } else if scope == .application {
            throw ImportError.notSettings
        }
        return configuration
    }

    /// Imports servers, retaining matched IDs and omitted passwords. Older
    /// files match all other fields; a supplied ID also permits updates.
    /// Replace follows the file's selection; Add keeps the current one.
    @discardableResult
    public mutating func add(serversOf other: Configuration, replacing: Bool = false) -> Int {
        let previous = servers
        let selected = selectedServer?.id
        // Reserve UUID updates even when their old legacy profile appears first.
        let retainedIDs = Set(previous.map(\.id)).intersection(other.servers.map(\.id))
        var merged = replacing ? [] : servers
        var mapped: [UUID: UUID] = [:]
        var added = 0
        for var server in other.servers {
            let importedID = server.id
            let candidates = merged + previous.filter { old in !merged.contains { $0.id == old.id } }
            let existing = candidates.first { $0.id == server.id }
                ?? candidates.first { existing in
                    var incoming = server
                    if incoming.password.isEmpty { incoming.password = existing.password }
                    if retainedIDs.contains(existing.id), var updated = other.servers.first(where: { $0.id == existing.id }) {
                        if updated.password.isEmpty { updated.password = existing.password }
                        guard updated.isSame(as: incoming) else { return false }
                    }
                    return existing.isSame(as: incoming)
                }
            if let existing {
                server.id = existing.id
                if server.password.isEmpty { server.password = existing.password }
            } else {
                added += 1
            }
            mapped[importedID] = server.id
            if let index = merged.firstIndex(where: { $0.id == server.id }) {
                merged[index] = server
            } else {
                merged.append(server)
            }
        }
        servers = merged
        selectedServerID = replacing || selected == nil ? other.selectedServer.flatMap { mapped[$0.id] } : selected
        return added
    }
}

/// Why a file cannot be imported, in words for the user.
public enum ImportError: Error, Equatable, LocalizedError {
    case notTOML(String)
    case notSettings
    case noServers
    case invalid(String)

    public var errorDescription: String? {
        switch self {
        case .notTOML(let why): return "The file is not a TOML settings file. \(why)"
        case .notSettings: return "The file holds neither Network Relay Tun settings nor a network-relay-tun-core configuration."
        case .noServers: return "The file has no server ([[server]])."
        case .invalid(let why): return why
        }
    }
}

/// The values of one table of an imported file, by type; a value of the
/// wrong type is an error that says where it is.
private struct TableReader {
    let values: [String: TOMLValue]
    /// Where the table is, for the errors: "[proxy]", "server 2".
    let place: String

    init(_ values: [String: TOMLValue], where place: String) {
        self.values = values
        self.place = place
    }

    private func wrong(_ key: String, _ what: String) -> ImportError {
        .invalid("“\(key)”\(place.isEmpty ? "" : " in \(place)") must be \(what).")
    }

    func string(_ key: String) throws -> String? {
        switch values[key] {
        case nil: return nil
        case .string(let text)?: return text
        default: throw wrong(key, "a string in quotes")
        }
    }

    func strings(_ key: String) throws -> [String] {
        switch values[key] {
        case nil: return []
        case .string(let text)?: return [text]
        case .array(let items)?:
            return try items.map {
                guard case .string(let text) = $0 else { throw wrong(key, "a list of strings") }
                return text
            }
        default: throw wrong(key, "a list of strings")
        }
    }

    func integer(_ key: String) throws -> Int? {
        switch values[key] {
        case nil: return nil
        case .integer(let number)?: return number
        default: throw wrong(key, "a whole number")
        }
    }

    func boolean(_ key: String) throws -> Bool? {
        switch values[key] {
        case nil: return nil
        case .boolean(let flag)?: return flag
        default: throw wrong(key, "true or false")
        }
    }

    func transport(_ key: String) throws -> Transport? {
        guard let text = try string(key) else { return nil }
        guard let transport = Transport(rawValue: text) else {
            throw wrong(key, "one of " + Transport.allCases.map { "“\($0.rawValue)”" }.joined(separator: ", "))
        }
        return transport
    }

    func table(_ key: String) throws -> [String: TOMLValue]? {
        switch values[key] {
        case nil: return nil
        case .table(let inner)?: return inner
        default: throw wrong(key, "a table ([\(key)])")
        }
    }

    func tables(_ key: String) throws -> [[String: TOMLValue]] {
        switch values[key] {
        case nil: return []
        case .array(let items)?:
            return try items.map {
                guard case .table(let inner) = $0 else { throw wrong(key, "an array of tables ([[\(key)]])") }
                return inner
            }
        default: throw wrong(key, "an array of tables ([[\(key)]])")
        }
    }
}
