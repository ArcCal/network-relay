// Adapted from Masque NF; independent Network Relay NF copy.
import Foundation

/// What the user fills in, apart from the password.
public struct Settings: Codable, Equatable {
    /// The server's IP address. Empty: connect to the address the domain
    /// resolves to.
    public var serverIP: String
    /// The server's domain, as in its certificate. May end in `:port`
    /// when the server does not listen on 443.
    public var domain: String
    public var username: String
    /// Where the SOCKS5 proxy listens.
    public var listenAddress: String
    public var port: Int
    /// Connect as soon as the app starts.
    public var connectOnLaunch: Bool
    /// Which HTTP version carries the tunnel.
    public var transport: Transport

    public init(
        serverIP: String = "",
        domain: String = "",
        username: String = "",
        listenAddress: String = "127.0.0.1",
        port: Int = 1080,
        connectOnLaunch: Bool = false,
        transport: Transport = .auto
    ) {
        self.serverIP = serverIP
        self.domain = domain
        self.username = username
        self.listenAddress = listenAddress
        self.port = port
        self.connectOnLaunch = connectOnLaunch
        self.transport = transport
    }

    private enum CodingKeys: String, CodingKey {
        case serverIP, domain, username, listenAddress, port, connectOnLaunch, transport
    }

    /// A field that is missing or unreadable, because another version of
    /// the app saved the settings, takes its default; the other fields and
    /// the password are kept. Settings saved before the transport option
    /// so load as "auto", which is what that version did. Fields this
    /// version does not know, such as those of the Cloudflare option that
    /// early 0.7.0 builds had and of the cf-masque option of 1.1 to 1.3
    /// (`protocol`, `cfMasque`), are ignored and dropped from the file the
    /// next time the settings are saved.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let defaults = Settings()
        func value<T: Decodable>(_ key: CodingKeys, _ fallback: T) -> T {
            (try? c.decodeIfPresent(T.self, forKey: key)) ?? fallback
        }
        serverIP = value(.serverIP, defaults.serverIP)
        domain = value(.domain, defaults.domain)
        username = value(.username, defaults.username)
        listenAddress = value(.listenAddress, defaults.listenAddress)
        port = value(.port, defaults.port)
        connectOnLaunch = value(.connectOnLaunch, defaults.connectOnLaunch)
        transport = value(.transport, defaults.transport)
    }

    /// The SOCKS5 address programs are set to use, such as `127.0.0.1:1080`.
    public var proxyAddress: String {
        socketAddress(listenAddress.trimmed, port)
    }

    /// Whether only programs on this Mac can reach the proxy.
    public var listensOnlyLocally: Bool {
        let address = listenAddress.trimmed
        return address == "::1" || address.hasPrefix("127.")
    }
}

/// Which HTTP version carries the tunnel: the values network-relay-nf-core's
/// `transport` setting takes.
public enum Transport: String, Codable, CaseIterable, Equatable {
    /// HTTP/3 first; TCP (HTTP/2 or HTTP/1.1) when QUIC cannot connect.
    case auto
    case h3
    case h2
    case http1 = "http/1.1"

    /// As shown in the menu.
    public var title: String {
        switch self {
        case .auto: return "Automatic (HTTP/3 first, TCP if it cannot connect)"
        case .h3: return "HTTP/3 (QUIC, UDP)"
        case .h2: return "HTTP/2 (TCP)"
        case .http1: return "HTTP/1.1 (TCP)"
        }
    }
}

/// Why the settings cannot be used, in words for the user.
public enum SettingsError: Error, Equatable, LocalizedError {
    case missingDomain
    case invalidDomain
    case invalidServerIP
    case missingUsername
    case invalidUsername
    case missingPassword
    case invalidPassword
    case invalidListenAddress
    case invalidPort

    public var errorDescription: String? {
        switch self {
        case .missingDomain: return "Enter the server's domain."
        case .invalidDomain: return "The server's domain is not valid. Example: vpn.example.com (vpn.example.com:8443 when the port is not 443)."
        case .invalidServerIP: return "The server IP is not valid. Example: 203.0.113.5; leave it empty if you do not know it."
        case .missingUsername: return "Enter the username."
        case .invalidUsername: return "The username may contain only letters, digits, “-”, “_” and “.”, up to 64 characters, and must not start with “.”."
        case .missingPassword: return "Enter the password."
        case .invalidPassword: return "The password must not contain control characters such as line breaks."
        case .invalidListenAddress: return "The listen address must be an IP address, such as 127.0.0.1."
        case .invalidPort: return "The port must be between 1 and 65535."
        }
    }
}

/// Protocol-core configuration in the existing network-relay-nf-core format: SOCKS mode only, so
/// nothing else on the Mac changes.
public func clientConfiguration(_ settings: Settings, password: String) throws -> String {
    let (host, serverPort) = try parseDomain(settings.domain)
    let ip = settings.serverIP.trimmed
    if !ip.isEmpty && !isIPAddress(ip) {
        throw SettingsError.invalidServerIP
    }
    let username = settings.username.trimmed
    if username.isEmpty {
        throw SettingsError.missingUsername
    }
    // Match the independent core account validation.
    let nameCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
    if username.count > 64 || username.hasPrefix(".") || username.unicodeScalars.contains(where: { !nameCharacters.contains($0) }) {
        throw SettingsError.invalidUsername
    }
    if password.isEmpty {
        throw SettingsError.missingPassword
    }
    // What network-relay-nf-core refuses (RFC 7617 §2): control characters. Other
    // invisible characters, such as a zero-width space, are allowed.
    if password.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) {
        throw SettingsError.invalidPassword
    }
    let listen = try listenAddress(settings)

    // With an IP, connect to it and check the certificate against the domain.
    let authority = socketAddress(ip.isEmpty ? host : ip, serverPort)
    var lines = [
        "uri_template = \(tomlString("https://\(authority)/.well-known/masque/udp/{target_host}/{target_port}/"))",
    ]
    if !ip.isEmpty {
        lines.append("server_name = \(tomlString(host))")
    }
    lines += [
        "username = \(tomlString(username))",
        "password = \(tomlString(password))",
    ]
    // The client's default is "auto" too; the line is only written when
    // the user chose something.
    if settings.transport != .auto {
        lines.append("transport = \(tomlString(settings.transport.rawValue))")
    }
    lines += [
        "mode = \"socks\"",
        "",
        "[socks]",
        "listen = [\(tomlString(listen))]",
    ]
    return lines.joined(separator: "\n") + "\n"
}

/// The checked `host:port` the SOCKS5 proxy listens on.
func listenAddress(_ settings: Settings) throws -> String {
    let listen = settings.listenAddress.trimmed
    if !isIPAddress(listen) {
        throw SettingsError.invalidListenAddress
    }
    if !(1...65535).contains(settings.port) {
        throw SettingsError.invalidPort
    }
    return socketAddress(listen, settings.port)
}

/// `vpn.example.com` or `vpn.example.com:8443`.
func parseDomain(_ text: String) throws -> (host: String, port: Int) {
    var host = text.trimmed.lowercased()
    if host.isEmpty {
        throw SettingsError.missingDomain
    }
    var port = 443
    if let colon = host.lastIndex(of: ":") {
        guard let p = Int(host[host.index(after: colon)...]), (1...65535).contains(p) else {
            throw SettingsError.invalidDomain
        }
        port = p
        host = String(host[..<colon])
    }
    if host.hasSuffix(".") {
        host.removeLast()
    }
    let labelCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789-")
    let labels = host.split(separator: ".", omittingEmptySubsequences: false)
    let valid = !host.isEmpty && host.count <= 253 && labels.allSatisfy { label in
        !label.isEmpty && label.count <= 63 && !label.hasPrefix("-") && !label.hasSuffix("-")
            && label.unicodeScalars.allSatisfy { labelCharacters.contains($0) }
    }
    if !valid || isIPAddress(host) {
        // An IP address goes into the IP field; the domain is needed to
        // check the server's certificate.
        throw SettingsError.invalidDomain
    }
    return (host, port)
}

/// An IPv4 or IPv6 address literal, without a zone (`fe80::1%en0`):
/// network-relay-nf-core refuses a configuration with a zone named after an
/// interface, and inet_pton accepts zones on macOS but not on Linux, so
/// they are refused everywhere.
public func isIPAddress(_ text: String) -> Bool {
    var v4 = in_addr()
    var v6 = in6_addr()
    return !text.contains("%")
        && (inet_pton(AF_INET, text, &v4) == 1 || inet_pton(AF_INET6, text, &v6) == 1)
}

/// `host:port`, with an IPv6 address in brackets.
func socketAddress(_ host: String, _ port: Int) -> String {
    host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
}

/// A TOML basic string. Control characters, which a TOML string may not
/// hold as they are, are escaped (the settings' checks keep them out of
/// network-relay-nf-core's configuration; a server's name may have them).
func tomlString(_ text: String) -> String {
    var out = "\""
    for scalar in text.unicodeScalars {
        switch scalar {
        case "\"": out += "\\\""
        case "\\": out += "\\\\"
        case "\t": out += "\\t"
        case "\n": out += "\\n"
        case "\r": out += "\\r"
        case _ where scalar.value < 0x20 || scalar.value == 0x7F:
            out += String(format: "\\u%04X", scalar.value)
        default: out.unicodeScalars.append(scalar)
        }
    }
    return out + "\""
}

extension String {
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
}
