import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

public enum RelayEndpoints {
    /// Resolve only before capture. The caller pins each native attempt to one
    /// of these addresses and keeps the configured domain for TLS and HTTP.
    public static func resolve(_ settings: Settings) throws -> [String] {
        let pin = settings.serverIP.trimmingCharacters(in: .whitespacesAndNewlines)
        let host = try parseDomain(settings.domain).host
        if !pin.isEmpty && !isIPAddress(pin) { throw SettingsError.invalidServerIP }
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        #if canImport(Darwin)
        hints.ai_socktype = SOCK_STREAM
        #else
        hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
        #endif
        if !pin.isEmpty { hints.ai_flags = AI_NUMERICHOST }
        var head: UnsafeMutablePointer<addrinfo>?
        let code = getaddrinfo(pin.isEmpty ? host : pin, nil, &hints, &head)
        guard code == 0, let first = head else { throw ResolutionError() }
        defer { freeaddrinfo(first) }
        var found: [String] = []
        var item: UnsafeMutablePointer<addrinfo>? = first
        while let entry = item {
            item = entry.pointee.ai_next
            var address = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(entry.pointee.ai_addr, entry.pointee.ai_addrlen, &address,
                           socklen_t(address.count), nil, 0, NI_NUMERICHOST) == 0 {
                found.append(String(cString: address))
            }
        }
        let addresses = candidates(found)
        guard !addresses.isEmpty else { throw ResolutionError() }
        return addresses
    }

    private struct ResolutionError: LocalizedError {
        var errorDescription: String? { "The relay has no usable IPv4 or IPv6 address." }
    }

    // Match the broker's endpoint restrictions. Keep resolver preference within
    // each family and try the other family before a second same-family address.
    static func candidates(_ addresses: [String]) -> [String] {
        var seen = Set<String>()
        let usable = addresses.filter { address in
            guard !address.contains("%"), seen.insert(address).inserted else { return false }
            var v4 = in_addr()
            if inet_pton(AF_INET, address, &v4) == 1 {
                let n = UInt32(bigEndian: v4.s_addr)
                return n != 0 && n != .max && n >> 24 != 127 && n >> 28 != 14 && n >> 16 != 0xa9fe
            }
            var v6 = in6_addr()
            guard inet_pton(AF_INET6, address, &v6) == 1 else { return false }
            return withUnsafeBytes(of: &v6) { bytes in
                bytes[0] != 0xff && !(bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80)
                    && !(bytes.prefix(15).allSatisfy { $0 == 0 } && bytes[15] <= 1)
                    && !(bytes.prefix(10).allSatisfy { $0 == 0 } && bytes[10] == 255 && bytes[11] == 255)
            }
        }
        guard let first = usable.first else { return [] }
        let preferV6 = first.contains(":")
        var primary = usable.filter { $0.contains(":") == preferV6 }.makeIterator()
        var secondary = usable.filter { $0.contains(":") != preferV6 }.makeIterator()
        var ordered: [String] = []
        while ordered.count < usable.count {
            if let address = primary.next() { ordered.append(address) }
            if let address = secondary.next() { ordered.append(address) }
        }
        return ordered
    }
}
