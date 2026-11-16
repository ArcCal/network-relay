// Adapted from Masque NF; independent Network Relay Tun copy.
import Foundation

private let maximumSettingsTextBytes = 4 << 20

/// Read an import with the same byte limit as the parser, before allocating
/// an arbitrarily large String from a user-selected file.
public func readSettingsText(from file: URL) throws -> String {
    let handle = try FileHandle(forReadingFrom: file)
    defer { try? handle.close() }
    var data = Data()
    while data.count <= maximumSettingsTextBytes {
        let count = min(64 << 10, maximumSettingsTextBytes + 1 - data.count)
        guard let chunk = try handle.read(upToCount: count), !chunk.isEmpty else { break }
        data.append(chunk)
    }
    guard data.count <= maximumSettingsTextBytes else {
        throw TOMLError(line: 1, "the settings file exceeds 4 MiB")
    }
    guard let text = String(data: data, encoding: .utf8) else {
        throw CocoaError(.fileReadInapplicableStringEncoding, userInfo: [NSFilePathErrorKey: file.path])
    }
    return text
}

/// A TOML value, as far as the app's files need: strings, whole numbers,
/// booleans, arrays and tables. What else TOML has (floats, dates,
/// multi-line strings) is refused with the line it is on.
public enum TOMLValue: Equatable {
    case string(String)
    case integer(Int)
    case boolean(Bool)
    case array([TOMLValue])
    case table([String: TOMLValue])
}

/// Why a file cannot be read as TOML, with the line where it went wrong.
public struct TOMLError: Error, Equatable, LocalizedError {
    public var line: Int
    public var message: String

    public init(line: Int, _ message: String) {
        self.line = line
        self.message = message
    }

    public var errorDescription: String? { "Line \(line): \(message)" }
}

/// Reads a TOML document (the subset `TOMLValue` covers) into its top-level
/// table: comments, `key = value` with bare, quoted and dotted keys,
/// `[tables]`, `[[arrays of tables]]`, arrays that span lines, and inline
/// tables.
public func parseTOML(_ text: String) throws -> [String: TOMLValue] {
    // Check bytes before expanding every scalar into parser storage.
    guard text.utf8.count <= maximumSettingsTextBytes else {
        throw TOMLError(line: 1, "the settings file exceeds 4 MiB")
    }
    var parser = TOMLParser(Array(text.unicodeScalars))
    return try parser.document()
}

private struct TOMLParser {
    private let s: [Unicode.Scalar]
    private var i = 0
    private var line = 1
    private var valueDepth = 0
    private var root: [String: TOMLValue] = [:]
    /// The table that `key = value` lines go into.
    private var current: [String] = []
    /// Tables a `[header]` defined, which may not be defined again.
    private var defined: Set<[String]> = []

    init(_ scalars: [Unicode.Scalar]) {
        s = scalars
    }

    mutating func document() throws -> [String: TOMLValue] {
        while true {
            skipBlank()
            guard let c = peek() else { return root }
            switch c {
            case "\n":
                newline()
            case "#":
                skipComment()
            case "[":
                try header()
                try endOfLine()
            default:
                let key = try keyPath()
                try expect("=")
                let value = try value()
                try set(value, at: current + key.dropLast(), key: key.last!)
                try endOfLine()
            }
        }
    }

    // MARK: Lines

    private func peek(_ offset: Int = 0) -> Unicode.Scalar? {
        i + offset < s.count ? s[i + offset] : nil
    }

    private func error(_ message: String) -> TOMLError {
        TOMLError(line: line, message)
    }

    private mutating func skipBlank() {
        while let c = peek(), c == " " || c == "\t" || (c == "\r" && peek(1) == "\n") {
            i += 1
        }
    }

    private mutating func skipComment() {
        while let c = peek(), c != "\n" {
            i += 1
        }
    }

    private mutating func newline() {
        i += 1
        line += 1
    }

    /// Blanks, newlines and comments, as allowed inside an array.
    private mutating func skipBlankLines() {
        while true {
            skipBlank()
            switch peek() {
            case "\n": newline()
            case "#": skipComment()
            default: return
            }
        }
    }

    private mutating func endOfLine() throws {
        skipBlank()
        if peek() == "#" {
            skipComment()
        }
        guard let c = peek() else { return }
        guard c == "\n" else { throw error("unexpected “\(c)” after the value") }
        newline()
    }

    private mutating func expect(_ c: Unicode.Scalar) throws {
        skipBlank()
        guard peek() == c else { throw error("“\(c)” expected") }
        i += 1
    }

    // MARK: Keys and headers

    private mutating func keyPath() throws -> [String] {
        var path: [String] = []
        while true {
            skipBlank()
            path.append(try key())
            guard path.count <= 64 else { throw error("table paths exceed 64 levels") }
            skipBlank()
            guard peek() == "." else { return path }
            i += 1
        }
    }

    private mutating func key() throws -> String {
        switch peek() {
        case "\"":
            return try basicString()
        case "'":
            return try literalString()
        default:
            let bare = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
            let start = i
            while let c = peek(), bare.contains(c) {
                i += 1
            }
            guard i > start else { throw error("a key is expected") }
            return String(String.UnicodeScalarView(s[start..<i]))
        }
    }

    private mutating func header() throws {
        i += 1
        let isArray = peek() == "["
        if isArray {
            i += 1
        }
        let path = try keyPath()
        try expect("]")
        if isArray {
            guard peek() == "]" else { throw error("“]]” expected") }
            i += 1
            try modify(at: path.dropLast()) { table, line in
                switch table[path.last!] {
                case nil:
                    table[path.last!] = .array([.table([:])])
                case .array(var items)? where items.allSatisfy({ if case .table = $0 { return true } else { return false } }):
                    items.append(.table([:]))
                    table[path.last!] = .array(items)
                default:
                    throw TOMLError(line: line, "“\(path.joined(separator: "."))” is already something else than an array of tables")
                }
            }
        } else {
            guard defined.insert(path).inserted else {
                throw error("the table [\(path.joined(separator: "."))] appears twice")
            }
            try modify(at: path[...]) { _, _ in }
        }
        current = path
    }

    /// Runs `change` on the table at `path`, made if it is missing; through
    /// an array of tables it goes into its last table, as TOML does.
    private mutating func modify(at path: ArraySlice<String>, _ change: (inout [String: TOMLValue], Int) throws -> Void) throws {
        try Self.modify(&root, path, line: line, change)
    }

    private static func modify(
        _ table: inout [String: TOMLValue], _ path: ArraySlice<String>, line: Int,
        _ change: (inout [String: TOMLValue], Int) throws -> Void
    ) throws {
        guard path.count <= 64 else { throw TOMLError(line: line, "table paths exceed 64 levels") }
        guard let first = path.first else {
            try change(&table, line)
            return
        }
        switch table[first] {
        case nil:
            var inner: [String: TOMLValue] = [:]
            try modify(&inner, path.dropFirst(), line: line, change)
            table[first] = .table(inner)
        case .table(var inner)?:
            try modify(&inner, path.dropFirst(), line: line, change)
            table[first] = .table(inner)
        case .array(var items)?:
            guard case .table(var inner)? = items.last else {
                throw TOMLError(line: line, "“\(first)” is not a table")
            }
            try modify(&inner, path.dropFirst(), line: line, change)
            items[items.count - 1] = .table(inner)
            table[first] = .array(items)
        default:
            throw TOMLError(line: line, "“\(first)” is not a table")
        }
    }

    private mutating func set(_ value: TOMLValue, at path: [String], key: String) throws {
        try modify(at: path[...]) { table, line in
            guard table[key] == nil else {
                throw TOMLError(line: line, "“\(key)” is set twice")
            }
            table[key] = value
        }
    }

    // MARK: Values

    private mutating func value() throws -> TOMLValue {
        guard valueDepth < 64 else { throw error("values exceed 64 nesting levels") }
        valueDepth += 1
        defer { valueDepth -= 1 }
        skipBlank()
        switch peek() {
        case "\"":
            return .string(try basicString())
        case "'":
            return .string(try literalString())
        case "[":
            return try array()
        case "{":
            return try inlineTable()
        case nil, "\n", "#":
            throw error("a value is expected")
        default:
            return try bareValue()
        }
    }

    private mutating func bareValue() throws -> TOMLValue {
        let word = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_+-.:")
        let start = i
        while let c = peek(), word.contains(c) {
            i += 1
        }
        let text = String(String.UnicodeScalarView(s[start..<i]))
        switch text {
        case "true": return .boolean(true)
        case "false": return .boolean(false)
        default:
            let digits = text.replacingOccurrences(of: "_", with: "")
            let unsigned = digits.hasPrefix("+") || digits.hasPrefix("-") ? digits.dropFirst() : Substring(digits)
            if !unsigned.isEmpty, unsigned.allSatisfy(\.isASCII), unsigned.allSatisfy(\.isNumber), let number = Int(digits) {
                return .integer(number)
            }
            throw error(text.isEmpty ? "a value is expected" : "“\(text)” is not a value this file may have (a string in quotes, a whole number, true or false)")
        }
    }

    private mutating func array() throws -> TOMLValue {
        i += 1
        var items: [TOMLValue] = []
        while true {
            skipBlankLines()
            if peek() == "]" {
                i += 1
                return .array(items)
            }
            items.append(try value())
            skipBlankLines()
            switch peek() {
            case ",": i += 1
            case "]": continue
            default: throw error("“,” or “]” expected in the array")
            }
        }
    }

    private mutating func inlineTable() throws -> TOMLValue {
        i += 1
        var table: [String: TOMLValue] = [:]
        skipBlank()
        if peek() == "}" {
            i += 1
            return .table(table)
        }
        while true {
            let path = try keyPath()
            try expect("=")
            let value = try value()
            try Self.modify(&table, path.dropLast(), line: line) { inner, line in
                guard inner[path.last!] == nil else { throw TOMLError(line: line, "“\(path.last!)” is set twice") }
                inner[path.last!] = value
            }
            skipBlank()
            switch peek() {
            case ",": i += 1
            case "}":
                i += 1
                return .table(table)
            default: throw error("“,” or “}” expected in the inline table")
            }
        }
    }

    private mutating func literalString() throws -> String {
        if peek(1) == "'" && peek(2) == "'" {
            throw error("multi-line strings are not supported")
        }
        i += 1
        let start = i
        while let c = peek(), c != "'" {
            if c == "\n" { throw error("the string does not end on its line") }
            try checkAllowed(c)
            i += 1
        }
        guard peek() == "'" else { throw error("the string does not end") }
        defer { i += 1 }
        return String(String.UnicodeScalarView(s[start..<i]))
    }

    private mutating func basicString() throws -> String {
        if peek(1) == "\"" && peek(2) == "\"" {
            throw error("multi-line strings are not supported")
        }
        i += 1
        var out = String.UnicodeScalarView()
        while let c = peek() {
            switch c {
            case "\"":
                i += 1
                return String(out)
            case "\n":
                throw error("the string does not end on its line")
            case "\\":
                i += 1
                out.append(try escape())
            default:
                try checkAllowed(c)
                out.append(c)
                i += 1
            }
        }
        throw error("the string does not end")
    }

    private mutating func escape() throws -> Unicode.Scalar {
        guard let c = peek() else { throw error("the string does not end") }
        i += 1
        switch c {
        case "b": return "\u{8}"
        case "t": return "\t"
        case "n": return "\n"
        case "f": return "\u{C}"
        case "r": return "\r"
        case "\"": return "\""
        case "\\": return "\\"
        case "u", "U":
            let count = c == "u" ? 4 : 8
            guard i + count <= s.count,
                  let code = UInt32(String(String.UnicodeScalarView(s[i..<(i + count)])), radix: 16),
                  let scalar = Unicode.Scalar(code) else {
                throw error("“\\\(c)” must be followed by \(count) hexadecimal digits of a character")
            }
            i += count
            return scalar
        default:
            throw error("“\\\(c)” is not an escape TOML knows (write a backslash as \\\\)")
        }
    }

    /// TOML strings may not hold control characters other than tab.
    private func checkAllowed(_ c: Unicode.Scalar) throws {
        if (c.value < 0x20 && c != "\t") || c.value == 0x7F {
            throw error("a control character in a string must be written as an escape")
        }
    }
}
