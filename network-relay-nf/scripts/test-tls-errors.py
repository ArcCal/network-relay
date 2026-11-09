#!/usr/bin/env python3
"""Exercise production native TLS state handlers with controlled platform APIs.

This tests error propagation and classification without claiming execution of
Network.framework or Security.framework on macOS.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


STUBS = r'''import Foundation

typealias CFString = String
typealias CFArray = [String]
struct CFError: CustomStringConvertible { let description: String }
final class FakeTrust {
    var valid = true
    var error: CFError?
    var networkFetchAllowed: Bool?
}
enum TLSVersion { case TLSv13 }
final class sec_protocol_options_t {
    var name = ""
    var verify: ((Int, FakeTrust, @escaping (Bool) -> Void) -> Void)?
}
let errSecSuccess = 0
let kSecRevocationUseAnyAvailableMethod: UInt32 = 1
let kSecRevocationNetworkAccessDisabled: UInt32 = 2
let errSSLXCertChainInvalid: Int32 = -9807, errSSLBadCert: Int32 = -9808
let errSSLUnknownRootCert: Int32 = -9812, errSSLNoRootCert: Int32 = -9813
let errSSLCertExpired: Int32 = -9814, errSSLCertNotYetValid: Int32 = -9815
let errSSLPeerBadCert: Int32 = -9825, errSSLPeerUnsupportedCert: Int32 = -9826
let errSSLPeerCertRevoked: Int32 = -9827, errSSLPeerCertExpired: Int32 = -9828
let errSSLPeerCertUnknown: Int32 = -9829, errSSLPeerUnknownCA: Int32 = -9831
let errSSLHostNameMismatch: Int32 = -9843, errSSLBadCertificateStatusResponse: Int32 = -9862
let errSSLCertificateRequired: Int32 = -9863
func sec_protocol_options_set_min_tls_protocol_version(_ options: sec_protocol_options_t, _ version: TLSVersion) {}
func sec_protocol_options_set_tls_server_name(_ options: sec_protocol_options_t, _ name: UnsafePointer<CChar>) {
    options.name = String(cString: name)
}
func sec_protocol_options_set_verify_block(_ options: sec_protocol_options_t,
    _ verify: @escaping (Int, FakeTrust, @escaping (Bool) -> Void) -> Void, _ queue: DispatchQueue) {
    options.verify = verify
}
func sec_trust_copy_ref(_ trust: FakeTrust) -> Unmanaged<FakeTrust> { .passRetained(trust) }
func SecPolicyCreateSSL(_ server: Bool, _ name: CFString) -> String { name }
func SecPolicyCreateRevocation(_ flags: UInt32) -> String? { "revocation" }
func SecTrustSetPolicies(_ trust: FakeTrust, _ policies: CFArray) -> Int { errSecSuccess }
func SecTrustSetNetworkFetchAllowed(_ trust: FakeTrust, _ allowed: Bool) -> Int {
    trust.networkFetchAllowed = allowed; return errSecSuccess
}
func SecTrustEvaluateWithError(_ trust: FakeTrust, _ error: inout CFError?) -> Bool {
    error = trust.error; return trust.valid
}

enum NativePOSIX { case EADDRINUSE, ETIMEDOUT, EMFILE, ENFILE, ENETDOWN, ECONNABORTED }
enum NWError: Error {
    case tls(Int32)
    case posix(NativePOSIX)
    case dns(Int32)
}
enum NativeState {
    case ready, failed(NWError), cancelled, waiting(NWError), setup
}
final class NWConnection {
    var stateUpdateHandler: ((NativeState) -> Void)?
    var cancelled = false
    func start(queue: DispatchQueue) {}
    func cancel() { cancelled = true }
}
final class NWConnectionGroup {
    var stateUpdateHandler: ((NativeState) -> Void)?
    var cancelled = false
    func cancel() { cancelled = true }
}

final class NativeClient {
    private let queue = DispatchQueue(label: "tls-error-check")
    private var handle: Int? = 1
    private var connections: [UInt64: Connection] = [:]
    private var groups: [UInt64: Group] = [:]
    private var failures: [(UInt32, UInt64, UInt64, String)] = []
    private var logs: [String] = []
    private var closed: [UInt64] = []
    private func input(_ kind: UInt32, _ id: UInt64, flags: UInt64, data: Data) {
        failures.append((kind, id, flags, String(decoding: data, as: UTF8.self)))
    }
    private func log(_ severity: String, _ text: String) { logs.append(text) }
    private func close(_ id: UInt64) {
        closed.append(id)
        connections.removeValue(forKey: id)?.native.cancel()
        groups.removeValue(forKey: id)?.native.cancel()
    }
    private func prepareDatagrams(_ id: UInt64, _ group: Group) {}
'''

CHECKS = r'''
    private static func check(_ condition: Bool, _ text: String) {
        if !condition { fputs("FAIL: \(text)\n", stderr); exit(1) }
    }
    static func run() {
        let evaluator = NativeClient()
        let options = sec_protocol_options_t()
        let result = TrustResult()
        evaluator.configureTLS(options, name: "relay.test", trustResult: result)
        let untrusted = FakeTrust()
        untrusted.valid = false
        untrusted.error = CFError(description: "Certificate hostname mismatch")
        var accepted: Bool?
        options.verify?(0, untrusted, { accepted = $0 })
        check(options.name == "relay.test" && accepted == false && untrusted.networkFetchAllowed == false,
              "trust rejection must preserve SNI and disabled certificate network fetching")
        CHECK_TRUST_REASON
        let trusted = FakeTrust()
        options.verify?(0, trusted, { accepted = $0 })
        check(accepted == true && !result.rejected, "valid trust evaluation must not leave a stale rejection")
        print("PASS actual trust callback retains rejection details and clears them after acceptance")

        for quic in [false, true] {
            let label = quic ? "QUIC" : "TCP"
            func resource(_ owner: NativeClient, trust: TrustResult? = nil) -> (NativeState) -> Void {
                if quic {
                    let native = NWConnectionGroup()
                    let group = Group(native, trust: trust ?? TrustResult())
                    owner.groups[1] = group
                    owner.startGroup(native, group: group, id: 1)
                    return { native.stateUpdateHandler?($0) }
                }
                let native = NWConnection()
                owner.connections[1] = Connection(native, trust: trust)
                owner.start(native, id: 1, onReady: {})
                return { native.stateUpdateHandler?($0) }
            }
            for error in [NWError.posix(.ENETDOWN), .dns(-65563), .tls(-9803), .tls(-9805),
                          .tls(-9806), .tls(-9844), .tls(-9852), .tls(-9853)] {
                let owner = NativeClient()
                let state = resource(owner)
                state(.waiting(error))
                check(owner.failures.isEmpty && owner.closed.isEmpty,
                      "\(label) temporary waiting must remain pending")
                check(owner.logs.last?.contains("waiting:") == true,
                      "\(label) temporary waiting must retain its diagnostic")
            }
            print("PASS \(label) temporary POSIX, DNS and TLS waiting remains recoverable")

            let waiting = NativeClient()
            let state = resource(waiting)
            state(.waiting(.tls(-9808)))
            check(waiting.failures.count == 1 && waiting.failures[0].0 == 104 && waiting.failures[0].2 == 1,
                  "\(label) TLS waiting must promptly report a security error")
            check(waiting.failures[0].3.contains("-9808") && waiting.closed == [1],
                  "\(label) TLS waiting must retain the error and close the native resource")
            state(.cancelled)
            state(.failed(.tls(-9808)))
            check(waiting.failures.count == 1 && waiting.closed == [1],
                  "\(label) late callbacks must not duplicate the terminal result")
            print("PASS \(label) TLS waiting reports once and invalidates late callbacks")

            for code: Int32 in [-9807, -9812, -9813, -9814, -9815, -9825, -9826, -9827, -9828, -9829, -9831, -9843, -9862, -9863] {
                let owner = NativeClient()
                resource(owner)(.waiting(.tls(code)))
                check(owner.failures.count == 1 && owner.failures[0].2 == 1 && owner.closed == [1],
                      "\(label) certificate status \(code) must promptly report a security error")
            }
            print("PASS \(label) known certificate waiting failures are terminal")

            let rejected = NativeClient()
            let trust = TrustResult()
            let reason = "Certificate is not valid for relay.test"
            SET_REJECTION
            resource(rejected, trust: trust)(.waiting(.posix(.ECONNABORTED)))
            check(rejected.failures.count == 1 && rejected.failures[0].2 == 1,
                  "\(label) rejected trust must remain a security failure behind a POSIX error")
            check(rejected.failures[0].3.contains(reason),
                  "\(label) certificate validation details must survive the native error")
            print("PASS \(label) trust rejection preserves the certificate failure reason")

            let failed = NativeClient()
            resource(failed)(.failed(.tls(-9808)))
            check(failed.failures.count == 1 && failed.failures[0].2 == 1 && failed.closed == [1],
                  "\(label) existing failed-state security handling must remain intact")
            print("PASS \(label) failed-state TLS handling remains terminal")
        }
    }
}

@main struct Check { static func main() { NativeClient.run() } }
'''


def declaration(source, signature):
    start = source.index("    " + signature)
    first_line = source[start:source.index("\n", start)]
    if first_line.endswith("}"):
        return first_line + "\n"
    return source[start:source.index("\n    }", start) + len("\n    }")] + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--swiftc", default="swiftc")
    args = parser.parse_args()
    compiler = shutil.which(args.swiftc)
    if compiler is None:
        parser.error("swiftc was not found; install Swift or pass --swiftc PATH")
    source = (Path(__file__).resolve().parents[1] /
              "App/Sources/NetworkRelayNF/NativeClient.swift").read_text()
    declarations = [declaration(source, signature) for signature in (
        "private final class TrustResult", "private final class Connection",
        "private final class Group", "private func failureFlag(",
        "private func fail(_ id: UInt64, error:",
        "private func fail(_ id: UInt64, message:",
        "private func start(_ connection:",
        "private func configureTLS(",
    )]
    if "    private func waiting(" in source:
        declarations.append(declaration(source, "private func waiting("))
    if "    private func terminalTLSWaiting(" in source:
        declarations.append(declaration(source, "private func terminalTLSWaiting("))
    start = source.index("        native.stateUpdateHandler = { [weak self, weak group] state in")
    handler = source[start:source.index("\n        native.start(queue: queue)", start)]
    declarations.append("    private func startGroup(_ native: NWConnectionGroup, group: Group, id: UInt64) {\n"
                        + handler + "\n    }\n")
    rejection = ('trust.failure = reason' if "var failure:" in source else "trust.rejected = true")
    trust_reason = ('check(result.failure?.contains("Certificate hostname mismatch") == true && '
                    'result.failure?.contains("relay.test") == true, "trust evaluation must retain its error and hostname")'
                    if "var failure:" in source else 'check(result.rejected, "trust evaluation must reject the certificate")')
    program = (STUBS + "\n".join(declarations) + CHECKS.replace("SET_REJECTION", rejection)
               .replace("CHECK_TRUST_REASON", trust_reason))
    with tempfile.TemporaryDirectory(prefix="network-relay-nf-tls-") as folder:
        build = Path(folder)
        environment = dict(os.environ, CLANG_MODULE_CACHE_PATH=str(build / "cache"),
                           XDG_CACHE_HOME=str(build / "cache"))
        (build / "Check.swift").write_text(program)
        executable = build / "tls-check"
        subprocess.run([compiler, "-parse-as-library", "-swift-version", "5", "-warnings-as-errors",
                        str(build / "Check.swift"), "-o", str(executable)], env=environment, check=True)
        subprocess.run([str(executable)], env=environment, check=True)


if __name__ == "__main__":
    main()
