#!/usr/bin/env bash
# Compile the production HostSession against a disposable helper that exits.
# No installation, credentials, utun, routes or DNS changes are involved.
set -euo pipefail
[[ $(uname -s) == Darwin ]] || { echo 'This regression requires macOS.' >&2; exit 77; }
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$root/.validation"
stage=$(mktemp -d "$root/.validation/host-session.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT
app="$stage/Host Session Check.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Helpers" "$app/Contents/Frameworks" "$stage/modules"
cat > "$app/Contents/Helpers/network-relay-tun-host" <<'HELPER'
#!/bin/sh
# Model a control bridge whose installed daemon is absent or unavailable.
exit 1
HELPER
chmod 755 "$app/Contents/Helpers/network-relay-tun-host"
python3 - "$root" "$stage" "$app" <<'PY'
import pathlib, plistlib, sys
root, stage, app = map(pathlib.Path, sys.argv[1:])
s = (root/'App/Sources/NetworkRelayTun/NativeClient.swift').read_text()
start = s.index('struct NativeError:')
# Keep the production error definition, not an independently implemented stub.
end = s.index('\n}', start) + 2
(stage/'NativeError.swift').write_text('import Foundation\n' + s[start:end] + '\n')
(app/'Contents/Info.plist').write_bytes(plistlib.dumps({
 'CFBundleExecutable': 'HostSessionCheck', 'CFBundleIdentifier': 'com.arccal.network-relay-tun.host-session-test',
 'CFBundlePackageType': 'APPL', 'CFBundleName': 'Host Session Check'}))
PY
cat > "$stage/Check.swift" <<'SWIFT'
import Foundation
import Darwin
@main struct Check {
    static func main() async throws {
        // This executable must survive closed-pipe failures without relying on
        // another component having installed a process-wide signal handler.
        signal(SIGPIPE, SIG_DFL)
        let files = FileManager.default
        let copies = files.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let bundled = copies.appendingPathComponent("bundle")
        let installed = copies.appendingPathComponent("installed")
        defer { try? files.removeItem(at: copies) }
        for directory in [bundled, installed] {
            try files.createDirectory(at: directory, withIntermediateDirectories: true)
            for name in ["network-relay-tun-host", "packet-worker"] {
                let url = directory.appendingPathComponent(name)
                try Data(name.utf8).write(to: url)
                try files.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
            }
        }
        try HostSession.checkInstalledFiles(bundled: bundled, installed: installed)
        for name in ["packet-worker", "network-relay-tun-host"] {
            let url = installed.appendingPathComponent(name)
            try Data("old version".utf8).write(to: url)
            do {
                try HostSession.checkInstalledFiles(bundled: bundled, installed: installed)
                fatalError("A mismatched installed helper was accepted")
            } catch { precondition(error.localizedDescription.contains("Install / Update Helper")) }
            try Data(name.utf8).write(to: url)
        }
        let control = HostSession()
        do {
            _ = try await control.request(["operation": "recover"])
            fatalError("A terminated helper unexpectedly accepted recovery")
        } catch { print("Initial helper failure surfaced: \(error.localizedDescription)") }
        do {
            try await control.stop()
            fatalError("A terminated helper unexpectedly confirmed cleanup")
        } catch { print("Cleanup failure surfaced without terminating the application") }
        control.close()
        print("PASS: helper failure and cleanup preserve the application process")
    }
}
SWIFT
swiftc -emit-library -emit-module -module-name NetworkRelayTunModel \
    -emit-module-path "$stage/modules/NetworkRelayTunModel.swiftmodule" \
    "$root"/App/Sources/NetworkRelayTunModel/*.swift \
    -o "$app/Contents/Frameworks/libNetworkRelayTunModel.dylib"
swiftc -parse-as-library -I "$stage/modules" -L "$app/Contents/Frameworks" \
    -lNetworkRelayTunModel -Xlinker -rpath -Xlinker @executable_path/../Frameworks \
    "$root/App/Sources/NetworkRelayTun/HostSession.swift" "$stage/NativeError.swift" "$stage/Check.swift" \
    -o "$app/Contents/MacOS/HostSessionCheck"
python3 - "$app/Contents/MacOS/HostSessionCheck" <<'PY'
import subprocess, sys
try:
 result = subprocess.run([sys.argv[1]], timeout=30)
except subprocess.TimeoutExpired:
 raise SystemExit('FAIL: host-session error handling exceeded 30 seconds')
if result.returncode != 0:
 raise SystemExit(f'FAIL: host-session regression process exited {result.returncode} (negative values identify signals)')
PY
