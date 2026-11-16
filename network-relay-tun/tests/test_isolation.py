"""Static build/store isolation checks; these do not replace native tests."""
from pathlib import Path
import plistlib
import unittest

ROOT = Path(__file__).resolve().parents[1]

class IsolationTests(unittest.TestCase):
    def test_product_identity(self):
        info = plistlib.loads((ROOT / "Info.plist.in").read_bytes())
        self.assertEqual(info["CFBundleIdentifier"], "com.arccal.network-relay-tun")
        self.assertEqual(info["CFBundleName"], "Network Relay Tun")
        self.assertEqual(info["CFBundleExecutable"], "NetworkRelayTun")

    def test_gui_never_uses_sibling_store_or_module(self):
        for source in (ROOT / "App").rglob("*.swift"):
            text = source.read_text()
            for forbidden in ("NetworkRelayNF", "NetworkRealyNF", "network-relay-nf", "network-realy-nf"):
                self.assertNotIn(forbidden, text, str(source))

    def test_build_paths_are_local(self):
        script = (ROOT / "build-macos.sh").read_text()
        self.assertNotIn("fresh-build-source.sh", script)
        self.assertNotIn("$root/..", script)
        self.assertIn('CARGO_TARGET_DIR="$root/target"', script)
        self.assertIn('--scratch-path "$root/.build/swift"', script)
        self.assertIn('CARGO_HOME="$root/.cargo"', script)

    def test_core_library_matches_gui_link(self):
        self.assertIn('name = "network-relay-tun-core"', (ROOT / "Core/Cargo.toml").read_text())
        self.assertIn('.linkedLibrary("network_relay_tun_core")', (ROOT / "App/Package.swift").read_text())
        header = ROOT / "App/Sources/NetworkRelayTunBridge/include/NetworkRelayTunBridge.h"
        self.assertTrue(header.is_file())

if __name__ == "__main__":
    unittest.main()
