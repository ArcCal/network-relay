"""Permission checks with isolated fixtures; no native build or network access."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
BASH = os.environ.get("BASH_TEST_BINARY", "bash")


class BuildPermissionTests(unittest.TestCase):
    def test_sourcing_helpers_preserves_caller_umask(self):
        for name in ("build-linux-clients-on-linux.sh", "build-linux-servers-on-linux.sh",
                     "tools/build-all-macos.sh"):
            for mask in (0o000, 0o077):
                with self.subTest(script=name, umask=oct(mask)):
                    result = subprocess.run(
                        [BASH, "-c", 'source "$1"; umask', "source-check", str(ROOT / name)],
                        capture_output=True, text=True, umask=mask, check=True)
                    self.assertEqual(int(result.stdout.strip(), 8), mask)

    def test_observation_failure_keeps_new_diagnostics_private(self):
        with tempfile.TemporaryDirectory(prefix="relay-observe-permissions-") as temporary:
            root = Path(temporary)
            tools = root / "tools"
            tools.mkdir()
            for name in ("uname", "git", "sw_vers", "xcodebuild", "xcrun", "shasum", "curl"):
                tool = tools / name
                if name == "uname":
                    body = 'case "$1" in -s) echo Darwin ;; *) echo arm64 ;; esac'
                elif name == "curl":
                    body = 'printf "fixture download failure\\n" >&2; exit 37'
                else:
                    body = "exit 0"
                tool.write_text("#!/bin/sh\n" + body + "\n")
                tool.chmod(0o755)
            app = root / "fixture-app"
            app.touch()
            output = root / "observations"
            result = subprocess.run(
                [BASH, str(ROOT / "network-relay-nf/scripts/observe-native.sh"), "rust", "h3", str(output)],
                env=dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"],
                         NF_APP_EXECUTABLE=str(app), NF_DOWNLOAD_URL="https://fixture.invalid/data",
                         NF_DOWNLOAD_SHA256="0" * 64), capture_output=True, text=True, umask=0o000)
            self.assertEqual(result.returncode, 37, result.stdout + result.stderr)
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            self.assertIn("fixture download failure", (output / "download.log").read_text())
            self.assertIn("INCOMPLETE", (output / "result.txt").read_text())
            for path in output.iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600, path)


if __name__ == "__main__":
    unittest.main()
