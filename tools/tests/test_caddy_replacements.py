"""Exercise Linux artifact publication using controlled Go build metadata."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
FORKS = (
    ("github.com/quic-go/quic-go", "./third_party/quic-go"),
    ("golang.org/x/net", "./third_party/x-net"),
    ("github.com/go-jose/go-jose/v3", "./third_party/go-jose-v3"),
    ("github.com/go-jose/go-jose/v4", "./third_party/go-jose-v4"),
)


class CaddyReplacementTests(unittest.TestCase):
    def run_case(self, missing="", wrong="", missing_tag=False):
        with tempfile.TemporaryDirectory(prefix="relay-caddy-forks-") as temporary:
            root = Path(temporary)
            tools = root / "bin"
            tools.mkdir()
            metadata = ["\tpath\tgithub.com/arccal/caddy-network-relay/cmd/caddy",
                        "\tdep\tgithub.com/caddy-dns/cloudflare\tv0.2.4",
                        "\t=>\t../cloudflare-src\t(devel)"]
            for module, replacement in FORKS:
                metadata.append("\tdep\t" + module + "\tv0.0.0")
                if module != missing:
                    metadata.append("\t=>\t" + replacement +
                                    ("-unreviewed" if module == wrong else "") + "\t(devel)")
            metadata += ["\tbuild\tGOARCH=amd64", "\tbuild\tCGO_ENABLED=0"]
            if not missing_tag:
                metadata.append("\tbuild\t-tags=http2legacy,relay_tls9846_v1")
            go = tools / "go"
            go.write_text(f"#!{sys.executable}\nprint({chr(10).join(metadata)!r})\n")
            go.chmod(0o755)
            for name, output in (("file", "ELF 64-bit LSB executable, x86-64, statically linked"),
                                 ("readelf", "fixture ELF headers")):
                tool = tools / name
                tool.write_text(f"#!{sys.executable}\nprint({output!r})\n")
                tool.chmod(0o755)
            binary = root / "candidate"
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)
            destination = root / "output"
            destination.mkdir()
            command = '''set -euo pipefail
source "$1/build-linux-servers-on-linux.sh"
host_arch=arm64
output=$2/output
lr_collect "$2/candidate" caddy-network-relay amd64
'''
            result = subprocess.run(["bash", "-c", command, "fork-check", str(ROOT), str(root)],
                                    env=dict(os.environ, PATH=f"{tools}:{os.environ['PATH']}"),
                                    capture_output=True, text=True, timeout=10)
            published = (destination / "caddy-network-relay-linux-amd64").exists()
            return result, published

    def test_all_four_reviewed_forks_are_required_before_publication(self):
        result, published = self.run_case()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(published)
        for module, _ in FORKS:
            with self.subTest(missing=module):
                result, published = self.run_case(missing=module)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(published)

    def test_tls_policy_is_required_before_publication(self):
        result, published = self.run_case(missing_tag=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('TLS policy build tag', result.stderr)
        self.assertFalse(published)

    def test_unreviewed_jose_paths_are_rejected(self):
        for module, _ in FORKS[2:]:
            with self.subTest(wrong_path=module):
                result, published = self.run_case(wrong=module)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(published)


if __name__ == "__main__":
    unittest.main()
