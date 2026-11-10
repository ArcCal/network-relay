#!/usr/bin/env python3
"""Check sourced Caddy download helpers with local fixtures and fake Go."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PROXY = "https://proxy.golang.org|direct"
POLICY = {"GOSUMDB": "sum.example.invalid+0123456789abcdef https://sum.example.invalid",
          "GONOSUMDB": "private.example.invalid", "GOPRIVATE": "private.example.invalid",
          "GOINSECURE": "private.example.invalid"}

FAKE_GO = r'''
import json, os, pathlib, sys
args = sys.argv[1:]
keys = ("GOPROXY", "GOSUMDB", "GONOSUMDB", "GOPRIVATE", "GOINSECURE")
with open(os.environ["TEST_GO_LOG"], "a") as log:
    log.write(json.dumps({"args": args, "env": {k: os.environ[k] for k in keys if k in os.environ}}) + "\n")
if args == ["version"]:
    print("go version go1.27.3 linux/amd64")
elif args == ["env", "GOVERSION"]:
    print("go1.27.3")
elif args[:2] == ["mod", "edit"]:
    pass
elif args[0] in ("get", "build"):
    if os.environ.get("TEST_GO_FAIL") == args[0]:
        print("controlled dependency fetch failure", file=sys.stderr)
        raise SystemExit(1)
    if args[0] == "build":
        pathlib.Path(args[args.index("-o") + 1]).write_bytes(b"fixture executable")
else:
    raise SystemExit("unexpected Go command")
'''

DRIVER = r'''
set -euo pipefail
source "$1/build-linux-servers-on-linux.sh"
caddy_src=$2/caddy-src
cloudflare_src=$2/cloudflare-src
work=$2
output=$2/output
host_arch=arm64
jobs=2
failures=0
# Exercise the existing retry loop without spending time in retry delays.
sleep() { :; }
lr_run prepare-caddy lr_prepare_caddy
(( failures == 0 )) || exit 1
lr_run build-caddy lr_build_caddy amd64
(( failures == 0 ))
'''


class CaddyDownloadTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="relay-caddy-test-", dir="/tmp")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.case = 0
        tools = self.directory / "bin"
        tools.mkdir()
        go = tools / "go"
        go.write_text(f"#!{sys.executable}\n" + FAKE_GO)
        go.chmod(0o755)
        self.env = dict(os.environ, PATH=f"{tools}:{os.environ['PATH']}", **POLICY)
        self.env.pop("GOPROXY", None)

    def run_helpers(self, **environment):
        self.case += 1
        case = self.directory / str(self.case)
        caddy = case / "caddy-src"
        cloudflare = case / "cloudflare-src"
        for directory in (caddy / "cmd/caddy", caddy / "third_party/x-net",
                          caddy / "third_party/quic-go", cloudflare, case / "output/logs"):
            directory.mkdir(parents=True, exist_ok=True)
        (caddy / "go.mod").write_text("module fixture.example/caddy\n\ngo 1.26.0\n")
        (caddy / "go.sum").write_text("fixture checksum\n")
        (caddy / "app.go").write_text('ID: "network_relay"\n')
        (caddy / "handler.go").write_text('ID: "http.handlers.network_relay"\n')
        (cloudflare / "go.mod").write_text("module github.com/caddy-dns/cloudflare\n")
        (cloudflare / "cloudflare.go").write_text('ID: "dns.providers.cloudflare"\n')
        log = case / "go.jsonl"
        result = subprocess.run(["bash", "-c", DRIVER, "caddy-test", str(ROOT), str(case)],
                                env=dict(self.env, TEST_GO_LOG=str(log), **environment),
                                capture_output=True, text=True, timeout=10)
        commands = [json.loads(line) for line in log.read_text().splitlines()]
        return result, commands, case

    def assert_policy(self, commands, proxy):
        self.assertTrue(commands)
        for command in commands:
            self.assertEqual(command["env"].get("GOPROXY"), proxy, command)
            for key, value in POLICY.items():
                self.assertEqual(command["env"].get(key), value, command)

    def test_default_proxy_reaches_separate_prepare_and_build_stages(self):
        result, commands, case = self.run_helpers()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_policy(commands, DEFAULT_PROXY)
        self.assertEqual(sum(command["args"][0] == "get" for command in commands), 1)
        build = next(command["args"] for command in commands if command["args"][0] == "build")
        self.assertIn("-mod=readonly", build)
        self.assertTrue((case / "caddy-network-relay-amd64").is_file())

    def test_explicit_proxy_and_security_policy_are_preserved(self):
        for proxy in ("off", "direct", "https://proxy.example.invalid", "",
                      "https://proxy.golang.org,direct"):
            with self.subTest(proxy=proxy):
                result, commands, _ = self.run_helpers(GOPROXY=proxy)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assert_policy(commands, proxy)

    def test_dependency_fetch_failure_remains_fatal_and_prevents_build(self):
        result, commands, case = self.run_helpers(TEST_GO_FAIL="get")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sum(command["args"][0] == "get" for command in commands), 3)
        self.assertFalse(any(command["args"][0] == "build" for command in commands))
        self.assertFalse((case / "caddy-network-relay-amd64").exists())

    def test_fetch_failure_during_build_remains_fatal(self):
        result, commands, case = self.run_helpers(TEST_GO_FAIL="build")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sum(command["args"][0] == "build" for command in commands), 1)
        self.assertFalse((case / "caddy-network-relay-amd64").exists())


if __name__ == "__main__":
    unittest.main()
