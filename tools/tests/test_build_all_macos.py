#!/usr/bin/env python3
"""Exercise build orchestration with fake tools; these are not Mac builds."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import textwrap
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "build-all-macos.sh"
BASH = os.environ.get("BASH_TEST_BINARY", "bash")


MOCK_TOOL = r'''
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

tool = Path(sys.argv[0]).name
args = sys.argv[1:]
watched = ["GOOS", "GOARCH", "GOAMD64", "GOARM64", "CGO_ENABLED", "GOFLAGS",
           "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET", "RUSTFLAGS", "CC", "SDKROOT"]
with open(os.environ["MOCK_COMMAND_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps({"tool": tool, "args": args, "cwd": os.getcwd(),
                          "env": {key: os.environ[key] for key in watched
                                  if key in os.environ}}) + "\n")

def emit_binary(path, target):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("MOCK-BINARY " + target + "\n", encoding="utf-8")
    path.chmod(0o755)

if tool == "git":
    if "clone" in args:
        counter = Path(os.environ["MOCK_CLONE_COUNTER"])
        attempt = int(counter.read_text()) + 1 if counter.exists() else 1
        counter.write_text(str(attempt))
        destination = Path(args[-1])
        destination.mkdir(parents=True, exist_ok=True)
        if attempt <= int(os.environ.get("MOCK_CLONE_FAILURES", "0")):
            (destination / "incomplete").write_text("partial download")
            print("fatal: early EOF", file=sys.stderr)
            sys.exit(1)
        (destination / ".git").mkdir()
        (destination / "complete").write_text("source downloaded")
    elif "rev-parse" in args:
        print("a" * 40)
    elif "status" in args:
        pass
elif tool == "cargo":
    if "--version" in args:
        print("cargo 1.99.0")
    elif "build" in args or "zigbuild" in args:
        target = args[args.index("--target") + 1]
        manifest = Path(args[args.index("--manifest-path") + 1]) if "--manifest-path" in args else Path.cwd() / "Cargo.toml"
        root = Path(os.environ.get("CARGO_TARGET_DIR", str(manifest.parent / "target")))
        bins = [args[index + 1] for index, value in enumerate(args[:-1]) if value == "--bin"]
        for binary in bins:
            emit_binary(root / target / "release" / binary, target)
elif tool == "go":
    if "version" in args:
        print("go version go1.27.2 darwin/arm64")
    elif "build" in args:
        emit_binary(args[args.index("-o") + 1], "linux-" + os.environ["GOARCH"])
elif tool == "file":
    path = Path(args[-1])
    if not path.exists():
        print("cannot open " + str(path), file=sys.stderr)
        sys.exit(1)
    contents = path.read_text(encoding="utf-8")
    if "apple-darwin" in contents or "macos-arm64" in contents:
        print("Mach-O 64-bit executable arm64")
    elif "aarch64" in contents or "linux-arm64" in contents:
        print("ELF 64-bit LSB executable, ARM aarch64, statically linked")
    else:
        print("ELF 64-bit LSB executable, x86-64, statically linked")
elif tool == "ditto":
    source, destination = map(Path, args[-2:])
    if "-c" in args:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("MOCK ARCHIVE")
    else:
        shutil.copytree(source, destination, dirs_exist_ok=True)
elif tool == "sw_vers":
    print(os.environ.get("MOCK_MACOS_VERSION", "27.0.1"))
elif tool == "xcrun":
    if os.environ.get("MOCK_XCRUN_FAILURE") == "1":
        sys.exit(1)
    if args[-1:] == ["xctest"] and os.environ.get("MOCK_XCTEST_MISSING") == "1":
        if not os.environ.get("MOCK_XCODE_STATE") or not Path(os.environ["MOCK_XCODE_STATE"]).exists():
            sys.exit(1)
    version = os.environ.get("MOCK_SDK_VERSION", "27.0")
    if os.environ.get("MOCK_XCODE_STATE"):
        version = "27.0" if Path(os.environ["MOCK_XCODE_STATE"]).exists() else version
    print(version if "--show-sdk-version" in args else "/Mock Xcode SDK")
elif tool == "uname":
    print("arm64" if "-m" in args else "Darwin")
elif tool == "rustc":
    print("rustc 1.99.0")
elif tool == "plutil":
    if "-extract" in args:
        print("ExampleExecutable")
elif tool == "mas":
    if "get" in args:
        if os.environ.get("MOCK_MAS_FAILURE") == "1":
            print("App Store sign-in required", file=sys.stderr)
            sys.exit(73)
        if os.environ.get("MOCK_XCODE_STATE"):
            Path(os.environ["MOCK_XCODE_STATE"]).write_text("Xcode installed")
elif tool == "brew":
    if args[:2] == ["list", "--versions"]:
        if os.environ.get("MOCK_MAS_MISSING") == "1":
            sys.exit(1)
        print("mas 3.0.0")
elif tool == "xcodebuild":
    if "-checkFirstLaunchStatus" in args and os.environ.get("MOCK_XCODE_NEEDS_SETUP") == "1":
        marker = Path(os.environ["MOCK_XCODE_STATE"] + ".initialized")
        sys.exit(0 if marker.exists() else 1)
    if "-runFirstLaunch" in args and os.environ.get("MOCK_XCODE_STATE"):
        Path(os.environ["MOCK_XCODE_STATE"] + ".initialized").write_text("setup complete")
elif tool == "xcode-select":
    if args == ["-p"]:
        print(os.environ.get("MOCK_SELECTED_DEVELOPER_DIR", ""))
elif tool == "sudo":
    if args:
        sys.exit(subprocess.call(args))
elif tool == "curl":
    print("Unexpected download in mocked orchestration test", file=sys.stderr)
    sys.exit(97)
'''


class BuildOrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="build orchestration ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.mock_bin = self.root / "mock-bin"
        self.mock_bin.mkdir()
        for name in ("git", "cargo", "go", "file", "ditto", "codesign", "xcrun",
                     "sw_vers", "uname", "rustc", "rustup", "sleep", "plutil",
                     "xcode-select", "mas", "brew", "xcodebuild", "sudo", "open", "curl"):
            path = self.mock_bin / name
            path.write_text("#!" + sys.executable + "\n" + MOCK_TOOL, encoding="utf-8")
            path.chmod(0o755)
        self.log = self.root / "commands.jsonl"
        self.env = os.environ.copy()
        self.env.pop("DEVELOPER_DIR", None)
        self.env.update({
            "PATH": str(self.mock_bin) + os.pathsep + self.env.get("PATH", ""),
            "MOCK_COMMAND_LOG": str(self.log),
            "MOCK_CLONE_COUNTER": str(self.root / "clone-counter"),
        })

    def run_bash(self, body, extra_env=None):
        environment = self.env.copy()
        if extra_env:
            environment.update(extra_env)
        return subprocess.run(
            [BASH, "-c", "set -euo pipefail\nsource " + shlex.quote(str(SCRIPT)) + "\n" + self.variables() + textwrap.dedent(body)],
            cwd=self.root, env=environment, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        )

    def variables(self):
        return textwrap.dedent("""\
            BUILD_ROOT="$PWD/build root"
            SOURCES="$BUILD_ROOT/sources"
            OUT="$BUILD_ROOT/out"
            OUTPUTS="$OUT"
            LOGS="$BUILD_ROOT/logs"
            BUILD_RESULTS="$BUILD_ROOT/results.tsv"
            SOURCE_REVISIONS="$BUILD_ROOT/source-revisions.tsv"
            JOB_FAILURES=0
            MACOS_MAJOR=27
            SDK_MAJOR=27
            mkdir -p "$SOURCES" "$OUT/linux-amd64" "$OUT/linux-arm64" \
                     "$OUT/macos-arm64/bin" "$OUT/macos-arm64/apps" "$LOGS"
            : > "$BUILD_RESULTS"
            : > "$SOURCE_REVISIONS"
            """)

    def commands(self, tool=None):
        records = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        return [record for record in records if tool is None or record["tool"] == tool]

    def test_plan_does_not_install_or_download(self):
        result = subprocess.run([BASH, str(SCRIPT), "--plan"], cwd=self.root,
                                env=self.env, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, check=False)
        self.assertEqual(result.returncode, 0, result.stdout)
        for project in ("caddy-masque", "caddy-network-relay", "masque-vpn",
                        "network-relay", "cf-masque"):
            self.assertIn(project, result.stdout)
        self.assertEqual(self.commands("git"), [])
        self.assertEqual(self.commands("cargo"), [])
        self.assertEqual(self.commands("go"), [])

    def test_sanitizer_removes_inherited_build_overrides(self):
        poisoned = ("CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET", "RUSTFLAGS", "CC",
                    "CXX", "AR", "CFLAGS", "CXXFLAGS", "LDFLAGS", "SDKROOT",
                    "MACOSX_DEPLOYMENT_TARGET", "GOOS", "GOARCH", "GOFLAGS",
                    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER", "RUSTUP_TOOLCHAIN",
                    "CARGO_ENCODED_RUSTFLAGS", "CGO_ENABLED", "CARGO_PROFILE_RELEASE_LTO")
        body = "sanitize_build_env\n" + shlex.quote(sys.executable) + " -c " + shlex.quote(
            "import json, os; print(json.dumps({key: os.environ.get(key) for key in " + repr(poisoned) + "}))")
        result = self.run_bash(body, {key: "POISON" for key in poisoned})
        self.assertEqual(result.returncode, 0, result.stdout)
        captured = json.loads(result.stdout.splitlines()[-1])
        self.assertNotIn("POISON", captured.values(), captured)

    def test_failed_job_stops_before_copy_and_next_job_continues(self):
        result = self.run_bash("""
            failing_job() {
                printf 'before failure\\n'
                false
                touch "$BUILD_ROOT/incorrect-success"
            }
            successful_job() { touch "$BUILD_ROOT/next-job-ran"; }
            run_job fail-example failing_job
            run_job success-example successful_job
            printf 'FAILURES=%s\\n' "$JOB_FAILURES"
            """)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertFalse((self.root / "build root/incorrect-success").exists(), result.stdout)
        self.assertTrue((self.root / "build root/next-job-ran").exists(), result.stdout)
        self.assertIn("FAILURES=1", result.stdout)
        results = (self.root / "build root/results.tsv").read_text()
        self.assertIn("fail-example", results)
        self.assertIn("success-example", results)

    def test_clone_retries_only_its_own_partial_directory(self):
        sentinel = self.root / "build root/sources/do-not-delete"
        sentinel.mkdir(parents=True)
        (sentinel / "keep").write_text("unrelated source")
        result = self.run_bash('clone_repo network-relay\n', {"MOCK_CLONE_FAILURES": "2"})
        self.assertEqual(result.returncode, 0, result.stdout)
        clones = [item for item in self.commands("git") if "clone" in item["args"]]
        self.assertEqual(len(clones), 3, result.stdout)
        self.assertTrue((self.root / "build root/sources/network-relay/complete").exists())
        self.assertEqual((sentinel / "keep").read_text(), "unrelated source")
        self.assertEqual(list((self.root / "build root/sources").rglob("incomplete")), [])

    def test_rust_selects_zig_for_linux_and_native_cargo_for_mac(self):
        repository = self.root / "build root/sources/network-relay"
        repository.mkdir(parents=True)
        (repository / ".git").mkdir()
        (repository / "Cargo.toml").write_text('[package]\nname="network-relay"\nversion="1.0.0"\n')
        (repository / "Cargo.lock").write_text("version = 4\n")
        result = self.run_bash("""
            build_rust network-relay . x86_64-unknown-linux-musl network-relay network-relay
            build_rust network-relay . aarch64-unknown-linux-musl network-relay network-relay
            build_rust network-relay . aarch64-apple-darwin network-relay network-relay
            """)
        self.assertEqual(result.returncode, 0, result.stdout)
        builds = [item for item in self.commands("cargo") if "build" in item["args"] or "zigbuild" in item["args"]]
        self.assertEqual(len(builds), 3, result.stdout)
        for item, target, command in zip(builds,
                                         ("x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl", "aarch64-apple-darwin"),
                                         ("zigbuild", "zigbuild", "build")):
            self.assertIn(command, item["args"])
            self.assertIn(target, item["args"])
            self.assertIn("--locked", item["args"])
            self.assertIn("--release", item["args"])
        artifacts = list((self.root / "build root/out").rglob("*"))
        self.assertEqual(len([path for path in artifacts if path.is_file() and path.read_text().startswith("MOCK-BINARY")]), 3)

    def test_go_preserves_relay_tag_and_portable_architectures(self):
        for repository in ("caddy-masque", "caddy-network-relay"):
            directory = self.root / "build root/sources" / repository
            directory.mkdir(parents=True)
            (directory / ".git").mkdir()
            (directory / "go.mod").write_text("module example.test/caddy\ngo 1.26.0\n")
        result = self.run_bash("""
            build_go caddy-masque amd64 '' caddy-masque
            build_go caddy-network-relay arm64 http2legacy caddy-network-relay
            """)
        self.assertEqual(result.returncode, 0, result.stdout)
        builds = [item for item in self.commands("go") if "build" in item["args"]]
        self.assertEqual(len(builds), 2, result.stdout)
        self.assertNotIn("http2legacy", builds[0]["args"])
        self.assertIn("http2legacy", builds[1]["args"])
        for item, architecture in zip(builds, ("amd64", "arm64")):
            self.assertEqual(item["env"]["GOOS"], "linux")
            self.assertEqual(item["env"]["GOARCH"], architecture)
            self.assertEqual(item["env"]["CGO_ENABLED"], "0")
            self.assertIn("./cmd/caddy", item["args"])
            self.assertIn("-trimpath", item["args"])

    def test_original_app_recipe_spaces_and_checksum_manifest(self):
        repository = self.root / "build root/sources/network-relay"
        (repository / ".git").mkdir(parents=True)
        recipe = repository / "example app/build-macos.sh"
        recipe.parent.mkdir()
        recipe.write_text(textwrap.dedent("""\
            #!/bin/bash
            set -euo pipefail
            cd "$(dirname "$0")"
            mkdir -p 'dist/Example App.app/Contents/MacOS'
            printf 'MOCK-BINARY macos-arm64\\n' > 'dist/Example App.app/Contents/MacOS/ExampleExecutable'
            chmod +x 'dist/Example App.app/Contents/MacOS/ExampleExecutable'
            printf 'mock plist\\n' > 'dist/Example App.app/Contents/Info.plist'
            touch 'recipe-ran'
            """))
        result = self.run_bash("""
            run_job app-example build_app network-relay 'example app/build-macos.sh' \
                'example app/dist/Example App.app' 'Example App' 13
            write_checksums
            """)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue((recipe.parent / "recipe-ran").exists())
        output = self.root / "build root/out"
        self.assertTrue((output / "macos-arm64/apps/Example App.app/Contents/MacOS/ExampleExecutable").is_file())
        self.assertTrue((output / "macos-arm64/apps/Example App.app.zip").is_file())
        manifest = output / "SHA256SUMS"
        rows = manifest.read_text().splitlines()
        self.assertEqual(len(rows), 3)
        for line in rows:
            digest, filename = line.split("  ", 1)
            self.assertNotEqual(filename, "./SHA256SUMS")
            self.assertEqual(digest, hashlib.sha256((output / filename).read_bytes()).hexdigest())
        self.assertIn("Example App.app.zip", manifest.read_text())

    def test_old_sdk_fails_only_app_job_and_next_job_runs(self):
        result = self.run_bash("""
            SDK_MAJOR=26
            subsequent_job() { touch "$BUILD_ROOT/other-job-ran"; }
            run_job unsupported-app build_app absent absent absent 'Network Relay NF' 27
            run_job unrelated-job subsequent_job
            printf 'FAILURES=%s\\n' "$JOB_FAILURES"
            """)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("SDK 27", result.stdout)
        self.assertIn("FAILURES=1", result.stdout)
        self.assertTrue((self.root / "build root/other-job-ran").exists())
        self.assertEqual(list((self.root / "build root/out/macos-arm64/apps").iterdir()), [])

    def test_ietf_recipe_exact_host_requirement_is_preserved(self):
        result = self.run_bash("""
            MACOS_MAJOR=28
            run_job unsupported-host build_app absent absent absent 'IETF Masque' 27 1
            printf 'FAILURES=%s\\n' "$JOB_FAILURES"
            """)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("macOS 27 exactly", result.stdout)
        self.assertIn("FAILURES=1", result.stdout)

    def test_missing_apple_tools_requests_install_and_stops(self):
        result = self.run_bash("""
            ensure_homebrew() { :; }
            prepare_apple_tools
            touch "$BUILD_ROOT/incorrect-bootstrap-success"
            """, {"MOCK_XCRUN_FAILURE": "1"})
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("rerun this script", result.stdout)
        self.assertFalse((self.root / "build root/incorrect-bootstrap-success").exists())
        self.assertIn(["--install"], [item["args"] for item in self.commands("xcode-select")])

    def test_failed_original_app_recipe_is_not_packaged(self):
        repository = self.root / "build root/sources/network-relay"
        (repository / ".git").mkdir(parents=True)
        recipe = repository / "build-macos.sh"
        recipe.write_text("#!/bin/bash\nexit 23\n")
        result = self.run_bash("""
            run_job app-failure build_app network-relay build-macos.sh \
                'dist/Example App.app' 'Example App' 13
            printf 'FAILURES=%s\\n' "$JOB_FAILURES"
            """)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("FAILURES=1", result.stdout)
        self.assertEqual(self.commands("ditto"), [])
        results = (self.root / "build root/results.tsv").read_text()
        self.assertIn("FAIL(23)", results)

    def test_ready_apple_sdk_does_not_install_xcode(self):
        result = self.run_bash("""
            ensure_homebrew() { printf 'unexpected homebrew install\\n'; return 91; }
            prepare_apple_tools 1
            printf 'SDK=%s\\n' "$SDK_MAJOR"
            """, {"MOCK_SDK_VERSION": "27.0"})
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("SDK=27", result.stdout)
        self.assertEqual(self.commands("mas"), [])
        self.assertEqual(self.commands("brew"), [])
        self.assertEqual(self.commands("curl"), [])

    def test_sdk_26_installs_xcode_and_rechecks_sdk_27(self):
        state = self.root / "xcode-installed"
        result = self.run_bash("""
            ensure_homebrew() { :; }
            prepare_apple_tools 1
            printf 'SDK=%s\\n' "$SDK_MAJOR"
            """, {"MOCK_SDK_VERSION": "26.4", "MOCK_XCODE_STATE": str(state),
                   "MOCK_MAS_MISSING": "1"})
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(state.exists())
        self.assertIn("SDK=27", result.stdout)
        self.assertEqual([item["args"] for item in self.commands("mas")],
                         [["get", "--force", "497799835"]])
        self.assertIn(["install", "mas"], [item["args"] for item in self.commands("brew")])
        sdk_probes = [item for item in self.commands("xcrun") if "--show-sdk-version" in item["args"]]
        self.assertGreaterEqual(len(sdk_probes), 3)
        self.assertEqual(self.commands("curl"), [])

    def test_sdk_present_but_xctest_missing_triggers_xcode_install(self):
        state = self.root / "xcode-installed"
        result = self.run_bash("""
            ensure_homebrew() { :; }
            prepare_apple_tools 1
            """, {"MOCK_SDK_VERSION": "27.0", "MOCK_XCTEST_MISSING": "1",
                   "MOCK_XCODE_STATE": str(state)})
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(state.exists())
        self.assertEqual(len(self.commands("mas")), 1)

    def test_no_bootstrap_rejects_old_sdk_without_installing(self):
        result = self.run_bash("""
            prepare_apple_tools 0
            touch "$BUILD_ROOT/incorrect-sdk-success"
            """, {"MOCK_SDK_VERSION": "26.4"})
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("--no-bootstrap", result.stdout)
        self.assertFalse((self.root / "build root/incorrect-sdk-success").exists())
        for command in ("mas", "brew", "curl", "sudo"):
            self.assertEqual(self.commands(command), [], command)
        self.assertNotIn(["--install"], [item["args"] for item in self.commands("xcode-select")])

    def test_app_store_failure_never_claims_sdk_install_success(self):
        state = self.root / "xcode-installed"
        result = self.run_bash("""
            ensure_homebrew() { :; }
            prepare_apple_tools 1
            touch "$BUILD_ROOT/incorrect-sdk-success"
            """, {"MOCK_SDK_VERSION": "26.4", "MOCK_XCODE_STATE": str(state),
                   "MOCK_MAS_FAILURE": "1"})
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(state.exists())
        self.assertFalse((self.root / "build root/incorrect-sdk-success").exists())
        self.assertNotIn("Apple build tools ready", result.stdout)
        self.assertIn("interactive Terminal", result.stdout)
        self.assertEqual(len(self.commands("mas")), 1)
        self.assertEqual(self.commands("curl"), [])

    def test_xcode_first_launch_setup_uses_selected_developer_directory(self):
        state = self.root / "xcode-installed"
        developer = str(self.root / "Custom Xcode.app/Contents/Developer")
        result = self.run_bash("initialize_xcode\n", {
            "DEVELOPER_DIR": developer, "MOCK_XCODE_STATE": str(state),
            "MOCK_XCODE_NEEDS_SETUP": "1",
        })
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(Path(str(state) + ".initialized").is_file())
        commands = self.commands("sudo")
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0]["args"],
                         ["env", "DEVELOPER_DIR=" + developer, "xcodebuild", "-runFirstLaunch"])

    @unittest.skipIf(Path("/Applications/Xcode.app/Contents/Developer").is_dir(),
                     "This case requires a globally selected nondefault Xcode without a default app")
    def test_global_custom_xcode_setup_honors_bootstrap_policy(self):
        state = self.root / "xcode-installed"
        developer = str(self.root / "Custom Xcode.app/Contents/Developer")
        environment = {"MOCK_SELECTED_DEVELOPER_DIR": developer,
                       "MOCK_SDK_VERSION": "27.0", "MOCK_XCODE_STATE": str(state),
                       "MOCK_XCODE_NEEDS_SETUP": "1"}
        refused = self.run_bash("prepare_apple_tools 0\n", environment)
        self.assertNotEqual(refused.returncode, 0, refused.stdout)
        self.assertIn("--no-bootstrap", refused.stdout)
        self.assertEqual(self.commands("sudo"), [])
        self.assertEqual(self.commands("mas"), [])
        prepared = self.run_bash("""
            ensure_homebrew() { printf 'unexpected Homebrew install\\n'; return 91; }
            prepare_apple_tools 1
            printf 'DEVELOPER=%s\\n' "$DEVELOPER_DIR"
            """, environment)
        self.assertEqual(prepared.returncode, 0, prepared.stdout)
        self.assertIn("DEVELOPER=" + developer, prepared.stdout)
        self.assertTrue(Path(str(state) + ".initialized").is_file())
        self.assertEqual([item["args"] for item in self.commands("sudo")],
                         [["env", "DEVELOPER_DIR=" + developer, "xcodebuild", "-runFirstLaunch"]])
        self.assertEqual(self.commands("mas"), [])
        self.assertEqual(self.commands("brew"), [])
        self.assertEqual(self.commands("curl"), [])
        self.assertGreaterEqual(len([item for item in self.commands("xcode-select")
                                     if item["args"] == ["-p"]]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
