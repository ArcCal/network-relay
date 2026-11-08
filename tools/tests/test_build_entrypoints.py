# Source/bootstrap control flow with local Git fixtures, not native Mac builds.
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
REAL_GIT = shutil.which("git")
REAL_MKTEMP = shutil.which("mktemp")
KEYS = ("CARGO_HOME", "RUSTUP_HOME", "CARGO_TARGET_DIR", "TMPDIR", "GOCACHE",
        "GOPATH", "GOMODCACHE", "GOTMPDIR", "PIP_CACHE_DIR", "ZIG_GLOBAL_CACHE_DIR",
        "ZIG_LOCAL_CACHE_DIR", "CLANG_MODULE_CACHE_PATH", "SWIFTPM_MODULECACHE_OVERRIDE")

TOOL = r'''import json, os, pathlib, subprocess, sys
p = pathlib.Path
tool = p(sys.argv[0]).name
args = sys.argv[1:]
entry = {"tool": tool, "args": args, "cwd": os.getcwd(),
         "cf_token_present": "CF_API_TOKEN" in os.environ}
with open(os.environ["TEST_COMMANDS"], "a") as log: log.write(json.dumps(entry) + "\n")
if tool == "git":
    if "clone" in args and args[-2] != "https://github.com/ArcCal/network-relay.git":
        raise SystemExit("unexpected clone source; fixture forbids network access")
    if any(action in args for action in ("fetch", "pull", "ls-remote")):
        raise SystemExit("fixture forbids remote network commands")
    args = ["protocol.file.allow=always" if a == "protocol.file.allow=never" else a for a in args]
    args = [os.environ["TEST_REMOTE"] if a == "https://github.com/ArcCal/network-relay.git" else a for a in args]
    if "clone" in args and (os.environ.get("TEST_DOWNLOAD_FAIL") == "1" or
                            os.environ.get("TEST_REQUIRE_TOKEN") and not os.environ.get("GIT_CONFIG_VALUE_1")):
        p(args[-1]).mkdir(parents=True, exist_ok=True)
        (p(args[-1]) / "partial").write_text("incomplete")
        raise SystemExit(1)
    os.execv(os.environ["TEST_REAL_GIT"], [os.environ["TEST_REAL_GIT"], *args])
elif tool == "env": os.execv("/usr/bin/env", ["/usr/bin/env", *args])
elif tool == "uname": print("arm64" if args == ["-m"] else "Darwin" if os.environ.get("TEST_MAC") else "Linux")
elif tool in ("sw_vers", "xcrun"): print("27.0")
elif tool == "rustup":
    if args and args[0] == "which":
        if not os.environ.get("TEST_INSTALLED_TOOLCHAIN"): raise SystemExit(1)
        print(str(p(os.environ["TEST_INSTALLED_TOOLCHAIN"]) / "bin/rustc"))
    elif args[:2] == ["toolchain", "link"]:
        link = p(os.environ["RUSTUP_HOME"]) / "toolchains" / args[2]
        link.parent.mkdir(parents=True, exist_ok=True); link.symlink_to(args[3])
    elif os.environ.get("TEST_INSTALLED_TOOLCHAIN"):
        raise SystemExit("existing complete toolchain must not be installed or modified")
elif tool == "df":
    if "-PT" in args:
        kind = "tmpfs" if os.environ.get("TEST_TMPFS") and args[-1] not in ("/var/tmp", os.environ["TEST_CALLER"]) else "ext4"
        print("Filesystem Type 1024-blocks Used Available Capacity Mounted on\nfixture " + kind + " 9000000 0 9000000 0% /")
    else: print("Filesystem 1024-blocks Used Available Capacity Mounted on\nfixture 9000000 0 9000000 0% /")
elif tool == "mktemp":
    if args[-1].startswith("/var/tmp/"):
        args[-1] = str(p(os.environ["TEST_DISK"]) / p(args[-1]).name)
    os.execv(os.environ["TEST_REAL_MKTEMP"], [os.environ["TEST_REAL_MKTEMP"], *args])
elif tool == "cargo" and args == ["build", "--help"]:
    print("Usage: cargo build [OPTIONS]")
elif tool in ("cargo", "record-build"):
    env = {k: os.environ[k] for k in json.loads(os.environ["TEST_KEYS"]) if k in os.environ}
    record = {"cwd": os.getcwd(), "args": args, "env": env,
              "source": os.environ["RELAY_FRESH_SOURCE_ROOT"], "work": os.environ["RELAY_BUILD_WORK_ROOT"],
              "ambient_target": os.environ.get("CARGO_BUILD_TARGET"),
              "toolchain": os.environ.get("RUSTUP_TOOLCHAIN"),
              "config_copied": (p(env["CARGO_HOME"]) / "config.toml").exists(),
              "credential_mode": (p(env["CARGO_HOME"]) / "credentials.toml").stat().st_mode & 0o777}
    source = p(record["source"])
    record["version"] = (source / "remote-version").read_text()
    record["history"] = subprocess.check_output([os.environ["TEST_REAL_GIT"], "-C", str(source), "rev-list", "--all", "--count"], text=True).strip()
    record["branches"] = subprocess.check_output([os.environ["TEST_REAL_GIT"], "-C", str(source), "for-each-ref", "--format=%(refname:short)", "refs/remotes/origin"], text=True).splitlines()
    record["shallow"] = subprocess.check_output([os.environ["TEST_REAL_GIT"], "-C", str(source), "rev-parse", "--is-shallow-repository"], text=True).strip()
    if tool == "record-build" and os.environ.get("TEST_WAIT"):
        child = subprocess.Popen(["/bin/sleep", "30"])
        record["pid"] = os.getpid(); record["child_pid"] = child.pid; record["pgid"] = os.getpgrp()
    p(os.environ["TEST_RECORD"]).write_text(json.dumps(record))
    cache = p(env["GOMODCACHE"]) / "readonly"
    cache.mkdir(parents=True, exist_ok=True); (cache / "cached-source").write_text("temporary"); cache.chmod(0o555)
    if tool == "record-build" and os.environ.get("TEST_WAIT"): child.wait()
    if tool == "cargo" and "build" in args and os.environ.get("TEST_CARGO_EXIT", "0") == "0":
        target = args[args.index("--target") + 1] if "--target" in args else ""
        binary = p(env["CARGO_TARGET_DIR"]) / target / "release/network-relay-cf-masque"
        binary.parent.mkdir(parents=True, exist_ok=True); binary.write_text("fresh binary"); binary.chmod(0o755)
    raise SystemExit(int(os.environ.get("TEST_CARGO_EXIT", "0") if tool == "cargo" else os.environ.get("TEST_PROBE_EXIT", "0")))
'''

PROBE = '''#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")" && pwd)
source "$root/tools/fresh-build-source.sh"
relay_require_fresh_source "$root" probe.sh "$@"
relay_prepare_build_environment "${RELAY_BUILD_WORK_ROOT:-$root/.work}"
swift build --cache-path /old-user-cache --config-path=/old-user-config --security-path /old-user-security
record-build
'''


class BuildEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="relay-entry-test-", dir="/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.remote = self.directory / "remote"
        self.remote.mkdir()
        self.git("init", "--quiet", "--initial-branch=main", str(self.remote))
        self.git("-C", str(self.remote), "config", "user.name", "Anonymous")
        self.git("-C", str(self.remote), "config", "user.email", "anonymous@example.invalid")
        for name in ["tools/fresh-build-source.sh", "tools/linux-build-memory.sh", "tools/run-build-child.sh",
                     "network-relay-nf/build-macos.sh", "network-relay-nf/VERSION",
                     "network-relay-rs/build-macos.sh", "network-relay-rs/VERSION",
                     "network-relay-cf-masque/scripts/build.sh", "network-relay-cf-masque/scripts/env.sh"]:
            target = self.remote / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        (self.remote / "probe.sh").write_text(PROBE)
        self.commit("one")
        self.git("-C", str(self.remote), "branch", "archive")
        self.caller = self.directory / "caller"
        self.git("clone", "--quiet", str(self.remote), str(self.caller))
        self.tools = self.directory / "tools"
        self.tools.mkdir()
        for tool in ("git", "uname", "sw_vers", "xcrun", "rustup", "cargo", "swift", "df", "mktemp",
                     "sleep", "env", "record-build", "plutil", "sips", "iconutil", "codesign", "ditto", "shasum", "otool"):
            path = self.tools / tool
            path.write_text(f"#!{sys.executable}\n" + TOOL)
            path.chmod(0o755)
        cargo = self.directory / "existing-cargo"
        cargo.mkdir()
        (cargo / "config.toml").write_text('[source.crates-io]\nreplace-with="stale-local-source"\n')
        (cargo / "credentials.toml").write_text("fixture credentials")
        self.disk = self.directory / "disk-work"
        self.disk.mkdir()
        self.env = dict(os.environ, PATH=f"{self.tools}:{os.environ['PATH']}", CDPATH=".",
                        TEST_REAL_GIT=REAL_GIT, TEST_REAL_MKTEMP=REAL_MKTEMP, TEST_REMOTE=str(self.remote),
                        TEST_COMMANDS=str(self.directory / "commands.jsonl"), TEST_KEYS=json.dumps(KEYS),
                        TEST_RECORD=str(self.directory / "record.json"), TEST_DISK=str(self.disk),
                        TEST_CALLER=str(self.caller),
                        TEST_PYTHON=sys.executable,
                        CARGO_HOME=str(cargo), RUSTUP_HOME=str(self.directory / "existing-rustup"),
                        CARGO_TARGET_DIR="old-target", CARGO_BUILD_TARGET="wrong-target",
                        TMPDIR=str(self.directory / "caller-temp"), CF_API_TOKEN="fixture-cloudflare-token")
        Path(self.env["TMPDIR"]).mkdir()
        for key in list(self.env):
            if key.startswith("RELAY_") or key in ("NETWORK_RELAY_TOKEN", "GIT_CONFIG_COUNT", "RUSTUP_TOOLCHAIN"):
                self.env.pop(key)

    def git(self, *args):
        identity = dict(os.environ, GIT_AUTHOR_NAME="Anonymous", GIT_AUTHOR_EMAIL="anonymous@example.invalid",
                        GIT_COMMITTER_NAME="Anonymous", GIT_COMMITTER_EMAIL="anonymous@example.invalid")
        return subprocess.run([REAL_GIT, *args], env=identity, check=True, capture_output=True, text=True).stdout.strip()

    def commit(self, version):
        (self.remote / "remote-version").write_text(version)
        (self.remote / "probe.sh").write_text(PROBE.replace("record-build\n", f"record-build --driver-revision={version}\n"))
        self.git("-C", str(self.remote), "add", ".")
        self.git("-C", str(self.remote), "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", version)

    def run_build(self, script="probe.sh", *args, **environment):
        result = subprocess.run(["bash", str(self.caller / script), *args], cwd=self.caller,
                                env=dict(self.env, **environment), capture_output=True, text=True)
        record = json.loads(Path(self.env["TEST_RECORD"]).read_text()) if Path(self.env["TEST_RECORD"]).exists() else None
        return result, record

    def commands(self):
        return [json.loads(line) for line in Path(self.env["TEST_COMMANDS"]).read_text().splitlines()]

    def assert_private_and_cleaned(self, record):
        source, work = Path(record["source"]), Path(record["work"])
        self.assertRegex(str(source), r"^/tmp/network-relay-\d{8}-\d{6}\.[^/]+/network-relay$")
        self.assertNotEqual(source.parent, Path(self.env["TMPDIR"]))
        self.assertFalse(source.parent.exists(), "source workspace survived build exit")
        self.assertFalse(work.exists(), "compiler workspace survived build exit")
        for value in record["env"].values():
            self.assertTrue(Path(value).is_relative_to(work), value)
        self.assertFalse(record["config_copied"])
        self.assertEqual(record["credential_mode"], 0o600)
        self.assertEqual(record["shallow"], "false")
        self.assertIn("origin/archive", record["branches"])

    def test_install_wrapper_help_with_cdpath(self):
        for script in ("install-debian13.sh", "install-from-source.sh"):
            result = subprocess.run(["bash", f"deploy/{script}", "--help"], cwd=ROOT,
                                    env=dict(os.environ, CDPATH="."), capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("usage:", result.stdout)

    def test_latest_full_sources_ignore_dirty_caller_and_tmpdir(self):
        (self.caller / "remote-version").write_text("dirty old copy")
        self.commit("two")
        first, record = self.run_build()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(record["version"], "two")
        self.assertEqual(record["history"], "2")
        self.assertEqual(record["args"], ["--driver-revision=two"])
        self.assert_private_and_cleaned(record)
        self.commit("three")
        second, newer = self.run_build()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(newer["version"], "three")
        self.assertEqual(newer["args"], ["--driver-revision=three"])
        self.assertNotEqual(record["source"], newer["source"])
        self.assert_private_and_cleaned(newer)
        self.assertEqual((self.caller / "remote-version").read_text(), "dirty old copy")
        clones = [item for item in self.commands() if item["tool"] == "git" and "clone" in item["args"]]
        self.assertEqual(len(clones), 2)
        self.assertTrue(all("--recurse-submodules" in item["args"] and "--depth" not in item["args"] for item in clones))
        self.assertTrue(all(not item["cf_token_present"] for item in clones))
        swift = [item for item in self.commands() if item["tool"] == "swift" and item["args"][:1] == ["build"]]
        self.assertTrue(swift)
        self.assertFalse(any("old-user" in value for item in swift for value in item["args"]))

    def test_disk_fallback_and_failed_build_are_cleaned(self):
        result, record = self.run_build(TEST_TMPFS="1", TEST_PROBE_EXIT="37")
        self.assertEqual(result.returncode, 37, result.stderr)
        work = Path(record["work"])
        self.assertTrue(work.is_relative_to(self.disk) or work.parent == self.caller)
        self.assert_private_and_cleaned(record)

    def test_failed_download_is_cleaned(self):
        result, record = self.run_build(TEST_DOWNLOAD_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(record)
        clones = [item for item in self.commands() if item["tool"] == "git" and "clone" in item["args"]]
        self.assertEqual(len(clones), 3)
        self.assertTrue(all(not Path(item["args"][-1]).parent.exists() for item in clones))

    def test_targeted_signal_stops_descendants_before_cleaning_source_and_work(self):
        process = subprocess.Popen(["bash", str(self.caller / "probe.sh")], cwd=self.caller,
                                   env=dict(self.env, TEST_WAIT="1", TEST_TMPFS="1"),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        record = None
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if Path(self.env["TEST_RECORD"]).exists():
                    try:
                        record = json.loads(Path(self.env["TEST_RECORD"]).read_text())
                        break
                    except json.JSONDecodeError:
                        pass
                if process.poll() is not None:
                    self.fail(str(process.communicate()))
                time.sleep(0.02)
            self.assertIsNotNone(record, "build child never started")
            process.send_signal(signal.SIGTERM)
            _, error = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 143, error)
            self.assert_private_and_cleaned(record)
            for pid in (record["pid"], record["child_pid"]):
                status = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True)
                self.assertTrue(not status.stdout.strip() or status.stdout.strip().startswith("Z"))
        finally:
            if record and record["pgid"] != os.getpgrp():
                try:
                    os.killpg(record["pgid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if process.poll() is None:
                process.terminate()
                try:
                    process.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()

    def test_standalone_linux_runner_stays_synced_with_shared_helper(self):
        expected = "\n".join((ROOT / "tools/run-build-child.sh").read_text().splitlines()[2:]).strip()
        for name in ("build-linux-clients-on-linux.sh", "build-linux-servers-on-linux.sh"):
            text = (ROOT / name).read_text()
            inline = text.split("# BEGIN SHARED BUILD CHILD RUNNER\n", 1)[1].split("# END SHARED BUILD CHILD RUNNER", 1)[0]
            self.assertEqual(inline.strip(), expected, name)

    def marked_context(self, root=None):
        path = self.directory / "context.json"
        command = ('source "$1/tools/fresh-build-source.sh"; relay_mark_fresh_source "$1"; '
                   '"$2" -c \'import json,os,sys; open(sys.argv[1],"w").write(json.dumps('
                   '{k:v for k,v in os.environ.items() if k.startswith("RELAY_FRESH_SOURCE_")}))\' "$3"')
        result = subprocess.run(["bash", "-c", command, "context", str(root or self.caller), sys.executable, str(path)],
                                env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(path.read_text())

    def test_dead_or_unrelated_live_marker_owner_cannot_reuse_old_sources(self):
        context = self.marked_context()
        self.commit("two")
        result, record = self.run_build(**context)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(record["version"], "two")
        self.assert_private_and_cleaned(record)
        unrelated = subprocess.Popen(["/bin/sleep", "30"])
        self.addCleanup(lambda: unrelated.poll() is None and unrelated.terminate())
        try:
            marker = Path(context["RELAY_FRESH_SOURCE_MARKER"])
            marker.write_text(f"{unrelated.pid}\n{context['RELAY_FRESH_SOURCE_COMMIT']}\n")
            self.assertIsNone(unrelated.poll(), "unrelated owner must still be alive")
            result, record = self.run_build(**context)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(record["version"], "two")
            self.assert_private_and_cleaned(record)
        finally:
            unrelated.terminate()
            unrelated.wait()

    def test_live_same_invocation_handoff_preserves_explicit_snapshot(self):
        work = self.directory / "handoff-work"
        work.mkdir()
        command = ('source "$1/tools/fresh-build-source.sh"; relay_mark_fresh_source "$1"; '
                   'export RELAY_BUILD_WORK_ROOT="$2"; bash "$1/probe.sh"')
        self.commit("two")
        result = subprocess.run(["bash", "-c", command, "handoff", str(self.caller), str(work)],
                                env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(Path(self.env["TEST_RECORD"]).read_text())
        self.assertEqual(record["version"], "one")
        self.assertEqual(Path(record["source"]), self.caller)
        self.assertFalse(any(item["tool"] == "git" and "clone" in item["args"] for item in self.commands()))
        for directory in work.rglob("*"):
            if directory.is_dir():
                directory.chmod(0o700)

    def test_native_recipes_use_fresh_private_targets_on_failure(self):
        self.commit("two")
        for name in ("network-relay-nf", "network-relay-rs"):
            with self.subTest(name=name):
                result, record = self.run_build(f"{name}/build-macos.sh", TEST_MAC="1", TEST_CARGO_EXIT="37")
                self.assertEqual(result.returncode, 37, result.stderr)
                self.assertEqual(record["version"], "two")
                self.assertTrue(Path(record["cwd"]).is_relative_to(Path(record["source"])))
                self.assertIsNone(record["ambient_target"])
                self.assert_private_and_cleaned(record)

    def test_cf_build_forwards_target_and_retains_only_final_binary(self):
        result, record = self.run_build("network-relay-cf-masque/scripts/build.sh", "--target", "aarch64-unknown-linux-musl")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("aarch64-unknown-linux-musl", record["args"])
        self.assertEqual(Path(record["cwd"]), Path(record["source"]) / "network-relay-cf-masque")
        self.assert_private_and_cleaned(record)
        target = self.caller / "network-relay-cf-masque/target"
        self.assertEqual([str(f.relative_to(target)) for f in target.rglob("*") if f.is_file()],
                         ["aarch64-unknown-linux-musl/release/network-relay-cf-masque"])
        clones = sum(item["tool"] == "git" and "clone" in item["args"] for item in self.commands())
        for option in ("--manifest-path", "--target-dir=/old-cache", "--build-dir=/old-cache", "--config=old-source.toml"):
            rejected, _ = self.run_build("network-relay-cf-masque/scripts/build.sh", option)
            self.assertEqual(rejected.returncode, 2, rejected.stderr)
            self.assertIn("Source and cache path overrides", rejected.stderr)
        help_result, _ = self.run_build("network-relay-cf-masque/scripts/build.sh", "--help")
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("Usage:", help_result.stdout)
        self.assertEqual(clones, sum(item["tool"] == "git" and "clone" in item["args"] for item in self.commands()))

    def test_existing_complete_toolchain_is_reused_without_global_changes(self):
        existing = self.directory / "installed-toolchain"
        (existing / "bin").mkdir(parents=True)
        for name in ("cargo", "rustc"):
            path = existing / "bin" / name
            path.write_text("#!/bin/sh\nexit 0\n")
            path.chmod(0o555)
        library = existing / "lib/rustlib/aarch64-apple-darwin/lib/libstd-fixture.rlib"
        library.parent.mkdir(parents=True)
        library.write_text("existing library")
        library.chmod(0o444)
        before = {str(path.relative_to(existing)): path.stat().st_mode for path in existing.rglob("*")}
        result, record = self.run_build("network-relay-rs/build-macos.sh", TEST_MAC="1",
                                        TEST_CARGO_EXIT="37", TEST_INSTALLED_TOOLCHAIN=str(existing))
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertEqual(record["toolchain"], "relay-existing")
        self.assert_private_and_cleaned(record)
        self.assertEqual(before, {str(path.relative_to(existing)): path.stat().st_mode for path in existing.rglob("*")})

    def test_token_fallback_never_places_authorization_in_process_arguments(self):
        result, record = self.run_build(TEST_REQUIRE_TOKEN="1", NETWORK_RELAY_TOKEN="fixture-token", GIT_CONFIG_VALUE_1="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_private_and_cleaned(record)
        env_calls = [item for item in self.commands() if item["tool"] == "env"]
        self.assertTrue(env_calls)
        self.assertFalse(any("Authorization: Basic " in argument
                             for item in env_calls for argument in item["args"]))

    def test_linux_private_handoff_rejects_unmarked_or_dead_owner_sources(self):
        for name, label in (("build-linux-clients-on-linux.sh", "network-relay-linux-clients"),
                            ("build-linux-servers-on-linux.sh", "relay-servers")):
            with self.subTest(script=name), tempfile.TemporaryDirectory(
                    prefix=f"{label}.20261108-010203.", dir="/tmp") as temporary:
                stage = Path(temporary)
                checkout = stage / "network-relay-checkout"
                self.git("clone", "--quiet", str(self.remote), str(checkout))
                commit = self.git("-C", str(checkout), "rev-parse", "HEAD")
                (stage / ".owner").write_text(commit + "\n")
                work = self.directory / f"{label}-work.20261108-010203.fixture"
                work.mkdir()
                args = ["bash", str(ROOT / name), "--build-updated", str(checkout), str(stage),
                        str(self.directory / "artifacts"), commit, "2", "0", "--fresh-sources-v1", str(work)]
                for context in ({}, self.marked_context(checkout)):
                    result = subprocess.run(args, cwd=self.caller, env=dict(self.env, **context),
                                            capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("Source handoff does not belong to this live build invocation", result.stderr)
                self.assertFalse(any(item["tool"] in ("cargo", "rustup", "record-build") for item in self.commands()))

    def test_linux_backend_refuses_output_without_mutating_caller_files(self):
        wrapper = '''source() {
    if [[ $1 == /etc/os-release ]]; then ID=debian; VERSION_ID=13;
    else builtin source "$@"; fi
}
export -f source
source "$1/tools/fresh-build-source.sh"
relay_mark_fresh_source "$1"
shift
"$BASH" "$@"
'''
        for name, label in (("build-linux-clients-on-linux.sh", "network-relay-linux-clients"),
                            ("build-linux-servers-on-linux.sh", "relay-servers")):
            with self.subTest(script=name), tempfile.TemporaryDirectory(
                    prefix=f"{label}.20261108-010203.", dir="/tmp") as temporary:
                stage = Path(temporary)
                checkout = stage / "network-relay-checkout"
                self.git("clone", "--quiet", str(self.remote), str(checkout))
                commit = self.git("-C", str(checkout), "rev-parse", "HEAD")
                (stage / ".owner").write_text(commit + "\n")
                work = self.directory / f"{label}-work.20261108-010203.output-check"
                work.mkdir()
                invalid = self.directory / (label + "-existing-output")
                invalid.mkdir(mode=0o750)
                invalid.chmod(0o750)
                (invalid / ".work").write_text("caller file")
                for output, message in ((invalid, "--output must be a new or empty directory"),
                                        (stage / "artifacts", "Output and source directories cannot overlap")):
                    command = ["bash", "-c", wrapper, "backend", str(checkout), str(ROOT / name),
                               "--build-updated", str(checkout), str(stage), str(output), commit,
                               "2", "0", "--fresh-sources-v1", str(work)]
                    result = subprocess.run(command, cwd=self.caller, env=self.env, capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(message, result.stderr)
                    self.assertEqual((invalid / ".work").read_text(), "caller file")
                    self.assertEqual(invalid.stat().st_mode & 0o777, 0o750)
                self.assertFalse(any(item["tool"] in ("cargo", "record-build") for item in self.commands()))

    def test_linux_launchers_run_downloaded_driver_and_clean_failed_source(self):
        driver = '''#!/usr/bin/env bash
set -euo pipefail
source "$2/tools/fresh-build-source.sh"
relay_source_is_current "$2" || { printf 'Missing live source handoff.\n' >&2; exit 99; }
"$TEST_PYTHON" - "$@" <<'PY'
import json, os, pathlib, sys
args = sys.argv[1:]
pathlib.Path(os.environ["TEST_RECORD"]).write_text(json.dumps({
    "args": args, "version": (pathlib.Path(args[1]) / "remote-version").read_text(),
    "cwd": os.getcwd()}))
PY
exit 37
'''
        for name in ("build-linux-clients-on-linux.sh", "build-linux-servers-on-linux.sh"):
            (self.remote / name).write_text(driver)
        self.commit("two")
        (self.caller / "remote-version").write_text("dirty old copy")
        for name, prefix in (("build-linux-clients-on-linux.sh", "lc"), ("build-linux-servers-on-linux.sh", "lr")):
            with self.subTest(script=name):
                command = (f'source "$1"; {prefix}_host() {{ platform=fixture; host_arch=amd64; }}; '
                           f'{prefix}_main --repo "$2" --output "$3" --jobs 2 --no-install-deps')
                result = subprocess.run(["bash", "-c", command, "launcher", str(ROOT / name),
                                         str(self.caller), str(self.directory / "artifacts")],
                                        cwd=self.caller, env=dict(self.env, TEST_TMPFS="1"), capture_output=True, text=True)
                self.assertEqual(result.returncode, 37, result.stderr)
                record = json.loads(Path(self.env["TEST_RECORD"]).read_text())
                self.assertEqual(record["version"], "two")
                self.assertEqual(record["args"][0], "--build-updated")
                self.assertEqual(len(record["args"]), 9)
                source, stage = Path(record["args"][1]), Path(record["args"][2])
                work = Path(record["args"][8])
                self.assertEqual(source.parent, stage)
                self.assertRegex(stage.name, r"\.\d{8}-\d{6}\.[^/]+$")
                self.assertEqual(stage.parent, Path("/tmp"))
                self.assertFalse(stage.exists(), "failed downloaded driver left sources behind")
                self.assertFalse(work.exists(), "failed downloaded driver left compiler work behind")
                self.assertTrue(work.is_relative_to(self.disk) or work.parent == self.caller)
                self.assertEqual(record["cwd"], str(self.caller))
                Path(self.env["TEST_RECORD"]).unlink()
                failed = subprocess.run(["bash", "-c", command, "launcher", str(ROOT / name),
                                         str(self.caller), str(self.directory / "artifacts")],
                                        cwd=self.caller, env=dict(self.env, TEST_DOWNLOAD_FAIL="1"),
                                        capture_output=True, text=True)
                self.assertNotEqual(failed.returncode, 0)
                self.assertFalse(Path(self.env["TEST_RECORD"]).exists())
                clones = [item for item in self.commands() if item["tool"] == "git" and "clone" in item["args"]][-3:]
                self.assertEqual(len(clones), 3)
                self.assertTrue(all(not Path(item["args"][-1]).parent.exists() for item in clones))
        self.assertEqual((self.caller / "remote-version").read_text(), "dirty old copy")


if __name__ == "__main__":
    unittest.main()
