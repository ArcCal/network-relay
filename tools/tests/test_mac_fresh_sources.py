"""Real Git checks of the Mac entrypoint bootstraps; no native build is run."""
import functools
import http.server
import json
import os
import pty
import re
import select
import signal
import socket
import sys
import time
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[2]
GIT = shutil.which("git")
BASH = os.environ.get("BASH_TEST_BINARY", "bash")
DRIVER = r'''#!/bin/bash
set -euo pipefail
python3 - "$@" <<'CHECK'
import json,os,pathlib,subprocess,sys
args=sys.argv[1:]
assert args[0]=='--build-updated',args
root=pathlib.Path(args[1]);work=pathlib.Path(args[2])
def git(*cmd):return subprocess.check_output(['git','-C',str(root),*cmd],text=True).strip()
record={'source':str(root),'work':str(work),'args':args,'version':(root/'fixture-version').read_text(),
        'head':git('rev-parse','HEAD'),'shallow':git('rev-parse','--is-shallow-repository'),
        'branches':git('for-each-ref','--format=%(refname)','refs/remotes/origin'),
        'tags':git('tag'),'clean':git('status','--porcelain')}
pathlib.Path(os.environ['TEST_BUILD_RESULT']).write_text(json.dumps(record))
CHECK
'''


class MacFreshSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mac fresh sources ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.remote = self.root / "remote"
        self.home = self.root / "home"
        self.tools = self.root / "tools"
        self.home.mkdir(); self.tools.mkdir()
        self.env = dict(os.environ, HOME=str(self.home), DEVELOPER_DIR="/Mock/Developer",
                        GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0",
                        GIT_AUTHOR_NAME="Anonymous", GIT_AUTHOR_EMAIL="anonymous@example.invalid",
                        GIT_COMMITTER_NAME="Anonymous", GIT_COMMITTER_EMAIL="anonymous@example.invalid")
        self.git("init", "-b", "main", str(self.remote))
        (self.remote / "fixture-version").write_text("remote-v1")
        for name in ("build-all-targets-on-macos.sh", "build-macos-gui-clients-on-macos.sh"):
            (self.remote / name).write_text(DRIVER)
        (self.remote / "tools").mkdir()
        shutil.copyfile(ROOT / "tools/fresh-build-source.sh", self.remote / "tools/fresh-build-source.sh")
        shutil.copyfile(ROOT / "tools/run-build-child.sh", self.remote / "tools/run-build-child.sh")
        self.git("-C", str(self.remote), "add", ".")
        self.git("-C", str(self.remote), "commit", "-m", "Initial source fixture")
        self.git("-C", str(self.remote), "branch", "extra")
        self.git("-C", str(self.remote), "tag", "fixture-tag")
        self.git("-C", str(self.remote), "update-server-info")
        class QuietHandler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *args):
                pass
        handler = functools.partial(QuietHandler, directory=str(self.root))
        self.http = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_http)
        self.remote_url = f"http://127.0.0.1:{self.http.server_port}/remote/.git"
        self.config = self.root / "gitconfig"
        self.env["GIT_CONFIG_GLOBAL"] = str(self.config)
        self.git("config", "--file", str(self.config),
                 f"url.{self.remote_url}.insteadOf", "https://github.com/ArcCal/network-relay.git")
        for name in ("rustup", "rustc", "cargo", "swift", "swiftc", "sips", "iconutil",
                     "otool", "codesign", "ditto", "plutil", "xattr", "unzip", "shasum"):
            self.tool(name, "exit 0")
        self.tool("uname", 'case "$1" in -m) echo arm64 ;; *) echo Darwin ;; esac')
        self.tool("sw_vers", "echo 27.0")
        self.tool("xcrun", "echo 27.0")
        self.env["PATH"] = str(self.tools) + os.pathsep + self.env["PATH"]
        self.old = self.home / "network-relay"
        self.git("clone", str(self.remote), str(self.old))
        self.old.chmod(0o700)
        (self.old / "fixture-version").write_text("dirty-local-source")
        (self.old / "local-document").write_text("preserve me")
        self.advance_remote("remote-v2")
        self.created = []
        self.addCleanup(self.cleanup_sources)

    def stop_http(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join()

    def advance_remote(self, version):
        self.version = version
        (self.remote / "fixture-version").write_text(version)
        self.git("-C", str(self.remote), "commit", "-am", "Advance remote source fixture")
        self.latest = self.git("-C", str(self.remote), "rev-parse", "HEAD").strip()
        self.git("-C", str(self.remote), "update-server-info")

    def git(self, *args):
        return subprocess.check_output([GIT, *args], env=self.env, text=True, stderr=subprocess.DEVNULL)

    def tool(self, name, body):
        path = self.tools / name
        path.write_text("#!/bin/sh\n" + body + "\n"); path.chmod(0o755)

    def cleanup_sources(self):
        for path in self.created:
            shutil.rmtree(path, ignore_errors=True)

    def invoke(self, name):
        result_file = self.root / "result.json"
        persistent_tmp = self.root / "persistent-temp"; persistent_tmp.mkdir(exist_ok=True)
        env = dict(self.env, TMPDIR=str(persistent_tmp), TEST_BUILD_RESULT=str(result_file),
                   NETWORK_RELAY_SRC=str(self.old))
        result = subprocess.run([BASH, str(ROOT / name), "--repo", str(self.old),
                                 "--output", str(self.root / "artifacts")], env=env,
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = json.loads(result_file.read_text())
        self.created.extend([record["source"], record["work"]])
        self.assertRegex(record["source"], r"^/(?:private/)?tmp/network-relay-\d{8}-\d{6}\.[A-Za-z0-9]+$")
        self.assertRegex(record["work"], r"^/(?:private/)?tmp/relay-mac-\d{8}-\d{6}\.[A-Za-z0-9]+$")
        self.assertEqual(record["version"], self.version)
        self.assertEqual(record["head"], self.latest)
        self.assertEqual(record["shallow"], "false")
        self.assertIn("refs/remotes/origin/extra", record["branches"])
        self.assertIn("fixture-tag", record["tags"])
        self.assertEqual(record["clean"], "")
        self.assertEqual((self.old / "fixture-version").read_text(), "dirty-local-source")
        self.assertEqual((self.old / "local-document").read_text(), "preserve me")
        self.assertEqual(self.old.stat().st_mode & 0o777, 0o700)
        self.assertFalse(list(persistent_tmp.iterdir()))
        self.assertFalse(Path(record["source"]).exists(), "source checkout survived exit")
        self.assertFalse(Path(record["work"]).exists(), "compiler work survived exit")
        return record

    def test_both_mac_bootstraps_use_fresh_remote_main_and_preserve_local_source(self):
        for name in ("build-all-targets-on-macos.sh", "build-macos-gui-clients-on-macos.sh"):
            with self.subTest(script=name):
                first = self.invoke(name)
                self.advance_remote(self.version + "-new")
                second = self.invoke(name)
                self.assertNotEqual(first["source"], second["source"])
                self.assertNotEqual(first["work"], second["work"])


    def test_failed_gui_build_cleans_source_work_and_private_caches(self):
        shutil.copyfile(ROOT / "build-macos-gui-clients-on-macos.sh", self.remote / "build-macos-gui-clients-on-macos.sh")
        for name in ("network-relay-nf", "network-relay-rs"):
            folder = self.remote / name; folder.mkdir()
            (folder / "build-macos.sh").write_text(
                "#!/bin/bash\npython3 - <<'CAPTURE'\n"
                "import json,os,pathlib\n"
                "keys=['RELAY_BUILD_WORK_ROOT','CARGO_HOME','RUSTUP_HOME','GOCACHE','GOMODCACHE','TMPDIR','HOMEBREW_CACHE']\n"
                "pathlib.Path(os.environ['TEST_BUILD_ENV']).write_text(json.dumps({k:os.environ[k] for k in keys}))\n"
                "cache=pathlib.Path(os.environ['GOMODCACHE'])/'fixture';cache.mkdir(parents=True);(cache/'readonly.go').write_text('cached');cache.chmod(0o555)\n"
                "CAPTURE\nexit 37\n")
        self.git("-C", str(self.remote), "add", ".")
        self.git("-C", str(self.remote), "commit", "-m", "Use current GUI build engine with failing fixture")
        self.git("-C", str(self.remote), "update-server-info")
        toolchain = self.root / "installed-rust"
        (toolchain / "bin").mkdir(parents=True)
        for name in ("rustc", "cargo"):
            file = toolchain / "bin" / name; file.write_text("#!/bin/sh\nexit 0\n"); file.chmod(0o755)
        libraries = toolchain / "lib/rustlib/aarch64-apple-darwin/lib"
        libraries.mkdir(parents=True); (libraries / "libstd-fixture.rlib").touch()
        self.tool("rustup", 'case "$1" in which) printf "%s/bin/rustc\\n" "$TEST_INSTALLED_RUST" ;; '
                  'toolchain) mkdir -p "$RUSTUP_HOME/toolchains"; ln -s "$4" "$RUSTUP_HOME/toolchains/$3" ;; esac')
        self.tool("df", "printf 'Filesystem 1024-blocks Used Available Capacity Mounted\\nfixture 99999999 0 99999999 0%% /\\n'")
        cache = self.root / "caller-cargo"; cache.mkdir(); (cache / "sentinel").write_text("preserve")
        capture = self.root / "private-environment.json"
        output = self.root / "failed-artifacts"
        result = subprocess.run([BASH, str(ROOT / "build-macos-gui-clients-on-macos.sh"), "--output", str(output)],
                                env=dict(self.env, TEST_INSTALLED_RUST=str(toolchain), TEST_BUILD_ENV=str(capture),
                                         CARGO_HOME=str(cache)), capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAILED (exit 37)", result.stdout + result.stderr)
        values = json.loads(capture.read_text())
        work = Path(values["RELAY_BUILD_WORK_ROOT"])
        for key, value in values.items():
            self.assertTrue(Path(value).is_relative_to(work), (key, value, work))
            self.assertFalse(Path(value).exists(), (key, value))
        self.assertEqual((cache / "sentinel").read_text(), "preserve")
        self.assertTrue((output / "logs/macos-network-relay-nf.log").is_file())
        self.assertFalse(os.path.lexists(output / ".work"))
        checkout = re.search(r"Temporary checkout: ([^\n]+)", result.stdout)[1]
        self.assertFalse(Path(checkout).exists())


    def test_legacy_all_product_builder_reloads_remote_engine_and_cleans_on_exit(self):
        self.tool("gh", "exit 0")
        (self.remote / "tools/build-all-macos.sh").write_text(r'''#!/bin/bash
set -euo pipefail
python3 - "$@" <<'CHECK'
import json,os,pathlib,subprocess,sys
args=sys.argv[1:];assert args[0]=='--build-downloaded',args
work=pathlib.Path(args[2]);root=work/'sources/network-relay'
def git(*cmd):return subprocess.check_output(['git','-C',str(root),*cmd],text=True).strip()
record={'source':str(root),'work':str(work),'output':args[1],
        'head':git('rev-parse','HEAD'),'version':(root/'fixture-version').read_text(),
        'shallow':git('rev-parse','--is-shallow-repository'),'cache':os.environ['HOMEBREW_CACHE']}
pathlib.Path(os.environ['TEST_BUILD_RESULT']).write_text(json.dumps(record))
CHECK
exit "${TEST_ENGINE_STATUS:-0}"
''')
        self.git("-C", str(self.remote), "add", ".")
        self.git("-C", str(self.remote), "commit", "-m", "Record the current all-product build invocation")
        self.latest = self.git("-C", str(self.remote), "rev-parse", "HEAD").strip()
        self.git("-C", str(self.remote), "update-server-info")
        for status in (0, 37):
            with self.subTest(exit_status=status):
                record_path = self.root / f"legacy-{status}.json"
                artifacts = self.root / f"artifacts-{status}"
                result = subprocess.run([BASH, str(ROOT / "tools/build-all-macos.sh"),
                                         "--no-bootstrap", "--output-parent", str(artifacts)],
                                        env=dict(self.env, TEST_BUILD_RESULT=str(record_path), TEST_ENGINE_STATUS=str(status)),
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                record = json.loads(record_path.read_text())
                self.assertEqual(record["head"], self.latest)
                self.assertEqual(record["version"], self.version)
                self.assertEqual(record["shallow"], "false")
                self.assertRegex(record["work"], r"^/(?:private/)?tmp/vpn-sources-\d{8}-\d{6}\.[A-Za-z0-9]+$")
                self.assertFalse(Path(record["source"]).exists())
                self.assertFalse(Path(record["work"]).exists())
                self.assertFalse(Path(record["cache"]).exists())
                self.assertTrue(Path(record["output"]).is_relative_to(artifacts))
                self.assertTrue((Path(record["output"]) / "logs/clone-network-relay.log").is_file())
                self.assertFalse((Path(record["output"]) / "sources").exists())



    def test_source_download_failure_does_not_fall_back_to_local_checkout(self):
        self.tool("sleep", "exit 0")
        self.remote.rename(self.root / "offline-remote")
        for name in ("build-all-targets-on-macos.sh", "build-macos-gui-clients-on-macos.sh"):
            with self.subTest(script=name):
                record = self.root / "should-not-build.json"
                result = subprocess.run([BASH, str(ROOT / name), "--repo", str(self.old)],
                                        env=dict(self.env, TEST_BUILD_RESULT=str(record)), text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(record.exists())
                source = re.search(r"into ([^\n]+)", result.stdout)[1]
                self.assertFalse(Path(source).exists())
                self.assertEqual((self.old / "fixture-version").read_text(), "dirty-local-source")
                self.assertEqual(self.old.stat().st_mode & 0o777, 0o700)


    def test_local_git_url_rewrite_is_rejected_instead_of_using_saved_source(self):
        self.tool("sleep", "exit 0")
        self.git("config", "--file", str(self.config), "--unset-all", f"url.{self.remote_url}.insteadOf")
        self.git("config", "--file", str(self.config), f"url.{self.old.as_uri()}.insteadOf",
                 "https://github.com/ArcCal/network-relay.git")
        for name in ("build-all-targets-on-macos.sh", "build-macos-gui-clients-on-macos.sh"):
            with self.subTest(script=name):
                record = self.root / "should-not-build.json"
                result = subprocess.run([BASH, str(ROOT / name)], env=dict(self.env, TEST_BUILD_RESULT=str(record)),
                                        text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("transport 'file' not allowed", result.stdout + result.stderr)
                self.assertFalse(record.exists())
                source = re.search(r"into ([^\n]+)", result.stdout)[1]
                self.assertFalse(Path(source).exists())


    def test_mac_bootstraps_embed_the_canonical_child_runner(self):
        canonical = "\n".join((ROOT / "tools/run-build-child.sh").read_text().splitlines()[2:]).strip()
        for name in ("build-all-targets-on-macos.sh", "build-macos-gui-clients-on-macos.sh", "tools/build-all-macos.sh"):
            embedded = (ROOT / name).read_text().split("# BEGIN SHARED BUILD CHILD RUNNER\n", 1)[1].split("# END SHARED BUILD CHILD RUNNER", 1)[0].strip()
            self.assertEqual(embedded, canonical, name)

    def test_parent_sigterm_stops_grandchild_writer_before_removing_work(self):
        slow = r"""#!/bin/bash
set -euo pipefail
python3 - "$@" <<'WRITE'
import json,os,pathlib,sys,time
args=sys.argv[1:]
if args[0]=='--build-updated':
    source=pathlib.Path(args[1]);work=pathlib.Path(args[2])
else:
    work=pathlib.Path(args[2]);source=work/'sources/network-relay'
pathlib.Path(os.environ['TEST_BUILD_RESULT']).write_text(json.dumps({'source':str(source),'work':str(work),'pid':os.getpid()}))
while True:
    (work/'recreated-cache').mkdir(parents=True,exist_ok=True)
    with pathlib.Path(os.environ['TEST_WRITE_LOG']).open('a') as f:f.write('write\n')
    time.sleep(.025)
WRITE
"""
        for name in ("build-all-targets-on-macos.sh", "build-macos-gui-clients-on-macos.sh", "tools/build-all-macos.sh"):
            (self.remote / name).write_text(slow)
        self.git("-C", str(self.remote), "add", ".")
        self.git("-C", str(self.remote), "commit", "-m", "Exercise owned build process cancellation")
        self.git("-C", str(self.remote), "update-server-info")
        self.tool("gh", "exit 0")
        for index, name in enumerate(("build-all-targets-on-macos.sh", "build-macos-gui-clients-on-macos.sh", "tools/build-all-macos.sh")):
            with self.subTest(script=name):
                ready = self.root / f"writer-{index}.json"
                writes = self.root / f"writes-{index}.log"
                args = ["--no-bootstrap", "--output-parent", str(self.root / f"products-{index}")] if name.startswith('tools/') else ["--output", str(self.root / f"products-{index}")]
                child = subprocess.Popen([BASH, str(ROOT / name), *args], env=dict(self.env, TEST_BUILD_RESULT=str(ready), TEST_WRITE_LOG=str(writes)), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                record = None
                try:
                    deadline = time.monotonic() + 15
                    while not ready.exists():
                        if child.poll() is not None:
                            self.fail(child.communicate()[0])
                        self.assertLess(time.monotonic(), deadline, name)
                        time.sleep(.02)
                    record = json.loads(ready.read_text())
                    child.send_signal(signal.SIGTERM)
                    output = child.communicate(timeout=10)[0]
                    self.assertEqual(child.returncode, 143, output)
                    after = writes.read_text()
                    time.sleep(.3)
                    self.assertEqual(writes.read_text(), after, 'writer survived its parent')
                    self.assertFalse(Path(record['source']).exists(), 'source survived cancellation')
                    self.assertFalse(Path(record['work']).exists(), 'writer recreated compiler work after cleanup')
                finally:
                    if child.poll() is None:
                        child.kill(); child.communicate()
                    if record is not None:
                        try: os.kill(record['pid'], signal.SIGKILL)
                        except ProcessLookupError: pass
                        for key in ('source', 'work'): shutil.rmtree(record[key], ignore_errors=True)


    def test_downloaded_build_drivers_can_read_interactive_terminal_input(self):
        driver = r"""#!/bin/bash
set -euo pipefail
read -r -p 'BUILD INPUT: ' answer
[[ $answer == hello ]]
python3 - "$@" <<'RECORD'
import json,os,pathlib,sys
args=sys.argv[1:]
if args[0]=='--build-updated':source=pathlib.Path(args[1]);work=pathlib.Path(args[2])
else:work=pathlib.Path(args[2]);source=work/'sources/network-relay'
pathlib.Path(os.environ['TEST_BUILD_RESULT']).write_text(json.dumps({'source':str(source),'work':str(work)}))
RECORD
"""
        for name in ("build-all-targets-on-macos.sh", "build-macos-gui-clients-on-macos.sh", "tools/build-all-macos.sh"):
            (self.remote / name).write_text(driver)
        self.git("-C", str(self.remote), "add", ".")
        self.git("-C", str(self.remote), "commit", "-m", "Exercise interactive build driver input")
        self.git("-C", str(self.remote), "update-server-info")
        self.tool("gh", "exit 0")
        # forkpty must not inherit a running HTTP server thread. Serve the Git
        # fixture in a separate process for this terminal-specific test.
        port = self.http.server_port
        self.stop_http()
        server = subprocess.Popen([sys.executable, '-m', 'http.server', str(port), '--bind', '127.0.0.1',
                                   '--directory', str(self.root)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def stop_server():
            server.terminate()
            server.wait(timeout=5)
        self.addCleanup(stop_server)
        deadline = time.monotonic() + 5
        while True:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.1): break
            except OSError:
                self.assertIsNone(server.poll())
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.02)
        for index, name in enumerate(("build-all-targets-on-macos.sh", "build-macos-gui-clients-on-macos.sh", "tools/build-all-macos.sh")):
            with self.subTest(script=name):
                record_path = self.root / f"terminal-{index}.json"
                args = ["--no-bootstrap", "--output-parent", str(self.root / f"terminal-products-{index}")] if name.startswith('tools/') else ["--output", str(self.root / f"terminal-products-{index}")]
                pid, master = pty.fork()
                if pid == 0:
                    os.execvpe(BASH, [BASH, str(ROOT / name), *args], dict(self.env, TEST_BUILD_RESULT=str(record_path)))
                output = b''; sent = False; status = None
                try:
                    deadline = time.monotonic() + 15
                    while time.monotonic() < deadline:
                        if select.select([master], [], [], .05)[0]:
                            try: output += os.read(master, 65536)
                            except OSError: pass
                        if b'BUILD INPUT:' in output and not sent:
                            os.write(master, b'hello\n'); sent = True
                        done, raw_status = os.waitpid(pid, os.WNOHANG)
                        if done:
                            status = os.waitstatus_to_exitcode(raw_status); break
                    self.assertIsNotNone(status, output.decode(errors='replace'))
                    self.assertEqual(status, 0, output.decode(errors='replace'))
                    self.assertTrue(sent, output.decode(errors='replace'))
                    for value in json.loads(record_path.read_text()).values():
                        self.assertFalse(Path(value).exists())
                finally:
                    # A failing handoff can leave a stopped process; clean only
                    # this fixture's session, including after its parent exits.
                    processes = subprocess.check_output(['ps', '-A', '-o', 'pid='], text=True).split()
                    for signal_number in (signal.SIGCONT, signal.SIGKILL):
                        for candidate in processes:
                            try:
                                candidate = int(candidate)
                                if os.getsid(candidate) == pid: os.kill(candidate, signal_number)
                            except (ProcessLookupError, PermissionError): pass
                    if status is None: os.waitpid(pid, 0)
                    self.created.extend(re.findall(r'/(?:private/)?tmp/(?:network-relay|relay-mac|vpn-sources)-\d{8}-\d{6}\.[A-Za-z0-9]+', output.decode(errors='replace')))
                    os.close(master)


if __name__ == "__main__":
    unittest.main()
