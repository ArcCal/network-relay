"""Run actual child ownership logic with disposable processes, not compilers."""
import os
from pathlib import Path
import pty
import select
import signal
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
BASH = os.environ.get('BASH_TEST_BINARY', 'bash')


class BuildChildTests(unittest.TestCase):
    def run_in_terminal(self, script, arguments, actions):
        pid, terminal = pty.fork()
        if pid == 0:
            os.execvpe(BASH, [BASH, '-c', script, 'check',
                             str(ROOT / 'tools/run-build-child.sh'), *map(str, arguments)], os.environ.copy())
        output = b''
        pending = list(actions)
        finished = False
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if select.select([terminal], [], [], 0.02)[0]:
                    try:
                        output += os.read(terminal, 65536)
                    except OSError:
                        pass
                if pending and pending[0][0] in output:
                    _, action = pending.pop(0)
                    action(pid, terminal)
                done, status = os.waitpid(pid, os.WNOHANG)
                if done:
                    finished = True
                    self.assertFalse(pending, output.decode(errors='replace'))
                    return os.waitstatus_to_exitcode(status), output.decode(errors='replace')
            self.fail('terminal build hung: ' + output.decode(errors='replace'))
        finally:
            if not finished:
                # Each test owns this new session and its foreground build group.
                group = os.tcgetpgrp(terminal)
                for owned_group in {pid, group}:
                    if owned_group > 0 and owned_group != os.getpgrp():
                        try:
                            os.killpg(owned_group, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                os.waitpid(pid, 0)
            os.close(terminal)

    def test_terminal_input_and_foreground_are_preserved(self):
        script = r'''set -eu
source "$1"
relay_run_build_child "$BASH" -c 'read -r -p "CHILD INPUT: " answer; [[ $answer == hello ]]'
read -r -p 'PARENT INPUT: ' answer
[[ $answer == goodbye ]]
'''
        status, output = self.run_in_terminal(script, [], [
            (b'CHILD INPUT:', lambda _pid, fd: os.write(fd, b'hello\n')),
            (b'PARENT INPUT:', lambda _pid, fd: os.write(fd, b'goodbye\n'))])
        self.assertEqual(status, 0, output)

    def test_terminal_parent_signal_stops_a_grandchild_before_cleanup(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            work, writes, artifact = (root / name for name in ('work', 'writes', 'artifact'))
            work.mkdir()
            artifact.write_text('keep')
            worker = root / 'worker.sh'
            worker.write_text('''printf 'BUILD READY\\n'
(while :; do printf x >> "$1"; sleep 0.02; done) &
wait
''')
            script = r'''set -eu
source "$1"
work=$2
trap 'rm -rf -- "$work"' EXIT
relay_run_build_child "$BASH" "$3" "$4"
'''
            status, output = self.run_in_terminal(script, [work, worker, writes], [
                (b'BUILD READY', lambda pid, _fd: os.kill(pid, signal.SIGTERM))])
            self.assertEqual(status, 143, output)
            self.assertFalse(work.exists())
            self.assertEqual(artifact.read_text(), 'keep')
            before = writes.read_bytes() if writes.exists() else b''
            time.sleep(0.15)
            self.assertEqual(writes.read_bytes() if writes.exists() else b'', before)

    def test_terminal_interrupt_allows_installer_rollback(self):
        with tempfile.TemporaryDirectory() as folder:
            restored = Path(folder) / 'restored'
            worker = Path(folder) / 'installer.sh'
            # Announce readiness after installing the handler. Bash 3.2 read -p
            # prints its prompt before activating interrupt handling.
            worker.write_text('''trap 'trap "" INT TERM; sleep 1.3; printf restored > "$1"; exit 130' INT
read -r -p 'BUILD INPUT: ' answer
python3 -u - <<'WAITER'
import signal
import sys
import time
signal.signal(signal.SIGINT, lambda *_: sys.exit(130))
print('BUILD READY', flush=True)
time.sleep(60)
WAITER
''')
            script = r'''set -eu
source "$1"
relay_run_build_child --wait-for-cleanup "$BASH" "$2" "$3"
'''
            status, output = self.run_in_terminal(script, [worker, restored], [
                (b'BUILD INPUT:', lambda _pid, fd: os.write(fd, b'go\n')),
                (b'BUILD READY', lambda _pid, fd: os.write(fd, b'\x03'))])
            self.assertEqual(status, 130, output)
            self.assertEqual(restored.read_text(), 'restored')

    def test_missing_process_inspection_fails_before_starting_a_build(self):
        with tempfile.TemporaryDirectory() as folder:
            environment = os.environ.copy()
            environment['PATH'] = folder
            result = subprocess.run(
                [shutil.which(BASH), '-c', 'source "$1"; relay_run_build_child /bin/sh -c "exit 0"',
                 'check', str(ROOT / 'tools/run-build-child.sh')],
                env=environment, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 125)
            self.assertIn('procps', result.stderr)

    def test_installer_rollback_finishes_before_owner_cleanup(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            work, ready, restored = (root / name for name in ('work', 'ready', 'restored'))
            work.mkdir()
            worker = root / 'installer.sh'
            worker.write_text('''trap 'sleep 1.3; printf restored > "$2"; exit 143' TERM
printf ready > "$1"
sleep 60
''')
            script = '''set -eu
source "$1"
work=$2
trap 'rm -rf -- "$work"' EXIT
relay_run_build_child --wait-for-cleanup "$BASH" "$3" "$4" "$5"
'''
            process = subprocess.Popen(
                [BASH, '-c', script, 'check', str(ROOT / 'tools/run-build-child.sh'), str(work),
                 str(worker), str(ready), str(restored)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 5
                while not ready.exists():
                    self.assertIsNone(process.poll())
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                process.terminate()
                _, errors = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 143, errors)
                self.assertEqual(restored.read_text(), 'restored')
                self.assertFalse(work.exists())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)

    def test_stopped_installer_is_resumed_to_handle_shutdown(self):
        with tempfile.TemporaryDirectory() as folder:
            ready = Path(folder) / 'ready'
            script = '''set -eu
source "$1"
relay_run_build_child --wait-for-cleanup "$BASH" -c 'trap "exit 143" TERM; : > "$1"; kill -STOP $$' check "$2"
'''
            process = subprocess.Popen(
                [BASH, '-c', script, 'check', str(ROOT / 'tools/run-build-child.sh'), str(ready)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 5
                while not ready.exists():
                    self.assertIsNone(process.poll())
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                process.terminate()
                _, errors = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 143, errors)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)

    def test_status_traps_and_monitor_state_are_preserved(self):
        for status in (0, 19):
            with self.subTest(status=status):
                script = r'''
set -eu
source "$1"
trap 'printf original' TERM
original=$(trap -p TERM)
before=$-
if relay_run_build_child "$BASH" -c "exit $2"; then actual=0; else actual=$?; fi
[[ $actual == "$2" && $(trap -p TERM) == "$original" ]]
[[ $before == "$-" ]]
'''
                result = subprocess.run(
                    [BASH, '-c', script, 'check', str(ROOT / 'tools/run-build-child.sh'), str(status)],
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_parent_signals_stop_descendants_before_cleanup(self):
        for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            for grandchild in (False, True):
                with self.subTest(signal=signum, grandchild=grandchild), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    work, ready, writes, artifact = (root / name for name in ('work', 'ready', 'writes', 'artifact'))
                    work.mkdir()
                    artifact.write_text('keep the final product')
                    worker = root / 'worker.sh'
                    worker.write_text(r'''#!/usr/bin/env bash
set -eu
if [[ $1 == grandchild ]]; then
    "$BASH" "$0" writer "$2" "$3" &
    wait
else
    printf ready > "$2"
    while :; do printf x >> "$3"; sleep 0.02; done
fi
''')
                    script = r'''
set -eu
source "$1"
work=$2
trap 'rm -rf -- "$work"' EXIT
relay_run_build_child "$BASH" "$3" "$4" "$5" "$6"
'''
                    process = subprocess.Popen(
                        [BASH, '-c', script, 'check', str(ROOT / 'tools/run-build-child.sh'), str(work),
                         str(worker), 'grandchild' if grandchild else 'writer', str(ready), str(writes)],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    try:
                        deadline = time.monotonic() + 5
                        while not ready.exists():
                            self.assertIsNone(process.poll(), 'build exited before readiness')
                            self.assertLess(time.monotonic(), deadline, 'worker did not start')
                            time.sleep(0.01)
                        process.send_signal(signum)
                        _, errors = process.communicate(timeout=5)
                        self.assertEqual(process.returncode, 128 + signum, errors)
                        self.assertFalse(work.exists(), 'source/cache owner did not clean up')
                        size = writes.stat().st_size
                        time.sleep(0.15)
                        self.assertEqual(writes.stat().st_size, size, 'a descendant kept writing after cleanup')
                        self.assertEqual(artifact.read_text(), 'keep the final product')
                    finally:
                        if process.poll() is None:
                            process.kill()
                            process.communicate(timeout=5)


if __name__ == '__main__':
    unittest.main()
