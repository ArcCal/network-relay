"""Execute the shared CI bootstrap with local Git and build-tool fixtures."""
import base64
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
WORKFLOW = ROOT / '.github/workflows/build.yml'
GIT = shutil.which('git')
BASH = os.environ.get('BASH_TEST_BINARY', 'bash')


def bootstrap():
    text = WORKFLOW.read_text()
    marker = '        run: &fresh_macos_build |\n'
    body = text.split(marker, 1)[1].split('      - name: Package\n', 1)[0]
    return '\n'.join(line[10:] for line in body.splitlines()) + '\n'


HELPER = '''relay_mark_fresh_source() { export RELAY_FRESH_SOURCE_ROOT=$1; unset RELAY_BUILD_OUTPUT_ROOT; }
relay_prepare_build_environment() {
    export CARGO_HOME="$1/cargo" RUSTUP_HOME="$1/rustup" CARGO_TARGET_DIR="$1/target" TMPDIR="$1/tmp"
    mkdir -p "$CARGO_HOME" "$RUSTUP_HOME" "$CARGO_TARGET_DIR" "$TMPDIR"
}
relay_remove_build_work() {
    find -P "$1" -type d -exec chmod u+w {} + 2>/dev/null || true
    rm -rf -- "$1"
}
'''

BUILD = r'''#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd -P)
project="network-relay-$RELAY_CI_APP"
if [[ -f $repo/tools/fresh-build-source.sh ]]; then
    source "$repo/tools/fresh-build-source.sh"
    [[ $RELAY_FRESH_SOURCE_ROOT == "$repo" ]]
    relay_prepare_build_environment "$RELAY_BUILD_WORK_ROOT"
    output="$RELAY_BUILD_OUTPUT_ROOT/$project"
else
    output="$repo/$project"
    rustup target add aarch64-apple-darwin
    swift build
fi
export OBSERVED_SOURCE=$repo OBSERVED_VERSION
OBSERVED_VERSION=$(cat "$repo/$project/VERSION")
python3 - <<'PY'
import json,os
from pathlib import Path
keys=['OBSERVED_SOURCE','OBSERVED_VERSION','CARGO_HOME','RUSTUP_HOME','CARGO_TARGET_DIR','TMPDIR']
data={key:os.environ[key] for key in keys}
data['credential_remaining']=any(key in os.environ for key in ['NETWORK_RELAY_TOKEN','GIT_CONFIG_VALUE_1'])
data['process_group']=os.getpgrp()
Path(os.environ['GITHUB_WORKSPACE'],'observed.json').write_text(json.dumps(data))
PY
mkdir -p "$RELAY_BUILD_WORK_ROOT/cache/readonly"
ln -s "$OUTSIDE_SENTINEL" "$RELAY_BUILD_WORK_ROOT/cache/readonly/user-cache"
chmod 500 "$RELAY_BUILD_WORK_ROOT/cache/readonly"
if [[ ${INTERRUPT_BUILD:-0} == 1 ]]; then
    (trap '' TERM; for i in {1..100}; do
        mkdir -p "$RELAY_BUILD_WORK_ROOT/late-cache"
        printf x >> "$GITHUB_WORKSPACE/pulses"
        printf x > "$RELAY_BUILD_WORK_ROOT/late-cache/data"
        sleep .05
    done) &
    wait "$!"
fi
[[ ${FAIL_BUILD:-0} != 1 ]] || exit 37
mkdir -p "$output/dist"
printf '%s' "$OBSERVED_VERSION" > "$output/dist/app.zip"
if [[ $RELAY_CI_APP == rs ]]; then
    if [[ -f $repo/tools/fresh-build-source.sh ]]; then
        printf '%s' "$OBSERVED_VERSION" > "$output/dist/network-relay-rs"
    else
        binary="$repo/$project/build/target/aarch64-apple-darwin/release/network-relay-rs"
        mkdir -p "${binary%/*}"
        printf '%s' "$OBSERVED_VERSION" > "$binary"
    fi
fi
'''


class CiBuildSourceTests(unittest.TestCase):
    def run_fixture(self, product, current, fail=False, interrupt=False):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            remote, workspace, tools = (root / name for name in ('remote', 'workspace', 'bin'))
            remote.mkdir()
            tools.mkdir()
            env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
                       GIT_AUTHOR_NAME='Anonymous', GIT_AUTHOR_EMAIL='anonymous@example.invalid',
                       GIT_COMMITTER_NAME='Anonymous', GIT_COMMITTER_EMAIL='anonymous@example.invalid')
            for name in ('GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0',
                         'GIT_CONFIG_KEY_1', 'GIT_CONFIG_VALUE_1'):
                env.pop(name, None)

            def git(*args, cwd=remote):
                return subprocess.check_output([GIT, *args], cwd=cwd, env=env, text=True,
                                               stderr=subprocess.DEVNULL).strip()

            git('init', '-b', 'main')
            project = remote / f'network-relay-{product}'
            project.mkdir()
            (project / 'VERSION').write_text('1.0.0\n')
            (project / 'build-macos.sh').write_text(BUILD)
            git('add', '.')
            git('-c', 'commit.gpgsign=false', 'commit', '-m', 'Legacy fixture')
            legacy = git('rev-parse', 'HEAD')
            (remote / 'tools').mkdir()
            (remote / 'tools/fresh-build-source.sh').write_text(HELPER)
            shutil.copyfile(ROOT / 'tools/run-build-child.sh', remote / 'tools/run-build-child.sh')
            (project / 'VERSION').write_text('2.0.0\n')
            git('add', '.')
            git('-c', 'commit.gpgsign=false', 'commit', '-m', 'Current fixture')
            selected = git('rev-parse', 'HEAD') if current else legacy
            git('clone', str(remote), str(workspace), cwd=root)
            git('checkout', '--detach', selected, cwd=workspace)
            # Advancing main must not change the selected tag's build identity.
            (project / 'VERSION').write_text('9.0.0\n')
            git('add', '.')
            git('-c', 'commit.gpgsign=false', 'commit', '-m', 'Later main fixture')

            log = root / 'git.jsonl'
            wrapper = tools / 'git'
            wrapper.write_text(f'#!{sys.executable}\n' +
                               'import json,os,sys\nfrom pathlib import Path\n'
                               'args=sys.argv[1:]\n'
                               f'with Path({str(log)!r}).open("a") as stream:\n'
                               ' stream.write(json.dumps({"args":args,"authenticated":bool(os.environ.get("GIT_CONFIG_VALUE_1")),"file_protocol":os.environ.get("GIT_CONFIG_VALUE_2")})+"\\n")\n'
                               f'args=[{str(remote)!r} if arg=="https://github.com/ArcCal/network-relay.git" else arg for arg in args]\n'
                               '# Substitute the network transport only in this offline fixture.\n'
                               'if os.environ.get("GIT_CONFIG_KEY_2")=="protocol.file.allow":\n'
                               ' os.environ["GIT_CONFIG_VALUE_2"]="always"\n'
                               f'os.execv({GIT!r},[{GIT!r},*args])\n')
            wrapper.chmod(0o755)
            for name, body in {
                'rustup': 'mkdir -p "$RUSTUP_HOME/downloads"',
                'swift': 'printf "%s\\n" "$@" >> "$GITHUB_WORKSPACE/swift-args"',
            }.items():
                path = tools / name
                path.write_text('#!/usr/bin/env bash\nset -e\n' + body + '\n')
                path.chmod(0o755)
            outside = root / 'user-cache'
            outside.mkdir()
            (outside / 'keep').write_text('existing user data')
            outside.chmod(0o500)
            original_mode = outside.stat().st_mode
            token = 'fixture-token-never-in-argv'
            env.update(PATH=f'{tools}:{env["PATH"]}', GITHUB_WORKSPACE=str(workspace),
                       GITHUB_SERVER_URL='https://github.com', GITHUB_REPOSITORY='ArcCal/network-relay',
                       GITHUB_SHA='deliberately-not-the-selected-tag', NETWORK_RELAY_TOKEN=token,
                       RELAY_CI_APP=product, OUTSIDE_SENTINEL=str(outside), FAIL_BUILD=str(int(fail)),
                       INTERRUPT_BUILD=str(int(interrupt)),
                       TMPDIR=str(root))
            process = subprocess.Popen([BASH, '-eo', 'pipefail', '-c', bootstrap()], cwd=workspace,
                                       env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, start_new_session=True)
            try:
                if interrupt:
                    deadline = time.monotonic() + 5
                    while not (workspace / 'pulses').exists() and time.monotonic() < deadline:
                        time.sleep(.01)
                    self.assertTrue((workspace / 'pulses').exists(), 'build descendant did not start')
                    process.send_signal(signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=8)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    if (workspace / 'observed.json').exists():
                        group = json.loads((workspace / 'observed.json').read_text())['process_group']
                        try:
                            os.killpg(group, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    process.communicate(timeout=2)
            self.assertEqual(process.returncode, 143 if interrupt else 37 if fail else 0, stderr)
            observed = json.loads((workspace / 'observed.json').read_text())
            self.assertEqual(observed['OBSERVED_VERSION'], '2.0.0' if current else '1.0.0')
            source = Path(observed['OBSERVED_SOURCE'])
            self.assertTrue(str(source).startswith(str(Path('/tmp').resolve()) + '/network-relay-ci-'))
            self.assertFalse(source.parent.exists(), 'source, caches and toolchains must be removed')
            self.assertFalse(observed['credential_remaining'])
            for key in ('CARGO_HOME', 'RUSTUP_HOME', 'CARGO_TARGET_DIR', 'TMPDIR'):
                self.assertTrue(Path(observed[key]).is_relative_to(source.parent), key)
            self.assertEqual(outside.stat().st_mode, original_mode)
            self.assertEqual((outside / 'keep').read_text(), 'existing user data')
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            clone = next(call for call in calls if call['args'][0] == 'clone')
            self.assertTrue(clone['authenticated'])
            self.assertEqual(clone['file_protocol'], 'never')
            self.assertIn('--no-checkout', clone['args'])
            self.assertNotIn('--depth', clone['args'])
            output = stdout + stderr + json.dumps(calls)
            self.assertNotIn(token, output)
            self.assertNotIn(base64.b64encode(f'x-access-token:{token}'.encode()).decode(), output)
            if not fail and not interrupt:
                dist = workspace / f'network-relay-{product}/dist'
                self.assertEqual((dist / 'app.zip').read_text(), observed['OBSERVED_VERSION'])
                if product == 'rs':
                    self.assertEqual((dist / 'network-relay-rs').read_text(), observed['OBSERVED_VERSION'])
                self.assertFalse((workspace / f'network-relay-{product}/build').exists())
            if not current:
                args = (workspace / 'swift-args').read_text()
                for option in ('--cache-path', '--config-path', '--security-path'):
                    self.assertIn(option, args)
            if interrupt:
                pulse_count = (workspace / 'pulses').stat().st_size
                time.sleep(.15)
                self.assertEqual((workspace / 'pulses').stat().st_size, pulse_count,
                                 'a compiler descendant survived source cleanup')
            outside.chmod(0o700)

    def test_old_and_new_tags_keep_identity_and_only_final_products(self):
        for product in ('nf', 'rs'):
            for current in (False, True):
                with self.subTest(product=product, current=current):
                    self.run_fixture(product, current)

    def test_failure_cleans_private_work_and_preserves_user_cache(self):
        for current in (False, True):
            with self.subTest(current=current):
                self.run_fixture('nf', current, fail=True)

    def test_both_jobs_share_the_bootstrap_and_package_only_the_final_cli(self):
        text = WORKFLOW.read_text()
        self.assertEqual(text.count('run: &fresh_macos_build |'), 1)
        self.assertEqual(text.count('run: *fresh_macos_build'), 1)
        self.assertIn('cp network-relay-rs/dist/network-relay-rs "dist/$name/"', text)

    def test_parent_term_stops_descendants_before_cleaning_old_and_new_tags(self):
        for current in (False, True):
            with self.subTest(current=current):
                self.run_fixture('rs', current, interrupt=True)


if __name__ == '__main__':
    unittest.main()
