"""Source installer staging tests; no packages or services are changed."""
from contextlib import redirect_stderr
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import signal
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('source_deploy', ROOT / 'deploy/install.py')
deploy = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = deploy
SPEC.loader.exec_module(deploy)


class SourceBootstrapTests(unittest.TestCase):
    def test_prebuilt_and_help_do_not_fetch(self):
        with mock.patch.object(deploy.subprocess, 'run') as command:
            for arguments in ([], ['--binary', '/tmp/program'], ['--build-from-source', '--help']):
                self.assertIsNone(deploy.source_bootstrap(arguments))
        command.assert_not_called()

    def test_only_verified_current_source_avoids_reloading(self):
        arguments = ['--build-from-source', '--domain', 'relay.example.com']
        with (mock.patch.object(deploy.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)),
              mock.patch.object(deploy, 'run') as command):
            self.assertIsNone(deploy.source_bootstrap(arguments))
            command.assert_not_called()
        with (mock.patch.object(deploy.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)),
              mock.patch.object(deploy.os, 'execvp', side_effect=RuntimeError('reloading source')) as command):
            with self.assertRaisesRegex(RuntimeError, 'reloading source'):
                deploy.source_bootstrap(arguments)
            command.assert_called_once_with('bash', ['bash', str(ROOT / 'deploy/install-debian13.sh'), *arguments])

    def test_direct_python_fetches_new_remote_source_and_cleans_success_and_failure(self):
        with tempfile.TemporaryDirectory(prefix='installer-fresh-', dir='/tmp') as folder:
            base = Path(folder)
            origin, caller = base / 'origin', base / 'caller'
            for root in (origin, caller):
                (root / 'tools').mkdir(parents=True)
                (root / 'deploy').mkdir()
                for helper in ('fresh-build-source.sh', 'linux-build-memory.sh', 'run-build-child.sh'):
                    shutil.copyfile(ROOT / 'tools' / helper, root / 'tools' / helper)
            driver = '''#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
source "$root/tools/fresh-build-source.sh"
relay_require_fresh_source "$root" deploy/install-debian13.sh "$@"
cat "$root/VERSION" > "$SOURCE_FIXTURE_RESULT"
printf '%s\\n%s\\n' "$root" "$RELAY_BUILD_WORK_ROOT" >> "$SOURCE_FIXTURE_RESULT"
git -C "$root" rev-list --count HEAD >> "$SOURCE_FIXTURE_RESULT"
exit "$SOURCE_FIXTURE_STATUS"
'''
            for root in (origin, caller):
                (root / 'deploy/install-debian13.sh').write_text(driver)
            for name in ('install.py', 'global-profile.py'):
                shutil.copyfile(ROOT / 'deploy' / name, caller / 'deploy' / name)
            (caller / 'VERSION').write_text('stale local source\n')
            config = base / 'gitconfig'
            config.write_text(f'[url "file://{origin}"]\n\tinsteadOf = https://github.com/ArcCal/network-relay.git\n')
            env = os.environ.copy()
            env.update(GIT_CONFIG_GLOBAL=str(config), GIT_CONFIG_NOSYSTEM='1', GIT_ALLOW_PROTOCOL='file',
                       GIT_AUTHOR_NAME='Anonymous', GIT_AUTHOR_EMAIL='anonymous@example.invalid',
                       GIT_COMMITTER_NAME='Anonymous', GIT_COMMITTER_EMAIL='anonymous@example.invalid')
            subprocess.run(['git', 'init', '-b', 'main', str(origin)], env=env, check=True, capture_output=True)
            result = base / 'artifact'
            for revision, status in ((1, 0), (2, 17)):
                (origin / 'VERSION').write_text(f'current remote {revision}\n')
                subprocess.run(['git', '-C', str(origin), 'add', '.'], env=env, check=True, capture_output=True)
                subprocess.run(['git', '-C', str(origin), '-c', 'commit.gpgsign=false', 'commit', '-m', 'Fixture source'],
                               env=env, check=True, capture_output=True)
                env.update(SOURCE_FIXTURE_RESULT=str(result), SOURCE_FIXTURE_STATUS=str(status))
                child = subprocess.run([sys.executable, str(caller / 'deploy/install.py'), '--build-from-source'],
                                       env=env, text=True, capture_output=True, timeout=30)
                self.assertEqual(child.returncode, status, child.stdout + child.stderr)
                version, source, work, commits = result.read_text().splitlines()
                self.assertEqual(version, f'current remote {revision}')
                self.assertEqual(int(commits), revision, 'the clone must retain full history')
                self.assertTrue(source.startswith('/tmp/network-relay-'))
                self.assertFalse(Path(source).exists())
                self.assertFalse(Path(work).exists())
            self.assertEqual((caller / 'VERSION').read_text(), 'stale local source\n')
            self.assertFalse((caller / 'deploy/__pycache__').exists())


class SourceWorkspaceTests(unittest.TestCase):
    def test_work_and_caches_are_removed_on_success_and_failure_but_artifacts_remain(self):
        for fail in (False, True, signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as folder:
                base = Path(folder)
                artifact = base / 'installed-binary'
                old_cache = base / 'existing-cache'
                old_cache.write_text('untouched')
                created = []

                def workspace():
                    work = tempfile.TemporaryDirectory(prefix='private-build-', dir=base)
                    created.append(Path(work.name))
                    class InterruptedCleanup:
                        def __enter__(self):
                            return work.__enter__()

                        def __exit__(self, *exception):
                            # A repeated stop signal must not interrupt deletion.
                            os.kill(os.getpid(), signal.SIGTERM)
                            return work.__exit__(*exception)
                    return InterruptedCleanup()

                def install(args):
                    self.assertTrue(args.build_root.is_dir())
                    for name in ('cargo', 'rustup', 'target', 'tmp'):
                        (args.build_root / name).mkdir()
                        (args.build_root / name / 'temporary').write_text('build cache')
                    artifact.write_text('final output')
                    if fail is True:
                        raise RuntimeError('controlled deployment failure')
                    if fail is not False:
                        os.kill(os.getpid(), fail)
                    return 0

                lock = (base / 'lock').open('w')
                with (mock.patch.object(deploy.sys, 'argv', ['installer', '--build-from-source']),
                      mock.patch.object(deploy, 'source_bootstrap', return_value=None),
                      mock.patch.object(deploy, 'preflight'),
                      mock.patch.object(deploy, 'open', return_value=lock, create=True),
                      mock.patch.object(deploy, 'build_workspace', side_effect=workspace),
                      mock.patch.object(deploy, 'install', side_effect=install),
                      redirect_stderr(io.StringIO())):
                    if fail is True or fail is False:
                        self.assertEqual(deploy.main(), 1 if fail else 0)
                    else:
                        with self.assertRaises(SystemExit) as exited:
                            deploy.main()
                        self.assertEqual(exited.exception.code, 128 + fail)
                self.assertEqual(len(created), 1)
                self.assertFalse(created[0].exists())
                self.assertEqual(artifact.read_text(), 'final output')
                self.assertEqual(old_cache.read_text(), 'untouched')

    def test_memory_is_checked_before_tool_download_and_parallelism_is_capped(self):
        with tempfile.TemporaryDirectory() as folder:
            args = SimpleNamespace(binary=None, jobs=16, build_root=Path(folder))
            calls = []

            def run(command, **options):
                calls.append((command, options))
                return subprocess.CompletedProcess(command, 0, stdout='1572864\n')

            with mock.patch.object(deploy, 'run', side_effect=run):
                deploy.build_binary(args)
            self.assertEqual(calls[0][0][0], 'bash')
            self.assertIn('nr_check_build_memory', calls[0][0][2])
            self.assertEqual(calls[1][0][0], 'curl')
            build_env = calls[-1][1]['env']
            self.assertEqual(build_env['CARGO_BUILD_JOBS'], '1')
            for name in ('CARGO_HOME', 'RUSTUP_HOME', 'CARGO_TARGET_DIR', 'TMPDIR', 'SCCACHE_DIR', 'CCACHE_DIR'):
                self.assertTrue(Path(build_env[name]).is_relative_to(args.build_root), name)

    def test_insufficient_disk_refuses_before_allocating_work(self):
        with (mock.patch.object(deploy.shutil, 'disk_usage', return_value=SimpleNamespace(free=1 << 30)),
              mock.patch.object(deploy.tempfile, 'TemporaryDirectory') as create):
            with self.assertRaisesRegex(ValueError, '5 GiB'):
                deploy.build_workspace()
            create.assert_not_called()

    def test_memory_refusal_preserves_swap_guidance_and_skips_downloads(self):
        with tempfile.TemporaryDirectory() as folder:
            args = SimpleNamespace(binary=None, jobs=1, build_root=Path(folder))
            error = subprocess.CalledProcessError(1, ['memory-check'], stderr='Add swap on a disk filesystem.\n')
            with mock.patch.object(deploy, 'run', side_effect=error) as commands:
                with self.assertRaisesRegex(ValueError, 'swap on a disk filesystem'):
                    deploy.build_binary(args)
                self.assertEqual(commands.call_count, 1)


if __name__ == '__main__':
    unittest.main()
