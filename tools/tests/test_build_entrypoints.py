"""Linux control-flow checks; these do not build or run native Mac software."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class BuildEntrypointTests(unittest.TestCase):
    def test_install_wrapper_help_with_cdpath(self):
        for script in ('install-debian13.sh', 'install-from-source.sh'):
            with self.subTest(script=script):
                result = subprocess.run(['bash', f'deploy/{script}', '--help'], cwd=ROOT,
                                        env=dict(os.environ, CDPATH='.'), capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('usage:', result.stdout)

    def test_cf_build_root_and_explicit_cross_target_with_cdpath(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            log = directory / 'cargo.json'
            cargo = directory / 'cargo'
            cargo.write_text(f'#!{sys.executable}\nimport json, os, sys\n'
                             'from pathlib import Path\n'
                             f'Path({str(log)!r}).write_text('
                             'json.dumps([os.getcwd(), {k: os.environ[k] for k in ("CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET") if k in os.environ}, sys.argv[1:]]))\n')
            cargo.chmod(0o755)
            project = directory / 'network-relay-cf-masque'
            (project / 'scripts').mkdir(parents=True)
            for script in ('build.sh', 'env.sh'):
                shutil.copyfile(ROOT / 'network-relay-cf-masque/scripts' / script, project / 'scripts' / script)
            result = subprocess.run(['bash', 'scripts/build.sh', '--target', 'aarch64-unknown-linux-musl'],
                                    cwd=project, env=dict(os.environ, CDPATH='.',
                                    PATH=f'{directory}:{os.environ["PATH"]}', CARGO_BUILD_TARGET='wrong-target'),
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            cwd, env, args = json.loads(log.read_text())
            self.assertEqual(cwd, str(project))
            self.assertEqual(env['CARGO_TARGET_DIR'], str(project / 'target'))
            self.assertNotIn('CARGO_BUILD_TARGET', env)
            self.assertEqual(args[-2:], ['--target', 'aarch64-unknown-linux-musl'])

    def test_native_recipes_select_native_tests_and_absolute_paths(self):
        for name in ('network-relay-nf', 'network-relay-rs'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                project = root / name
                project.mkdir()
                shutil.copyfile(ROOT / name / 'build-macos.sh', project / 'build-macos.sh')
                shutil.copyfile(ROOT / name / 'VERSION', project / 'VERSION')
                tools = root / 'bin'
                tools.mkdir()
                log = root / 'cargo.json'
                commands = {'uname': 'case $1 in -m) echo arm64 ;; *) echo Darwin ;; esac',
                            'sw_vers': 'echo 27.0', 'xcrun': 'echo 27.0',
                            'rustup': ':', 'swift': ':'}
                for command in ('plutil', 'sips', 'iconutil', 'codesign', 'ditto', 'shasum', 'otool'):
                    commands[command] = ':'
                for command, body in commands.items():
                    path = tools / command
                    path.write_text('#!/bin/sh\n' + body + '\n')
                    path.chmod(0o755)
                cargo = tools / 'cargo'
                cargo.write_text(f'#!{sys.executable}\nimport json, os\nfrom pathlib import Path\n'
                                 f'Path({str(log)!r}).write_text('
                                 'json.dumps({k: os.environ[k] for k in ("CARGO_TARGET_DIR", "CARGO_BUILD_TARGET") if k in os.environ}))\nraise SystemExit(37)\n')
                cargo.chmod(0o755)
                result = subprocess.run(['bash', f'{name}/build-macos.sh'], cwd=root,
                                        env=dict(os.environ, PATH=f'{tools}:{os.environ["PATH"]}',
                                        CDPATH='.', CARGO_BUILD_TARGET='aarch64-unknown-linux-musl',
                                        CARGO_TARGET_DIR='relative-target'), capture_output=True, text=True)
                self.assertEqual(result.returncode, 37, result.stderr)
                env = json.loads(log.read_text())
                self.assertNotIn('CARGO_BUILD_TARGET', env)
                self.assertTrue(Path(env['CARGO_TARGET_DIR']).is_absolute())


if __name__ == '__main__':
    unittest.main()
