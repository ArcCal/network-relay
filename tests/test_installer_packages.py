"""Check that uploadable installers contain the current deployment sources."""
import base64
import errno
import hashlib
import io
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('atomic_package_fixture', ROOT / 'deploy/package-installer.py')
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)


class InstallerPackageTests(unittest.TestCase):
    def test_atomic_write_failures_preserve_output_and_close_descriptors(self):
        for stage in ('fdopen', 'fsync', 'replace'):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory)
                output = parent / 'installer.sh'
                output.write_bytes(b'original output')
                output.chmod(0o640)
                opened = []
                real_open = os.open

                def tracking_open(*args, **kwargs):
                    descriptor = real_open(*args, **kwargs)
                    opened.append(descriptor)
                    return descriptor

                error = MemoryError('wrapper allocation failed') if stage == 'fdopen' else OSError(errno.EIO, stage)
                with mock.patch.object(PACKAGE.os, 'open', side_effect=tracking_open), \
                        mock.patch.object(PACKAGE.os, stage, side_effect=error):
                    with self.assertRaises(type(error)):
                        PACKAGE.atomic_write(output, b'replacement', 0o755, force_mode=True)
                self.assertEqual(output.read_bytes(), b'original output')
                self.assertEqual(output.stat().st_mode & 0o777, 0o640)
                self.assertEqual(set(parent.iterdir()), {output})
                self.assertTrue(opened, 'failure must occur after acquiring a descriptor')
                live = []
                for descriptor in set(opened):
                    try:
                        os.fstat(descriptor)
                    except OSError as failure:
                        self.assertEqual(failure.errno, errno.EBADF)
                    else:
                        live.append(descriptor)
                try:
                    self.assertEqual(live, [], 'failed writes must not retain descriptors')
                finally:
                    for descriptor in live:
                        os.close(descriptor)

    def test_atomic_write_preserves_modes_and_respects_checksum_umask(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'installer.sh'
            checksum = output.with_name(output.name + '.sha256')
            previous = os.umask(0o077)
            try:
                PACKAGE.atomic_write(output, b'script', 0o755, force_mode=True)
                PACKAGE.atomic_write(checksum, b'first hash', 0o644)
                self.assertEqual(output.stat().st_mode & 0o777, 0o755)
                self.assertEqual(checksum.stat().st_mode & 0o777, 0o600)
                checksum.chmod(0o640)
                PACKAGE.atomic_write(checksum, b'updated hash', 0o640, force_mode=True)
                self.assertEqual(checksum.stat().st_mode & 0o777, 0o640)
                self.assertEqual(checksum.read_bytes(), b'updated hash')
            finally:
                os.umask(previous)

    def test_packaging_creates_nested_output_directories_with_safe_permissions(self):
        for mask, expected in ((0o000, 0o755), (0o077, 0o700)):
            with self.subTest(umask=oct(mask)), tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / 'source'
                source.mkdir(mode=0o700)
                for relative in PACKAGE.FILES:
                    path = source / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text('fixture\n')
                script = source / 'deploy/package-installer.py'
                shutil.copyfile(ROOT / 'deploy/package-installer.py', script)
                existing = Path(directory) / 'output'
                existing.mkdir(mode=0o700)
                first = existing / 'new'
                second = first / 'nested'
                output = second / 'installer.sh'
                previous = os.umask(mask)
                try:
                    subprocess.run([sys.executable, '-B', str(script), '--out', str(output)],
                                   capture_output=True, text=True, check=True, timeout=15)
                finally:
                    os.umask(previous)
                for folder in (first, second):
                    self.assertEqual(folder.stat().st_mode & 0o777, expected)
                self.assertEqual(existing.stat().st_mode & 0o777, 0o700)
                self.assertEqual(source.stat().st_mode & 0o777, 0o700)

    def test_packaging_preserves_private_source_and_existing_output_permissions(self):
        spec = importlib.util.spec_from_file_location('permission_package_fixture', ROOT / 'deploy/package-installer.py')
        package = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(package)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source'
            output = Path(directory) / 'output'
            source.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            metadata = source / '.git'
            metadata.mkdir(mode=0o700)
            for relative in package.FILES:
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('fixture\n')
            script = source / 'deploy/package-installer.py'
            shutil.copyfile(ROOT / 'deploy/package-installer.py', script)
            subprocess.run([sys.executable, str(script), '--out', str(output / 'installer.sh')],
                           capture_output=True, text=True, check=True, timeout=15)
            for path in (source, metadata, output):
                with self.subTest(path=path.name):
                    self.assertEqual(path.stat().st_mode & 0o777, 0o700)

    def test_packaging_refuses_linked_outputs_before_changing_either_file(self):
        spec = importlib.util.spec_from_file_location('linked_package_fixture', ROOT / 'deploy/package-installer.py')
        package = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(package)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source'
            for relative in package.FILES:
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('fixture\n')
            script = source / 'deploy/package-installer.py'
            shutil.copyfile(ROOT / 'deploy/package-installer.py', script)
            output = Path(directory) / 'installer.sh'
            checksum = output.with_name(output.name + '.sha256')
            victim = Path(directory) / 'unrelated'
            for linked in (output, checksum):
                output.unlink(missing_ok=True)
                checksum.unlink(missing_ok=True)
                victim.write_bytes(b'unchanged')
                other = checksum if linked == output else output
                other.write_bytes(b'existing output')
                linked.symlink_to(victim)
                result = subprocess.run([sys.executable, str(script), '--out', str(output)],
                                        capture_output=True, text=True, timeout=15)
                with self.subTest(linked=linked.name):
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(victim.read_bytes(), b'unchanged')
                    self.assertEqual(other.read_bytes(), b'existing output')

    def test_help_is_offline_and_cleans_temporary_payloads(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            marker = base / 'git-used'
            git = base / 'git'
            git.write_text('#!/bin/sh\nprintf used > "$SOURCE_TEST_GIT_MARKER"\nexit 97\n')
            git.chmod(0o755)
            env = os.environ.copy()
            env.update(PATH=str(base) + os.pathsep + env['PATH'], TMPDIR=str(base / 'missing'),
                       SOURCE_TEST_GIT_MARKER=str(marker))
            before = set(Path('/tmp').glob('network-relay-installer-*'))
            for name in ('network-relay-install.sh', 'network-relay-install-from-source.sh'):
                result = subprocess.run(['bash', str(ROOT / name), '--help'], env=env, text=True,
                                        capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('Install or update Network Relay', result.stdout)
            self.assertFalse(marker.exists())
            self.assertFalse((base / 'missing').exists())
            self.assertEqual(set(Path('/tmp').glob('network-relay-installer-*')), before)

    def test_published_payloads_and_checksums_match_current_sources(self):
        for name in ('network-relay-install.sh', 'network-relay-install-from-source.sh'):
            with self.subTest(name=name):
                path = ROOT / name
                checksum, filename = path.with_suffix('.sh.sha256').read_text().split()
                self.assertEqual(filename, name)
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), checksum)
                match = re.search(r"<<'NETWORK_RELAY_DEPLOYMENT_BUNDLE'[^\n]*\n(.*?)\nNETWORK_RELAY_DEPLOYMENT_BUNDLE", path.read_text(), re.S)
                with tarfile.open(fileobj=io.BytesIO(base64.b64decode(match[1])), mode='r:gz') as archive:
                    for entry in archive:
                        with self.subTest(file=entry.name):
                            self.assertTrue(entry.isfile())
                            self.assertEqual(archive.extractfile(entry).read(), (ROOT / entry.name).read_bytes())


if __name__ == '__main__':
    unittest.main()
