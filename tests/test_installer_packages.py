"""Check that uploadable installers contain the current deployment sources."""
import base64
import hashlib
import io
from pathlib import Path
import re
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InstallerPackageTests(unittest.TestCase):
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
