import copy
import os
from pathlib import Path
import plistlib
import re
import runpy
import tempfile
import unittest

TOOL = runpy.run_path(str(Path(__file__).resolve().parents[1] / "select-apple-relay-transport.py"))
H2 = "https://tcp.example.test:8443/udp/{target_host}/{target_port}/"
H3 = "https://quic.example.test:443/other/{target_host}/{target_port}/"


def example(endpoints):
    return {"PayloadType": "Configuration", "PayloadIdentifier": "relay.test", "PayloadUUID": "profile-id",
            "PayloadContent": [{"PayloadType": "com.apple.security.pkcs12", "PayloadContent": b"synthetic fixture"},
                               {"PayloadType": "com.apple.relay.managed", "PayloadUUID": "relay-id",
                                "RelayUUID": "managed-id", "MatchDomains": ["example.test"], "ExcludedDomains": ["local.test"],
                                "MatchFQDNs": ["only.other.test"], "UIToggleEnabled": False, "AllowDNSFailover": False,
                                "Relays": [dict(endpoints, AdditionalHTTPHeaderFields={"Authorization": "Basic ZGVtbzpkZW1v"},
                                               PayloadCertificateUUID="cert-id", RawPublicKeys=[b"test-pin"])]}]}


class SelectTransportTests(unittest.TestCase):
    def test_endpoints_scope_and_identity(self):
        for initial in ({"HTTP2RelayURL": H2}, {"HTTP3RelayURL": H3}, {"HTTP2RelayURL": H2, "HTTP3RelayURL": H3}):
            for kind, key in TOOL["URL_KEYS"].items():
                for fmt in (plistlib.FMT_XML, plistlib.FMT_BINARY):
                    with self.subTest(initial=initial, kind=kind, fmt=fmt):
                        original = example(initial)
                        expected = copy.deepcopy(original)
                        hop = expected["PayloadContent"][1]["Relays"][0]
                        for field in initial:
                            hop.pop(field)
                        hop[key] = initial.get(key, next(iter(initial.values())))
                        result = TOOL["select_transport"](plistlib.dumps(original, fmt=fmt), kind)
                        self.assertEqual(result.startswith(b"bplist00"), fmt == plistlib.FMT_BINARY)
                        self.assertEqual(plistlib.loads(result), expected)

    def test_large_compact_domain_profile_preserves_values(self):
        profile = example({"HTTP2RelayURL": H2})
        relay = profile["PayloadContent"][1]
        relay["MatchDomains"] = [f"host-{n:05d}.example.test" for n in range(12400)]
        raw = re.sub(rb">\s+<", b"><", plistlib.dumps(profile))
        marker = b"<string>value with literal whitespace\n\t </string>"
        raw = raw.replace(b"<string>managed-id</string>", marker)
        self.assertLess(len(raw), TOOL["MAX_SIZE"])
        self.assertGreater(len(plistlib.dumps(plistlib.loads(raw))), TOOL["MAX_SIZE"])
        out = TOOL["select_transport"](raw, "h3")
        expected = plistlib.loads(raw)
        hop = expected["PayloadContent"][1]["Relays"][0]
        hop["HTTP3RelayURL"] = hop.pop("HTTP2RelayURL")
        self.assertEqual(plistlib.loads(out), expected)
        self.assertLessEqual(len(out), TOOL["MAX_SIZE"])

    def test_invalid_inputs(self):
        wrong = example({"HTTP2RelayURL": "http://example.test/"})
        multi = example({"HTTP2RelayURL": H2})
        multi["PayloadContent"][1]["Relays"] *= 2
        two = example({"HTTP2RelayURL": H2})
        two["PayloadContent"].append(two["PayloadContent"][1])
        data = [b"signed CMS envelope", b"<?xml version=\"1.0\"?><plist><dict>", b"x" * (TOOL["MAX_SIZE"] + 1)]
        data += [plistlib.dumps(p) for p in ({}, {"PayloadType": "Configuration"}, wrong, multi, two,
                                              example({}), example({"HTTP2RelayURL": "https://[invalid/"}),
                                              example({"HTTP2RelayURL": "https://user:secret@example.test/"}))]
        for source in data:
            with self.assertRaises(ValueError):
                TOOL["select_transport"](source, "h3")

    def test_private_atomic_copy(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            source = folder / "installed.mobileconfig"
            target = folder / "new.mobileconfig"
            original = plistlib.dumps(example({"HTTP2RelayURL": H2}))
            source.write_bytes(original)
            TOOL["write_copy"](source, target, "h3")
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            archive = target.read_bytes()
            alias = folder / "alias"
            alias.symlink_to(source)
            hard = folder / "hardlink"
            os.link(source, hard)
            for path in (source, target, alias, hard):
                with self.assertRaises(FileExistsError):
                    TOOL["write_copy"](source, path, "h2")
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(target.read_bytes(), archive)
            self.assertEqual(list(folder.glob(".relay-profile-*")), [])


if __name__ == "__main__":
    unittest.main()
