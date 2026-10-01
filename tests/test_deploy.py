"""Deployment regression tests. OS/package/ACME actions are mocked, never run here."""

import argparse
import base64
from contextlib import ExitStack, redirect_stdout
import importlib.util
import io
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('relay_deploy', ROOT / 'deploy/install.py')
deploy = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = deploy
SPEC.loader.exec_module(deploy)
GLOBAL_SPEC = importlib.util.spec_from_file_location('relay_global_profile', ROOT / 'deploy/global-profile.py')
global_profile = importlib.util.module_from_spec(GLOBAL_SPEC)
sys.modules[GLOBAL_SPEC.name] = global_profile
GLOBAL_SPEC.loader.exec_module(global_profile)
BINARY = ROOT / 'target/debug/network-relay'
PASSWORD = 'test-password-not-real-123'


def fixture_profile(**changes):
    relay = {
        'HTTP2RelayURL': 'https://relay.example.com' + deploy.UDP_TEMPLATE,
        'HTTP3RelayURL': 'https://relay.example.com' + deploy.UDP_TEMPLATE,
        'AdditionalHTTPHeaderFields': {
            'Authorization': 'Basic ' + base64.b64encode(('iphone:' + PASSWORD).encode()).decode()
        },
    }
    payload = {'PayloadType': 'com.apple.relay.managed', 'Relays': [relay], 'MatchDomains': ['google.com']}
    payload.update(changes)
    return {'PayloadContent': [payload], 'PayloadType': 'Configuration'}


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='relay-deploy-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for name, relative in {
            'ETC': 'etc', 'CONFIG': 'etc/relay.toml', 'PROFILE': 'etc/device.mobileconfig',
            'BINARY': 'bin/network-relay', 'UNIT': 'units/network-relay.service',
            'SYSCTL': 'sysctl/network-relay.conf', 'HOOK': 'renew/network-relay', 'SITE': 'site', 'CERTS': 'certs',
        }.items():
            self.stack.enter_context(mock.patch.object(deploy, name, self.root / relative))
        self.calls = []
        self.fail_restart = False
        self.fail_tls = False
        self.active = False
        self.stack.enter_context(mock.patch.object(deploy, 'preflight'))
        self.stack.enter_context(mock.patch.object(deploy.socket, 'getaddrinfo', return_value=[
            (2, 1, 6, '', ('127.0.0.1', 443))]))

    def profile_file(self, profile=None):
        path = self.root / 'input.mobileconfig'
        path.write_bytes(plistlib.dumps(profile or fixture_profile()))
        return path

    def fake_run(self, args, **kwargs):
        command = [str(a) for a in args]
        self.calls.append(command)
        if Path(command[0]) == BINARY and command[1] in ('passwd', 'profile', 'serve', '--version'):
            return deploy_run(args, **kwargs)
        output, status = '', 0
        if command[:2] == ['systemctl', 'show']:
            output = '123\n'
        elif command[:2] in (['systemctl', 'is-active'], ['systemctl', 'is-enabled']):
            status = 0 if self.active else 1
        elif command[:2] == ['sysctl', '-n']:
            output = '16777216\n'  # Existing tuning must not be lowered.
        elif command[:2] == ['systemctl', 'restart'] and self.fail_restart:
            raise subprocess.CalledProcessError(1, command)
        elif command[0] == 'curl' and self.fail_tls:
            status = 60
        elif command[0] == 'certbot':
            directory = deploy.CERTS / 'relay.example.com'
            directory.mkdir(parents=True)
            (directory / 'fullchain.pem').write_bytes((self.root / 'cert.pem').read_bytes())
            (directory / 'privkey.pem').write_bytes((self.root / 'key.pem').read_bytes())
        return subprocess.CompletedProcess(command, status, stdout=output, stderr='')

    def args(self, **changes):
        values = dict(profile=None, domain='relay.example.com', email=None, user=None, port=None,
                      domains=None, binary=BINARY, jobs=1, cert=self.root / 'cert.pem', key=self.root / 'key.pem')
        values.update(changes)
        return argparse.Namespace(**values)

    def certificates(self):
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=relay.example.com', '-addext', 'subjectAltName=DNS:relay.example.com',
                        '-keyout', str(self.root / 'key.pem'), '-out', str(self.root / 'cert.pem')],
                       check=True, capture_output=True)

    def test_profile_import_preserves_identity(self):
        identity, raw = deploy.read_profile(self.profile_file())
        self.assertEqual((identity.domain, identity.port, identity.user), ('relay.example.com', 443, 'iphone'))
        self.assertEqual(identity.password, PASSWORD)
        self.assertNotIn(PASSWORD, repr(identity))
        self.assertEqual(plistlib.loads(raw)['PayloadContent'][0]['MatchDomains'], ['google.com'])

    def test_global_or_bad_profiles_are_rejected(self):
        for domains in ([], ['*'], [''], ['com'], ['-bad.example']):
            with self.subTest(domains=domains), self.assertRaises(ValueError):
                deploy.read_profile(self.profile_file(fixture_profile(MatchDomains=domains)))
        for url in ('http://relay.example.com', 'https://user@relay.example.com',
                    'https://relay.example.com:0', 'https://relay.example.com:65536'):
            profile = fixture_profile()
            relay = profile['PayloadContent'][0]['Relays'][0]
            relay['HTTP2RelayURL'] = relay['HTTP3RelayURL'] = url + deploy.UDP_TEMPLATE
            with self.subTest(url=url), self.assertRaises(ValueError):
                deploy.read_profile(self.profile_file(profile))

    def test_invalid_base64_and_missing_colon_are_rejected(self):
        for value in ('Basic !!!', 'Bearer anything', 'Basic ' + base64.b64encode(b'no-colon').decode()):
            profile = fixture_profile()
            profile['PayloadContent'][0]['Relays'][0]['AdditionalHTTPHeaderFields']['Authorization'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                deploy.read_profile(self.profile_file(profile))

    def test_domain_list_rejects_empty_or_wildcard_rules(self):
        path = self.root / 'domains.txt'
        for content in ('# comment only\n', '*\n', 'example.com\ncloudflare.*\n'):
            path.write_text(content)
            with self.assertRaises(ValueError):
                deploy.load_domains(path)
        path.write_text('Google.COM. # service\ngoogle.com\nclaude.ai\n')
        self.assertEqual(deploy.load_domains(path), ['google.com', 'claude.ai'])

    def test_preset_has_service_domains_without_catch_all_cdn(self):
        domains = deploy.load_domains(ROOT / 'deploy/domains/google-ai-social.txt')
        for required in ('google.com', 'googleapis.com', 'claude.ai', 'claudeusercontent.com',
                         'x.com', 'twimg.com', 'chatgpt.com', 'grok.com', 'googlevideo.com'):
            self.assertIn(required, domains)
        for broad in ('cloudflare.com', 'amazonaws.com', 'azure.com', 'livekit.cloud', 'appspot.com'):
            self.assertNotIn(broad, domains)

    def test_config_escapes_paths_and_does_not_store_plain_password(self):
        identity = deploy.Identity('relay.example.com', 443, 'iphone', PASSWORD)
        data = deploy.render_config(identity, '$argon2id$fixture', Path('/a"b/cert'), Path('/a\\b/key'))
        config = tomllib.loads(data.decode())
        self.assertEqual(config['tls']['cert'], '/a"b/cert')
        self.assertNotIn(PASSWORD.encode(), data)
        self.assertNotIn('blocked_destinations', config['relay'])

    def test_atomic_write_preserves_private_modes_and_rejects_symlinks(self):
        target = self.root / 'private'
        target.write_text('old')
        target.chmod(0o644)
        deploy.atomic_write(target, b'new')
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        link = self.root / 'link'
        link.symlink_to(target)
        with self.assertRaises(ValueError):
            deploy.atomic_write(link, b'wrong')
        self.assertEqual(target.read_bytes(), b'new')

    def test_occupied_port_never_stops_another_service(self):
        output = 'LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=99,fd=3))\n'
        with mock.patch.object(deploy, 'run', return_value=subprocess.CompletedProcess([], 0, output)):
            with self.assertRaises(ValueError):
                deploy.port_available(443, 123)
            deploy.port_available(443, 99)

    @unittest.skipUnless(BINARY.exists(), 'run cargo build first')
    def test_install_and_repeat_with_real_binary_keep_credentials_and_configuration(self):
        self.certificates()
        with mock.patch.object(deploy, 'run', side_effect=self.fake_run), redirect_stdout(io.StringIO()):
            self.assertEqual(deploy.install(self.args(profile=self.profile_file())), 0)
            config = deploy.CONFIG.read_bytes()
            self.assertEqual(deploy.PROFILE.stat().st_mode & 0o777, 0o600)
            self.assertIn('16777216', deploy.SYSCTL.read_text())
            # An administrator's extra setting must survive subsequent upgrades.
            deploy.CONFIG.write_bytes(config + b'\n[debug]\nlog_requests = true\n')
            self.assertEqual(deploy.install(self.args()), 0)
        self.assertEqual(deploy.CONFIG.read_bytes(), config + b'\n[debug]\nlog_requests = true\n')
        self.assertEqual(deploy.read_profile(deploy.PROFILE)[0].password, PASSWORD)
        self.assertTrue(any(c[:2] == ['systemctl', 'restart'] for c in self.calls))
        self.assertTrue(all(PASSWORD not in ' '.join(c) for c in self.calls))

    @unittest.skipUnless(BINARY.exists(), 'run cargo build first')
    def test_generated_profile_matches_generated_server_account(self):
        self.certificates()
        with mock.patch.object(deploy, 'run', side_effect=self.fake_run), redirect_stdout(io.StringIO()):
            self.assertEqual(deploy.install(self.args()), 0)
        identity, raw = deploy.read_profile(deploy.PROFILE)
        self.assertGreaterEqual(len(identity.password), 24)
        self.assertEqual(tomllib.loads(deploy.CONFIG.read_text())['user'][0]['name'], identity.user)
        self.assertEqual(plistlib.loads(raw)['PayloadContent'][0]['MatchDomains'],
                         deploy.load_domains(ROOT / 'deploy/domains/google-ai-social.txt'))

    def test_manual_install_is_never_overwritten(self):
        deploy.CONFIG.parent.mkdir()
        deploy.CONFIG.write_text('manual configuration')
        with mock.patch.object(deploy, 'run') as commands, self.assertRaises(ValueError):
            deploy.install(self.args())
        commands.assert_not_called()
        self.assertEqual(deploy.CONFIG.read_text(), 'manual configuration')

    @unittest.skipUnless(BINARY.exists(), 'run cargo build first')
    def test_automatic_certificate_flow_enables_renewal_hook_and_timer(self):
        self.certificates()
        with mock.patch.object(deploy, 'run', side_effect=self.fake_run), redirect_stdout(io.StringIO()):
            self.assertEqual(deploy.install(self.args(cert=None, key=None, profile=self.profile_file())), 0)
        certbot = next(c for c in self.calls if c[0] == 'certbot')
        self.assertIn('--standalone', certbot)
        self.assertIn('--keep-until-expiring', certbot)
        self.assertEqual(certbot[certbot.index('-d') + 1], 'relay.example.com')
        self.assertIn(['systemctl', 'enable', '--now', 'certbot.timer'], self.calls)
        self.assertIn('systemctl reload network-relay', deploy.HOOK.read_text())
        self.assertEqual(deploy.HOOK.stat().st_mode & 0o777, 0o755)

    def test_profile_domain_mismatch_fails_before_changing_the_system(self):
        with mock.patch.object(deploy, 'run') as commands, self.assertRaises(ValueError):
            deploy.install(self.args(profile=self.profile_file(), domain='different.example.com'))
        commands.assert_not_called()

    def test_failed_upgrade_restores_files_and_running_service(self):
        self.active, self.fail_restart = True, True
        old_files = {deploy.BINARY: b'old binary', deploy.CONFIG: b'old config',
                     deploy.PROFILE: b'old profile', deploy.UNIT: b'old unit'}
        for path, contents in old_files.items():
            deploy.atomic_write(path, contents)
        new_binary = self.root / 'new-binary'
        new_binary.write_bytes(b'new binary')
        with mock.patch.object(deploy, 'run', side_effect=self.fake_run), self.assertRaises(subprocess.CalledProcessError):
            deploy.apply_install(new_binary, b'new config', b'new profile',
                                 deploy.Identity('relay.example.com', 443, 'iphone', PASSWORD), automated_cert=True)
        for path, contents in old_files.items():
            self.assertEqual(path.read_bytes(), contents)
        self.assertFalse(deploy.SYSCTL.exists())
        self.assertFalse(deploy.HOOK.exists())
        self.assertIn(['systemctl', 'start', 'network-relay'], self.calls)

    def test_failed_fresh_install_removes_new_files_and_disables_unit(self):
        self.fail_restart = True
        new_binary = self.root / 'new-binary'
        new_binary.write_bytes(b'new binary')
        with mock.patch.object(deploy, 'run', side_effect=self.fake_run), self.assertRaises(subprocess.CalledProcessError):
            deploy.apply_install(new_binary, b'new config', b'new profile',
                                 deploy.Identity('relay.example.com', 443, 'iphone', PASSWORD), automated_cert=True)
        self.assertFalse(deploy.CONFIG.exists())
        self.assertFalse(deploy.UNIT.exists())
        self.assertIn(['systemctl', 'disable', 'network-relay'], self.calls)
        self.assertNotIn(['systemctl', 'start', 'network-relay'], self.calls)

    def test_tls_health_failure_rolls_back_after_service_start(self):
        self.fail_tls = True
        new_binary = self.root / 'new-binary'
        new_binary.write_bytes(b'new binary')
        with mock.patch.object(deploy, 'run', side_effect=self.fake_run), mock.patch.object(deploy.time, 'sleep'), \
                self.assertRaises(RuntimeError):
            deploy.apply_install(new_binary, b'new config', b'new profile',
                                 deploy.Identity('relay.example.com', 443, 'iphone', PASSWORD), automated_cert=True)
        self.assertFalse(deploy.CONFIG.exists())
        self.assertFalse(deploy.BINARY.exists())
        self.assertIn(['systemctl', 'stop', 'network-relay'], self.calls)


GFWLIST = """[AutoProxy 0.2.9]
! comment
||Example.COM
||blocked.example/some/path
|https://www.site.example/x
|http://85.17.73.31/
.dotted.example
bare.example
/regex.*/
@@||allowed.example
||under_score.example
||wild*.example
keyword-only
||sub.example.com
"""


class GlobalProfileTests(unittest.TestCase):
    def test_gfwlist_rules_become_domains_and_the_rest_is_counted(self):
        domains, stats = global_profile.extract_gfwlist(GFWLIST)
        self.assertEqual(domains, ['bare.example', 'blocked.example', 'dotted.example', 'example.com',
                                   'sub.example.com', 'www.site.example'])
        self.assertEqual(stats['exception rules ignored'], 1)
        self.assertEqual(stats['regular expressions dropped'], 1)
        self.assertEqual(stats['path-limited rules widened to their domain'], 2)
        self.assertEqual(global_profile.collapse(domains), [d for d in domains if d != 'sub.example.com'])

    def test_both_gfwlist_encodings_are_read(self):
        plain = GFWLIST.encode()
        self.assertEqual(global_profile.decode_gfwlist(plain), GFWLIST)
        self.assertEqual(global_profile.decode_gfwlist(base64.b64encode(plain)), GFWLIST)

    def test_shipped_service_lists_are_clean(self):
        for name in ('global-services.txt', 'google-ai-social.txt'):
            text = (ROOT / 'deploy/domains' / name).read_text()
            listed = [line.split('#')[0].strip() for line in text.splitlines() if line.split('#')[0].strip()]
            self.assertEqual(global_profile.load_domain_file(ROOT / 'deploy/domains' / name), listed, name)
        listed = global_profile.load_domain_file(ROOT / 'deploy/domains/global-services.txt')
        for required in ('meta.ai', 'instagram.com', 'spotify.com', 'pandora.com', 'nytimes.com', 'wikipedia.org',
                         'notebooklm.google', 'grok.com', 'claude.ai', 'chatgpt.com'):
            self.assertIn(required, listed)

    @unittest.skipUnless(BINARY.exists(), 'run cargo build first')
    def test_generated_profile_has_the_expected_scope_and_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            gfw, out = Path(directory) / 'gfw.txt', Path(directory) / 'out.mobileconfig'
            gfw.write_text(GFWLIST)
            with redirect_stdout(io.StringIO()):
                global_profile.main(['--host', 'Relay.Example.com.', '--user', 'iphone', '--password', PASSWORD,
                                     '--gfwlist-file', str(gfw), '--binary', str(BINARY), '--out', str(out),
                                     '--services', str(ROOT / 'deploy/domains/global-services.txt')])
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)
            payload = plistlib.loads(out.read_bytes())['PayloadContent'][0]
            domains = payload['MatchDomains']
            self.assertEqual(len(domains), len(set(domains)))
            for expected in ('spotify.com', 'example.com', 'bare.example'):
                self.assertIn(expected, domains)
            self.assertNotIn('sub.example.com', domains)
            self.assertEqual(payload['ExcludedDomains'], ['relay.example.com'])
            self.assertIs(payload['UIToggleEnabled'], False)
            relay = payload['Relays'][0]
            self.assertTrue(relay['HTTP3RelayURL'].startswith('https://relay.example.com/.well-known/masque/udp/'))
            basic = relay['AdditionalHTTPHeaderFields']['Authorization'].split()[1]
            self.assertEqual(base64.b64decode(basic).decode(), 'iphone:' + PASSWORD)


deploy_run = deploy.run

if __name__ == '__main__':
    unittest.main()
