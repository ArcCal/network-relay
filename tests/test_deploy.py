"""Deployment regression tests. OS/package/ACME actions are mocked, never run here."""

import argparse
import base64
import os
from contextlib import ExitStack, redirect_stdout
import importlib.util
import io
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import time
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
BINARY = Path(os.environ.get('RELAY_BINARY', ROOT / 'target/debug/network-relay')).resolve()
ORIGINAL_GETADDRINFO = deploy.socket.getaddrinfo
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
            'ETC': 'etc', 'CONFIG': 'etc/relay.toml', 'STATE': 'etc/install.json',
            'LEGACY_PROFILE': 'etc/device.mobileconfig', 'TLS': 'etc/tls',
            'BINARY': 'bin/network-relay', 'UNIT': 'units/network-relay.service',
            'SYSCTL': 'sysctl/network-relay.conf', 'HOOK': 'renew/network-relay', 'SITE': 'site', 'CERTS': 'certs',
        }.items():
            self.stack.enter_context(mock.patch.object(deploy, name, self.root / relative))
        self.calls = []
        self.missing_user = False
        self.unreadable = set()
        self.fail_restart = False
        self.fail_tls = False
        self.active = False
        self.stack.enter_context(mock.patch.object(deploy, 'preflight'))
        # The service account: this test's own user and group, which it may
        # give files to without being root.
        self.stack.enter_context(mock.patch.object(deploy, 'service_ids', return_value=(os.getuid(), os.getgid())))
        self.stack.enter_context(mock.patch.object(deploy.socket, 'getaddrinfo', return_value=[
            (2, 1, 6, '', ('127.0.0.1', 443))]))

    def profile_file(self, profile=None):
        path = self.root / 'input.mobileconfig'
        path.write_bytes(plistlib.dumps(profile or fixture_profile()))
        return path

    def fake_run(self, args, **kwargs):
        command = [str(a) for a in args]
        self.calls.append(command)
        binary = Path(command[0])
        candidate = binary.name == 'network-relay' and binary.parent.name.startswith('.network-relay-install-')
        if (binary == BINARY or candidate) and command[1] in ('passwd', 'profile', 'serve', '--version'):
            return deploy_run(args, **kwargs)
        output, status = '', 0
        if command[:2] == ['id', '-u'] and self.missing_user:
            status = 1
        elif command[0] == 'runuser':
            status = 1 if command[-1] in self.unreadable else 0
        elif command[:2] == ['systemctl', 'show']:
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
            directory.mkdir(parents=True, exist_ok=True)
            (directory / 'fullchain.pem').write_bytes((self.root / 'cert.pem').read_bytes())
            (directory / 'privkey.pem').write_bytes((self.root / 'key.pem').read_bytes())
        return subprocess.CompletedProcess(command, status, stdout=output, stderr='')

    def args(self, **changes):
        values = dict(profile=None, domain='relay.example.com', email=None, user=None, port=None,
                      domains=None, binary=BINARY, jobs=1, cert=self.root / 'cert.pem', key=self.root / 'key.pem',
                      profile_out=None, refresh_profile=False, reset_password=False,
                      no_gfwlist=True, gfwlist_file=None, gfwlist_url=global_profile.GFWLIST_URL,
                      no_proxy_list=True, proxy_list_file=None, proxy_list_url=global_profile.PROXY_LIST_URL)
        values.update(changes)
        return argparse.Namespace(**values)

    def certificates(self):
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=relay.example.com', '-addext', 'subjectAltName=DNS:relay.example.com',
                        '-addext', 'basicConstraints=critical,CA:TRUE',
                        '-addext', 'keyUsage=critical,digitalSignature,keyCertSign,cRLSign',
                        '-addext', 'subjectKeyIdentifier=hash', '-addext', 'authorityKeyIdentifier=keyid:always',
                        '-keyout', str(self.root / 'key.pem'), '-out', str(self.root / 'cert.pem')],
                       check=True, capture_output=True)

    def test_profile_import_preserves_identity(self):
        identity, raw = deploy.read_profile(self.profile_file())
        self.assertEqual((identity.domain, identity.port, identity.user), ('relay.example.com', 443, 'iphone'))
        self.assertEqual(identity.password, PASSWORD)
        self.assertNotIn(PASSWORD, repr(identity))
        self.assertEqual(plistlib.loads(raw)['PayloadContent'][0]['MatchDomains'], ['google.com'])

    def test_global_or_bad_profiles_are_rejected(self):
        for domains in ([], ['*'], [''], ['*.com'], ['-bad.example']):
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

    def test_preflight_accepts_debian_12_and_13_only(self):
        self.stack.close()  # undo the preflight mock from setUp
        release = lambda version: {'ID': 'debian', 'VERSION_ID': version}
        with mock.patch.object(deploy.os, 'geteuid', return_value=0), \
                mock.patch.object(deploy.platform, 'machine', return_value='x86_64'), \
                mock.patch.object(deploy.Path, 'is_dir', return_value=True):
            for version in ('12', '13'):
                with mock.patch.object(deploy.platform, 'freedesktop_os_release', return_value=release(version)):
                    deploy.preflight()
            for version in ('11', '14'):
                with mock.patch.object(deploy.platform, 'freedesktop_os_release', return_value=release(version)), \
                        self.assertRaises(ValueError):
                    deploy.preflight()

    def test_occupied_port_never_stops_another_service(self):
        output = 'LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=99,fd=3))\n'
        with mock.patch.object(deploy, 'run', return_value=subprocess.CompletedProcess([], 0, output)):
            with self.assertRaises(ValueError):
                deploy.port_available(443, 123)
            deploy.port_available(443, 99)

    def test_cli_defaults_to_uploaded_binary_and_source_build_is_explicit(self):
        for options, expected in (([], Path('/tmp/network-relay')),
                                  (['--binary', '/root/relay'], Path('/root/relay')),
                                  (['--build-from-source'], None)):
            with (self.subTest(options=options),
                  mock.patch.object(sys, 'argv', ['install.py', *options]),
                  mock.patch('builtins.open', mock.mock_open()),
                  mock.patch.object(deploy.fcntl, 'flock'),
                  mock.patch.object(deploy, 'install', return_value=0) as install):
                self.assertEqual(deploy.main(), 0)
                self.assertEqual(install.call_args.args[0].binary, expected)
                self.assertFalse(install.call_args.args[0].no_gfwlist)
                self.assertFalse(hasattr(install.call_args.args[0], 'proxy_list_url'))

    def test_missing_archive_and_wrong_architecture_fail_before_system_changes(self):
        upload = self.root / 'upload'
        for data in (None, b'not an executable', b'\x7fELF\x02\x01' + bytes(12) + b'\xb7\x00'):
            with self.subTest(data=data):
                if data is not None:
                    upload.write_bytes(data)
                with mock.patch.object(deploy, 'run') as commands, self.assertRaises(ValueError):
                    deploy.install(self.args(binary=upload))
                commands.assert_not_called()
                self.assertFalse(deploy.CONFIG.exists())
                self.assertEqual(list(deploy.BINARY.parent.glob('.network-relay-install-*')), [])

    @unittest.skipUnless(BINARY.exists(), 'run cargo build first or set RELAY_BINARY')
    def test_uploaded_binary_without_execute_permission_is_installed_from_private_snapshot(self):
        self.certificates()
        upload = self.root / 'upload'
        upload.write_bytes(BINARY.read_bytes())
        upload.chmod(0o600)
        bundle = self.root / 'bundle'
        for relative in ('deploy/network-relay.service', 'deploy/certbot-hook.sh',
                         'deploy/domains/google-ai-social.txt', 'deploy/domains/public-suffix-icann.dat'):
            target = bundle / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / relative).read_bytes())
        self.assertFalse((bundle / 'Cargo.toml').exists(), 'no Rust source or manifest in deployment bundle')
        with (mock.patch.object(deploy, 'REPO', bundle),
              mock.patch.object(deploy, 'run', side_effect=self.fake_run), redirect_stdout(io.StringIO())):
            self.assertEqual(deploy.install(self.args(binary=upload)), 0)
        self.assertEqual(deploy.BINARY.read_bytes(), upload.read_bytes())
        self.assertEqual(upload.stat().st_mode & 0o777, 0o600, 'uploaded file is left untouched')
        self.assertEqual(deploy.BINARY.stat().st_mode & 0o777, 0o755)
        self.assertFalse(any(c[0] == str(upload) for c in self.calls), '/tmp is never executed')
        self.assertTrue(any('.network-relay-install-' in c[0] and c[1] == 'profile' for c in self.calls))
        self.assertEqual(list(deploy.BINARY.parent.glob('.network-relay-install-*')), [])

    @unittest.skipUnless(BINARY.exists(), 'run cargo build first or set RELAY_BINARY')
    def test_explicit_source_build_installs_build_tools(self):
        self.certificates()
        with (mock.patch.object(deploy, 'run', side_effect=self.fake_run),
              mock.patch.object(deploy, 'build_binary', return_value=BINARY) as build,
              redirect_stdout(io.StringIO())):
            self.assertEqual(deploy.install(self.args(binary=None)), 0)
        self.assertIsNone(build.call_args.args[0].binary)
        apt = [c for c in self.calls if c[0] == 'apt-get']
        self.assertTrue(any(all(p in c for p in ('build-essential', 'pkg-config', 'git')) for c in apt))

    @unittest.skipUnless(BINARY.exists(), 'run cargo build first')
    def test_install_and_repeat_with_real_binary_keep_credentials_and_configuration(self):
        self.certificates()
        with mock.patch.object(deploy, 'run', side_effect=self.fake_run), redirect_stdout(io.StringIO()):
            self.assertEqual(deploy.install(self.args(profile=self.profile_file())), 0)
            config = deploy.CONFIG.read_bytes()
            self.assertFalse(deploy.LEGACY_PROFILE.exists(), 'no copy of the password is kept')
            self.assertEqual(deploy.STATE.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(PASSWORD.encode(), deploy.STATE.read_bytes())
            self.assertIn('16777216', deploy.SYSCTL.read_text())
            # An administrator's extra setting must survive subsequent upgrades.
            deploy.CONFIG.write_bytes(config + b'\n[debug]\nlog_requests = true\n')
            self.assertEqual(deploy.install(self.args()), 0)
            # Upgrades need neither the profile nor the password.
            self.assertEqual(deploy.install(self.args(domain=None)), 0)
        self.assertEqual(deploy.CONFIG.read_bytes(), config + b'\n[debug]\nlog_requests = true\n')
        self.assertEqual(deploy.read_state(deploy.STATE),
                         deploy.Identity('relay.example.com', 443, 'iphone', None))
        self.assertTrue(any(c[:2] == ['systemctl', 'restart'] for c in self.calls))
        self.assertTrue(all(PASSWORD not in ' '.join(c) for c in self.calls))
        apt = [c for c in self.calls if c[0] == 'apt-get']
        self.assertTrue(apt and all('DPkg::Lock::Timeout=1800' in c for c in apt), 'apt waits for the dpkg lock')
        self.assertTrue(any('procps' in c for c in apt), 'sysctl and kill come from procps')
        self.assertFalse(any(p in c for c in apt for p in ('build-essential', 'pkg-config', 'git')))
        self.assertFalse(any('cargo' in Path(c[0]).name or 'rustup' in Path(c[0]).name for c in self.calls))
        health = [c for c in self.calls if c[0] == 'curl']
        # The website is optional: any HTTP answer, even 404 without [web], is a healthy relay.
        self.assertTrue(health and all('--fail' not in c for c in health))

    @unittest.skipUnless(BINARY.exists(), 'run cargo build first')
    def test_generated_profile_is_published_once_and_matches_the_account(self):
        self.certificates()
        output = io.StringIO()
        with mock.patch.object(deploy, 'run', side_effect=self.fake_run), redirect_stdout(output):
            self.assertEqual(deploy.install(self.args()), 0)
        published = list((deploy.SITE / '.publish').glob('*.mobileconfig'))
        self.assertEqual(len(published), 1)
        self.assertEqual(published[0].stat().st_mode & 0o777, 0o600)
        self.assertIn(f'https://relay.example.com/{published[0].name}', output.getvalue())
        generation = next(i for i, c in enumerate(self.calls) if len(c) > 1 and c[1] == 'profile')
        restart = self.calls.index(['systemctl', 'restart', 'network-relay'])
        self.assertLess(generation, restart, 'the profile is ready before the account starts')
        identity, raw = deploy.read_profile(published[0])
        self.assertGreaterEqual(len(identity.password), 24)
        self.assertNotIn(identity.password, output.getvalue())
        self.assertFalse(deploy.LEGACY_PROFILE.exists())
        user = tomllib.loads(deploy.CONFIG.read_text())['user'][0]
        self.assertEqual(user['name'], identity.user)
        self.assertTrue(user['password_hash'].startswith('$pbkdf2-sha256$'), 'a generated secret needs no Argon2')
        expected = global_profile.root_domains(deploy.load_domains(ROOT / 'deploy/domains/google-ai-social.txt'),
                         (ROOT / 'deploy/domains/public-suffix-icann.dat').read_text())
        self.assertEqual(plistlib.loads(raw)['PayloadContent'][0]['MatchDomains'], expected)

    @unittest.skipUnless(BINARY.exists(), 'run cargo build first')
    def test_profile_out_writes_a_private_file_instead_of_publishing(self):
        self.certificates()
        out = self.root / 'device.mobileconfig'
        with mock.patch.object(deploy, 'run', side_effect=self.fake_run), redirect_stdout(io.StringIO()):
            self.assertEqual(deploy.install(self.args(profile_out=out)), 0)
        self.assertEqual(out.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list((deploy.SITE / '.publish').glob('*.mobileconfig')), [], 'nothing published')
        self.assertEqual(deploy.read_profile(out)[0].user, 'iphone')

    @unittest.skipUnless(BINARY.exists(), 'set RELAY_BINARY')
    def test_combined_root_profile_and_refresh_keep_existing_credentials(self):
        self.certificates()
        gfw = self.root / 'gfw.txt'
        gfw.write_text('[AutoProxy 0.2.9]\n||deep.google.com\n||login.blocked.co.uk\n||api.list-only.org\n||site.adult\n')
        options = dict(no_gfwlist=False, gfwlist_file=gfw)
        with mock.patch.object(deploy, 'run', side_effect=self.fake_run), redirect_stdout(io.StringIO()):
            self.assertEqual(deploy.install(self.args(**options)), 0)
            old_profile = next((deploy.SITE / '.publish').glob('*.mobileconfig'))
            initial_domains = plistlib.loads(old_profile.read_bytes())['PayloadContent'][0]['MatchDomains']
            self.assertFalse(any(d == 'adult' or d.endswith('.adult') for d in initial_domains))
            identity = deploy.read_profile(old_profile)[0]
            before = deploy.CONFIG.read_bytes()
            gfw.write_text(gfw.read_text() + '||new.updated.org\n')
            start = len(self.calls)
            out = self.root / 'updated.mobileconfig'
            with mock.patch.object(deploy, 'verify_refresh_credentials') as verify:
                self.assertEqual(deploy.install(self.args(refresh_profile=True, profile_out=out, **options)), 0)
                self.assertEqual(verify.call_args.args[0].password, identity.password)
        payload = plistlib.loads(out.read_bytes())['PayloadContent'][0]
        self.assertIn('google.com', payload['MatchDomains'])
        self.assertIn('blocked.co.uk', payload['MatchDomains'])
        self.assertIn('list-only.org', payload['MatchDomains'])
        self.assertIn('updated.org', payload['MatchDomains'])
        self.assertNotIn('co.uk', payload['MatchDomains'])
        self.assertEqual(payload['MatchDomains'], sorted(set(payload['MatchDomains'])))
        self.assertEqual(payload['ExcludedDomains'], ['relay.example.com'])
        self.assertTrue(payload['UIToggleEnabled'])
        self.assertEqual(deploy.read_profile(out)[0].password, identity.password)
        self.assertEqual(deploy.CONFIG.read_bytes(), before)
        self.assertFalse(any(len(c) > 1 and c[1] == 'passwd' for c in self.calls[start:]))
        generated = [c for c in self.calls if len(c) > 1 and c[1] == 'profile']
        self.assertTrue(all(c.count('--match-domain') == 1 for c in generated), 'no ARG_MAX-sized command')

    @unittest.skipUnless(BINARY.exists(), 'set RELAY_BINARY')
    def test_password_reset_needs_no_old_password_and_preserves_other_accounts_and_settings(self):
        self.certificates()
        with mock.patch.object(deploy, 'run', side_effect=self.fake_run), redirect_stdout(io.StringIO()):
            self.assertEqual(deploy.install(self.args()), 0)
            old_profile = next((deploy.SITE / '.publish').glob('*.mobileconfig'))
            old_identity = deploy.read_profile(old_profile)[0]
            config = tomllib.loads(deploy.CONFIG.read_text())
            spare = {'name': 'spare', 'password_hash': config['user'][0]['password_hash']}
            deploy.CONFIG.write_text(deploy.CONFIG.read_text() + '\n[debug]\nlog_requests = true\n\n'
                                     + '[[user]]\nname = "spare"\npassword_hash = '
                                     + deploy.json.dumps(spare['password_hash']) + '\n')
            before = tomllib.loads(deploy.CONFIG.read_text())
            old_profile.unlink()  # No previous cleartext credential is available.
            out = self.root / 'reset.mobileconfig'
            with (mock.patch.object(deploy, 'refresh_credentials') as recover,
                  mock.patch.object(deploy, 'verify_refresh_credentials') as authenticate,
                  mock.patch.object(deploy.getpass, 'getpass') as prompt):
                self.assertEqual(deploy.install(self.args(reset_password=True, profile_out=out)), 0)
                recover.assert_not_called()
                authenticate.assert_not_called()
                prompt.assert_not_called()
        identity = deploy.read_profile(out)[0]
        self.assertNotEqual(identity.password, old_identity.password)
        self.assertGreaterEqual(len(identity.password), 24)
        after = tomllib.loads(deploy.CONFIG.read_text())
        self.assertNotEqual(after['user'][0]['password_hash'], before['user'][0]['password_hash'])
        before['user'][0]['password_hash'] = after['user'][0]['password_hash']
        self.assertEqual(after, before, 'only the target password hash changes')
        self.assertEqual(after['user'][1], spare)

    def test_reset_user_hash_handles_quotes_and_refuses_ambiguous_users(self):
        source = b"[[ user ]] # account\n'name' = 'iphone'\n'password_hash' = 'old'\n\n[[user]]\nname='other'\npassword_hash='keep'\n"
        updated = tomllib.loads(deploy.reset_user_hash(source, 'iphone', 'new').decode())
        self.assertEqual(updated['user'][0]['password_hash'], 'new')
        self.assertEqual(updated['user'][1]['password_hash'], 'keep')
        with self.assertRaises(ValueError):
            deploy.reset_user_hash(source, 'absent', 'new')

    @unittest.skipUnless(BINARY.exists(), 'set RELAY_BINARY')
    def test_failed_password_reset_rolls_back_old_hash_and_device_profile(self):
        self.certificates()
        with mock.patch.object(deploy, 'run', side_effect=self.fake_run), redirect_stdout(io.StringIO()):
            self.assertEqual(deploy.install(self.args()), 0)
            before = deploy.CONFIG.read_bytes()
            old_profile = next((deploy.SITE / '.publish').glob('*.mobileconfig'))
            profile_data = old_profile.read_bytes()
            self.fail_restart = True
            out = self.root / 'failed-reset.mobileconfig'
            with self.assertRaises(subprocess.CalledProcessError):
                deploy.install(self.args(reset_password=True, profile_out=out))
        self.assertEqual(deploy.CONFIG.read_bytes(), before)
        self.assertEqual(old_profile.read_bytes(), profile_data)
        self.assertFalse(out.exists())

    @unittest.skipUnless(BINARY.exists(), 'set RELAY_BINARY')
    def test_failed_download_and_empty_gfwlist_do_not_install_partial_profile(self):
        self.certificates()
        bad = self.root / 'empty-gfw.txt'
        bad.write_text('[AutoProxy 0.2.9]\n! no domains\n')
        for options in (dict(no_gfwlist=False, gfwlist_file=bad), dict(no_gfwlist=False)):
            with (self.subTest(options=options),
                  mock.patch.object(deploy, 'run', side_effect=self.fake_run),
                  mock.patch.object(deploy.RULES.urllib.request, 'urlopen', side_effect=OSError('offline')),
                  redirect_stdout(io.StringIO()), self.assertRaises(ValueError)):
                deploy.install(self.args(cert=None, key=None, **options))
            self.assertFalse(deploy.CONFIG.exists())
            self.assertFalse(any(c[0] == 'certbot' for c in self.calls))
            self.assertFalse(any(c[:2] == ['systemctl', 'restart'] for c in self.calls))

    @unittest.skipUnless(BINARY.exists(), 'set RELAY_BINARY')
    def test_oversized_single_profile_is_refused_without_installing_account(self):
        self.certificates()
        domains = [f'domain-{i:05d}-example.com' for i in range(40000)]
        with (mock.patch.object(deploy, 'run', side_effect=self.fake_run),
              mock.patch.object(deploy, 'profile_domains', return_value=domains), redirect_stdout(io.StringIO())):
            with self.assertRaisesRegex(ValueError, '524288-byte limit'):
                deploy.install(self.args())
        self.assertFalse(deploy.CONFIG.exists())
        self.assertFalse(deploy.STATE.exists())
        self.assertFalse(any(c[:2] == ['systemctl', 'restart'] for c in self.calls))
        self.assertEqual(list((deploy.SITE / '.publish').glob('*.mobileconfig')), [])

    @unittest.skipUnless(BINARY.exists(), 'set RELAY_BINARY')
    def test_oversized_reset_keeps_existing_hash_and_profile(self):
        self.certificates()
        with mock.patch.object(deploy, 'run', side_effect=self.fake_run), redirect_stdout(io.StringIO()):
            self.assertEqual(deploy.install(self.args()), 0)
            before = deploy.CONFIG.read_bytes()
            old_profile = next((deploy.SITE / '.publish').glob('*.mobileconfig'))
            old_data = old_profile.read_bytes()
            out = self.root / 'oversized-reset.mobileconfig'
            start = len(self.calls)
            with (mock.patch.object(deploy.RULES, 'profile_with_domains',
                                    return_value=b'x' * deploy.MAX_DEVICE_PROFILE_BYTES),
                  self.assertRaisesRegex(ValueError, '524288-byte limit')):
                deploy.install(self.args(reset_password=True, profile_out=out))
        self.assertEqual(deploy.CONFIG.read_bytes(), before)
        self.assertEqual(old_profile.read_bytes(), old_data)
        self.assertFalse(out.exists())
        self.assertFalse(any(c[:2] == ['systemctl', 'restart'] for c in self.calls[start:]))

    @unittest.skipUnless(BINARY.exists(), 'set RELAY_BINARY')
    def test_profile_refresh_authenticates_locally_with_real_tls(self):
        deploy.socket.getaddrinfo.side_effect = ORIGINAL_GETADDRINFO
        self.certificates()
        with deploy.socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            port = reserved.getsockname()[1]
        identity = deploy.Identity('relay.example.com', port, 'iphone', PASSWORD)
        password_hash = tomllib.loads(subprocess.run(
            [str(BINARY), 'passwd', '--name', 'iphone', '--stdin', '--fast-hash'],
            input=PASSWORD + '\n', text=True, capture_output=True, check=True).stdout)['user'][0]['password_hash']
        config = self.root / 'test-server.toml'
        config.write_bytes(deploy.render_config(identity, password_hash, self.root / 'cert.pem', self.root / 'key.pem',
                                               deploy.SITE)
                           .replace(b'listen = "[::]:', b'listen = "127.0.0.1:'))
        # The website is optional; create it for this otherwise real configuration.
        deploy.SITE.mkdir()
        (deploy.SITE / 'index.html').write_text('test relay')
        log_path = self.root / 'test-server.log'
        log = log_path.open('w')
        self.addCleanup(log.close)
        process = subprocess.Popen([str(BINARY), 'serve', '--config', str(config)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 10
            while True:
                try:
                    with deploy.socket.create_connection(('127.0.0.1', port), timeout=.2):
                        break
                except OSError:
                    if time.monotonic() > deadline or process.poll() is not None:
                        self.fail('test relay did not start: ' + log_path.read_text())
                    time.sleep(.05)
            context = deploy.ssl.create_default_context(cafile=str(self.root / 'cert.pem'))
            context.verify_flags |= deploy.ssl.VERIFY_X509_STRICT
            with mock.patch.object(deploy.ssl, 'create_default_context', return_value=context):
                deploy.verify_refresh_credentials(identity)
                with self.assertRaises(ValueError):
                    deploy.verify_refresh_credentials(deploy.replace(identity, password='wrong-password-123'))
        finally:
            process.terminate()
            process.wait(timeout=10)

    @unittest.skipUnless(BINARY.exists(), 'run cargo build first')
    def test_installations_from_before_the_state_file_upgrade_from_their_profile(self):
        self.certificates()
        with mock.patch.object(deploy, 'run', side_effect=self.fake_run), redirect_stdout(io.StringIO()):
            self.assertEqual(deploy.install(self.args(profile=self.profile_file())), 0)
            deploy.STATE.unlink()
            deploy.LEGACY_PROFILE.write_bytes(self.profile_file().read_bytes())
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(deploy.install(self.args(domain=None)), 0)
        self.assertEqual(deploy.read_state(deploy.STATE).user, 'iphone')
        self.assertIn(f'rm {deploy.LEGACY_PROFILE}', output.getvalue())
        self.assertTrue(deploy.LEGACY_PROFILE.exists(), 'the administrator decides when to delete it')

    @unittest.skipUnless(BINARY.exists(), 'run cargo build first')
    def test_external_certificate_symlinks_are_kept_and_upgrades_keep_them(self):
        self.certificates()
        # Let's Encrypt style: live/ holds symlinks into archive/.
        archive, live = self.root / 'archive', self.root / 'live'
        archive.mkdir(), live.mkdir()
        (self.root / 'cert.pem').rename(archive / 'fullchain1.pem')
        (self.root / 'key.pem').rename(archive / 'privkey1.pem')
        (live / 'fullchain.pem').symlink_to(archive / 'fullchain1.pem')
        (live / 'privkey.pem').symlink_to(archive / 'privkey1.pem')
        external = dict(cert=live / 'fullchain.pem', key=live / 'privkey.pem', profile=self.profile_file())
        with mock.patch.object(deploy, 'run', side_effect=self.fake_run), redirect_stdout(io.StringIO()):
            self.assertEqual(deploy.install(self.args(**external)), 0)
            tls = tomllib.loads(deploy.CONFIG.read_text())['tls']
            self.assertEqual(tls['cert'], str(live / 'fullchain.pem'), 'the live symlink, not its target')
            self.assertEqual(tls['key'], str(live / 'privkey.pem'))
            # An upgrade without --cert/--key keeps the external certificate.
            self.calls.clear()
            self.assertEqual(deploy.install(self.args(cert=None, key=None)), 0)
        self.assertFalse(any(c[0] == 'certbot' for c in self.calls), 'no switch to certbot on upgrade')
        self.assertFalse(deploy.HOOK.exists(), 'no certbot hook for an external certificate')
        self.assertEqual(tomllib.loads(deploy.CONFIG.read_text())['tls'], tls)

    @unittest.skipUnless(BINARY.exists(), 'run cargo build first')
    def test_a_different_certificate_on_upgrade_is_refused_not_ignored(self):
        self.certificates()
        with mock.patch.object(deploy, 'run', side_effect=self.fake_run), redirect_stdout(io.StringIO()):
            self.assertEqual(deploy.install(self.args(profile=self.profile_file())), 0)
        other = self.root / 'other'
        other.mkdir()
        for name in ('cert.pem', 'key.pem'):
            (other / name).write_bytes((self.root / name).read_bytes())
        before = deploy.CONFIG.read_bytes()
        self.calls.clear()
        with mock.patch.object(deploy, 'run', side_effect=self.fake_run), self.assertRaises(ValueError):
            deploy.install(self.args(cert=other / 'cert.pem', key=other / 'key.pem'))
        self.assertEqual(self.calls, [], 'refused before changing anything')
        self.assertEqual(deploy.CONFIG.read_bytes(), before)

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
        self.assertEqual(deploy.HOOK.read_bytes(), (ROOT / 'deploy/certbot-hook.sh').read_bytes())
        self.assertEqual(deploy.HOOK.stat().st_mode & 0o777, 0o755)
        # The relay runs as its own user: it reads copies of certbot's files
        # through its group, and the configuration likewise.
        tls = tomllib.loads(deploy.CONFIG.read_text())['tls']
        self.assertEqual((tls['cert'], tls['key']), (str(deploy.TLS / 'fullchain.pem'), str(deploy.TLS / 'privkey.pem')))
        live = deploy.CERTS / 'relay.example.com'
        self.assertEqual((deploy.TLS / 'privkey.pem').read_bytes(), (live / 'privkey.pem').read_bytes())
        self.assertEqual((deploy.TLS / 'source').read_text().strip(), str(live))
        for path, mode in ((deploy.TLS / 'privkey.pem', 0o640), (deploy.CONFIG, 0o640), (deploy.ETC, 0o750),
                           (deploy.TLS, 0o750), (deploy.STATE, 0o600)):
            self.assertEqual(path.stat().st_mode & 0o777, mode, path)
        self.assertEqual(deploy.CONFIG.stat().st_gid, os.getgid())
        publish = deploy.SITE / '.publish'
        self.assertEqual((publish.stat().st_mode & 0o777, publish.stat().st_uid), (0o700, os.getuid()))

    @unittest.skipUnless(BINARY.exists(), 'run cargo build first')
    def test_upgrade_moves_a_root_era_certbot_setup_to_readable_copies(self):
        self.certificates()
        with mock.patch.object(deploy, 'run', side_effect=self.fake_run), redirect_stdout(io.StringIO()):
            self.assertEqual(deploy.install(self.args(cert=None, key=None, profile=self.profile_file())), 0)
            # As earlier versions wrote it: certbot's files, read as root.
            live = deploy.CERTS / 'relay.example.com'
            config = deploy.CONFIG.read_text()
            for name in ('fullchain.pem', 'privkey.pem'):
                config = config.replace(f'"{deploy.TLS / name}"', f'"{live / name}"')
            deploy.CONFIG.write_text(config + '\n[debug]\nlog_requests = true\n')
            self.assertEqual(deploy.install(self.args(cert=None, key=None)), 0)
        config = tomllib.loads(deploy.CONFIG.read_text())
        self.assertEqual(config['tls']['cert'], str(deploy.TLS / 'fullchain.pem'))
        self.assertEqual(config['tls']['key'], str(deploy.TLS / 'privkey.pem'))
        self.assertTrue(config['debug']['log_requests'], 'the rest of the configuration is kept')

    def test_certbot_hook_copies_only_its_certificate_and_reloads(self):
        import grp
        tls, live, bin_dir = self.root / 'tls', self.root / 'live/relay.example.com', self.root / 'bin'
        for d in (tls, live, bin_dir):
            d.mkdir(parents=True)
        (tls / 'source').write_text(f'{live}\n')
        (live / 'fullchain.pem').write_text('chain v2')
        (live / 'privkey.pem').write_text('key v2')
        log = self.root / 'systemctl.log'
        fake = bin_dir / 'systemctl'
        fake.write_text(f'#!/bin/sh\necho "$@" >> {log}\nexit 0\n')
        fake.chmod(0o755)
        env = dict(os.environ, NETWORK_RELAY_TLS=str(tls), NETWORK_RELAY_GROUP=grp.getgrgid(os.getgid()).gr_name,
                   PATH=f'{bin_dir}:{os.environ["PATH"]}')
        hook = ROOT / 'deploy/certbot-hook.sh'
        other = subprocess.run(['sh', hook], env=dict(env, RENEWED_LINEAGE=str(self.root / 'live/other')),
                               capture_output=True, text=True)
        self.assertEqual(other.returncode, 0, other.stderr)
        self.assertFalse((tls / 'privkey.pem').exists(), 'another certificate is not copied')
        ours = subprocess.run(['sh', hook], env=dict(env, RENEWED_LINEAGE=str(live)), capture_output=True, text=True)
        self.assertEqual(ours.returncode, 0, ours.stderr)
        self.assertEqual((tls / 'privkey.pem').read_text(), 'key v2')
        self.assertEqual((tls / 'fullchain.pem').read_text(), 'chain v2')
        self.assertEqual((tls / 'privkey.pem').stat().st_mode & 0o777, 0o640)
        self.assertEqual(list(tls.glob('.*.new')), [], 'no temporary files left')
        self.assertIn('reload network-relay', log.read_text())
        by_hand = subprocess.run(['sh', hook], env=env, capture_output=True, text=True)
        self.assertEqual(by_hand.returncode, 0, 'run by hand, without RENEWED_LINEAGE, it copies too')
        (live / 'fullchain.pem').write_text('chain v3')
        (live / 'privkey.pem').unlink()
        failed = subprocess.run(['sh', hook], env=env, capture_output=True, text=True)
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual((tls / 'fullchain.pem').read_text(), 'chain v2', 'keep the old pair when staging fails')
        self.assertEqual((tls / 'privkey.pem').read_text(), 'key v2')
        self.assertEqual(list(tls.glob('.*.new')), [])

    def test_the_service_account_is_created_when_missing(self):
        self.missing_user = True
        with mock.patch.object(deploy, 'run', side_effect=self.fake_run):
            deploy.ensure_service_user()
        useradd = [c for c in self.calls if c[0] == 'useradd']
        self.assertEqual(len(useradd), 1)
        self.assertIn('--system', useradd[0])
        self.assertEqual(useradd[0][-1], 'network-relay')
        self.calls.clear()
        self.missing_user = False
        with mock.patch.object(deploy, 'run', side_effect=self.fake_run):
            deploy.ensure_service_user()
        self.assertFalse(any(c[0] == 'useradd' for c in self.calls))

    @unittest.skipUnless(BINARY.exists(), 'run cargo build first')
    def test_an_external_key_the_service_cannot_read_is_refused(self):
        self.certificates()
        self.unreadable = {str(self.root / 'key.pem')}
        with mock.patch.object(deploy, 'run', side_effect=self.fake_run), redirect_stdout(io.StringIO()), \
                self.assertRaisesRegex(ValueError, 'chgrp network-relay'):
            deploy.install(self.args(profile=self.profile_file()))
        self.assertFalse(deploy.CONFIG.exists())
        self.assertFalse(any(c[:2] == ['systemctl', 'restart'] for c in self.calls))

    def test_profile_domain_mismatch_fails_before_changing_the_system(self):
        with mock.patch.object(deploy, 'run') as commands, self.assertRaises(ValueError):
            deploy.install(self.args(profile=self.profile_file(), domain='different.example.com'))
        commands.assert_not_called()

    def test_failed_upgrade_restores_files_and_running_service(self):
        self.active, self.fail_restart = True, True
        old_files = {deploy.BINARY: b'old binary', deploy.CONFIG: b'old config',
                     deploy.STATE: b'old state', deploy.UNIT: b'old unit'}
        for path, contents in old_files.items():
            deploy.atomic_write(path, contents)
        old_gid = 12345 if os.geteuid() == 0 else os.getgid()
        os.chown(deploy.CONFIG, -1, old_gid)
        deploy.CONFIG.chmod(0o640)
        new_binary = self.root / 'new-binary'
        new_binary.write_bytes(b'new binary')
        with mock.patch.object(deploy, 'run', side_effect=self.fake_run), \
                mock.patch.object(deploy, 'atomic_write', wraps=deploy.atomic_write) as writes, \
                self.assertRaises(subprocess.CalledProcessError):
            deploy.apply_install(new_binary, b'new config', b'new state',
                                 deploy.Identity('relay.example.com', 443, 'iphone', PASSWORD), automated_cert=True)
        config_writes = [call for call in writes.call_args_list if call.args[0] == deploy.CONFIG]
        self.assertEqual(config_writes[-1].args[3:5], (old_gid, os.getuid()),
                         'rollback must explicitly restore ownership even when the test user has only one group')
        for path, contents in old_files.items():
            self.assertEqual(path.read_bytes(), contents)
        self.assertEqual(deploy.CONFIG.stat().st_gid, old_gid, 'the service must still be able to read its config')
        self.assertEqual(deploy.CONFIG.stat().st_mode & 0o777, 0o640)
        self.assertFalse(deploy.SYSCTL.exists())
        self.assertFalse(deploy.HOOK.exists())
        self.assertIn(['systemctl', 'start', 'network-relay'], self.calls)

    def test_staged_tls_validation_accepts_both_toml_quote_styles(self):
        original = b"[tls]\ncert = '/old/cert.pem' # administrator comment\nkey = '/old/key.pem'\n[debug]\nlog_requests = true\n"
        updated = deploy.retarget_tls(original, (Path('/old/cert.pem'), Path('/old/key.pem')),
                                      (Path('/staged/cert.pem'), Path('/staged/key.pem')))
        parsed = tomllib.loads(updated.decode())
        self.assertEqual(parsed['tls'], {'cert': '/staged/cert.pem', 'key': '/staged/key.pem'})
        self.assertTrue(parsed['debug']['log_requests'])

    @unittest.skipUnless(BINARY.exists(), 'run cargo build first')
    def test_profile_generation_failure_never_installs_an_unrecoverable_account(self):
        self.certificates()
        def fail_profile(args, **kwargs):
            if len(args) > 1 and args[1] == 'profile':
                raise subprocess.CalledProcessError(1, args)
            return self.fake_run(args, **kwargs)
        with mock.patch.object(deploy, 'run', side_effect=fail_profile), redirect_stdout(io.StringIO()), \
                self.assertRaises(subprocess.CalledProcessError):
            deploy.install(self.args())
        self.assertFalse(deploy.CONFIG.exists())
        self.assertFalse(deploy.BINARY.exists())
        self.assertFalse(any(c[:2] == ['systemctl', 'restart'] for c in self.calls))

    def test_failed_install_restores_an_existing_profile_and_its_ownership(self):
        self.fail_restart = True
        binary = self.root / 'candidate'
        binary.write_bytes(b'new binary')
        path = self.root / 'device.mobileconfig'
        deploy.atomic_write(path, b'old profile', 0o640)
        with mock.patch.object(deploy, 'run', side_effect=self.fake_run), self.assertRaises(subprocess.CalledProcessError):
            deploy.apply_install(binary, b'new config', b'new state',
                                 deploy.Identity('relay.example.com', 443, 'iphone', PASSWORD), automated_cert=False,
                                 profile=(path, b'new profile', None, None))
        self.assertEqual(path.read_bytes(), b'old profile')
        self.assertEqual(path.stat().st_mode & 0o777, 0o640)

    def test_failed_fresh_install_removes_new_files_and_disables_unit(self):
        self.fail_restart = True
        new_binary = self.root / 'new-binary'
        new_binary.write_bytes(b'new binary')
        cert = deploy.TLS / 'fullchain.pem'
        key = deploy.TLS / 'privkey.pem'
        deploy.atomic_write(cert, b'old cert', 0o640)
        deploy.atomic_write(key, b'old key', 0o640)
        with mock.patch.object(deploy, 'run', side_effect=self.fake_run), self.assertRaises(subprocess.CalledProcessError):
            deploy.apply_install(new_binary, b'new config', b'new state',
                                 deploy.Identity('relay.example.com', 443, 'iphone', PASSWORD), automated_cert=True,
                                 certificates={cert: (b'new cert', 0o640, os.getgid()),
                                               key: (b'new key', 0o640, os.getgid())})
        self.assertEqual(cert.read_bytes(), b'old cert')
        self.assertEqual(key.read_bytes(), b'old key')
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
            deploy.apply_install(new_binary, b'new config', b'new state',
                                 deploy.Identity('relay.example.com', 443, 'iphone', PASSWORD), automated_cert=True)
        self.assertFalse(deploy.CONFIG.exists())
        self.assertFalse(deploy.BINARY.exists())
        self.assertIn(['systemctl', 'stop', 'network-relay'], self.calls)


GFWLIST = """[AutoProxy 0.2.9]
! comment
||Example.COM
||blocked.example/some/path
|https://www.site.example/x
|http://192.0.2.31/
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
    def test_proxy_payload_and_registered_roots(self):
        domains = global_profile.extract_proxy_domains(
            "payload:\n  - '+.cdn.google.com'\n  - 'api.google.com'\n  - '+.google.com'\n  - '+.adult'\n")
        suffixes = (ROOT / 'deploy/domains/public-suffix-icann.dat').read_text()
        roots = global_profile.root_domains(domains + ['api.example.co.uk', 'www.city.kawasaki.jp',
                                         'openaiassets.blob.core.windows.net', 'foo.github.io'], suffixes)
        self.assertEqual(roots, ['adult', 'city.kawasaki.jp', 'example.co.uk', 'github.io', 'google.com', 'windows.net'])
        with self.assertRaises(ValueError):
            global_profile.extract_proxy_domains("payload:\n  - 'DOMAIN-KEYWORD,google'\n")

    def test_domain_downloads_have_a_byte_limit(self):
        with mock.patch.object(global_profile, 'MAX_LIST_BYTES', 64):
            self.assertEqual(global_profile.read_bounded(io.BytesIO(b'x' * 64)), b'x' * 64)
            with self.assertRaises(ValueError):
                global_profile.read_bounded(io.BytesIO(b'x' * 65))

    def test_empty_service_selection_never_generates_an_all_traffic_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            services = Path(directory) / 'services.txt'
            out = Path(directory) / 'original.mobileconfig'
            out.write_bytes(b'previous profile')
            for content in ['# no valid services\n', 'relay.example.com\n']:
                services.write_text(content)
                with mock.patch.object(global_profile.subprocess, 'run') as generate:
                    with self.assertRaises(ValueError):
                        global_profile.main(['--host', 'relay.example.com', '--user', 'iphone',
                            '--password', PASSWORD, '--binary', str(BINARY), '--no-gfwlist', '--services', str(services),
                            '--out', str(out)])
                    generate.assert_not_called()
                self.assertEqual(out.read_bytes(), b'previous profile')

    def test_gfwlist_rules_become_domains_and_the_rest_is_counted(self):
        domains, stats = global_profile.extract_gfwlist(GFWLIST)
        self.assertEqual(domains, ['bare.example', 'blocked.example', 'dotted.example', 'example.com',
                                   'sub.example.com', 'www.site.example'])
        self.assertEqual(stats['exception rules ignored'], 1)
        self.assertEqual(stats['regular expressions dropped'], 1)
        self.assertEqual(stats['path-limited rules widened to their domain'], 2)
        self.assertEqual(global_profile.collapse(domains), [d for d in domains if d != 'sub.example.com'])
        self.assertEqual(global_profile.collapse(['com', 'google.com', 'mail.google.com', 'example.org']),
                         ['com', 'example.org'])

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
            self.assertIs(payload['UIToggleEnabled'], True, 'the user can switch off a relay that is down')
            relay = payload['Relays'][0]
            self.assertTrue(relay['HTTP3RelayURL'].startswith('https://relay.example.com/.well-known/masque/udp/'))
            basic = relay['AdditionalHTTPHeaderFields']['Authorization'].split()[1]
            self.assertEqual(base64.b64decode(basic).decode(), 'iphone:' + PASSWORD)


deploy_run = deploy.run

if __name__ == '__main__':
    unittest.main()
