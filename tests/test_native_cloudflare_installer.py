"""Regression tests for install-network-relay-native-build-cloudflare-dns.sh.

Only installer shell functions are sourced. Terminal reads are redirected to a
pipe in a private copy, and socket inspection is stubbed, so nothing is
installed or stopped. These are control-flow checks, not a deployment test.
"""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / 'install-network-relay-native-build-cloudflare-dns.sh'
TOKEN = 'A' * 20 + 'b' * 10 + '0123456789'
SAVED = 'cfut_' + 'S' * 40


def run(command, data='', script=SCRIPT, env=None):
    return subprocess.run(['bash', '-c', 'source "$1"; shift; ' + command, 'test', str(script)],
                          input=data, capture_output=True, text=True, env=env, timeout=30)


class DomainTests(unittest.TestCase):
    def test_hostnames_including_punycode_tlds_are_accepted(self):
        for value in ('relay.example.com', 'a-b.example.org', 'relay.example.xn--p1ai', 'relay.xn--80ao21a'):
            result = subprocess.run(['bash', '-c', 'source "$1"; nr_domain "$2"', 'test', str(SCRIPT), value])
            self.assertEqual(result.returncode, 0, value)

    def test_addresses_urls_wildcards_and_bad_labels_are_rejected(self):
        for value in ('10.0.0.1', 'relay.example.123', 'relay.example.xn--', 'relay.example.xn---', '*.example.com',
                      'https://relay.example.com', 'example', 'relay..example.com', '-relay.example.com',
                      'relay.example.c', 'relay.example.com:443', 'relay.exa"mple.com'):
            result = subprocess.run(['bash', '-c', 'source "$1"; nr_domain "$2"', 'test', str(SCRIPT), value])
            self.assertNotEqual(result.returncode, 0, value)


class TokenInputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        # Feed the two terminal reads from stdin; everything else is unchanged.
        text = SCRIPT.read_text().replace('</dev/tty', '')
        self.script = self.base / 'installer.sh'
        self.script.write_text(text)
        self.certs = self.base / 'letsencrypt'
        self.certs.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def inputs(self, data, saved=None):
        if saved is not None:
            path = self.certs / 'network-relay-cloudflare-relay.example.com.ini'
            path.write_text(saved)
            path.chmod(0o600)
        # The real dedicated-path check is exercised separately as root.
        command = ('nr_check_parent_dirs() { printf "checked:parents:%s\\n" "$1" >&2; }; CERT_ROOT="$1"; cf_token=; '
                   'nr_inputs; if [[ $cf_token == "$2" ]]; then echo token-selected; fi')
        return subprocess.run(['bash', '-c', 'source "$1"; shift; ' + command, 'test', str(self.script),
                               str(self.certs), SAVED], input=data, capture_output=True, text=True, timeout=30)

    def test_enter_reuses_the_checked_saved_renewal_token(self):
        result = self.inputs('relay.example.com\n\n', f'dns_cloudflare_api_token = {SAVED}\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('token-selected', result.stdout)
        # Bash prints read -p prompts only for terminal input, so the prompt
        # wording is not observable through this pipe.
        self.assertIn('checked:parents:', result.stderr)
        self.assertNotIn(SAVED, result.stdout + result.stderr)

    def test_typed_token_takes_precedence_over_saved_token(self):
        result = self.inputs(f'relay.example.com\n{TOKEN}\n', f'dns_cloudflare_api_token = {SAVED}\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('token-selected', result.stdout)
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_enter_without_saved_token_fails(self):
        result = self.inputs('relay.example.com\n\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('No safe saved renewal token', result.stderr)

    def test_malformed_saved_token_is_not_used(self):
        result = self.inputs('relay.example.com\n\n', 'dns_cloudflare_api_token = bad token\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Expected a Cloudflare API Token', result.stderr)
        self.assertNotIn('bad token', result.stdout + result.stderr)

    def real_inputs(self, mode, owner=0, link=False):
        with tempfile.TemporaryDirectory(dir='/root') as private:
            certs = Path(private) / 'letsencrypt'
            certs.mkdir(mode=0o700)
            path = certs / 'network-relay-cloudflare-relay.example.com.ini'
            source = certs / 'elsewhere.ini' if link else path
            source.write_text(f'dns_cloudflare_api_token = {SAVED}\n')
            source.chmod(mode)
            os.chown(source, owner, owner)
            if link:
                path.symlink_to(source)
            command = 'CERT_ROOT="$1"; cf_token=; nr_inputs; if [[ $cf_token == "$2" ]]; then echo token-selected; fi'
            return subprocess.run(['bash', '-c', 'source "$1"; shift; ' + command, 'test', str(self.script),
                                   str(certs), SAVED], input='relay.example.com\n\n', capture_output=True, text=True)

    @unittest.skipUnless(os.geteuid() == 0, 'the real dedicated-path check requires root-owned parents')
    def test_loose_mode_saved_token_is_reused_and_reported(self):
        result = self.real_inputs(0o640)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('token-selected', result.stdout)
        self.assertIn('rewritten root-only', result.stderr)
        self.assertNotIn(SAVED, result.stderr)

    @unittest.skipUnless(os.geteuid() == 0, 'creating a foreign-owned file requires root')
    def test_foreign_owned_or_linked_saved_token_is_never_read(self):
        for kwargs in ({'mode': 0o600, 'owner': 65534}, {'mode': 0o600, 'link': True}):
            result = self.real_inputs(**kwargs)
            self.assertNotEqual(result.returncode, 0, kwargs)
            self.assertNotIn('token-selected', result.stdout)
            self.assertNotIn(SAVED, result.stdout + result.stderr)


class PortRecheckTests(unittest.TestCase):
    def test_occupied_port_before_start_is_reported_not_stopped(self):
        result = run('nr_port_inodes() { echo 4242; }; nr_report_ports() { echo reported >&2; }; '
                     'systemctl() { echo "systemctl $*" >&2; }; kill() { echo killed >&2; }; nr_ports_free; echo free')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('reported', result.stderr)
        self.assertNotIn('systemctl', result.stderr)
        self.assertNotIn('killed', result.stderr)
        self.assertNotIn('free', result.stdout)

    def test_free_port_passes(self):
        result = run('nr_port_inodes() { :; }; nr_ports_free && echo free')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('free', result.stdout)

    def test_deploy_rechecks_ports_immediately_before_start(self):
        text = SCRIPT.read_text()
        body = text[text.index('nr_deploy() {'):text.index('\n}\n', text.index('nr_deploy() {'))]
        enable = body.index('systemctl enable "$SERVICE"')
        start = body.index('systemctl start "$SERVICE"')
        self.assertIn('nr_ports_free', body[enable:start])


@unittest.skipUnless(os.geteuid() == 0, 'dedicated-path checks require root-owned parents')
class SameNameRepairTests(unittest.TestCase):
    """Real files under a private root-owned directory; nothing outside it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir='/root')
        self.base = Path(self.tmp.name)
        self.outside = self.base / 'unrelated'
        self.outside.mkdir()
        (self.outside / 'data').write_text('keep')

    def tearDown(self):
        self.tmp.cleanup()

    def shell(self, command, *args):
        return subprocess.run(['bash', '-c', 'source "$1"; shift; ' + command, 'test', str(SCRIPT), *args],
                               capture_output=True, text=True, timeout=30)

    def test_symlinked_or_misplaced_files_are_replaced_without_writing_through(self):
        source = self.base / 'new'
        source.write_text('new')
        linked = self.base / 'linked'
        linked.symlink_to(self.outside / 'data')
        directory = self.base / 'was-directory'
        directory.mkdir()
        (directory / 'inside').write_text('old')
        for destination in (linked, directory):
            result = self.shell('nr_atomic_install "$1" "$2" 644', str(source), str(destination))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(destination.is_symlink())
            self.assertEqual(destination.read_text(), 'new')
        self.assertEqual((self.outside / 'data').read_text(), 'keep', 'a link target must never be written')
        aside = [p for p in self.base.iterdir() if p.name.startswith('was-directory.replaced-')]
        self.assertEqual(len(aside), 1)
        self.assertEqual((aside[0] / 'inside').read_text(), 'old', 'a displaced directory is kept, not deleted')

    def test_directories_get_only_their_own_mode_fixed_and_files_are_set_aside(self):
        loose = self.base / 'loose'
        loose.mkdir()
        (loose / 'child').mkdir(mode=0o777)
        os.chmod(loose, 0o777)
        os.chmod(loose / 'child', 0o777)
        result = self.shell('nr_repair_dir "$1" root 750', str(loose))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(loose.stat().st_mode & 0o777, 0o750)
        self.assertEqual((loose / 'child').stat().st_mode & 0o777, 0o777, 'repair must not be recursive')
        stale = self.base / 'stale'
        stale.write_text('stale')
        self.assertEqual(self.shell('nr_repair_dir "$1" root 700', str(stale)).returncode, 0)
        self.assertTrue(stale.is_dir())
        self.assertTrue(any(p.read_text() == 'stale' for p in self.base.glob('stale.replaced-*')))

    def test_symlinked_dedicated_directory_is_reported_not_followed(self):
        link = self.base / 'etc-link'
        link.symlink_to(self.outside)
        os.chmod(self.outside, 0o777)
        result = self.shell('nr_repair_dir "$1" root 750', str(link))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('symlink', result.stderr)
        self.assertEqual(self.outside.stat().st_mode & 0o777, 0o777, 'the link target must be untouched')

    def test_rollback_restores_a_directory_that_occupied_a_file_path(self):
        backup = self.base / 'backup'
        (backup / 'files/0').mkdir(parents=True)
        (backup / 'files/0/kept').write_text('old tree')
        target = self.base / 'binary'
        target.write_text('candidate')
        (backup / 'manifest').write_text(f'0\t1\tfile\t{target}\n')
        command = ('backup_dir="$1"; was_active=0; was_enabled=disabled; nr_lock_tls() { :; }; nr_unlock_tls() { :; }; '
                   'nr_unit_identity() { return 1; }; systemctl() { case "$1" in is-enabled) echo disabled;; '
                   'is-active) return 3;; esac; }; nr_rollback && echo restored')
        result = self.shell(command, str(backup))
        self.assertIn('restored', result.stdout, result.stderr)
        self.assertEqual((target / 'kept').read_text(), 'old tree')


@unittest.skipUnless(os.geteuid() == 0 and os.environ.get('NR_TEST_ACCOUNTS') == '1',
                     'creates and deletes a temporary local account; set NR_TEST_ACCOUNTS=1 in a disposable host')
class AccountRepairTests(unittest.TestCase):
    def test_login_shell_home_and_supplementary_groups_are_repaired(self):
        name = f'nrtest{os.getpid() % 100000}'
        subprocess.run(['useradd', '--system', '--user-group', '--shell', '/bin/bash', '--home-dir', '/root',
                        '--groups', 'adm', name], check=True)
        try:
            result = subprocess.run(['bash', '-c', 'source "$1"; SERVICE="$2"; nr_account && echo repaired',
                                     'test', str(SCRIPT), name], capture_output=True, text=True, timeout=60)
            self.assertIn('repaired', result.stdout, result.stderr)
            entry = subprocess.run(['getent', 'passwd', name], capture_output=True, text=True).stdout.strip()
            self.assertTrue(entry.endswith(':/nonexistent:/usr/sbin/nologin'), entry)
            groups = subprocess.run(['id', '-Gn', name], capture_output=True, text=True).stdout.split()
            self.assertEqual(groups, [name])
            self.assertEqual(os.stat('/root').st_uid, 0, 'the previous home is never chowned')
        finally:
            subprocess.run(['userdel', '-f', name], check=False)
            subprocess.run(['groupdel', name], check=False, stderr=subprocess.DEVNULL)

    def test_shared_uid_is_still_refused(self):
        name = f'nrshare{os.getpid() % 100000}'
        # Share a non-root system UID; UID 0 would make cleanup depend on root
        # processes, and a privileged leftover account must never remain.
        uid = subprocess.run(['id', '-u', 'daemon'], capture_output=True, text=True, check=True).stdout.strip()
        subprocess.run(['useradd', '--system', '--non-unique', '--uid', uid, '--user-group', name], check=True)
        try:
            result = subprocess.run(['bash', '-c', 'source "$1"; SERVICE="$2"; nr_account', 'test', str(SCRIPT), name],
                                    capture_output=True, text=True, timeout=60)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('shared by another account', result.stderr)
        finally:
            subprocess.run(['userdel', '-f', name], check=False)
            subprocess.run(['groupdel', name], check=False, stderr=subprocess.DEVNULL)


class StandaloneTakeoverTests(unittest.TestCase):
    """Real processes and /proc; a compiled sleeper stands in for the server."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        source = self.base / 'sleeper.c'
        source.write_text('#include <unistd.h>\nint main(void) { for (;;) pause(); }\n')
        self.binary = self.base / 'network-relay'
        subprocess.run(['cc', '-o', str(self.binary), str(source)], check=True)
        self.config = str(self.base / 'relay.toml')
        self.processes = []

    def tearDown(self):
        for process in self.processes:
            process.kill()
            process.wait()
        self.tmp.cleanup()

    def start(self, *args, binary=None):
        process = subprocess.Popen([str(binary or self.binary), *args])
        self.processes.append(process)
        return process

    def shell(self, command, *args):
        return subprocess.run(['bash', '-c', 'source "$1"; BIN="$2"; CONFIG="$3"; shift 3; ' + command, 'test',
                               str(SCRIPT), str(self.binary), self.config, *args], capture_output=True, text=True,
                              timeout=60)

    def identified(self, process):
        return self.shell('nr_is_relay_pid "$1"', str(process.pid)).returncode == 0

    def test_only_exact_executable_and_managed_config_are_positive(self):
        for args in (['serve'], ['serve', '--config', self.config], ['serve', '-c', self.config],
                     ['serve', '--config=' + self.config], ['serve', '-c' + self.config]):
            self.assertTrue(self.identified(self.start(*args)), args)
        other = self.base / 'copy' / 'network-relay'
        other.parent.mkdir()
        other.write_bytes(self.binary.read_bytes())
        other.chmod(0o755)
        for args, binary in ((['serve', '--check'], None), (['serve', '--config', '/etc/other.toml'], None),
                             (['serve', '--config', self.config, '--config', self.config], None),
                             (['serve', '-c=' + self.config], None), (['passwd'], None),
                             (['serve', '--config', self.config], other)):
            self.assertFalse(self.identified(self.start(*args, binary=binary)), (args, binary))

    def test_unlinked_old_binary_is_still_identified(self):
        process = self.start('serve', '--config', self.config)
        self.binary.rename(self.base / 'moved')
        self.assertFalse(self.identified(process), 'a renamed inode is not the installed path')
        (self.base / 'moved').rename(self.binary)
        replacement = self.base / 'replacement'
        replacement.write_bytes(self.binary.read_bytes())
        self.binary.unlink()
        self.assertTrue(self.identified(process), 'an upgraded-away (deleted) BIN is still this deployment')
        replacement.rename(self.binary)

    def test_takeover_stops_identified_instances_and_spares_others(self):
        ours = self.start('serve')
        foreign = self.start('serve', '--config', '/etc/other.toml')
        result = self.shell('nr_stop_standalone && echo stopped')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Sent TERM', result.stdout)
        self.assertIsNotNone(ours.wait(timeout=5))
        self.assertIsNone(foreign.poll(), 'an unidentified process must never be signalled')


class ConcurrentCertificateTests(unittest.TestCase):
    def run_job(self, body):
        with tempfile.TemporaryDirectory() as work:
            command = ('set -Eeuo pipefail; work="$1"; nr_prepare_certificate() { ' + body + '; }; '
                       'nr_certificate_job & certificate_job=$!; nr_wait_certificate; echo continued')
            result = subprocess.run(['bash', '-c', 'source "$1"; shift; ' + command, 'test', str(SCRIPT), work],
                                    capture_output=True, text=True, timeout=30)
            return result

    def test_failure_inside_the_background_job_stops_the_installer(self):
        result = self.run_job('false; echo after-failure')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('after-failure', result.stdout + result.stderr, 'errexit must apply inside the job')
        self.assertNotIn('continued', result.stdout)
        self.assertIn('Certificate preparation failed', result.stderr)

    def test_success_output_is_shown_after_the_wait(self):
        result = self.run_job('echo reused-certificate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('reused-certificate\ncontinued', result.stdout)

    def test_main_launches_certificate_work_before_the_build(self):
        text = SCRIPT.read_text()
        body = text[text.index('nr_main() {'):]
        self.assertLess(body.index('nr_certificate_job &'), body.index('nr_build "$jobs"'))
        self.assertLess(body.index('nr_build "$jobs"'), body.index('nr_wait_certificate'))
        self.assertLess(body.index('nr_wait_certificate'), body.index('nr_deploy'))
        deploy = text[text.index('nr_deploy() {'):text.index('\n}\n', text.index('nr_deploy() {'))]
        self.assertNotIn('nr_prepare_certificate', deploy)


if __name__ == '__main__':
    unittest.main()
