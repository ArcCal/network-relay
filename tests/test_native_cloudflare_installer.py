"""Regression tests for install-network-relay-native-build-cloudflare-dns.sh.

Only installer shell functions are sourced. Terminal reads are redirected to a
pipe in a private copy, and socket inspection is stubbed, so nothing is
installed or stopped. These are control-flow checks, not a deployment test.
"""

import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / 'install-network-relay-native-build-cloudflare-dns.sh'
TOKEN = 'A' * 20 + 'b' * 10 + '0123456789'
SAVED = 'cfut_' + 'S' * 40


def own_service_unit():
    """The systemd service whose cgroup this process is in, if any.

    Processes a test starts inherit it. The installer never stops a relay
    that another service unit supervises, so under a CI runner's service the
    test's own stand-in relays would count as another unit's.
    """
    try:
        lines = Path('/proc/self/cgroup').read_text().splitlines()
    except OSError:
        return None
    group = next((line[3:] for line in lines if line.startswith('0::')), '')
    units = [part for part in group.split('/') if part.endswith('.service')]
    return units[-1][:-len('.service')] if units else None


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

    @unittest.skipUnless(os.geteuid() == 0, 'requires a root-owned saved token')
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
        self.assertIn('No safe saved renewal token', result.stderr)
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

    def test_unsafe_or_linked_dedicated_directories_are_refused_not_adopted(self):
        # Content of a directory another account could write may be planted;
        # a top-level chmod would adopt it, so the preflight check refuses it.
        loose = self.base / 'loose'
        loose.mkdir()
        os.chmod(loose, 0o777)
        link = self.base / 'etc-link'
        link.symlink_to(self.outside)
        os.chmod(self.outside, 0o777)
        for path in (loose, link):
            result = self.shell('nr_check_leaf "$1" rootdir', str(path))
            self.assertNotEqual(result.returncode, 0, path)
        self.assertEqual(loose.stat().st_mode & 0o777, 0o777, 'refusal must not change the directory')
        self.assertEqual(self.outside.stat().st_mode & 0o777, 0o777, 'a link target must be untouched')

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

    def test_account_in_use_is_repaired_and_its_home_change_deferred(self):
        # A process runs as the account, as the old relay does during an
        # upgrade. Some shadow-utils versions refuse a home change then, and
        # the change waits until the old relay stops; others make it at once.
        # Either way the run must not abort and the account is repaired.
        name = f'nrbusy{os.getpid() % 100000}'
        subprocess.run(['useradd', '--system', '--user-group', '--shell', '/bin/bash', '--home-dir',
                        f'/var/lib/{name}', '--groups', 'adm', name], check=True)
        process = subprocess.Popen(['sleep', '60'], user=name)
        try:
            result = subprocess.run(['bash', '-c', 'source "$1"; SERVICE="$2"; nr_account && '
                                     'echo "repaired pending=$account_home_pending"', 'test', str(SCRIPT), name],
                                    capture_output=True, text=True, timeout=60)
            self.assertRegex(result.stdout, r'repaired pending=[01]\n', result.stderr)
            deferred = 'repaired pending=1' in result.stdout
            entry = subprocess.run(['getent', 'passwd', name], capture_output=True, text=True).stdout.strip()
            home = f'/var/lib/{name}' if deferred else '/nonexistent'
            self.assertTrue(entry.endswith(f':{home}:/usr/sbin/nologin'), entry)
            groups = subprocess.run(['id', '-Gn', name], capture_output=True, text=True).stdout.split()
            self.assertEqual(groups, [name])
            process.kill()
            process.wait()
            # After the previous instances stop, the deferred change succeeds.
            result = subprocess.run(['bash', '-c', 'source "$1"; SERVICE="$2"; nr_account && '
                                     'echo "repaired pending=$account_home_pending"', 'test', str(SCRIPT), name],
                                    capture_output=True, text=True, timeout=60)
            self.assertIn('repaired pending=0', result.stdout, result.stderr)
            entry = subprocess.run(['getent', 'passwd', name], capture_output=True, text=True).stdout.strip()
            self.assertTrue(entry.endswith(':/nonexistent:/usr/sbin/nologin'), entry)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
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

    def shell(self, command, *args, service=None):
        # The stand-in relays run in this test's cgroup: make its service, if
        # any, the deployment's own, as the installed relay's would be.
        service = service or own_service_unit() or 'network-relay'
        return subprocess.run(['bash', '-c', 'source "$1"; BIN="$2"; CONFIG="$3"; SERVICE="$4"; shift 4; ' + command,
                               'test', str(SCRIPT), str(self.binary), self.config, service, *args],
                              capture_output=True, text=True, timeout=60)

    def identified(self, process):
        return self.shell('nr_is_relay_pid "$1"', str(process.pid)).returncode == 0

    def test_only_exact_executable_and_managed_config_are_positive(self):
        for args in (['serve', '--config', self.config], ['serve', '-c', self.config],
                     ['serve', '--config=' + self.config], ['serve', '-c' + self.config]):
            self.assertTrue(self.identified(self.start(*args)), args)
        # A bare `serve` uses clap's default path, which is only this
        # deployment when CONFIG is that default.
        bare = self.start('serve')
        self.assertFalse(self.identified(bare))
        result = self.shell('CONFIG=/etc/network-relay/relay.toml; nr_is_relay_pid "$1"', str(bare.pid))
        self.assertEqual(result.returncode, 0)
        other = self.base / 'copy' / 'network-relay'
        other.parent.mkdir()
        other.write_bytes(self.binary.read_bytes())
        other.chmod(0o755)
        for args, binary in ((['serve', '--check'], None), (['serve', '--config', '/etc/other.toml'], None),
                             (['serve', '--config', self.config, '--config', self.config], None),
                             (['serve', '-c=' + self.config], None), (['passwd'], None),
                             (['serve', '--config', self.config], other)):
            self.assertFalse(self.identified(self.start(*args, binary=binary)), (args, binary))

    @unittest.skipUnless(os.geteuid() == 0, 'creating a mount namespace requires root')
    def test_process_in_another_mount_namespace_is_never_identified(self):
        # A container shows its own path in /proc/PID/exe; identical path and
        # argv must not make another deployment's relay a takeover target.
        process = subprocess.Popen(['unshare', '-m', '--propagation', 'private', str(self.binary),
                                    'serve', '--config', self.config])
        self.processes.append(process)
        for _ in range(50):
            if os.readlink(f'/proc/{process.pid}/ns/mnt') != os.readlink('/proc/self/ns/mnt'):
                break
            time.sleep(0.02)
        self.assertFalse(self.identified(process))
        result = self.shell('nr_stop_standalone && echo none')
        self.assertIn('none', result.stdout)
        self.assertIsNone(process.poll(), 'a process in another namespace must never be signalled')

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

    @unittest.skipUnless(own_service_unit(), 'needs to run inside a systemd service cgroup, as CI runners do')
    def test_relay_supervised_by_another_service_unit_is_never_identified(self):
        process = self.start('serve', '--config', self.config)
        result = self.shell('nr_is_relay_pid "$1"', str(process.pid), service='another-relay-deployment')
        self.assertNotEqual(result.returncode, 0, 'a relay under another service unit belongs to that unit')

    def test_takeover_stops_identified_instances_and_spares_others(self):
        ours = self.start('serve', '--config', self.config)
        foreign = self.start('serve', '--config', '/etc/other.toml')
        result = self.shell('nr_stop_standalone && echo stopped')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Sent TERM', result.stdout)
        self.assertIsNotNone(ours.wait(timeout=5))
        self.assertIsNone(foreign.poll(), 'an unidentified process must never be signalled')


class AptLockRetryTests(unittest.TestCase):
    def apt(self, script):
        command = ('sleep() { echo slept >&2; }; attempts=0; apt-get() { attempts=$((attempts+1)); ' + script +
                   '; }; nr_apt update; echo "status=$? attempts=$attempts"')
        return run(command)

    def test_held_list_lock_is_retried_until_free(self):
        result = self.apt('if (( attempts < 3 )); then echo "E: Could not get lock /var/lib/apt/lists/lock. '
                          'It is held by process 1 (apt-get)" >&2; return 100; fi; return 0')
        self.assertIn('status=0 attempts=3', result.stdout, result.stderr)
        self.assertEqual(result.stderr.count('slept'), 2)

    def test_other_failures_are_not_retried(self):
        result = self.apt('echo "E: Unable to locate package nonexistent" >&2; return 100')
        self.assertIn('status=100 attempts=1', result.stdout)
        self.assertNotIn('slept', result.stderr)


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

    def test_ctrl_c_to_the_process_group_does_not_stop_the_certificate_request(self):
        with tempfile.TemporaryDirectory() as work:
            # The outer shell HANDLES INT (a handler is not inherited, unlike
            # an ignored signal), so only the job's own disposition protects it.
            command = ('work="$1"; nr_prepare_certificate() { sleep 1; echo issued; }; '
                       'nr_certificate_job & certificate_job=$!; sleep 0.3; kill -INT -- -$$; '
                       'status=129; while (( status > 128 )) && kill -0 "$certificate_job" 2>/dev/null; do '
                       'wait "$certificate_job"; status=$?; done; cat "$work/certificate.log"')
            result = subprocess.run(['setsid', 'bash', '-c', 'trap : INT; source "$1"; shift; ' + command, 'test',
                                     str(SCRIPT), work], capture_output=True, text=True, timeout=30)
            self.assertIn('issued', result.stdout, result.stderr)

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


class BuildMemoryTests(unittest.TestCase):
    """The build was measured under memory caps; see nr_check_build_memory."""

    def check(self, available, swap, cgroups='', groups=None):
        """`groups` maps a cgroup directory, relative to a fake mount, to its
        files; `cgroups` is /proc/self/cgroup. No cgroups by default, so the
        machine running the tests does not matter."""
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            meminfo = base / 'meminfo'
            meminfo.write_text(f'MemTotal: 4000000 kB\nMemAvailable: {available} kB\nSwapFree: {swap} kB\n')
            (base / 'self-cgroup').write_text(cgroups)
            mounts = []
            for kind, options in (('cgroup2', 'rw'), ('cgroup', 'rw,memory')):
                mount = base / kind
                mount.mkdir()
                mounts.append(f'30 25 0:26 / {mount} rw,nosuid - {kind} {kind} {options}\n')
            (base / 'mountinfo').write_text(''.join(mounts))
            for relative, files in (groups or {}).items():
                folder = base / relative
                folder.mkdir(parents=True, exist_ok=True)
                for name, value in files.items():
                    (folder / name).write_text(f'{value}\n')
            return subprocess.run(['bash', '-c', 'source "$1"; nr_check_build_memory "$2" "$3" "$4" && echo accepted',
                                   'test', str(SCRIPT), str(meminfo), str(base / 'self-cgroup'), str(base / 'mountinfo')],
                                  capture_output=True, text=True, timeout=30)

    def test_too_little_memory_is_refused_with_advice(self):
        result = self.check(1048576 - 1, 0)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('1 GiB of available memory plus free swap', result.stderr)

    def test_exact_threshold_is_accepted(self):
        self.assertIn('accepted', self.check(1048576, 0).stdout)

    def test_free_swap_counts_toward_the_requirement(self):
        self.assertIn('accepted', self.check(1048576 // 2, 1048576 // 2).stdout)

    # A container or systemd unit with a memory limit caps the build below
    # what the host's /proc/meminfo reports.
    def test_a_cgroup_v2_limit_below_the_requirement_is_refused(self):
        groups = {'cgroup2/system.slice': {'memory.max': 'max'},
                  'cgroup2/system.slice/install.scope': {'memory.max': 512 << 20, 'memory.current': 8 << 20,
                                                         'memory.stat': 'inactive_file 0', 'memory.swap.max': 0}}
        result = self.check(4000000, 0, '0::/system.slice/install.scope\n', groups)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('memory limit on this container or service', result.stderr)

    def test_a_limit_on_an_ancestor_cgroup_counts(self):
        groups = {'cgroup2/lxc': {'memory.max': 768 << 20, 'memory.current': 0, 'memory.stat': 'inactive_file 0'},
                  'cgroup2/lxc/c1': {'memory.max': 'max'}}
        self.assertNotEqual(self.check(4000000, 0, '0::/lxc/c1\n', groups).returncode, 0)

    def test_reclaimable_cache_and_allowed_swap_count_within_a_limit(self):
        # 768 MiB limit, 400 MiB used of which 300 MiB is inactive file cache,
        # plus 512 MiB of the cgroup's swap allowance: about 1.15 GiB.
        group = {'memory.max': 768 << 20, 'memory.current': 400 << 20, 'memory.stat': f'inactive_file {300 << 20}',
                 'memory.swap.max': 512 << 20, 'memory.swap.current': 0}
        self.assertIn('accepted', self.check(4000000, 2 << 20, '0::/svc\n', {'cgroup2/svc': group}).stdout)
        # Host swap that the cgroup may not use does not count.
        group['memory.swap.max'] = 0
        self.assertNotEqual(self.check(4000000, 2 << 20, '0::/svc\n', {'cgroup2/svc': group}).returncode, 0)

    def test_a_cgroup_v1_limit_counts_and_unlimited_is_ignored(self):
        limited = {'memory.limit_in_bytes': 512 << 20, 'memory.usage_in_bytes': 0, 'memory.stat': 'total_inactive_file 0'}
        result = self.check(4000000, 0, '4:memory:/docker/c1\n', {'cgroup/docker/c1': limited})
        self.assertNotEqual(result.returncode, 0)
        unlimited = dict(limited, **{'memory.limit_in_bytes': 9223372036854771712})
        self.assertIn('accepted', self.check(4000000, 0, '4:memory:/docker/c1\n', {'cgroup/docker/c1': unlimited}).stdout)

    def test_a_roomy_cgroup_leaves_the_host_figure_in_charge(self):
        group = {'memory.max': 8 << 30, 'memory.current': 0, 'memory.stat': 'inactive_file 0'}
        self.assertIn('accepted', self.check(1048576, 0, '0::/svc\n', {'cgroup2/svc': group}).stdout)
        self.assertNotEqual(self.check(1048576 - 1, 0, '0::/svc\n', {'cgroup2/svc': group}).returncode, 0)

    def test_check_precedes_packages_and_the_build(self):
        text = SCRIPT.read_text()
        body = text[text.index('nr_main() {'):]
        positions = [body.index(marker) for marker in ('nr_check_build_memory', '"${apt[@]}" update', 'nr_certificate_job &', 'nr_build "$jobs"')]
        self.assertEqual(positions, sorted(positions))



class WebsiteAndServicePreflightTests(unittest.TestCase):
    """Isolated source-level regression checks; never mutate host services."""

    def test_website_access_is_checked_before_packages_and_build(self):
        script = SCRIPT.read_text()
        main = script[script.index('nr_main() {'):]
        self.assertLess(main.index('nr_preflight_web_access'), main.index('"\u0024{apt[@]}" update'))
        self.assertLess(main.index('nr_preflight_web_access'), main.index('nr_build "\u0024jobs"'))
        deploy = script[script.index('nr_deploy() {'):script.index('\n}\n', script.index('nr_deploy() {'))]
        self.assertLess(deploy.index('nr_check_web_access'), deploy.index('nr_prepare\n'))
        self.assertIn('nr_prepare_log', deploy)
        self.assertIn('runuser -u "\u0024SERVICE" -- "\u0024BIN" --version', deploy)

    def test_unreadable_site_index_fails_without_chmodding_shared_parents(self):
        with tempfile.TemporaryDirectory() as folder:
            website = Path(folder) / 'site'
            website.mkdir()
            (website / 'index.html').write_text('hello')
            command = (
                'SERVICE=nobody; WWW="\u00241"; '
                'runuser() { [[ "\u0024*" != *index.html* ]]; }; '
                'nr_check_web_access'
            )
            result = subprocess.run(
                ['bash', '-c', 'source "\u00241"; shift; ' + command, 'test', str(SCRIPT), str(website)],
                capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('cannot read', result.stderr.lower())

    def test_untrusted_log_symlink_is_rejected_before_ownership_changes(self):
        with tempfile.TemporaryDirectory() as folder:
            logs = Path(folder)
            (logs / 'network-relay.log').symlink_to(logs / 'secret')
            command = (
                'SERVICE=network-relay; LOGS="\u00241"; '
                'nr_check_leaf() { :; }; '
                'install() { :; }; '
                'nr_prepare_log'
            )
            result = subprocess.run(
                ['bash', '-c', 'source "\u00241"; shift; ' + command, 'test', str(SCRIPT), str(logs)],
                capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Unsafe managed log entry', result.stderr)

    def test_service_start_failure_collects_diagnostics_before_rollback(self):
        script = SCRIPT.read_text()
        deploy = script[script.index('nr_deploy() {'):script.index('\n}\n', script.index('nr_deploy() {'))]
        self.assertIn('if ! systemctl start "\u0024SERVICE"; then\n        nr_service_diagnostics', deploy)
        self.assertIn('nr_die \'Candidate could not start; restoring the previous deployment.\'', deploy)

if __name__ == '__main__':
    unittest.main()
