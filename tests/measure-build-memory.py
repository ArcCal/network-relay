#!/usr/bin/env python3
"""Measure how much memory the native installer build needs.

Each run sources install-network-relay-native-build-cloudflare-dns.sh and calls
its own nr_host and nr_build 1 in a fresh private work directory, so toolchain
downloads, environment scrubbing and build flags match a real installation.

Without --cap, the build runs unconstrained and the peak memory of its process
tree is sampled. With one or more --cap MIB values, each build runs in a
memory-limited cgroup without swap and the result shows whether it completed or
was OOM-killed. The threshold in nr_check_build_memory was chosen from such
capped runs; repeat them after toolchain or dependency changes, e.g.:

    sudo python3 -I tests/measure-build-memory.py --cap 768 --cap 896

Requires root on a Debian 12+/Ubuntu 24.04+ host, Internet access to the
toolchain and crate sources, and about 5 GiB of free disk per run. Capped runs
use a cgroup v1 memory child directory, or systemd-run on cgroup v2 hosts.
Nothing is installed: only the private work directory is written and removed.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / 'install-network-relay-native-build-cloudflare-dns.sh'
BUILD = ('set -Eeuo pipefail; source "$1"; export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C; '
         'nr_host; work=$2; nr_build 1')
# Proxy and CA settings that downloads may need inside a transient systemd unit.
FORWARDED = ('http_proxy', 'https_proxy', 'no_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY',
             'SSL_CERT_FILE', 'SSL_CERT_DIR', 'CURL_CA_BUNDLE')


def build_command(work):
    return ['bash', '-c', BUILD, 'measure', str(INSTALLER), str(work)]


def children(pid):
    found = []
    try:
        for task in os.listdir(f'/proc/{pid}/task'):
            with open(f'/proc/{pid}/task/{task}/children') as stream:
                found += [int(value) for value in stream.read().split()]
    except OSError:
        pass
    return found


def usage(pid):
    """Return (PSS KiB, RSS KiB, name) for one process, zeros if it exited."""
    try:
        with open(f'/proc/{pid}/smaps_rollup') as stream:
            fields = {line.split()[0]: int(line.split()[1]) for line in stream
                      if line.split()[0] in ('Rss:', 'Pss:')}
        with open(f'/proc/{pid}/comm') as stream:
            return fields.get('Pss:', 0), fields.get('Rss:', 0), stream.read().strip()
    except (OSError, ValueError, IndexError):
        return 0, 0, ''


def sampled(work, log):
    """Run unconstrained, sampling the whole process tree every 0.2 seconds."""
    with open(log, 'w') as output:
        process = subprocess.Popen(build_command(work), stdout=output, stderr=subprocess.STDOUT)
        peak_pss = peak_rss = largest = 0
        largest_name = ''
        while process.poll() is None:
            pending, total_pss, total_rss = [process.pid], 0, 0
            while pending:
                pid = pending.pop()
                pss, rss, name = usage(pid)
                total_pss, total_rss = total_pss + pss, total_rss + rss
                if rss > largest:
                    largest, largest_name = rss, name
                pending += children(pid)
            peak_pss, peak_rss = max(peak_pss, total_pss), max(peak_rss, total_rss)
            time.sleep(0.2)
    return (process.returncode, f'peak tree PSS {peak_pss // 1024} MiB, peak tree RSS {peak_rss // 1024} MiB, '
            f'largest process RSS {largest // 1024} MiB ({largest_name})')


def memory_v1_base():
    for line in Path('/proc/self/cgroup').read_text().splitlines():
        _, controllers, path = line.split(':', 2)
        if 'memory' in controllers.split(','):
            base = Path('/sys/fs/cgroup/memory') / path.lstrip('/')
            return base if base.is_dir() else None
    return None


def capped_v1(base, limit, work, log):
    group = base / f'measure-build-{os.getpid()}-{limit}'
    group.mkdir()
    try:
        (group / 'memory.limit_in_bytes').write_text(str(limit * 1024 * 1024))
        swap = group / 'memory.memsw.limit_in_bytes'
        if swap.exists():
            swap.write_text(str(limit * 1024 * 1024))
        procs = str(group / 'cgroup.procs')

        def enter():
            with open(procs, 'w') as stream:
                stream.write(str(os.getpid()))

        with open(log, 'w') as output:
            status = subprocess.run(build_command(work), stdout=output, stderr=subprocess.STDOUT,
                                    preexec_fn=enter).returncode
        events = dict(line.split() for line in (group / 'memory.oom_control').read_text().splitlines())
        return status, int(events.get('oom_kill', 0)) > 0
    finally:
        group.rmdir()


def capped_systemd(limit, work, log):
    command = ['systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--service-type=exec',
               f'--property=MemoryMax={limit}M', '--property=MemorySwapMax=0', '--property=OOMPolicy=continue']
    command += [f'--setenv={name}={os.environ[name]}' for name in FORWARDED if name in os.environ]
    with open(log, 'w') as output:
        result = subprocess.run(command + build_command(work), stdout=output, stderr=subprocess.PIPE, text=True)
        output.write(result.stderr)
    return result.returncode, 'oom-kill' in result.stderr


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--cap', type=int, action='append', metavar='MIB',
                        help='run the build under this memory cap without swap; repeat for several caps')
    parser.add_argument('--work-root', default='/var/tmp', help='parent of the private work directories')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run as root: the build and memory cgroups require it.')
    base = memory_v1_base() if args.cap else None
    if args.cap and base is None and not shutil.which('systemd-run'):
        raise SystemExit('Capped runs need a cgroup v1 memory controller or systemd-run.')
    failed = False
    for limit in args.cap or [None]:
        if limit is not None and limit < 64:
            raise SystemExit('Caps below 64 MiB are not meaningful.')
        work = Path(tempfile.mkdtemp(prefix='network-relay-measure.', dir=args.work_root))
        log = work.with_name(work.name + '.log')
        start = time.monotonic()
        try:
            if limit is None:
                status, detail = sampled(work, log)
                label = 'uncapped'
            else:
                status, oom = capped_v1(base, limit, work, log) if base else capped_systemd(limit, work, log)
                detail = 'OOM-killed' if oom else ('built' if status == 0 else 'failed (not OOM; see the log)')
                label = f'cap {limit} MiB'
        finally:
            shutil.rmtree(work, ignore_errors=True)
        failed = failed or (status != 0 and not (limit is not None and oom))
        print(f'{label}: exit {status}, {time.monotonic() - start:.0f} s, {detail}; log {log}', flush=True)
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
