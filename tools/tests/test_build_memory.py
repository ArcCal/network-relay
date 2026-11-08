"""Read-only memory preflight against synthetic procfs and cgroup files."""
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "linux-build-memory.sh"
MIB = 1024 * 1024
GIB = 1024 * MIB


class BuildMemoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.meminfo = self.root / "meminfo"
        self.cgroups = self.root / "cgroup"
        self.mountinfo = self.root / "mountinfo"
        self.cgroups.write_text("")
        self.mountinfo.write_text("")
        self.host(8 * GIB, 4 * GIB)

    def host(self, ram, swap):
        self.meminfo.write_text(f"MemAvailable: {ram // 1024} kB\nSwapFree: {swap // 1024} kB\n")

    def hierarchy(self, kind="cgroup2", relative="/group/child", root="/", space=False):
        self.mount = self.root / ("memory mount" if space else "memory")
        self.mount.mkdir(exist_ok=True)
        suffix = relative[len(root.rstrip('/')):]
        (self.mount / suffix.lstrip('/')).mkdir(parents=True, exist_ok=True)
        encoded = str(self.mount).replace('\\', '\\134').replace(' ', '\\040')
        self.mountinfo.write_text(f"24 20 0:28 {root} {encoded} rw - {kind} cgroup rw,memory\n")
        self.cgroups.write_text(f"{'0::' if kind == 'cgroup2' else '5:memory:'}{relative}\n")

    def v2(self, path, limit="max", usage=0, inactive=0, swap="max", swap_used=0):
        directory = self.mount / path
        directory.mkdir(parents=True, exist_ok=True)
        for name, value in {"memory.max": limit, "memory.current": usage,
                            "memory.stat": f"inactive_file {inactive}",
                            "memory.swap.max": swap, "memory.swap.current": swap_used}.items():
            (directory / name).write_text(str(value) + "\n")

    def v1(self, path, limit, usage=0, inactive=0, memsw=None, memsw_used=0):
        directory = self.mount / path
        directory.mkdir(parents=True, exist_ok=True)
        for name, value in {"memory.limit_in_bytes": limit, "memory.usage_in_bytes": usage,
                            "memory.stat": f"total_inactive_file {inactive}"}.items():
            (directory / name).write_text(str(value) + "\n")
        if memsw is not None:
            (directory / "memory.memsw.limit_in_bytes").write_text(str(memsw) + "\n")
            (directory / "memory.memsw.usage_in_bytes").write_text(str(memsw_used) + "\n")

    def run_helper(self, requested="8", function="relay_build_memory_jobs"):
        args = ["bash", "-c", 'set -euo pipefail; source "$1"; function_name=$2; shift 2; "$function_name" "$@"',
                "memory-test", str(SCRIPT), function]
        if function == "relay_build_memory_jobs":
            args.append(str(requested))
        args += [str(self.meminfo), str(self.cgroups), str(self.mountinfo)]
        return subprocess.run(args, capture_output=True, text=True)

    def jobs(self, expected, requested=8):
        result = self.run_helper(requested)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(expected))
        return result

    def test_host_swap_counts_and_requested_parallelism_never_increases(self):
        self.host(512 * MIB, 2 * GIB)
        self.jobs(2, 8)
        self.jobs(1, 1)

    def test_below_floor_explains_disk_swap_without_mutating_host(self):
        self.host(768 * MIB, 0)
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("1 GiB", result.stderr)
        self.assertIn("not /tmp tmpfs", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_v2_accounts_usage_reclaimable_cache_and_swap_usage(self):
        self.hierarchy()
        self.v2("group/child", 2 * GIB, 512 * MIB, 256 * MIB, GIB, 256 * MIB)
        self.jobs(2)
        result = self.run_helper(function="relay_build_memory_kib")
        self.assertEqual(result.stdout.strip(), str(2560 * 1024))

    def test_v2_tightest_ancestor_caps_all_children(self):
        self.hierarchy()
        self.v2("group/child", 4 * GIB, GIB)
        self.v2("group", GIB, swap=0)
        self.jobs(1)

    def test_v2_unlimited_ram_does_not_allow_forbidden_host_swap(self):
        self.host(768 * MIB, 8 * GIB)
        self.hierarchy()
        self.v2("group/child", swap=0)
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("memory/swap limit", result.stderr)

    def test_v2_swap_is_also_capped_by_host_free_swap(self):
        self.host(8 * GIB, 512 * MIB)
        self.hierarchy()
        self.v2("group/child", 2 * GIB, swap=99 * GIB)
        self.jobs(2)

    def test_v1_combined_limit_includes_usage_and_inactive_cache(self):
        self.hierarchy("cgroup")
        self.v1("group/child", 2 * GIB, 512 * MIB, 256 * MIB, 1536 * MIB, 512 * MIB)
        self.jobs(1)

    def test_v1_unlimited_ram_still_obeys_combined_memory_and_swap(self):
        self.hierarchy("cgroup")
        self.v1("group/child", 9223372036854771712, inactive=256 * MIB,
                memsw=2 * GIB, memsw_used=GIB)
        self.jobs(1)

    def test_v1_tightest_ancestor_is_used(self):
        self.hierarchy("cgroup")
        self.v1("group/child", 8 * GIB)
        self.v1("group", GIB, memsw=GIB)
        self.jobs(1)

    def test_delegated_mount_root_and_escaped_mount_path(self):
        self.hierarchy(root="/group", space=True)
        self.v2("child", 2 * GIB, swap=0)
        self.jobs(2)

    def test_cgroup_namespace_root_still_obeys_visible_limit(self):
        self.hierarchy(relative="/", root="/..")
        self.v2("", GIB, swap=0)
        self.jobs(1)

    def test_malformed_memory_or_jobs_fail_closed(self):
        for jobs in ("0", "-1", "1e3", "999999999999999999999999"):
            with self.subTest(jobs=jobs):
                self.assertNotEqual(self.run_helper(jobs).returncode, 0)
        self.meminfo.write_text("MemAvailable: invalid kB\nSwapFree: 0 kB\n")
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cannot inspect", result.stderr)

    def test_unreadable_cgroup_accounting_fails_closed(self):
        self.hierarchy()
        self.v2("group/child", GIB)
        (self.mount / "group/child/memory.current").write_text("invalid\n")
        self.assertNotEqual(self.run_helper().returncode, 0)


if __name__ == "__main__":
    unittest.main()
