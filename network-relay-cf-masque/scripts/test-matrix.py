#!/usr/bin/env python3
"""Run the local packet-backed acceptance tests and an optional real-time soak.

These tests emulate Cloudflare's wire protocol locally. They do not establish
live Cloudflare interoperability or a public Cloudflare exit identity.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", default="cargo", help="Cargo executable, already on PATH")
    parser.add_argument("--soak-seconds", type=int, help="Run the soak only after every finite check passes; minimum 3600, recommended 3900")
    args = parser.parse_args()
    if args.soak_seconds is not None and args.soak_seconds < 3600:
        parser.error("--soak-seconds must be at least 3600")
    environment = os.environ.copy()
    # These acceptance clients run on the current machine. An inherited target
    # from a deployment build must not silently cross-compile their executables.
    environment.pop("CARGO_BUILD_TARGET", None)
    environment.update(CARGO_HOME=str(ROOT / ".build/cargo-home"), CARGO_TARGET_DIR=str(ROOT / "target"), TMPDIR=str(ROOT / "target/test-runtime"))
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment.setdefault("CARGO_BUILD_JOBS", "3")
    Path(environment["TMPDIR"]).mkdir(parents=True, exist_ok=True)
    guard_checks = subprocess.run([sys.executable, str(ROOT / "tests/support/verify_soak_regressions.py")], cwd=ROOT, env=environment, text=True, stdout=subprocess.PIPE)
    if guard_checks.returncode:
        print(guard_checks.stdout, end="")
        return guard_checks.returncode
    print(f"Evidence verifier guard checks passed: {json.loads(guard_checks.stdout)['checks']} synthetic checks", flush=True)
    prepare = subprocess.run([sys.executable, str(ROOT / "scripts/prepare-client-tests.py")], cwd=ROOT, env=environment)
    if prepare.returncode:
        return prepare.returncode
    command = [args.cargo, "test", "--locked", "--test", "warp_matrix", "--test", "warp_protocol_failures", "--test", "cli_warp_wiring", "--test", "http_file_matrix", "--test", "udp_mtu_frontend", "--test", "client_interop", "--test", "h3_settings_validation", "--", "--test-threads=1"]
    result = subprocess.run(command, cwd=ROOT, env=environment)
    if result.returncode or args.soak_seconds is None:
        return result.returncode

    # Obtain the actual executable from Cargo, then copy it so the run's
    # binary remains immutable and no long-running Cargo build lock is held.
    build = subprocess.run([args.cargo, "test", "--locked", "--test", "warp_matrix", "--no-run", "--message-format=json"], cwd=ROOT, env=environment, text=True, stdout=subprocess.PIPE)
    if build.returncode:
        return build.returncode
    executable = None
    for line in build.stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("reason") == "compiler-artifact" and event.get("target", {}).get("name") == "warp_matrix" and event.get("executable"):
            executable = Path(event["executable"])
    if executable is None:
        print("Cargo did not report the matrix test executable", file=sys.stderr)
        return 1
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = ROOT / "target/test-runtime" / f"soak-{stamp}-{os.getpid()}"
    directory.mkdir()
    binary = directory / "runner"
    shutil.copy2(executable, binary)
    source_files = sorted({path for directory in ["src", "tests", "crates", "vendor"]
                           for path in (ROOT / directory).rglob("*")
                           if path.is_file() and (directory == "vendor" or path.suffix == ".rs"
                                                  or path.name in {"Cargo.toml", "Cargo.lock"})}
                          | {ROOT / "Cargo.toml", ROOT / "Cargo.lock",
                             ROOT / "tests/support/verify_soak.py"})
    manifest = {"launched_at_utc": datetime.now(timezone.utc).isoformat(), "requested_seconds": args.soak_seconds, "live_cloudflare": False, "binary_path": str(binary.relative_to(ROOT)), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "source_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in source_files}}
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    environment["SOAK_SECONDS"] = str(args.soak_seconds)
    print(f"Starting fixed-binary soak; manifest: {directory / 'manifest.json'}", flush=True)
    process = subprocess.Popen([str(binary), "one_hour_forced_h2_and_h3_soak_with_resource_metrics", "--ignored", "--nocapture", "--test-threads=1"], cwd=ROOT, env=environment)
    manifest["process_id"] = process.pid
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    exit_code = process.wait()
    logs = list((ROOT / "target/evidence").glob(f"soak-*-{process.pid}.jsonl"))
    if len(logs) == 1:
        manifest.update(evidence_log=str(logs[0].relative_to(ROOT)), evidence_sha256=hashlib.sha256(logs[0].read_bytes()).hexdigest())
    elif exit_code == 0:
        print("Soak returned success without one uniquely identified process evidence log", file=sys.stderr)
        exit_code = 1
    manifest.update(ended_at_utc=datetime.now(timezone.utc).isoformat(), test_exit_code=exit_code, exit_code=exit_code, result="passed" if exit_code == 0 else "failed")
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    retained_manifest = ROOT / "target/evidence" / f"soak-manifest-{stamp}-{process.pid}.json"
    retained_manifest.write_text(json.dumps(manifest, indent=2) + "\n")
    if exit_code == 0:
        summary = ROOT / "target/evidence" / f"soak-summary-{stamp}-{process.pid}.json"
        verified = subprocess.run([sys.executable, str(ROOT / "tests/support/verify_soak.py"), str(logs[0]), str(retained_manifest), "--output", str(summary)], cwd=ROOT, env=environment)
        if verified.returncode:
            manifest.update(independent_verification="failed", result="failed_evidence_verification", exit_code=verified.returncode)
            (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
            retained_manifest.write_text(json.dumps(manifest, indent=2) + "\n")
            return verified.returncode
        manifest.update(independent_verification="passed", independent_summary=str(summary.relative_to(ROOT)))
        (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        retained_manifest.write_text(json.dumps(manifest, indent=2) + "\n")
    return exit_code

if __name__ == "__main__":
    raise SystemExit(main())
