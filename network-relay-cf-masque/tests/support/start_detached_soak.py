#!/usr/bin/env python3
"""Launch the gated local WARP soak outside a bounded interactive tool session.

A launch record is not a test pass. Read the worker result, the soak manifest,
and the independent summary after actual completion.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def write_record(path: Path, record: dict) -> None:
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(record, indent=2) + "\n")
    temporary.replace(path)


def environment() -> dict:
    variables = os.environ.copy()
    variables.pop("CARGO_BUILD_TARGET", None)
    variables.update(CARGO_HOME=str(ROOT / ".build/cargo-home"),
                     CARGO_TARGET_DIR=str(ROOT / "target"),
                     TMPDIR=str(ROOT / "target/test-runtime"),
                     CARGO_BUILD_JOBS="3", PYTHONDONTWRITEBYTECODE="1")
    return variables


def worker(path: Path) -> int:
    record = json.loads(path.read_text())
    record.update(result="running", launcher_pid=os.getpid(),
                  launcher_session=os.getsid(0), launcher_process_group=os.getpgrp(),
                  started_at_utc=datetime.now(timezone.utc).isoformat())
    write_record(path, record)
    command = [sys.executable, str(ROOT / "scripts/test-matrix.py"),
               "--soak-seconds", str(record["requested_soak_seconds"])]
    try:
        process = subprocess.Popen(command, cwd=ROOT, env=environment(), stdin=subprocess.DEVNULL)
        record["matrix_launcher_pid"] = process.pid
        write_record(path, record)
        exit_code = process.wait()
    except OSError as error:
        record["launch_error"] = str(error)
        exit_code = 1
    record.update(result="passed" if exit_code == 0 else "failed", exit_code=exit_code,
                  ended_at_utc=datetime.now(timezone.utc).isoformat())
    write_record(path, record)
    return exit_code if exit_code >= 0 else 128 - exit_code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=3900, help="Measured soak seconds, minimum 3600")
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        return worker(args.worker)
    if args.seconds < 3600:
        parser.error("--seconds must be at least 3600")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = ROOT / "target/test-runtime" / f"detached-soak-{stamp}-{os.getpid()}"
    directory.mkdir(parents=True)
    directory.chmod(0o700)
    path, output = directory / "launcher.json", directory / "output.log"
    record = {"result": "queued", "requested_soak_seconds": args.seconds,
              "live_cloudflare": False, "detached": True,
              "finite_gate_required": True, "launch_is_not_acceptance": True,
              "output_log": str(output.relative_to(ROOT)),
              "queued_at_utc": datetime.now(timezone.utc).isoformat()}
    write_record(path, record)
    with output.open("wb") as sink:
        process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--worker", str(path)],
                                   cwd=ROOT, env=environment(), stdin=subprocess.DEVNULL,
                                   stdout=sink, stderr=subprocess.STDOUT,
                                   start_new_session=True, close_fds=True)
    print(json.dumps({"result": "launched", "acceptance_pending": True,
                      "launcher_pid": process.pid,
                      "launcher_manifest": str(path.relative_to(ROOT)),
                      "output_log": str(output.relative_to(ROOT))}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
