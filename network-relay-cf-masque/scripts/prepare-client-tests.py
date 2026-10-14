#!/usr/bin/env python3
"""Verify retained unchanged client snapshots and build isolated test harnesses.

All copies, locks, compiler outputs and ephemeral files stay under this project.
No parent checkout, application source edits or shared client/server h3 build
graph is required. Cargo preserves archive checksum and TLS verification.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify(fixture):
    pin = json.loads((fixture / "PIN.json").read_text())
    records = pin["unchanged_files"]
    aggregate = digest(json.dumps(records, sort_keys=True).encode())
    if aggregate != pin["aggregate_sha256"]:
        raise RuntimeError(f"invalid aggregate source manifest: {fixture.name}")
    for record in records:
        relative = Path(record["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise RuntimeError("snapshot path escapes retained fixture")
        path = fixture / "core" / relative
        if path.is_symlink() or digest(path.read_bytes()) != record["sha256"]:
            raise RuntimeError(f"unchanged source checksum mismatch: {fixture.name}/{relative}")
    for name in ["Cargo.toml", "Cargo.lock", "src/main.rs", "ORIGINAL-NOTICE.md"]:
        if not (fixture / name).is_file():
            raise RuntimeError(f"missing reproducible harness artifact: {fixture.name}/{name}")
    print(f"Verified {fixture.name}: {len(records)} unchanged source files; SHA-256 {aggregate}", flush=True)
    return pin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="use the prepared Cargo archive cache only")
    args = parser.parse_args()
    project = Path(__file__).resolve().parent.parent
    fixtures = project / "tests/client-fixtures"
    runtime = project / "target/test-runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.pop("CARGO_BUILD_TARGET", None)
    env["CARGO_HOME"] = str(project / ".build/cargo-home")
    env["CARGO_BUILD_JOBS"] = "3"
    env["TMPDIR"] = str(runtime)
    verification = []
    for client in ["nf", "rs", "nf-current", "rs-current"]:
        fixture = fixtures / client
        pin = verify(fixture)
        cache = project / "target/client-interop-cache" / client
        shutil.copytree(fixture, cache, dirs_exist_ok=True)
        verify(cache)
        family = client.split("-", 1)[0]
        env["CARGO_TARGET_DIR"] = str(project / f"target/client-interop-{family}")
        command = ["cargo", "build", "--manifest-path", str(cache / "Cargo.toml"),
                   "--bin", f"client-interop-{client}", "--locked"]
        if args.offline:
            command.append("--offline")
        subprocess.run(command, cwd=project, env=env, check=True)
        verification.append({"client": client, "source_revision": pin["source_revision"],
                             "aggregate_sha256": pin["aggregate_sha256"],
                             "source_files": len(pin["unchanged_files"]),
                             "harness_lock_sha256": digest((fixture / "Cargo.lock").read_bytes())})
    output = project / "target/client-interop-cache/SOURCE-VERIFICATION.json"
    output.write_text(json.dumps(verification, indent=2) + "\n")
    print(f"Four unchanged client harnesses prepared; source verification {output}", flush=True)


if __name__ == "__main__":
    main()
