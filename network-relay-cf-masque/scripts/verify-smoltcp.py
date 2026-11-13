#!/usr/bin/env python3
"""Verify pinned smoltcp provenance and optionally run its production-feature tests.

Generated Cargo locks and test sources live in a disposable copy, never in the
vendored source directory. The local patch is reversed and reapplied there to
prove the recorded upstream and patched source hashes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "vendor/smoltcp"
PROVENANCE_FILES = {"UPSTREAM.json", "effective-smss.patch"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_files(directory: Path, expected: dict[str, str]) -> None:
    require(not any(path.is_symlink() for path in directory.rglob("*")),
            "vendored smoltcp contains a symlink")
    actual = {
        str(path.relative_to(directory))
        for path in directory.rglob("*")
        if path.is_file() and ".git" not in path.relative_to(directory).parts
    }
    require(actual == set(expected) | PROVENANCE_FILES,
            "vendored smoltcp file set differs from its provenance record")
    for name, sha256 in expected.items():
        require(digest(directory / name) == sha256,
                f"vendored smoltcp hash mismatch: {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test", action="store_true",
                        help="also run upstream unit tests with exact production features")
    args = parser.parse_args()
    metadata = json.loads((VENDOR / "UPSTREAM.json").read_text())
    upstream = metadata["upstream_files_sha256"]
    patched = metadata["patched_files_sha256"]
    added = metadata.get("added_files_sha256", {})
    require(not (set(added) & set(upstream)), "added files overlap upstream files")
    for name in set(upstream) | set(patched) | set(added) | PROVENANCE_FILES:
        path = Path(name)
        require(not path.is_absolute() and ".." not in path.parts,
                "unsafe path in smoltcp provenance record")
    require(set(patched) <= set(upstream), "patch adds an unrecorded upstream file")
    require(len(metadata["upstream_commit"]) == 40,
            "smoltcp provenance must identify a full upstream commit")
    patch = VENDOR / "effective-smss.patch"
    require(digest(patch) == metadata["patch_sha256"],
            "smoltcp patch hash mismatch")
    expected = upstream | patched | added
    check_files(VENDOR, expected)
    # scripts/env.sh points TMPDIR into this workspace. Use the system scratch
    # directory explicitly so Cargo cannot adopt the test copy as a member.
    with tempfile.TemporaryDirectory(prefix="network-relay-smoltcp-", dir="/tmp") as temporary:
        copied = Path(temporary) / "smoltcp"
        shutil.copytree(VENDOR, copied)
        subprocess.run(["git", "init", "--quiet", str(copied)], check=True)
        subprocess.run(["git", "apply", "--reverse", str(patch)], cwd=copied, check=True)
        check_files(copied, upstream)
        subprocess.run(["git", "apply", str(patch)], cwd=copied, check=True)
        check_files(copied, expected)
        print(json.dumps({"vendor_provenance": "passed",
                          "upstream_commit": metadata["upstream_commit"],
                          "source_files": len(upstream),
                          "patched_files": sorted(patched),
                          "added_files": sorted(added),
                          "patch_sha256": metadata["patch_sha256"]}), flush=True)
        if args.test:
            packages = json.loads(subprocess.check_output(
                ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
                cwd=ROOT))["packages"]
            production = next(package for package in packages
                              if package["name"] == "warp-masque-egress")
            dependency = next(dependency for dependency in production["dependencies"]
                              if dependency["name"] == "smoltcp")
            require(not dependency["uses_default_features"],
                    "smoltcp production default features unexpectedly enabled")
            require(Path(dependency["path"]).resolve() == VENDOR.resolve(),
                    "production smoltcp does not use this verified vendor directory")
            features = ",".join(dependency["features"])
            manifest = copied / "Cargo.toml"
            subprocess.run(["cargo", "generate-lockfile", "--manifest-path", str(manifest)],
                           check=True)
            print(json.dumps({"disposable_test_lock_sha256": digest(copied / "Cargo.lock"),
                              "production_features": features}), flush=True)
            jobs = max(1, min(2, int(os.environ.get("CARGO_BUILD_JOBS", "2"))))
            environment = os.environ.copy()
            target = Path(environment.get("CARGO_TARGET_DIR", str(ROOT / "target")))
            environment["CARGO_TARGET_DIR"] = str(target / "smoltcp-upstream-tests")
            subprocess.run(["cargo", "test", "--locked", "--manifest-path", str(manifest),
                            "--lib", "--no-default-features", "--features", features,
                            "--jobs", str(jobs)], env=environment, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
