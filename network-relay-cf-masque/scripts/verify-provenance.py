#!/usr/bin/env python3
"""Validate pinned vendored source identity and the recorded final union."""
import hashlib
import json
from pathlib import Path

project = Path(__file__).resolve().parent.parent
manifest = json.loads((project / "vendor/h3/UNION-SOURCE-HASHES.json").read_text())
bad = []
for entry in manifest["files"]:
    path = project / entry["path"]
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != entry["union_sha256"]:
        bad.append(entry["path"])
datagrams = json.loads((project / "docs/evidence/h3-datagram-source.json").read_text())
for relative, entry in datagrams["files"].items():
    if relative == "Cargo.toml":
        continue  # documented path/workspace-only dependency adaptation
    path = project / "vendor/h3-datagram" / relative
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
        bad.append(str(path.relative_to(project)))
print(json.dumps({"passed": not bad, "source_hash_mismatches": bad}))
raise SystemExit(bool(bad))
