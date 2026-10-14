#!/usr/bin/env python3
"""Compare this development tree with its recorded outside-project baseline."""
import datetime
import hashlib
import json
import subprocess
from pathlib import Path

project = Path(__file__).resolve().parent.parent
baseline = json.loads((project / "docs/evidence/parent-baseline.json").read_text())
parent = project.parent
changes = []
for relative, before in baseline["files"].items():
    path = parent / relative
    if before.get("missing"):
        if path.exists():
            changes.append({"path": relative, "reason": "originally missing file appeared"})
    elif not path.is_file():
        changes.append({"path": relative, "reason": "original file disappeared"})
    elif hashlib.sha256(path.read_bytes()).hexdigest() != before["sha256"]:
        changes.append({"path": relative, "reason": "content changed"})

listed = subprocess.check_output(
    ["git", "-C", str(parent), "ls-files", "--cached", "--others", "--exclude-standard", "-z"]
).decode().split("\0")
new = [name for name in listed if name and not name.startswith(project.name + "/") and name not in baseline["files"]]
changes.extend({"path": name, "reason": "new outside-project file"} for name in new)
result = {
    "observed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "baseline_files": len(baseline["files"]),
    "outside_project_changes": changes,
    "passed": not changes,
    "note": "Development-tree baseline proof, not a gate for unrelated fresh checkouts.",
}
(project / "docs/evidence/parent-final-verification.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result))
raise SystemExit(bool(changes))
