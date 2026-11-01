#!/usr/bin/env python3
"""Exercise evidence rejection with temporary synthetic fixtures, never a soak."""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile

import verify_soak

ROOT = verify_soak.ROOT


def synthetic_rows() -> list[dict]:
    digest = hashlib.sha256()
    hashes = {}
    for sequence in range(362):
        payload = bytearray(((sequence * 71) ^ (offset * 53) ^ (offset >> 5)) & 255
                            for offset in range(4096))
        payload[:8] = sequence.to_bytes(8, "big")
        digest.update(payload)
        hashes[sequence + 1] = digest.hexdigest()
    rows = []
    for index in range(121):
        pings, age = 2 + 3 * index, 10 + 30 * index
        modes = []
        for transport in ("h2", "h3"):
            tcp = [{"inbound": inbound, "age_seconds": age, "pings": pings,
                    "echo_bytes": pings * 4096, "sha256": hashes[pings]}
                   for inbound in ("h1", "h2", "h3")]
            udp = [{"inbound": inbound, "age_seconds": age, "pings": pings,
                    "echo_bytes": pings * 512} for inbound in ("h1", "h2", "h3")]
            modes.append({"warp_transport": transport,
                          "egress": {"available": True, "failure": None, "generation": 1,
                                     "sockets": 6, "lingering_sockets": 0, "socket_limit": 64,
                                     "dropped_packets": 0,
                                     "inbound_queue_drops": 0, "stack_queue_drops": 0},
                          "peer": {"tunnels": 1, "authenticated_clients": 1},
                          "relay_tunnels": 6, "persistent_tcp": tcp, "persistent_udp": udp})
        rows.append({"live_cloudflare": False, "cycle": index,
                     "elapsed_seconds": index * 30 + 0.25,
                     "process": {"metrics_available": True, "rss_kib": 100000, "fd_count": 20},
                     "modes": modes})
    return rows


def main() -> int:
    runtime = ROOT / "target/test-runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="verifier-regressions-", dir=runtime) as name:
        directory = Path(name)
        # This is deliberately not executable. The verifier only checks retained
        # bytes against the manifest; these fixtures test guard semantics.
        binary = directory / "synthetic-binary"
        binary.write_bytes(b"synthetic verifier hash fixture; never executed\n")
        log = directory / f"soak-synthetic-{os.getpid()}.jsonl"
        manifest_path = directory / "manifest.json"
        names = {path for section in ("src", "crates", "vendor") for path in (ROOT / section).rglob("*")
                 if path.is_file() and (path.suffix == ".rs" or path.name in {"Cargo.toml", "Cargo.lock"})}
        names |= {ROOT / "Cargo.toml", ROOT / "Cargo.lock"}
        baseline = {"result": "passed", "exit_code": 0, "requested_seconds": 3600,
                    "selftest_synthetic": True, "live_cloudflare": False,
                    "process_id": os.getpid(), "evidence_log": str(log.relative_to(ROOT)),
                    "binary_path": str(binary.relative_to(ROOT)),
                    "binary_sha256": verify_soak.file_sha256(binary),
                    "source_sha256": {str(path.relative_to(ROOT)): verify_soak.file_sha256(path)
                                      for path in sorted(names)}}
        rows = synthetic_rows()

        def write_case(case_rows: list[dict], manifest: dict) -> None:
            log.write_text("".join(json.dumps(row) + "\n" for row in case_rows))
            manifest["evidence_sha256"] = verify_soak.file_sha256(log)
            manifest_path.write_text(json.dumps(manifest))

        write_case(rows, copy.deepcopy(baseline))
        for evidence_only in (False, True):
            result = verify_soak.verify(log, manifest_path, evidence_only)
            expected = "recorded_evidence_verified" if evidence_only else "passed"
            assert result["result"] == expected
            assert result["frozen_binary_checked"] is (not evidence_only)
            results.append({"case": "synthetic_positive_control", "evidence_only": evidence_only,
                            "outcome": "expected_control_accepted"})

        closing_rows = copy.deepcopy(rows)
        closing_rows[0]["modes"][0]["egress"].update(sockets=8, lingering_sockets=2)
        write_case(closing_rows, copy.deepcopy(baseline))
        for evidence_only in (False, True):
            verify_soak.verify(log, manifest_path, evidence_only)
            results.append({"case": "bounded_closing_sockets", "evidence_only": evidence_only,
                            "outcome": "expected_control_accepted"})

        cases = []
        for label, expected in [
            ("pending_manifest", "pending or failed"),
            ("failed_manifest", "pending or failed"),
            ("wrong_log_path", "does not belong"),
            ("wrong_process_id", "process ID"),
            ("wrong_log_digest", "completed run's hash"),
            ("zero_rss", "resource observations"),
            ("unavailable_metrics", "resource observations"),
            ("missing_fd", "fd_count"),
            ("stalled_flow", "cadence stalled"),
            ("bad_tcp_digest", "SHA-256 mismatch"),
            ("outer_restart", "restarted or reenrolled"),
            ("missing_held_socket", "lost or added"),
            ("unexpected_live_socket", "lost or added"),
            ("invalid_linger", "invalid socket accounting"),
            ("missing_linger", "lingering_sockets"),
            ("over_socket_limit", "invalid socket accounting"),
            ("bad_production_hash", "production source changed"),
            ("changed_production_file_set", "production file set"),
        ]:
            cases.append((label, expected))
        for label, expected in cases:
            changed_rows, manifest = copy.deepcopy(rows), copy.deepcopy(baseline)
            if label == "pending_manifest":
                manifest["result"] = "pending"
            elif label == "failed_manifest":
                manifest.update(result="failed", exit_code=1)
            elif label == "wrong_log_path":
                manifest["evidence_log"] = "target/evidence/unrelated.jsonl"
            elif label == "wrong_process_id":
                manifest["process_id"] += 1
            elif label == "zero_rss":
                changed_rows[0]["process"]["rss_kib"] = 0
            elif label == "unavailable_metrics":
                changed_rows[0]["process"]["metrics_available"] = False
            elif label == "missing_fd":
                del changed_rows[0]["process"]["fd_count"]
            elif label == "stalled_flow":
                initial = rows[0]["modes"][0]["persistent_tcp"][0]
                for row in changed_rows:
                    flow = row["modes"][0]["persistent_tcp"][0]
                    flow.update(pings=initial["pings"], echo_bytes=initial["echo_bytes"], sha256=initial["sha256"])
            elif label == "bad_tcp_digest":
                changed_rows[0]["modes"][0]["persistent_tcp"][0]["sha256"] = "0" * 64
            elif label == "outer_restart":
                changed_rows[0]["modes"][0]["egress"]["generation"] = 2
            elif label == "missing_held_socket":
                changed_rows[0]["modes"][0]["egress"]["sockets"] = 5
            elif label == "unexpected_live_socket":
                changed_rows[0]["modes"][0]["egress"]["sockets"] = 7
            elif label == "invalid_linger":
                changed_rows[0]["modes"][0]["egress"]["lingering_sockets"] = 8
            elif label == "missing_linger":
                del changed_rows[0]["modes"][0]["egress"]["lingering_sockets"]
            elif label == "over_socket_limit":
                changed_rows[0]["modes"][0]["egress"].update(sockets=65, lingering_sockets=59)
            elif label == "bad_production_hash":
                manifest["source_sha256"]["src/main.rs"] = "0" * 64
            elif label == "changed_production_file_set":
                del manifest["source_sha256"]["src/main.rs"]
            write_case(changed_rows, manifest)
            if label == "wrong_log_digest":
                manifest["evidence_sha256"] = "0" * 64
                manifest_path.write_text(json.dumps(manifest))
            for evidence_only in (False, True):
                try:
                    verify_soak.verify(log, manifest_path, evidence_only)
                except (OSError, KeyError, ValueError) as error:
                    assert expected in str(error), f"{label} hit an unrelated guard: {error}"
                else:
                    raise AssertionError(f"{label} falsely accepted, evidence_only={evidence_only}")
                results.append({"case": label, "evidence_only": evidence_only, "outcome": "rejected"})
        # The opt-in archival mode intentionally does not check retired binary
        # bytes, and distinctly reports recorded_evidence_verified above.
        manifest = copy.deepcopy(baseline)
        manifest["binary_sha256"] = "0" * 64
        write_case(rows, manifest)
        try:
            verify_soak.verify(log, manifest_path)
        except ValueError as error:
            assert "retained executable" in str(error)
        else:
            raise AssertionError("normal acceptance ignored the frozen binary hash")
        results.append({"case": "bad_frozen_binary_hash", "evidence_only": False, "outcome": "rejected"})
    print(json.dumps({"verifier_selfcheck": "passed", "synthetic_fixtures_only": True,
                      "checked_at_utc": datetime.now(timezone.utc).isoformat(),
                      "verifier_sha256": verify_soak.file_sha256(Path(verify_soak.__file__)),
                      "selfcheck_sha256": verify_soak.file_sha256(Path(__file__)),
                      "checks": len(results), "temporary_fixtures_removed": not directory.exists(),
                      "cases": results}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
