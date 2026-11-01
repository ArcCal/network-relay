#!/usr/bin/env python3
"""Independently verify a completed synthetic WARP soak's retained evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(log: Path, manifest_path: Path, evidence_only: bool = False) -> dict:
    manifest = json.loads(manifest_path.read_text())
    require(manifest.get("result") == "passed" and manifest.get("exit_code") == 0,
            "a pending or failed run cannot satisfy acceptance")
    require(manifest.get("requested_seconds", 0) >= 3600, "requested run was shorter than one hour")
    require(manifest.get("live_cloudflare") is False, "evidence must identify its synthetic peer")
    require(manifest.get("evidence_log") == str(log.resolve().relative_to(ROOT)),
            "metric log does not belong to this run manifest")
    require(log.name.endswith(f"-{manifest.get('process_id')}.jsonl"),
            "metric log process ID does not match its frozen runner")
    require(file_sha256(log) == manifest.get("evidence_sha256"),
            "metric log no longer matches the completed run's hash")
    if not evidence_only:
        binary = ROOT / manifest["binary_path"] if "binary_path" in manifest else manifest_path.parent / "runner"
        require(file_sha256(binary) == manifest["binary_sha256"],
                "retained executable no longer matches its frozen hash")
    production_names = {
        name for name in manifest["source_sha256"]
        if name.startswith(("src/", "crates/", "vendor/")) or name in {"Cargo.toml", "Cargo.lock"}
    }
    current_names = {
        str(path.relative_to(ROOT))
        for directory in ("src", "crates", "vendor")
        for path in (ROOT / directory).rglob("*")
        if path.is_file() and (path.suffix == ".rs" or path.name in {"Cargo.toml", "Cargo.lock"})
    } | {"Cargo.toml", "Cargo.lock"}
    require(current_names == production_names, "production file set changed after the frozen build")
    for name in sorted(production_names):
        require(file_sha256(ROOT / name) == manifest["source_sha256"][name],
                f"production source changed after the frozen build: {name}")

    rows = [json.loads(line) for line in log.read_text().splitlines() if line.strip()]
    require(len(rows) >= 120, "fewer than 120 metric samples")
    require(rows[-1]["elapsed_seconds"] >= 3600, "recorded measured clock is shorter than one hour")
    counts = {flow["pings"] for row in rows for mode in row["modes"] for flow in mode["persistent_tcp"]}
    require(counts and min(counts) > 0, "persistent TCP did not exchange any sequences")

    # Independent Python producer: the Rust client emits one 4096-byte payload
    # per sequence, puts its big-endian sequence in the first eight bytes,
    # and validates the full echoed payload before advancing its digest.
    digest = hashlib.sha256()
    expected_hashes = {}
    for sequence in range(max(counts)):
        payload = bytearray(((sequence * 71) ^ (offset * 53) ^ (offset >> 5)) & 255
                            for offset in range(4096))
        payload[:8] = sequence.to_bytes(8, "big")
        digest.update(payload)
        if sequence + 1 in counts:
            expected_hashes[sequence + 1] = digest.hexdigest()

    previous = {}
    last_elapsed = -1.0
    for row_number, row in enumerate(rows):
        require(row["live_cloudflare"] is False, f"sample {row_number} loses the synthetic label")
        require(row["elapsed_seconds"] > last_elapsed, "sample clock did not advance monotonically")
        last_elapsed = row["elapsed_seconds"]
        require({mode["warp_transport"] for mode in row["modes"]} == {"h2", "h3"},
                "a sample omitted an explicit WARP transport")
        require(row["process"].get("metrics_available", True)
                and row["process"]["rss_kib"] > 0 and row["process"]["fd_count"] > 0,
                "Linux resource observations are missing")
        for mode in row["modes"]:
            transport = mode["warp_transport"]
            status, peer = mode["egress"], mode["peer"]
            require(status["available"] and status["failure"] is None, f"{transport} became unavailable")
            require(status["generation"] == peer["tunnels"] == peer["authenticated_clients"] == 1,
                    f"{transport} restarted or reenrolled its outer session")
            sockets, lingering = status["sockets"], status["lingering_sockets"]
            require(0 <= lingering <= sockets <= status["socket_limit"],
                    f"{transport} has invalid socket accounting or exceeded its limit")
            require(sockets - lingering == 6 and mode["relay_tunnels"] == 6,
                    f"{transport} lost or added a retained business flow")
            require(not any(status[name] for name in
                            ("dropped_packets", "inbound_queue_drops", "stack_queue_drops")),
                    f"{transport} reported a packet queue drop")
            for protocol in ("tcp", "udp"):
                flows = mode[f"persistent_{protocol}"]
                require({flow["inbound"] for flow in flows} == {"h1", "h2", "h3"},
                        f"{transport}/{protocol} omitted an inbound transport")
                for flow in flows:
                    key = (transport, protocol, flow["inbound"])
                    before = previous.get(key)
                    if before:
                        require(flow["age_seconds"] >= before["age_seconds"]
                                and flow["pings"] >= before["pings"],
                                f"held flow restarted: {key}")
                    require(flow["echo_bytes"] == flow["pings"] * (4096 if protocol == "tcp" else 512),
                            f"retained-flow byte accounting changed: {key}")
                    require(flow["pings"] >= max(1, int(flow["age_seconds"] // 10) - 3)
                            and flow["age_seconds"] + 30 >= row["elapsed_seconds"],
                            f"retained-flow sequence cadence stalled: {key}")
                    if protocol == "tcp":
                        require(flow["sha256"] == expected_hashes[flow["pings"]],
                                f"independent expected TCP SHA-256 mismatch: {key}")
                    previous[key] = flow
    require(len(previous) == 12, "not all twelve TCP/UDP pairings were retained")
    require(min(flow["age_seconds"] for flow in previous.values()) >= 3600,
            "a held flow did not live for at least one hour")
    rss = [row["process"]["rss_kib"] for row in rows]
    descriptors = [row["process"]["fd_count"] for row in rows]
    require(max(rss) <= rss[0] + 192 * 1024 and max(descriptors) <= descriptors[0] + 48,
            "recorded memory or descriptor growth exceeded the acceptance limit")
    return {
        "result": "recorded_evidence_verified" if evidence_only else "passed",
        "frozen_binary_checked": not evidence_only,
        "verifier_sha256": file_sha256(Path(__file__)),
        "live_cloudflare": False,
        "log": str(log.resolve().relative_to(ROOT)),
        "manifest": str(manifest_path.resolve().relative_to(ROOT)),
        "binary_sha256": manifest["binary_sha256"],
        "production_source_matches_frozen_build": True,
        "independent_expected_tcp_sha256_matches_every_sample": True,
        "samples": len(rows),
        "measured_seconds": rows[-1]["elapsed_seconds"],
        "minimum_held_flow_age_seconds": min(flow["age_seconds"] for flow in previous.values()),
        "minimum_held_flow_pings": min(flow["pings"] for flow in previous.values()),
        "held_tcp_flows": 6,
        "held_udp_flows": 6,
        "outer_generations_per_transport": 1,
        "reported_packet_queue_drops": 0,
        "rss_kib": {"first": rss[0], "minimum": min(rss), "maximum": max(rss), "last": rss[-1]},
        "fd_count": {"first": descriptors[0], "minimum": min(descriptors), "maximum": max(descriptors), "last": descriptors[-1]},
        "final_modes": rows[-1]["modes"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path, help="Save the independent acceptance summary as JSON")
    parser.add_argument("--evidence-only", action="store_true",
                        help="Verify recorded metrics and current production hashes without checking the historical executable")
    args = parser.parse_args()
    try:
        summary = verify(args.log, args.manifest, args.evidence_only)
    except (OSError, KeyError, ValueError) as error:
        print(f"Soak evidence rejected: {error}", file=sys.stderr)
        return 1
    text = json.dumps(summary, indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
