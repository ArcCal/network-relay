"""Repeat the checked link experiments with the product stack and fixed resource limits."""
import json
import os
import subprocess
import sys
from pathlib import Path

bins, evidence = map(Path, sys.argv[1:])
for repeat, order in enumerate([
    ["original", "large", "reno", "immediate-ack"],
    ["immediate-ack", "reno", "large", "original"],
    ["reno", "original", "immediate-ack", "large"],
]):
    for rtt in [0, 50, 100]:
        for variant in order:
            binary = bins / ("path-large" if variant == "large" else "path")
            proc = subprocess.run([binary, str(rtt), str(repeat)], env=dict(os.environ, RELAY_STACK_STUDY=variant),
                                  capture_output=True, timeout=135)
            result = json.loads(proc.stdout)
            assert result["variant"] == variant
            assert result["payload_bytes_each_direction"] == 8 * 1024 * 1024
            for direction in ["upstream", "downstream"]:
                transfer = result[direction]
                assert transfer["received_bytes"] == result["payload_bytes_each_direction"]
                assert transfer["sha256"] == transfer["expected_sha256"]
            with (evidence / "paths.jsonl").open("a") as out:
                out.write(json.dumps(result) + "\n")
            print(variant, rtt, repeat, result["success"], f'{result["transfer_wall_s"]:.2f}', flush=True)
            if proc.returncode or not result["success"]:
                raise RuntimeError("Transfer integrity or resource reclamation failed")
