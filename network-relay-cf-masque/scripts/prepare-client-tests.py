#!/usr/bin/env python3
"""Build the client interoperability harnesses.

Each harness wraps a client core of this repository (network-relay-nf/Core
and network-relay-rs/Core) as it is, with that client's own h3, and builds
into this project's target directory.
"""

import argparse
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="use the Cargo cache only")
    args = parser.parse_args()
    project = Path(__file__).resolve().parent.parent
    env = os.environ.copy()
    env.pop("CARGO_BUILD_TARGET", None)
    for client in ["nf", "rs"]:
        env["CARGO_TARGET_DIR"] = str(project / f"target/client-interop-{client}")
        command = ["cargo", "build", "--locked", "--manifest-path",
                   str(project / f"tests/client-interop/{client}/Cargo.toml")]
        if args.offline:
            command.append("--offline")
        subprocess.run(command, cwd=project, env=env, check=True)
    print("NF and RS client harnesses built", flush=True)


if __name__ == "__main__":
    main()
