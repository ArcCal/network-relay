# Immutable client protocol test snapshots

These are test-only, byte-for-byte Rust protocol cores and their vendored h3:

- `nf` and `rs`: actual pre-existing parent client sources at setup time; the NF directory/package still uses its historical `network-realy-nf` spelling. Per-file hashes define the exact local source identity.
- `nf-current` and `rs-current`: canonical current Network Relay sources at `cc7ea4df2924d0454ab5075e089cbb53d94b178e`.

No original client code or application is edited. `PIN.json` records each unchanged source file, aggregate SHA-256 and source revision. Original ArcCal application notices and provenance are retained; those notices explicitly do not grant a new license for ArcCal-owned application code. Each vendored hyperium/h3 retains its original MIT license in `core/vendor/h3/LICENSE` and local patch record.

The surrounding standalone harness manifests and entrypoints are new test code. NF's unchanged native bridge test emulator executes on Linux; RS uses its unchanged production Tokio/rustls/Quinn backend. Native macOS networking/UI and an Apple installed profile are not exercised. Separate workspaces keep each client's own h3 implementation instead of substituting the server's vendor union.

Run `python3 scripts/prepare-client-tests.py` from project root. It validates all retained source hashes, copies into ignored project `target/client-interop-cache`, and builds with each frozen lock. Add `--offline` after dependencies are cached. Root `scripts/test.sh` performs this prerequisite before the functional test. All generated files remain project-contained; a parent checkout is unnecessary.

Functional evidence is retained in `docs/evidence/client-interop.json` and explained in `docs/evidence/client-interop.md`.
