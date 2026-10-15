# Unchanged client-core interoperability

The new server was tested through its real `WarpEgress` userspace TCP/UDP stack and packet pump to a local pinned-mTLS WARP H2/H3 peer. The peer is synthetic, not Cloudflare.

Four unchanged source snapshots are retained below `tests/client-fixtures`:

| Fixture | Exact source identity | Aggregate SHA-256 of the 68 retained core files |
| --- | --- | --- |
| `nf` | Actual pre-existing `network-realy-nf/Core`, version 0.1.0; historical package spelling and local source bytes at parent HEAD `27bccd28f97d6c45067abb6495b50321061de1c5` | `194560cff41357eaaf0bb0d6650a54983d33df991f1f8ead962c4d93793957d4` |
| `rs` | Actual pre-existing local `network-relay-rs/Core`, version 0.1.0; file hashes define its local identity rather than implying all files were in the parent commit | `5d7bd7d8248411a903d79f0158fda1cff679865a5d5952db3864a412800a24db` |
| `nf-current` | Canonical Network Relay commit `cc7ea4df2924d0454ab5075e089cbb53d94b178e`, `network-relay-nf/Core`, version 0.1.0 | `a497375c5d845a841c3b9acc0e26cb1d265c81d1bba78bc0dc5a3c845b0c85aa` |
| `rs-current` | Same canonical commit, `network-relay-rs/Core`, version 0.1.0 | `cb9a647f4fbb6aa50798429c8c11518dfed24b6e357f46fd10b434a9257d4088` |

Every retained core, vendored h3 and NF native-bridge emulator source is byte-for-byte unchanged. Surrounding test harnesses are new code. Original application notices/provenance and h3 MIT licenses are retained. `client-source-pins.json` records source and frozen harness-lock identities; individual fixture `PIN.json` files contain every source checksum.

Separate Cargo workspaces preserve each client's own vendored h3. This avoids replacing client-specific behavior with the server's union. The actual older NF requires exactly 200/101 and literal `Capsule-Protocol: ?1`; newer cores accept broader valid responses. The current frontend's 200/101 plus `?1` satisfies the tested intersection. See [client-header-contract.md](client-header-contract.md) for detailed source evidence and response/reset differences.

The root test runs each of the four cores with explicit ingress HTTP/1.1, HTTP/2 and HTTP/3 against explicit WARP H2 and H3: **24 combinations**. Each combination verifies eight functional cases:

- Domain TCP CONNECT, 2 MiB deterministic echo, full content SHA-256 and write FIN/read EOF.
- IPv6 TCP CONNECT, 16 KiB deterministic echo, full content SHA-256 and directional shutdown.
- Domain and IPv6 CONNECT-UDP, each with zero-byte, one-byte and 1,200-byte whole datagrams and exact content/hash equality.

That yields **192 TCP/UDP cases**, plus **48 negative checks** for wrong credentials and wrong certificate names. Each combination requires observed WARP IP packets in both directions, tunneled target DNS, and server tunnel release. RS additionally requires zero production transport resources after shutdown; WARP shutdown requires zero workers. All four cores disable ingress QUIC DATAGRAM and use reliable HTTP Datagram capsules, which this matrix verifies. Separate frontend regressions cover ingress QUIC DATAGRAM delivery.

NF executes its unchanged native bridge test emulator on Linux, with real Tokio/rustls/Quinn I/O to loopback ingress. It exercises Rust protocol and bridge behavior, not Apple's Network.framework or Swift UI. RS executes its unchanged production Rust transport backend, but its AppKit GUI/bundle is not run. Installed Apple Network Relay profiles/devices, automatic transport fallback and live Cloudflare are outside this matrix. Large UDP payloads above inner path MTU are not represented as a WARP delivery requirement.

Reproduce from a fresh project checkout after loading the project Rust environment:

```sh
python3 scripts/prepare-client-tests.py
cargo test --test client_interop --locked -- --nocapture
```

The preparer validates each source hash and builds immutable copies only below project `target/client-interop-cache`, with outputs below project `target/client-interop-nf` and `target/client-interop-rs`. No original parent checkout or ignored `.research` file is required. Use `--offline` after dependency archives are prepared. Root `scripts/test.sh` invokes the prerequisite. Snapshot locks are frozen; Cargo archive checksums and TLS verification remain enabled.

`client-interop.json` is written only when the complete matrix passes, and records its start/end, all combinations, exact source identities, content hashes and packet/DNS deltas. Ephemeral credentials are mode-0600 fixture files removed after testing; result evidence contains no passwords, registration keys or certificate contents. The canonical NF emulator retains an inherited harmless `unused_mut` compiler warning to preserve source identity.
