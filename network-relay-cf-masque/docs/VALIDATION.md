# Validation record

Fixtures use ephemeral keys and a local synthetic WARP peer; no live
Cloudflare account or real enrollment is used. Tests write their evidence to
`target/evidence` (not tracked). Earlier records about the removed private
copy of the relay are not retained: they described different code.

## HTTP/3 initialization follow-up (November 1, 2026)

The missing deadline was independently reproduced through public
`WarpEgress::connect`, using pinned server keys and enforced enrolled-client
mTLS. A peer with zero unidirectional stream credit kept QUIC alive beyond
the configured 5-second idle timeout; setup was still pending at the test's
20-second guard. The guard failed before the production change.

The builder now has its own 15-second deadline. Regression tests verify
limits of 0, 1 and 2 streams and observe an application close from the peer.
Separate controls confirm that a peer granting all 3 streams but withholding
SETTINGS still hits the existing 5-second deadline, and that cancelling a
pending connect closes QUIC. Both control cases passed before the fix too.
No new cleanup abstraction or change to the parent server was required.

Validation on Linux x86_64 completed with 110 finite workspace tests and
1 library doctest passed. The affected 6-test protocol target passed again
after test-only fixture and lint corrections. Parent validation passed 165
unit tests and 76 integration tests, plus the same 76 integration tests with
loopback egress. Strict all-target/all-feature Clippy, strict production
Clippy, formatting, the locked standalone consumer and the optimized default
build passed. All 394 tracked parent files remain unchanged against baseline
`5b58468b3c9358ffabbb7e28bba59d856b0a2fd9`.

The first full run exposed a fixture observation race: its own close replaced
the received remote close reason with `LocallyClosed`. The raw peer now leaves
the received reason intact, and the strict application-close assertion stays.
A redundant Result wrapper in a test helper was also removed after Clippy.
The affected target and all remaining validation steps were rerun afterward.

Logs are under `target/evidence/h3-setup/`. `before-fix.log` records the
original timeout regression; `cleanup-controls-before.log` records the two
pre-existing cleanup controls. `finite-tests-and-initial-lint.log` records
all finite test results and the initial lint failure; `validation-completion.log`
records the final affected-target, lint, format, consumer and parent checks.
`production-clippy.log` and `release-build.log` record the production checks.
The initial fixture failure is retained as `full-tests-before-fixture-fix.log`.
Failed runs are not counted as passes.

The initial audit's long-run results below describe its earlier code and
are separate historical evidence for that revision.

## Initial audit results (November 1, 2026 UTC; revision 7f7bb34)

Linux x86_64, Rust/Cargo 1.99.1, Go 1.26.10 and Python 3.12.14. This
environment supports IPv6 loopback and has no configured WARP credentials
or Mac runtime. [AUDIT.md](AUDIT.md) records scope, findings, standards
applicability and architecture decisions.

| Final-code check | Actual result |
| --- | --- |
| `scripts/test.sh`: workspace tests with all features | Passed: 107 tests and 1 library doctest; the 2 long tests are separate runs |
| Live validation helper's local URL regression | Passed: 1 test; includes numeric IPv6 and rejects userinfo/plain HTTP/port zero |
| NF/RS interoperability through synthetic WARP | Passed: 12 ingress/egress pairs, 96 IPv4/domain and IPv6 TCP/UDP checks, authentication and TLS negatives |
| Independent H2/H3 WARP and IPv4/IPv6 coverage | Passed: IPv4 and IPv6 outer endpoints, IPv6-only DNS transport, both inner families, half-close, UDP and packet-loss recovery |
| Functional/bulk/failure matrix | Passed: six pairings, repeated 64 MiB integrity transfers, 64 MiB HTTP files, MTU drops, keepalive, resets, revocation, controller loss and CLI reload/failure |
| New DNS, credential and TCP close/window regressions | Passed; the two DNS defects, lost-final-ACK defect and independent TCP zero-window stall demonstrably failed before their fixes |
| Strict Clippy, formatting and standalone `examples/reuse` with `--locked` | Passed |
| Independent soak-evidence verifier regressions | Passed: 41 synthetic guard/control cases, including valid close state, invalid socket accounting and socket-limit violations |
| Default-feature optimized build, `scripts/build.sh -j 2`, and strict production Clippy | Passed |
| Pinned official smoltcp source, deployed TCP/IP features | Passed: 430 upstream unit tests |
| Immutable parent's Rust tests | Passed: 165 unit tests and 76 integration tests; another 76 integration tests passed with `NETWORK_RELAY_TEST_EGRESS=loopback` |
| Canonical shared h3 source tests and doctests | Passed: 263 tests and 9 doctests, with native IPv6 and no source modifications |
| Canonical shared h3-quinn source with all features | Passed: 1 unit test; original source through a disposable manifest, no parent changes |
| Parent Go MASQUE / curl interoperability | Passed: Go CONNECT/CONNECT-UDP and H1/H2 curl, integrity, half-close, credentials, policy and TLS negatives |
| Available parent Python deployment/installer regressions | Passed: 70 tests; 9 root-dependent tests skipped by their own guards and 1 additional root-owned-credential test unavailable |
| Separate H3 bulk diagnostic | Passed: 64 rounds per WARP mode, 128 transfers of 64 MiB each direction with SHA-256/half-close and held TCP/UDP flows, 1865.13 seconds |
| Fresh 3900-second held-flow/resource soak | Passed and independently verified: 3926.300 measured seconds, 131 samples, 12 held flows; no outer restart or packet queue drop |

The full Python discovery initially reported one failure because its saved-token
test creates a file as the current user while the installer deliberately accepts
only root-owned credential files. Root is unavailable here. The immutable test
had no non-root guard for this case; it was explicitly excluded as unavailable
from the subsequent available-tests run. That run selected 79 tests, passed 70,
and retained the 9 existing skips. No parent test or installer was changed.
Root-only profile ownership adoption is likewise not established by non-root
CLI execution.

The shared h3 suite ran through a disposable manifest under
`target/test-runtime/h3-canonical-tests`, with its library path pointing at the
original `../vendor/h3/src/lib.rs`. Its test-only manifest/lockfile and all
artifacts stayed inside this subproject. The implementation was not copied or
patched. Official standards snapshots and their hashes are retained in
`target/evidence/audit/standards/`.

Final-run logs are `target/evidence/audit/upstream-final-tests.log`,
`upstream-release-build.log`, `upstream-production-clippy.log`,
`upstream-live-helper.log`, `upstream-reuse.log`, `upstream-smoltcp-tests.log`,
`upstream-soak-run.log`, `upstream-h3-bulk-diagnostic.log`, `h3-tests.log`,
`h3-quinn-tests.log`, `parent-interop.log` and `parent-python-available.log`.
Older baseline and superseded logs are not final-code acceptance evidence.
The independently verified soak manifest, log, summary,
binary hash and source hashes are retained separately under `target/evidence/`.
The soak uses a debug test executable. Its six live business sockets per WARP
mode are accounted separately from TCP sockets retained for close/TIME-WAIT;
all of them remain subject to the same 64-socket limit. The verifier checks
the held flows, closing-state counts and limit independently.

The fresh run retained six TCP and six UDP flows for at least 3920.012
seconds each, with at least 394 verified exchanges per flow. RSS ranged
from 118328 to 132860 KiB, with 40-43 file descriptors. Both WARP modes
kept one outer generation. The independent verifier recomputed every
recorded TCP digest and checked the resource bounds and retained executable.
All 33 frozen source/manifest/lockfile hashes matched that run's source, and
all 392 parent-file hashes remained unchanged during the initial audit. The retained summary is
`target/evidence/soak-summary-20261101T075137Z-173871.json`, with the
corresponding `soak-manifest-20261101T075137Z-173871.json` in the same
directory. The frozen runner's SHA-256 is
`151fadb38ed22faec0945a2daf6aa7aa0b2baa67f34761fe0d6519b4170ddbd9`.
The extended bulk diagnostic's detailed record is
`target/evidence/h3-bulk-diagnostic-1793520941868-166029.json`.

## Earlier restoration results (2026-10-31 UTC)

Historical run on Linux x86_64 without container IPv6, Rust 1.97. These
measurements describe the earlier source, not fresh acceptance of this audit.

| Check | Result |
| --- | --- |
| `scripts/test.sh`: this workspace's tests (`--test-threads=1`) | Passed; 2 long tests ignored and run separately below |
| NF and RS client cores of this repository, 3 ingress x 2 WARP modes | Passed: 12 pairs, 96 TCP/UDP checks, wrong password and TLS name refused |
| Six ingress/WARP pairings: functional, 64 MiB transfers with hash and half-close, HTTP file streaming, UDP MTU drops, idle keepalive, resets and revocation | Passed |
| CLI: one file, `--check`, IPv6 warning, missing `[warp]` and legacy options refused, SIGHUP reload, WARP loss ends the process and closes the listener | Passed |
| Strict Clippy, formatting, `examples/reuse` | Passed |
| network-relay's tests (`cargo test`, 163 unit + 72 integration) | Passed |
| network-relay's integration suite with every tunnel through an egress (`NETWORK_RELAY_TEST_EGRESS=loopback`) | Passed: 72 |
| network-relay's vendored h3 suite (its `[::]` binds changed to IPv4 in a scratch copy, as the container has no IPv6) | Passed: 260 tests and 9 doctests |
| network-relay's quic-go/masque-go and curl interoperability, deployment tests | Passed |
| `diagnose_h3_bulk_with_persistent_pairings`: 16 rounds per WARP mode, 32 HTTP/3 transfers of 64 MiB with six TCP and six UDP flows held | Passed in 323.5 s |
| `scripts/soak.sh`: finite tests, then 3900 s with six TCP and six UDP flows held over both WARP modes | Passed and independently verified: 3919 s measured, 131 samples, every flow at least 3910 s old with at least 393 pings, one outer generation per mode, no packet or queue drops, RSS 120-131 MiB, 40-43 file descriptors |

### Intermittent bulk timeout investigation

An earlier restoration run passed both the diagnostic and the soak, but
subsequent repeated transfers reproduced an H3 timeout. That earlier success
did not establish a root cause. The prior attribution to the canonical
server's connection-credit change was not supported by isolation testing.

The current audit reproduced the stall in an independent duplex TCP test
without HTTP or QUIC. With receive backpressure and packet loss, registry
smoltcp 0.14.0 could replace retransmission with zero-window probing while
bytes were still in flight. Official upstream fixes correct this interaction
and scaled-window/FIN handling. This adapter now uses unmodified official
revision `336a1dd1aaf0eeb1afab5e3b4b479e818a23c03e`, not a local fork.
The failing IPv4/IPv6 TCP regression passes with that revision. Fresh full
acceptance, the extended 128-transfer H3 diagnostic and the new fixed-binary
3900-second soak all passed. The earlier runs were not used as acceptance
evidence for this change.
Parent code and client timeout settings remain unchanged.

## Reproduction

```bash
bash scripts/test.sh
bash scripts/soak.sh
```

## Outstanding deployment gates

On a machine with authorized WARP connectivity, first run the `live-warp`
probe separately with explicit H2 and H3. It must return `warp=on/plus`, a
valid exit IP, tunneled DNS and UDP evidence. Then run the relay with its
ordinary certificate and credentials and test the clients over each chosen
ingress mode. Earlier live attempts (2026-10-14) failed during WARP setup:
numeric H2 returned `Connection refused` and H3 setup timed out; they reached
neither account acceptance nor an exit-IP check.

Use the live download helper with an independently verified checksum for an
artifact of at least 64 MiB, and complete an hour-plus run with held TCP/UDP
connections. Monitor memory, descriptors, socket/task counts, packet drops
and terminal reasons. Native Apple device/profile trust, mobility and
Network.framework behavior must be exercised on those devices.
