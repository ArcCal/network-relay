# Local WARP packet-backed acceptance matrix

The peer in `tests/support/warp_peer.rs` emulates the observed Cloudflare WARP
wire forms locally. It is **not Cloudflare**. These results establish local
transport, packet routing, frontend interoperability and resource behavior;
they do not establish live enrollment, a public Cloudflare exit identity, or
reachability of Cloudflare's real endpoints.

Only the relay ingress and the peer's outer H2/H3 transport use host loopback
sockets. The peer's HTTP port 80, TCP port 7 echo, TCP port 9 reset, UDP port 7 echo, and DNS port 53 services
run on its own userspace `NetStack`. Client business packets must cross the
production `WarpEgress` packet pump before reaching those services. The peer
checks assigned source/destination IPs, packet lengths, mTLS enrolled-client
SPKI and CertificateVerify signatures, and independent framing; its byte,
packet and DNS-query observations support the application assertions.

| Coverage | Test / evidence |
| --- | --- |
| All six inbound H1/H2/H3 × fixed WARP H2/H3 pairings, TCP and UDP | `six_inbound_warp_transport_pairings_use_real_packet_egress`; seven unchanged standard `check::run` outcomes per WARP mode |
| Frozen NF and Rust client cores against every frontend/egress pairing | `client_interop.rs`; source-hash-verified client fixtures prepared by `scripts/prepare-client-tests.py` |
| Cloudflare H2 plain CONNECT + `cf-connect-proto` + bare-IP type-0 capsule | Peer request/header/packet assertions; `h2_capsules` counter |
| Cloudflare H3 `cf-connect-ip`, quarter-stream/context 0 DATAGRAM, full-route capsule | Peer protocol/framing assertions; `h3_datagrams` and route-advertisement counters |
| Server key pin and enrolled client key rejection on both transports | `server_pin_and_enrolled_client_key_mismatches_are_rejected` |
| UDP source pinning, oversize rejection, valid traffic after oversize | `tunnel_dns_udp_peer_pinning_oversize_auth_and_terminal_failure` |
| Client-facing UDP 1400 silently drops, then UDP 1200 echoes on the same flow in every pairing | `udp_mtu_frontend.rs`; peer counters prove only 1200 reached the service; H3 oversize uses request DATA, valid echo proves QUIC DATAGRAM |
| DNS A/AAAA, NXDOMAIN, truncated UDP → TCP fallback, pending DNS wakes on WARP death | Same failure test; peer records DNS wire queries and TCP-query counter |
| Wrong user/password, new-request rejection after revocation | Same failure test using all standard ingress checks |
| Held H1/H2/H3 TCP and UDP flows stop after active revocation | `persistent_pairings_relay_inner_resets_and_active_revocation` |
| Inner TCP RST produces H1 error and exact H2/H3 CONNECT_ERROR | `inner_rst_and_malformed_control_map_to_exact_inbound_codes` |
| Malformed oversized capsule rejected from its header; illegal datagram on TCP | Same protocol failure test, exact H2 PROTOCOL_ERROR / H3 DATAGRAM_ERROR |
| Nonboolean H3 DATAGRAM/extended-CONNECT settings reject with exact H3_SETTINGS_ERROR, while valid and unknown settings work | `h3_settings_validation.rs`; wire regressions and vendor frame tests distinguish published RFC rules from the legacy draft extension |
| Repeated 64 MiB byte integrity, streaming memory, FIN/half-close | Two transfers per pairing, each 64 MiB in both directions, SHA-256 and exact peer TCP byte counters |
| Actual HTTP GET of a known 64 MiB file on all six pairings | `http_file_matrix.rs`; Content-Length 67108864; SHA256 `6e337e4992fc84fc2744a38b784928aaaf460757861b749fcb01c066fbb80780` |
| Truly idle outer WARP transport with keepalive, no business packets for 65 seconds | `idle_outer_keepalive_and_active_inner_flows_survive_two_idle_windows` |
| Actual root CLI wiring, offline check, transport validation and terminal shutdown | `cli_warp_wiring.rs` launches the built `serve` binary on both transports |
| At least one hour of held business connections, mixed traffic and metrics | PID 138810 passed its 3900-second target; ignored by the finite runner and executed explicitly with frozen-binary/source verification |

## Completed synthetic soak

PID 138810 finished on 2026-10-15T00:01:47Z with actual test exit 0 and
independent verification passed. Its [manifest](soak-manifest-20261014T225555Z-138810.json),
[metric log](soak-1792018581928-138810.jsonl) and
[independent summary](soak-summary-20261014T225555Z-138810.json) bind the exact
frozen executable and source to the completed 3900-second target.

| Observation | Completed result |
| --- | --- |
| Metric samples / measured time | 131 / 3925.266063896 seconds |
| Held business flows | Six TCP and six UDP, covering all six pairings |
| Minimum held-flow age / activity | 3920.017192809 seconds / 394 pings |
| Outer generations | One per WARP transport |
| Reported production packet/queue drops | Zero |
| Process RSS | 118632–130004 KiB |
| Process file descriptors | 40–43 |

The independent verifier checked the frozen binary, matching production source,
metric-log binding and its independently generated expected TCP hash at every
sample. These observed resource bounds apply to this workload and duration.
The [final audit](soak-final-audit-138810.json) reran the verifier and checked
all 398 frozen source hashes. Its late cleanup observation found the test
runner, matrix launcher, captured socket identities/endpoints and two fixture
directories absent. The detached Python wrapper remained a PID-1-adopted zombie
with reported `FDSize: 0`; immediate post-exit external cleanup timing was not
observed. This is not a claim that every process was reaped.
The earlier PID 128443 timeout remains unresolved; this pass and the separate
diagnostic stress do not prove it was corrected. The [bounded timeout review](../review/SOAK-TIMEOUT-REVIEW.md)
records that distinction. This remains synthetic evidence; live Cloudflare
exit/download/stability and native Apple execution are outstanding gates.

## Reproduction and retained earlier outcomes

Run the finite packet-backed acceptance suite from the project root with Rust/Cargo on PATH:

```sh
python3 scripts/test-matrix.py
```

Run a 65-minute soak only after that finite suite passes:

```sh
python3 scripts/test-matrix.py --soak-seconds 3900
```

The runner first exercises the evidence verifier's rejection guards, verifies and
builds the frozen client fixtures through the visible `scripts/prepare-client-tests.py`
script, then runs the seven packet-backed acceptance integration-test targets.
It clears inherited `CARGO_BUILD_TARGET` so the clients run on the current machine.
The runner uses project-local Cargo home, target and temporary directories,
`--locked`, and a copied test executable for the soak. Its manifest contains the
binary SHA-256 and source SHA-256 hashes across `src`, `crates`, `vendor` and
`tests`. This makes a running snapshot distinguishable from subsequent edits
and avoids holding the Cargo build lock for an hour.
Completed manifests also bind the exact metric log path, process ID and SHA-256;
the runner retains a copy under `docs/evidence/soak-manifest-*.json` and verifies
that evidence independently before returning overall success. Summaries refer
to the retained manifest, while its `binary_path` identifies the frozen local
executable under the ignored runtime directory.

Every WARP mode keeps one outer generation and three TCP plus three UDP
business flows, one per ingress transport, open for the entire soak. Independent
workers send deterministic sequence pings every 10 seconds, accumulating TCP SHA-256.
The main loop records RSS, file descriptors, socket counts, workers, packet/byte
counters, reported queue drops, held-flow ages and sequence counts every 30 seconds.
It also runs fresh standard probes and periodic 64 MiB transfers. Final checks
require each held flow to exceed 3600 seconds, no outer-session restart, and successful
resource shutdown. Metrics are JSONL under `docs/evidence/soak-*.jsonl`;
manifests are under `target/test-runtime/soak-*/manifest.json`.
Resource gates require positive RSS and file-descriptor observations from Linux
`/proc`. New samples include `metrics_available`; inaccessible or unsupported
metrics fail the bulk/soak resource gates explicitly. Standalone functional probes
can report unavailable metrics without asserting memory bounds. The independent
`tests/support/verify_soak.py` checker rejects pending/failed manifests, missing
resource measurements, changed production sources, retained-flow restarts and
TCP digests that differ from its own Python sequence generator.

The resource-availability guard was added after the earlier PID 91781 snapshot.
Its targeted test, `resource_gates_reject_unavailable_and_nonpositive_observations`,
passed separately, and `cargo clippy --locked --test warp_matrix -- -D warnings`
passed. These follow-up checks are separate from the earlier 598-test workflow.
That interrupted Linux log uses the earlier schema without `metrics_available`;
the independent verifier requires every recorded RSS and FD value to be positive.
The replacement snapshot includes the guard and explicit availability flag,
and the complete 604-test workflow includes its regression. No production
source changed for that test-only guard; the later H3 settings correction is
separately documented and included before the replacement snapshot.
The Python verifier regression suite also passed 29 checks: synthetic positive
controls and rejection of pending/failed manifests, wrong log/PID/digest binding,
zero/unavailable/missing resource metrics, stalled flows, bad TCP digests, outer
restarts, production hash/file-set changes, and a wrong frozen executable hash.
Every applicable rejection ran in both normal and evidence-only modes. Its
project-local temporary fixtures were removed. Results are retained in
`verifier-regressions-20261014.json`; these synthetic guard tests are not a soak.

The initial preliminary run is retained as a **failed** run. It used 30 seconds between
held-flow pings, matching the unchanged standard H3 client's default 30-second QUIC
idle timeout. The failure was reproduced separately as exact
`quinn::ConnectionError::TimedOut`, while WARP remained available. The corrected
harness uses 10-second activity without changing or disabling the client's idle limit.
The subsequent production frontend forced-shutdown correction also required a
new binary snapshot. A preliminary partial log is never counted as a passed
one-hour run.

The subsequent PID 91781 run was interrupted by SIGKILL after 114 samples and
3390.309663 measured seconds (56.5 minutes). Its original tool session was no
longer available, and the launcher never wrote a completion result. The Linux
zombie wait status was exactly 9, establishing SIGKILL; the origin is unknown.
The timing is consistent with a bounded tool-session lifetime, but this is not
proven. This is **not** a one-hour pass or a demonstrated transport assertion
failure. The tracked manifest is `soak-manifest-20261014T205453Z-91781.json`;
`soak-interruption-91781.json` records the diagnosis and explicit cleanup of
the two owned ephemeral fixture directories. Graceful test cleanup was not
observed. The verifier rejects this manifest even in evidence-only mode.

The completed replacement uses the corrected production H3 SETTINGS parser
after finite validation. For future runs in a cloud tool session with a bounded lifetime, use
`python3 tests/support/start_detached_soak.py --seconds 3900` with the project
environment already active. This launches the gated runner in a separate
session and saves output plus worker/matrix PIDs under `target/test-runtime`.
Any launch record alone means acceptance is pending; final worker, soak-manifest and
independent-summary results must all be checked after actual completion.

The detached replacement PID 128443 passed all seven finite preflight targets,
then **failed** at 22:35:59 UTC with Rust test exit 101 and `Connection error:
Timeout`. It recorded 20 samples, ending at cycle 19 / 570.216823 measured
seconds; the failure occurred during cycle 20's periodic inbound H3 bulk work.
The original error lacks the failing WARP mode or send/receive/FIN phase. Its
exact boundary is the unchanged inbound H3 client's QUIC timeout; this does
not establish whether the underlying stall is a client, fixture or production
defect. Timeouts have not been raised. The tracked manifest is
`soak-manifest-20261014T222452Z-128443.json`; `soak-failure-128443.json` and
`soak-failed-128443-output.txt` preserve diagnosis and original output.
This is not a one-hour pass. Test-only diagnostics now record operation stage,
byte progress, client close reason/stats and peer/egress observations.

The subsequent ignored H3 diagnostic stress test passed with actual test exit 0
after 434.01 seconds: 16 rounds on each fixed WARP mode, 32 transfers of 64 MiB,
2 GiB sent and echoed in each direction, with all twelve retained business flows
active. It preserved the unchanged client's idle limit. This did **not** reproduce
or resolve the prior timeout and is not a one-hour soak. Exact executable hash,
test output and evidence links are retained in
`h3-bulk-diagnostic-summary-131141.json`.
After moving the diagnostic's passed-evidence write after successful cleanup,
a one-round follow-up also passed with exact exit 0 in 27.23 seconds (two
64 MiB transfers, one per WARP mode). Its result is retained in
`h3-bulk-cleanup-order-summary.json`. The completed detached PID 138810 run
kept all timeouts unchanged and passed all seven finite preflight targets
before its 3900-second held-flow clock. Its passed result and exact metrics
are recorded above; they do not resolve PID 128443's earlier failure.

Observed initial bulk evidence: 768 MiB sent and echoed in each direction across
the six pairings. For the six repetitions on forced WARP H2, measured RSS growth
was 5544 KiB; for forced WARP H3 it was 1604 KiB. Those initial artifacts preserve
their dates and source context. The completed final runner retained fresh
evidence for its frozen source; failed, interrupted and merely launched runs
remain distinct from the completed pass.
