# Bounded review of the synthetic soak timeout

Source review date: 2026-10-14; completion evidence updated 2026-10-15 UTC.
Scope: this project, its retained evidence, and its
project-owned dependency cache. This review made no production, test, or
dependency changes and ran no additional tests or network requests.

**PID 128443 failed, and its root cause remains unresolved.** The later 32 H3
bulk transfers passed but did not establish that the original failure was
resolved. Replacement PID 138810 subsequently passed its 3900-second target
with 3925.266 measured seconds and independent verification. That completed
run establishes its own local acceptance result; it does not establish the
original timeout's cause or correction. All runs discussed here use a local
synthetic WARP peer, not live Cloudflare.

## Retained observations

- The [failed-run manifest](../evidence/soak-manifest-20261014T222452Z-128443.json),
  [process binding](../evidence/soak-run-binding-128443.json),
  [original output](../evidence/soak-failed-128443-output.txt), and
  [failure summary](../evidence/soak-failure-128443.json) identify the actual
  frozen executable and source. The test exited 101 after 666.63 seconds with
  `Connection error: Timeout`.
- Its [metric log](../evidence/soak-1792016720226-128443.jsonl) contains 20
  samples, ending at cycle 19 and 570.216822894 measured seconds. At that last
  sample both WARP modes remained available, had generation 1, six egress
  sockets, six relay tunnels, one authenticated outer session, and zero
  reported packet/queue drops. The retained TCP and UDP flows were advancing.
  These observations describe the last recorded sample, not the unobserved
  failure interval.
- Cycle 10 completed the periodic H2 bulk transfer in both WARP modes; its
  sample was written at 325.054142998 measured seconds. Cycle 20 selects
  inbound H3 bulk and runs the WARP H2 and H3 fixtures serially. The missing
  cycle-20 sample and raw H3 error implicate that bulk work, but the original
  output does not identify the WARP mode or request/send/receive/FIN stage.
- The exact error maps through `vendor/h3-quinn/src/lib.rs:155-168` from
  `quinn::ConnectionError::TimedOut` to H3's connection timeout. The standard
  client's `check::H3::connect` uses Quinn's default transport configuration
  without a keepalive override (`crates/relay-frontend/src/check.rs:301-312`).
  A failure of the test's separate 240-second bulk deadline would instead
  carry `H3 bulk deadline`. This identifies the observed boundary; it does
  not explain why QUIC stopped making progress.
- The [subsequent diagnostic summary](../evidence/h3-bulk-diagnostic-summary-131141.json)
  records actual test exit 0 after 434.01 seconds: 16 rounds per WARP mode,
  32 transfers of 64 MiB, and 2 GiB sent and echoed in each direction with
  six retained TCP and six retained UDP flows. It preserved the client's
  idle limit. The summary explicitly records
  `original_timeout_resolved: false` and `one_hour_soak: false`.
- Replacement PID 138810 has a separate
  [process binding](../evidence/soak-run-binding-138810.json) and
  [metric log](../evidence/soak-1792018581928-138810.jsonl). Its final
  [manifest](../evidence/soak-manifest-20261014T225555Z-138810.json) records
  actual test exit 0 and independent verification passed at
  2026-10-15T00:01:47Z. The [independent summary](../evidence/soak-summary-20261014T225555Z-138810.json)
  records 131 samples over 3925.266063896 measured seconds, six held TCP and
  six held UDP flows, minimum age 3920.017192809 seconds and at least 394
  pings per flow. Each outer mode retained generation 1 with no reported
  production packet/queue drops. RSS ranged 118632–130004 KiB and file
  descriptors 40–43. See the [evidence matrix](../evidence/MATRIX.md) for the
  maintained acceptance record and its limits.
- The [final evidence audit](../evidence/soak-final-audit-138810.json) reran
  verification and checked all 398 frozen source hashes. Its late cleanup
  observation found the runner, matrix launcher, captured sockets/endpoints
  and two fixture directories absent. The detached Python wrapper remained
  an adopted zombie with reported `FDSize: 0`. This does not establish
  immediate external cleanup timing or complete process reaping.

## Dependency identity and source references

`Cargo.lock:1125-1147` pins `quinn 0.11.12` and `quinn-proto 0.11.19`.
The lockfile's SHA-256 matched the original PID 128443 manifest during this
review. The reviewed production files also matched that manifest. The test
harness subsequently gained diagnostics, so current test source must not be
mistaken for the old executable's exact source.

The cached crates declare `https://github.com/quinn-rs/quinn` as their repository.
Their `.cargo_vcs_info.json` files provide these immutable source revisions:

| Crate | Cached VCS commit | Path within upstream repository |
| --- | --- | --- |
| Quinn 0.11.12 | [`eaec0db4bcb698f76df736d89938743c88a2ad5f`][quinn-release] | `quinn` |
| Quinn-proto 0.11.19 | [`8192ed399a26a6e8f0aba43d10ec8badaa5b905e`][proto-release] | `quinn-proto` |

The source was read locally under
`.build/cargo-home/registry/src/index.crates.io-1949cf8c6b5b557f/`.
The upstream links below use those cached VCS revisions; this review did not
fetch or independently compare the remote GitHub files.

## Actual pinned Quinn timers

| Mechanism | Verified behavior | Source and implication |
| --- | --- | --- |
| QUIC idle | Default 30 seconds; keepalive disabled. Effective idle deadline is the larger of the negotiated timeout and three PTOs. Idle expiry produces `ConnectionError::TimedOut`. | [`config/transport.rs:375-392`][q-idle-default], [`connection/mod.rs:1982-1992`][q-idle-reset], [`connection/mod.rs:1202-1203`][q-idle-expire]. Compatible with the observed local H3 error, but the exact last-progress time was not retained. |
| MTU discovery | Default repeat interval 600 seconds after the previous search completes; upper bound 1452 bytes; black-hole cooldown 60 seconds. | [`config/transport.rs:673-683,746-752`][q-mtu-config]. This is a real 600-second default, not evidence that it caused the failure. |
| Key update | First key phase is randomly 10-999 sent packets. Later phases use the AEAD confidentiality limit minus 10,000 packets. | [`connection/mod.rs:302-308`][q-key-initial], [`connection/packet_builder.rs:46-51`][q-key-trigger], [`connection/mod.rs:3571-3583`][q-key-update], [`connection/mod.rs:4072-4075`][q-key-margin]. Packet-count trigger, not a 600-second rotation timer. |
| Old-key discard | Three PTOs from the relevant acknowledgment/start; expiry discards old keys. | [`connection/mod.rs:1639-1652`][q-key-discard-arm], [`connection/mod.rs:1219-1221`][q-key-discard-expire]. No fixed ten-minute age limit. |
| Connection ID lifetime | Default endpoint uses the hashed generator; hashed and random generators default to no CID lifetime. Lifetime tracking returns without scheduling retirement when it is `None`. | [`config/mod.rs:53-61`][q-cid-default], [`cid_generator.rs:49-54,115-118`][q-cid-lifetime], [`connection/cid_state.rs:63-67`][q-cid-track]. The WARP H3 client selects the random generator (`crates/warp-egress/src/masque.rs:431-432`) without adding a lifetime. |
| Path validation | Armed during migration for three times the larger relevant PTO. Expiry restores the previous path if available and clears its challenge. | [`connection/mod.rs:3062-3102`][q-path-arm], [`connection/mod.rs:1223-1229`][q-path-expire]. No periodic 600-second migration timer was found. |

PTO means QUIC probe timeout. No other fixed 600-second timer was found in
the bounded key-update, CID, path-validation, idle, and close-timer review.
That statement is limited to the inspected pinned source, not a claim that
every dependency or operating-system timer has been exhaustively ruled out.

## Why normal MTU re-probing is not an established cause

Quinn's repeat search starts at the **current discovered MTU** and leaves that
MTU in use while searching. It does not reset the path to 1200 bytes merely
because 600 seconds elapsed (`connection/mtud.rs:195-245`). If the current
MTU already equals the 1452-byte default upper bound, the next-probe calculation
returns `None` and sends no new probe
([`connection/mtud.rs:305-350`][q-mtu-search]). On loopback the initial search
would normally reach that upper bound, but the failed run did not log the
actual outer QUIC MTU, so that condition cannot be asserted from its evidence.

When a probe is needed, Quinn sends a padded PING, not a business datagram
([`connection/mod.rs:949-988`][q-mtu-ping]). Lost MTU probes are excluded from
the ordinary congestion-loss and black-hole path
([`connection/mod.rs:1725-1731,1780-1821`][q-mtu-loss]). The project's H3 health
counter also explicitly subtracts sent PLPMTUD probes from the unanswered
application/keepalive count (`crates/warp-egress/src/masque.rs:815-819`). Thus
an oversized probe being lost does not by itself establish either a health
failure or a reduction of the business packet size.

Ordinary packet loss can trigger black-hole recovery and reduce QUIC's current
MTU to its minimum (`connection/mtud.rs:160-170`), after which this project's
500-millisecond MTU checks can change the inner stack's supported packet size
(`crates/warp-egress/src/runtime.rs:328-355`). An inner MTU below 1280 disables
IPv6 and aborts affected TCP sockets
(`crates/warp-egress/src/netstack.rs:239-269`). This is a possible chain to
investigate **if actual packet loss and MTU changes are observed**. It is not
normal periodic re-probing, and the original evidence does not demonstrate
that chain. Its last recorded inner MTU was 1280 in both WARP modes.

The new local H3 bulk connection is fresh at cycle 20, so its own 600-second
discovery interval cannot explain a timeout shortly after opening. Only the
older outer WARP H3 connection could have reached that age; the original
failure does not identify whether its bulk was using WARP H2 or H3.

## Other reviewed paths and remaining hypotheses

The frontend QUIC transport idle limit is 300 seconds
(`crates/relay-frontend/src/server/over_h3.rs:184`). Application idle handling
requires zero active requests; the active-request guard surrounds the awaited
H3 request/pump (`server/over_h3.rs:305-336`, `server/mod.rs:479-497`). These
paths do not establish a ten-minute maximum connection lifetime.

The userspace TCP timeout is 120 seconds, dropped-stream linger is 30 seconds,
and the ephemeral range has 16,384 ports
(`crates/warp-egress/src/netstack.rs:49-60`). Closed/TimeWait lingering sockets
are removed, and current socket ports are excluded from allocation
(`netstack.rs:480-513`). Stable six-socket observations make cumulative
production socket exhaustion an unsupported explanation for this run. The
original log did not contain fake-peer socket-state diagnostics.

Authentication has a 600-second positive-cache lifetime, but each successful
cache use extends it (`crates/relay-frontend/src/auth.rs:550-559`). Thirty-second
standard probes repeatedly authenticate, so this constant does not establish
a ten-minute credential cutoff.

H3 forwarding polls both directions and retains the other direction after one
half finishes (`crates/relay-frontend/src/server/pump.rs:129-224`). A no-progress
or EOF/FIN propagation problem in the client, relay, or synthetic peer remains
a hypothesis. No concrete forwarding defect was established by this review.
A fresh H3 bulk connection also crosses Quinn's early packet-count key-update
threshold, but that is a transfer-stage event and does not establish an age
correlation. The successful repeated transfers do not identify the failed
run's cause.

## Diagnostic decision

No keepalive was added and no client or operation timeout was increased as a
response to this unresolved failure. Either change could let a stalled tunnel
remain alive longer without explaining or correcting the lost progress. The
existing defaults also preserve comparability with the unchanged standard
client and the failed run.

Test-only diagnostics now retain the WARP mode, H3 stage, byte progress,
client close reason/statistics, and peer/egress observations. A useful failure
record should distinguish request setup, active transfer, and final FIN/EOF,
and show outer QUIC MTU/probe/loss counters if that path is suspected. PID
138810's completed passed soak establishes that run's acceptance result; it
does not retroactively turn PID 128443 into a pass or prove its root cause
resolved.

[quinn-release]: https://github.com/quinn-rs/quinn/tree/eaec0db4bcb698f76df736d89938743c88a2ad5f/quinn
[proto-release]: https://github.com/quinn-rs/quinn/tree/8192ed399a26a6e8f0aba43d10ec8badaa5b905e/quinn-proto
[q-idle-default]: https://github.com/quinn-rs/quinn/blob/8192ed399a26a6e8f0aba43d10ec8badaa5b905e/quinn-proto/src/config/transport.rs#L375-L392
[q-idle-reset]: https://github.com/quinn-rs/quinn/blob/8192ed399a26a6e8f0aba43d10ec8badaa5b905e/quinn-proto/src/connection/mod.rs#L1982-L1992
[q-idle-expire]: https://github.com/quinn-rs/quinn/blob/8192ed399a26a6e8f0aba43d10ec8badaa5b905e/quinn-proto/src/connection/mod.rs#L1202-L1203
[q-mtu-config]: https://github.com/quinn-rs/quinn/blob/8192ed399a26a6e8f0aba43d10ec8badaa5b905e/quinn-proto/src/config/transport.rs#L673-L752
[q-key-initial]: https://github.com/quinn-rs/quinn/blob/8192ed399a26a6e8f0aba43d10ec8badaa5b905e/quinn-proto/src/connection/mod.rs#L302-L308
[q-key-trigger]: https://github.com/quinn-rs/quinn/blob/8192ed399a26a6e8f0aba43d10ec8badaa5b905e/quinn-proto/src/connection/packet_builder.rs#L46-L51
[q-key-update]: https://github.com/quinn-rs/quinn/blob/8192ed399a26a6e8f0aba43d10ec8badaa5b905e/quinn-proto/src/connection/mod.rs#L3571-L3583
[q-key-margin]: https://github.com/quinn-rs/quinn/blob/8192ed399a26a6e8f0aba43d10ec8badaa5b905e/quinn-proto/src/connection/mod.rs#L4072-L4075
[q-key-discard-arm]: https://github.com/quinn-rs/quinn/blob/8192ed399a26a6e8f0aba43d10ec8badaa5b905e/quinn-proto/src/connection/mod.rs#L1639-L1652
[q-key-discard-expire]: https://github.com/quinn-rs/quinn/blob/8192ed399a26a6e8f0aba43d10ec8badaa5b905e/quinn-proto/src/connection/mod.rs#L1219-L1221
[q-cid-default]: https://github.com/quinn-rs/quinn/blob/8192ed399a26a6e8f0aba43d10ec8badaa5b905e/quinn-proto/src/config/mod.rs#L53-L61
[q-cid-lifetime]: https://github.com/quinn-rs/quinn/blob/8192ed399a26a6e8f0aba43d10ec8badaa5b905e/quinn-proto/src/cid_generator.rs#L49-L118
[q-cid-track]: https://github.com/quinn-rs/quinn/blob/8192ed399a26a6e8f0aba43d10ec8badaa5b905e/quinn-proto/src/connection/cid_state.rs#L63-L67
[q-path-arm]: https://github.com/quinn-rs/quinn/blob/8192ed399a26a6e8f0aba43d10ec8badaa5b905e/quinn-proto/src/connection/mod.rs#L3062-L3102
[q-path-expire]: https://github.com/quinn-rs/quinn/blob/8192ed399a26a6e8f0aba43d10ec8badaa5b905e/quinn-proto/src/connection/mod.rs#L1223-L1229
[q-mtu-search]: https://github.com/quinn-rs/quinn/blob/8192ed399a26a6e8f0aba43d10ec8badaa5b905e/quinn-proto/src/connection/mtud.rs#L305-L350
[q-mtu-ping]: https://github.com/quinn-rs/quinn/blob/8192ed399a26a6e8f0aba43d10ec8badaa5b905e/quinn-proto/src/connection/mod.rs#L949-L988
[q-mtu-loss]: https://github.com/quinn-rs/quinn/blob/8192ed399a26a6e8f0aba43d10ec8badaa5b905e/quinn-proto/src/connection/mod.rs#L1725-L1821
