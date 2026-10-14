# Independent final source and adversarial review

Review date: 2026-10-14. Scope: this project only. No production source was
changed by the reviewers. The reviewers added two isolated root integration
tests and used the project's locked dependencies and project-owned build paths.

## Findings and disposition

1. **Resolved accepted-client lifetime bug.** Canceling `server::run` in a
   continuing Tokio runtime originally left detached accepted TCP handlers
   running during TLS handshake and ordinary HTTP processing. The independent
   `tests/review_frontend.rs` reproduction sent a partial TLS record, aborted
   and awaited the run task, then waited for client EOF/error. It failed after
   251.565 ms; the configured handshake timeout was ten seconds. The frontend
   author added forced-shutdown handling in `server/over_tcp.rs`, including a
   bounded H2 flush to retain tunnel error delivery. The same independent test
   now passes. This was a server-owner cancellation problem, not host-network
   fallback for relayed traffic.

2. **Resolved live-probe deadline gap.** The original trace probe bounded bytes
   and each frame wait but had no complete-operation deadline. A slow response
   or empty frames could keep one probe and the soak command pending. Download
   checked a body-only deadline after data frames, excluding setup and final
   EOF. Current `examples/live-warp.rs` wraps the whole trace operation in a
   90-second timeout and the whole download operation in a 1,800-second timeout.
   Download still hashes incrementally and checks the expected hash/length;
   trace still bounds its body to 64 KiB and requires the authenticated origin's
   WARP exit marker. The fix was checked in source; this review did not connect
   to Cloudflare or run a live origin download.

3. **Resolved CLI naming mismatch in current source.** Helper output originally
   named the original `network-relay` executable/service, even though this
   independent application is `network-relay-cf-masque`. The parent updated the
   displayed commands and reload service names. The canonical config pathname
   is still an installation convention; use an explicit project configuration
   when running this experimental server.

4. **Provenance refresh needed after dependency-path changes.** The canonical
   H3-Quinn transport source and license remain unchanged. Its manifest now
   references local `../h3` and `../h3-datagram`, improving standalone reuse.
   At the last reviewer hash check, `vendor/h3/UNION-SOURCE-HASHES.json` still
   recorded older hashes for `vendor/h3-quinn/Cargo.toml` and `Cargo.lock`.
   Refresh those hashes and wording that still describes git resolution after
   the parent finishes manifest/lock changes. This affects the reproducibility
   metadata, not packet framing or the retained MIT source license.

5. **Concrete Windows compile limitation; not a validated target.** The
   non-Linux `set_mark` signature at `crates/warp-egress/src/masque.rs` uses
   `std::os::fd::AsFd`, which is a Unix descriptor interface and is unavailable
   on Windows. It should use an unconstrained generic parameter in the
   unsupported-platform error function if Windows support is intended. Linux
   is the actual execution target of this review; no Windows or native macOS
   build was performed. Avoid a Windows portability claim until it is addressed
   and checked.

## Egress judgments supported by source and tests

- Transport selection is explicit: only H2 or H3 is configured. No reviewed
  failure path switches HTTP versions, substitutes a host resolver, or dials a
  business destination with a host socket. Numeric edge addresses are separate
  from SNI and logical HTTP authority; enrollment is external.
- Device authentication uses a P-256 client certificate signed by the enrolled
  key. Peer verification compares exact DER SubjectPublicKeyInfo and still
  verifies TLS CertificateVerify signatures with the configured crypto provider.
  Mismatched endpoint keys and unknown client keys are rejected by local tests.
  Registration debug and parse errors redact credential contents.
- Terminal stack failure is monotonic. It wakes socket operations and DNS
  waiters, invalidates cached/literal DNS lookups, clears packet queues, and
  aborts TCP state. A new controller does not attach old sockets to a new
  generation. The final controller owner is separate from surviving socket
  state, so dropping that owner can invalidate sockets that remain owned by an
  embedding application.
- The reviewer added `tests/review_controller_drop.rs` using the real packet
  pump and authenticated local H2/H3 peer. Dropping a nonfinal clone preserves
  availability; dropping the final clone interrupts already-pending TCP and UDP
  reads with `ConnectionAborted`, and subsequent UDP sends fail. Both transport
  cases passed.
- Connected UDP pins its numeric peer and serializes readers/writers so the
  userspace stack's single socket waker cannot be overwritten by concurrent
  callers. Socket counts, packet queues, and per-socket buffers are bounded.
  TCP abort controls check socket-owner identity before touching a reused handle.
- MTU changes recheck UDP payload limits, wake waiting UDP operations, disable
  IPv6 below 1280 bytes, and reset existing affected TCP flows. DNS EDNS capacity
  follows the reachable DNS server's family and current UDP limit. The current
  tests cover capability loss/restoration and do not revive old TCP flows.
- Frontend DNS/TCP/UDP opening uses injected `Egress`. Auth, request validation,
  policy refusal, quota waits, half-close/reset, and terminal error paths retain
  the standard relay behavior in the reviewed adaptation. Existing policy and
  protocol tests are separate from actual Apple native execution.

## H3 union, licensing, and reuse

The initial independent source comparison found exactly seven H3 source changes
from the canonical snapshot for the reviewed client additions and regressions.
The later mandatory SETTINGS-value correction below is an additional behavior
change within one of those seven files. No canonical H3 `server/**` source,
request header validator, `connection.rs`, typed error representation, or
H3-Quinn transport source changed. Both MIT
licenses are identical to the canonical input. The local H3-Datagram source and
license match their pinned source manifest.

Every reviewed Cargo path dependency resolves inside this project. The egress
crate depends on the local H3/H3-Quinn union directly, and the independent
`examples/reuse` workspace has no dependency patches or frontend dependency.
Keep the project-owned vendor directories when using this path dependency;
copying the egress crate directory alone does not include its reviewed HTTP/3
dependencies. Package publication and Windows support were not tested.

## Independent checks

Executed with `CARGO_HOME=$PROJECT/.build/cargo-home` and
`CARGO_TARGET_DIR=$PROJECT/target/review`:

```sh
cargo test --offline --locked -p warp-masque-egress -- --test-threads=2
cargo test --offline --locked --test review_frontend --test review_controller_drop
cargo test --offline --locked --manifest-path vendor/h3-quinn/Cargo.toml --all-features
cargo check --offline --locked --manifest-path examples/reuse/Cargo.toml
```

Observed: 78 egress unit tests and one doctest passed; both independent review
tests passed after the accepted-client fix; H3-Quinn's structured transport error
test passed with optional datagram support. The independent consumer workspace
also passed its offline locked check, resolving the egress crate and local H3
dependencies without consumer dependency patches or the frontend crate.

No live WARP exit was established by this review. Local authenticated fake-peer
results demonstrate framing, injection, and lifecycle behavior; the reported
real H2 refusal and H3 timeout remain distinct outcomes. Large-transfer and
one-hour soak evidence belong to the separate matrix runner and are not claimed
as reviewer executions here.

## Integration dispositions

The root author subsequently refreshed both H3-Quinn manifest/lock hashes
and local-path documentation. `scripts/verify-provenance.py` passes. The CLI
also uses independent default `config/relay.toml` instead of the parent service
configuration path. The documented Windows target limitation remains.

## Later focused H3 settings review

Recognizing draft-00 DATAGRAM setting `0x276` is permitted by HTTP/3 extension
rules. Its local advertisement defaults off, and the standard relay builder
does not enable it; standard DATAGRAM authorization still uses `0x33`.

The review nevertheless found an inherited mandatory validation gap:
`SETTINGS_H3_DATAGRAM (0x33)=2` decoded successfully and became `true`.
RFC 9297 section 2.1.1 requires values other than 0 or 1 to terminate the
connection with `H3_SETTINGS_ERROR`. Extended-CONNECT setting `0x8` has the
corresponding RFC 9220 requirement. The recognized legacy `0x276` boolean
also has a draft/private-dialect rule, distinct from the published RFC.
The correction is confined to this project's copy; its old-fail/new-pass
unit and exact QUIC wire evidence is recorded separately.

RFC 9114 section 7.2.4 says senders must not duplicate setting identifiers,
but receiver duplicate rejection is optional (`MAY`). Accepting duplicate
unknown identifiers is therefore not a proven receiver violation. No extra
identifier collection or settings-count limit is added for that optional case.
