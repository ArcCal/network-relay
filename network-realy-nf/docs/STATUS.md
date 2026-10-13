# Implementation status

As of 2026-10-11, version 0.1.0 development. This status belongs only to Network
Realy NF. Historical Masque NF failures are evidence of an inherited risk, not
proof that this new binary has failed or succeeded.

## Implemented and checked in this environment

- Independent Rust core, C ABI, bounded native bridge and copied QUIC adapter.
- HTTP/1.1 CONNECT/CONNECT-UDP Upgrade, HTTP/2 and HTTP/3 request framing, Basic
  authorization and DATAGRAM Capsule parsing/encoding.
- SOCKS5 CONNECT and UDP ASSOCIATE source enforcement and bounded destination
  flow management. Server-side DNS forwarding; no client IP-stack dependency.
- 43 unit tests, 25 native-boundary tests and 6 FFI lifecycle
  tests passed (2026-10-13). They cover malformed Capsule handling, queue bounds, EOF/error
  propagation, opposite-pump failure wakeups, probe renewal, half-close, cancellation isolation, terminal security failures, retried 502/503/504, connection aborts
  and native initialization/exit while routine core logs are suppressed.
- `cargo check` and project-only Clippy with warnings denied passed on Linux.
  This establishes Rust compilation, not Swift
  compilation, application packaging or Apple runtime behavior.

The real Rust and Go/Caddy server matrices passed all three transports, including
SOCKS TCP/UDP, certificate-name rejection, source pinning, fragment rejection and
native-resource cleanup in the emulator. Real-server results are recorded in [evidence/interop-results.json](evidence/interop-results.json).
Only cases actually reported PASS in that file count as verified. The emulator
uses test-only rustls/Quinn in place of Network.framework; its PASS cannot be
promoted to a native interoperability claim.

## User-reported Mac execution

The user built and launched source revision
`666b795c881b44eeaade9891edfae04ffcbd34a6` on a Mac. Application/native/core logs
establish that the renamed binary and native bridge ran. Following account
troubleshooting on Rust network-relay, a SOCKS HTTPS request returned Google's
200 response and the UDP observer received a matching DNS response with eight
answers. [Selected evidence and coverage](evidence/native-mac-20261011.md).

The later cumulative trace now attributes these positive native results to
forced HTTP/2 run `810BA952`. Native H3 runs `5FBDACF5` and `30625FF0` reach
admission but repeatedly fail with group EINVAL approximately ten seconds later.
Run `E5EF8AE9` shows a different H2 incident: clean readiness-probe EOF after
300.001568 seconds. [Current trace and provenance](evidence/native-quic-20261011.json).
Complete build/test/signature output, native Caddy results and sustained native
H3 forwarding are still missing.

## Implemented, requiring further Mac verification

- SwiftUI/AppKit window, icon, menu bar, independent store and TOML import/export.
- Automatic restart after server/transport selection; retaining the active server
  when saving a new blank server. Copied portable model tests are included.
- Native TCP/TLS, local SOCKS TCP/UDP and NWConnectionGroup QUIC adapter.
- Streams-only HTTP/3 Capsules, no DATAGRAM extraction, actual SID diagnostic log.
- macOS build, signing/bundling script and native boundary smoke runner.
- Five live log levels, ordered from Everything to Errors Only, with the copied
  Masque NF log view, bounded retention, complete-buffer copy/save and embedded
  source/build identity. Detailed records relay host/SNI and real QUIC stream
  IDs/parents; Everything adds I/O metadata. The reported application launch
  establishes compilation of that revision; the log controls and broader GUI
  interactions still require their own runtime checks.

No macOS SDK is available in this environment. These Swift sources and Mac
commands have **not** been compiled or executed here. The user-reported Mac
results above are separate from the checks executed in this environment.

## Confirmed defects repaired in source

- (2026-10-13) A late nonempty receive callback after Rust removed a resource
  was reported as `Native stream receive queue overflow`. The DATA boundary now
  distinguishes accepted content, a closed resource, a full live queue and
  invalid input. Swift ignores already-closed delivery without replacing the
  original error; real queue saturation still fails the stream. Queue bounds,
  pull-driven reads, EOF delivery and the legacy boolean ABI remain unchanged.
  Four new regression tests cover closure, saturation, parallel-flow isolation
  and FFI results. [Investigation and validation](evidence/receive-callback-20261013.md).
- (2026-10-13) A user-reported macOS 27.0.1 crash entered
  `nw_quic_set_application_error` from `NativeClient.close`, then called
  `strlen(NULL)`. QUIC group closure now supplies an explicit empty reason
  instead of the initializer's optional nil default, preserving the error code.
  An independent open-source implementation documents the same workaround.
  This native workaround still requires a Mac retest; portable tests cannot
  establish its runtime effect. See the crash section in the same evidence file.
- HTTP/2/3 stream pump failure could leave opposite pending I/O asleep. Both
  directions now wake, preserve the first cause and deliver buffered response
  bytes before a read failure. Three regression tests pass.
- The idle readiness probe's normal EOF was reported as a relay failure. The
  source now renews admission every 60 seconds and refreshes clean FIN without
  warning/failure status, preserving independent SOCKS flows and selected
  transport. Four regression tests pass; native/malformed errors remain failures.
- Retry delay no longer stays at 30 seconds after a long admitted session;
  a readiness interval of at least 30 seconds resets it to one second. Short H3
  flaps retain exponential backoff. H3 driver termination is logged at DEBUG.
- (2026-10-13) Every HTTP refusal was terminal, so a 503 from a relay at its
  tunnel limit (or a 502/504) on the readiness probe ended the whole client: all
  SOCKS sessions closed and nothing reconnected. Reproduced against both servers
  with `max_tunnels_per_user = 1` over HTTP/1.1, HTTP/2 and HTTP/3. 502, 503 and
  504 are now retried with backoff and shown as reconnecting; the client becomes
  ready again once a tunnel is free. Credential, request and TLS rejections stay
  terminal.
- (2026-10-13) When a tunnel failed mid-transfer (the destination reset, so the
  relay reset the HTTP/2 or HTTP/3 stream or dropped the HTTP/1.1 connection),
  the SOCKS program's connection was closed with FIN: a cut-off download looked
  complete. The core now aborts that connection (CLOSE with `native::ABORT`) and
  the app resets it with `NWConnection.forceCancel()`. Through the emulator the
  program now sees ECONNRESET on every transport with both servers. **The Swift
  change has not been compiled or run** (no Swift toolchain here).

These are portable source repairs. No Mac retest establishes that the new binary
runs them correctly or that they stop the unrelated native H3 EINVAL.

## Confirmed issues and limitations

- **This new client's native H3 is unstable.** Several forced H3 connections are
  admitted and then fail with native group EINVAL about ten seconds later.
  Business-flow groups also fail. The trigger is not proven and is not repaired.
  [Research and handoff](QUIC-RESEARCH.md).
- H1 logs include a control connection reset and individual flow timeouts; H2
  logs include individual flow resets. Their causes are unconfirmed. Do not
  declare all TCP transports stable for long sessions from the one positive H2
  forwarding test, or treat every per-flow reset as a global relay failure.
- Historical Masque NF/removed Swift failures are separate CONNECT-IP evidence;
  the old response timeout must not be substituted for this admitted-H3 fault.
- The complete Apple-to-both-server acceptance matrix and build/test/signature
  artifacts are missing. Therefore “perfect interoperability” has not been delivered.
- One outer connection per flow can exhaust restrictive server connection limits
  and adds handshake overhead. Shared HTTP/2/3 connections are not implemented.
  Measured 2026-10-13 with default limits: network-relay accepts 64 connections
  per client IP over TCP and QUIC, and caddy-network-relay 64 HTTP/3 connections
  (HTTP/2 was not limited at 80). Beyond about 63 concurrent SOCKS flows (the
  readiness probe holds one connection), new flows fail.
- The client waits 10 seconds for a CONNECT response; network-relay may take up
  to 15 (5-second DNS timeout plus its default 10-second connect timeout). A slow
  destination can therefore fail as a client timeout rather than the relay's 504.
- Readiness verifies authenticated CONNECT-UDP admission only. It sends no target
  traffic or heartbeat, can be denied by destination policy, and cannot establish
  Internet reachability or continuously verify every independent SOCKS flow.
- Custom UDP templates are accepted only by core configuration, not by the GUI.
  Mutual TLS/client-certificate identity, BIND, SOCKS UDP fragments, Intel builds
  and pre-macOS-27 support are not implemented.
- Reliable UDP Capsules have head-of-line blocking. Native QUIC DATAGRAMs, path
  MTU optimization and full-size IPv6 UDP are intentionally absent.
- Passwords use the copied private-file store; Keychain integration and independent
  security audit are pending. Ad-hoc signing is not notarization.

## Native confirmation, 2026-10-11 14:12–14:16 UTC

A Mac run of `97479f7` ([evidence](evidence/native-http3-20261011-1412.md))
logged `groupSID=0` for every group and every request on SID 4. Seven
QUIC groups failed as the **group** object, with POSIX 22, 10.36–11.60 s
after their first request. HTTP/2 and HTTP/1.1 controls stayed up. This
confirms natively the client side of the idle-stream-0 chain. The server
event is inferred from source and emulator, not yet logged. The group API
cannot use stream 0, so the repair is server-side.

## Server repair, 2026-10-11 (implemented and tested; native confirmation pending)

With server changes permitted, both relay servers now start the HTTP/3 header
deadline at a request stream's first byte and leave an unwritten stream open:
network-relay `9821c4f`, caddy-network-relay `ef04df6`. Network Realy NF is
unchanged. Against the rebuilt servers, `Core/tests/idle_stream_zero.rs` sees
no event on stream 0 thirteen seconds after admission (before: reset at
10.01 s), and the unchanged real-server matrix passes over HTTP/1.1, HTTP/2 and
HTTP/3 ([evidence](evidence/native-http3-20261011-1412.md#server-repair)).
Native confirmation needs a deployed fixed server: no group `POSIX 22` about
ten seconds after the first request, and HTTP/3 sessions that stay up.

## Possible issues, not established root causes

- Initial bidi ownership and an implicit idle SID 0 may interact with the
  servers' ten-second header rejection and Apple's group lifecycle. Since
  2026-10-11, two of the three steps are established without a Mac
  ([evidence](evidence/idle-group-stream-zero-20261011.md)). Apple documents
  that the group owns stream 0 with no I/O on it. Before their repairs
  (network-relay `9821c4f`, caddy-network-relay `ef04df6`), both relay
  servers reset and stopped an idle stream 0 about ten seconds after the
  first request: the Rust relay with H3_REQUEST_REJECTED,
  caddy-network-relay with H3_REQUEST_INCOMPLETE. The emulator measured
  both. Still unverified:
  that Network.framework turns that reset into the group EINVAL, and which
  server build is deployed. Group failures are now logged at WARN to settle
  this on a Mac.
- Stream-only extraction may avoid DATAGRAM lifecycle coupling, but no Mac A/B
  has shown that it fixes the earlier failure. Disabling GREASE is also unproven.
- Native UDP overflow, address rebinding, network migration, long idle sessions
  and EOF/cancellation races need real Apple runtime testing.
- The user-reported build/launch establishes that the renamed code linked and
  ran for the supplied revision. It does not verify every GUI action or the
  portable Swift tests and native smoke gates.

## Deferred work and QUIC stopping rule

The native H3 stopping rule has been reached. Preserve the failing runs and use
forced HTTP/2; do not spend this delivery replacing the QUIC backend. A future
repairer can select a bounded A/B from the report without changing either server
in this task. Confirm the new source fixes on a Mac and complete native H2 TCP/UDP
against Caddy, then the remaining UI, security, concurrency and long-session gates.
