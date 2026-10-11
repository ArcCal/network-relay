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
- 37 unit tests, 21 native-boundary tests and 5 FFI lifecycle
  tests passed. They cover malformed Capsule handling, queue bounds, EOF/error
  propagation, opposite-pump failure wakeups, probe renewal, half-close, cancellation isolation, terminal security failures
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

## Possible issues, not established root causes

- Initial bidi ownership and an implicit idle SID 0 may interact with the
  servers' ten-second header rejection and Apple's group lifecycle. Since
  2026-10-11, two of the three steps are established without a Mac
  ([evidence](evidence/idle-group-stream-zero-20261011.md)). Apple documents
  that the group owns stream 0 with no I/O on it. Both relay servers reset
  and stop an idle stream 0 about ten seconds after the first request: the
  Rust relay with H3_REQUEST_REJECTED, caddy-network-relay with
  H3_REQUEST_INCOMPLETE. The emulator measured both. Still unverified:
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
