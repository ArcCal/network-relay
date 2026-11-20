# Implementation status

## November 20, 2026 macOS validation

The signed NF application launched and 72 Swift tests passed. At the
5000-record cap, reading the severity prefix directly preserved visibility
and retention across 9000 generated lines. Native H2/H3 TCP, UDP and
wrong-root checks ran against both Linux server architectures.
[Log measurements](../../docs/performance-alternatives-2026-11-20.md#native-nf-and-tun-ui-log-retention) and [product interoperability](../../docs/performance-alternatives-2026-11-20.md#product-connection-reuse-and-application-concurrency).

## Server deletion and import/export check, 2026-10-27

The minus button used to remove a server from the settings form only, so
nothing changed until Save. It now deletes a saved server from the saved
settings at once after a confirmation, keeping other unsaved edits; deleting
the connected server moves the connection to its neighbor in the list, and an
unsaved server only leaves the form. Saved server and transport choices still
apply immediately; unsaved or newly imported servers still need Save.
Exports from Network Relay RS (lowercase IDs, its own header, probe targets)
import with every field kept, and NF exports import into RS without loss.
All 56 portable model tests, including three new ones, pass with Swift 6.1.2
on Linux. **The SwiftUI change has only been syntax-checked; it has not been
compiled or run on a Mac.**

## Shared HTTP/2 receive window, 2026-10-26

The shared HTTP/2 connection used a 5 MiB receive window beside 2 MiB stream
windows, so three flows whose data was not being read could take all of it and
stall every other flow on the connection. A new regression opens four such
flows and an active flow on one connection; it timed out before the change and
passes with the connection window at the protocol maximum. Each flow still
buffers at most its 2 MiB stream window. All 97 core tests, Clippy with
warnings as errors and both real-server matrices (network-relay and
caddy-network-relay, HTTP/1.1, HTTP/2 and HTTP/3 over the rustls/Quinn
emulator) pass. A silently dead path needs no client keepalive here:
Network.framework TCP keepalive and `connectionDropTime` already end it.
Network.framework itself remains untested.

## Scoped client repair, 2026-10-16

Changes are restricted to `network-relay-nf/`; neither server nor another client
is modified. HTTP/2 and HTTP/3 sessions now share outer connections, while
HTTP/1.1 retains one connection per tunnel. CONNECT response waiting is separate
from transport initialization and allows the Rust relay's default DNS/connect
budget. Native QUIC options, certificate verification and the earlier resolved
periodic-disconnect repairs remain unchanged. Portable regression results for
this revision are [recorded separately](evidence/client-reliability-20261016.md)
from native Mac acceptance.

GOAWAY retires cached sessions without cancelling admitted streams. A local
HTTP/3 library fix rechecks GOAWAY after waiting for stream credit, preventing
a queued request from sending HEADERS in violation of RFC 9114 section 5.2.
Recovery permits one same-protocol attempt only when native stream creation
fails before any HEADERS could be submitted; submitted requests are never
replayed. Forced HTTP/1.1 handshakes remain independent.

The UI says **Relay Connected** and explains that authentication/admission is
not proof of Internet access. Each server profile now exposes its existing core
`probe_target` as **Admission probe target**, default `1.1.1.1:53`. It accepts a
numeric IPv4/IPv6 address and UDP port allowed by the relay's existing policy.
It sends no target datagrams and does not bypass that policy. The field persists
through JSON storage and TOML import/export; old profiles keep their default.

UDP queue saturation is counted separately in each direction, with bounded
warning frequency and final association totals. Deliveries after queue closure
are counted separately and must not be labelled queue overflow.

The opt-in [native acceptance procedure](NATIVE-ACCEPTANCE.md) and
`scripts/observe-native.sh` record build identity and bounded real TCP/UDP
observations. They do not turn missing Apple SDK/runtime execution into a pass.
The six forced server/transport pairings, held active/idle connections,
sleep/wake and network changes still require the real Mac and current deployed
server binaries.

## Local authentication removal, 2026-10-14

Kerberos/GSS-API support, its UI/settings, native bridge and helper scripts are
removed from Network Relay NF. The local proxy supports only no authentication.
Remote relay Basic authentication and the HTTP/QUIC protocols are unchanged.
The deliberately limited SOCKS5 profile is documented in [SPEC.md](SPEC.md).
Dated test results below describe their recorded revisions before removal; the
current build script runs the remaining checks and native smoke tests.

## Client response update, 2026-10-14

Classic CONNECT now accepts any 2xx across HTTP/1.1, HTTP/2 and HTTP/3.
CONNECT-UDP retains its separate 101/Upgrade or permitted-2xx rules and content
header restrictions, but no longer requires a literal `Capsule-Protocol: ?1`
response. Its known protocol token already defines Capsule framing; unknown
parameters and advisory field values cannot invalidate that agreement.

HTTP/1.1 uses Hyper's supported manual connection handoff so legal classic
CONNECT 204 responses establish real tunnels. It preserves read-ahead bytes,
waits for outstanding native request-write acknowledgement, and keeps native
transport failures. No dependency, server or QUIC transport option changed.
[Validation and remaining limits](evidence/client-response-20261014.md).

The previously reported periodic HTTP/3 disconnect was confirmed resolved by the
user after earlier server idle-stream-0 and client probe-lifecycle fixes. Those
fixes are retained. Older failures below describe older builds and must not be
read as a new reproduction. The current response fix still needs a fresh Mac
build and native retest; Linux rustls/Quinn fixtures do not run Network.framework.

## Earlier implementation record

Post-removal portable validation: 83 Core tests and 50 Swift model tests passed,
with no failures. The original Rust/Caddy server matrices passed HTTP/1.1,
HTTP/2 and HTTP/3, including TCP, UDP, credentials, certificate identity and
cleanup. Three external-fixture tests remain ignored in ordinary Core runs.
These checks use rustls/Quinn emulation; native Mac verification remains separate.

### Mac build initialization-stop follow-up

The user's build of `867152d` passed 84 Core tests, 49 Swift model tests and the
release Swift build. Five native smoke checks passed, but the final immediate
initialization-stop check exited with `operation interrupted` and prevented
packaging. A requested stop could cancel a pending native request before the
initialization future was polled, and the core reported that cancellation as
fatal.

The core now polls initialization first to preserve an already-completed
listener failure, and treats only an `Interrupted` request after an explicit
stop as clean cancellation. No native smoke check is skipped. The previous
source reproduced the failure on attempt 2 of a 1,000-stop stress test; the fix
passed all 9 lifecycle tests and the full 87-test Core suite (4 external-fixture
tests ignored), including 1,000 immediate stops, 50 listener restart cycles and
preservation of a genuine listener failure. These are portable ABI tests; the
Mac native smoke must be rerun by the build script. Protocols, QUIC options,
runtime worker selection and server code are unchanged.

Initial record dated 2026-10-11, version 0.1.0 development. This status belongs only to Network
Relay NF. Historical Masque NF failures are evidence of an inherited risk, not
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
These H3 failures came from older builds and are user-confirmed resolved; see
Confirmed issues and limitations below. Complete build/test/signature output,
native Caddy results and sustained native H3 forwarding are still missing.

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

These source-repair entries retain their original portable validation limits.
The dated update above supersedes their earlier unresolved-H3 classification.

## Confirmed issues and limitations

- **Historical native H3 periodic disconnect: user-confirmed resolved.** Earlier
  builds reached admission then failed about ten seconds later. The old
  [research](QUIC-RESEARCH.md) remains historical evidence; the server idle-stream-0
  and client probe-lifecycle fixes must be preserved.
- **HTTP/1.1 reset versus EOF is not established as a client defect.** A retained
  Caddy build can send TLS close-notify before a later raw TCP reset even to
  standalone OpenSSL, without NF or its emulator. The client must preserve real
  errors and half-closes, not invent an error for an authenticated TLS EOF. See
  [the boundary investigation](evidence/h1-reset-boundary-20261016.md). The exact
  current deployed pairing and Apple boundary still need native verification;
  no server was changed in this task.
- H1 logs include a control connection reset and individual flow timeouts; H2
  logs include individual flow resets. Their causes are unconfirmed. Do not
  declare all TCP transports stable for long sessions from the one positive H2
  forwarding test, or treat every per-flow reset as a global relay failure.
- Historical Masque NF/removed Swift failures are separate CONNECT-IP evidence;
  the old response timeout must not be substituted for this admitted-H3 fault.
- The complete Apple-to-both-server acceptance matrix and build/test/signature
  artifacts are missing. Therefore “perfect interoperability” has not been delivered.
- The old one-outer-connection-per-flow limit is addressed for HTTP/2 and HTTP/3
  by shared sessions. Server tunnel/stream limits still apply, and HTTP/1.1 still
  requires one connection per tunnel. Current-build native concurrency/resource
  verification remains a separate gate.
- CONNECT response waiting now allows 20 seconds rather than 10, covering the
  Rust relay's default 5-second DNS plus 10-second connect budget. Servers with
  longer custom budgets can still exceed this bounded client wait.
- Readiness verifies authenticated CONNECT-UDP admission only. It sends no target
  traffic or heartbeat, can be denied by destination policy, and cannot establish
  Internet reachability or continuously verify every independent SOCKS flow.
  The UI now makes this distinction explicit and permits an allowed numeric
  admission target per server.
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

## Historical server repair, 2026-10-11

With server changes permitted, both relay servers now start the HTTP/3 header
deadline at a request stream's first byte and leave an unwritten stream open:
network-relay `9821c4f`, caddy-network-relay `ef04df6`. Network Relay NF is
unchanged. Against the rebuilt servers, `Core/tests/idle_stream_zero.rs` sees
no event on stream 0 thirteen seconds after admission (before: reset at
10.01 s), and the unchanged real-server matrix passes over HTTP/1.1, HTTP/2 and
HTTP/3 ([evidence](evidence/native-http3-20261011-1412.md#server-repair)).
At that point native confirmation required a deployed fixed server. The user
later confirmed the periodic disconnect resolved; the earlier pending label is
historical and does not reopen that resolved fault.

## Historical hypotheses and remaining native coverage

- The historical initial-bidi/implicit-idle-SID-0 explanation concerned the
  servers' ten-second header rejection and Apple's group lifecycle. Since
  2026-10-11, two of the three steps are established without a Mac
  ([evidence](evidence/idle-group-stream-zero-20261011.md)). Apple documents
  that the group owns stream 0 with no I/O on it. Before their repairs
  (network-relay `9821c4f`, caddy-network-relay `ef04df6`), both relay
  servers reset and stopped an idle stream 0 about ten seconds after the
  first request: the Rust relay with H3_REQUEST_REJECTED,
  caddy-network-relay with H3_REQUEST_INCOMPLETE. The emulator measured
  both. The user later confirmed the periodic fault resolved. The archived
  record still does not directly trace how Network.framework turns that reset
  into group EINVAL, or identify every deployed server build in those older
  captures. Group failures are logged at WARN for
  any new investigation; this is not evidence of a remaining periodic fault.
- Stream-only extraction may avoid DATAGRAM lifecycle coupling, but no Mac A/B
  has shown that it fixes the earlier failure. Disabling GREASE is also unproven.
- Native UDP overflow, address rebinding, network migration, long idle sessions
  and EOF/cancellation races need real Apple runtime testing.
- The user-reported build/launch establishes that the renamed code linked and
  ran for the supplied revision. It does not verify every GUI action or the
  portable Swift tests and native smoke gates.

## Remaining native validation

Preserve the historical failing runs and the user-confirmed resolution. Do not
replace the QUIC backend to address a stale failure description. Run the current
six-pairing [native matrix](NATIVE-ACCEPTANCE.md), with independent security,
concurrency, active/idle long-session, sleep/wake and network-change results.
