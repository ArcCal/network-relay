# Late receive callbacks reported as queue overflow

## Diagnosis

The user's Network Realy NF build identifies source
`628935d01c6e22b33daf9e457da68a7d1f7bf6c5`. Its Swift receive callback labels
every false `nf_input(DATA)` result as `Native stream receive queue overflow`.
The Rust result also means that the resource is absent or its receiver closed.

Rust can remove a resource and enqueue CLOSE while a native receive callback is
already pending. Before Swift consumes CLOSE, its local connection still exists,
but Rust rejects the late content. This reproduces the diagnostic condition with
an empty queue. It does not establish a Network.framework capacity defect.

Eight messages occur in the supplied cumulative log:

- Rust server, HTTP/2 run `EC934F09`: resources 1249, 1885, 2134 and 2424 during
  normal readiness-probe renewal, followed by successful replacement probes.
- Caddy server, HTTP/3 run `15B4705B`: resource 97, immediately after a local
  SOCKS connection reset.
- Caddy server, HTTP/3 run `2E39D356`: resources 911, 667 and 2099, likewise
  immediately after local SOCKS resets.

The close race fits these observations. The old boolean interface did not
record which rejection branch occurred, so the individual live events cannot
all be conclusively classified from that log alone. The earlier inference that
these messages proved saturation causing the SOCKS failures was too strong.

## Minimal repair

The additive nonempty-DATA API returns Accepted, Closed, Full or Invalid. The
legacy boolean API and its EOF behavior remain available. Swift ignores late
Closed deliveries without replacing the original terminal error. Full still
fails the stream with the queue-overflow diagnostic; Invalid has its own error.
The one-slot channel, pull-driven reads, trust checks and data/error ordering
are preserved. No relay server, RS, dependency or wire-protocol change is made.

## Validation

- NF core: 43 unit, 25 native-boundary, 6 FFI lifecycle, one push-frame and one
  portable GSS negotiation test passed (76 total).
- New regressions distinguish a full live queue, a removed resource before
  CLOSE is consumed, a dropped receiver with a retained lease, and invalid FFI
  inputs. They preserve queued bytes, original errors, legacy EOF and parallel
  connections.
- A C smoke program linked to the Rust static library checked the four numeric
  results against the committed bridge header.
- Formatting and NF-only Clippy (`--all-targets --no-deps -- -D warnings`) pass.
  Clippy including path dependencies stops on an existing `type_complexity`
  warning in unchanged vendored h3 code; that code was not altered.
- Real Rust network-relay built from base `628935d` and caddy-network-relay
  `8a0df41`: the unchanged `server_interop` matrix passed over HTTP/1.1,
  HTTP/2 and HTTP/3, including TCP half-close, UDP Capsules, SOCKS forwarding,
  authentication rejection, certificate-name rejection and cleanup.
- Large transfers against Rust passed over all three transports, including
  64 MiB direct/SOCKS downloads, a paused 32 MiB reader and deliberate resets.
  The same checks against Caddy HTTP/2 and HTTP/3 passed in a separate targeted
  run using identical modified production sources and unchanged assertions.

### Existing Caddy HTTP/1.1 abort failure

The first large-transfer run passed all transports against Rust network-relay.
Against Caddy, 64 MiB downloads and the slow-reader check completed, but a
deliberately aborted HTTP/1.1 SOCKS download ended with clean EOF after 8 MiB
minus 106 bytes. Its reset assertion failed. This result was not discarded.

The unmodified `628935d` core reproduced the same failed assertion with the
same Caddy binary. A separate complete baseline run passed, so the result is
timing dependent. The targeted reproduction changed only fixture selection
to Caddy/HTTP/1.1; production code and assertions were unchanged.

The test emulator uses the legacy boolean DATA interface. Caddy's HTTP/1.1
abort path sets TCP zero linger but closes its TLS wrapper; Go can send TLS
`close_notify` before the TCP reset. That is a separate candidate cause for
the clean EOF, not an established consequence of the new Swift result branch.
The server and the large-transfer assertion are outside this small NF repair
and were not changed. This finding does not establish a specification violation
without further investigation of the wire-level close sequence.

### Native QUIC close crash

The user subsequently supplied a crash report for NetworkRealyNF 0.1.0 on
macOS 27.0.1 (26A434), recorded at 2026-10-13 05:16:59 -0700. The network
dispatch queue crashed with EXC_BAD_ACCESS at address zero. Its stack is:

```text
_platform_strlen
String.init(cString:)
Network
nw_quic_set_application_error
NativeClient.close(_:code:)
NativeClient.consume(_:)
```

The group-close code constructs `ApplicationError(code:)`, whose reason
defaults to nil. Apple's API explicitly permits that default; this is not
evidence that omitting the argument violates the documented API contract.
The stack identifies a null-string crash in the framework's error-setting
path, distinct from the receive-delivery diagnostic.

The minimal workaround supplies `reason: ""` when setting group application
error metadata. It retains the application error code and the existing close
and cancellation sequence. RFC 9000 section 19.19 permits a zero-length
CONNECTION_CLOSE reason phrase. No stream-reset code or protocol error is
silently discarded.

Independent source evidence: the g-cqd/HTTP project at pinned commit
`82dee19bbbd656b3c8c079d31a5062a854b47740` documents the same macOS 27
`strlen(NULL)` crash and uses an explicit empty reason in its legacy and
modern QUIC adapters. Its additional platform assertions are not adopted here.

- [Apple initializer](https://developer.apple.com/documentation/network/nwprotocolquic/applicationerror/init(code:reason:))
- [Independent legacy adapter](https://github.com/g-cqd/HTTP/blob/82dee19bbbd656b3c8c079d31a5062a854b47740/Sources/Transport/HTTPTransport/Quic/LegacyQUICConnection.swift#L100)
- [RFC 9000 section 19.19](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.19)

No Apple SDK or native runtime is available in the Linux environment. The
workaround is source-reviewed and independently corroborated, but not claimed
as a natively reproduced-and-verified fix. A fresh Mac build must test sustained
HTTP/3 plus connection closure/server switching and preserve any new crash
report. The crash report itself contains no source commit, so its exact binary
revision must not be inferred from the 0.1.0 bundle version alone.

The ordinary core command skips tests requiring real-server/Kerberos fixtures;
it does not establish native Apple interoperability. The separate server checks
are recorded above. Linux cannot execute Network.framework callbacks or build
the macOS application. A fresh Mac build and native close/transfer observation
remain necessary, using `build-macos.sh` and the existing observation guide.
