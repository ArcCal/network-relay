# Application and wire specification

Revision: 0.1.0 development, 2026-10-11. Normative words describe the acceptance target;
[STATUS.md](STATUS.md) says which requirements have actually been verified.

## Supported protocol profile

| Transport | TCP forwarding | UDP forwarding | Required response |
| --- | --- | --- | --- |
| HTTP/1.1 over native TLS | Classic CONNECT, authority-form destination | GET + `Connection: Upgrade` + `Upgrade: connect-udp` at the UDP template | TCP 200; UDP 101 with Upgrade and Capsule negotiation |
| HTTP/2 over native TLS | Classic CONNECT, `:authority` destination | Extended CONNECT, `:protocol = connect-udp`, expanded HTTPS template | 200; peer ENABLE_CONNECT_PROTOCOL; UDP `Capsule-Protocol: ?1` |
| HTTP/3 over native QUIC | Classic CONNECT on a bidirectional request stream | Extended CONNECT, `:protocol = connect-udp`, expanded HTTPS template | 200; peer Extended CONNECT setting; UDP `Capsule-Protocol: ?1` |

References: RFC 9110 §9.3.6, RFC 9113, RFC 9114, RFC 9220, RFC 9297 and RFC 9298.
The `.well-known/masque` path is the standard URI namespace; its spelling does
not imply this client uses CONNECT-IP or depends on the Masque NF repository.

The GUI generates the default UDP template only. The core supports the inherited
restricted RFC 6570 template parser. The GUI currently rejects custom template
imports instead of silently rewriting them. Custom endpoint editing is missing.

HTTP Basic credentials are sent in `Authorization` only to the relay. They must
not be forwarded as application payload or logged. Non-success responses fail
before a SOCKS success reply. The initial profile requires username/password;
client-certificate-only and mandatory mutual TLS server configurations are outside
this implementation. It never downgrades certificate checks to obtain compatibility.

An explicit IP determines the socket endpoint while the domain determines SNI
and certificate identity. TLS trust uses the system Security framework. Production
has no “accept any certificate” switch. Certificate online fetches remain disabled
as in the copied adapter. Test emulator trust is restricted to its fixture CA.

## Stream and Capsule behavior

- TCP must preserve arbitrary binary bytes and independent half-closes. Client
  write EOF must permit a destination response to arrive afterwards.
- UDP uses context ID 0 in DATAGRAM Capsules. A payload may be empty. Unknown
  capsule types and unsupported contexts are discarded with bounded buffering.
- Truncated Capsules fail on EOF. Headers/trailers invalid for a CONNECT-UDP
  tunnel fail rather than being treated as application data.
- HTTP/3 DATAGRAM setting is false; no native QUIC DATAGRAM channel is requested.
  UDP therefore remains reliable and ordered inside the request stream.
- Initial maximum outgoing UDP payload: 65,507 bytes. SOCKS responses are capped
  at 65,240 payload bytes to leave room for every supported address header.
  Full IPv6 UDP maximum size is not implemented.
- HTTP/2/3 stream pumps use a 64 KiB bounded duplex buffer and 16 KiB write
  chunks. HTTP/2 returns receive credit after the consumer accepts bytes.
- Dropping an unfinished stream resets/cancels it and aborts owned pumps/drivers.
  Dropping the last native lease releases its resources. Late events for another
  app generation must not revive a cancelled connection.

## Readiness and failure classification

Authenticated CONNECT-UDP admission is the readiness condition. It must not be
presented as proof of destination reachability, a completed HTTPS transfer or
sustained HTTP/3 forwarding. The idle readiness probe sends no target datagrams;
current source replaces it after 60 seconds and refreshes clean peer FIN without
reporting a relay failure. Independent SOCKS flows retain their own lifetimes.
Malformed Capsules and native I/O errors remain failures. A failure in either
HTTP stream pump must wake pending I/O in the opposite direction while preserving
buffered response bytes and normal half-close semantics.

Forced transport selection must remain forced; a silent switch from failing
HTTP/3 to HTTP/2 does not pass HTTP/3 acceptance. Automatic fallback must be
tested separately. Retry delay is exponential for short failures and resets
after at least 30 seconds of admitted readiness; repeated ten-second failures
must not be hidden by retry logs or reported as a stable session.

The latest supplied older binary has one complete HTTP/3 admission-to-EINVAL
cycle lasting 10.002560 seconds in run `16A52488`; its following SID 4 request
ends awaiting a response. The same upload has separate HTTP/2 control-flow
closures near 300 seconds, plus broken-pipe/timeouts with unproven causes.
[Evidence](evidence/native-http3-20261011-1202.md) records the exact build and
observation limits. Current probe/pump source repairs have portable tests but no
Mac retest; native HTTP/3 stability is unresolved. Different Masque NF profile
outcomes must not be treated as proof of this application's root cause or as
identification of a server backend from a display label.

## SOCKS5 profile

RFC 1928 version 5, no local authentication, CONNECT and UDP ASSOCIATE.
BIND and UDP fragmentation are unsupported. The default listener is loopback;
users may explicitly select a non-loopback IP, exposing an unauthenticated SOCKS
listener. Remote destination names remain names and are resolved by the server.
ASCII DNS names, IPv4 and IPv6 address syntax are accepted; raw internationalized
SOCKS names are not normalized and must be supplied as ASCII/Punycode.

A UDP association is tied to its TCP control connection. UDP source IP must match
that TCP peer; an advertised nonzero port is enforced, otherwise the first valid
UDP sender port is pinned. Other sources and fragments are dropped. Each
association has at most 32 destination flows, a 16-packet outgoing queue per flow,
a 32-packet response queue and a 120-second inactive-flow timeout. Queue overflow
is dropped; per-drop user-visible counters are not implemented. The app caps
concurrent SOCKS TCP sessions at 256.

Closing the control TCP connection cancels all destination flows and closes the
local native UDP socket. The server independently enforces authentication,
destination restrictions, byte limits and idle timeouts; this app must not bypass
those restrictions. Server rejection of a UDP target has no SOCKS UDP error
response and is visible in Detailed logs.

## Settings and lifecycle

Selecting a different configured server or changing the selected transport must
automatically restart an active client after this instance releases its listeners.
Saving an inactive server, editing its display name or changing log level must not
restart the active connection. An explicit Disconnect cancels any pending automatic
restart. Saving a new incomplete server must not select the first list entry over
an existing active selection. Invalid settings fail before a usable client starts.

Stored settings, exported TOML and log filenames use this app's identity. Export
may omit passwords; export with passwords must use private file permissions.
Logs retain at most 5,000 recent lines in memory. The level menu runs from most
to least detailed: Everything (TRACE through ERROR), Detailed (DEBUG through
ERROR), Normal (INFO through ERROR), Warnings and Errors, Errors Only. Changing
the level updates the view and runtime logging without reconnecting. The copied
Masque NF presentation includes selectable monospaced lines, severity colors,
Follow latest, Latest, Copy All and Save. Exports include all retained lines,
including those hidden by the current view. Native/app operation messages may
remain in the buffer at a low view level; ungenerated diagnostics cannot be
recovered later. Verbose records are removed first at the retention cap; logs
are not automatically persisted to disk. The app must not manage system proxy settings, routes,
firewalls, helpers or another application's processes.

## Compatibility acceptance

The server pairings for this application are network-relay and
caddy-network-relay. Masque NF's masque-server/caddy-masque CONNECT-IP matrix is
a separate acceptance task. Do not substitute a different client's pass or
another server's pass for a missing pairing.

Each server must independently pass native TCP and UDP tests for every advertised
transport, including authentication rejection, certificate rejection, destination
policy rejection, remote DNS, IPv4/IPv6, empty and large UDP packets, binary bulk
TCP, both half-close directions, cancellation, server disconnect, reconnect,
network changes and automatic fallback. Exercise at least ten minutes of native
admitted operation, with actual TCP/UDP target responses and separate idle and
active periods, to cover the observed ten-second failure and five-minute probe
expiry. This minimum is a regression gate, not proof of indefinite stability.
Probe renewal must preserve independent active flows, and a clean probe FIN
must not produce a global failure status. Test stream errors, buffered data and
half-closes independently from native QUIC group failures.

Tests must record client source/build, OS/build/SDK, server revision and binary
hash, effective configuration and transport-specific results. Use disposable
accounts and test targets. Logs must not contain passwords, Authorization,
application payload or certificate/private-key contents. Capture actual QUIC
stream IDs, direction, parent/group, request/response phases and reset/close codes;
bridge resource handles alone must not be interpreted as stream IDs. Correlate
the first native error with server events before assigning a root cause.

A Linux emulator pass, QUIC `.ready`, local HEADERS completion, a listener opening,
or one successful CONNECT does not establish this acceptance matrix. Until the
native matrix passes, the product must remain development/experimental and must
not advertise universal or perfect compatibility.

## Independent investigation and change scope

All hypothesized remedies and research recommendations in the existing documents
are non-binding references. Claude or another repairer must first review actual
source, specifications, dependency versions, sanitized evidence and test coverage,
then independently verify applicable Apple documentation and open-source code.
Choose a minimal necessary repair from that evidence; do not mechanically apply
the reports' suggested options, stream layout, timeouts or API/backend migration.
If a claim cannot be reproduced or distinguished from alternatives, keep it a
hypothesis. Network.framework's involvement does not prove an inherent defect.

Production DNS, sockets, TLS and QUIC must remain owned by Network.framework.
Other clients and server production code remain read-only comparison material
for changes scoped to this application. Changes are limited to QUIC/HTTP/3 or
another defect supported by clear evidence. Evaluate each proposed change's
necessity, evidence, affected behavior and regression risks before editing, then
validate that focused change before proceeding to another. Speculative cleanup,
unrelated refactoring, dependency upgrades and redesign are outside this repair.
Preserve settings, security and supported TCP behavior, and add meaningful
regression tests for confirmed defects. Passing portable tests is necessary but
cannot replace the native pairing that failed. Report failures and untested gates explicitly; update
the status/research documents when a bounded investigation cannot establish a
fix. [CLAUDE-HANDOFF.md](CLAUDE-HANDOFF.md) provides the cross-client work order.
