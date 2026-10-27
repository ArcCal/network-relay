# Design goals and architecture

Revision: 0.1.0 development, 2026-10-11. This is the intended design; actual
implementation and evidence are tracked separately in [STATUS.md](STATUS.md).

## Goals

1. Provide a standalone application named Network Relay NF with the familiar
   Masque NF window, icon, server management, logs and menu bar.
2. Interoperate with the standard CONNECT and CONNECT-UDP endpoints of both
   network-relay and caddy-network-relay, without server modifications.
3. Use Apple Network.framework for every production OS network operation:
   relay DNS resolution, TCP/TLS, UDP/QUIC, QUIC streams and local SOCKS sockets.
4. Keep protocol logic and its portable tests separate from the Apple transport.
   Use real servers for protocol checks, and clearly identify tests that replace
   the native transport.
5. Preserve certificate verification, ALPN selection, cancellation, bounded
   queues and half-close behavior. Do not hide forced HTTP/3 failures as success.
6. Keep this application directory, documentation, configuration, build and lifecycle independent. Changes
   here must not change Masque NF or either relay server's production code.
7. Document defects and missing work accurately. Native QUIC repair has a limited
   time budget; HTTP/2 is the initial operational path when HTTP/3 is unreliable.
   A shared use of Network.framework is not proof that different client failures
   have the same cause or that the framework has an unavoidable defect.

## Network ownership

```mermaid
flowchart LR
    A[Local SOCKS application] --> N[Swift Network.framework listeners]
    N --> S[Rust SOCKS5 and relay core]
    S --> H[hyper / h2 / h3 HTTP framing]
    H --> B[C ABI and bounded event bridge]
    B --> T[Swift Network.framework TCP / TLS / QUIC]
    T --> R[network-relay or caddy-network-relay]
    R --> D[Destination TCP or UDP service]
```

`App/.../NativeClient.swift` owns NWListener, NWConnection and NWConnectionGroup.
`Core/src/native.rs` presents asynchronous byte streams and datagram sockets to
Rust using C ABI events. Production code contains no Rust socket dialing,
OS resolver, TLS handshake implementation or QUIC packet engine. Standard-library
IP/address types merely parse metadata; Tokio supplies scheduling and byte I/O.
Quinn and rustls are development dependencies used only by the test emulator.

Rust still implements HTTP/1.1, HTTP/2 and HTTP/3 framing, QPACK, SOCKS5 and
CONNECT-UDP Capsules. A network observer may distinguish HTTP settings, request
and control-stream ordering, timing and other application behavior. Using Apple's
TLS/QUIC transport does not guarantee an indistinguishable Apple application or
absence of Rust-influenced behavior. No fingerprint-evasion claim is made.

This client relays TCP and UDP directly. It does not allocate a virtual IP,
request CONNECT-IP routes, run smoltcp, create a TUN device, or send target DNS
queries through a client-side IP stack. SOCKS domain names go to the relay, which
resolves them under its own DNS and destination policy. A relay hostname is
resolved by Network.framework unless the user supplies its IP.

## Connections and readiness

HTTP/2 and HTTP/3 SOCKS flows share one outer TLS/QUIC connection per session;
a connection that received GOAWAY or failed is not reused for new flows, while
its admitted flows continue. HTTP/1.1 has no multiplexing and still opens one
outer TLS connection per flow.

A separate authenticated idle CONNECT-UDP flow acts as the connection monitor.
“Relay ready” means that the server accepted this authenticated protocol request.
It does not prove arbitrary destination reachability, web access, working DNS or
continued liveness after a network change. The default probe target is
`1.1.1.1:53`; no application datagram is sent. Core configuration can override
`probe_target`. The client renews the probe every 60 seconds, before the Rust
server's minimum supported UDP idle expiry. Clean probe FIN refreshes admission
without a failure status; native errors and malformed Capsules still trigger
failure/retry. Renewal retains the selected transport and existing independent
SOCKS flows. It sends no application heartbeat. TCP-only policies that deny this probe
are not supported by the current readiness design.

Automatic mode tries HTTP/3 for five seconds, then native TCP with ALPN `h2`,
`http/1.1`. Authentication/security rejection is terminal rather than a reason
to downgrade; 502, 503 and 504 refusals are temporary and are retried. Forced modes do not silently change transport. The monitor's
successful transport becomes the preferred mode for new flows until reconnect.
Existing flows stay on the connection they started on and are not migrated.
Retry backoff remains exponential for short failures and returns to one second
after at least 30 seconds of admitted readiness. Readiness is not target reachability.

## HTTP/3 scope

UDP uses RFC 9297 DATAGRAM Capsules on the request's reliable byte stream.
The client advertises no HTTP/3 DATAGRAM support and extracts no native DATAGRAM
child. This is permitted by the protocol and both server implementations support
Capsules. It avoids the earlier clients' extra DATAGRAM extraction and its known
lifecycle concerns. It can cause head-of-line blocking; native unreliable QUIC
DATAGRAM optimization is deliberately deferred.

The inherited NWConnectionGroup stream adapter remains experimental. The initial
core also disables outbound GREASE streams to keep the layout simple during
bring-up. These two changes are design choices, not a controlled proof of the
old fault's cause. The periodic native HTTP/3 disconnect was user-confirmed
resolved after the server idle-stream-0 and client probe-lifecycle fixes. Actual stream IDs
are logged and range-checked. Complete local stream direction/initiator checks
and modern NetworkConnection<QUIC> evaluation are deferred.

## Native QUIC evidence and repair method

This section is a historical record of older builds. The disconnect it describes
was later user-confirmed resolved; see [STATUS.md](STATUS.md).

The latest supplied Relay log runs the older binary from source
`666b795c881b44eeaade9891edfae04ffcbd34a6`, built at
2026-10-11T09:37:18Z. In run `16A52488`, authenticated HTTP/3 readiness at
12:02:49.394733Z is followed by POSIX 22 (EINVAL) at 12:02:59.397293Z, an
interval of 10.002560 seconds. The next attempt sends request HEADERS on actual
SID 4 and ends while waiting for a response. This attachment contains one
complete admitted/failure cycle; it does not establish the outcome of that next
attempt. [Sanitized trace and provenance](evidence/native-http3-20261011-1202.md).

This is separate from the older HTTP/2 readiness-probe closures near 300 seconds.
The current source renews that idle probe and repairs opposite-pump error wakeups,
but those portable repairs have not been retested on the user's Mac. An older
binary's failure cannot show whether the later repairs work, and those repairs
are not claimed to fix the native HTTP/3 EINVAL.

New Masque NF observations also differ by profile: `caddy-masuqe` has six HTTP/3
tunnel establishments and forwarded-byte evidence, while `masque-vpn` has twelve
initial HTTP/3-response timeouts and no recorded HTTP/3 tunnel establishment.
Those attempts exchange QUIC control/QPACK bytes and select Capsules; the natural
timeouts occur 10.190977 to 10.230700 seconds after Capsule selection. No EINVAL
is recorded for the failing Masque profile. Profile labels alone do not establish
the actual server implementation, revision or endpoint. Local flow resets and
ENETDOWN events in that sample also
prevent a claim of complete Caddy stability or compatibility. Masque NF uses
CONNECT-IP; this application uses CONNECT/CONNECT-UDP. Neither failure is a
substitute for diagnosing the other. See the
[separate Masque evidence](https://github.com/ArcCal/masque-vpn/blob/main/masque-nf/docs/evidence/native-http3-20261011-1205.md).

Every proposed cause, workaround and research suggestion in this design and
[QUIC-RESEARCH.md](QUIC-RESEARCH.md) is a non-binding investigation reference.
The repairer, including Claude, must inspect the actual client and server code,
verify the applicable Apple API contracts and availability, examine relevant
open-source implementations, and independently identify the cause and choose
the smallest necessary repair. Do not copy a suggested stream-ownership, options,
timeout or backend change merely because it appears in a report. Unproven
hypotheses must remain labeled as such.

Use a fixed endpoint, settings and build identity for a bounded reproduction;
change one relevant variable at a time and correlate real stream IDs, request
phases, reset/close codes and the first native error callback with server traces.
Separate stream-level closure from group failure and clean idle expiry. Read
other clients and server production code as comparison material; repair work in
this directory must preserve the Network.framework production boundary and keep
those other implementations unchanged. [The handoff](CLAUDE-HANDOFF.md) and
[SPEC.md](SPEC.md) define review and acceptance requirements. Changes must target
QUIC/HTTP/3 defects or another defect established by clear evidence. Before each
change, evaluate its necessity, supporting evidence, affected behavior and
regression risks; verify that focused change before proceeding to another.
Speculative cleanup, unrelated refactoring, dependency upgrades and redesign are
outside this repair. If native evidence is unavailable or a minimal repair cannot
be established, record the limitation
instead of declaring the fault fixed or rewriting the transport.

## Isolation and UI

Bundle identifier: `com.arccal.network-relay-nf`. Executable/module:
`NetworkRelayNF`. The app has its own Application Support directory and does not
import an existing Masque NF store automatically. Its canonical settings file is
`~/Library/Application Support/NetworkRelayNF/settings.json`. When this file is
absent, it reads its own previous `NetworkRealyNF/settings.json` store; the next
save writes the canonical path and retains the legacy copy. Canonical settings
take precedence. Deleting this app's settings removes both stores and their
preference domains. Password persistence follows
the copied file-store design; Keychain migration is not implemented.

The copied UI includes server CRUD, active selection, transport changes,
application/proxy settings, scoped TOML import/export, masked passwords, in-memory
logs, menu controls, connect on launch and deletion of this app's stored settings.
The active-server restart and blank-new-server selection fixes are retained.
The user has reported a Mac build/launch and SOCKS TCP/UDP forwarding success.
The individual UI behaviors and complete native acceptance matrix still need
verification; [the evidence](evidence/native-mac-20261011.md) records the limits.
