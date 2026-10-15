# Experimental specification: version 0.1.0

## Required scope

The independent project is `network-relay/network-relay-cf-masque/`. Its
production sources, dependency declarations and locks, tests, scripts,
documentation, local secrets and generated artifacts stay here. Parent and
sibling project files are not edited. Existing Network Relay clients do not
need source changes.

## Client-facing contract

The frontend retains the reviewed standard Network Relay implementation at
`cc7ea4df2924d0454ab5075e089cbb53d94b178e`:

| Capability | Required behavior |
| --- | --- |
| TLS | Same certificate/hostname trust, ALPN H1/H2/H3 and optional pinned client identity |
| TCP proxy | Ordinary authority-form CONNECT; independent bidirectional close and abnormal reset |
| UDP H1 | RFC 9298 GET/Upgrade, 101 response and Capsule Protocol |
| UDP H2/H3 | Extended CONNECT `connect-udp`, standard template, settings and capsule/datagram handling |
| Authentication | Existing Basic/Proxy-Authorization and configured client fingerprint formats; unchanged rejection cover behavior |
| Reload/revocation | Standard users, policy, certificate and website reload; active revoked flows cancel |
| Policy | All resolved addresses and selected peers checked; original special-range/own-address/port restrictions |
| Limits | Original ingress concurrency, rate, idle and memory limits, plus explicitly bounded WARP sockets |
| Website/profiles | Standard cover website and Apple profile/DDM controls; private output files |

Relevant IETF behavior remains governed by RFC 9110/9112/9113/9114, 8441,
9220, 9297 and 9298 and their applicable normative references. The existing
Apple profile schema is preserved, including HTTP/2-only output when
`--no-http3` is selected. Tests are evidence for specific behaviors, not a
certificate of compliance with every applicable document.

## WARP contract and explicit modes

WARP uses Cloudflare's private MASQUE dialect, not an assertion that its
`cf-connect-ip` wire format is standard RFC 9484 CONNECT-IP. Each mode is
explicitly selected and separately tested:

| Egress | Wire behavior |
| --- | --- |
| H2 | TLS to numeric endpoint, registered SPKI pin, generated P-256 device certificate, WARP plain CONNECT headers, bare IP DATAGRAM Capsules, bounded flow control and PING liveness |
| H3 | Quinn QUIC, registered SPKI pin, device certificate, `cf-connect-ip`, RFC/draft-00 datagram settings compatibility, quarter-stream/context framing, reviewed 20-byte connection ID and route advertisements |

The client token/license is not logged or used to silently register a new
device. The existing device private key and endpoint pin are validated before
opening sockets. Origin HTTPS in validation tools uses normal CA/hostname
verification; WARP's enrolled endpoint uses its registered public-key pin.

Ingress H1/H2/H3 × egress H2/H3 forms six independent pairings. No automatic
transport downgrade is allowed. A failed H3 setup is a failed H3 test even if
H2 works. Outer endpoints and DNS servers are numeric; DNS never reaches the
host resolver through the production egress implementation.

## Data, failures and lifecycle

Business TCP/UDP/DNS is represented as IP packets in the WARP tunnel. No
release `DirectEgress` exists. On tunnel death, availability is revoked before
cleanup; blocked reads/writes/dials/DNS fail, cached/literal resolution is
rejected, and ingress flows fail even while idle or rate-limited. Backend loss
is an error, not clean EOF. Wrong credentials and denied destinations cannot
open inner sockets.

Version 0.1.0 has one immutable session generation. The app exits on terminal
loss; the embedding library user or process supervisor can explicitly create
a fresh session. Old sockets never attach to it. Root controller drop,
cancellation during setup and server-owner cancellation must release owned
tasks and sockets. Normal graceful shutdown differs from abort/reset.

The TCP façade has endpoint metadata and an independent abort control. Stale
abort controls cannot reset a subsequently reused socket. Connected UDP
accepts only its selected peer and preserves empty packets. UDP forwards no
IP fragments; an oversized path-MTU datagram is silently dropped by the
frontend while preserving the flow (RFC 9298 §3.1). IPv6 operations require an
MTU of at least 1280. Loss of that capability fails affected pending operations
and is reflected separately from assigned addresses in diagnostics.

## Resource contract

- 64 total userspace sockets, shared by business traffic and DNS, including
  connecting/closing TCP. Overload fails rather than growing without bound.
- TCP RX/TX buffers are 256/128 KiB per socket. Packet queues, UDP metadata and
  byte buffers, DNS cache/in-flight requests and capsule parsing are bounded.
- Packet and byte metrics identify accepted sends, received packets, stack
  and transport queue drops, MTU, socket/task counts, capability and terminal
  reason. Local send acceptance is not proof of remote delivery.
- Credentials and arbitrary peer headers are excluded from public status.
- The sample relay permits 48 business tunnels to reserve backend sockets;
  this is a capacity choice, not a new client wire protocol.

## Reusable library contract

`warp-masque-egress` has no dependency on the relay frontend or its CLI, SOCKS,
Apple UI, TUN or policy routing. `Egress` supplies resolve/TCP/connected UDP,
availability and an independent terminal-failure future. `WarpEgress`
implements it and owns explicit connection, status, closed and shutdown
operations. The independent `examples/reuse` workspace must build without
Cargo patches or sibling-project dependencies.

## Release gates and status discipline

The implementation must pass its local unit/security/protocol tests, actual
synthetic WARP packet tests, six-pair client interoperability, repeated large
streaming transfers with expected hashes, failure cleanup, and real elapsed
long-held connection tests. Native Apple execution, actual Cloudflare exit,
live downloads and live stability are separate gates. A network-blocked test,
ignored soak, preliminary failing run or compile-only check is never a pass.

As of 2026-10-15 UTC, the final finite workflow passed 604 tests with zero
failures and two intentionally ignored tests executed separately. Synthetic
PID 138810 passed its 3900-second held-flow target and independent verification,
recording 3925.266 measured seconds across all six pairings. This satisfies that
local run's sustained-test gate. The earlier PID 128443 timeout remains
unresolved, and the passed run does not establish its cause or correction.
Actual Cloudflare account/exit verification, live large-download integrity,
live held-flow stability, native Apple device/profile execution and deployment
platform runtime checks remain separate outstanding gates.

[STATUS.md](STATUS.md) identifies implemented, tested, known-limited and
unverified capabilities. [VALIDATION.md](VALIDATION.md) links retained evidence
and documents exact source/executable identity and failed attempts.
The [timeout review](review/SOAK-TIMEOUT-REVIEW.md) records the unresolved
failure and the limits of the later synthetic pass.
