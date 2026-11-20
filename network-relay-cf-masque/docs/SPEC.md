# Experimental specification: version 0.1.0

## Required scope

The project is `network-relay/network-relay-cf-masque/`. It is network-relay
with its tunnels carried through WARP: it depends on the parent crate
(`network-relay`, path `..`) and calls its code rather than keeping a copy.
Only the WARP egress, the one-file configuration reader and the binary are
its own. Existing Network Relay clients do not need source changes.

## Client-facing contract

The client-facing side is network-relay's own server (`network_relay::server`),
the same code as the standard server's, with the same parameters:

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
9220, 9297 and 9298, including the finalized RFC 9931 update, and their
applicable normative references. TLS 1.3 is specified by RFC 9846, which
replaces RFC 8446. The existing
Apple profile schema is preserved, including HTTP/2-only output when
`--no-http3` is selected. Tests are evidence for specific behaviors, not a
certificate of compliance with every applicable document.

## WARP contract and explicit modes

### Single-file configuration

`serve --config relay.toml` loads relay settings/users and WARP settings from
one standalone TOML file. `[warp.registration]` holds the enrolled
credentials inline. There is no other configuration file: no separate WARP
settings file, enrollment JSON or migration command. Everything outside
`[warp]` is network-relay's configuration, parsed and checked by its own
`Config`. Certificate/key assets are separate files, not extra application
configuration documents.

`warp.transport` is required and must be `h2` or `h3`. Within
`[warp.registration]`, `private_key`, `endpoint_public_key` and `tunnel_ipv4`
are required. `device_id`, `access_token` and `license` are optional metadata
and are not needed for tunnel establishment. Endpoint overrides, DNS servers,
keepalive and idle limits retain their existing defaults and validation. H2
defaults to the numeric IPv4 endpoint `162.159.198.2:443`; H3 needs
`registration.endpoint_v4` unless an explicit `warp.endpoint` replaces it.

All IPv6 registration fields are optional. Without `tunnel_ipv6` or
`endpoint_v6`, `serve` (and `serve --check`) prints a warning naming the
missing fields, logs it, and keeps running. With no `tunnel_ipv6`, the inner
stack supports IPv4 only; IPv6 traffic is never redirected through the host.
Outer WARP addressing is independently selected: it defaults to IPv4 unless
`ipv6_endpoint = true` or an explicit IPv6 `endpoint` is configured. IPv6
operations require both an assigned address and the necessary tunnel MTU.
An IPv4-only deployment omits the IPv6 fields and retains the IPv4 defaults.

Config files containing inline private keys require private filesystem
permissions. WARP configuration is fixed for the process generation; changing
it requires a restart. SIGHUP preserves standard relay reload semantics.

### Transport behavior

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

Version 0.1.0 has one immutable session generation. On terminal loss open
tunnels fail (H3_CONNECT_ERROR, HTTP/2 CONNECT_ERROR, failed UDP flows), the
server sends GOAWAY, drains as on SIGTERM and exits with failure; the process
supervisor can start a fresh session. Old sockets never attach to it. Root
controller drop and cancellation during setup release owned tasks and
sockets. Normal graceful shutdown differs from abort/reset.
HTTP/3 control/QPACK stream initialization has a 15-second deadline,
independent of QUIC keepalives and the subsequent 5-second SETTINGS wait.
Initialization timeout explicitly closes QUIC and cancels the pending builder.
TCP TIME-WAIT remains owned by smoltcp after application handles are dropped;
the adapter must not remove it early or abort it at the ordinary close deadline.
After peer FIN, queued response bytes still use the peer's advertised window.
An in-sequence ACK that only updates that window can resume or limit transmission
before the local FIN is sent (RFC 9293 sections 3.10.4 and 3.10.7.4).

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
  The DNS cache holds 4096 name and query-type pairs. At capacity, a new entry
  displaces a cold or expired entry, giving recently read answers a second
  chance. Hits preserve the original positive or negative expiry.
- Packet and byte metrics identify accepted sends, received packets, stack
  and transport queue drops, MTU, socket/task counts, capability and terminal
  reason. Local send acceptance is not proof of remote delivery.
- Credentials and arbitrary peer headers are excluded from public status.
- The sample relay permits 48 business tunnels to reserve backend sockets;
  this is a capacity choice, not a new client wire protocol.

## Reusable library contract

`warp-masque-egress` implements network-relay's `egress::Egress` interface
(resolve/TCP/connected UDP, availability and an independent terminal-failure
future), and reuses the parent's hostname rules, public QUIC integer and
Capsule encoders, and Capsule response-header validation;
it has no SOCKS,
Apple UI, TUN or policy routing dependency. `WarpEgress` owns explicit
connection, status, closed and shutdown operations. The independent
`examples/reuse` workspace builds with one Cargo patch, pointing h3 at
network-relay's vendored copy as network-relay itself does.

## Release gates and status discipline

The implementation must pass its local unit/security/protocol tests, actual
synthetic WARP packet tests, six-pair client interoperability, repeated large
streaming transfers with expected hashes, failure cleanup, and real elapsed
long-held connection tests. Native Apple execution, actual Cloudflare exit,
live downloads and live stability are separate gates. A network-blocked test,
ignored soak, preliminary failing run or compile-only check is never a pass.

[STATUS.md](STATUS.md) identifies implemented, tested, known-limited and
unverified capabilities. [VALIDATION.md](VALIDATION.md) records the tests run
on the current code and how to repeat them.
