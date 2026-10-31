# Network Relay CF MASQUE: design

## Scope

network-relay-cf-masque is network-relay with one difference: every tunnel's
name lookups, TCP connections and UDP flows go through Cloudflare WARP
(MASQUE) instead of the host's own network. Everything else is
network-relay's own code, called rather than copied: TLS, HTTP/1.1 CONNECT,
HTTP/2 and HTTP/3 CONNECT and CONNECT-UDP, authentication and revocation,
destination rules, the cover website, rate, connection and memory limits,
reloads, logging, the configuration format and the `passwd`, `identity`,
`profile` and `check` commands. Their parameters and defaults are the same.

Research was completed before implementation. See the four `RESEARCH-*.md`
reports for the pinned sources read: Network Relay, ArcCal/cf-masque, usque,
usque-rs, Xray-core, sing-box and mihomo. Cloudflare WARP is a distinct
dialect of MASQUE; generic RFC CONNECT-IP alone is insufficient. The WARP
transport, userspace stack and resolver reuse pinned MIT cf-masque sources.
GPL reference implementations supply behavioral evidence and are not copied.
[NOTICE.md](../NOTICE.md) records sources and licenses.

## Components and data path

1. network-relay (the parent crate, `..`) has an `egress` interface
   (`network_relay::egress::Egress`): resolve a name, open a TCP connection
   or a connected UDP flow, report availability and terminal loss.
   `server::Relay::with_egress` and `server::run_variant` run the relay with
   an egress; network-relay itself runs without one, on the host network,
   exactly as before.
2. With an egress, names resolve through it, every resolved address then
   passes the destination rules before a connection is opened, and
   connections whose peer is not the address allowed are reset and refused.
   Nothing falls back to the host network or resolver.
3. `crates/warp-egress` implements that interface with a pinned, mutually
   authenticated WARP tunnel, smoltcp sockets and tunnel DNS. It needs no
   host TUN, policy routes or host DNS. It depends on network-relay only for
   the interface.
4. Only the physical WARP transport uses host TCP/UDP. Relayed TCP/UDP and
   DNS become IP packets inside WARP.
5. The binary (`src/main.rs`) reads the one configuration file, connects
   WARP, then runs network-relay with it. Its other commands are
   network-relay's (`network_relay::cli`), under this program's name.
6. The HTTP/3 library is network-relay's vendored h3 (`../vendor/h3`),
   which also carries the client extensions WARP needs (`cf-connect-ip`,
   the draft-00 datagram setting and the peer's SETTINGS); a server never
   uses them.

## Transports and fail-closed lifecycle

Ingress H1/H2/H3 and egress H2/H3 are independent selections; all six
pairings are tested. No automatic HTTP transport downgrade is allowed. WARP
H3 preserves `cf-connect-ip`, raw SPKI pinning, P-256 device identity, peer
DATAGRAM negotiation, draft-00 compatibility and flow/context identifiers.
WARP H2 preserves its distinct authority/headers, bare IP DATAGRAM Capsules,
and narrow absent-ALPN compatibility rule.

Tunnel loss revokes availability first, fails every outstanding socket
operation and rejects new lookups and connections. Open tunnels end as failed
destination connections: HTTP/3 streams with H3_CONNECT_ERROR, HTTP/2 streams
with CONNECT_ERROR (RFC 9114 section 4.4, RFC 9113 section 8.5), UDP flows as
failed, including tunnels paused by a traffic budget or idle. The server then
sends GOAWAY, gives connections the usual drain time to report this, closes
and exits with failure; a supervisor starts a fresh process with the same
transport. Version 0.1.0 does not reconnect in process.

TCP half-close and abnormal reset are separate outcomes: an egress connection
has an explicit abort that resets it, as a kernel socket with a zero linger
time does. Connected UDP validates the peer, and payloads above the current
tunnel MTU are dropped without IP fragmentation (RFC 9298 section 5). IPv6
requires its minimum MTU. Socket counts and buffers are bounded.

## Configuration

One standalone TOML file holds network-relay's settings and users, `[warp]`
and the inline `[warp.registration]`. Everything outside `[warp]` is parsed
by network-relay's own `Config`, as strictly as network-relay parses its file;
errors never quote the file, which holds the WARP private key. There is no
separate WARP file, enrollment JSON or migration command. The file must be
mode 0600 and kept out of version control; credentials never appear in
diagnostic dumps or logs.

The required WARP inputs are an explicitly selected H2/H3 mode, the enrolled
P-256 private key, the endpoint SPKI pin and the assigned inner IPv4 address.
Device ID, access token and license are optional metadata. H2 uses its
numeric IPv4 endpoint default; H3 requires a registered IPv4 endpoint or an
explicit numeric override. IPv6 is optional: without `tunnel_ipv6` or
`endpoint_v6` the server warns at start and keeps running IPv4 only. No
omitted IPv6 field may cause an implicit IPv6 connection or direct VPS
fallback. WARP changes take effect after a restart; network-relay's SIGHUP
reload is otherwise unchanged.

## Validation

See [VALIDATION.md](VALIDATION.md) and [STATUS.md](STATUS.md). The synthetic
WARP peer used by the tests is not live Cloudflare evidence; actual Cloudflare
exit, downloads and native Apple GUI/device behavior are deployment gates.
