# Network Relay frontend and egress contract research

Research date: 2026-10-14. Status: source review and design recommendation only; no server or client implementation was changed or built for this report.

The canonical source reviewed is `ArcCal/network-relay` at **`cc7ea4df2924d0454ab5075e089cbb53d94b178e`**, version 1.5.0. The local, project-contained snapshot is `../.research/upstream/network-relay` relative to this document. All line references below refer to that commit. The original parent checkout and sibling applications are outside this project's write scope. This report does not recommend editing them.

## Recommendation

Retain the current standard Network Relay frontend, authentication, target parsing, policy, cover website, profiles, protocol adapters, and bounded tunnel lifecycle in an independent project-owned server. Substitute an injected asynchronous egress capability at the shared destination-opening boundary. The egress crate must be independent of Network Relay and must provide tunnel DNS, TCP streams, UDP sessions, selected numeric peer metadata, explicit TCP abort, and observable terminal failure.

**Replacing only `connect::tcp` and `connect::udp` is insufficient.** `Policy::resolve` currently performs business DNS through the host system resolver. `Opened` and the pumps also depend on concrete kernel socket operations, including TCP reset and owned-half behavior. Those are the necessary additional insertion points.

No NF, RS, or Apple profile wire-format change is necessary: clients continue using classic CONNECT for TCP and CONNECT-UDP for UDP. Cloudflare's upstream MASQUE transport belongs entirely behind the server's egress boundary. The ingress server must not start advertising CONNECT-IP or draft `connect-tcp` merely because the backend uses an IP tunnel.

## Source organization and boundaries

| Area | Canonical source and exact lines | Responsibility and treatment |
| --- | --- | --- |
| Public library modules | [src/lib.rs:6–22][lib] | Exposes server, configuration, authentication, protocols, profiles, diagnostics, OS helpers. Copy only into the independent project with upstream licenses and provenance. |
| CLI and server entry | [src/main.rs:182–305][main-cli], [308–354][main-serve] | Dispatches `serve`, `passwd`, `identity`, `profile`, `check`; configuration validation and logging precede server start. Keep frontend helpers; integrate egress startup only in the independent server. |
| Server assembly | [src/server/mod.rs:80–191][relay-state], [834–950][run] | Shared settings/state, limits, `Relay` creation, listeners, reload, shutdown. Add a required injected `Arc<dyn Egress>` and supervision here. |
| Shared request/auth/open | [src/server/mod.rs:292–343][request-kind], [669–825][open] | Classifies classic/extended CONNECT, authenticates, resolves, applies admission and opens TCP/UDP. This is the smallest business-I/O boundary. |
| H1/H2 adapters | [src/server/over_tcp.rs:131–285][tcp-listener], [287–495][tcp-handlers] | TLS ingress, HTTP/1 upgrades, h2 CONNECT, resets, status responses. Preserve wire decisions. |
| H3 adapter | [src/server/over_h3.rs:201–365][h3-listener], [369–508][h3-request] | QUIC ingress, HTTP/3 validation/settings, datagram routes and cancellation. Preserve transport behavior. |
| Target policy/DNS | [src/policy.rs:22–96][target], [285–374][policy] | Strict target parsing, port/IP/own-address policy and system DNS. Retain policy; replace the resolver dependency. |
| Direct target sockets | [src/connect.rs:44–125][connect] | Kernel TCP Happy Eyeballs and connected UDP sockets. Exclude direct business dial/bind from the production experimental server. Adapt address racing to tunnel TCP. |
| Tunnel pumps | [src/server/pump.rs:25–121][pump-stream], [130–225][pump-h3], [227–354][pump-udp] | Byte accounting, half-close, reset, UDP lifetime, quotas and failure mapping. Generalize only target-side I/O. |
| H2 byte stream | [src/server/h2_stream.rs:11–118][h2-stream] | Explicit flow-control credit, half-close, reset notification, trailers rejection. Ingress adapter remains independent of egress. |
| Capsule/HTTP Datagram stream | [src/tunnel.rs:24–39][tunnel-bounds], [132–435][tunnel] | Bounded reader/writer tasks, capsules versus QUIC datagrams, protocol abort codes and close drain. Preserve this client-facing abstraction. |
| Wire parsing | [src/proto/mod.rs:14–50][proto], [src/proto/capsule.rs:15–154][capsules], [src/proto/datagram.rs:18–38][datagram], [src/proto/uri_template.rs:59–96][uri], [156–298][uri-match] | Protocol tokens, content metadata restrictions, variable integers, framing and URI matching. No target network access. |
| Auth and limits | [src/auth.rs:262–367][auth-state], [472–695][auth], [src/limits.rs:15–39][client-key], [418–492][memory] | User identity/expiry/revocation, caches, thread-limited hashing, admission and budgets. Reuse without giving passwords to the egress crate. |
| TLS/certificates | [src/tls.rs:24–125][tls], [src/certs.rs:122–178][certs] | ALPN and optional pinned client certificates; file-based certificate loading and scheduling. Ingress TLS credentials remain distinct from WARP credentials. |
| Website/profile/private output | [src/web.rs:42–259][web], [src/profile.rs:24–65][profile-options], [190–374][profile], [src/private_file.rs:9–30][private] | Cover responses, bounded static snapshots and one-time links; unchanged Apple profile payloads and owner-only writes. |
| Diagnostics | [src/check.rs:28–140][check], [439–460][check-tls] | Client-side connections to the relay and requests through it. A localhost/remote check connection is ingress validation, not business egress. Keep separate from server outbound policy. |

## Existing ingress contract

### Classification, authentication and refusal

`Kind::of_connect` accepts classic CONNECT without `:protocol` as TCP, and a case-insensitive `connect-udp` token with `:scheme=https` as UDP. Other extended protocols produce an authenticated 501; wrong UDP scheme produces an authenticated 400 ([server/mod.rs:318–330][request-kind]). H1 uses its own standards-compliant upgrade form below. `connect-tcp` is deliberately unsupported and logged once ([server/mod.rs:688–705][authorize]).

`authorize` parses a target before verification but does no DNS or socket work. A UDP template mismatch returns the cover response before authentication; an invalid target matching the template is a refusal only after authentication. Configured certificate fingerprints authenticate first; otherwise `Proxy-Authorization` takes precedence over `Authorization`. Failed or missing Basic credentials, expired users and throttled verification all receive cover responses, not a proxy challenge ([server/mod.rs:673–724][authorize]). Preserve that order and never let unauthorized requests trigger tunnel DNS, TCP or UDP allocation.

Basic parsing accepts case-insensitive `Basic`, validates base64/UTF-8, and splits on the first colon ([auth.rs:89–104][basic]). The authenticator holds HMAC-derived cache tags rather than plain headers, positive cache entries for 600 seconds with refresh, negative entries for 60 seconds, at most 4,096 entries and four new pending verifications per connection. Per-client new verification budget is a 30-attempt burst and one attempt/second; IPv6 clients share a /64 key ([auth.rs:57–74][auth-bounds], [auth.rs:594–670][auth], [limits.rs:15–39][client-key]). Concurrent identical headers share one verification. Hashing uses dedicated threads and memory/CPU-sized slots; cancellation retains a running hash's permit until computation finishes ([auth.rs:473–489][auth], [673–695][auth]). Preserve these protections.

A `User` includes the specific password hash or `sha256:<fingerprint>` credential and account expiry. Current-user comparison includes expiry and credential equality. Reload changes a generation watch, invalidates stale caches, and open tunnels watch removal, credential/expiry changes and time expiry ([auth.rs:262–310][auth-state], [496–546][auth], [server/mod.rs:599–620][cancel]). WARP session failure is an additional cancellation condition, not an authentication change.

`Refusal::status`, `error_type` and `proxy_status` define the current authenticated HTTP contract ([policy.rs:98–197][refusal]): malformed target/request 400; port denied or user revoked 403; DNS/connect timeout 504; denied address, DNS failure/no addresses, refused or unreachable target 502; capacity limits 503; unsupported protocol 501. Preserve mappings and stable `network-relay` Proxy-Status behavior. Provider internals, WARP keys and credentials should not enter refusal details or logs.

### HTTP/1.1 and HTTP/2

TCP ingress uses TLS ALPN `h2` and `http/1.1` ([over_tcp.rs:27–39][tcp-config]). TCP connections are admitted before TLS, bounded buffers are established before processing, and the handshake has a ten-second deadline. H1 has a 64 KiB total read buffer and ten-second header timeout. Website/refusal writes have a 30-second stall guard; once a connection carries a tunnel it permits TCP backpressure ([over_tcp.rs:34–110][tcp-config], [131–215][tcp-listener]).

H1 requires exactly one Host field for HTTP/1.1. UDP requires HTTP/1.1 GET, a `Connection` token list including Upgrade and an `Upgrade` token list including case-insensitive `connect-udp`; malformed recognizable UDP requests get an authenticated 400. HTTP/1.0 ignores UDP Upgrade. Classic CONNECT takes authority from the request target with Host fallback. Successful TCP returns 200; successful UDP returns 101 with `Connection: Upgrade`, `Upgrade: connect-udp` and `Capsule-Protocol: ?1`. Successful tunnel responses carry no content framing body metadata. Hyper's upgrade future is raced against tunnel cancellation, and a failed upgrade aborts an already-opened target ([over_tcp.rs:383–494][http1]). The independent server must retain all of these details.

H2 uses `enable_connect_protocol`, a 256-stream limit, a 32 KiB header list, memory-sized windows, and a 64 KiB send buffer. Keepalive is a ping every 30 seconds with a 20-second response deadline; idle/shutdown sends GOAWAY ([over_tcp.rs:218–284][h2-config]). h2 validates malformed CONNECT forms before application handling. Authentication and opening are raced against peer reset; UDP with Content-Length, Content-Type or Transfer-Encoding is reset with PROTOCOL_ERROR. Open succeeds before a 200 response; an unsuccessful response transmission aborts the target. UDP sends `Capsule-Protocol: ?1` ([over_tcp.rs:287–379][http2]).

The h2 stream wrapper releases receive flow-control credit only for consumed bytes, reserves bounded send capacity, detects reset while writes are pending, uses END_STREAM for write-half shutdown, and resets CONNECT trailers with PROTOCOL_ERROR ([h2_stream.rs:20–118][h2-stream]). Retain the wrapper rather than replacing it with an unbounded transport bridge.

### HTTP/3

The QUIC frontend starts at 100 client bidirectional streams and raises to 1,024 after first authentication. Field sections are bounded to 32 KiB. It enables Extended CONNECT and HTTP Datagrams; flow-control windows, QUIC DATAGRAM receive/send buffers and transport capacity come from memory reservations. Initial/minimum QUIC MTU is 1,200; discovery upper bound is a UDP payload of 1,452; transport idle maximum is 300 seconds ([over_h3.rs:151–198][h3-transport], [255–276][h3-listener]). These are ingress-path settings; upstream WARP path MTU is a separate constraint.

New unvalidated QUIC handshakes exceeding 200/second with a 400 burst get Retry. Connection admission is before expensive handshake work, and handshakes/H3 setup are timed ([server/mod.rs:42–78][server-constants], [over_h3.rs:203–271][h3-listener]).

An unwritten lower-number request stream is intentionally left open: Apple's Network.framework can implicitly open stream 0 and never write it. Request activity and the ten-second HEADERS deadline start at the first byte, not stream acceptance. A delayed HEADERS request is rejected with H3_REQUEST_REJECTED ([over_h3.rs:292–326][h3-listener]). Removing this special handling can break unchanged NF/Apple clients.

There is exactly one datagram reader per connection. It dispatches by HTTP Datagram quarter stream ID. Pending/unrecognized stream data is bounded to 64 packets, 256 KiB total, one-second retention; each UDP flow has a 64-datagram queue. The router remembers 1,024 recently closed streams and drops their late datagrams. Payloads are copied out of Quinn transport allocations before queuing ([over_h3.rs:45–148][h3-router], [279–285][h3-listener], [622–630][h3-dispatch]). Preserve this ownership and bounded early-delivery behavior.

The request handler registers the pending route before authorization, holds early UDP, and switches to an active bounded UDP route only after authentication and capsule-header checks. Authentication, opening and response transmission observe STOP_SENDING/connection loss. Ordinary acknowledged response FIN does not cancel the still-live other direction; connection loss does. Datagrams on a live TCP/non-datagram request cause H3_DATAGRAM_ERROR; those received after request receive-side close are silently dropped. All request-end paths remove routes via `RouteGuard` ([over_h3.rs:379–508][h3-request], [520–574][h3-route-life]).

Idle connection shutdown sends bounded GOAWAY then closes; graceful server shutdown sends GOAWAY, drains active requests, waits up to three RTTs bounded to 100 ms–1 second for final acknowledgements, then uses H3_NO_ERROR. GOAWAY itself has a one-second send deadline ([over_h3.rs:335–365][h3-drain], [511–517][h3-goaway]). Preserve this behavior independently from upstream tunnel reconnect.

### Vendored HTTP/3 fixes are part of compatibility

The manifest pins h3, h3-datagram and h3-quinn to `43745ad87e95b0c035ac9c547aad467303213425` and patches h3/h3-quinn locally. The project-owned copy must retain reviewed fixes or demonstrate equivalent behavior before changing those dependencies. [vendor/h3/PATCH.md:7–70][h3-patches] describes truncated DATA detection, immediate CONNECT-trailer rejection, empty DATA behavior, strict request/header/control-frame validation, `OtherProtocol`, correct GOAWAY IDs, header deadlines, first-byte waiting, 431 completion, push rejection and control-frame retention while grease streams open. [vendor/h3-quinn/PATCH.md:8–29][quinn-patches] describes explicit stopped notifications and cancellation-safe receive operations that deliver the requested STOP_SENDING error code during pending reads.

These are essential even if Cloudflare's egress has its own H3 stack. Frontend and provider H3 framing/lifecycle should stay separate.

## Destination contract and all direct business-I/O sites

`Target` requires explicit nonzero port 1–65,535, strips one trailing DNS dot and lowercases names. Classic CONNECT requires bracketed IPv6; UDP URI variables use unbracketed IPv6. Names are ASCII, at most 253 characters with 1–63-character labels; underscores are currently accepted. Preserve the parser rather than letting an egress URL/parser introduce another authority interpretation ([policy.rs:40–96][target]). URI matching supports path/query templates, checks invertibility, percent-decodes after separating delimiters, and rejects malformed escapes ([uri_template.rs:156–298][uri-match]).

The current open sequence is centralized ([server/mod.rs:747–825][try-open]):

1. Subscribe to auth changes and settings before awaiting; reject stale users and malformed targets.
2. Acquire per-user/global tunnel permits, connection transport-memory reservation and 512 KiB per-tunnel memory.
3. Acquire per-user DNS permission before global DNS permission, so one user's queued lookups do not monopolize the global pool.
4. Resolve and filter under destination policy, then check the user remains current.
5. Open the chosen kind; the entire resolve/connect operation races revocation.
6. Obtain the **selected numeric destination**, update counters, and put permits/watchers/budget into `TunnelCtx`.

Direct business network access exists at these exact production sites:

| Site | Current operation | Required experimental substitution |
| --- | --- | --- |
| [policy.rs:345–357][dns-direct] | `spawn_blocking` with `std::net::ToSocketAddrs` | `Egress::resolve` using DNS packets inside the WARP data tunnel. No host resolver or resolver fallback. |
| [connect.rs:46–49][connect] | Kernel `TcpSocket::new_v4/new_v6` and `.connect(addr)` | TCP open in the independent userspace egress stack to an already-approved numeric SocketAddr. |
| [connect.rs:99–124][connect] | Kernel UDP wildcard bind, peer connect, no-fragment socket setting | Peer-pinned virtual UDP session in egress, using selected approved numeric SocketAddr. |
| [server/mod.rs:788–789][try-open] | Calls `connect::tcp/udp` | Calls required egress object; no production Direct backend/default or fallback. |
| [server/pump.rs:155–175][pump-h3], [263][pump-udp], [286–311][pump-udp] | Target TCP read/write and target UDP send/readiness/receive | Abstract target stream/session operations. Preserve budgets and protocol error propagation. |

Listener sockets in `sys::bind_tcp/udp`, accepted client sockets, and the configured Cloudflare transport endpoint are authorized transport operations, not direct business egress. `check::addresses` and `tls_connect` connect a diagnostic client to the relay itself ([check.rs:89–98][check], [439–460][check-tls]); the diagnostic module must not be invoked as a fallback business dialer. Certificate/profile/website helpers do not perform business DNS/TCP/UDP.

### Policy and DNS split

The default deny set includes local/private/shared/link-local/multicast/documentation/reserved address space for IPv4/IPv6; default denied port is SMTP/25 ([config.rs:18–56][default-policy], [279–288][defaults]). `Policy::allows_ip` canonicalizes mapped IPv4, inspects embedded IPv4 for NAT64 well-known /96, 6to4, Teredo and compatible forms, and checks the host's own interface addresses. Own-address reads are cached ten seconds, and inability to read fails closed ([policy.rs:200–324][policy-security]). Do not weaken these protections simply because the new transport reaches addresses from Cloudflare.

The implementation filters blocked addresses individually and permits remaining allowed answers; it does not refuse an entire name because one answer is blocked. It preserves resolver ordering and deduplicates canonical numeric addresses. Empty DNS answer is `NoAddresses`; all answers filtered is `AddressBlocked`. Port rejection occurs before DNS. IP literals bypass DNS permits and resolution ([policy.rs:334–373][policy]). Preserve these differences.

Recommended independent-server decomposition:

- Keep port rejection, literal handling, canonicalization, address deduplication and allow checks in the frontend policy layer.
- For a name, hold existing DNS admission through `Egress::resolve(host)` under one five-second deadline that includes admission wait. The egress resolver sends A/AAAA queries only through the active WARP generation. Its UDP-to-TCP DNS retry also stays in that generation; there is no `/etc/resolv.conf`, `lookup_host`, `ToSocketAddrs`, system DNS, direct DoH/DoT, or fallback use for business names.
- Convert returned IPs to the client's requested port and filter before any business dial/session open. Do not pass the hostname to a separate provider resolver after policy verification. Enforce the selected peer belongs to the approved candidate set.
- Add the egress stack's assigned/own addresses to self-destination protections as appropriate; preserve current host own-address protection. Keep the resolver's configured service destination explicit and distinct from arbitrary business targets.
- Keep the auth/settings watches active during DNS/dial and revalidate current policy at selected-peer handoff. This avoids accepting a target approved by stale settings just before a reload. Existing pumps already watch latest policy after opening.

Current system DNS cannot be canceled: permits are moved into the blocking task and survive a five-second timeout until the resolver returns ([policy.rs:330–357][dns-direct]). A new truly asynchronous resolver may release per-request permits on cancellation, **only if its underlying query/session allocations are also canceled/refunded**. Bound DNS result count, outstanding IDs and parser memory inside egress; async I/O does not eliminate resource limits. DNS ordering must be explicit; host `ToSocketAddrs` currently supplies preference order, while a tunnel DNS implementation has to establish it itself.

## Proposed independent async egress API

This table is a design contract, not an implementation. Object-safe methods can return boxed `Send` futures; alternatively a concrete generic egress owner can be used. The provider crate must not import Network Relay `User`, `Target`, `Refusal`, HTTP request types or client credentials.

| Capability | Suggested logical signature/result | Required semantics |
| --- | --- | --- |
| Resolve | `resolve(host) -> Result<Vec<IpAddr>, EgressError>` | Business DNS exclusively in the active tunnel; A/AAAA, bounded validation/cancellation, no fallback. App owns destination policy. |
| TCP single-address dial | `connect_tcp(SocketAddr) -> Result<TcpConnection, EgressError>` | Numeric-only, completes on actual virtual TCP establishment, selected peer known, bounded queued bytes; no host socket. App can race candidates. |
| TCP stream | `TcpConnection { io: Box<dyn AsyncIo + Send + Unpin>, peer: SocketAddr, control, generation }` where `AsyncIo: AsyncRead + AsyncWrite` | Reads/writes honor backpressure; read EOF is remote FIN; write shutdown is local FIN while read remains usable; I/O/abort errors never masquerade as clean EOF. |
| TCP control | Independent clonable abort control; idempotent `abort()` | Immediate abnormal virtual TCP teardown/RST, usable before and after stream splitting and failed HTTP response. Held until the whole pump ends. |
| UDP session | `open_udp(SocketAddr) -> Result<UdpSession, EgressError>` | One fixed numeric peer and generation, unique virtual local port, source-pinned whole datagrams, no implicit target re-resolution. Opening selects capability/route, not remote liveness. |
| UDP send | `send(payload) -> Result<(), UdpSendError>` | Sends exactly one datagram to the fixed peer or fails/drops it; empty payload valid; no partial send result interpreted as success; cancellation-safe and bounded. |
| UDP receive | `recv() -> Result<Bytes, UdpRecvError>` or equivalent buffer/poll API | One whole datagram per completion, no stream semantics or silent truncation, terminal failure wakeup; cancellation-safe packet ownership. |
| UDP release | Session Drop / explicit close | Immediately removes virtual socket/flow state, frees port and queues; pending receive/send wakes on generation failure. |
| Shared health | Generation-tagged terminal failure observation | DNS/TCP/UDP calls fail promptly on WARP/session/driver loss. Existing handles never migrate to a newly connected generation. No direct retry backend. |

Rust does not allow two non-auto traits directly as `dyn AsyncRead + AsyncWrite`; an `AsyncIo` supertrait (or equivalent project-local trait alias pattern) supplies the boxed stream. The trait is about I/O only. Peer metadata and abort control remain separate because these cannot be recovered from AsyncRead/AsyncWrite.

The provider's generic `UdpSocket::send_to/recv_from` may remain useful outside Network Relay. The server must wrap it as a **connected** UDP session: sends always use the selected peer, and receives compare the source address/port against that peer after mapped-IP canonicalization. A shared unconnected socket that returns arbitrary source packets would weaken current `connect::udp` source pinning and could deliver another flow's data. A unique per-flow port and demultiplexing key are required.

### TCP pump changes needed

The current `Counted` wrapper holds `&mut TcpStream`, counts every completed byte and pauses after byte-budget debt ([pump.rs:31–90][pump-stream]). Generalize its target to `AsyncRead + AsyncWrite + Unpin` while retaining counters and bounded buffers.

`tcp_over_stream` currently uses `copy_bidirectional_with_sizes` with 64 KiB each way and races the entire two-direction operation against cancellation. On error it sets SO_LINGER=0 so target drop sends reset ([pump.rs:93–121][pump-stream]). Replace kernel linger with the egress abort handle; do not call write shutdown on cancellation, since that would turn failure into orderly FIN.

H3 currently splits the concrete TCP socket with `into_split`; successful FIN in one direction leaves the other direction and cancellation active. When aborting, it resets both H3 halves, sets reset-on-close on the target read half, and `forget()`s the target write half to prevent automatic FIN ([pump.rs:130–225][pump-h3]). With boxed I/O, use an appropriate generic split and retain independent abort control outside both directional futures. Explicitly abort **before dropping halves**. Do not emulate `OwnedWriteHalf::forget` by leaking a generic half or leaving a background virtual connection alive. Each direction can finish independently; both must finish for an orderly close. Cancellation after one FIN remains observable.

Handshake abort also occurs before pumps start: `Opened::abort` on failed h2 response, failed H1 upgrade, and canceled/failed H3 response ([server/mod.rs:529–550][opened], [over_tcp.rs:359–365][http2], [463–478][http1], [over_h3.rs:474–488][h3-request]). An abort handle is mandatory to preserve those semantics.

Current target TCP opens alternate address families with 250 ms stagger, start another attempt immediately after failure, race until one succeeds, and have one overall configurable connect deadline; dropping the JoinSet cancels the losers ([connect.rs:13–95][connect-race]). Preserve this algorithm with virtual TCP rather than racing host sockets. Loser cancellation must remove stack entries and local ports, including an attempt that established just as the winning result was chosen. Map virtual refused/timeout/unreachable distinctly. The default ten-second TCP deadline is separate from the five-second DNS deadline ([config.rs:283–288][defaults]).

### UDP pump changes needed

Current outbound client events refresh activity, parse a context variable integer, drop unknown contexts, permit context-zero empty datagrams and reject context-zero payloads over 65,527 bytes as malformed. Packet/byte quota excess is dropped. Awaited send preserves a new flow's first datagram, often a QUIC handshake ([pump.rs:227–284][pump-udp], [datagram.rs:18–38][datagram]). Preserve these rules.

Current inbound kernel processing waits for readable, batches at most 32 `try_recv`s using one buffer, then yields. Cancellation and UDP idle deadline wrap the entire transfer including blocked sends, with cancellation priority ([pump.rs:286–324][pump-udp]). An async session may use one cancel-safe receive per selection and a bounded ready-packet batch, but it must keep equivalent fairness and allow cancellation during sends. Do not spawn an unbounded producer/channel as a substitute.

The default UDP idle timeout is 300 seconds, configurable 120–3,600 ([config.rs:129–132][relay-config], [333–337][config-check]). Client DATAGRAM activity refreshes before context validation/drop; accepted target receives refresh activity after quota acceptance. Keep that existing behavior unless deliberately documented otherwise. A UDP request's normal stream FIN closes the flow; it is not a TCP-style half-close. Idle close is normal, while malformed capsules/context/payload, client cancellation and target failure produce the existing abort categories.

The current transient datagram errors are WouldBlock, Interrupted, PermissionDenied, EMSGSIZE and ENOBUFS. They drop packets; refused/host/network-unreachable and other unusable socket errors terminate the flow with CONNECT_ERROR ([pump.rs:332–353][udp-errors]). A userspace backend cannot rely on raw OS errno; define typed `TooBig`, `QueueFull`, transient and terminal errors and map them equivalently. Report ICMP destination-unreachable when the backend can observe it. If the stack cannot surface ICMP, document that limitation; do not claim existing immediate unreachable behavior is retained.

At an effective inner MTU of 1,280, a WARP userspace stack without IP fragmentation has per-datagram ceilings of **1,252 bytes for IPv4** and **1,232 bytes for IPv6** before additional IP options/extensions. Actual capacity must come from the active backend's `max_payload`/effective MTU, rather than being hardcoded to this example. The backend must report oversized datagrams as `TooBig`/EMSGSIZE for packet drop. The frontend's RFC maximum remains 65,527: a valid but path-oversized packet is lost as UDP allows, not labeled malformed solely due to the backend MTU. Outer QUIC DATAGRAM capacity is another independent ceiling. No backend may silently fragment IP to preserve large UDP. Virtual TCP must segment to the available inner path instead.

The provider source review reports that the stack can lower MTU below 1,280 and that the outer QUIC initial size may temporarily imply less inner capacity. Below the IPv6 minimum, IPv6 must not be advertised as ready without a valid strategy. Tunnel DNS EDNS size and UDP-to-TCP fallback must also follow available capacity. See [RESEARCH-CF-EGRESS.md](RESEARCH-CF-EGRESS.md) for the provider-specific evidence and extraction hazards, including a generic upstream server path that uses host DNS and must not enter this backend.

## Capsules, datagrams and resource lifecycle to preserve

`Tunnel` is already independent of target sockets and can remain unchanged. It carries HTTP Datagram payloads, including context ID, while the egress session carries only UDP application bytes. This distinction prevents double context framing or accidental reuse of Cloudflare's CONNECT-IP framing for clients.

- H1/H2 carry DATAGRAM capsules on the reliable request stream. H3 normally uses QUIC DATAGRAM frames and still reads capsules ([tunnel.rs:241–304][tunnel]).
- H3 falls back to DATAGRAM capsules when peer HTTP Datagram settings or QUIC DATAGRAM support is absent/unavailable. A datagram too large for supported QUIC DATAGRAM capacity is dropped as `TooBig`; it must not be resent reliably merely to fit ([tunnel.rs:281–303][tunnel]).
- Capsule decoder skips unknown types and unknown UDP contexts incrementally rather than accumulating potentially huge values. Context-zero UDP has the 65,527-byte limit. Partial capsule at EOF is malformed ([capsule.rs:57–153][capsules]).
- CONNECT-UDP rejects Content-Length, Content-Type and Transfer-Encoding. H2 and H3 established tunnels reject trailers; vendored H3 does so before FIN ([proto/mod.rs:46–50][proto], [tunnel.rs:336–353][tunnel], [h2_stream.rs:58–64][h2-stream]).
- Stream chunks copied into inbound queues are at most 16 KiB with queue depth eight; outbound capsule queue depth is 16 with a combined writer/queue byte cap 128 KiB. Payload copies avoid retaining entire transport allocations ([tunnel.rs:24–39][tunnel-bounds], [143–164][tunnel], [306–327][tunnel]).
- Dropping a UDP tunnel tells reader tasks to stop and writers to drain for at most one second; abort categories map malformed to H3_MESSAGE_ERROR/h2 PROTOCOL_ERROR, destination failure to H3_CONNECT_ERROR/h2 CONNECT_ERROR, cancellation to H3_REQUEST_CANCELLED/h2 CANCEL ([tunnel.rs:62–89][tunnel-abort], [168–212][tunnel], [397–434][tunnel]). Keep egress session cleanup separate and prompt; it must not depend on an ingress writer drain finishing.

Admission state is RAII: global owned semaphore permit, per-user slot and memory permit live in `TunnelCtx`, alongside user/policy watchers and traffic budget ([server/mod.rs:552–620][cancel], [811–825][try-open]). HTTP/1 upgraded tunnels retain connection admission through `ConnInfo` even after Hyper's connection future returns ([server/mod.rs:345–389][conn-info]). Every early return, canceled DNS/dial, response failure, target reset, datagram error and backend generation loss must refund **both** relay reservations and backend allocations.

Current memory budgets allocate half detected memory to shared capacity, a 1–8 MiB transport reservation per multiplexed connection, 256 KiB for H1, and 512 KiB per tunnel ([server/mod.rs:166–183][relay-state], [limits.rs:452–492][memory]). Those constants cover frontend buffers, not a new virtual TCP stack's per-socket buffers, WARP queues, DNS state or additional packet copies. Allocate and cap backend memory explicitly, reserve its shared base state, and revise the independent server's total accounting as needed. Retaining current constants while adding unaccounted large per-flow stack buffers would make old capacity claims false.

Settings reload replaces policies/timeouts/logging/budgets while existing tunnels watch destinations; unchanged budget settings preserve debt across reload/reconnect ([server/mod.rs:193–209][reload], [246–257][budget], [586–597][cancel]). Preserve current semantics for established tunnel timeouts/budgets rather than silently resetting every budget on provider reconnect. For backend-generation loss, fail existing flows and require new client requests for new sessions; never move byte streams or old UDP mappings into a new generation.

## Helpers and existing client compatibility

The cover website is local file-backed; startup/reload reads bounded snapshots rather than making upstream website requests. Files are limited to 1,000 and 64 MiB total, published profiles to 1 MiB. Missing `.well-known` paths return 404, ordinary missing paths use the index, unauthenticated CONNECT gets index content with 404, ordinary unsupported methods get 405/Allow, and no configured website means 404 ([web.rs:42–49][web], [114–155][web], [190–258][web]). Keep framing-header restrictions and safe file-opening/symlink protections ([web.rs:130–145][web], [297–460][web-files]).

One-time published profiles are served to GET only, within 15 minutes, at most once even across overlapping reload snapshots; `.publish` is hidden storage ([web.rs:158–176][web], [232–246][web]). These files carry client credentials; they must remain owner-only and never be logged or committed. `private_file::write` uses a mode-0600 exclusive temporary file, sync then atomic rename, rejecting nonregular existing output ([private_file.rs:9–30][private]). Preserve this helper.

Apple `.mobileconfig` profiles contain `com.apple.relay.managed`; the DDM form contains `com.apple.configuration.network.relay`. Both point `HTTP3RelayURL` and `HTTP2RelayURL` at the same HTTPS UDP URI template, carry `Authorization` in AdditionalHTTPHeaderFields for password users, and optionally reference client certificate identity ([profile.rs:190–208][profile], [252–270][profile], [321–374][ddm]). Domain/FQDN routing, exclusions, optional toggle, DNS failover and relay UUID controls remain client policy. An egress route change requires no alteration to these values. Certificates/profile generation use local cryptography and files, not target networking ([identity.rs:25–45][identity], [main.rs:468–533][profile-cli]).

Existing NF/RS clients continue speaking standard Network Relay. Their local SOCKS listeners, native Network.framework transport, and downstream DNS choices do not need provider-specific code. Preserve endpoint template/auth/status/half-close/abort semantics and ingress settings; changing the cloud outbound provider must remain invisible at those APIs. The profile's `AllowDNSFailover` setting is an Apple-side routing option and is not authorization for this server to fall back to host DNS.

The `check` helper exercises six protocol/transport combinations plus hidden-without-password behavior ([check.rs:103–131][check]). Its configured TCP target request and UDP DNS payload go through the relay. Resolving the **relay frontend hostname** is separate from resolving business targets; use explicit ingress addresses for no-DNS validation where useful. `serve --check` currently validates config/certificate/website/users only, not live business reachability ([main.rs:322–335][main-serve]). Keep its claim precise; add separate egress readiness and functional checks in the independent project.

## Minimal insertion/change plan for the independent server

| Change | Files in the project-owned frontend copy | Why necessary |
| --- | --- | --- |
| Required egress injection and lifecycle supervision | `src/server/mod.rs`, independent `src/main.rs` and config entry | Prevents a constructor or startup path from accidentally selecting direct business I/O. Share one supervised tunnel/stack; surface readiness and terminal loss. |
| Resolver dependency separated from policy | `src/policy.rs`, `Relay::try_open` | Removes system business DNS while preserving all validation, permit and deny rules. |
| Abstract result metadata/control | `Opened`, target egress adapter module | Replace concrete TcpStream/UdpSocket with virtual stream/session; retain numeric peer and explicit abort. |
| Generalize TCP pumps | `src/server/pump.rs` | Keep byte accounting, half-close and client codes; remove kernel linger/into_split/forget assumptions. |
| Generalize UDP pump | `src/server/pump.rs`, connected virtual UDP adapter | Preserve one-flow/one-peer datagrams, cancellation/fairness, quotas, idle and typed error mappings. |
| Exclude direct production dialer | `src/connect.rs`, `src/lib.rs` module exposure | No direct fallback and no reachable production business `TcpSocket`, `UdpSocket::bind` or host resolver. Address-race helper may be reused with virtual connect callbacks. |
| Independent CLI/service defaults | Project-owned manifest, CLI/help, deployment examples | Distinct binary/config/log/service names prevent collision with original Network Relay. Preserve the standard ingress format. |
| Project-local regression harness injection | Project-owned tests only | Existing loopback/direct fixtures require a fake/test egress or isolated injected test backend. No source/test edits in original repositories. |

Do not place a generic upstream-IP tunnel adapter inside `Tunnel`, `QuicDatagrams`, URI matching or auth. Those describe client HTTP semantics, while the new egress moves target packets. No new protocol branch is needed in each of H1/H2/H3 beyond their abstract Opened values and normal pump invocation.

For startup, establish/configure the WARP egress owner under bounded deadlines, then report readiness accurately. A failed backend can either prevent listener readiness or serve cover and authenticated 502/503 while recovering under a bounded policy; choose and document one behavior in the root implementation plan. In every state it fails closed. Preserve SIGTERM listener stop/GOAWAY/drain and explicitly stop the egress driver after draining or after the drain deadline ([server/mod.rs:915–945][run]). Egress reconnection should be bounded/backed off and observable; authentication or business connection failure must never invoke a direct route.

## Validation required after implementation

No checks listed here were executed by this research subtask. Source-derived tests are acceptance requirements for the future independent implementation, not evidence of runtime compatibility.

Reuse the upstream regression behaviors in project-local tests after dependency injection. Strong existing anchors include:

| Behavior | Existing exact test location |
| --- | --- |
| H1 upgraded admission/drain and transport churn | [tests/in_process.rs:29–56][test-h1], [356–454][test-churn] |
| Six TCP/UDP transport variants plus hidden auth | [1214–1230][test-all] |
| Auth errors, denied targets, unreachable Proxy-Status | [1252–1337][test-auth-policy] |
| H2/H3 TCP half-close, bulk data, client reset, revocation | [1339–1517][test-halfclose] |
| H3 early UDP and removed user | [1519–1589][test-early] |
| Oversize/capsule metadata/trailers/empty DATA | [870–1132][test-capsule] |
| H3 capsule fallback and datagram-on-TCP | [1134–1187][test-fallback] |
| UDP revoked cancellation and late datagram drop | [1697–1759][test-udp-cancel] |
| Client-certificate auth, per-user tunnels, connection/bandwidth limits | [1840–1980][test-limits] |
| UDP terminal destination error and settings reload block | [2260–2324][test-udp-error], [2408–2463][test-reload] |
| GOAWAY/drain, unwritten stream 0 and delayed HEADERS | [2326–2406][test-shutdown], [2504–2584][test-idle] |
| Case-insensitive token/unencoded IPv6/correct abort while pending | [2702–2883][test-native] |

The original fragmentation test at [1190–1211][test-fragment] checks kernel socket settings. In the independent project replace that assertion with meaningful packet-level proof that virtual UDP never emits IP fragments and oversize valid datagrams are dropped/reported. Keep kernel ingress tests where they still describe ingress.

Add egress-specific contract checks with a controllable fake provider, including:

1. Unauthorized requests, mismatched templates and denied ports cause zero resolver/dial/session calls.
2. Domain answers are tunnel-resolved, canonicalized, filtered and deduplicated before numeric dial. Mixed allowed/denied answers preserve the allowed set; all-denied and no-answer refusals stay distinct. DNS timeout includes permit wait. Mapped/embedded IPv4 and own/assigned tunnel destinations remain protected.
3. The provider cannot select a numeric peer outside the approved set, nor change peer mid-flow. UDP unexpected-source packets are dropped and never delivered to another client.
4. Canceled/losing TCP opens, timed-out DNS, response/upgrade failures, quota drops and terminal provider loss leave no virtual socket/port/queue allocation or relay permit behind.
5. Read and write half-close remain independent; abort before/after split produces abnormal close, never a clean FIN. A failure after one directional FIN remains observable. Tests exercise pending backpressure and empty UDP, not only short echo payloads.
6. Generation failure wakes pending DNS/TCP/UDP operations and terminates all old-generation sessions. Reconnect does not revive stale sessions, reset user budgets or select a direct fallback.
7. Both ingress and egress bounded queues remain within declared byte limits under stalled peers and datagram floods; cancellation and idle timers still progress.
8. Path-valid but backend-oversize UDP is dropped as too big, protocol-invalid oversized context-zero UDP remains malformed, and outgoing IP fragmentation never occurs.
9. In a network-observed functional check, frontend business TCP, UDP and DNS exit through WARP. Permit only the necessary outer Cloudflare transport/control destinations and verify no direct target sockets/DNS appear. A source scan alone is insufficient proof; scan plus restricted routing/packet capture/effectively independent egress identity provide stronger evidence.
10. Exercise unchanged NF/RS clients and an Apple generated profile on supported Apple systems against the experimental endpoint. Linux HTTP integration tests do not establish native Network.framework behavior; an authenticated idle CONNECT-UDP admission does not establish destination reachability.

## Remaining design decisions and limitations

The root plan must choose the egress crate API, virtual TCP implementation/abort behavior, generation failure supervision, tunnel DNS resolver policy, and whether backend readiness gates listening. The proposed common implementation supplies a Tokio-compatible `TcpStream` wrapper with `peer_addr`/`local_addr`, independent `abort` control and generic splitting, plus a connected UDP wrapper with `send`/`recv`/`peer_addr`/`max_payload`. These wrappers satisfy the conceptual contract above; the frontend can box them or use their concrete public types without importing provider protocol internals. The plan must reconcile actual inner/outer MTU and account for backend memory. None of these requires an ingress protocol invention or client changes.

Source review establishes the minimal seam and behaviors to preserve. It does not establish live Cloudflare acceptance, WARP account suitability, remote UDP ICMP support, DNS answer equivalence, throughput, IPv6 reachability or Apple client compatibility. Those require the provider research and subsequent functional validation. Preserve these distinctions in readiness and experimental release documentation.

<!-- All links below pin exact reviewed source, so future upstream changes cannot silently move the evidence. -->
[lib]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/lib.rs#L6-L22
[main-cli]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/main.rs#L182-L305
[main-serve]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/main.rs#L308-L354
[relay-state]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/mod.rs#L80-L191
[run]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/mod.rs#L834-L950
[request-kind]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/mod.rs#L292-L343
[open]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/mod.rs#L669-L825
[tcp-listener]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/over_tcp.rs#L131-L285
[tcp-handlers]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/over_tcp.rs#L287-L495
[h3-listener]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/over_h3.rs#L201-L365
[h3-request]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/over_h3.rs#L369-L508
[target]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/policy.rs#L22-L96
[policy]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/policy.rs#L285-L374
[connect]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/connect.rs#L44-L125
[pump-stream]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/pump.rs#L25-L121
[pump-h3]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/pump.rs#L130-L225
[pump-udp]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/pump.rs#L227-L354
[h2-stream]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/h2_stream.rs#L11-L118
[tunnel-bounds]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/tunnel.rs#L24-L39
[tunnel]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/tunnel.rs#L132-L435
[proto]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/proto/mod.rs#L14-L50
[capsules]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/proto/capsule.rs#L15-L154
[datagram]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/proto/datagram.rs#L18-L38
[uri]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/proto/uri_template.rs#L59-L96
[uri-match]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/proto/uri_template.rs#L156-L298
[auth-state]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/auth.rs#L262-L367
[auth]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/auth.rs#L472-L695
[client-key]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/limits.rs#L15-L39
[memory]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/limits.rs#L418-L492
[tls]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/tls.rs#L24-L125
[certs]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/certs.rs#L122-L178
[web]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/web.rs#L42-L259
[profile-options]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/profile.rs#L24-L65
[profile]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/profile.rs#L190-L374
[private]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/private_file.rs#L9-L30
[check]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/check.rs#L28-L140
[check-tls]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/check.rs#L439-L460
[authorize]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/mod.rs#L673-L724
[basic]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/auth.rs#L89-L104
[auth-bounds]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/auth.rs#L57-L74
[cancel]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/mod.rs#L552-L620
[refusal]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/policy.rs#L98-L197
[tcp-config]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/over_tcp.rs#L27-L110
[http1]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/over_tcp.rs#L383-L494
[h2-config]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/over_tcp.rs#L218-L284
[http2]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/over_tcp.rs#L287-L379
[h3-transport]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/over_h3.rs#L151-L198
[server-constants]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/mod.rs#L42-L78
[h3-router]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/over_h3.rs#L45-L148
[h3-dispatch]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/over_h3.rs#L622-L630
[h3-route-life]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/over_h3.rs#L520-L574
[h3-drain]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/over_h3.rs#L335-L365
[h3-goaway]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/over_h3.rs#L511-L517
[h3-patches]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/vendor/h3/PATCH.md#L7-L70
[quinn-patches]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/vendor/h3-quinn/PATCH.md#L8-L29
[try-open]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/mod.rs#L747-L825
[dns-direct]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/policy.rs#L330-L357
[default-policy]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/config.rs#L18-L56
[defaults]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/config.rs#L279-L288
[policy-security]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/policy.rs#L200-L324
[opened]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/mod.rs#L529-L550
[connect-race]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/connect.rs#L13-L95
[relay-config]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/config.rs#L109-L163
[config-check]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/config.rs#L315-L376
[udp-errors]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/pump.rs#L332-L353
[tunnel-abort]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/tunnel.rs#L62-L89
[conn-info]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/mod.rs#L345-L389
[reload]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/mod.rs#L193-L209
[budget]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/server/mod.rs#L246-L257
[web-files]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/web.rs#L297-L460
[ddm]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/profile.rs#L321-L374
[identity]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/identity.rs#L25-L45
[profile-cli]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/src/main.rs#L468-L533
[test-h1]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/tests/in_process.rs#L29-L56
[test-churn]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/tests/in_process.rs#L356-L454
[test-all]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/tests/in_process.rs#L1214-L1230
[test-auth-policy]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/tests/in_process.rs#L1252-L1337
[test-halfclose]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/tests/in_process.rs#L1339-L1517
[test-early]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/tests/in_process.rs#L1519-L1589
[test-capsule]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/tests/in_process.rs#L870-L1132
[test-fallback]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/tests/in_process.rs#L1134-L1187
[test-udp-cancel]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/tests/in_process.rs#L1697-L1759
[test-limits]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/tests/in_process.rs#L1840-L1980
[test-udp-error]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/tests/in_process.rs#L2260-L2324
[test-reload]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/tests/in_process.rs#L2408-L2463
[test-shutdown]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/tests/in_process.rs#L2326-L2406
[test-idle]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/tests/in_process.rs#L2504-L2584
[test-native]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/tests/in_process.rs#L2702-L2883
[test-fragment]: https://github.com/ArcCal/network-relay/blob/cc7ea4df2924d0454ab5075e089cbb53d94b178e/tests/in_process.rs#L1190-L1211
