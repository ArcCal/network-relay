# cf-masque extraction and reusable egress design

Research baseline: `ArcCal/cf-masque` at
`a65c600494cd50fed2c621b8538be7abda5e7fa4`.
The inspected, clean snapshot is
`.research/upstream/cf-masque`; `/workspace/cf-masque` is a read-only reference.
Line citations below refer to that pinned snapshot, not to its historical
review documents. This report proposes implementation work; it does not claim
that a new library, a live WARP test, or a soak test has already run.

## Decision

Extract the userspace packet transport, TCP/IP stack, and DNS resolver into an
independent Rust library, tentatively `cf-masque-egress`. Keep Network Relay
policy, HTTP ingress, authentication, metrics presentation, and request framing
in the application. All destination TCP, UDP, and DNS must enter the userspace
stack, whose only packet wire is one authenticated WARP CONNECT-IP tunnel.

The current upstream primitives provide a useful starting point, but simply
making modules public would not satisfy fail-closed lifecycle requirements.
The upstream stack has no terminal session state. When its packet runner ends,
existing stream and UDP operations can remain pending, and UDP writes can be
accepted into a stack with no working wire. A terminal error and explicit
wakeup mechanism are required before integrating the library.

## Pinned source map

Each source URL is permanent at the baseline above and resolves without a
local research checkout.

| Component | Inspected source and purpose |
| --- | --- |
| Tunnel, H3, H2, TLS, capsule parser | [`src/masque.rs`](https://github.com/ArcCal/cf-masque/blob/a65c600494cd50fed2c621b8538be7abda5e7fa4/src/masque.rs), [pinned source](https://github.com/ArcCal/cf-masque/blob/a65c600494cd50fed2c621b8538be7abda5e7fa4/src/masque.rs) |
| Userspace TCP/UDP and socket lifetime | [`src/netstack.rs`](https://github.com/ArcCal/cf-masque/blob/a65c600494cd50fed2c621b8538be7abda5e7fa4/src/netstack.rs), [pinned source](https://github.com/ArcCal/cf-masque/blob/a65c600494cd50fed2c621b8538be7abda5e7fa4/src/netstack.rs) |
| DNS parser, cache, in-flight sharing | [`src/dns.rs`](https://github.com/ArcCal/cf-masque/blob/a65c600494cd50fed2c621b8538be7abda5e7fa4/src/dns.rs), [pinned source](https://github.com/ArcCal/cf-masque/blob/a65c600494cd50fed2c621b8538be7abda5e7fa4/src/dns.rs) |
| Registration/configuration | [`src/api.rs`](https://github.com/ArcCal/cf-masque/blob/a65c600494cd50fed2c621b8538be7abda5e7fa4/src/api.rs), [pinned source](https://github.com/ArcCal/cf-masque/blob/a65c600494cd50fed2c621b8538be7abda5e7fa4/src/api.rs) |
| Packet pump and Happy Eyeballs currently inside SOCKS | [`src/socks.rs`](https://github.com/ArcCal/cf-masque/blob/a65c600494cd50fed2c621b8538be7abda5e7fa4/src/socks.rs), [pinned source](https://github.com/ArcCal/cf-masque/blob/a65c600494cd50fed2c621b8538be7abda5e7fa4/src/socks.rs) |
| Kernel backend that must not become business egress | [`src/net.rs`](https://github.com/ArcCal/cf-masque/blob/a65c600494cd50fed2c621b8538be7abda5e7fa4/src/net.rs) |
| Scoped forwarding cancellation | [`src/shutdown.rs`](https://github.com/ArcCal/cf-masque/blob/a65c600494cd50fed2c621b8538be7abda5e7fa4/src/shutdown.rs) |
| Diagnostic IP/ICMP/DNS probes | [`src/probe.rs`](https://github.com/ArcCal/cf-masque/blob/a65c600494cd50fed2c621b8538be7abda5e7fa4/src/probe.rs), [`src/ip.rs`](https://github.com/ArcCal/cf-masque/blob/a65c600494cd50fed2c621b8538be7abda5e7fa4/src/ip.rs) |
| Dependency/features and patched H3 | [`Cargo.toml`](https://github.com/ArcCal/cf-masque/blob/a65c600494cd50fed2c621b8538be7abda5e7fa4/Cargo.toml), [`vendor/h3/PATCH.md`](https://github.com/ArcCal/cf-masque/blob/a65c600494cd50fed2c621b8538be7abda5e7fa4/vendor/h3/PATCH.md) |
| CLI/protocol fixture suites | [`tests/transport`](https://github.com/ArcCal/cf-masque/blob/a65c600494cd50fed2c621b8538be7abda5e7fa4/tests/transport/run.sh) |
| Privileged RFC-server integration | [`tests/local-check.sh`](https://github.com/ArcCal/cf-masque/blob/a65c600494cd50fed2c621b8538be7abda5e7fa4/tests/local-check.sh), [`tests/ipv6-check.sh`](https://github.com/ArcCal/cf-masque/blob/a65c600494cd50fed2c621b8538be7abda5e7fa4/tests/ipv6-check.sh) |

The crate is currently a binary: `main.rs:4–14` declares private modules and
there is no library target. Its manifest requires Rust 1.91 and smoltcp 0.14,
with IP-medium IPv4/IPv6, TCP, UDP, Cubic, and 32 assembler segments. It does
not enable IP fragmentation. The Git H3/H3-Quinn revision is
`43745ad87e95b0c035ac9c547aad467303213425`, with the local H3 patch covering
custom protocol tokens, draft-00 datagram SETTINGS, and peer SETTINGS/error
inspection. Preserve that exact patched compatibility surface and its license
until replacements have equivalent tests. The new workspace's root patch must
apply to H3-Quinn as well; a member-only patch does not establish this.

## What upstream actually implements

### Tunnel and transport selection

`Options` holds a numeric `SocketAddr`, SNI, URI, static protocol token,
verification/authentication variants, optional socket mark, keepalive, idle
timeout, one explicit `Transport::{H3,H2}`, and an RFC-server flag
(`masque.rs:78–122`). There is no H3-to-H2 automatic fallback. H3 retries once
only when setup mentions QUIC `PROTOCOL_VIOLATION` (`masque.rs:195–208`).
Preserve explicit selection in public configuration and report the selected
transport; a transport failure must never open a destination host socket.

H3 creates one host UDP socket to the configured numeric WARP endpoint. Quinn
uses 20-byte connection IDs, TLS 1.3, configured keepalives/idle timeout,
initial UDP capacity 1332, and 4 MiB datagram send/receive buffers
(`masque.rs:429–475`). The H3 client sends both normal and draft-00 datagram
SETTINGS, does not advertise server-side extended CONNECT support, and waits
at most five seconds for peer SETTINGS before requiring standard datagrams.
It tolerates Cloudflare's absent extended-CONNECT setting
(`masque.rs:486–539`). The CONNECT request uses `cf-connect-ip`,
`capsule-protocol: ?1`, the configured URI, and no User-Agent. Successful setup
then sends IPv4/IPv6 default ROUTE_ADVERTISEMENT capsules with a 15-second
deadline (`masque.rs:541–579`).

H3 IP datagrams contain Quarter Stream ID, Context ID zero, and the IP packet.
Receive decoding compares integer values, allowing legal non-minimal varint
widths and ignoring other streams/contexts (`masque.rs:283–310,946–958`).
The boxed H3 `SendRequest` is intentionally retained so the connection stays
open; removing it during extraction would be a lifecycle regression
(`masque.rs:179–180,624`). A capsule reader watches the CONNECT response stream
and closes Quinn on EOF, decoding failure, or stream error
(`masque.rs:581–610`). H3 presently requires negotiated HTTP datagrams: it
does not provide an H3 capsule fallback.

H2 creates one host TCP socket to the configured numeric WARP endpoint and
then TLS/H2, with 15-second bounds on TCP, TLS, H2 setup, readiness, and CONNECT
response stages (`masque.rs:630–755`). Cloudflare compatibility specifically
allows absent ALPN, while an RFC test server must negotiate `h2`; any other
ALPN fails (`masque.rs:656–671`). The WARP wire form is plain CONNECT to the
URI authority (normally `cloudflareaccess.com:443`), headers
`cf-connect-proto: cf-connect-ip` and `pq-enabled: false`, no User-Agent and no
Capsule-Protocol header. WARP DATAGRAM capsules carry bare IP with no Context
ID and no initial route advertisement (`masque.rs:717–739,756–763`). RFC mode
uses extended CONNECT, a Context ID, and routes instead. Historical
`FOLLOW_UP_ASSESSMENT.md` describes older missing-ALPN rejection; the pinned
code and current wire tests are authoritative for the present behavior.

H2 transport windows are 4 MiB per stream and 8 MiB per connection. A bounded
256-capsule output queue is drained by one writer; it splits each capsule
according to currently granted H2 capacity, avoiding a deadlock when a
capsule is larger than a peer receive window (`masque.rs:674–678,764–777,
930–945`). The reader releases received DATA capacity and incrementally
parses capsules into a bounded 256-packet input queue, dropping packets when
that queue is full (`masque.rs:787–824`). H2 has reliable outer TCP transport,
but still applies datagram-style inner queue loss; TCP retransmits, UDP does
not. This is a performance tradeoff that deserves measurements and counters.

### Authentication and configuration

`api::Config` accepts cf-masque and usque aliases, stores registration IDs,
access token/license, a base64 P-256 private key, endpoint public key, endpoint
addresses, and assigned tunnel addresses (`api.rs:26–51`). It converts Go's
SEC1 EC key form into PKCS#8 as needed. Endpoint parsing accepts only numeric
addresses; H3 uses registered endpoints. H2 defaults to `162.159.198.2` for
IPv4 when absent and requires an explicitly configured H2 IPv6 endpoint
(`api.rs:99–177`). Loading a configuration does not make an API request.

The tunnel itself needs the enrolled private key, endpoint SPKI, numeric
endpoint, and tunnel addresses. Access token and license are registration
control-plane data and need not enter every runtime session. Pinned TLS checks
the exact leaf SubjectPublicKeyInfo and still verifies the TLS handshake
signature with Rustls; it intentionally does not use public CA/name validation
for the WARP pinning mode (`masque.rs:1206–1238,1270–1323`). A fresh self-signed
P-256 client certificate is generated for each connection, valid from five
minutes before now through 24 hours after now (`masque.rs:1241–1264`). Never
replace these checks with insecure certificate acceptance. Wrong-key rejection
must apply equally to H2 and H3.

Registration is a POST to `/v0a4471/reg` with a disposable WireGuard key, then
a PATCH to `/v0a4471/reg/{device_id}` enrolling the P-256 public SPKI and changing
the tunnel type to MASQUE. Requests use Android WARP version headers; an
optional access JWT is supplied only on registration; enrollment uses the
returned bearer token (`api.rs:248–313,331–386`). The CLI requires explicit
terms acceptance before registration (`main.rs:403–417`). Do not automatically
register on startup failure or add this external side effect to an egress dial.

`Config::save` creates a new file exclusively, mode 0600 on Unix, writes a
complete JSON configuration, and syncs; it refuses existing files and symlinks
(`api.rs:68–96,486–533`). Preserve these properties in any separate registration
utility. Upstream derives `Debug` for secret-bearing configuration/account
types and includes raw API response text in errors (`api.rs:26,183,316–327`).
The extraction should use redacted Debug and bounded/sanitized API errors,
never dump configuration or response bodies into normal logs, and never
include secret material in committed examples or test evidence.

### Userspace TCP/UDP

`NetStack` is an `Arc<Shared>` with a single mutex protecting smoltcp interface,
IP-medium packet queues, sockets, assigned addresses, and linger records.
Its runner polls the stack/timers, drains outgoing packets with `try_send`,
then waits for input, socket notification, or at most one second
(`netstack.rs:66–86,169–205`). All default routes point into this packet wire;
there is no host destination socket in `netstack.rs` (`netstack.rs:327–344`).

TCP uses a 2 MiB RX buffer and 512 KiB TX buffer per connection, disables
Nagle, uses Cubic, gives SYN setup ten seconds and unanswered TCP data 120
seconds (`netstack.rs:37–55,210–239,301–312`). `TcpStream` implements Tokio
AsyncRead/AsyncWrite using smoltcp send/receive wakers. Reads report EOF on a
finished peer half; shutdown queues FIN after data. Flush presently returns
immediate success, representing local acceptance rather than remote ACK
completion (`netstack.rs:468–543`). Dropping a stream with unread data or an
unfinished handshake aborts it; otherwise it closes gracefully and retains a
socket for up to 30 seconds (`netstack.rs:548–562,379–396`). Timers must keep
running while graceful cleanup is pending. Library extraction must preserve
half-close and cancellation behavior, and add an explicit abort handle for
adapters that must issue a reset after a failed relay.

UDP has 128 RX/TX datagram slots and 128 KiB buffers per direction; sending
waits for socket buffer capacity and receiving returns one complete `Bytes`
plus source address (`netstack.rs:264–290,627–675`). At the normal MTU of 1280,
maximum payloads are 1252 for IPv4 and 1232 for IPv6. Larger datagrams fail;
upstream provides no fragmentation/reassembly path. A new adapter must expose
this explicit limit and an identifiable message-too-large error. An API
accepting 64 KiB relay datagrams cannot imply that all such datagrams cross
this tunnel. The app can pin a numeric UDP peer and ignore other source
addresses; the reusable library can retain generic `send_to`/`recv_from`.
Mapped IPv4 addresses should be canonicalized consistently at validation,
family selection, and reply filtering.

The stack caps all sockets, including DNS, TCP races, and linger, at 1024 and
has a finite randomized ephemeral-port allocator with a bounded full-range
scan (`netstack.rs:315–322,361–422`). This bounds socket count, not bytes:
1024 TCP sockets can reserve roughly 2.5 GiB of buffer capacity before other
resources. Upstream changes glibc allocator behavior globally in the binary
to reduce resident memory under churn (`main.rs:367–380`). A generic library
must not change the application's allocator process-wide. Make buffer/socket
budgets explicit, test peak and recovered memory, and leave any allocator
selection to the embedding executable.

### DNS and policy boundary

`dns::Resolver` resolves through `Net`; in SOCKS userspace mode this is the
stack. It never calls the host resolver for destination names. It sends A and
AAAA lookups concurrently and returns available families, with IPv6 first;
independent family lookups also support Happy Eyeballs without waiting for a
slow family (`dns.rs:75–168`). The upstream `Net` abstraction also contains a
kernel/TUN backend (`net.rs:27–32,95–148`); replace that abstraction with a
stack-only handle in the extracted DNS path. Do not carry host `lookup_host`
from generic-server CLI setup (`main.rs:274–276`) into runtime destination or
resolver behavior. Use explicit numeric outer endpoints and numeric DNS
servers, so bootstrap itself cannot leak a destination hostname.

DNS uses random IDs and source ports, checks source server/port, transaction,
question/name/type/class, CNAME-chain ownership, record lengths and compression
bounds. It retries each reachable server at two-second and three-second rounds,
and retries truncated UDP responses over stack TCP with a five-second whole
TCP-query bound (`dns.rs:203–290,301–571`). EDNS advertises 1232. Cache lifetime
is the minimum relevant CNAME/address TTL, bounded at one hour; negative
lifetimes derive from applicable SOA records, zero TTL is uncacheable, and
transport failure is not negatively cached. Cache entries are bounded at
4096 (`dns.rs:169–202,388–478`). Shared in-flight queries use OnceCell and a
scoped guard that cleans completed/last-cancelled waiters while preserving
survivors (`dns.rs:43–73,140–164`). Preserve these cancellation regressions.

The public resolver must check session health before returning an IP literal
or a cached result, and pending DNS must wake immediately on terminal failure.
Upstream `LookupError::NoAnswer` conflates DNS timeout with failed transport;
add a distinct terminal-session error without caching it. Return address
candidates only. Network Relay must apply its existing policy to all numeric
answers, then pass only approved addresses to the library dial method. DNS
success must not bypass application destination filtering. See
[`RESEARCH-RELAY-CONTRACT.md`](RESEARCH-RELAY-CONTRACT.md).

### Packet size, diagnostics, shutdown

`Tunnel::max_packet` reports live QUIC datagram payload after stream/context
overhead; H2 has no outer datagram limit. `send_packet` returns `Yes`,
`TooLarge(current_max)`, or `QueueFull`, and counts sent/received/dropped
packets (`masque.rs:273–325`). The SOCKS pump adjusts stack MTU immediately
and periodically, including after oversize errors; it does not decrement
TTL for packets originated by this local stack (`socks.rs:218–281`). Keep this
logic in the generic session pump, outside the SOCKS frontend.

Upstream permits stack MTU 576 through 1280 for both families
(`netstack.rs:141–153`). QUIC can fall back toward 1200-byte UDP path MTU,
leaving fewer than 1280 bytes for IP. This needs an explicit IPv6 readiness
policy: a link carrying IPv6 has a 1280-byte minimum and cannot claim that
minimum merely by generating smaller TCP segments. Reject unavailable IPv6
operations or add and test an appropriate transport/fragmentation mechanism;
do not silently report a valid 1280-byte IPv6 path. EDNS sizing should track
actual UDP payload capacity when MTU shrinks. Existing MTU tests mainly cover
IPv4 TCP segments and do not prove these IPv6 cases.

`ip.rs` contains checksum, hop decrement, and bounded packet-too-big helpers
for a forwarding/TUN router. Those router behaviors are not needed for local
userspace business sockets. `probe.rs` manually creates ICMP/DNS packets and
validates both endpoints, checksums and matching identifiers; `exchange`
consumes `Tunnel::recv_packet` directly (`probe.rs:184–212`). A probe must not
compete with the production pump for the same receive stream. Perform a
pre-pump check or use a demultiplexed diagnostic interface; business readiness
is better verified with stack TCP/UDP/DNS operations.

`SetupTasks` aborts started connection tasks when setup fails or its future is
cancelled. Tunnel drop aborts owned tasks and closes Quinn. Graceful shutdown
closes Quinn and waits up to two seconds for idle, or drops the H2 request
sender and waits up to two seconds for stream failure
(`masque.rs:148–163,183–191,363–381`). `shutdown::relay` scopes all forwarding
futures in a select, ensuring unfinished directions are dropped before return
(`shutdown.rs:40–56`). These are useful cancellation patterns, but signal
registration belongs to the application, not to the reusable crate.

H3 closed detection combines Quinn closure with a ten-second unanswered-frame
detector driven only while `Tunnel::closed` is polled. Its 500 ms sampling
excludes expected-loss path-MTU probes. With keepalives, silent loss detection
is approximately keepalive interval plus ten seconds, rather than immediate
knowledge of network failure (`masque.rs:385–403,846–910`). H2 PING has the
configured idle timeout; zero keepalive/idle values can disable useful failure
bounds. The H2 shared watch records the first cause before cleanup can mask
it (`masque.rs:680–715,901–929`). Preserve first-cause behavior and structured
error categories in the library.

## Minimal library boundary and proposed API

Extract `masque`, `varint`, `netstack`, and `dns` plus the needed configuration
parsing into the crate. Move the transport pump out of `socks::pump`. Preserve
tests beside the extracted logic. Keep `socks`, `tun`, CLI flags, global signal
handling, host/kernel business sockets, routing/DNS changes, and global
allocator tuning outside the crate. Registration can be a separate optional
feature or utility; it must not be implicit runtime traffic.

This API sketch expresses ownership and guarantees, not a committed Rust ABI:

```rust
pub enum Transport { H2, H3 }
pub struct WarpCredentials { /* redacted private key and endpoint SPKI */ }
pub struct EgressOptions {
    pub endpoint: SocketAddr,       // outer WARP control connection only
    pub transport: Transport,      // explicit; no direct fallback
    pub addresses: TunnelAddresses,
    pub dns_servers: Vec<IpAddr>,   // queried only through the stack
    pub limits: ResourceLimits,
    pub timeouts: Timeouts,
    pub credentials: WarpCredentials,
}
pub struct Egress { /* cloneable controller handle for one generation */ }
impl Egress {
    pub async fn connect(opts: EgressOptions) -> Result<Self, EgressError>;
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, EgressError>;
    pub async fn dial_tcp(&self, peer: SocketAddr) -> Result<TcpStream, EgressError>;
    pub fn bind_udp(&self) -> Result<UdpSocket, EgressError>;
    pub fn status(&self) -> SessionStatus;
    pub fn stats(&self) -> EgressStats;
    pub async fn closed(&self) -> Arc<EgressFailure>;
    pub async fn shutdown(&self) -> Result<(), EgressError>;
}
// TcpStream: AsyncRead + AsyncWrite + Unpin + Send; local_addr/peer_addr;
// abort_handle(): independently cloneable handle that resets this TCP socket.
// UdpSocket: whole-datagram send_to/recv_from, local port, payload ceiling;
// optional connected-peer facade implemented without a host socket.
```

Use structured timeout, refused, missing-family, message-too-large,
resource-limit, authentication, protocol, tunnel-lost, and shutdown errors.
Expose safe counters for queue drops, oversize drops, DNS cache/query counts,
socket use, MTU, bytes, and generation; do not expose response-header strings
or secret-bearing Debug as the primary health surface. Upstream
`describe(headers)` logs arbitrary headers; use an allowlist or redaction in
the extracted client. Exact error/timeout representation can remain small
and independent of Network Relay.

TCP hostnames can be supported as an opt-in helper that resolves and races
addresses through the same library. The required policy-aware app should use
`resolve` and numeric `dial_tcp` separately. Generic Happy Eyeballs can reuse
the ordering/cancellation mechanics at `socks.rs:620–752` without importing
SOCKS refusal codes or application policy. The app's own dial strategy must
return the chosen numeric peer and retain an independent abort handle.

## Required failure and ownership changes

1. **One terminal state per generation.** Add a first-error, monotonic failed
   state under the stack mutex. On tunnel loss, packet-pump failure, stack
   runner failure/panic, explicit shutdown, or final controller drop, publish
   failure before dropping forwarding tasks. Every connect, read, write,
   flush, shutdown, UDP operation, resolver cache/literal lookup and status
   check must observe it. Waking sockets without checking failure still lets
   empty UDP receives re-register forever.
2. **Wake all pending work.** Maintain reliable per-socket read/write and
   lifecycle wake registration; explicitly wake those waiters when publishing
   failure. A single Tokio Notify wakes the runner, not every blocked socket.
   Poll wrappers need register-then-recheck semantics to avoid a failure race.
   Do not rely only on TCP's 120-second retransmission timeout, connect's
   ten-second timeout, or a new socket's admission check.
3. **Keep handle destruction safe.** Upstream stream/UDP Drop accesses its
   smoltcp `SocketHandle`. Do not remove all socket handles on failure while
   application wrappers survive: that can panic on a later operation or Drop.
   Mark them dead, abort TCP, clear packet queues, and retain safe tombstones
   or valid sockets until wrappers release them. Release resources once they
   are no longer reachable.
4. **Separate owner from operation state.** Controller clones own a task guard;
   pump tasks and stream wrappers must not hold that controller in a strong
   Arc cycle. Streams can retain shared dead-state/socket storage without
   keeping an abandoned controller or tunnel alive. Final controller drop
   synchronously publishes failure and cancels owned tasks; explicit async
   shutdown additionally joins/observes them within a bound. Cancellation of
   startup must drop already spawned tasks and the partial tunnel.
5. **Reconnect by replacing generations.** Current SOCKS deliberately keeps
   one stack across tunnel reconnects, hoping inner connections survive
   (`socks.rs:126–132,186–211`; `masque.rs:54–57`). The proposed fail-closed
   contract requires old operations to fail promptly once death is detected.
   New sessions get a fresh stack, resolver and queues; old handles keep their
   terminal error even if addresses are reused. Admission stays disabled
   during reconnect. No queued old packet or DNS waiter crosses generations.
   An embedding app may supervise a new connection with bounded backoff, but
   a successful reconnect cannot revive an old stream or change transport
   implicitly.
6. **Bound and fairly service packet work.** Check both closed channels and
   failed tasks instead of ignoring closed outgoing `try_send`. Cap input
   draining and stack polling batches so continuous inbound traffic cannot
   grow a private RX queue indefinitely or hold the single mutex while socket
   tasks wait. Bound bytes as well as packet counts; distinguish QueueFull
   from Closed and count each direction's intentional drops.
7. **Define UDP concurrency.** smoltcp exposes one receive/send waker per
   socket; concurrent receivers on one generic socket can overwrite wakers.
   Document one concurrent receiving task, serialize it, or implement a
   proper multiplexer. Cancelled pending `send_to`/`recv_from` must not consume
   a datagram secretly. Keep socket closure, destination filtering, and zero
   length datagrams explicit. Recheck MTU under the lock before queueing a
   send after waiting for capacity.

These fixes are required architectural work, not optional robustness polish.
A TCP write completed just before a detected failure can legitimately mean
local buffer acceptance; it must not imply peer delivery. Once terminal
failure is published, subsequent polls must fail rather than report success.
Prompt wakeup should be tested after *detected* loss separately from the
protocol's bound on *detecting* a silent loss.

## Test inventory read and reuse plan

The relevant application tests were read, including transport/TLS, stack,
resolver, registration/config files, packet probes/IP helpers, scoped shutdown,
SOCKS cancellation/fairness and Happy Eyeballs. Kernel/TUN routing/rollback tests
and all six retained Python transport suites plus both privileged shell suites
were also inspected to establish what they actually exercise. Vendored H3's
patch contract and test command were inspected; the upstream H3 crate's entire
general-purpose test implementation is not an independent egress audit.

| Existing coverage | Evidence at pinned baseline | What it does not prove |
| --- | --- | --- |
| H2 WARP wire, no ALPN, RFC strict ALPN, mTLS public key, wrong server pin; H3 packet framing/routes | `masque.rs:1683–1993`; Python `additional_tests.py` checks literal `cf-connect-ip` H3 token | A live Cloudflare server has accepted the configuration here |
| Capsule truncation/bounds, unknown skip, every varint width, malformed prefix atomicity; 20,000 seeded mutations | `masque.rs:1342–1646` | Business I/O wakes after packet pump/tunnel death |
| H2 windows 16/1024 bytes; first failure wins; failed setup task cancellation | `masque.rs:1652–1674,1999–2077` | H2 bulk transfer with many concurrent inner sockets remains bounded |
| TCP IPv4/IPv6 echo, 3 MiB transfer, 1 MiB with every 100th outgoing packet lost, 20 concurrent connections, MTU shrink, refusal/family errors, linger cleanup and socket/port budgets | `netstack.rs:779–1066` | GiB-scale sustained bidirectional transfer, long idle, channel failure, generation replacement, memory recovery |
| UDP both families, maximum IPv4 payload, oversize error | `netstack.rs:950–974` | IPv6 payload boundary, empty UDP over stack, concurrent waker/cancellation races, MTU-change/send race |
| DNS source/question/CNAME/TTL/SOA parsing, 20,000 mutations, UDP-to-TCP fallback, sharing, cancellation and survivor completion, no failure negative cache | `dns.rs:591–1139` | Cached/literal resolve fails on dead session; all pending DNS fails promptly on tunnel death |
| Registration request headers/body, SEC1 compatibility, exclusive 0600 config save, symlink refusal, API failure | `api.rs:392–800` | Actual enrollment or secret-redacted error reporting |
| Scoped forwarding cancellation and SOCKS DNS/fairness/port-pinning regressions | `shutdown.rs:60–102`; `socks.rs:888–1255` | Generic egress controller final drop cleans every task and socket |
| Six binary/loopback H2/H3 suites, currently runner announces 59 cases | `tests/transport/run.sh` and all six Python files | Running the reusable crate or production relay; script's announced count alone is not executed evidence |
| RFC caddy-masque TUN/SOCKS IPv4/IPv6, 2 MiB uploads, routing rollback, server restart and signals | `tests/local-check.sh`, `tests/ipv6-check.sh` | Live WARP; these require privileged namespaces, Caddy and kernel TUN, and are not the library's required no-TUN test path |

Historical docs record passing prior local runs, but those results are not
fresh validation of this project. No credentials, raw-network capability,
privileged namespace capability, or live WARP behavior is inferred from them.

## Additional regressions and soak gates

Tests must use independent fixture assertions rather than mirroring the
implementation. A local test tunnel should terminate in a real fixture stack
or service and observe only IP from the enrolled test addresses. Run every
transport-sensitive case separately with explicit H2 and explicit H3.

* Inject tunnel EOF, CONNECT reset, H2 driver error, QUIC close, silent blackhole,
  output-channel closure, input-channel closure, stack-task panic and explicit
  shutdown while established TCP read/write, UDP receive/full-send, SYN and
  shared DNS are blocked. Synchronize on actual waiter registration, then
  require terminal failures within a small bounded wakeup deadline (for
  example one second). Test detection deadlines separately for blackholes.
* Warm DNS cache and IP-literal lookup, fail the session, then require both to
  fail without producing wire packets. Reconnect a new generation at identical
  addresses and verify old handles still fail, while new TCP/UDP/DNS works.
* Cancel initialization at each network/setup stage, including stalled peer
  SETTINGS and route-advertisement flow control. Count fixture connections,
  sockets and tasks after cancellation; verify no detached pump survives.
* Transfer at least 128 MiB per required regression and a configurable larger
  GiB-scale amount in soak, streaming deterministic bytes with a digest in
  both directions. Include simultaneous download/upload, slow readers,
  receive-window closure/reopening, half-close with delayed final response,
  repeated short/large writes, loss/reorder/delay and partial I/O. Bound wall
  time and memory without preallocating the whole test payload.
* Keep TCP/UDP sessions idle past several keepalive intervals and TCP's
  configured timeout, then exchange bytes/datagrams. Distinguish clean idle
  from outstanding unacknowledged data. Exercise silent endpoint death during
  idle and fresh-session recovery; do not add arbitrary business inactivity
  expiry that breaks valid long-lived TCP streams.
* Exercise UDP lengths zero, one, exactly per-family maximum, and maximum plus
  one; prove each receive preserves one datagram and source. Test changing
  MTU between validation and buffer readiness, IPv4-mapped inputs, pinned-peer
  filtering in the app, and IPv6 readiness at below-minimum path capacity.
* Flood traffic with slow/full H2 outer windows while DNS, small TCP and UDP
  remain active. Require progress and bounded queues; report intentional UDP
  loss rather than assuming reliability. Repeat connect/cancel/drop churn
  beyond the socket budget, check clean overload and eventual slot reuse,
  and record peak/residual RSS plus allocated socket/queue bytes.
* Prove fail closed with a direct-destination trap: leave the host's direct
  destination path functional and instrument it while killing the tunnel.
  TCP/UDP/DNS must error and the trap must receive no application traffic.
  Audit dependencies/API surfaces for host business dials and resolver calls.
  Local host sockets are permitted only for ingress listeners, synthetic
  fixtures, explicit registration control plane, and the numeric outer WARP
  endpoint. This is testable and should not be inferred from class names.

Run format, locked build, crate/application suites and strict Clippy for the
final extracted surface. Preserve failed/skipped/unrun results distinctly.
Optional expensive soak should produce bounded-duration JSON/text evidence
with actual transferred byte counts, digests, workload, transport, session
generations, queue/socket maxima, failure timing, and memory observations.
Never commit or print credential material.

## Live verification boundary

A real check requires an enrolled configuration provided through a secure file
path and usable direct TCP/UDP access to the selected WARP endpoints. H3 needs
outer UDP; H2 needs outer TCP and the service-specific endpoint/pinning/mTLS
behavior. An HTTP proxy available to dependency downloads does not establish
that either raw transport works. Missing credentials cannot be substituted
with synthetic keys or an automatic registration attempt.

After those prerequisites are available, verify explicit H2 and H3 separately:
authenticated tunnel setup, stack TCP transfer, UDP exchange, DNS through the
tunnel, IPv4/IPv6 when enabled, graceful shutdown, silent loss and recovery,
and a bounded real workload. Record exactly which transport/families and
targets ran. Local verified TLS fixtures validate compatibility logic and
lifecycle; they do not establish live WARP interoperability or production
throughput.
