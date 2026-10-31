# usque, usque-rs, and mihomo source research

Research date: 2026-10-14 UTC. This is source inspection, not a successful live WARP test or a performance certification. Sources were fetched through the inherited HTTPS proxy with normal TLS verification. No account was registered, credential read, dependency installed, tunnel connected, or parent/sibling file changed by this research.

## Revisions and licensing

| Repository / selected ref | Exact revision | Language / role | License observed in selected source |
| --- | --- | --- | --- |
| Diniboy1123/usque, main and HEAD | `6aa03fc97d12848dce34eedbd187fb1077b5d1ea` | Go WARP client, native TUN and proxy frontends | MIT, [LICENSE.md lines 1–16][U-license] |
| Diniboy1123/usque-rs, main and HEAD | `1b808bb3f2e49cc5f73dcbe764adb07af6802f16` | Genuine Rust rewrite, Linux native TUN only | MIT, [Cargo.toml lines 1–13][R-cargo] and retained LICENSE.md |
| Diniboy1123/connect-ip-go, version pinned by Go usque | `66cba32d7d33e0fb3ba9d1cdaac664379271a54b` | Go CONNECT-IP framing/library fork | MIT, [LICENSE lines 1–7][D-license] |
| MetaCubeX/mihomo, Meta branch | `88dcbf7f1614a67c3b36b848ee3592dfa92ada36` | Go outbound adapter and tunnel transport | GNU GPL version 3, [LICENSE lines 1–18][M-license] |
| MetaCubeX/connect-ip-go, version pinned by mihomo | `67ccdb0cf77141ed5107ea1b413e90a9e8cc55a3` | Go H3 CONNECT-IP fork | Retained MIT LICENSE; treat mihomo files themselves as GPL |
| MetaCubeX/quic-go, version pinned by mihomo | `2548683b76f4d57a720b95a2a52f2fd1ecec5f10` | Go QUIC/H3 transport fork | Dependency inspected for behavior only; no implementation copied |

The GitHub repository API and HTTPS `git ls-remote` for mihomo currently identify main/HEAD as `008b91bfe8c0e2daca0ab69061efd9ea1ad71bd2`. That selected tree has 37 entries and is Python, without the Go MASQUE transport. The Go implementation is on **Meta**, verified independently through refs and its 1,249-entry tree. Consequently a repository-wide API language/license label is not a license determination for the reviewed Go files. The Meta tree's own LICENSE and go.mod are the evidence. Go usque's module and dependencies are at [go.mod lines 1–16][U-mod]; mihomo's pinning is at [go.mod lines 1–33][M-mod].

The selected raw files and retrieval metadata are under `.research/refs-usque-mihomo/{usque,usque-rs,connect-ip-go,mihomo}`. The first three SOURCE.json files record full revisions, tree metadata, and SHA-256 hashes; mihomo has independent tree/manifest metadata and a detailed NOTES.md. This directory is reference material. **Do not copy GPL mihomo code into the new implementation.** Use the independently MIT-licensed usque sources, existing authorized Rust modules, protocol facts, and original Rust glue. MIT copying still requires retaining the applicable copyright/license notice.

## Authentication and identity

Go usque registers with the Cloudflare client API, originally sending a generated WireGuard-like public key, then enrolls a P-256 public key with `key_type=secp256r1` and `tunnel_type=masque`. Enrollment is an authenticated PATCH with the account token. The assigned IPv4/IPv6 addresses, peer endpoint, and peer public key are saved from the enrollment response. The bearer token authenticates the **control-plane API**; tunnel authentication uses a certificate made from the enrolled private key, not a bearer header on every packet. Sources: [api/cloudflare.go lines 37–113][U-register], [api/cloudflare.go lines 136–186][U-enroll], [cmd/register.go lines 75–103][U-reg-config].

Go usque's private key is base64 SEC1 EC DER (`x509.MarshalECPrivateKey` / `ParseECPrivateKey`); usque-rs stores and parses base64 PKCS#8 DER. Both enroll a SubjectPublicKeyInfo public key. A configuration importer must deliberately accept/convert these formats; identical field names do not make the documents interchangeable. Sources: [internal/utils.go lines 70–92][U-key], [config/config.go lines 80–120][U-key-config], [usque-rs/src/register.rs lines 171–219][R-key], [usque-rs/src/tls.rs lines 20–30][R-tls-key].

Go usque makes a self-signed certificate valid for 24 hours. TLS uses SNI `consumer-masque.cloudflareclient.com` and does not perform ordinary certificate-name/CA-chain validation because the endpoint certificate is not for that SNI. Instead it compares the leaf ECDSA public key with the pinned key from registration; an insecure option removes the callback. Mihomo follows the same model, but loops through peer certificates and accumulates pin errors. Sources: [internal/utils.go lines 95–116][U-cert], [api/masque.go lines 35–86][U-pin], [mihomo transport/masque/masque.go lines 38–103][M-pin].

The new facade should require the pin and reject absent certificates and mismatches, with no insecure production option. This is stricter than two observed edge cases: Go usque returns nil if rawCerts is empty ([api/masque.go lines 59–62][U-pin]); Rust usque-rs warns and skips pinning if quiche supplies no certificate ([src/tunnel.rs lines 235–243][R-pin]). These source branches are not evidence that the underlying TLS libraries permit an unauthenticated connection, but they are unsuitable logic to copy into a fail-closed API.

## Cloudflare transport forms

| Item | HTTP/3 | HTTP/2 |
| --- | --- | --- |
| Outer transport | UDP QUIC, H3 ALPN | TCP TLS, h2 ALPN |
| Endpoint | Go/Rust usque use enrollment `endpoint_v4` or `endpoint_v6`; examples show IPv4 `162.159.198.1` | Go usque separately selects `endpoint_h2_v4`, default `162.159.198.2`; H2 IPv6 is empty by default and requires explicit configuration |
| Request authority / URI | `cloudflareaccess.com`, path `/` | Plain CONNECT to `cloudflareaccess.com:443` |
| Protocol selector | `:protocol=cf-connect-ip` | Header `cf-connect-proto: cf-connect-ip` |
| Other headers | Empty User-Agent; `capsule-protocol: ?1` | Empty User-Agent; `pq-enabled: false`; no Capsule-Protocol header set in the reviewed Cloudflare path |
| Business packet framing | QUIC DATAGRAM payload: QUIC varint quarter-stream ID, QUIC varint context ID 0, IP packet | Request/response DATA body: QUIC varint capsule type 0, QUIC varint length, **bare IP packet** |
| Control capsules | H3 stream carries address/route capsules and must be drained independently of datagrams | Reviewed Cloudflare H2 paths do not support route/address control capsule exchange |

H2 endpoint selection is explicit, not automatic H3 downgrade: [usque/config/endpoints.go lines 9–69][U-endpoints]. The shared SNI/URI constants are at [usque/internal/consts.go lines 4–15][U-consts]. Go usque chooses H2 or H3 using a boolean and the corresponding endpoint type, with no cross-transport fallback in `ConnectTunnel`: [api/masque.go lines 109–160][U-connect]. H3 enables QUIC and H3 datagrams, uses a 20-byte connection ID, and sends the deprecated H3 datagram setting `0x276:1` for compatibility. It deliberately ignores the server's Extended CONNECT setting but still requires server datagram support: [api/masque.go lines 181–208][U-h3], [connect-ip-go/client.go lines 25–66][D-h3]. Mihomo confirms the same settings and selector, and additionally advertises the full IPv4/IPv6 ranges on the H3 request stream: [transport/masque/masque.go lines 109–167][M-h3].

The crucial H2 variant is independently visible in MIT source: [connect-ip-go/client_h2.go lines 22–64][D-h2-dial] and [lines 87–143][D-h2-frame]. The common Conn layer expects context ID 0, so this fork removes it on H2 send and restores it internally on receive. Mihomo's dedicated H2 IpConn handles raw IP directly: [transport/masque/client_h2.go lines 31–67][M-h2-dial] and [lines 279–317][M-h2-frame]. Mihomo uses an HTTP2-only guard in its own HTTP fork to avoid HTTP/1.1 fallback after a wrong ALPN; copying that configuration into stock Go net/http would not mean the same thing: [adapter/outbound/masque.go lines 180–207][M-h2-alpn].

Transport selection must remain fixed throughout each H2/H3 acceptance run, and logs/results must identify actual ALPN and transport. A successful normal HTTPS GET through the cloud HTTP proxy cannot establish either pinned WARP transport. The reviewed Go usque H2 transport honors HTTP_PROXY/HTTPS_PROXY and rewrites direct dialing, but its proxy branch still lets the HTTP proxy handle origin CONNECT authority; do not assume the selected WARP IP is preserved by a generic intercepting HTTP proxy. Source: [api/masque.go lines 223–298][U-h2-proxy]. This research verified GitHub HTTPS access, not transparent raw TCP/UDP access to the WARP endpoints.

## MTU, queues, capsules, and liveness

The inner IP MTU and the outer QUIC datagram/packet limit are different values. Go usque defaults inner MTU to 1280, warns on other settings, and now defaults initial QUIC packet size to automatic path MTU discovery; setting a nonzero initial size disables discovery. Mihomo currently defaults inner MTU 1280, initial packet 1242, and a 30-second QUIC keepalive. Sources: [usque/cmd/socks.go lines 187–193][U-mtu], [lines 309–315][U-mtu-default], [internal/utils.go lines 119–140][U-quic-config], [mihomo adapter/outbound/masque.go lines 210–220][M-mtu]. Neither 1242 nor 1280 is a universal outer packet ceiling suitable for the Rust egress module.

Go usque reserves one byte before each inner IP packet for context ID zero and uses a pool sized MTU+1. It forwards generated Packet Too Big ICMP back into the stack and treats normal packet errors as drops. The connect-ip library validates minimum IPv4/IPv6 headers, decrements TTL/hop-limit, recomputes the IPv4 checksum, and returns ICMP on QUIC datagram-too-large errors (with advertised inner MTU 1280). Sources: [api/tunnel.go lines 158–160,233,318–349][U-pump], [connect-ip-go/conn.go lines 400–480][D-send]. These are packet semantics; application TCP stream chunks may be arbitrarily larger because the userspace TCP stack segments them.

H3 and H2 have different loss/backpressure characteristics. In mihomo's pinned QUIC dependency the send datagram queue has 32 entries and blocks when full; the connection receive queue has 128 entries and drops overflow. The H3 stream has a separate receive queue of 32 datagrams. Sources: [quic-go/datagram_queue.go lines 12–15,44–68,92–109][Q-queue], [http3/state_tracking_stream.go lines 13,135–155][Q-stream-queue]. In H2, both clients serialize capsule writes into io.Pipe, so reliable TCP/H2 flow control can block the writer: [MIT client_h2.go lines 123–143][D-h2-frame], [mihomo client_h2.go lines 305–317][M-h2-frame]. Reliability of the outer stream does not remove inner packet queue overflow or head-of-line blocking between flows.

Capsule parsers need explicit size bounds and incremental handling across arbitrary DATA chunk boundaries. MIT connect-ip-go accumulates an incomplete H2 capsule until its declared length arrives, without an evident limit ([client_h2.go lines 87–119,161–178][D-h2-parse]); mihomo allocates `make([]byte,payloadLen)` directly ([client_h2.go lines 279–301][M-h2-frame]). Go usque's H3 control reader handles address assign and routes but treats unknown capsule types as errors ([connect-ip-go/conn.go lines 208–253][D-controls]). Mihomo's separate pinned connect-ip-go H3 reader discards unknown capsules rather than aborting ([conn.go lines 191–238][MD-controls]). The Rust module should retain its bounded decoder and drain/skip unknown capsules without retaining their whole payload.

Go usque has a reconnect supervisor with two forwarding goroutines and a delay. Its demand-driven path reads and discards the triggering packet, unlike usque-rs which retains it. It waits up to two seconds for old pumps. The read mutex is instantiated within each connection iteration, so the comment claiming it serializes a stale reader with a later iteration is not sufficient by itself; the new module should cancel and join its own channel pumps deterministically. Sources: [api/tunnel.go lines 235–254,305–320,378–409][U-lifecycle]. Mihomo starts on demand behind a semaphore, publishes running only after successful handshake, cancels/cleans resources when either packet loop exits, and starts again through later Dial/Listen calls; no autonomous reconnect loop appears in the reviewed adapter. Sources: [adapter/outbound/masque.go lines 279–375][M-lifecycle], [lines 377–438][M-pumps].

The genuine Rust usque-rs is useful as independent Rust protocol evidence, but it is not a reusable userspace dialer. Its README says Linux-only native TUN and no proxy support ([README.md lines 3–7][R-readme]), and Cargo defines a binary using quiche 0.22 ([Cargo.toml lines 8–13][R-cargo]). It reconnects on traffic, retains the first packet, enables quiche datagram queues of 1000 entries, fixes maximum UDP payload at 1350, and sets local maximum idle timeout to zero ([src/tunnel.rs lines 79–125,139–165][R-config]). Its send queue `Done` result drops a packet; other failures emit a fixed 1280 ICMP ([lines 408–449][R-drop]). It constructs flow/context framing explicitly ([lines 373–394,550–570][R-frame]). However, the main H3 loop discards events without calling recv_body to drain capsule DATA, and its named keepalive timer calls quiche on_timeout without an explicit ping in the inspected loop ([lines 403–467,481–491][R-loop]). Do not infer full capsule handling, confirmed PMTU behavior, or live liveness guarantees from README claims alone. Some `?`/`bail!` exits also bypass the later stats_handle.abort ([lines 410–413,527–547][R-task-exit]); use owned task guards in the new library.

## DNS and fail-closed behavior

Go usque's default SOCKS path creates the userspace netstack with tunnel addresses and routes target TCP/UDP through it. Its resolver uses the same stack by default, but `localDNS` or `systemDNS` deliberately select host/system DNS. The resolver's Dial callback always returns UDP even if net.Resolver requests TCP, so this code is not a model for truncated-response TCP fallback. Sources: [cmd/socks.go lines 244–282][U-proxy-stack], [internal/dns.go lines 13–49,69–88,121–159][U-dns]. Rust usque-rs forwards IP through native TUN, sets no host route policy itself, and provides no userspace resolver: README lines3–7 explain that scope. Neither client proves a host-wide kill switch from those sources.

Mihomo only creates its dedicated resolver when `remote-dns-resolve` is enabled **and** nonempty DNS servers are supplied; those server entries use the MASQUE outbound. Otherwise target-name resolution defaults to mihomo's global DefaultResolver, whose routing depends on global configuration. TCP/UDP dial failures return errors without a direct-socket fallback in this adapter, but that is narrower than proving all business DNS and frontend paths are fail-closed. Sources: [adapter/outbound/masque.go lines 252–264][M-dns], [lines 464–527][M-dials]. The separate H3 L4 proxy mode supports TCP CONNECT and explicitly rejects UDP; it cannot satisfy the new project's all-TCP/UDP/DNS requirement ([lines 493–495][M-dials]; [Go usque/api/l4proxy.go lines 28–42][U-l4]).

## Recommendation for the reusable Rust egress module

Reuse the already available **cf-masque NetStack + Tunnel + tunnel DNS resolver**, with original facade/lifecycle glue in this independent project. Source inspection of `/workspace/cf-masque` at HEAD `a65c600494cd50fed2c621b8538be7abda5e7fa4` found that sources expose the needed operations; the workspace has unrelated existing manifest/license/document changes, so preserve it in place and record provenance when bringing authorized source into the new project.

1. Expose a small MASQUE-only API: connect TCP by address or hostname, create UDP associations, resolve names, read readiness/status/statistics, and shut down. The frontend sees the facade, not a mode enum with a direct socket alternative. Select Net::Stack only; avoid exposing Net::Kernel or any generic host resolver. Existing sources: `src/netstack.rs` lines85–170,210–289; `src/net.rs` lines23–27,92–138; `src/dns.rs` lines1–4,77–118.
2. Own exactly one packet pump pair and tunnel session per generation. Publish ready only after pin, negotiated transport, CONNECT success, and usable configured inner addresses. On Tunnel::closed, synchronously revoke readiness, cancel/join pumps, reject new dials, and close or reset affected streams. Reconnect only to configured Cloudflare endpoints with bounded delay; never invoke a VPS internet dialer. Existing Tunnel shutdown/drop/closed APIs: `src/masque.rs` lines165–209,360–402.
3. Feed Tunnel::max_packet into NetStack::set_mtu, retaining the already implemented periodic fitting logic and TooLarge/QueueFull outcomes. Keep bounded channels and socket/session limits; count drops and publish pressure metrics. Existing sources: `src/masque.rs` lines271–325; `src/netstack.rs` lines33–57,137–154,167–206; `src/socks.rs` lines248–281. Choose UDP oversize rejection semantics explicitly; do not silently split one business datagram into multiple UDP messages.
4. Use the same tunnel stack for all DNS, including TCP fallback for a truncated response. The current cf-masque resolver already supports this and has cache/duplicate-query bounds; route API-name DNS differently only as a documented control-plane requirement. Keep endpoint addresses numeric where possible so business DNS cannot become a bootstrap escape route.
5. Keep protocol and generic RFC test mode separate. Production Cloudflare H2 must use plain CONNECT, `cf-connect-proto`, and bare-IP type 0 capsules; H3 must use Cloudflare's selector, pin, datagrams, and control stream handling. The current `src/masque.rs` already contains these distinctions (lines96–112,630–811,1020–1129).

## Evidence required before accepting implementation

Run independent forced-H2 and forced-H3 suites; record the actual endpoint, transport/ALPN, dates, exit identity, byte counts, checksums, throughput, queue drops, reconnection counts, and failures without credentials. A generic local CONNECT-IP server proves parser/stack behavior, not Cloudflare WARP interoperability. Live evidence must use an enrolled configuration and successful business TCP, UDP, and DNS traffic whose egress is Cloudflare.

Include large upload/download with content hashes; concurrent long and short TCP flows; DNS UDP and deliberately truncated TCP fallback; UDP MTU-boundary/oversize cases; pin mismatch, wrong ALPN, rejected CONNECT, endpoint outage, idle-to-active reconnect, and cancellation while queues are full. For each forced transport run an actual continuous soak of at least one hour with bounded memory, stable descriptor/task counts, and periodic business probes. During a forced tunnel failure, observe that target TCP/UDP/DNS never appears on the VPS/direct network and new business requests fail. A successful build, zero-test run, upstream speed claim, or scheduled future soak does not meet these acceptance conditions.

## Exact upstream source links

[U-license]: https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/LICENSE.md#L1-L16
[U-mod]: https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/go.mod#L1-L16
[U-register]: https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/cloudflare.go#L37-L113
[U-enroll]: https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/cloudflare.go#L136-L186
[U-reg-config]: https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/cmd/register.go#L75-L103
[U-key]: https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/internal/utils.go#L70-L92
[U-key-config]: https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/config/config.go#L80-L120
[U-cert]: https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/internal/utils.go#L95-L116
[U-pin]: https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/masque.go#L35-L86
[U-endpoints]: https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/config/endpoints.go#L9-L69
[U-consts]: https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/internal/consts.go#L4-L15
[U-connect]: https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/masque.go#L109-L160
[U-h3]: https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/masque.go#L181-L208
[U-h2-proxy]: https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/masque.go#L223-L298
[U-mtu]: https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/cmd/socks.go#L187-L193
[U-mtu-default]: https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/cmd/socks.go#L309-L315
[U-quic-config]: https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/internal/utils.go#L119-L140
[U-pump]: https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/tunnel.go#L158-L349
[U-lifecycle]: https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/tunnel.go#L235-L409
[U-proxy-stack]: https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/cmd/socks.go#L244-L282
[U-dns]: https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/internal/dns.go#L13-L159
[U-l4]: https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/l4proxy.go#L28-L42
[R-cargo]: https://github.com/Diniboy1123/usque-rs/blob/1b808bb3f2e49cc5f73dcbe764adb07af6802f16/Cargo.toml#L1-L13
[R-readme]: https://github.com/Diniboy1123/usque-rs/blob/1b808bb3f2e49cc5f73dcbe764adb07af6802f16/README.md#L3-L7
[R-key]: https://github.com/Diniboy1123/usque-rs/blob/1b808bb3f2e49cc5f73dcbe764adb07af6802f16/src/register.rs#L171-L219
[R-tls-key]: https://github.com/Diniboy1123/usque-rs/blob/1b808bb3f2e49cc5f73dcbe764adb07af6802f16/src/tls.rs#L20-L30
[R-pin]: https://github.com/Diniboy1123/usque-rs/blob/1b808bb3f2e49cc5f73dcbe764adb07af6802f16/src/tunnel.rs#L235-L243
[R-config]: https://github.com/Diniboy1123/usque-rs/blob/1b808bb3f2e49cc5f73dcbe764adb07af6802f16/src/tunnel.rs#L79-L165
[R-drop]: https://github.com/Diniboy1123/usque-rs/blob/1b808bb3f2e49cc5f73dcbe764adb07af6802f16/src/tunnel.rs#L408-L449
[R-frame]: https://github.com/Diniboy1123/usque-rs/blob/1b808bb3f2e49cc5f73dcbe764adb07af6802f16/src/tunnel.rs#L373-L570
[R-loop]: https://github.com/Diniboy1123/usque-rs/blob/1b808bb3f2e49cc5f73dcbe764adb07af6802f16/src/tunnel.rs#L403-L491
[R-task-exit]: https://github.com/Diniboy1123/usque-rs/blob/1b808bb3f2e49cc5f73dcbe764adb07af6802f16/src/tunnel.rs#L410-L547
[D-license]: https://github.com/Diniboy1123/connect-ip-go/blob/66cba32d7d33e0fb3ba9d1cdaac664379271a54b/LICENSE#L1-L7
[D-h3]: https://github.com/Diniboy1123/connect-ip-go/blob/66cba32d7d33e0fb3ba9d1cdaac664379271a54b/client.go#L25-L66
[D-h2-dial]: https://github.com/Diniboy1123/connect-ip-go/blob/66cba32d7d33e0fb3ba9d1cdaac664379271a54b/client_h2.go#L22-L64
[D-h2-frame]: https://github.com/Diniboy1123/connect-ip-go/blob/66cba32d7d33e0fb3ba9d1cdaac664379271a54b/client_h2.go#L87-L143
[D-h2-parse]: https://github.com/Diniboy1123/connect-ip-go/blob/66cba32d7d33e0fb3ba9d1cdaac664379271a54b/client_h2.go#L87-L178
[D-send]: https://github.com/Diniboy1123/connect-ip-go/blob/66cba32d7d33e0fb3ba9d1cdaac664379271a54b/conn.go#L400-L480
[D-controls]: https://github.com/Diniboy1123/connect-ip-go/blob/66cba32d7d33e0fb3ba9d1cdaac664379271a54b/conn.go#L208-L253
[M-license]: https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/LICENSE#L1-L18
[M-mod]: https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/go.mod#L1-L33
[M-pin]: https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/transport/masque/masque.go#L38-L103
[M-h3]: https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/transport/masque/masque.go#L109-L167
[M-h2-dial]: https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/transport/masque/client_h2.go#L31-L67
[M-h2-frame]: https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/transport/masque/client_h2.go#L279-L317
[M-h2-alpn]: https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/adapter/outbound/masque.go#L180-L207
[M-mtu]: https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/adapter/outbound/masque.go#L210-L220
[M-lifecycle]: https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/adapter/outbound/masque.go#L279-L375
[M-pumps]: https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/adapter/outbound/masque.go#L377-L438
[M-dns]: https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/adapter/outbound/masque.go#L252-L264
[M-dials]: https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/adapter/outbound/masque.go#L464-L527
[Q-queue]: https://github.com/MetaCubeX/quic-go/blob/2548683b76f4d57a720b95a2a52f2fd1ecec5f10/datagram_queue.go#L12-L109
[Q-stream-queue]: https://github.com/MetaCubeX/quic-go/blob/2548683b76f4d57a720b95a2a52f2fd1ecec5f10/http3/state_tracking_stream.go#L13-L155
[MD-controls]: https://github.com/MetaCubeX/connect-ip-go/blob/67ccdb0cf77141ed5107ea1b413e90a9e8cc55a3/conn.go#L191-L238
