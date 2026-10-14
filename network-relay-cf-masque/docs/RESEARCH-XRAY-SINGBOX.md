# Xray-core and sing-box: current MASQUE and WARP source research

Research date: 2026-10-14. This is source and documentation research, not an implementation or a live interoperability test.

## Findings that affect this project

Current Xray-core implements generic CONNECT-IP and explicit Cloudflare WARP compatibility over both HTTP/3 and HTTP/2. Current sing-box development upstream implements generic RFC CONNECT-IP client/server endpoints, but does **not** implement Cloudflare WARP's protocol deviations. WARP support cannot be inferred from a `masque-client`, `cloudflared`, or WireGuard name.

The reusable Rust egress crate needs a Cloudflare-specific dialect on top of the CONNECT-IP machinery. In particular, generic RFC H2 extended CONNECT with a context-ID-prefixed DATAGRAM capsule is not the same wire format as Cloudflare's WARP H2 transport. Explicit H2/H3 selection, authenticated peer verification, DNS transport selection, and error propagation are separate requirements; a functioning tunnel alone does not establish them.

| Question | Xray-core current source | sing-box current development source |
| --- | --- | --- |
| Generic CONNECT-IP | Implemented | Implemented |
| Explicit Cloudflare WARP mode | Implemented | Absent; requested in upstream issue #4603 |
| H2 and H3 | Both, including WARP-specific H2 | Both for generic RFC CONNECT-IP |
| Automatic version downgrade | No H3-to-H2 dialer fallback found | Enabled by default; disable explicitly |
| WARP enrollment/registration | Keys and endpoint configured externally | No WARP enrollment or identity support |
| Userspace TCP/UDP stack | Netstack-backed outbound | Endpoint device backed by sing-tun Go stack |
| All server DNS automatically constrained to tunnel | Target-domain DNS tunnels by default; outer edge resolution remains separate | No; DNSRouter and DNS transport detours are separate |
| License | MPL-2.0 root; embedded CONNECT-IP license separately retained | GPL-3.0-or-later plus naming restriction |

## Repositories, pins, and evidence method

The inspected sources were fetched from their current default branches. These are commit snapshots, not assertions about every stable release:

| Repository | Branch | Exact commit | Commit date |
| --- | --- | --- | --- |
| [XTLS/Xray-core](https://github.com/XTLS/Xray-core) | Default branch HEAD | [`0888beb38a9ba45440557175e71ce21cf8ba3b13`](https://github.com/XTLS/Xray-core/commit/0888beb38a9ba45440557175e71ce21cf8ba3b13) | 2026-10-14 |
| [SagerNet/sing-box](https://github.com/SagerNet/sing-box) | `testing` | [`dfb80349bf5779ec0a3f834c9ec2794345bff8f0`](https://github.com/SagerNet/sing-box/commit/dfb80349bf5779ec0a3f834c9ec2794345bff8f0) | 2026-10-13 |

Selected unmodified upstream files, their license files, source metadata, public issue/commit responses, and RFC text are retained exclusively under `.research/refs-xray-singbox/`. The retained files are research references, not production dependencies. `sing-box-manifest.json` records exact upstream links and SHA-256 hashes for 88 selected files; `xray-core/PIN.json` pins and hashes 79 selected files. `sing-box-source-search.txt` records the full-checkout WARP search performed before reducing the snapshot to selected references.

No builds, tests, registration requests, credential handling, or live WARP connection attempts were performed in this research subtask. Upstream tests described below were read, not executed. No GPL source was copied into production code.

## Xray-core

### Credentials, authority, and endpoint separation

The outbound config requires address and nonzero port; these are the actual destination. streamSettings.masqueSettings.warp supplies privateKey, publicKey and address. privateKey accepts PEM or base64 DER, parses PKCS#8 or SEC1, requires ECDSA P-256, and normalizes to PKCS#8. publicKey accepts PEM/base64 DER and must parse as PKIX/SPKI. The tunnel address list accepts at most one IPv4 and one IPv6 address/prefix, with a mandatory nonempty list.

Cloudflare authority defaults to cloudflareaccess.com and path "/". These are HTTP authority/path values, independent of actual outbound address/port and TLS serverName. SNI is supplied through the normal TLS config; the WARP test fixture uses consumer-masque.cloudflareclient.com. The transport does not hard-code that SNI, a physical endpoint IP, or a default physical WARP port. A nonempty host config overrides authority; otherwise generic MASQUE derives it from TLS ServerName and port.

The configured P-256 private key signs a self-signed client X.509 certificate generated at dial time with a random 128-bit serial, NotBefore now minus one hour, NotAfter now plus 24 hours. GetClientCertificate returns this certificate for mTLS. This is a configured, already registered device key; no Cloudflare device registration, account license exchange, API bearer-token flow, endpoint discovery API, key rollover, or renewal worker was found in these MASQUE paths.

Default WARP peer verification replaces CA/hostname verification with exact byte comparison between leaf.RawSubjectPublicKeyInfo and configured publicKey. It fails on missing cert, invalid cert, or mismatching SPKI. Nuance: if Xray's normal TLS config already set InsecureSkipVerify for pinnedPeerCertSha256 or verifyPeerCertByName, useWarp retains that existing certificate verifier and does not add the WARP SPKI comparison. Therefore these options select alternate validation; they do not stack with the WARP publicKey check. The config still requires a syntactically valid publicKey.

Generic MASQUE supports user/pass converted to Authorization: Basic, or arbitrary headers (including caller-specified Authorization). user/pass is rejected together with warp. WARP itself relies on mTLS; no required bearer or Basic auth header is automatically generated.

Evidence:
- [Required destination config, infra/conf/masque.go:14-38](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/infra/conf/masque.go#L14-L38)
- [Transport/WARP config and defaults, infra/conf/transport_method.go:798-904](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/infra/conf/transport_method.go#L798-L904)
- [Key/address parser, infra/conf/transport_method.go:907-975](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/infra/conf/transport_method.go#L907-L975)
- [Client cert, authority and pinning, transport/internet/masque/warp.go:15-78](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/transport/internet/masque/warp.go#L15-L78)
- [TLS alternate verification setup, transport/internet/tls/config.go:382-405](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/transport/internet/tls/config.go#L382-L405)
- [Authority construction, transport/internet/masque/dialer.go:309-320](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/transport/internet/masque/dialer.go#L309-L320)
- [Test fixture SNI, transport/internet/masque/warp_test.go:93-106](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/transport/internet/masque/warp_test.go#L93-L106)

### H3 and H2 are separate wire protocols

Client choice is explicit: usesHTTP2 returns true only if the protobuf TLS ALPN list includes h2 and excludes h3. With no explicit list, or h3 present, the MASQUE dialer takes H3 and sets its TLS ALPN to h3. No automatic UDP-blocked H3-to-H2 fallback exists in this dialer. Server config can listen on both UDP/H3 and TCP/H2 when both ALPNs are enabled.

H3:
- Underlying destination changes to UDP. QUIC enables DATAGRAM, starts with a 1350-byte packet, disables incoming bidirectional streams, uses 30-second idle timeout by default, 10-second default keepalive, and BBR by default. WARP forces 20-byte connection IDs.
- HTTP/3 enables datagrams and advertises draft-00 datagram setting 0x276 = 1 in addition to normal datagram support. The Cloudflare CONNECT request has :protocol = cf-connect-ip; generic CONNECT has connect-ip and Capsule-Protocol: ?1.
- Generic peers must advertise Extended CONNECT; the Cloudflare path bypasses that requirement. Cloudflare accepts either normal datagram support or draft-00 setting 0x276. A response must be 2xx.
- H3 IP data uses QUIC DATAGRAM carrying HTTP request quarter-stream ID and CONNECT-IP context ID zero followed by IP packet. For draft mode, Xray receives QUIC DATAGRAM directly, filters by quarter-stream ID, then exposes the context-prefixed payload; current RFC mode uses the library's HTTP3 stream datagrams. In H3, DATAGRAM capsules received on the reliable request stream are dropped.
- Cloudflare local tunnel addresses come from config; no ADDRESS_REQUEST is sent. Generic MASQUE requests IPv4 /32 and IPv6 /128 and waits for at least one assignment.

H2:
- Underlying destination changes to TCP; wraps normal TLS or uTLS according to fingerprint. WARP accepts negotiated h2 or empty ALPN, whereas generic MASQUE requires h2.
- A custom single-stream HTTP/2 client uses stream ID 1, HPACK, SETTINGS, DATA framing, bounded receive windows, flow control, PING, RST_STREAM and GOAWAY handling. It carries an entire IP tunnel over that one stream; many TCP/UDP flows are multiplexed by the inner userspace network stack.
- Generic MASQUE uses Extended CONNECT (:scheme, :path, :protocol = connect-ip) and Capsule-Protocol: ?1.
- Cloudflare uses classic CONNECT: only :method and :authority among these pseudoheaders, with authority cloudflareaccess.com:443 by default. It removes Capsule-Protocol and adds Cf-Connect-Proto: cf-connect-ip and Pq-Enabled: false. Because it has no :protocol pseudoheader, the custom H2 client's Extended CONNECT requirement does not apply.
- Both use DATAGRAM capsules (capsule type varint 0, length varint, data), transported in HTTP/2 DATA frames. Generic data is context ID zero + IP. WARP sends bare IP bytes without context ID; receive handling tolerates bare IP or an explicit context ID zero. Thus H2 cannot simply reuse H3 data framing unchanged.

The CONNECT-IP parser recognizes capsule types 0 DATAGRAM, 1 ADDRESS_ASSIGN, 2 ADDRESS_REQUEST, 3 ROUTE_ADVERTISEMENT. It bounds capsule/address/route counts; ignores unknown capsule types. Outgoing IP packets have IPv4 TTL or IPv6 Hop Limit decremented; IPv4 checksum is recomputed. Incoming packets are checked against assigned destination addresses and advertised routes; the connection reports packet-too-big ICMP to the inner netstack. Tunnel MTU is fixed at 1280, and establishment fails if H3 cannot carry that minimum; there is no MASQUE-layer fragmentation scheme in these inspected paths.

Evidence:
- [Client choice/H3 setup, transport/internet/masque/dialer.go:35-152](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/transport/internet/masque/dialer.go#L35-L152)
- [H2 dial and ALPN, transport/internet/masque/dialer.go:154-205](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/transport/internet/masque/dialer.go#L154-L205)
- [Address setup/MTU, transport/internet/masque/dialer.go:211-284](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/transport/internet/masque/dialer.go#L211-L284)
- [H3 Cloudflare negotiation/draft support, transport/internet/masque/connectip/client.go:20-114](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/transport/internet/masque/connectip/client.go#L20-L114)
- [H2 Cloudflare headers/bare mode, transport/internet/masque/connectip/http2.go:35-85](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/transport/internet/masque/connectip/http2.go#L35-L85)
- [H2 SETTINGS and single-stream gate, transport/internet/masque/http2.go:24-198](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/transport/internet/masque/http2.go#L24-L198)
- [Classic vs extended CONNECT serialization, transport/internet/masque/http2.go:201-254](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/transport/internet/masque/http2.go#L201-L254)
- [Capsule IDs, transport/internet/masque/connectip/capsule.go:21-30](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/transport/internet/masque/connectip/capsule.go#L21-L30)
- [H3 capsule dropping and receive framing, transport/internet/masque/connectip/conn.go:415-530](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/transport/internet/masque/connectip/conn.go#L415-L530)
- [Packet send/framing/MTU, transport/internet/masque/connectip/conn.go:592-703](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/transport/internet/masque/connectip/conn.go#L592-L703)
- [Server dual listen selection, transport/internet/masque/hub.go:47-88](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/transport/internet/masque/hub.go#L47-L88)

### Outbound abstraction and the WireGuard distinction

Xray's proxy.Outbound.Process(context, transport.Link, internet.Dialer) receives the routed TCP/UDP target via session context. transport.Link is a buffer reader/writer pair. The outbound handler is also the dialer; it calls internet.Dial using stream settings, which dispatches to the registered masque transport.

proxy/masque then gets or creates a shared IP tunnel, creates a gVisor userspace TCP/IP stack using wireguard.CreateNetTUN, and dials each target using its wireguard.Net TCP/UDP methods. Two pump loops move raw IP packets between the inner tun.Device and outer CONNECT-IP connection. No kernel TUN is opened by this path and no WireGuard encryption or WireGuard UDP tunnel is layered inside MASQUE.

The "wireguard" naming is code reuse: netstack.go supplies gVisor IPv4/IPv6/TCP/UDP/ICMP endpoints and a tun.Device interface. Xray's separate real WireGuard outbound creates a device.NewDevice and sets WireGuard private/public keys, endpoint and allowed IPs through IpcSet. MASQUE never invokes that device.NewDevice path. This separation is useful for a relay design: the outer authenticated CONNECT-IP transport exposes packet read/write and inner TCP/UDP dialing, while a genuine WireGuard transport is another packet carrier.

Evidence:
- [Outbound interface, proxy/proxy.go:70-74](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/proxy/proxy.go#L70-L74)
- [Link abstraction, transport/link.go:5-9](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/transport/link.go#L5-L9)
- [Dialer/transport registry, transport/internet/dialer.go:21-74](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/transport/internet/dialer.go#L21-L74)
- [Handler dialing, app/proxyman/outbound/handler.go:268-277](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/app/proxyman/outbound/handler.go#L268-L277)
- [Per-flow TCP/UDP dialing, proxy/masque/client.go:105-192](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/proxy/masque/client.go#L105-L192)
- [Netstack creation/raw pumps, proxy/masque/client.go:318-390](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/proxy/masque/client.go#L318-L390)
- [gVisor userspace stack, proxy/wireguard/netstack.go:53-115](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/proxy/wireguard/netstack.go#L53-L115)
- [Real WireGuard device creation, proxy/wireguard/client.go:290-329](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/proxy/wireguard/client.go#L290-L329)

### DNS, failover, and lifecycle

For target domains, the inner netstack sends DNS through the tunnel. Default remote DNS IPs are 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001; config accepts IP literals only. Servers are filtered to reachable address families, with a warning if none match. Each supported family does A/AAAA lookup concurrently, each query tries DNS servers in config order for two rounds, with five-second exchanges. Exchange tries UDP first and TCP only for a truncated UDP answer, not for a UDP timeout. Results are cached by TTL. IPv6 results are ordered before IPv4 whenever IPv6 exists; inner target dialing is sequential, dividing a TCP deadline over remaining addresses, not racing Happy Eyeballs. NXDOMAIN exits early. Physical MASQUE endpoint DNS is separate through internet.DialSystem/system resolver policy, so target remoteDNS does not bootstrap the outer tunnel.

CONNECT-IP tunnel establishment has a 10-second timeout and detaches the triggering flow's cancellation while linking the client lifetime cancellation. XMUX pools full inner IP tunnels and counts running per-flow users; default maxConnections is 1, default reusable lifetime randomized 1800-3000 seconds. Retired tunnels close after active flows finish. Failed new tunnel creation records an error and imposes a one-second retry interval; existing healthy tunnels can continue accepting flows. This is healthy-tunnel pool fallback, not protocol, endpoint, or account failover. No automatic new endpoint selection or transparent established TCP-session migration appears in these paths.

Close uses sync.Once to close the CONNECT-IP connection and gVisor tun, remove tunnel tracking, and wake readers. QUIC context teardown closes transport and UDP PacketConn. WARP configured addresses are seeded instead of requesting new addresses; generic reassignment withdrawing an active local address closes the tunnel, and newly added family waits for a future tunnel. Outer Conn deadline methods return nil without applying deadlines; inner TCP flow/timeouts and establish cancellation provide the actual timeout behavior.

H2 defaults to a 45-second idle period before PING (ChromeH2KeepAlivePeriod); after a ping it fails if no frame arrives in 15 seconds. HTTP/2 has bounded flow-control windows and an outgoing StreamBuffer threshold of 32 KiB; this threshold checks the buffer before appending a write and is not a strict post-append total-size cap.

Evidence:
- [Default DNS/lifetime constants, proxy/masque/client.go:33-102](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/proxy/masque/client.go#L33-L102)
- [Healthy pool fallback/retry, proxy/masque/client.go:195-245](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/proxy/masque/client.go#L195-L245)
- [Establish/client close, proxy/masque/client.go:254-285](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/proxy/masque/client.go#L254-L285)
- [DNS family selection, proxy/masque/client.go:318-343](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/proxy/masque/client.go#L318-L343)
- [DNS exchange UDP/truncated TCP, proxy/wireguard/netstack.go:426-478](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/proxy/wireguard/netstack.go#L426-L478)
- [DNS rounds/server order, proxy/wireguard/netstack.go:532-583](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/proxy/wireguard/netstack.go#L532-L583)
- [Parallel A/AAAA, proxy/wireguard/netstack.go:586-634](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/proxy/wireguard/netstack.go#L586-L634)
- [IPv6 first/cache and sequential dial, proxy/wireguard/netstack.go:696-833](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/proxy/wireguard/netstack.go#L696-L833)
- [XMUX retirement, transport/internet/splithttp/mux.go:28-146](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/transport/internet/splithttp/mux.go#L28-L146)
- [Address withdrawal/deadlines, transport/internet/masque/conn.go:72-127](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/transport/internet/masque/conn.go#L72-L127)
- [H2 ping timeout, transport/internet/masque/http2.go:369-397](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/transport/internet/masque/http2.go#L369-L397)
- [Actual keepalive defaults, common/net/net.go:17-20](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/common/net/net.go#L17-L20)

### Upstream tests inspected

These are local synthetic peers, not proof of a successful connection to a live Cloudflare account.
- [warp_test.go:214-288](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/transport/internet/masque/warp_test.go#L214-L288): H3 Cloudflare protocol, draft and RFC datagrams, context ID zero, no ADDRESS_REQUEST.
- [warp_test.go:290-365](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/transport/internet/masque/warp_test.go#L290-L365): H2/empty ALPN, headers, bare IP DATAGRAM capsule, mTLS.
- [warp_test.go:367-439](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/transport/internet/masque/warp_test.go#L367-L439): SPKI match/mismatch, alternate cert pin and rejected client key.
- [http2_test.go:200-437](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/transport/internet/masque/http2_test.go#L200-L437): classic CONNECT, single-stream/Extended CONNECT requirements, flow control, oversized frames, reset, ping.
- [proxy/masque/client_test.go:22-54](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/proxy/masque/client_test.go#L22-L54): existing healthy tunnel fallback on failed new dial and retry suppression.
- [testing/scenarios/masque_test.go:383-388](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/testing/scenarios/masque_test.go#L383-L388): full Xray generic MASQUE H3/H2 scenario entrypoints.

Dependencies are pinned in [go.mod:3-36](https://github.com/XTLS/Xray-core/blob/0888beb38a9ba45440557175e71ce21cf8ba3b13/go.mod#L3-L36): Go 1.27; apernet/quic-go fork 184d081eef3e; WireGuard f333402bd9cb; gVisor 89a5d21be8f0. These are research references, not recommended production dependencies or a runnable retained checkout.

## sing-box

### What exists and what does not

The [client documentation](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/docs/configuration/endpoint/masque-client.md#L1-L5) and [server documentation](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/docs/configuration/endpoint/masque-server.md) identify `masque-client` and `masque-server` as RFC 9484 CONNECT-IP endpoints, introduced in 1.15.0. The [changelog](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/docs/changelog.md#L38-L73) places the initial feature in **1.15.0-alpha.7**. Therefore this finding concerns the present `testing` source and must not be presented as stable 1.14.x functionality.

Real implementation files exist in [`protocol/masque`](https://github.com/SagerNet/sing-box/tree/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/protocol/masque) and [`transport/masque`](https://github.com/SagerNet/sing-box/tree/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/transport/masque). The endpoint registry registers both types in [`include/registry.go:119`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/include/registry.go#L119). This is an IP tunnel, not just TCP CONNECT plus CONNECT-UDP support on a regular HTTP proxy.

A repository-wide case-insensitive search for whole-word WARP, `warp-masque`, `engage.cloudflare`, and `162.159` returned no matches. More decisively, the implementation hard-codes `upgradeToken = "connect-ip"` in [`transport/masque/session.go:17`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/transport/masque/session.go#L17), and the configurable options have no Cloudflare dialect or WARP key field. The existing [Cloudflared inbound](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/docs/configuration/inbound/cloudflared.md#L5-L9) is a Cloudflare Tunnel client for incoming traffic; it does not establish WARP egress capability.

The open upstream [feature request #4603](https://github.com/SagerNet/sing-box/issues/4603), created 2026-10-03, explicitly states that the current endpoint only supports normal RFC MASQUE and cannot connect to WARP because Cloudflare's MASQUE deviates from the RFC. It requests the missing compatibility work and cites usque and a sing-box fork. This is corroborating evidence, while the pinned source remains the basis for the capability conclusion. The public issue and empty comments response are retained locally.

### Authentication, endpoints, and peer key verification

[`option/masque.go`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/option/masque.go#L24-L43) exposes `server`, `server_port`, username/password, TLS, `path`, custom headers, version controls, route advertisement, MTU, NAT parameters, and on-demand operation. There is no built-in Cloudflare endpoint discovery, registration API, account token refresh, WARP public key lookup, or WARP client certificate synthesis.

The generic default URI template is `/.well-known/masque/ip/{target}/{ipproto}/`; [`Template.Expand`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/transport/masque/template.go#L121-L140) substitutes `*` for both fields, yielding `/.well-known/masque/ip/*/*/`. A configured path can change this resource path, but cannot change the hard-coded `connect-ip` protocol into Cloudflare's `cf-connect-ip` dialect.

[`protocol/masque/client.go:97-119`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/protocol/masque/client.go#L97-L119) derives HTTP authority from a custom Host header or the configured server, independently of the physical dialer. [`transport/http/client.go:168-170`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/transport/http/client.go#L168-L170) builds Basic authorization. `OpenTunnel` selects origin authorization, so the header is `Authorization`, rather than normal forward-proxy `Proxy-Authorization`; see [`tunnel_client.go:27-36`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/transport/http/tunnel_client.go#L27-L36) and [`buildRequestHeader:325-340`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/transport/http/client.go#L325-L340).

Generic mutual TLS is available. [`common/tls/std_client.go:196-224`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/common/tls/std_client.go#L196-L224) loads PEM client certificates and keys, requires them together, parses the X.509 key pair, and supplies it to TLS. This is credential loading, not WARP-specific identity creation.

The generic `certificate_public_key_sha256` setting pins the SHA-256 digest of DER SubjectPublicKeyInfo in base64; see the [TLS documentation](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/docs/configuration/shared/tls.md#L346-L361). [`VerifyPinnedCertificate:279-300`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/common/tls/std_client.go#L279-L300) hashes the leaf certificate public key via `x509.MarshalPKIXPublicKey` and requires a configured match. When pinning is configured, [`std_client.go:138-145`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/common/tls/std_client.go#L138-L145) replaces normal chain verification with the pin verifier. Certificate-hash and SPKI-hash alternatives can be configured; a raw base64 WARP SPKI is not the same value as the base64 SHA-256 digest expected here.

### HTTP versions and downgrade behavior

[`ResolvedVersion`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/option/masque.go#L48-L53) resolves `version: 0` to HTTP/3. [`protocol/masque/client.go:72-79`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/protocol/masque/client.go#L72-L79) additionally changes the implicit/default version to HTTP/2 when the binary lacks HTTP/3. This build-dependent choice happens even before runtime fallback. Strict mode therefore needs an explicit version, not just a fallback flag.

[`transport/http/tunnel_client.go:47-87`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/transport/http/tunnel_client.go#L47-L87) attempts HTTP/3, can mark it unavailable, then attempts HTTP/2, and finally HTTP/1.1 Upgrade. `disable_version_fallback` defaults false. With explicit HTTP/3 and the flag true, initial H3 errors return without trying H2; explicit H3 also fails construction if QUIC was not built. With explicit HTTP/2 and the flag true, lack of TLS, lack of H2 ALPN, or unavailable/unsupported extended CONNECT returns an error. H2 requires TLS in strict mode. The source's generic `NewClient` can default to `N.SystemDialer` when no dialer is supplied, which is another reason a fail-closed crate should require an egress transport explicitly instead of accepting a hidden system fallback.

H3 is behind the `with_quic` build tag in [`transport/http/client_h3.go`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/transport/http/client_h3.go#L1-L26). It enables QUIC datagrams, dials the configured server over UDP, and caches one live HTTP/3 connection (`acquire`, lines 76-104). The CONNECT-IP request uses HTTPS scheme, configured authority, method CONNECT, `Proto: connect-ip`, and `Capsule-Protocol: ?1` (lines 168-184). The source uses `DialEarly`; this observation does not by itself establish whether authenticated CONNECT-IP requests are replayable 0-RTT traffic under every TLS configuration.

Generic H2 uses ALPN `h2`, caches/reuses HTTP/2 connections, and sends extended CONNECT with `:protocol: connect-ip`, scheme/path/authority, and `Capsule-Protocol: ?1`; see [`client_h2.go:18-45`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/transport/http/client_h2.go#L18-L45) and [`tunnel_client.go:146-157`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/transport/http/tunnel_client.go#L146-L157). It is not Cloudflare WARP's traditional H2 CONNECT variant.

The endpoint gives the HTTP/2 keep-alive period a default of ten seconds and sizes the QUIC initial packet for MTU plus overhead; see [`protocol/masque/client.go:37-85`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/protocol/masque/client.go#L37-L85). [HTTP2 fields](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/docs/configuration/shared/http2.md) expose idle timeout, keep-alive, receive windows, and maximum concurrent streams.

### Encapsulation and address configuration

[`transport/masque/session.go`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/transport/masque/session.go) multiplexes control capsules on the CONNECT stream and packet datagrams when the carrier exposes a DatagramStream. Its constants are MTU 1280 and max IP packet 65,535 bytes. Packet datagrams use context ID zero. The H3 wrapper delegates the QUIC stream-ID association to the HTTP/3 library; the MASQUE layer explicitly encodes/decodes the context ID.

`loopCapsule` enforces a 1 MiB capsule-length limit, handles DATAGRAM plus ADDRESS_ASSIGN, ADDRESS_REQUEST, and ROUTE_ADVERTISEMENT, and skips unknown capsule types. [`transport/masque/capsule.go`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/transport/masque/capsule.go#L13-L109) uses control capsule types 1, 2, and 3 and validates IP versions, prefix lengths, address ranges, ordering, and overlap.

`writePackets` sends native H3 datagrams when possible. A datagram-unsupported result falls back to DATAGRAM capsules **on the same HTTP/3 stream**, rather than selecting another HTTP version. H2/H1 always carry DATAGRAM capsules. These RFC capsules contain context ID zero followed by the IP packet. Oversized H3 datagrams generate inner Packet Too Big feedback when the resulting MTU is at least 1280; otherwise the session fails. This distinction between same-carrier capsule use and HTTP-version downgrade should be modeled explicitly in the Rust API and metrics.

On connection, [`transport/masque/client.go:161-200`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/transport/masque/client.go#L161-L200) opens CONNECT-IP and requests an IPv4 and IPv6 address with request IDs 1 and 2. Optional client routes are advertised. The endpoint becomes ready after it has a usable assigned address and its device accepts configuration; route advertisement may arrive later (`handleAddressAssign`, `handleRouteAdvertisement`, `updateConfiguration`, lines 336-396). The readiness criterion is address/device readiness, not a proven public Internet request or DNS exchange.

### Network abstraction and DNS

[`adapter.Outbound`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/adapter/outbound.go#L15-L21) includes the shared `N.Dialer`; [`adapter.Endpoint`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/adapter/endpoint.go#L10-L15) adds lifecycle to the outbound interface. [`ClientEndpoint`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/protocol/masque/client.go#L39-L60) provides TCP/UDP dial, packet listening, raw flow forwarding, route preference, interface-change handling, and on-demand operation. It advertises TCP, UDP, and ICMP support in the endpoint adapter.

The MASQUE transport is separated from the network stack by a `ClientHandler` that updates addresses, receives packet buffers, and reports required headroom. [`transport/device.Device`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/transport/device/device.go#L18-L84) is a second boundary: dial/listen plus packet input/output, MTU/address configuration, queue creation, return-path attachment, startup, and close. `system: false` chooses the internal stack; privileged system interface support is optional.

The current userspace device uses `sing-tun`'s Go stack with a memory TUN. [`transport/device/stack.go:81-115`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/transport/device/stack.go#L81-L115) creates TCP and UDP connections in that stack. [`bindAddress:118-134`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/transport/device/stack.go#L118-L134) fails when the required local address family is missing; it does not silently dial the host network.

Destination DNS is a separate service. [`ClientEndpoint.DialContext:303-324`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/protocol/masque/client.go#L303-L324) resolves domain destinations with `DNSRouter.Lookup`, then serially attempts addresses through the tunnel device. Packet listening similarly resolves via DNSRouter (lines 327-352). That lookup does not automatically inherit the endpoint's MASQUE tunnel. Incoming DNS packets may also be passed to DNSRouter's hijack handler; see [`protocol/masque/endpoint.go:92-101`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/protocol/masque/endpoint.go#L92-L101).

DNS server transports construct an independent dialer. [`dns/transport_dialer.go:19-25`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/dns/transport_dialer.go#L19-L25) calls `dialer.NewWithOptions`; [`common/dialer/dialer.go:46-64`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/common/dialer/dialer.go#L46-L64) uses a configured detour or a default direct dialer. The [UDP DNS documentation explicitly confirms](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/docs/configuration/dns/server/udp.md#L29-L32) that the new transport defaults to the equivalent of an empty direct outbound. Thus a DNS server `detour` to the tunnel endpoint, or a Rust resolver that accepts only the tunnel's TCP/UDP interfaces, is necessary to enforce all server DNS through MASQUE.

The physical MASQUE server's own domain is separately resolved using configured resolver options (`RemoteIsDomain`, `ResolverOnDetour`, lines 87-93 of the endpoint constructor). A strict no-direct-DNS design should use a supplied edge IP with separate logical authority/SNI, or a separately documented bootstrap mechanism. It must not recursively resolve the WARP edge through the tunnel that is still being established.

### Failover, lifecycle, resource handling, and regression references

[`transport/masque/client.go:18-19,110-158`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/transport/masque/client.go#L110-L158) reconnects with exponential backoff from one second to one minute. A previously established session resets the backoff. The same configured server is retried; no WARP endpoint-discovery or health-ranked edge failover was found. The HTTP helper also has an H3-unavailable backoff of five seconds to five minutes, relevant only when version fallback is enabled.

Suspend and interface-change restart cancel the current session and reset cached HTTP connections. `Close` cancels the client context, waits for the reconnect loop, then closes the HTTP client. [`session.run:59-72`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/transport/masque/session.go#L59-L72) closes the carrier on cancellation, cancels after the capsule reader exits, and joins the datagram reader. Packet/control writes are serialized. Buffer release is explicit on invalid, discarded, successful datagram, and error paths.

The endpoint's normal dial fails with `endpoint is not ready yet` while disconnected; on-demand mode resumes and waits with a bounded TCP timeout. There is no direct host-network fallback in these endpoint dial methods. However [`Client.WritePacketBuffers:287-333`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/transport/masque/client.go#L287-L333) releases and silently drops buffers when no active/ready session exists, and cancels the current session on packet-write failure without returning that write error at the end. This is fail-closed with respect to routing, but weaker failure observability than the proposed Rust egress contract should provide. Distinguish lost packets, failed sends, and disconnects explicitly.

Startup uses cleanup scopes. [`adapter.Scope.Close:128-141`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/adapter/lifecycle.go#L128-L141) cancels the scope and runs registered cleanups in reverse order. The client registers device then client cleanup; the userspace device has close-once shutdown for stack and memory TUN. Device options carry UDP/ICMP timeouts, NAT mapping/filtering/max count, and a memory-pressure callback. These are useful patterns, but the selected sing-box source alone does not prove all underlying `sing-tun` queue and connection memory bounds.

The generic MASQUE server allocates per-session tunnel addresses, returns them to the pool on release, uses a per-destination `tun.OutboundQueue`, and cancels sessions during shutdown; see [`transport/masque/server.go:149-250`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/transport/masque/server.go#L149-L250). This server is a useful comparison for session isolation, although this project's server protocol is network-relay and its egress is WARP.

Read-only regression evidence:

- [`test/masque_test.go:157-286`](https://github.com/SagerNet/sing-box/blob/dfb80349bf5779ec0a3f834c9ec2794345bff8f0/test/masque_test.go#L157-L286) covers self-to-self H3/H2/H1, version fallback, advertised routes, no route, packet-too-big behavior, reconnect backoff, and a stuck/flooded client. These tests use generic local endpoints. They do not establish WARP interoperability or a one-hour soak.
- [Issue #4561](https://github.com/SagerNet/sing-box/issues/4561) reports H2 extended CONNECT failures after Go 1.27 changed HTTP/2 internals. Its closing comment identifies [fix `f95851544a90f8c34215e31afc411e5a0799fbc1`](https://github.com/SagerNet/sing-box/commit/f95851544a90f8c34215e31afc411e5a0799fbc1). Current source has legacy/internal HTTP2 wrappers and explicitly reports unavailable extended CONNECT when applicable. This is historical regression evidence, not a claim the pinned source still has the old bug.
- [Issue #4575](https://github.com/SagerNet/sing-box/issues/4575) reports an old 256-packet server session queue silently dropping packets and limiting inner TCP. The pinned current session code no longer contains that queue. [Commit `74182ce8efd184f98dcfc87e8c2658362004c6c8`](https://github.com/SagerNet/sing-box/commit/74182ce8efd184f98dcfc87e8c2658362004c6c8) changes per-destination backpressure, including server queues, device interfaces, and session writes. Retest stalled peers, large transfers, fairness, and memory growth in the independent Rust implementation instead of carrying forward the historical throughput claim as a current fact.
- [Issue #4000](https://github.com/SagerNet/sing-box/issues/4000) requests endpoint-style CONNECT-IP and explains why tunnel addresses, TCP/UDP sharing, and DNS loop avoidance resemble WireGuard endpoint concerns. This is design context; current source demonstrates which parts were implemented.

## Standards and interpretation

The locally retained standards are [RFC 9484](https://www.rfc-editor.org/rfc/rfc9484.html) (CONNECT-IP, address/route control capsules, IP packet semantics), [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297.html) (HTTP Datagrams and Capsule Protocol), [RFC 9220](https://www.rfc-editor.org/rfc/rfc9220.html) (extended CONNECT over HTTP/3), and [RFC 8441](https://www.rfc-editor.org/rfc/rfc8441.html) (extended CONNECT and SETTINGS_ENABLE_CONNECT_PROTOCOL for HTTP/2).

A generic RFC CONNECT-IP tunnel and Cloudflare's WARP dialect need distinct configuration and wire-format cases. In particular, one should not infer H2 support from an H3-capable MASQUE package, reuse the H3 context-ID rules blindly in WARP H2, or infer authentication from a field called `public_key`. Public key formats and verifier precedence matter. The recorded code behavior is evidence for an independent implementation design, not a promise of server compatibility without later live tests.

## Implications for the independent Rust egress crate

1. Require an explicit transport enum (`h2` or `h3`) and an explicit WARP dialect. An unsupported build, failed ALPN negotiation, pin failure, wrong HTTP response, or missing required capability must return a typed error. Never choose another HTTP version or host-network egress implicitly.
2. Separate physical edge address, TLS server identity/key pin, logical HTTP authority/resource, and client identity. WARP enrollment should remain a deliberate external/configuration operation unless an independently documented API workflow is added.
3. Put raw IP packet transport below a userspace TCP/UDP stack. Give callers stream and datagram interfaces that cannot escape to system sockets; this supports both the relay server and future consumers without requiring a process-wide TUN route.
4. Make DNS an explicit consumer of those same tunnel-only interfaces. Supplied edge IPs avoid a bootstrap DNS exception. Relayed TCP, UDP, and server-side DNS must share the same fail-closed policy.
5. Model generation/ready/disconnected/shutdown state, bound connection/packet queues, propagate send failures, interrupt waits on close, and join background tasks. Address assignment alone is insufficient functional readiness evidence.
6. Reproduce the relevant malformed capsule, version/no-downgrade, wrong pin, missing address family, packet-too-big, reconnect, stalled peer, cancellation, queue-pressure, and DNS-leak regressions. Add actual large transfer and at least one-hour soak results later; this research has not run them.

The GPL sing-box sources are retained solely for study and should not be copied or mechanically translated into production. Keep the Rust implementation independent and derive protocol behavior from the cited standards and independently verified wire observations. Preserve the licenses of all retained reference sources; Xray's MPL root license does not override the separate license on embedded CONNECT-IP files.
