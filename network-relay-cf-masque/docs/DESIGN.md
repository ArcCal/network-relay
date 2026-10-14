# Network Relay CF MASQUE: independent experimental design

## Scope and evidence-driven decisions

All project source, manifests, locks, tests, examples, documentation, private test files and generated outputs stay in this subdirectory. The parent and sibling repositories are read-only. `docs/evidence/parent-baseline.json` records the initial parent tree, including its pre-existing changes.

Research was completed before implementation. See the four `RESEARCH-*.md` reports for pinned sources actually read: current Network Relay, ArcCal/cf-masque, usque, usque-rs, Xray-core, sing-box and mihomo. Cloudflare WARP is a distinct dialect of MASQUE; generic RFC CONNECT-IP alone is insufficient. MIT cf-masque code is reused. GPL reference implementations supply behavioral evidence and are not copied into production.

## Components and data path

1. The independent CLI builds the reviewed Network Relay ingress snapshot inside `crates/relay-frontend`. Its TLS, HTTP/1.1 CONNECT, HTTP/2 and HTTP/3 CONNECT/CONNECT-UDP, authentication, user revocation, policy checks, cover website, rate and memory limits retain their existing semantics.
2. The frontend receives a required `Arc<dyn Egress>`. It cannot create a default direct egress. Names resolve through this interface, then every resolved numeric address passes the existing destination policy before dialing. All UDP flows retain peer source pinning and port restrictions.
3. `crates/warp-egress` provides an application-independent async TCP/connected UDP/DNS interface and a concrete userspace WARP implementation. It owns a pinned, mutually authenticated WARP tunnel, smoltcp sockets and tunnel DNS. It has no dependency on Network Relay, SOCKS, host TUN, policy routes or host DNS.
4. Only the physical WARP transport uses host TCP/UDP. Relayed business TCP/UDP and DNS become IP packets inside WARP. There is no kernel/direct fallback implementation in the release application.

## Transports and fail-closed lifecycle

Ingress H1/H2/H3 and egress H2/H3 are independent selections. The six pairings must be tested explicitly. No automatic HTTP transport downgrade is allowed. WARP H3 preserves `cf-connect-ip`, raw SPKI pinning, P-256 device identity, peer DATAGRAM negotiation, draft-00 compatibility and flow/context identifiers. WARP H2 preserves its distinct authority/headers, bare IP DATAGRAM Capsules, and narrow absent-ALPN compatibility rule.

Tunnel loss must revoke availability before cleanup, wake and fail every outstanding socket operation, reject new cached/literal/DNS/dial operations, close existing ingress tunnels with the correct errors, and release tasks/sockets. Reconnection, when enabled, uses only the selected transport and a fresh stack generation; old sockets never attach to a new tunnel. Shutdown and cancellation must not orphan connection tasks. No process-global allocator or host network modification is imported from a CLI client.

TCP half-close and abnormal reset are separate outcomes. The generic stream interface therefore includes numeric endpoint metadata and an explicit abort handle, not just `AsyncRead`/`AsyncWrite`. Connected UDP validates the peer and rejects payloads above the current tunnel MTU. IPv6 requires its minimum MTU; unsupported capabilities must be explicit, not silently disguised as another transport. Socket counts and buffers are bounded, and allocated stack memory is included when evaluating relay capacity.

## Configuration and independent reuse

The existing relay TOML format remains usable. WARP settings and the enrolled registration are separate files. Registration files and in-memory credentials never appear in tracked examples, diagnostic dumps or logs. The user-provided live registration is stored only under ignored `.secrets/` with mode 0600.

Other Rust projects can depend on `warp-masque-egress`, construct the WARP implementation and use its resolver/TCP/UDP methods without depending on the frontend crate. Since the selected HTTP/3 upstream revision needs both existing server correctness patches and Cloudflare client extensions, the standalone workspace carries a documented, tested union in its own vendor directories.

## Validation gates and honest status

Build and strict lint are followed by copied protocol/security regressions, userspace TCP/UDP/DNS failure/cancellation tests, synthetic WARP H2/H3 tests, all six ingress/egress pairings, unchanged client checks, half-close/reset/bulk/hash tests, and bounded-resource cleanup checks. The synthetic fixture is not live Cloudflare evidence.

Real WARP validation uses the authorized existing registration and separately selected H2/H3, confirms a Cloudflare egress IP and `warp=on/plus`, tunneled DNS and UDP, authenticated unchanged clients, full content hashes and large downloads. Only after functional validation is a >=3600-second soak started; longer runs are recorded separately. Metrics include packet/byte counters, drops, generations, socket/task/file-descriptor counts and RSS. Every test records source identity, start/end times, actual assertions, failures and omissions. Network/environment blockers remain blockers, never passes.

This is experimental work. No universal absence-of-bugs or full Apple device certification is claimed. Native NF GUI/device execution is distinct from portable protocol-core interoperability.
