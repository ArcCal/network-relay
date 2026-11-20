# Implementation status

Updated November 20, 2026 UTC. [Validation](VALIDATION.md) links the native Linux runs.
[Audit](AUDIT.md) records the earlier protocol and packet-stack review.

This project was restored after its removal and rebuilt on network-relay
itself: the client-facing server, configuration format and helper commands
are network-relay's code, called through the parent crate, not a copy. Only
the WARP egress, the one-file configuration reader and `serve` are this
project's own.

| Requirement | Implementation | Validation |
| --- | --- | --- |
| Same relay as network-relay, H1/H2/H3, TCP/UDP/auth/policy | network-relay's own server through `Relay::with_egress` / `server::run_variant` | network-relay's full integration suite also runs with every tunnel through an egress; six-pair WARP matrix |
| Mandatory WARP egress, no direct fallback | `network_relay::egress::Egress`, implemented by `warp-masque-egress` | Egress-loss, unavailable-egress and wrong-peer tests in network-relay; terminal-failure tests here |
| Explicit WARP H2 and H3 | Implemented | Synthetic pinned/mTLS peers; live Cloudflare not yet reached |
| Server DNS through WARP | Implemented | Peer-observed DNS, TCP fallback, negatives and post-failure denial |
| One standalone configuration file | `[warp]` and inline `[warp.registration]` in network-relay's file | CLI tests: single file, missing `[warp]`, legacy options refused, secret-free errors |
| IPv6 optional with a warning | `WarpConfig::warnings()`; printed and logged at start | CLI and unit tests: warning without `tunnel_ipv6`/`endpoint_v6`, server keeps running |
| Bounded IPv4/IPv6 receive reassembly | 16 contexts per family, 1500-byte reassembled packets, absolute 60-second expiry; overlap poisoning and independent atomic fragments | Exact-feature vendor tests, packet/mutation controls and a frozen 3950.46-second synthetic soak pass; see the November 13 validation record |
| Large file integrity/half-close | Implemented | 64 MiB transfers in all six pairings |
| NF/RS client compatibility | Their cores in this repository, used as they are | 12 ingress/egress pairs, 96 TCP/UDP checks, authentication and TLS negatives; NF uses its Linux bridge, not Network.framework |
| Long-held TCP/UDP stability | Implemented | Final local-peer soaks ran 3918.87 and 3928.85 seconds on Linux x86-64 and arm64. Each held 12 flows with one outer generation per mode and zero reported packet queue drops. The two older local failures remain open |
| Actual Cloudflare exit IP, live download, live soak | Not established | Requires a host with authorized WARP connectivity |
| Native Apple NF GUI/profile/device execution | Not executed here | Linux tests cannot substitute for it |

## Known limitations and deliberate behavior

1. Single selected-mode WARP generation. No in-process automatic reconnect;
   on terminal loss the server fails open tunnels, drains and exits. A
   supervisor restarts it in the same mode.
2. The userspace stack's socket limit, shared by DNS and connecting/closing
   TCP, is sized from memory: as many sockets as fit, full (384 KiB each),
   in a quarter of it, between 64 and 4096 (682 at 1 GiB, 341 at 512 MiB);
   `warp.max_sockets` sets another. network-relay's own memory-based
   `relay.max_tunnels` default is smaller, so it binds first and leaves room
   for DNS and closing connections. Beyond the socket limit, new tunnels are
   refused with 503 `connection_limit_reached`.
   TIME-WAIT remains until smoltcp expires it; `lingering_sockets` reports
   these retained sockets separately from live business flows.
3. UDP payloads are bounded by the WARP MTU, 1252/1232 bytes (IPv4/IPv6) at
   MTU 1280. Larger datagrams are dropped without fragmentation; the flow
   continues. They are never sent through the VPS network instead.
   Receive-side reassembly now accepts complete IP packets up to 1500 bytes;
   this does not increase the outbound UDP ceiling or fragment outgoing packets.
4. The Cloudflare enrollment must already exist. Registration/refresh,
   account lifecycle and license management are outside this project.
5. The server runs on Linux x86-64 and Linux arm64. Both architectures ran
   the standard suite and long local-peer soak on native Linux runners.
6. The local WARP peer reproduces a reviewed Cloudflare dialect, not every
   deployment condition at Cloudflare: account acceptance, real PMTU, loss,
   NAT and remote long-term stability need a live deployment.

No claim is made that these checks eliminate every possible defect.
