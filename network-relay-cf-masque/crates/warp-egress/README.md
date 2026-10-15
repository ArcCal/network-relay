# WARP MASQUE egress

This crate exposes TCP streams, UDP datagrams, and DNS resolution through an
existing Cloudflare WARP MASQUE registration and a userspace TCP/IP stack. It
requires no TUN device or host routing changes. The frontend supplies an
`Egress`; this crate's `WarpEgress` implements that interface.

Load the application's TOML file with `WarpConfig::load`, then connect with
`WarpEgress::connect(&config)`. Loading and `config.validate()` check the enrolled
P-256 key, pinned endpoint public key, assigned addresses, and configuration
without opening a socket. Device registration is an explicit external step;
there is no registration REST client or automatic enrollment in this crate.

```toml
[warp]
transport = "h2"

[warp.registration]
private_key = "REPLACE_WITH_ENROLLED_BASE64_P256_PKCS8_PRIVATE_KEY"
endpoint_public_key = """-----BEGIN PUBLIC KEY-----
REPLACE_WITH_ENROLLED_PUBLIC_KEY_BASE64
-----END PUBLIC KEY-----
"""
tunnel_ipv4 = "172.16.0.2"
```

This IPv4-only example needs no JSON file. Replace its credential placeholders
and assigned address with the existing enrollment values. A combined relay
TOML or a WARP-only TOML is accepted. Select `h2` or `h3` explicitly. Inline
registration requires the private key, endpoint public key and assigned IPv4
address; IPv6 fields and account metadata (`device_id`, `access_token`,
`license`) are optional. H3 needs an enrolled `endpoint_v4` or explicit numeric
endpoint override. Protect the configuration with mode 0600.

For legacy callers, `registration = "path.json"` remains supported instead of
the inline table; its path is relative to the TOML file's directory. The loader
accepts the pinned cf-masque format and usque aliases (`id`, `ipv4`, `ipv6`,
`endpoint_pub_key`); it converts usque's SEC1 P-256 private keys to PKCS#8.
Registration contents are redacted from `Debug` and parse errors.

An optional `endpoint` must be a numeric IP or socket address, such as
`"162.159.198.2"` or `"[2606:4700:103::1]:443"`. An optional `port` overrides the
chosen port; otherwise bare IPs and registration endpoints use 443, including
registration endpoints written with port zero. HTTP/2 uses its separate
registered endpoint or the pinned client's IPv4 default `162.159.198.2`.
`ipv6_endpoint = true` selects a registered outer IPv6 endpoint when no override
is supplied. Default `sni` is `consumer-masque.cloudflareclient.com` and default
`uri` is `https://cloudflareaccess.com/`.

DNS servers must be numeric socket addresses; the default is `1.1.1.1:53`.
Each configured DNS server's address family must have an assigned tunnel
address; an IPv4-only registration must use IPv4 DNS servers. With no
`tunnel_ipv6`, DNS skips AAAA queries and IPv6 destinations cannot be dialed.
Queries, including TCP fallback after truncated UDP answers, use the userspace
stack. A terminal tunnel failure immediately rejects DNS requests, including
cached answers, literals, and shared pending queries. The transport never falls
back to the host resolver or direct kernel sockets.

`WarpEgress` owns one fixed-transport session. Its cloneable controller and
socket handles share terminal state; detected tunnel loss, worker failure,
explicit shutdown, or dropping the final controller wakes blocked operations
and makes them fail. `Egress::failed()` is an independent failure future, so an
embedding application can cancel rate-limited or otherwise paused relays.
`WarpEgress::closed()` reports the first cause. There is no automatic reconnect:
construct a fresh `WarpEgress` after failure if the application chooses to retry.
Old sockets never attach to that new session.

TCP supplies numeric local/peer metadata and a separate reset control through
`abort_handle()`, while normal write shutdown sends FIN. Connected UDP only
returns packets from its selected numeric peer, preserves empty datagrams,
serializes concurrent send/receive waiters, and refuses datagrams above the
current MTU. With MTU 1280, payload ceilings are 1252 bytes for IPv4 and 1232
bytes for IPv6; IP fragmentation is not implemented. If the path cannot carry
IPv6's 1280-byte minimum, new IPv6 operations fail and existing IPv6 TCP flows
are reset. DNS EDNS capacity follows the actual per-family UDP ceiling.

The stack permits 64 total sockets, including DNS, connecting and lingering
TCP. Each TCP socket reserves 256 KiB RX and 128 KiB TX; each UDP socket has
bounded packet slots and byte buffers. Overload returns a resource error.
`status()` serializes availability, capabilities, MTU, socket/worker counts and
packet/byte/drop counters without credential or arbitrary response-header
values. Packet send counters indicate local transport acceptance, not remote
delivery. Shutdown invalidates flows before waiting briefly for worker and
transport cleanup.

The `test-support` feature exposes packet-stack primitives for synthetic peers.
It is excluded from the default production API and does not provide a direct
host-network egress implementation.
