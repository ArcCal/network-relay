# network-relay-vless

network-relay with every tunnel carried through a downstream VLESS server:
devices connect exactly as to network-relay (HTTP CONNECT for TCP and
CONNECT-UDP, RFC 9298, over HTTP/3, HTTP/2 and HTTP/1.1, with the same
users, profiles, website and limits), and instead of opening connections
from this host, the relay opens each one through a VLESS server such as
Xray-core. There is no fallback: when the VLESS server cannot be reached,
tunnels are refused.

It is a separate program built on network-relay's library, as
network-relay-cf-masque is. The relay itself (TLS, QUIC, HTTP, CONNECT-UDP,
authentication, destination rules, limits, reloads, `passwd`, `identity`,
`profile`, `check`) is network-relay's code, unchanged; this project adds
only an `Egress` (`src/egress.rs`) that carries name lookups, TCP
connections and UDP flows over VLESS, and the `[vless]` configuration table.

## What is supported

The downstream connection is **VLESS over a plaintext WebSocket**, as an
Xray-core inbound with these settings serves it:

```json
{
  "inbounds": [{
    "listen": "0.0.0.0", "port": 80, "protocol": "vless",
    "settings": { "clients": [{ "id": "b4e4fad1-c320-428e-92dc-f8f6944a7dec" }], "decryption": "none" },
    "streamSettings": { "network": "ws", "security": "none",
                        "wsSettings": { "path": "/J2kV4jxviMDXceRQYVXiv6YwCc462T6P0Dayx5JYR8R" } },
    "sniffing": { "enabled": true, "destOverride": ["http", "quic", "tls"], "routeOnly": true }
  }]
}
```

(The ID and path are examples; use your own.) Keep `routeOnly` enabled,
or disable sniffing, so the downstream uses the destination address the
relay checked. Apply destination restrictions on the downstream too.

| Setting | Supported |
|---|---|
| VLESS version | 0, no addons |
| `encryption` / `decryption` | `none` only |
| `flow` | none only (XTLS Vision needs TLS) |
| Commands | TCP (1) and UDP (2); one VLESS connection per tunnel; no Mux, XUDP or reverse |
| Transport (`network`) | `ws` (WebSocket, RFC 6455) only |
| Security | `none` only: no TLS, no REALITY |
| WebSocket | path (with any query) and Host header configurable; no early data, no extra headers |
| User ID | a UUID, or a 1 to 30 byte string mapped to a UUID as Xray-core does |

Anything else in `[vless]` (another transport or security, a flow, VLESS
encryption, unknown keys) stops the program with an error naming the key;
nothing is reinterpreted as a supported setting.

## Configuration

One TOML file holds network-relay's settings, unchanged, and a `[vless]`
table. `examples/relay.toml` is a complete example for the inbound above.

| `[vless]` key | Meaning |
|---|---|
| `server` | the VLESS server, `host:port` (IPv6 in brackets); a host name is looked up with this host's resolver |
| `uuid` | the inbound's client `id` |
| `transport` | must be `"ws"` |
| `security` | must be `"none"`; written out so the plaintext connection is a deliberate choice |
| `path` | the inbound's `wsSettings.path`, exactly |
| `host` | the WebSocket Host header (default: the server's host, with `:port` unless 80) |
| `dns_servers` | resolvers for destination names, `ip:port`, asked through the VLESS server (default `1.1.1.1:53`, `8.8.8.8:53`; at most 8) |
| `ip_preference` | `ipv4_first` (default), `ipv6_first`, `ipv4_only` or `ipv6_only` |
| `encryption`, `flow` | accepted only as `"none"` and `""`, for configurations copied from Xray-core |

Errors never quote the file, and the log never shows the user ID or path.
`SIGHUP` reloads what network-relay reloads; `[vless]` changes need a
restart (the program says so when it notices one).

## How tunnels work

- **TCP**: for a CONNECT the relay resolves the name (below), checks every
  address against `blocked_destinations`, `blocked_ports` and its own
  addresses, then opens a VLESS connection per attempt: TCP to the VLESS
  server, the WebSocket upgrade, and the VLESS request naming the checked
  IP address and port. The request goes out at once, so server-first
  protocols work.
- **UDP**: each CONNECT-UDP flow is one VLESS connection with the UDP
  command to the checked address; datagrams travel with a 2-byte length.
  An empty datagram is encoded as a zero length and stays a datagram on
  receipt. Payloads over 8190 bytes are dropped, as Xray-core does not pass
  larger ones back. The tested mihomo and sing-box versions pass empty
  datagrams; Xray-core v26.10.31 discards them in its own reader/writers.
- **Names**: looked up with DNS over TCP to `dns_servers`, each lookup over
  its own VLESS connection, A and AAAA pipelined; answers are cached for
  their TTL, including CNAMEs (at most five minutes). Unrelated answer
  records are ignored. A usable answer is retained if the other address
  family fails or times out; waiting does not renew the answer's TTL. Names
  never reach this host's resolver. NXDOMAIN and NODATA are cached only
  for a relevant SOA's negative lifetime, bounded by any CNAME TTL and
  five minutes; without an SOA or with a zero TTL they are not cached.
  Completed lookup failures are cached for one second (RFC 9520), keeping
  their error distinct from NXDOMAIN/NODATA. The shared cache holds at most
  4096 names. Cancellation does not create a failure entry.
  The relay allows a lookup five seconds, including its admission wait;
  each resolver gets up to 2.5 seconds within that same deadline. A lookup
  that reaches the deadline caches a one-second timeout failure. Cancelling
  earlier or timing out before admission does not create a failure entry.
  A slower concurrent failure never replaces a still-valid successful answer.
  Lookups start with the most recently successful resolver and try the others
  sequentially in circular configuration order. If the total deadline expires,
  the next uncached lookup starts after the interrupted resolver, unless another
  lookup has selected a working resolver in the meantime. This avoids repeatedly
  waiting for a dead first entry and eventually reaches later entries without
  adding concurrent DNS requests. Duplicate addresses are tried only once per
  lookup. Configured resolvers should be interchangeable for destination names.
- **Failures**: a VLESS server that refuses the connection or is down gives
  502; a timeout 504. Every tunnel needs the VLESS server; nothing is ever
  sent directly. At start the program sends one DNS query through the VLESS
  server and logs whether it worked; it starts either way, and tunnels fail
  until the server works.
- **Writing**: each VLESS connection has a task that sends and flushes
  what the tunnel writes (up to 8 messages of 16 KiB queued), since
  network-relay writes to a tunnel as to a kernel socket, without flushing.
  An explicit flush waits for local socket completion, not a remote
  acknowledgment. Writer failures wake waiting readers and flushes; received
  payload and queued UDP replies precede their terminal errors.
  Messages from the server are limited to 256 KiB.
- **Ending**: when a tunnel ends, queued data and its WebSocket close get
  at most five seconds before the connection is dropped. Tunnel, user and
  memory reservations stay charged until background I/O releases the socket.
  Failed or canceled connection attempts retain their reservations too.
  Replying to a received WebSocket Close uses the same bounded close budget;
  error Close codes and missing or truncated Close handshakes remain errors.
  When the device
  resets it, the VLESS connection is reset (`SO_LINGER` 0) at once.

## Limitations

These follow from VLESS, the WebSocket transport or the server's settings,
and this relay cannot remove them.

1. **Plaintext downstream.** With `security = "none"` the WebSocket is not
   encrypted. Anyone on the path between this host and the VLESS server can
   read the user ID (and then use the VLESS server), every destination and
   all traffic that is not itself encrypted, and can change it. Devices'
   connections to this relay stay TLS-protected; only the second leg is
   exposed. Use it only on a network you trust (the same host, a private
   network or an encrypted tunnel such as WireGuard), and do not reuse the
   ID elsewhere.
2. **Sniffing can override the checked destination.** With `sniffing.enabled`
   and `destOverride` `http`, `tls` and `quic`, Xray-core reads the HTTP
   Host, the TLS server name or the QUIC server name of the first data
   and, unless `routeOnly` is `true`, connects to that name instead of the
   address the relay checked, resolving it with its own resolver. So for
   HTTP, TLS and QUIC traffic the relay's `blocked_destinations` and the
   relay's own name lookup do not decide where the connection goes: a
   device can CONNECT to an allowed address and send a Host or SNI naming
   another. Only the port stays the checked one. Tested: with `routeOnly`
   disabled, a request to an allowed address with `Host: localhost` reached
   a loopback server the relay blocks (`tests/xray_interop.rs`, with
   loopback allowed on the Xray side); with `"routeOnly": true` it reached
   the checked address. To keep the relay's rules authoritative, set
   `"routeOnly": true` or disable sniffing on the inbound. Either way,
   restrict what the VLESS server may reach on its own side: Xray-core
   v26.10.31, the release tested, blocks private and special ranges for
   VLESS inbounds by default in its freedom outbound (its `finalRules`
   override that), but whether a given release does is for its own
   documentation to say, and other outbounds differ. For public
   destinations the relay's `blocked_destinations` are bypassed whenever
   the sniffed name is used.
3. **A 200 does not mean the destination answered.** VLESS has no reply to
   a request: the server's response header comes with its first data. The
   relay therefore answers CONNECT and CONNECT-UDP with 2xx once the VLESS
   request is sent; a destination the VLESS server cannot reach, or a user
   ID it rejects, usually shows as the tunnel being reset right after.
   A valid response header followed by a normal WebSocket close cannot be
   distinguished from an empty destination response: the tested Xray
   version uses this sequence when the destination refuses its connection.
   For the same reason only the
   first address of a name is tried in practice; `ip_preference` picks
   which family comes first.
4. **No half-close.** A WebSocket close ends both directions, so when a
   device finishes sending, the destination is not told; it learns when
   the whole tunnel ends. Protocols that wait for the client's FIN before
   answering do not work.
5. **One VLESS connection per tunnel and per lookup** (TCP, the WebSocket
   upgrade, then data): a tunnel takes about two round trips to the VLESS
   server longer to start than a direct one, and each tunnel uses a file
   descriptor here and one on the server. Name lookups add one round trip
   more unless cached.
6. **This host resolves the VLESS server's name** with its own resolver
   each time a tunnel opens; use an IP address in `server` to avoid it.
7. **IPv6 destinations** work only if the VLESS server has IPv6;
   `ip_preference = "ipv4_only"` avoids them.

## Build and run

Needs Rust (as network-relay does). From this directory:

```bash
cargo build --locked --release
```

The binary is `target/release/network-relay-vless`. To install it as a
service:

```bash
sudo install -m 755 target/release/network-relay-vless /usr/local/bin/
sudo useradd --system --no-create-home --shell /usr/sbin/nologin network-relay-vless
sudo install -d -m 750 -g network-relay-vless /etc/network-relay-vless
sudo install -m 640 -g network-relay-vless examples/relay.toml /etc/network-relay-vless/relay.toml
sudo install -m 644 deploy/network-relay-vless.service /etc/systemd/system/
```

Then edit `/etc/network-relay-vless/relay.toml` (the certificate, a user
from `network-relay-vless passwd --name iphone`, and `[vless]`), make the
certificate readable by the service as for network-relay, and:

```bash
network-relay-vless serve --check --config /etc/network-relay-vless/relay.toml
```

```bash
sudo systemctl enable --now network-relay-vless
```

Device profiles come from `network-relay-vless profile`, as from
network-relay; `network-relay-vless check --server relay.example.com
--user iphone` tests the running relay over every HTTP version.

## Tests

- `scripts/test.sh`: formatting, clippy and the tests that need no VLESS
  server: the VLESS header layout, user ID parsing (checked against
  Xray-core's own results), response parsing, the configuration's checks
  and that errors and the log hide the user ID, data written without a
  flush still reaching a slow WebSocket server, a server that closes
  without answering being an error, DNS failure/negative cache lifetimes,
  cancellation, distinct pipelined DNS IDs, truncated DNS replies,
  predecode question-count allocation bounds and empty reads, and the
  program's `serve --check` and `profile` with the example file.
- `scripts/test-xray.sh`: the same relay against a real Xray-core server
  with the inbound above (on loopback, with loopback destinations allowed in
  its freedom outbound, and a hosts entry for the fixture name): network-relay's
  `check` over HTTP/3, HTTP/2 and HTTP/1.1 (TCP, UDP and name lookups through
  VLESS), 4 MiB each way over TCP, 120 UDP datagrams of up to 1150 bytes,
  destination rules applied before the VLESS server, an unknown name, a
  rejected user ID and a missing server failing without direct traffic,
  sniffing with and without `routeOnly`, VLESS connections closed after
  tunnels end or are reset, and the program itself serving from one file.
  It uses `XRAY_BIN`, or builds Xray-core from source with Go.

Additional Linux checks against real mihomo and sing-box WebSocket inbounds
verify empty UDP datagrams interleaved with 1, 1200 and 8190-byte datagrams.
The same Xray control passes nonempty payloads but drops empty packets before
they reach the target. These results do not establish TCP half-close support.

Not tested: a real network between the relay and the VLESS server, a CDN or
reverse proxy in front of it, and long-running load.
