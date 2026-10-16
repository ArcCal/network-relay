# Scoped Network Relay NF repairs

Date: 2026-10-16. All tracked changes are inside `network-relay-nf/`, including
its private copy of h3. Neither relay server nor another client was modified.
No dependency versions, lockfiles, TLS verification, QUIC options or probe-renewal
intervals changed.

## Repairs and boundaries

| Previously listed issue | Result |
| --- | --- |
| One outer connection per flow exhausts a relay connection quota | HTTP/2 and HTTP/3 now share sessions within one client/account. HTTP/1.1 still requires a dedicated connection per tunnel. Peer stream/tunnel quotas remain enforced. |
| CONNECT response wait shorter than default server DNS/connect budget | Response wait increased from 10 to 20 seconds, separately from transport setup, within a 30-second overall open bound. An 11-second response succeeds in all forced modes and Auto. |
| Admission shown as Internet readiness; hardcoded target can be denied | UI explicitly says relay authentication does not verify Internet access. Each saved server can select an allowed numeric UDP admission target. Existing profiles retain `1.1.1.1:53`; policy and credentials are not bypassed. |
| UDP saturation drops lack accounting | Exact per-association counts in both directions, logarithmically limited warnings and final totals. Closed-queue deliveries remain separate from overflow. Queue sizes and drop policy are unchanged. |
| Intermittent Caddy HTTP/1.1 destination reset appears as EOF | Independently reproduced without NF. Caddy can authenticate TLS EOF before its TCP reset. No speculative client rewrite; controlled tests preserve real errors and legitimate half-closes. [Evidence](h1-reset-boundary-20261016.md). |
| Incomplete real Apple acceptance | Added an opt-in native observation script and [explicit acceptance matrix](../NATIVE-ACCEPTANCE.md). Native execution remains NOT RUN here. |

## Session ownership and request safety

The cache owns a shared connection driver. Each established flow also retains
the session but owns only its own pumps, so cancelling a flow does not close
siblings. Retired sessions remain alive while admitted flows use them. Different
client instances/accounts never share sessions. Forced HTTP/1.1 setup bypasses
the multiplexed cache and preserves independent concurrent handshakes.

Auto fallback is restricted to initial transport/capability setup. It never
replays a CONNECT because its response is slow or rejected. A narrowly typed
native bidirectional-stream creation failure proves that no request HEADERS
were submitted; only that case permits one fresh HTTP/3 attempt. Permission or
trust failures, deadlines, observed GOAWAY and post-open write/response errors
are excluded. Cache eviction checks session identity to preserve a newer session.

Review also reproduced a queued-request race in the local h3 library. While
waiting for stream credit, a request could receive GOAWAY and subsequently send
HEADERS. RFC 9114 section 5.2 says:

> Endpoints MUST NOT initiate new requests or promise new pushes on the
> connection after receipt of a GOAWAY frame from the peer.

The minimal repair rechecks GOAWAY immediately after stream creation and before
HEADERS. Existing admitted streams continue. The regression failed before this
repair and passes afterward; an independent reproduction additionally observed
the driver's closing state before releasing stream credit.

## Executed validation

Linux x86_64, Rust 1.99.0 and the official signed Swift 6.1.2 Linux toolchain.
The tests use real local TLS/QUIC relay binaries and disposable credentials,
with test-only rustls/Quinn replacing the native transport bridge.

- Rust: **95 passed**, zero failures; four external-fixture tests are ignored in
  the ordinary run and invoked separately. Formatting and project-only Clippy
  with warnings denied pass.
- Swift portable models: **53 passed**, zero failures, including backward
  settings, target validation/import/export and active-profile reconnect rules.
- Both servers, forced HTTP/1.1/2/3: remote DNS, TCP/UDP, 2 MiB duplex/half-close,
  Capsules of 0–65,000 bytes, account and certificate rejection, SOCKS source
  enforcement, fragment rejection and resource cleanup pass.
- Both servers, HTTP/2 and HTTP/3: **80 simultaneous tunnels use one outer
  connection**; cancelling 40 preserves the remaining tunnels. Controlled tests
  additionally check a peer stream limit of two, GOAWAY, account isolation,
  client-drop ownership, delayed responses and bounded pre-HEADERS recovery.
- Twenty additional dead-connection recovery repetitions pass for both HTTP/2
  and HTTP/3. Six controlled HTTP/1.1 EOF/reset/half-close cases pass, plus
  twenty additional executions of those six cases.
- Both servers, HTTP/2 and HTTP/3: 64 MiB direct and SOCKS downloads preserve
  exact bytes; a 32 MiB reader paused for five seconds resumes correctly;
  destination aborts remain errors and local SOCKS resets.
- Both servers: the retained idle group stream 0 stays untouched after thirteen
  seconds. No historical periodic-disconnect repair was removed.
- Both servers, HTTP/2 and HTTP/3: persistent TCP and UDP flows exchange exact
  payloads for 125–127 seconds across two successful 60-second probe renewals,
  using one outer connection per client, with no failure status and zero
  retained native-bridge resources after cancellation. This bounded check is
  not a one-hour stability test.

The complete unfiltered large-transfer run passes all three modes on the Rust
server, but reproduces the retained Caddy HTTP/1.1 reset-to-EOF boundary. Its
assertions were **not** weakened. An explicit transport selector allows separate
HTTP/2/3 bulk checks without hiding that HTTP/1.1 failure.

The accompanying [machine-readable results](client-reliability-20261016.json)
retain server hashes, execution times and source fingerprints for each external
run. The servers are Rust network-relay 1.5.0 and the retained Caddy 2.11.6/plugin
`8a0df410a4734790dd34aa8b95097be2b7994381` build, not an asserted current VPS
deployment. Results apply to those exact binaries.

Run the external suites from this directory using the two retained binaries:

```bash
python3 scripts/test-interop.py --rust-server /path/to/network-relay \
  --caddy /path/to/caddy --results .build/interop.json
python3 scripts/test-interop.py --rust-server /path/to/network-relay \
  --caddy /path/to/caddy --test idle_stream_zero --results .build/idle.json
python3 scripts/test-interop.py --rust-server /path/to/network-relay \
  --caddy /path/to/caddy --test pooled_renewal --results .build/renewal.json
RELAY_NF_TEST_TRANSPORT=h3 python3 scripts/test-interop.py \
  --rust-server /path/to/network-relay --caddy /path/to/caddy \
  --test large_transfer --results .build/bulk-h3.json
```

Repeat the last command with `h2`; omit the selector to retain the full
HTTP/1.1/2/3 bulk suite and its known Caddy HTTP/1.1 failure assertion.

## Not established by these checks

There is no macOS SDK or Network.framework runtime in this environment. Native
GUI packaging, actual Apple cancellation/concurrency, sleep/wake and network
migration remain unexecuted. Portable tests and a green admission indicator do
not establish those results. Reliable UDP Capsules still have head-of-line
blocking; native DATAGRAM support, new authentication methods, Keychain, BIND
and additional platform support are outside this repair.
