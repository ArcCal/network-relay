# Client response compatibility, 2026-10-14

Scope: Network Relay NF only, based on network-relay main
`0cb601a70f6b46846422af30ef60eed37444e0e3`. No server, RS, dependency, lockfile,
vendored library, deployment or QUIC option changes.

## Defects and minimal repair

- Classic CONNECT accepted only 200 instead of every 2xx (RFC 9110 §9.3.6).
  HTTP/1.1 needs a supported manual Hyper handoff because its automatic upgrade
  path treats 204 as no-content before recognizing the CONNECT tunnel. Buffered
  bytes are restored before reads; pending native write acknowledgements are
  drained with the existing timeout before application writes begin.
- CONNECT-UDP required the exact response value `Capsule-Protocol: ?1`, rejecting
  valid unknown parameters. RFC 9298 §3 defines Capsule framing for `connect-udp`;
  RFC 9297 §3.4 makes the field advisory. Removing that extra gate avoids adding
  a parser or dependency. Outgoing `?1`, Capsule decoding, HTTP/1.1 101/Upgrade,
  forbidden content headers, and the 204/205/206 Capsule restrictions remain.

The prior periodic HTTP/3 disconnect is user-confirmed resolved. Neither QUIC
stream creation nor the 60-second readiness renewal is changed by this patch.

## Executed portable checks

Linux x86_64, Rust 1.99.0. These checks exercise production Rust through synthetic
native events or test-only rustls/Quinn transports, not Network.framework.

- Full locked Core suite: **84 passed, 0 failed, 4 ignored**. The ignored cases
  require real servers, long-transfer fixtures, idle-stream fixtures or Kerberos.
- Five new integration tests pass: 93 controlled TLS response combinations,
  three unknown-parameter cases, six 512 KiB duplex handoffs with fragmented or
  coalesced HTTP-looking payload, four delayed-ACK/error cases, and six
  cancellation/drop/reset cases. Unit tests also check statuses 100 through 599.
- A fresh separate build of the unchanged base with the two controlled-response
  tests fails as expected: classic CONNECT 201 and an unknown Capsule-Protocol
  parameter are rejected. It uses a separate Cargo target to prevent cached
  patched artifacts from invalidating the comparison.
- Original real-server matrix passes against both unchanged Rust and Caddy
  binaries over HTTP/1.1, HTTP/2 and HTTP/3: exact 2 MiB TCP echo with half-close,
  UDP payloads from zero to 65,000 bytes, SOCKS TCP/UDP, credential and certificate
  rejection, UDP source pinning, fragment rejection and resource cleanup.
- Idle implicit QUIC stream 0 diagnostic passes against both binaries; no stream
  0 event is observed after thirteen seconds in these runs.
- An external 130-second HTTP/3 regression passes against each binary. It runs
  production `Client::monitor`, holds the original TCP and UDP flows through two
  60-second probe renewals, and completes 27 exact echo rounds with unchanged
  native resources and Quinn session identities. Each run reports three probe
  admissions, one ready status and zero failed statuses. This fixture reserves
  idle stream 0 and uses a 60-second QUIC idle timeout with 30-second keepalive;
  it still does not run Network.framework.
- Project all-target Clippy (`--no-deps`, warnings denied), formatting and
  `git diff --check` pass. Independent handoff review checked
  byte ordering, write acknowledgements, cancellation, leases and error handling.

Frozen server binaries used for the fresh matrices:

| Server | SHA-256 |
| --- | --- |
| Rust network-relay, version 1.5.0 | `a916de7037488e9a6c2f75d00ed5ef910787427c6e63f21d413c0ae198658878` |
| caddy-network-relay, source `8a0df410a4734790dd34aa8b95097be2b7994381` | `b309743bdc76c37330aada6b53f29afbf432ebcb34dbd18192af0fd2ea6a53e7` |

Repeat from this application directory:

```bash
cargo test --locked --manifest-path Core/Cargo.toml
python3 scripts/test-interop.py \
  --rust-server /absolute/path/to/network-relay \
  --caddy /absolute/path/to/caddy-with-network-relay \
  --results /tmp/relay-nf-response-matrix.json
python3 scripts/test-interop.py \
  --rust-server /absolute/path/to/network-relay \
  --caddy /absolute/path/to/caddy-with-network-relay \
  --test idle_stream_zero --results /tmp/relay-nf-idle-stream-zero.json
```

## Limits and deferred observations

The intermittent NF/Caddy HTTP/1.1 target-reset-to-EOF observation has no confirmed
client root cause. A frozen reset trace preserved ECONNRESET through the client;
TLS close-notify may precede a later raw reset. Do not classify all clean EOF as
failure or claim this response fix repairs that observation. HTTP/2 and HTTP/3
reset checks previously passed.

The root Rust CLI self-check's 404-versus-Caddy-405 expectation is deferred; the
server/root project is outside this client-only patch. It does not invalidate
successful target data forwarding in the independent matrices.

No Apple SDK/runtime is available here. Full SwiftUI build, linking, signing and
native Network.framework-to-server retesting must run on the Mac using
`bash build-macos.sh`. Portable passes do not guarantee native stability or
complete the application's full acceptance matrix.
