# Network Relay Tun

An independent macOS TUN client for existing Network Relay servers. A SwiftUI
application uses Network.framework for authenticated relay connections. An
unprivileged packet worker translates IPv4/IPv6 TCP and UDP into the application's
loopback SOCKS service. A narrowly scoped root helper owns utun, routes and
transient system DNS configuration.

All source, vendored code, dependency locks, tests and build outputs belong to
this directory. NF, RS, the servers and repository-wide build files are unchanged.
No paid Apple developer account or Network Extension entitlement is required.

On macOS 27.0.1, revision `e6e4eb6` passed 71 Swift tests, strict app and
helper signature verification, authenticated helper installation, utun worker
startup and restoration after preparation. See the [validation record](docs/validation.md)
for results and the remaining device and network-switching checks.

## Build and run

Requirements: Apple Silicon, macOS 27+, Xcode with macOS SDK 27+, Rust/Cargo,
Python 3 and Internet access for locked dependencies. Run as your regular user:

```sh
cd network-relay-tun
./build-macos.sh
open "dist/Network Relay Tun.app"
```

The standalone script runs Rust tests, portable isolation checks and Swift model
tests, builds all three Rust components and the GUI, bundles the helpers, and
ad-hoc signs the finished application. It does not install privileged software
or change networking. Compilation caches remain inside this directory.

1. Enter the existing server's certificate domain, account and password. An
   optional server IPv4 or IPv6 address pins the endpoint. The certificate domain is
   retained for TLS validation. Choose a local SOCKS port not already in use.
2. Leave **Global TUN** enabled. Click **Install / Update Helper** and approve
   the local macOS administrator dialog. This installs only this product's
   root-owned daemon and packet worker.
3. Click Connect. Endpoint bypass and utun preparation precede native relay
   admission. IPv4/IPv6 capture routes and DNS activate only after admission.
4. Disconnect or Quit waits for network restoration before stopping the relay.
   **Recover Network** retries incomplete restoration. Failed work stays in a
   root-owned journal; subsequent captures remain blocked until recovery succeeds.

With Global TUN disabled, the same application provides its local SOCKS service
without requiring the helper. There is no routing rule engine or forced kill
switch. Loss of the control connection causes capture restoration; a helper
restart also attempts recovery. A failed restoration is shown rather than
silently reported as success.

## Traffic and boundaries

- Captured TCP uses CONNECT; UDP uses CONNECT-UDP through the copied NF core.
  HTTPS and QUIC are ordinary TCP/UDP traffic. DNS UDP and TCP follow the same
  relay path; no fake-IP mapping is used. Transient resolvers are 1.1.1.1 and
  8.8.8.8. DNS queries made to private UDP DNS addresses are redirected by the
  selected adapter to its remote resolver through SOCKS.
- The client resolves the relay before capture and tries usable IPv4 and IPv6
  addresses in resolver order within each family. IPv4 uses a physical bypass
  route. For an IPv6 relay the client binds its outer connection to the physical
  interface chosen by the kernel. Each attempt retains the configured TLS name.
  A failed attempt must finish restoration before the next address is tried.
- Capture installs IPv4 and IPv6 split-default routes. macOS loopback, multicast,
  interface-scoped traffic and existing more-specific routes can take precedence.
  In particular, connected LAN routes and other VPN routes are not forcibly
  replaced. This is broad system capture, not a guarantee that every macOS
  packet traverses the relay, and not an enforced leak-prevention product.
- Only captured TCP/UDP are forwarded. Other IP protocols, including ICMP, are
  dropped. IP fragmentation is reassembled with bounded contexts and overlap
  rejection. IPsec and protocols requiring raw IP forwarding are unsupported.
- Capture MTU is 1500. UDP preserves empty and large datagrams within protocol
  and local SOCKS transport limits. Actual oversized utun injection and PMTU
  behavior still require native acceptance. Do not infer these from jumbo-MTU
  portable tests.
- The worker admits at most 128 sessions, uses bounded packet queues and expires
  idle UDP sessions. Overload drops whole IP packets rather than growing queues
  indefinitely; TCP can retransmit. The relay core has additional admission limits.
- Bootstrap DNS resolution occurs before capture. Relay IP bypass prevents the
  outer connection from re-entering TUN. Credentials stay in the unprivileged
  application; helper requests contain only validated network plans and leases.

## Tests

```sh
./scripts/test-portable.sh
```

The tests use loopback sockets and in-memory packet devices, never privileged
route/DNS operations. The inherited real-server interoperability tests are
explicitly ignored unless their external fixture is configured; they are not
counted as passes. See [validation](docs/validation.md) for measured results and
[macOS acceptance](docs/macos-acceptance.md) for native verification.

## Uninstall the helper

Disconnect, use Recover Network if needed, and quit the application. Then:

```sh
sudo /bin/bash "dist/Network Relay Tun.app/Contents/Resources/uninstall-helper.sh"
```

The uninstaller refuses to remove recovery resources while a journal remains.
It preserves application settings. Deleting the app bundle alone does not remove
its installed helper. Never delete a recovery journal to bypass an error.

See [implementation review](docs/implementation-review.md) and [source notices](NOTICE.md).
