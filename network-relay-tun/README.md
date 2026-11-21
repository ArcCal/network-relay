# Network Relay Tun

An independent macOS TUN client for existing Network Relay servers. A SwiftUI
application uses Network.framework for authenticated relay connections. An
unprivileged packet worker translates IPv4/IPv6 TCP and UDP into the application's
loopback SOCKS service. A narrowly scoped root helper owns utun, routes and
transient system DNS configuration.

The app, helper, dependency locks, tests and build are self-contained in this
directory. Building and running it requires no paid Apple developer account
or Network Extension entitlement.

A disposable Mac installed and updated the signed helper. System sockets
carried IPv4/IPv6 TCP, UDP and DNS through both Linux servers over H2 and
H3. All eight combinations restored the split routes, resolver and relay
endpoint bypass on stop. Physical handover and sleep/wake still need device
tests. [Validation record](docs/validation.md).

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
ad-hoc signs the finished application. The app and its versioned ZIP are in
`dist/`. Both root macOS build scripts also export the app and ZIP and include
them in `SHA256SUMS`. Building does not install privileged software
or change networking. Compilation caches remain inside this directory.

1. Enter the existing server's certificate domain, account and password. An
   optional server IPv4 or IPv6 address pins the endpoint. The certificate domain is
   retained for TLS validation. Choose a local SOCKS port not already in use.
2. Leave **Global TUN** enabled. Click **Install / Update Helper** and approve
   the local macOS administrator dialog. This installs only this product's
   root-owned daemon and packet worker. Both ship inside the app. The
   installer registers the daemon with launchd so the GUI can stay
   unprivileged. Repeat this step if the app reports a helper version
   mismatch. Ordinary connections use the installed helper.
3. Click Connect. Endpoint bypass and utun preparation precede native relay
   admission. IPv4/IPv6 capture routes and DNS activate only after admission.
4. Disconnect or Quit waits for network restoration before stopping the relay.
   **Recover Network** retries incomplete restoration. Failed work stays in a
   root-owned journal; subsequent captures remain blocked until recovery succeeds.

While connected, switch **Global TUN** in the main window or menu bar to
change modes. The app reconnects the relay, so existing connections can
briefly drop. Enabling capture checks the installed helper first. If that
check fails, the existing SOCKS session stays connected. Disconnect and
use **Install / Update Helper**, then try again. Disabling capture restores
this app's routes and DNS before starting the SOCKS-only session.

In the Log tab, `System capture: Capturing IPv4 and IPv6` confirms that the
helper activated capture for that run. `System capture: Off` on connection
means that only the SOCKS service started. At the Detailed level, a TCP
`SOCKS CONNECT ready` line includes `local_resource`. Match this ID and the
`run` ID to a native error to identify a failure on the local SOCKS socket.

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
- The worker admits at most 128 sessions and uses bounded packet queues. The
  ordinary UDP idle timeout is 120 seconds. At 112 active sessions an A, AAAA
  or HTTPS lookup that has received its matching reply and has been quiet for
  one second can give up its slot. Unanswered and overlapping DNS queries
  retain the ordinary timeout. Each SOCKS UDP association ends when its TCP
  control connection closes. A later packet can open a fresh association.
  At capacity new packets can still be dropped. The relay core also has its
  own admission limits.
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
