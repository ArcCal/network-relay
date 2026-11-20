# macOS acceptance

Run these field checks with a real Mac and a reachable Linux Network Relay
server. The native CI counterpart covers codesigning, installed helper IPC,
global capture with a controlled SOCKS peer, update and cleanup.
[Native validation record](validation.md). Keep a local
terminal available. Do not use a remote-only administration connection to test
route changes. Retain logs locally; configuration and network snapshots can
contain private information.

## Build and baseline

1. Run `./build-macos.sh` from this directory as a regular user. Require success
   from Rust tests, Swift tests, Swift release build and codesign verification.
2. Record macOS/Xcode versions, server revision and selected transport. Save
   `netstat -rn -f inet`, `netstat -rn -f inet6`, `scutil --dns`,
   `scutil --nwi` and `route -n get default` before connecting. Record other VPNs.
3. Open the bundle, enter a test account, and use a vacant loopback SOCKS port.
   Verify that NF's configuration, running process and app bundle remain unchanged.
4. Install the helper with its GUI button. Administrator authorization is expected
   once for installation, not on each connection. Confirm the helper runs as root
   and the packet worker runs as the installing user. Do not change server policy
   to accommodate a failed client test.

## Connectivity and restoration

1. Connect in H2 first, then repeat in H3 and Automatic. Require Prepared before
   capture, relay admission before Connected, and an assigned utun interface.
2. Inspect routes. An IPv4 relay must retain its physical bypass. An IPv6 relay
   must use the physical interface selected before capture, including on an
   IPv6-only uplink. Check both split-default routes for each family.
   Document any LAN/scoped/more-specific exclusions instead of calling them leaks
   fixed by this implementation.
3. Resolve public A and AAAA records with system APIs, explicit UDP DNS and TCP
   DNS. Test a large DNS response and fallback. Verify through relay-side counters
   or destination logs that traffic reached the server. A successful local SOCKS
   test alone is insufficient.
4. Fetch HTTPS over IPv4 and IPv6. Compare checksums on uploads and downloads of
   at least 64 MiB. Exercise simultaneous flows, slow readers, client half-close,
   remote resets and an application closing mid-transfer.
5. Use a known QUIC-capable client to force HTTP/3 to a controlled destination.
   Verify transport selection; a browser silently falling back to H2 is not proof
   of UDP/QUIC support. Check zero-length UDP and payloads around 1200, 1472, 4096
   and 8192 bytes with controlled echo endpoints. Verify entire payloads, not only
   byte counts. Capture fragment/PMTU behavior and native utun write errors.
6. Disconnect, then compare routes and DNS with the baseline. Existing foreign
   entries must survive. Repeat Connect/Disconnect and Quit during connection
   setup. No packet worker should remain after successful cleanup.

## Failures and switching

- Reject credentials, block the relay port, and use an unavailable endpoint.
  Capture must not activate before relay readiness. Prepared bypasses must be
  removed after cancellation or failure.
- Switch Wi-Fi/Ethernet, change Wi-Fi networks, remove the default route and
  sleep/wake. Confirm endpoint bypass updates, bounded retries and eventual
  restoration or a clear Recovery Required state.
- Force-quit the GUI, terminate the worker, and restart the helper separately.
  Confirm root recovery, worker parent-pipe cancellation and retained journal on
  cleanup failure. Repeat after a reboot; prior boot state must not remove a
  new owner's routes with a reused utun name.
- Start a second application instance or another VPN and confirm that ownership
  checks refuse conflicting capture without deleting the other owner's routes.
- Restore the network, quit the app and run the bundled uninstaller. Require
  successful helper removal and unchanged application settings and NF files.

## Performance comparison

Measure direct baseline, relay SOCKS-only, and Global TUN separately against the
same controlled destination. For each forced transport record median/tail latency,
throughput, CPU/RSS, packet loss, retransmissions and concurrent-flow counts. Use
multiple runs and identical payloads. Warm and cold connection results must be
separate. Existing native H3 stalls or H2 UDP issues must be reproduced and
attributed before claiming they are resolved by this independent client.

Do not mark native acceptance complete until these results are recorded. Portable
mocks and cross-target type checking do not replace these tests.
