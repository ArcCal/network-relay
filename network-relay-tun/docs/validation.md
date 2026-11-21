# Validation record

## November 21, 2026

The previous signed GUI kept its Global TUN checkbox disabled after a
working SOCKS connection to a Linux H2 relay. With the repaired app, the
same checkbox accepted a click. Without an installed helper, the app showed
installation guidance and the original SOCKS service still delivered a
4096-byte HTTPS response. With the helper installed, two successive
SOCKS-to-TUN-to-SOCKS cycles used a real utun route and restored the
original route and DNS after each cycle. HTTPS through SOCKS succeeded in
each mode. [Original GUI](https://github.com/ArcCal/caddy-network-relay/actions/runs/44867403634/job/136734041928).
[Signed switch and restoration test](https://github.com/ArcCal/caddy-network-relay/actions/runs/44868125189).

On macOS 27 the signed release app displayed a connection failure when the
helper was missing. The process and window remained alive through the
eight-second observation. The same build passed helper installation, capture
and rollback. A separate interoperability matrix exercised the TUN controller
in SOCKS mode against both Linux servers on x86-64 and arm64 over H2 and H3.
The original exit on Connect has no crash report linking it to a particular
fault. [Signed app and helper](https://github.com/ArcCal/caddy-network-relay/actions/runs/44851313443).
[Native client and Linux server matrix](https://github.com/ArcCal/caddy-network-relay/actions/runs/44850970737).

## November 20, 2026

The macOS 27 package passed 74 Swift tests. A real helper update and repeated
captures preserved the physical service while TUN installed its own split
routes and DNS. Across eight backend/transport/Linux architecture combinations,
ordinary system sockets completed 48 TCP exchanges, 144 UDP echoes and 24 DNS
questions. All eight restored the resolver, split routes and endpoint bypass.
Hardware sleep/wake, physical network transitions and WAN throughput remain
unmeasured. [Package tests](../../docs/performance-alternatives-2026-11-20.md#native-nf-and-tun-ui-log-retention) and [system-wide capture and restoration](../../docs/audit-2026-11-20.md#system-wide-tun-checks-against-linux).

## Earlier helper and packet tests

The portable suite ran on Linux with Rust 1.99.1. The native suite ran on
Apple Silicon, macOS 27.0.1, Xcode 27.1 and Swift 6.4. The disposable Mac
installed the real helper and tested network changes. The application and its
build remain independent. [Native acceptance run](https://github.com/ArcCal/network-relay/actions/runs/44746108048).

| Check | Result |
| --- | --- |
| Independent relay core | 115 ordinary tests passed. All four external-fixture cases also passed against Linux relay binaries. |
| Host ownership, rollback, IPC and boot recovery | 50 tests passed |
| Engine wrapper | 1 test passed |
| Fragment reassembly | 3 tests passed |
| TCP packet path | 1 test passed, covering TCP/443, TCP/53 and combined data/FIN |
| UDP packet path | 7 tests passed, covering IPv4/IPv6, empty/large replies, target checks, DNS ports and out-of-order fragments |
| Vendored adapter | 21 inherited library tests passed |
| Vendored IP stack | 61 tests passed, including queue saturation and checksum rejection |
| Isolation checks | 4 checks passed |
| macOS Rust helper/worker | Linked, signed and executed on an Apple Silicon Mac |
| Swift GUI/model build | Production build and 73 Swift tests passed on the Mac runner |
| Application bundle signing | Both nested helpers and the finished application passed strict signature verification |
| Privileged installation and real utun | Installed and updated the daemon, authenticated IPC and ran the packet worker. IPv4 and IPv6 TCP, UDP, DNS, relay bypass and route/DNS restoration passed twice. Uninstallation removed the service and its owned files. |
| Physical network and hardware | Roaming, sleep/wake, production WAN throughput and an IPv6-only physical uplink require field measurements. |

The first full-core run failed during rustdoc dependency loading while another
Cargo graph was replacing artifacts in the same target directory. A sequential
rerun passed. The final portable test script deliberately runs graphs sequentially.

An inherited HTTP/3 frame test intermittently accepted a previous case's retry
connection before sending its test frames. Each case now has a fresh listener
and awaits cancellation of its opening task. Ten consecutive targeted runs and
the subsequent full portable script passed.

The packet-level and native capture tests use a loopback SOCKS echo fixture.
The separate core interoperability tests use two real Linux relay servers. TCP/53 exercises
transparent TCP forwarding rather than recursive DNS service behavior. IPv6
packet tests use a real IPv6 IP header/checksum over an IPv4 loopback SOCKS
association. Portable success does not establish IPv6-only uplink support.

Regression evidence includes a failing packet-level half-close test before the
TCP fix and a passing test afterward. The earlier 8192-to-4096 UDP truncation was
also reproduced before repair. Tests assert complete payloads and route ownership,
not just absence of exceptions. There is no claim of exhaustive absence of bugs
or verified production throughput.

Run `scripts/test-portable.sh` to reproduce the portable checks. Build and native
acceptance instructions are in README.md and macos-acceptance.md. Development
logs are retained locally under the ignored `.validation/` directory.

The supplied Mac log after commit 9bba0ad confirms that the NativeError visibility
fix allowed Swift compilation and all 71 model tests to pass. Strict bundle
verification then rejected uninstall-helper.sh in Contents/Helpers. Shell scripts
now live in Contents/Resources and are sealed by the outer bundle signature;
Helpers retains only the separately signed native binaries. The GUI installer
path and installer's sibling-binary lookup follow that layout. The current native run verified that layout. It also reproduced a separate
launchd race after a successful capture. The installer and uninstaller now
wait for service removal before replacing or deleting helper files. The
regression run tested an update, a second capture and a clean uninstall.
[Apple code signing guidance](https://developer.apple.com/library/archive/technotes/tn2206/_index.html).
