# Executed interoperability evidence

`interop-results.json` records the actual executed production Rust client,
production Tokio/rustls/Quinn transport, server binary fingerprints, source
fingerprints, lockfile, platform and captured results. A test transport emulator
is not used. The fixture creates disposable local accounts, certificates and
TCP/UDP echo services.

`app-smoke-results.json` separately records the final application rebuild
following two logging-control corrections: live log-level changes now use a
dynamic filter, and headless output applies the GUI's selected visibility rule.
Its app source and binary fingerprints differ from the preserved stability run;
its protocol core, HTTP/3 sources, tests, manifests and lockfile fingerprints
are identical. The 125-second evidence is not relabeled as a soak of the later
app binary.

The final application again passed both protocol matrices, real automatic
fallback and all nine headless app cases. Every positive app case enables
Everything logging, requires TRACE I/O request/read metadata and rejects
plaintext fixture-password or Basic-token exposure. Six additional Errors-only
app cases verify that healthy sessions hide INFO/WARN/DEBUG/TRACE, and that wrong
credentials produce an ERROR and nonzero exit without exposing credentials.

The final run passed against these unmodified real server builds:

| Server | Source revision | Version | Binary SHA-256 |
| --- | --- | --- | --- |
| Rust network-relay | `a8cc0e8f3b3949de83634f52ff422c41cb87615d` | 1.5.0 | `e93c28942bf2a634e498b2f1ae14623a870c4670bfd1b95e7322ca425104defe` |
| caddy-network-relay | `ef245375aa67eecde830a5bcd5044b34cca52c4d` | Caddy 2.11.6, Go 1.26.8 | `dbf473abe26ccc838e3260a4f49ead4a48b81ce4750c1de0f0eb9d4ebc297787` |

Each server passed HTTP/1.1, HTTP/2, HTTP/3 and automatic mode. The core matrix
checks remote-name TCP CONNECT, 2 MiB binary duplex traffic and client write
half-close; UDP Capsules of 0, 1, 1,200, 32,768 and 65,000 bytes; bad-password,
certificate-name and untrusted-CA rejection; blocked-port HTTP 403 handling;
SOCKS TCP and UDP; sender pinning, fragment rejection and cancellation cleanup.
Automatic mode selects available HTTP/3 in this matrix.

Each pairing also passed a 125-second HTTP/3 observation with persistent TCP
and UDP flows, traffic every five seconds, and an independently idle readiness
probe crossing two planned renewals. No reconnect status occurred and all
production transport resources were released. Observed durations were 125.311
seconds with Rust and 125.251 seconds with Caddy.

A separate Caddy fixture enables HTTP/1.1 and HTTP/2 while disabling HTTP/3.
The production client's real QUIC attempt fails, automatic mode selects HTTP/2,
and both TCP and a 65,000-byte UDP Capsule succeed. The actual headless app also
passes this fallback, rather than relying only on a direct core test.

Nine headless app checks cover configuration import, SOCKS listeners, 1 MiB
SOCKS TCP half-close, remote-name SOCKS UDP and clean Control-C shutdown: four
transport choices per server, plus automatic fallback against TCP-only Caddy.

## Boundaries

Execution used Linux x86_64 and local server fixtures. These results do not
claim a native macOS GUI launch, macOS ARM64 runtime, a ten-minute remote
stability test, explicit IPv6-literal/scoped-address coverage, or reverse
TCP half-close coverage. Both server revisions and the tested app binary are
fingerprinted in the JSON artifact. A dirty development revision is identified
as such; the production core source fingerprint provides exact input evidence.

Caddy's fixture uses the deployed baseline, without the unmerged first-byte
HTTP/3 header-deadline change. Fixture destination restrictions permit local
echo services and are not installation defaults.
