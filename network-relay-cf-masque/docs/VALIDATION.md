# Validation record

Fixtures use ephemeral keys and a local synthetic WARP peer; no live
Cloudflare account or real enrollment is used. Tests write their evidence to
`target/evidence` (not tracked). Earlier records about the removed private
copy of the relay are not retained: they described different code.

## Current results (2026-10-31 UTC)

Run on Linux x86_64 (no IPv6 in the container), Rust 1.97.

| Check | Result |
| --- | --- |
| `scripts/test.sh`: this workspace's tests (`--test-threads=1`) | Passed; 2 long tests ignored and run separately below |
| NF and RS client cores of this repository, 3 ingress x 2 WARP modes | Passed: 12 pairs, 96 TCP/UDP checks, wrong password and TLS name refused |
| Six ingress/WARP pairings: functional, 64 MiB transfers with hash and half-close, HTTP file streaming, UDP MTU drops, idle keepalive, resets and revocation | Passed |
| CLI: one file, `--check`, IPv6 warning, missing `[warp]` and legacy options refused, SIGHUP reload, WARP loss ends the process and closes the listener | Passed |
| Strict Clippy, formatting, `examples/reuse` | Passed |
| network-relay's tests (`cargo test`, 163 unit + 72 integration) | Passed |
| network-relay's integration suite with every tunnel through an egress (`NETWORK_RELAY_TEST_EGRESS=loopback`) | Passed: 72 |
| network-relay's vendored h3 suite (its `[::]` binds changed to IPv4 in a scratch copy, as the container has no IPv6) | Passed: 260 tests and 9 doctests |
| network-relay's quic-go/masque-go and curl interoperability, deployment tests | Passed |
| `diagnose_h3_bulk_with_persistent_pairings`: 16 rounds per WARP mode, 32 HTTP/3 transfers of 64 MiB with six TCP and six UDP flows held | Passed in 323.5 s |
| `scripts/soak.sh`: finite tests, then 3900 s with six TCP and six UDP flows held over both WARP modes | Passed and independently verified: 3919 s measured, 131 samples, every flow at least 3910 s old with at least 393 pings, one outer generation per mode, no packet or queue drops, RSS 120-131 MiB, 40-43 file descriptors |

### The earlier H3 timeout

The removed version once failed a soak with an HTTP/3 `Connection error:
Timeout` during periodic H3 bulk work, never explained. That version kept an
older copy of network-relay's server, from before network-relay's fix
"Keep stalled tunnels from exhausting connection flow control": a
connection's receive window then held only two stream windows, so tunnels
whose destination stopped reading could leave a connection without credit,
and with no packets in flight QUIC's idle timeout fires. This project now
runs network-relay's current server, with that fix. The H3 bulk diagnostic
and the soak above, which repeats periodic H3 bulk work through the hour,
both passed; the timeout did not recur.

## Reproduction

```bash
bash scripts/test.sh
bash scripts/soak.sh
```

## Outstanding deployment gates

On a machine with authorized WARP connectivity, first run the `live-warp`
probe separately with explicit H2 and H3. It must return `warp=on/plus`, a
valid exit IP, tunneled DNS and UDP evidence. Then run the relay with its
ordinary certificate and credentials and test the clients over each chosen
ingress mode. Earlier live attempts (2026-10-14) failed during WARP setup:
numeric H2 returned `Connection refused` and H3 setup timed out; they reached
neither account acceptance nor an exit-IP check.

Use the live download helper with an independently verified checksum for an
artifact of at least 64 MiB, and complete an hour-plus run with held TCP/UDP
connections. Monitor memory, descriptors, socket/task counts, packet drops
and terminal reasons. Native Apple device/profile trust, mobility and
Network.framework behavior must be exercised on those devices.
