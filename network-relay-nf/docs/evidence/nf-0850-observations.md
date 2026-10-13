# Original Masque NF observations, 08:50–08:53 UTC

Uploaded on 2026-10-11. This is evidence from **Masque NF**, not a run of
Network Relay NF. [Original-file provenance](nf-0850-provenance.json) records
347,542 bytes, 3,516 lines and SHA-256
`e9e52f5f03efd89e4e420708a5d5ff66688139720e33809a76547859c479b8d1`.
[Filtered verbatim excerpts](nf-0850-transport-excerpts.log) omit application
destinations, credentials, full headers and payload.

## Complete HTTP/3 failures

For display name `masque-vpn`, run `1AC94CBF` reaches native QUIC readiness and
receives peer control/QPACK bytes. It then waits for a request response:

| Attempt | Capsule selection | Request bridge resource / local write | Natural response timeout |
| --- | --- | --- | --- |
| First | `08:52:00.356828` | 48 / 120 bytes, then READ | `08:52:10.593018` |
| Second | `08:52:13.367081` | 133 / 120 bytes, then READ | `08:52:23.602864` |

Neither request records received response bytes. There is no H3 tunnel up.
The first attempt also exchanges outgoing resources 37/38/39 (31/1/1 bytes)
and incoming 43/44/45 (31/1/1 bytes), plus resource 46 (23 bytes, final=true).
These lengths are consistent with control/QPACK/GREASE behavior in the original
h3 implementation; they do not identify actual stream IDs or server parsing.
An extra OPEN on resource 47 without WRITE does not establish idle bidi SID 0.

Switching to HTTP/2 at `08:52:27` produces tunnel up at `08:52:28.680049`
(`7B10D991`). Other H1/H2 runs also establish `10.89.0.100/32`, 8 routes.
This upload supplies the natural-timeout evidence missing from the shorter
08:02 UI samples. It reinforces the unresolved response-stage failure and does
not prove its cause. Manual switching does not validate Automatic fallback.

## Separate Caddy profile connection problem

The display name `caddy-masuqe` is reproduced exactly, including its spelling.
HTTP/2 run `E4F71A52` opens native TLS at `08:50:47`, then reports `timed out`
at `08:50:57.747598` without a TLS ready event or any outer-stream application
write. Other H1/H2/H3 attempts are interrupted by settings or Disconnect.
No TLS/QUIC ready or tunnel up appears for this display name in the upload.

This is an earlier connection-stage problem even on TCP. Possible causes include
the profile's endpoint, service listener, routing/firewall or handshake/trust
configuration; the log does not distinguish them. It must not be presented as
proof that QUIC is the sole Caddy failure or that a Network.framework defect
causes both profiles to fail.

## Still missing

The launch line contains no source/build/binary identity. The display names are
not measured public IPs; this log does not reconfirm the earlier domain/IP/server
answers. Actual native metadata SIDs, direction/initiator, parent ownership and
synchronized server accept/header-parse events are absent. Successful H1/H2
tunnel setup is not a complete Internet/SOCKS acceptance test. The new relay
client's Apple transport and compatibility matrix remain untested.
