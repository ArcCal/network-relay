# Relay servers and the idle group-owned QUIC stream 0

Date: 2026-10-11. Times are UTC. This document separates observation, source
and documentation findings, portable emulator measurements, and open Mac
questions. **No Network.framework code ran here, and the post-admission EINVAL
is not claimed repaired.**

## Question

Native HTTP/3 admission succeeds, then the session fails with POSIX 22 /
EINVAL 10.002560 seconds after readiness
([field evidence](native-http3-20261011-1202.md), binary `666b795`). What does
each relay server do around ten seconds after admission?

## Established from documentation and source

1. **The group owns client bidirectional stream 0 and exposes no I/O on it.**
   Apple DTS: a QUIC `NWConnectionGroup` "owns" stream ID 0 and "you can't
   access it at all"; a group `send` opens a new stream
   ([Apple Developer Forums 750808](https://developer.apple.com/forums/thread/750808)).
   Network Realy NF uses `NWConnectionGroup(with: NWMultiplexGroup(to:))` and
   `extract`, and the field log shows the request on **actual SID 4**. Under
   RFC 9000 §3.2, using stream 4 implicitly opens stream 0 at the server.
2. **Rust network-relay rejects that idle stream after ten seconds.**
   `src/server/over_h3.rs` resolves each accepted stream concurrently with
   `resolve_request_before(sleep(HEADER_TIMEOUT))`, where `HEADER_TIMEOUT` is
   10 s. On expiry, `vendor/h3/src/server/request.rs` sends STOP_SENDING and
   RESET_STREAM with `H3_REQUEST_REJECTED` (0x10B). The request on stream 4 is
   not blocked. Read-only source at `4f40c1f`.
3. **caddy-network-relay does the same with a different code.** `app.go` sets
   `http3.Server.ReadHeaderTimeout` to 10 s by default. Its quic-go fork
   (`third_party/quic-go/http3/server_conn.go`, `handleRequestStream`) sets a
   read deadline on every request stream. On expiry it cancels both directions
   with `H3_REQUEST_INCOMPLETE` (0x10D). Read-only source at `ef24537`.
4. For contrast, caddy-masque sets no header deadline, and the Rust
   masque-server blocks on the idle stream. That is the Masque NF
   initial-timeout case, recorded in the masque-vpn repository. It is a
   different server reaction, not the same failure.

## Measured with the portable emulator

The test backend's new opt-in mode opens client bidirectional stream 0 after
the QUIC handshake and holds both halves without writing, finishing or
stopping them. The production request therefore uses stream 4. Test:
`Core/tests/idle_stream_zero.rs::idle_group_stream_zero` (ignored; it needs the
fixture from `scripts/test-interop.py`). It admits CONNECT-UDP, echoes a UDP
payload, waits 13 s, echoes again, and prints what the peer did to stream 0.

Run 2026-10-11T14:01:36Z on Linux 6.18 with rustc 1.97.0, loopback, real
server binaries, and the client Core tree digest
`6689a9a0552ba5508f0eba3ff35cea4a5467a6609e8742cddaf1bb03935b86ea`:

| Server | Binary SHA-256 | Stream 0, time after QUIC ready | Stream 4 session |
| --- | --- | --- | --- |
| network-relay `4f40c1f`, release build | `5b1bb411…2e031a26` | STOP_SENDING and RESET_STREAM 267 (0x10B, H3_REQUEST_REJECTED) at 10.013 s | UDP echo still works at 13 s on Quinn |
| caddy-network-relay `ef24537`, Go 1.26.8, `-tags http2legacy` | `9e7a4237…b486435dc` | RESET_STREAM and STOP_SENDING 269 (0x10D, H3_REQUEST_INCOMPLETE) at 10.016 s | UDP echo still works at 13 s on Quinn |

In the same run, the unchanged `real_server_matrix` passed against both
servers over HTTP/1.1, HTTP/2 and HTTP/3: 2 MiB TCP half-close, UDP Capsules
from 0 to 65,000 bytes, wrong-password and certificate-name rejection, SOCKS
CONNECT and UDP, source pinning, fragment drop and resource cleanup. The full
Core suite (`cargo test --locked`) passed: 37 unit, 5 and 21 integration
tests. Environment limit: the container has no IPv6, so a scratch copy of the
fixture runner bound the UDP echo to IPv4. The repository script is unchanged.

## Interpretation

- **Established (source plus emulator):** both relay servers send a stream
  reset and STOP_SENDING for the implicitly opened, idle stream 0 about ten
  seconds after the first request. Both behaviors are permitted by RFC 9114
  §4.1.1 and §8.1. Neither server closes the connection, and Quinn clients
  continue normally.
- **Consistent, not verified:** Network.framework may surface a peer
  STOP_SENDING or RESET_STREAM on the stream its group owns as a failure of the
  group, which the bridge reports as EINVAL on every child. The field failure
  at 10.002560 s after readiness agrees with the ten-second server timer to
  within milliseconds. No native trace shows which object failed first, and
  Apple documents no such behavior.
- The HTTP/2 closures near 300 s remain a separate case. They fit UDP idle
  policy and are unrelated to stream 0.

## Repair options and why none was applied here

| Option | Assessment |
| --- | --- |
| Servers leave an idle stream without HEADERS alone until the connection idles, or do not reset streams the client never wrote | Avoids the event. Both servers are outside this task's modification boundary, so neither was changed. It also weakens their protection against stalled requests, so it is a server design decision. |
| Own stream 0 with a QUIC `NWConnection` and send the first request on it | Apple documents stream-0 I/O only for `NWConnection`. Receiving server-initiated control and QPACK streams without a group is undocumented. Not implemented without a Mac. |
| `NetworkConnection<QUIC>` (macOS 26+) | A bounded Mac experiment only; its stream-0 behavior is undocumented for this case. |
| Ignore a group failure while child streams still work | Unknown whether the children survive; it could mask a real connection loss. Rejected without native evidence. |
| Longer timeouts or keepalive | Unrelated to a ten-second server header deadline. Rejected. |

## Change made in this task (diagnostics only)

`App/Sources/NetworkRealyNF/NativeClient.swift`:

- logs `Native QUIC group ready resource=<id> groupSID=<sid>` at Detailed;
- logs a QUIC **group** failure (`Resource <id> failed: …`) at WARN instead of
  DEBUG. The 12:02:59Z failure was recorded before Detailed logging was
  enabled, so it never said whether the group or a stream failed first.
  Stream-level failures stay at DEBUG.

There is no Swift toolchain here, so this was not compiled.

## Next Mac evidence needed

Use a build of this branch and keep the log level at Normal or higher. Force
HTTP/3 to the Rust relay and connect a CONNECT-UDP flow; then repeat with
caddy-network-relay.

1. Record whether a WARN `Resource <group> failed: … EINVAL` appears about ten
   seconds after the `HTTP/3 request HEADERS sent … sid=4` line, and before any
   stream failure.
2. On the server, at debug level, record the unusable-request event for stream
   0. The Rust relay logs `unusable HTTP/3 request` for late headers.
3. Control: the same flow over HTTP/2 must stay up past ten seconds.

If the group fails right after the server rejects stream 0, the mechanism is
confirmed. The remaining fix then lies in server stream-0 handling or in a
stream-0-owning native API, and both need native acceptance.
