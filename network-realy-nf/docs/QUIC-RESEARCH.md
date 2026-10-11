# Native QUIC research and handover

Date: 2026-10-11. This report separates observed failures, supported mechanisms,
unproven hypotheses and this new client's implementation choices. It does not
assert that Network.framework has an unavoidable defect.

## New relay application observation

The user has now built and launched Network Realy NF source
`666b795c881b44eeaade9891edfae04ffcbd34a6` on a Mac and reported successful SOCKS
TCP forwarding to Google and UDP DNS forwarding through Rust network-relay.
Earlier HTTP/2 404 responses coincided with explicit server authentication
failures; those failures do not identify a native transport defect. The successful
terminal probes lack a current application run/transport line, and curl's
`HTTP/2 200` describes Google's response protocol. These results establish a
reported native TCP/UDP forwarding success, but no new HTTP/3 result or controlled
QUIC diagnosis. [Evidence and remaining scope](evidence/native-mac-20261011.md).

## Confirmed historical observations

The user reported macOS 27.0.1, build 26A434, on a Mac mini. Masque NF and Masque
Swift both had HTTP/3 problems; HTTP/2 worked. The server was Rust masque-server
at `masque.kitendesecschool.com / 34.4.108.158`. These clients used CONNECT-IP,
whereas Network Realy NF uses CONNECT/CONNECT-UDP and different relay servers.

Masque NF run `2A09D400`, 2026-10-11 06:35 UTC, completed native QUIC readiness,
received peer HTTP/3 control/QPACK bytes and wrote 120 bytes on local request
resource 16. It then received no response before the ten-second deadline.
Resources 35/78/161 repeated the sequence. Local resources 15/16 are bridge
handles, **not** actual QUIC stream IDs. The extra stream could have been a
unidirectional GREASE stream; its existence does not prove an idle bidi stream 0.

Later new-UI logs at 08:02–08:03 showed working H1/H2 and H3 QUIC readiness plus
Capsule selection, but no H3 tunnel establishment. The user explicitly confirmed
that H3 still failed. Settings changes cancelled those samples before the natural
response deadline, limiting phase diagnosis; this does not make the failure
unconfirmed or justify blaming the user's waiting time.

The newest 08:50–08:53 UTC log now contains two natural response timeouts in
`1AC94CBF` for the display name `masque-vpn`. The first attempt selected Capsules
at `08:52:00.356828`, exchanged 31/1/1-byte control/QPACK streams, wrote 120 bytes
on request resource 48, then timed out at `08:52:10.593018`. Request resource 133
repeated this and timed out at `08:52:23.602864`. Switching to H2 produced tunnel
up at `08:52:28.680049` (`7B10D991`). These are complete response-stage failures,
not merely samples cancelled by settings. Actual SIDs, binary identity, endpoint
and server-side parsing remain absent; do not silently identify this display name
as the earlier confirmed public endpoint.

The same upload shows `caddy-masuqe` H2 (`E4F71A52`) timing out before any TLS
ready event. Several other H1/H2/H3 attempts on that profile were cancelled.
No TLS/QUIC ready or tunnel up is recorded for it. Investigate that profile's
endpoint, listener, reachability and trust independently; the log does not prove
a QUIC-specific framework failure on Caddy. Sanitized excerpts and original-file
hash are in [the latest evidence](evidence/nf-0850-observations.md).

An earlier apple/Caddy public-IP mismatch (`34.3.100.106` versus the VPS's actual
`34.3.104.75`) was a separate incident. Earlier apple H3 run `0726844B` had
negotiated Capsules and carried packets. That historical success disproves an
absolute “Apple QUIC can never work” claim, but does not establish current native
compatibility. Swift's HTTP/2 POSIX 49 error recovered approximately one second
later and is not direct evidence of the H3 response timeout's cause.

Detailed original study and archived source/log evidence:
[Masque NF research at its recorded source revision](https://github.com/ArcCal/masque-vpn/tree/d57ffa064bf444aa742691b58ad7ab4fd49173ee/docs/research/network-framework-http3).
This link is historical context; the new application neither imports nor changes
that implementation.

## Completed attempts and their limits

1. User native tests established H1/H2 success and H3 failure on the Rust target;
   detailed logs narrowed NF failure to waiting for response after local HEADERS.
   Actual SIDs and synchronized server request-accept traces were not captured.
2. A Linux test of the unchanged Rust masque-server with NF core and a controlled
   Quinn host allocated idle bidi 0 before request 4. It produced a response
   timeout at 10.016906678 seconds. Request 0 before idle 4 connected in
   3.590117499 seconds and passed TCP/UDP/DNS/IPv4/IPv6/large-packet/half-close
   checks. This proves a sufficient blocking condition, not the Mac root cause.
3. A separate Linux NF-core/Caddy matrix passed eight cases (34 TCP and 38 UDP
   echoes, 18 server starts). It replaced the Apple transport and did not exercise
   the exported C ABI. Earlier other-client tests had not included NF.
4. Public source/docs were examined for stream ownership, extraction options,
   DATAGRAM interaction and modern APIs. Their reports were not reproduced on the
   user's OS; no matching official Apple defect confirmation was established.
5. This independent client omits native DATAGRAM extraction and disables H3
   DATAGRAM advertisement. It uses standard Capsules and adds actual stream-ID
   logs. Its initial H3 layout also disables outbound GREASE. These changes are
   **not** a one-variable diagnosis of the historical fault and have no native
   success result yet.

The initial relay-core interoperability runner tests both real relay binaries
through an emulator; see [STATUS.md](STATUS.md) and recorded results. It cannot
answer whether Apple's old QUIC API works on this Mac.

## Candidate causes

| Candidate | Supporting evidence | Limits / counterevidence |
| --- | --- | --- |
| Implicit unused lower bidi stream plus serial request-head parsing | Controlled idle-stream test; Quinn #1742 reports data on stream 4 while 0 is idle | User SIDs unknown; stream 4 is legal; historical Swift already reserved a request child but still failed |
| Fresh child QUIC options associate incorrectly with the parent | VpnHood and fuziki source comments describe fresh-options/ENETDOWN behavior | Third-party reports; this NF case already receives peer control bytes and completes local HEADERS write |
| DATAGRAM extraction interferes with stream dispatch or lifecycle | DitchOoM #173 describes streams-only workaround; old clients retain a DATAGRAM receive loop even after selecting Capsules | NF receives peer control/QPACK; another DitchOoM ENETDOWN was later attributed to its own leaked lifecycle |
| Metadata/READY/cancellation delivery or wrong stream direction | Old NF had diagnostic and defensive gaps; no actual-SID log | No captured evidence identifying a bridge race, wrong request type or callback deadlock as this root cause |
| OS-specific old API behavior | Both failing clients share native transport; HTTP/2 differs | Same symptoms can arise from application sequencing or server parsing; no official confirmation for 27.0.1/26A434 |

POSIX 50 `.waiting` followed by `.ready` and peer bytes is not proof of persistent
network failure. Apple documents waiting errors as nonfatal. An available QUIC
DATAGRAM capacity of 1168 below the CONNECT-IP requirement 1289 justifies Capsules;
RFC 9221 forbids fragmenting QUIC DATAGRAMs. Capsule selection alone is not
successful negotiation or a usable tunnel.

## Public references worth reviewing

- [Quinn #1742](https://github.com/quinn-rs/quinn/issues/1742), including the
  [maintainer explanation](https://github.com/quinn-rs/quinn/issues/1742#issuecomment-1899618012)
  that higher stream IDs implicitly open lower same-type streams under RFC 9000.
  A server can parse streams concurrently with bounds; request SID 4 is valid.
- [VpnHood bidi extraction](https://github.com/vpnhood/VpnHood/blob/8bcbb46654a7638376259b03cacd74f613f46fad/src/Net/VpnHood.Net.Quic.Ios/IosQuicConnection.cs#L54)
  and [fuziki example](https://github.com/fuziki/swift-quic-examples/blob/4b6c574267f9668fad268d6a8a1d0a7ca8c35862/Sources/QuicDemo/NWConnectionGroup/ConnectionGroupView.swift#L136).
  Do not copy disabled certificate checks or turn every stream's options to nil:
  control/QPACK still require unidirectional semantics.
- [DitchOoM/socket #173](https://github.com/DitchOoM/socket/issues/173) and its
  [lifecycle correction](https://github.com/DitchOoM/socket/commit/ae3b50f1efa5d79cadbc660e031a9fc729419864).
- Apple's [old group extraction API](https://developer.apple.com/documentation/network/nwconnectiongroup/extract(connectionto:using:)),
  [modern openStream](https://developer.apple.com/documentation/network/networkconnection/openstream(directionality:)),
  [connection-wide datagrams](https://developer.apple.com/documentation/network/networkconnection/datagrams),
  [inboundStreams](https://developer.apple.com/documentation/network/networkconnection/inboundstreams(_:))
  and [actual streamID](https://developer.apple.com/documentation/network/quic/stream/streamid).
  The old extract contract does not promise the first extracted stream is SID 0.
- [Apple swift-nio-quic 0.4.1 initial bidi ownership](https://github.com/apple/swift-nio-quic/blob/0.4.1/Sources/NIOQUIC/SwiftNetwork/SwiftNetworkQUICConnection.swift#L409)
  and [first-bidi reuse](https://github.com/apple/swift-nio-quic/blob/0.4.1/Sources/NIOQUIC/SwiftNetwork/SwiftNetworkQUICConnection.swift#L558).
  This is a useful ownership pattern, not the source of the installed old API.
- [swift-network-evolution](https://github.com/apple/swift-network-evolution/blob/7854eb128acf01e6a5615db250a11356c326af7f/README.md),
  [swift-nio-quic](https://github.com/apple/swift-nio-quic/blob/913cb68454ac8dbad32cd86f257d9dbcfe0aec37/README.md),
  [swift-nio-http3](https://github.com/apple/swift-nio-http3/blob/15ef379b7722d2d297bdfeecef94826f0db36e65/README.md),
  [swift-nio-transport-services](https://github.com/apple/swift-nio-transport-services).
  NIO QUIC's package SwiftNetwork/SwiftTLS over NIO UDP is a different backend;
  adopting it is not a simple Network.framework wrapper change. Prerelease/main
  features must not be described as stable-release guarantees.
- [Swift.org packages](https://www.swift.org/packages/) and
  [Swift Package Index networking](https://swiftpackageindex.com/keywords/networking)
  are discovery catalogs. Alamofire, Moya and URLSession wrappers do not validate
  raw QUIC stream/DATAGRAM combinations or replace a CONNECT-UDP tunnel backend.

The cited observations were inherited from the completed Masque NF investigation;
this task has not rerun those public projects or asserted fresh upstream results.

## Limited next steps

First establish native HTTP/2 TCP and UDP against both relay servers. Then perform
one forced H3 test with fixed endpoint/IP/SNI/credentials and no settings changes.
Keep ordinary deadlines and collect actual SID, parent resource, stream purpose,
requested direction, HEADERS-send completion, response receive and first error.
Pair it with the server's accepted SID/header-parse trace if available. Do not log
Authorization, full request headers, application payload or certificate contents.

If still failing, stop initial QUIC development and preserve the failing run.
Potential future A/B tests, one change each: child-options inheritance; initial
request-stream ownership; old group versus modern system API; bounded server
request parsing. Changing either server is outside this application's task scope.
A replacement QUIC backend is a later design decision because it may violate the
Network.framework ownership goal. Longer timeouts, relaxed trust and successful
HTTP/2 fallback must not be used as evidence of forced-H3 success.
