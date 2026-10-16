# Native QUIC research and handover

Historical investigation date: 2026-10-11. This report separates observed failures, supported mechanisms,
unproven hypotheses and this new client's implementation choices. It does not
assert that Network.framework has an unavoidable defect.

## Current conclusion

**The earlier periodic native HTTP/3 disconnect is user-confirmed resolved.**
The server idle-stream-0 and client probe-lifecycle repairs must be preserved.
The ten-second EINVAL runs below describe their recorded older builds; they are
not a current failure or a reason to disable working HTTP/3. The report retains
the original evidence and the limits of the root-cause attribution. It never
established an unavoidable Network.framework defect.

The complete current-build Apple-to-both-server acceptance matrix is still
incomplete. [NATIVE-ACCEPTANCE.md](NATIVE-ACCEPTANCE.md) separates forced
HTTP/1.1, HTTP/2 and HTTP/3, actual forwarding, long-lived flows, idle operation,
sleep/wake and network changes. A Linux Quinn pass cannot fill a native row.

Two separately established client defects have been repaired in the current
source: HTTP stream pump errors did not wake the opposite pending I/O operation;
and normal expiry of an idle readiness probe was treated as a relay failure.
The fixes have portable regression coverage. The user later confirmed the
periodic disconnect resolved; that confirmation does not establish every native
acceptance case on every server/build.

### Historical 2026-10-11 follow-up: server reaction to idle stream 0

See [the evidence](evidence/idle-group-stream-zero-20261011.md). Apple DTS
documents that an `NWConnectionGroup` owns client bidirectional stream 0 and
exposes no I/O on it, so the observed request on SID 4 leaves stream 0
implicitly open and idle. With that state emulated, real Rust network-relay
and caddy-network-relay binaries each reset and stop stream 0 about ten
seconds after readiness (codes 0x10B and 0x10D). The admitted stream-4
session continues on Quinn. At that investigation point, the final link,
Network.framework surfacing that reset as group EINVAL, was unobserved and the
EINVAL was not yet repaired. The group API did not expose stream 0 for client
I/O. The client logs group failures at WARN and the group-owned SID at Detailed.

Later the same day, a Mac run confirmed `groupSID=0`, requests on SID 4 and
group EINVAL failures 10.36–11.60 s after each group's first request
([evidence](evidence/native-http3-20261011-1412.md)). Server changes were then
permitted: network-relay `9821c4f` and caddy-network-relay `ef04df6` start the
header deadline at a request stream's first byte, so the unwritten stream 0 is
left open. Network Relay NF is unchanged. Emulator and server tests pass;
native acceptance against a deployed fixed server was pending at that point.
The later user-confirmed resolution supersedes that earlier stopping conclusion;
the archived source/emulator evidence alone does not prove Apple's internal
error mapping.

## New relay application observations

The supplied cumulative log identifies app/core 0.1.0, built at
2026-10-11T09:37:18Z from source
`666b795c881b44eeaade9891edfae04ffcbd34a6`. The user earlier reported macOS
27.0.1, build 26A434. The endpoint is `relay.kitendesecschool.com`, with server
IP override `35.212.234.101:443`, using Rust network-relay. The deployed server's
exact source revision, executable hash and effective timeout configuration are
not recorded. The later source fixes were not present in this Mac binary.

Selected lines and original-upload hashes are retained in
[native-quic-20261011.log](evidence/native-quic-20261011.log) and
[native-quic-20261011.json](evidence/native-quic-20261011.json). The three uploads
are cumulative observations, not three independent controlled experiments.
Credentials, password hashes, Google cookies and application payload are omitted.

| Observation | Evidence | Interpretation |
| --- | --- | --- |
| Forced native HTTP/2 TCP and UDP work | Run `810BA952`, readiness 09:55:43.635736; Google 200 and DNS UDP response at 09:56:09 | User-reported positive H2 forwarding against one Rust deployment; the app trace now supplies the outer transport attribution |
| Native H3 reaches admission, then fails | Run `5FBDACF5`, ready 09:57:22.411888; native EINVAL 09:57:32.387843 | 9.975955 seconds after admission; this is not a missing initial HTTP/3 response |
| New H3 attempts repeat the same timing | Run `30625FF0`, five ready/failure intervals: 10.004961, 10.079869, 10.000147, 9.998890 and 10.004688 seconds | Persistent native failure while the forced transport is unchanged; retries back off 1, 2, 4, 8 and 16 seconds |
| Real request SID is 4 | Resource 162, parent 148, SID 4, requested bidi; resource 170, parent 151, also SID 4 | These are actual metadata IDs, unlike the old bridge-handle-only logs. SID 4 is legal; no trace of SID 0 is supplied |
| Native parent and business flow fail too | Parents 148/151 fail at 09:58:01/09:58:02; a SOCKS CONNECT had been admitted at 09:57:52.886760 | More than a readiness-probe warning; independent H3 flow groups also fail. Admission is not proof of a completed HTTPS transfer |
| An H2 probe ends after five minutes | Run `E5EF8AE9`, ready 10:02:25.883977; clean control EOF 10:07:25.885545 | 300.001568 seconds; consistent with the server's default UDP flow idle expiry |
| Other TCP events are separate | H1 run `39938F96` has a control connection reset; H2 logs include individual SOCKS resource resets/timeouts | Do not combine per-flow closure, clean probe expiry and H3 group EINVAL into one root cause |

The positive TCP/UDP probes ran on the user's Mac, not here. curl's `HTTP/2 200`
alone identifies Google's response protocol; the newly supplied application run
is what attributes the outer H2 transport. There is still no sustained native
H3 TCP/UDP acceptance result or native Caddy matrix. Earlier H2 404s coincided
with explicit server authentication failures and are a separate resolved
configuration incident. [Mac forwarding evidence](evidence/native-mac-20261011.md).

## Repairs made after reviewing these logs

1. **Wake pending I/O on either HTTP pump's error.** `Core/src/stream.rs` used to
   store an error string without waking a reader waiting on the opposite pump.
   A writer failure could leave an idle reader pending; a read failure could
   leave a backpressured writer pending. A shared failure state now registers
   and wakes both directions, preserves the first error, returns buffered bytes
   before a read error, and reports the error through flush/shutdown. Three
   regression tests cover these cases. Normal half-close remains independent.
2. **Refresh the idle admission probe rather than report normal expiry as a
   broken relay.** The probe sends no UDP payload and the source server defaults
   to a 300-second UDP idle expiry, with a supported minimum of 120 seconds.
   The client now replaces its probe every 60 seconds, without migrating or
   stopping independent SOCKS flows. Clean peer FIN also refreshes the probe;
   malformed Capsules and native I/O errors remain failures. Four regression
   tests cover idle renewal without traffic, a fixed renewal deadline despite
   incoming Capsules, clean FIN and truncated-Capsule rejection. This is probe
   lifecycle handling, not an Internet heartbeat or a native QUIC repair.
3. **Keep useful failure diagnostics.** HTTP/3 driver termination is now logged
   at DEBUG. Retry delay resets after at least 30 seconds of admitted readiness;
   a ten-second H3 flap still receives exponential backoff. Native stream options,
   certificate checks and transport selection have not been relaxed.

All 63 ordinary Rust tests pass (37 unit, 21 boundary, five ABI), project Clippy
passes, and both real Rust/Caddy matrices pass H1/H2/H3 through the test-only
rustls/Quinn emulator. The matrices include 2 MiB TCP half-close and UDP payloads
through 65,000 bytes. A full cloud filesystem briefly blocked recompilation;
removing generated cache restored the checks, with no server or source change.
These results verify the portable repairs and preserve protocol compatibility;
they cannot establish a native EINVAL fix or a Swift build result.

## Historical leading explanation, not proof of Apple's internal error mapping

Opening client bidi SID 4 implicitly makes lower same-type SID 0 exist under
RFC 9000. A plausible sequence is: the group owns an unused initial bidi stream;
the app's extracted request uses SID 4 and succeeds; a server header deadline
then rejects idle SID 0; the legacy Apple group exposes that rejection as group
EINVAL. This explains both successful admission and a repeatable ten-second
failure, but its last steps have not been observed.

The inspected Rust network-relay source accepts request resolvers concurrently
in `src/server/over_h3.rs`. It applies `HEADER_TIMEOUT = 10 seconds` from
`src/server/mod.rs`. `vendor/h3/src/server/request.rs::resolve_request_before`
rejects late HEADERS with STOP_SENDING and RESET_STREAM carrying
`H3_REQUEST_REJECTED`; it does not intentionally close the whole connection.
Thus the older **serial parsing blocks request 4 behind idle 0** explanation
cannot simply be reused for this successful-admission case. The actual deployed
build may differ from the inspected source. No server trace identifies idle SID
0, its rejection code or the first event preceding the Apple group failure.

The client configures QUIC `idleTimeout = 60_000`. Apple's documentation defines
this value in **milliseconds**, so it is 60 seconds, not 60,000 seconds; stream
metadata sets a connection keepalive interval of 30 seconds. The observed ten-
second failures therefore do not match the configured native idle timeout.
Increasing this timeout or adding keepalives is not an evidenced fix.
The separate clean H2 EOF at 300 seconds fits application UDP idle policy;
transport keepalive does not send a UDP Capsule to reset that policy timer.

## Confirmed historical observations

The user reported macOS 27.0.1, build 26A434, on a Mac mini. Masque NF and Masque
Swift both had HTTP/3 problems; HTTP/2 worked. The server was Rust masque-server
at `masque.kitendesecschool.com / 34.4.108.158`. These clients used CONNECT-IP,
whereas Network Relay NF uses CONNECT/CONNECT-UDP and different relay servers.

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
   **not** a one-variable diagnosis of the historical fault. The new native logs
   show successful H3 admission but subsequent EINVAL; these choices have not
   delivered stable native H3. Client-side DATAGRAM extraction is therefore not
   required for the new failure to occur.

The initial relay-core interoperability runner tests both real relay binaries
through an emulator; see [STATUS.md](STATUS.md) and recorded results. It cannot
answer whether Apple's old QUIC API works on this Mac.

## Historical candidate causes

| Candidate | Supporting evidence | Limits / counterevidence |
| --- | --- | --- |
| Implicit idle bidi 0 is rejected, triggering native group failure | New request SID 4 is real; failures repeat near ten seconds; inspected server has a ten-second late-header rejection | Idle 0 and the rejection have not been traced; deployed server build unknown; native error promotion is unproven |
| Serial request-head parsing blocks a higher stream | Controlled historical masque-server idle-stream test; Quinn #1742 | Explains a sufficient old timeout condition, not the new admitted request; current network-relay parses concurrently |
| Fresh child QUIC options associate incorrectly with the parent | VpnHood and fuziki source comments describe fresh-options/ENETDOWN behavior | Third-party reports; the new client completes admission before EINVAL; requires a controlled native options A/B |
| DATAGRAM extraction interferes with stream dispatch or lifecycle | DitchOoM #173; old clients retain a DATAGRAM receive loop | New failing client has no DATAGRAM extraction, so it is not necessary for this fault; another DitchOoM ENETDOWN was its own lifecycle leak |
| Metadata/READY/cancellation delivery or wrong stream direction | Old NF had diagnostic and defensive gaps; no actual-SID log | No captured evidence identifying a bridge race, wrong request type or callback deadlock as this root cause |
| OS-specific old API behavior | Older clients and this new binary share the old native QUIC API; H2 is usable | Framework boundary is implicated, but sequencing, child ownership and server rejection may interact; no official confirmation for 27.0.1/26A434 |

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
- Apple's [QUIC idle timeout](https://developer.apple.com/documentation/network/nwprotocolquic/options/idletimeout)
  specifies milliseconds; [metadata keepalive](https://developer.apple.com/documentation/network/nwprotocolquic/metadata/keepalive)
  describes connection keepalive behavior. Neither guarantees that resetting
  an unused child stream leaves an old group usable on the reported OS.
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

The project observations were inherited from the completed Masque NF study;
those projects have not been rerun on the user's OS. Apple's extraction,
idle-timeout and keepalive documentation was checked again for this update.

## Current regression follow-up

The earlier stopping rule applied to the recorded failing builds. Do not reopen
that resolved incident solely because its archived logs remain in this report.
Preserve the existing server and client fixes, and use the opt-in native matrix
with current binaries. This application's repair scope does not authorize server
changes, a QUIC backend replacement or relaxed certificate validation.

If a new failure is observed, make one bounded native reproduction with fixed settings,
no unrelated SOCKS traffic, and synchronized client/server traces. First capture
accepted SIDs 0/4, late-header rejection or connection-close code, and which native
callback first reports EINVAL. Record the deployed server revision and effective
timeout configuration before comparing them with this report. Do not log
Authorization, full request headers, application payload or certificate contents.

Then test one variable: first-bidi ownership/reuse; child-options inheritance
while preserving uni/bidi direction; or old group versus modern system QUIC API.
An isolated Quinn experiment can verify that rejecting idle 0 leaves request 4
usable on the same Rust build, but cannot prove Apple's reaction. Raising or
disabling a header deadline would only be a diagnostic experiment, not a security-
preserving repair. Changing either server is outside this application's task scope.
A replacement QUIC backend is a later design decision because it may violate the
Network.framework ownership goal. Longer timeouts, relaxed trust and successful
HTTP/2 fallback must not be used as evidence of forced-H3 success.
