# Claude task: independently repair native QUIC and HTTP/3 defects

Updated: 2026-10-11. Read this entire task before proposing changes.

## Mandatory independent judgment

The hypotheses, candidate remedies and research notes in this instruction and
the repositories are references only. They are not a prescribed implementation,
an established root cause, or instructions to copy a proposed fix.

You must carefully inspect the actual current code, dependency versions and
evidence. Read the applicable Apple specifications, API documentation, release
notes and available source, and compare relevant open-source implementations.
Independently determine the cause and the smallest justified repair. Reject or
replace earlier hypotheses when the evidence warrants it. Explain your reasoning
and distinguish observed facts, source-derived mechanisms and untested ideas.

## Hard scope and change constraints

You may modify only:

- `ArcCal/masque-vpn`: `masque-nf/**`.
- `ArcCal/network-relay`: `network-relay-nf/**`.

Every other project, server, shared crate, root manifest/lockfile/document, CI
file and Caddy repository is read-only. Do not reintroduce Masque Swift. Preserve
unrelated working-tree changes. If a necessary repair lies outside this boundary,
document it inside the relevant NF directory and report the limitation.

Keep every modification minimal. Change only QUIC/HTTP/3 defects or other clearly
evidenced faults; do not include speculative cleanup, refactoring, broad
dependency upgrades, UI redesign, unrelated features or architectural migration.

Before EACH modification:

1. Identify the concrete fault and the evidence that the change is necessary.
2. Evaluate affected paths, ownership/lifecycle, interoperability and regression
   risks, including the currently working server and HTTP/2 cases.
3. Make one small coherent change, inspect its diff and run appropriate tests.
4. Evaluate the result before starting the next change. Resolve regressions or
   withdraw the responsible change. Do not call an untested change a confirmed
   repair or guarantee that it introduces no new bugs.

Production OS networking must remain Network.framework. Rust may implement
HTTP/3 framing, QPACK, Capsules and SOCKS; it must not replace Apple's production
TCP/TLS/QUIC transport with Quinn, rustls, quiche or another socket/packet engine.
An emulator pass is useful protocol evidence, not native acceptance.

## Read the code and documents first

For each repository, inspect its current instructions, Git status and revision,
dependency manifests/lockfiles, application build identity, existing tests,
build scripts and recorded evidence. Read the following before editing:

Masque NF:

- `masque-nf/README.md`, `DESIGN.md`, `SPEC.md`, `VALIDATION.md`,
  `CLOSE-REVIEW.md` and `CHANGELOG.md`.
- `masque-nf/docs/evidence/native-http3-20261011-1205.md`.
- `docs/research/network-framework-http3/` as historical read-only context.
- `masque-nf/App/Sources/MasqueNF/NativeClient.swift` and
  `TunnelController.swift`; the C bridge and header.
- `masque-nf/Core/src/{native,quic,client,tunnel,socks}.rs`, including the actual
  HTTP/3 dependency and the read-only shared protocol/TCP-IP/DNS code it calls.
- `masque-nf/Core/tests/{native_boundary,ffi_lifecycle,server_interop}.rs`,
  test support, `Tests/{NativeSmoke,NativeCloseChecks}.swift`,
  `scripts/test-native.sh` and `build-macos.sh`.

Network Relay NF:

- `network-relay-nf/README.md`, `docs/{DESIGN,SPEC,STATUS,VALIDATION,
  QUIC-RESEARCH,BUILD-AND-OBSERVE}.md`, `docs/evidence/` and
  `SOURCE-PROVENANCE.json`.
- `network-relay-nf/docs/evidence/native-http3-20261011-1202.md`.
- `network-relay-nf/App/Sources/NetworkRelayNF/{NativeClient,TunnelController}.swift`
  and its C bridge/header.
- `network-relay-nf/Core/src/{native,quic,client,stream,socks}.rs`,
  `Core/src/proto/`, `Core/vendor/h3/` and dependency manifests/lockfiles.
- `network-relay-nf/Core/tests/{native_boundary,ffi_lifecycle,server_interop}.rs`,
  test support, native Swift checks, `scripts/{test-native.sh,test-interop.py,
  probe-socks-udp.py}` and `build-macos.sh`.

Inspect the corresponding server request handling, timeout/error behavior and
protocol configuration READ-ONLY, including Rust request acceptance and the
Caddy implementations. Pin the actual deployed server revision when possible;
current source is not proof of what the user's VPS runs.

## Distinguish the observed failures

Masque NF uses CONNECT-IP. The latest user logs show SERVER-PROFILE-DEPENDENT
initial HTTP/3 behavior:

- Profile label `caddy-masuqe`: six HTTP/3/Capsule tunnel establishments, four
  forced HTTP/3 and two Auto runs explicitly selecting HTTP/3. Byte forwarding
  occurs. The first session lasts roughly 55 seconds before a settings restart.
- Profile label `masque-vpn`: twelve completed initial-response timeouts, after
  native QUIC readiness and request write/read-wait, with no HTTP/3 tunnel
  establishment. Timeouts occur 10.190977-10.230700 seconds after
  Capsule-negotiation logging. HTTP/2 succeeds in three comparison runs.
- Successful sessions end after user/settings changes; some individual SOCKS
  resources still report DEBUG errors. Do not call the successful profile fully
  stable or universally compatible.
- Both profiles choose Capsules below the 1,289-byte threshold and show a
  transient POSIX 50 waiting state followed by readiness. Neither fact alone
  explains the different outcomes.
- Labels do not prove backend identity, endpoint or deployed revision. The
  attachment has no client build SHA and bridge resource handles are not QUIC
  stream IDs. Do not treat a 120-versus-121-byte request-size difference as a
  root cause. Preserve both uploads because the later bounded export omits some
  earlier verbose records.

Network Relay NF uses CONNECT and CONNECT-UDP. Its distinct latest recorded
failure occurs AFTER authenticated HTTP/3 admission:

- Run `16A52488`, 2026-10-11 UTC: ready at `12:02:49.394733Z`; POSIX 22 /
  EINVAL at `12:02:59.397293Z`, exactly 10.002560 seconds later; retry after 1s.
- Next attempt sends HEADERS on actual SID 4 at `12:03:00.893549Z`; the file
  ends waiting for a response. Only one complete cycle appears in that file;
  earlier evidence records recurrence.
- Binary source `666b795c881b44eeaade9891edfae04ffcbd34a6`, built
  `2026-10-11T09:37:18Z`. Establish which source fixes are present before
  assessing the current implementation.
- Separate HTTP/2 control-flow closures occur near 300 seconds. Source changes
  for probe renewal, stream error propagation and retry backoff already exist,
  but the latest old-build log does not verify them on a Mac.

Do not merge these symptoms into one proven cause. Do not assume an inherent
Network.framework defect; successful native HTTP/3 provides a regression control.
Conditional framework behavior, adapter lifecycle, HTTP/3 logic and server
interaction remain possibilities until evidence distinguishes them.

## Research applicable Apple APIs and open-source behavior

Review the relevant Network.framework documentation and API availability for the
reported macOS 27.0.1 build 26A434, plus the actual reproduction OS/SDK:

- NWConnectionGroup, NWMultiplexGroup, extraction, child connection ownership,
  stream direction/metadata, completion handlers, cancellation and FIN/reset.
- NWProtocolQUIC.Options and Metadata, real stream identifiers, DATAGRAM
  support, idleTimeout units and keepalive semantics.
- Newer NetworkConnection<QUIC> stream/datagram APIs only as a bounded candidate
  if supported by the actual toolchain; do not assume a migration is the fix.
- Apple release notes, API headers and documented limitations.

Search Apple's swift-network-evolution, swift-nio-quic, swift-nio-http3 and
swift-nio-transport-services; VpnHood, fuziki/swift-quic-examples,
DitchOoM/socket discussions and Quinn issue #1742 where relevant. Verify current
source, platform, backend and later corrections. Swift.org/packages and Swift
Package Index's networking list are discovery aids, not compatibility evidence.
A URLSession wrapper or non-Apple QUIC engine is not proof of correct raw
Network.framework stream handling.

Consult RFC 9000/9001/9002, 9114, 9204, 9221, 9297, 9298 and 9484 as applicable.
Stream SID 4 is legal. Implicit stream 0, serial parsing, peer rejection,
DATAGRAM extraction, child options, callback ownership, timeout/keepalive changes
and modern-API migration are unproven ideas to assess, not fixes to implement
automatically. Current Network Relay request resolution is concurrent; a
historical Masque server experiment must not be copied into a causal conclusion
about the Relay server.

## Diagnose, repair and verify

Trace the FIRST failure with correlated native and server events: parent/child
identity, actual SID/direction, creation order, request write/receive completion,
peer FIN/reset/STOP_SENDING, cancellation and exact stage durations. Logs must
exclude credentials and packet contents. Any added instrumentation must be
minimal, relevant and inside the permitted NF directories.

Keep endpoint, certificate identity, credentials, server revision and network
conditions controlled when comparing cases. Each experiment must answer a
specific question. Longer deadlines, fallback or repeated reconnection must not
conceal failure.

Test the correct independent pairings:

1. Masque NF with Rust masque-server.
2. Masque NF with caddy-masque.
3. Network Relay NF with Rust network-relay.
4. Network Relay NF with caddy-network-relay.

Use real native macOS transport for final acceptance. Force HTTP/3 for QUIC
tests; test Auto separately. Exercise sustained SOCKS TCP and UDP, idle periods,
concurrency, binary bulk transfer, both half-close directions, cancellation,
reconnect, network changes, and authentication/certificate/policy rejection.
Sustained checks should last at least ten minutes to exceed both recorded
ten-second and five-minute failures. Preserve working profile and HTTP/2
behavior. Record server/transport cases separately; never count an HTTP/2
fallback or emulator result as native HTTP/3 success.

Update only the relevant NF design/specification/evidence documents with what
is implemented, confirmed faulty, suspected, repaired and verified, or still
missing. Cite exact source versions, test conditions and limits. If blocked,
finish independent analysis and document the narrow blocker rather than expand
scope or invent a successful result.

Once a repair is confirmed by relevant tests, provide complete fresh-clone Mac
instructions using the tested revision: prerequisites, full repository download,
build commands, app launch, build identity verification, graded logging and
TCP/UDP observation. If native verification is unavailable, label the change
unverified and do not claim the defects are fixed.
