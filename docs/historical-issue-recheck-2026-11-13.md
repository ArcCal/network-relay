# Historical issue recheck, 2026-11-13

All69 PR summaries (network-relay1-50,Caddy1-19), all69 discussion timelines, all69 review-submission lists and all69 inline-review-thread lists retrieved. Discussion count14 across3 PRs; submitted reviews0; inline threads0; no reported fetch errors. Issue search returned zero results. Historical claims are not independent current validation; inventory remains open.

Historical failures remain open unless matching evidence establishes their cause and correction. Passing later tests alone does not close an unexplained failure. Candidate changes are committed and pushed on separate audit branches. Main remains unchanged; failures are not waived.

## H01: Slow Apple system Relay with generated mobileconfig

Source: User report; network-relay PR19

Status: OPEN: native baseline now measured; field/WAN cause unknown

Runs 43429591616 and 43431073499 each passed 96 positive cases / 608 samples and 16 rejection controls for an HTTP/1 origin. Separate UDP and inner HTTP/3 runs revealed failures tracked in H17 and H18. Both baseline one-click installers already generate H2-only profiles; low-level profile generation permits H3. Installed-profile, WAN/iPhone, RTT/loss and current-candidate native acceptance remain open. Candidate upload and branch pushes are authorized; ongoing native comparisons retain all failures in the native candidate report. Native H2 UDP63 truncation is now reproduced on macOS15.8.2 and27.0.1 before server DATA parsing, tracked inH18; it is a concrete failure mechanism, not full field attribution.

## H02: Earlier CF H3 timeout around ten minutes

Source: network-relay PR31

Status: OPEN: old failure not explained

Preserve the failure independently of later successful soaks and the new TCP persist repair.

## H03: CF soak reset after 3842.91 seconds

Source: scratch/frozen-warp-soak-20261113T073817Z-245051

Status: OPEN: reset cause unknown

Current fixed-binary run completed3948.49s and passed independent verification:131 samples covering3923.49s,6 heldTCP and6 heldUDP flows; payload hashes, source/binary freeze, queue drops and resources verified. RSS117812-129360KiB,FD40-43. Old3842.91-second reset remains unexplained; this passing run is not causal proof. Old retained evidence has120 records: cycle119 at3630.38s still shows both egress generations1, no drops/failure, RSS132920KiB,FD40 and365/366 held TCP pings. Failure occurs inside the next periodic64MiB bulk operation; no failure-time packet/TCB capture exists to establish its cause. The later reassembly candidate independently passes3950.46s,131 samples,exact hashes and no outer reconnect/queue drops. This second passing run still does not identify the old reset cause.

## H04: Caddy H1 TLS close-notify before subsequent TCP reset

Source: network-relay PR28/PR33; NF docs/evidence/h1-reset-boundary-20261016.md

Status: SERVER REPAIR VALIDATED; native Apple acceptance remains open

Current Caddy abort closes raw TCP directly. Frozen candidate33ffbad... passed independent OpenSSL30 target resets (all errors, no clean TLS EOF) and3 clean8MiB half-closes with reverse traffic; h1-reset-boundary-results.json. Existing h1_abort_test also passes. No client-side EOF reclassification.

## H05: Caddy reload resets connections queued on old listener

Source: caddy-network-relay PR11

Status: CURRENT DETERMINISTIC HANDOFF REPAIR VALIDATED

Current full race plus10 repetitions of actual retiring-listener gate and revoked-tunnel synchronization passed; historical-targeted-race.log56.859s. Oldload-rate claim is not a measured currentload-rate.

## H06: HTTP3 request header timeout absent from plugin API

Source: caddy-network-relay PR1 S02

Status: LATER REPAIR EXISTS

PR11 introduced vendored ReadHeaderTimeout. Current app.go and vendored server enforce first-byte header deadlines; verify idle Apple streams separately.

## H07: Anonymous connections can exhaust authenticated capacity

Source: network-relay PR6

Status: LATER REPAIR EXISTS

PR13 adds reservation; current anonymous_connections_cannot_take_the_capacity_devices_need passes in main and egress suites.

## H08: Profile identifier host/user component collision

Source: network-relay PR6 finding10

Status: RETAINED COMPATIBILITY RISK

Legacy deterministic identifier replacement is intentional. Need a migration-safe solution before changing identifiers; do not label documentation as a repair.

## H09: NF periodic admitted H3 failure around ten seconds

Source: network-relay PR18/21/22/23; NF STATUS

Status: BASELINE NATIVE FUNCTIONAL CONTROLS PASS; workflow cleanup failed

Run43442359934 exercises actual NativeClient and TunnelController: H2/H3/H1 each hold active and idle TCP flows for610s, survive sibling cancellations, detect killed Caddy and reconnect. H3 detection10.40s/recovery1.27s. All seven trust/password/hostname rejection controls leave origin unchanged. Test CA removal times out in both cleanup attempts; overall workflow failed. Not current-candidate, GUI, sleep/wake, installed-profile or WAN acceptance.

## H10: NF silent server-death recovery and independent idle flows

Source: network-relay PR47

Status: BASELINE NATIVE RECOVERY VERIFIED; overall workflow failed cleanup

Run43442359934: active/idle TCP held610.19-610.60s; H2/H3 each80 concurrent flows, H1 sixteen, cancel half and verify survivors. Actual TunnelController detects server death in2.03/10.40/11.92s and reconnects in1.58/1.27/0.69s respectively. Post-death attempt fails closed. Three held harnesses finish stopped. Owned relay.test CA removal times out twice, so cleanup is unverified and workflow is not passed. Hosted job has ended. Current candidate and real GUI/network changes remain separate.

## H11: RS remote SETTINGS/response stalls and setup budgets

Source: network-relay PR34; RS STATUS

Status: PARTIALLY COVERED

Current delayed H2 response regression passes after setup-budget repair. Remote SETTINGS stalls and native/WAN behavior remain independent.

## H12: Unknown HTTP3-frame memory stress timeout

Source: network-relay PR48; baseline GitHub run43421800256 ARM64 job

Status: NATIVE ARM64 BASELINE PASSES; QEMU timeout remains environment-dependent and unresolved

Run43431527610 on actual Linux aarch64 passed original256MiB case isolated4.25s and4.18s after full76-case concurrent suite16.56s. Original20s deadline and128MiB growth bound unchanged. This is baseline, not local Rustls candidate validation; no proof yet separating QEMU CPU overhead from load.

## H13: Malformed H3 control-frame timeouts during race load

Source: caddy-network-relay PR19

Status: CURRENT TARGETED REPETITIONS PASS; old timeout cause unproven

TestH3PushFramesAreChecked includes malformed control/request frames;10 repeated race executions passed with original deadlines, alongside listener reload controls56.859s. Retain old timed-out artifact. PR11 comments separately identify frame-length overread and connection-error scope in both server and shared-client paths. Current TestH3PushFramesAreChecked and TestH3ClientChecksPushFrames explicitly cover them, including non-minimal encodings and withheld bytes; the latter is covered by the previously completed full race suite.

## H14: IPv6 underlay tests previously unavailable

Source: network-relay PR45/48; caddy-network-relay PR11

Status: FIVE HISTORICAL IPV6 SOCKET GAPS NOW PASS; native/WAN coverage separate

Current vendored QUIC upstream TestReadECNFlagsIPv6, TestReadECNFlagsDualStack, TestSendPacketsWithECNOnIPv6, TestSysConnPacketInfoIPv6 and TestSysConnPacketInfoDualStack all pass with -race, no skips. Original assertions and full snapshot hashes verified by the existing harness. Current Caddy TestIPv6TargetInTemplate also passed the retained normal and race suites. These do not validate an Apple IPv6 Relay endpoint or an external IPv6 route.

## H15: Old WARP configs retain limits48/32 causing503

Source: network-relay PR45/48

Status: RETAINED OPERATOR CONFIGURATION

Defaults changed, explicit existing limits remain by design. Audit diagnostic visibility and document migration without silently widening configured quotas.

## H16: Native GUI, sleep/wake, migration and high-connection-count CPU coverage

Source: NF and RS acceptance/status documents; PR8/24/45

Status: OPEN COVERAGE

Model/build tests do not establish native interaction or production scaling. Separate current-source native and bounded capacity measurements.

## H17: Native Apple UDP packet-size sensitivity on Caddy H3

Source: macOS run43433768783

Status: OPEN DIAGNOSIS; not classified as a standards violation

Cold baseline lost1350/1400-byte H3 replies. Warmup run43435452789 passed1350 bytes on H3/auto, but H3-1 andauto-1400 cases lost their first1200-byte warmup packet; H3-1400 completed warmup but lost first1400-byte reply. Native maximumDatagramSize mostly16356 does not describe proxy reverse-path limit. Baseline already requests PMTU probes after DatagramTooLarge. Inner HTTP/3 run 43435886537 failed; see H18. RFC9298 section6.1 drop recommendation preserved.

## H18: Native inner HTTP/3 uploads stall through H2 CONNECT-UDP

Source: macOS baseline run 43435886537

Status: REPRODUCED NATIVE H2 UDP63 TRUNCATION; no conformant server repair accepted

Raw H2 frame runs43447935315(macOS15.8.2) and43447941138(macOS27.0.1) both capture length66,flags0x0,prefix00404000+payload00..3d; expected67bytes ending3e. Missing byte exists before DATA parsing/padding or body pipe. Both have zero origin packets for63bytes, neighboring sizes and direct/H3 controls pass. Continuous innerH3 uploads subsequently misparse45aa00 as unknown type1450,length0. Independent Go42x64MiB upload controls pass. Server must not guess bytes/resynchronize/reject legal unknown Capsules. Actual installed profile/iPhone/WAN and candidate acceptance remain open.

## H19: Historical unwritten H3 stream quota fix was later revised for implicit stream opening

Source: caddy-network-relay PR11 discussion and commit184dd1a

Status: CURRENT POLICY IDENTIFIED; large-scale resource acceptance remains separate

PR11 initially restored 16 pre-first-byte slots. Later commit184dd1a intentionally moved pending-header accounting to first byte because RFC9000 section3.2 implicitly opens lower stream IDs. Current TestH3UnwrittenStreamsAreBounded allows 200 implicit empty streams; TestH3IncompleteHeadersPerConnection still rejects 17 started incomplete requests. Do not restore the obsolete16-empty-stream rule. QUIC stream/connection bounds and native high-concurrency behavior must be assessed separately.

## H20: Native H3 TCP downloads intermittently stop before completion

Source: macOS baseline run43478717847 and candidate-repeat run43476603192

Status: OPEN: baseline and candidate observations; causal attribution unresolved

Unchanged Caddy baseline macOS 27: four 64 MiB downloads on one H3 connection all timeout near 120.85 seconds after 44-47 MiB forwarded per stream. Candidate macOS 15: one of three serial 64 MiB downloads times out on actual H3 auto route. HTTP/1.1 TLS origin; distinct from H2 UDP 63. Same bounded observer runs 43482779652/43482785124 are pending; no transport policy relaxation. Partial ABBA cannot establish regression or improvement.

Further baseline run 43480897922 reproduces four parallel H3 timeouts near
120.06 seconds after about 5-7 MB per stream; both candidate phases pass.
Flow observations 43482779652 and 43482785124 pass 32/112/16 per binary but
do not reproduce the stall. Unchanged-binary watchdog 43488457625 is pending.
