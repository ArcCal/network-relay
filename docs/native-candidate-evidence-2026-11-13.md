# Native candidate evidence snapshot, 2026-11-13

This snapshot preserves selected verified measurements after hosted artifacts expire.
Full raw evidence remains in the local audit workspace. Passing focused uploads do
not waive failed native downloads, UDP cases, unit suites, or missing field acceptance.

## Sustained upload inputs and retained artifacts

Diagnostic commit: `746e8042034dd36a289be1ff14ff62f93cf18a96`.
Each run uses ABBA, 24 samples of 64 MiB per case, two case orders per phase,
and one/four concurrent requests. Each run passes 96 cases, 2,304 samples and
64 exact rejection controls. Total uploaded data is 144 GiB per run.

| Candidate / host | Run | Artifact | Verified ZIP SHA256 |
| --- | --- | --- | --- |
| Rust / macOS 27 | 43494363421 | 14073070453 | `b0fa0b3f3261eda935f5008c3655937772eed6610d02a68136efc41b2295cf09` |
| Caddy / macOS 15 | 43494379234 | 14073140470 | `d00be523470a075734e7881a1fcf627fca5b20fcd3a6762f5d4f3778856934cf` |

## Rust candidate on macOS 27

Each cell lists the four case observations in phase/case order, in MiB/s.
The other server is unchanged; direct rows bypass the explicit Relay.
Ratios compare medians and are descriptive, not causal speedup estimates.

| Server / mode / concurrency | Baseline observations | Candidate observations | Ratio | Baseline CPU s/GiB | Candidate CPU s/GiB |
| --- | --- | --- | ---: | ---: | ---: |
| caddy / direct / 1 | 1009.4, 1004.9, 746.2, 687.3 | 997.8, 660.1, 637.1, 748.3 | 0.804 | 0.000 | 0.000 |
| caddy / direct / 4 | 1382.9, 1667.7, 1061.2, 957.6 | 1653.8, 1327.8, 889.5, 859.9 | 0.907 | 0.000 | 0.000 |
| caddy / h2 / 1 | 582.7, 668.0, 498.7, 432.7 | 728.0, 600.4, 433.9, 534.7 | 1.050 | 1.330 | 1.297 |
| caddy / h2 / 4 | 854.4, 753.4, 444.0, 497.8 | 613.1, 683.3, 478.7, 554.2 | 0.933 | 1.247 | 1.297 |
| caddy / h3 / 1 | 216.2, 216.3, 113.7, 103.0 | 218.8, 161.2, 104.0, 108.7 | 0.818 | 7.560 | 8.437 |
| caddy / h3 / 4 | 186.9, 208.3, 105.5, 100.0 | 173.2, 164.0, 97.2, 105.2 | 0.920 | 8.103 | 8.553 |
| rust / direct / 1 | 1002.8, 1039.2, 603.0, 730.9 | 917.8, 1044.2, 657.9, 423.7 | 0.909 | 0.000 | 0.000 |
| rust / direct / 4 | 1417.4, 1661.1, 787.6, 1022.6 | 1513.3, 1620.5, 1046.5, 964.6 | 1.049 | 0.000 | 0.000 |
| rust / h2 / 1 | 766.7, 879.2, 421.8, 527.8 | 879.7, 686.2, 513.7, 422.1 | 0.927 | 1.130 | 1.087 |
| rust / h2 / 4 | 648.9, 779.7, 494.0, 455.9 | 782.1, 822.0, 422.9, 363.0 | 1.054 | 1.333 | 1.227 |
| rust / h3 / 1 | 158.5, 133.2, 108.8, 105.0 | 171.8, 178.2, 103.5, 113.7 | 1.180 | 9.133 | 7.707 |
| rust / h3 / 4 | 113.5, 159.1, 87.2, 115.3 | 164.2, 174.5, 113.6, 105.8 | 1.215 | 9.420 | 7.727 |

Minimum recorded free disk by phase: baseline 34.294 GiB, candidate 33.199 GiB, candidate-repeat 33.805 GiB, baseline-repeat 33.697 GiB.

## Caddy candidate on macOS 15

Each cell lists the four case observations in phase/case order, in MiB/s.
The other server is unchanged; direct rows bypass the explicit Relay.
Ratios compare medians and are descriptive, not causal speedup estimates.

| Server / mode / concurrency | Baseline observations | Candidate observations | Ratio | Baseline CPU s/GiB | Candidate CPU s/GiB |
| --- | --- | --- | ---: | ---: | ---: |
| caddy / direct / 1 | 653.1, 653.8, 690.0, 642.6 | 734.4, 607.2, 679.4, 666.1 | 1.030 | 0.000 | 0.000 |
| caddy / direct / 4 | 653.1, 612.9, 713.9, 707.8 | 851.5, 784.5, 814.3, 779.0 | 1.175 | 0.000 | 0.000 |
| caddy / h2 / 1 | 282.8, 287.1, 342.8, 297.4 | 346.5, 309.5, 349.7, 346.0 | 1.185 | 2.940 | 2.757 |
| caddy / h2 / 4 | 304.0, 307.6, 297.9, 328.2 | 306.7, 355.2, 283.1, 331.9 | 1.044 | 2.957 | 2.720 |
| caddy / h3 / 1 | 108.2, 109.8, 113.5, 115.1 | 114.5, 123.6, 124.9, 115.5 | 1.071 | 9.450 | 8.660 |
| caddy / h3 / 4 | 102.0, 105.8, 111.6, 118.0 | 117.9, 120.3, 109.7, 102.4 | 1.047 | 9.413 | 8.767 |
| rust / direct / 1 | 622.7, 588.0, 614.0, 622.7 | 678.8, 695.3, 743.4, 678.9 | 1.111 | 0.000 | 0.000 |
| rust / direct / 4 | 740.4, 737.7, 788.3, 780.9 | 677.7, 785.0, 724.6, 561.0 | 0.922 | 0.000 | 0.000 |
| rust / h2 / 1 | 338.9, 385.4, 365.5, 371.4 | 379.1, 387.5, 391.1, 392.0 | 1.057 | 2.207 | 2.117 |
| rust / h2 / 4 | 345.9, 372.4, 318.6, 347.2 | 389.7, 390.5, 397.7, 389.2 | 1.126 | 2.400 | 2.167 |
| rust / h3 / 1 | 119.0, 120.7, 124.6, 121.5 | 118.9, 136.2, 137.5, 131.7 | 1.106 | 7.783 | 7.240 |
| rust / h3 / 4 | 121.3, 120.4, 122.6, 125.1 | 121.6, 138.9, 133.9, 132.1 | 1.090 | 7.573 | 7.137 |

Minimum recorded free disk by phase: baseline 43.221 GiB, candidate 43.177 GiB, candidate-repeat 43.071 GiB, baseline-repeat 43.063 GiB.

## Original-binary H3 stall captures

Diagnostic commit: `3857bc2fac674065205ccb9032c8f51c8cb82d05`.
Each host attempts 96 download cases / 336 samples / 48 rejection controls per
binary. All rejection controls and all independent Go controls pass.

| Host | Run | Verified ZIP SHA256 |
| --- | --- | --- |
| macOS 15 | 43491697222 | `87c9211cbb061c377b1ad4fefe07f5b3b1e486990649567a40d6b4166d05e5e0` |
| macOS 27 | 43491680899 | `52bd3aff3615b36cdc9988cea738fb5a168fa3a99921b296b97172b0c9b08bd4` |

| Host / phase | Failed case | Minimum free disk GiB |
| --- | --- | ---: |
| macOS 15 / baseline | caddy-0-h3-67108864-4-download | 42.734 |
| macOS 15 / candidate | caddy-10-h3-67108864-4-download | 42.222 |
| macOS 27 / baseline | caddy-2-h3-67108864-4-download | 33.267 |
| macOS 27 / candidate | None | 32.851 |

Each failed case has four simultaneous native timeouts. Four snapshots show
four server goroutines waiting in `quic-go.SendStream.write`, with no origin
write progress for approximately 47 seconds. macOS 15 retains small ongoing
bidirectional UDP traffic and zero socket queues. The macOS 27 filtered UDP
capture is empty, so its queue state is unknown. These observations rule out
ENOSPC for these three stalls but do not establish flow-credit exhaustion,
packet loss, a scheduling defect, or which endpoint is responsible.

## Extended flow observations

Diagnostic commit: `9f31ea60ba0915c1b193863cc364b200369ea7e6`.
macOS 27 run 43495255618 fails; its ZIP SHA256 is
`88f6886388a188a76d01e3ebe8c1d5c43a4f630231def4f10446f486b3c7fdc8`.
Source, observer and prepared-Go identities match. Five concurrent download
stalls retain exact equality between peer MAX_DATA, total observed stream
sending offsets and the last DATA_BLOCKED limit. All four data streams retain
individual credit; no STOP_SENDING or FIN is observed before cancellation.

| Phase / case | Connection limit = observed offset sum (bytes) | Stable equality (seconds) | Remaining stream credit, IDs 0 / 4 / 8 / 12 (bytes) |
| --- | ---: | ---: | --- |
| baseline / caddy-9-auto-67108864-4-download | 106457328 | 80.20 | 2011905 / 2009395 / 1298877 / 1305428 |
| candidate / caddy-0-h3-67108864-4-download | 218037170 | 80.26 | 1287832 / 928944 / 938459 / 937082 |
| candidate / caddy-11-auto-67108864-4-download | 174080916 | 80.33 | 1994219 / 1476275 / 1178175 / 1187240 |
| candidate / caddy-11-h3-67108864-4-download | 156184531 | 80.41 | 1541970 / 1542224 / 1539833 / 1541328 |
| candidate / caddy-12-h3-67108864-4-download | 157092454 | 80.61 | 1221447 / 1225489 / 1210420 / 1224074 |

This establishes connection-level credit exhaustion in these five observations,
not why receiver credit updates stopped. Maximum acknowledged packet numbers
do not prove every preceding packet arrived. A zero loss-declaration counter
in two cases does not prove zero network loss. Instrumented timings are not
performance measurements.

The macOS 27 baseline collects 125 positive cases / 436 samples / 64 rejection
controls; three later H3 serial cases fail immediately with generic -1005, and
three following parallel cases are absent. Three expected credential controls
also fail to establish their expected error. Candidate collects 128/448/64,
with four four-stream timeouts and all rejection controls passing.

macOS 15 run 43495250468 attempt 1 fails hosted runner allocation without
executing tests. Attempt 2 fails after collecting 125/436/64 per binary, with
three short H3 setup failures and four incorrect credential-rejection results
per phase; no long download stall is reproduced. ZIP SHA256:
`226091f1cbef0b8f480d073576074456079dd6738595983020c404e5b2be62c5`.

All nine late short setup failures across these three phases occur with exactly
64 existing data-carrying H3 connections in the trace intervals, matching the
configured per-client cap of 64. The observer does not retain closure error
codes, so this is a strongly matching capacity observation rather than a
captured closure reason. No connection cap is increased. These failures remain
separate from the five long connection-credit stalls.

The next experiment, run 43500071883, keeps the same pinned 4954911 source and
prepared Go in both arms. A diagnostic overlay repeats accurate DATA_BLOCKED
metadata instead of idle keepalive PING when connection credit is exhausted
and data remains queued. Existing cadence, credit, quotas and security policy
are preserved. Both arms use 12 rounds to avoid the known extended-fixture
connection accumulation. Local strict-TLS credit/resumption controls and race
checks including H1/H2/H3 64 MiB transfers pass. Native execution completes
with overall failure because the control arm stalls; this is not a production
change or accepted repair.

Artifact 14075426349 ZIP SHA256:
`47ead287972a26f3a2fa8135dcd7f6888c7ab02b234ca5ab81dd741a07510b90`.
Both arms collect 96 positive cases / 336 samples / 48 exact rejection
controls. All source, overlay, prepared-Go and executed-binary checks pass.
Minimum free disk is 33.188 / 32.748 GiB. All six race-enabled independent Go
controls pass, covering bounded credit/resumption, H1/H2/H3 transfers and 24
concurrent tunnels. The deliberate 16,384-byte credit control observes one
notification without the overlay and seven with it, then verifies all
131,072 resumed bytes under strict TLS.

Control case `caddy-2-auto-67108864-4-download` times out at 120.115 seconds.
Observed MAX_DATA, sent stream offsets and DATA_BLOCKED limit all equal
22,950,380 bytes across five blocked snapshots spanning 80.236 seconds.
The DATA_BLOCKED counter stays at two during that interval. The periodic arm
passes every case, but its longest is only 4.444 seconds. Neither arm records
a snapshot-to-snapshot increase in the notification counter at unchanged
connection credit. There is no native evidence of the experimental branch
rescuing a stall; a passing intermittent run is insufficient causal proof.
Unchanged repeats 43503924416 (macOS 15) and 43503936645 (macOS 27) both
fail with periodic-arm stalls; their retained results are detailed below.

## Balanced H2 follow-up

Run 43497806792, diagnostic `fc02572f8f52339deb8254bb1032d9a601b988e6`,
builds both executables before eight ABBABAAB phases. All 128 cases, 3,072
samples and 128 exact rejection controls pass; 209 source inputs and all
repeated binary/control identities match. It transfers 192 GiB. ZIP SHA256:
`1cde07a343627f22dcf5c40075e9832793ccda9042f3b2677fb1580abed31b45`.

The following eight observations per binary preserve the raw distribution.
Rust serial H2 remains a performance concern, with a median ratio of 0.837
versus unchanged Caddy 0.958 and direct Rust 0.875. This is not a no-regression
acceptance. Previous unit, UDP and H3 download failures remain unchanged.

| Server / mode / concurrency | Baseline MiB/s observations | Candidate MiB/s observations | Ratio | Baseline CPU s/GiB | Candidate CPU s/GiB |
| --- | --- | --- | ---: | ---: | ---: |
| caddy / direct / 1 | 686.0, 669.1, 502.3, 762.6, 1031.9, 1031.2, 1055.9, 1034.5 | 740.8, 694.1, 704.9, 806.7, 796.8, 707.5, 996.2, 634.9 | 0.807 | 0.000 | 0.000 |
| caddy / direct / 4 | 899.6, 1002.6, 817.1, 1089.6, 1583.7, 1595.8, 1493.0, 1628.3 | 1016.0, 878.6, 1183.9, 1067.4, 1529.4, 1065.0, 1297.4, 879.2 | 0.826 | 0.000 | 0.000 |
| caddy / h2 / 1 | 472.9, 466.5, 483.5, 492.5, 708.6, 766.8, 744.6, 649.8 | 430.6, 550.0, 412.7, 551.6, 566.6, 544.2, 644.1, 455.3 | 0.958 | 1.280 | 1.453 |
| caddy / h2 / 4 | 432.8, 583.4, 481.8, 420.5, 628.8, 675.4, 714.6, 745.3 | 512.5, 531.3, 487.7, 713.8, 476.6, 534.5, 502.5, 441.8 | 0.837 | 1.287 | 1.523 |
| rust / direct / 1 | 700.6, 603.1, 497.2, 708.8, 1028.6, 1024.6, 1045.5, 963.6 | 654.6, 735.8, 639.4, 732.4, 755.8, 731.2, 922.5, 595.0 | 0.875 | 0.000 | 0.000 |
| rust / direct / 4 | 960.1, 895.7, 558.6, 949.7, 1578.4, 1563.7, 1476.4, 1575.9 | 943.2, 1146.0, 1209.2, 1071.5, 909.8, 997.6, 1635.0, 1234.2 | 0.910 | 0.000 | 0.000 |
| rust / h2 / 1 | 658.0, 449.8, 350.5, 357.8, 764.6, 566.0, 819.7, 819.9 | 469.4, 425.8, 532.4, 492.0, 454.7, 579.2, 834.6, 806.8 | 0.837 | 1.027 | 1.393 |
| rust / h2 / 4 | 385.1, 389.5, 404.2, 393.4, 720.6, 705.0, 756.6, 608.6 | 481.3, 480.0, 461.4, 525.2, 633.9, 351.6, 752.9, 661.6 | 0.994 | 1.347 | 1.420 |

## Isolated Linux TLS upload control

This compares original Rustls 0.23.46 with the patched candidate using identical
dependency locks and a harness that verifies every plaintext byte, strict
TLS 1.3 AES-128-GCM and CPU affinity 0. Both executables are built before eight
balanced 4 GiB observations; two 512 MiB warmups precede measurement. It is a
memory-only Linux x86_64 control, not HTTP/2, Apple or field acceptance.

| Variant | Encryption MiB/s observations | Decryption MiB/s observations |
| --- | --- | --- |
| baseline | 6417.0, 6979.6, 7064.7, 7200.5 | 5107.4, 5831.0, 5682.5, 5881.6 |
| candidate | 7197.3, 7081.0, 7233.6, 7236.1 | 5851.7, 5792.6, 5957.9, 5899.1 |

Candidate median ratios are 1.028 for encryption and 1.021 for decryption.
No decline is reproduced in this isolated control; the native H2 concern remains.

harness SHA256: `eb2a97bb3e1d7f094ad1bb8fd3ec6902b1e0172486da9235fdbd31a5ea31f8ae`.

dependency lock SHA256: `d7ac7344f211a9788858f2724e75da0a3525748dd616f5cd7158371ee59e718f`.

baseline binary SHA256: `83b0e5768f158462406923a1428a562942ebd8932512a2297774208d7178befc`.

candidate binary SHA256: `f65f3e2c24bd1e2fc080ef28c0ecfab5fd6bab29e163884201e9467a3b14fca7`.

The balanced native run's unchanged direct probe in the Rust-labelled group
has a median CPU/GiB ratio of 1.357. Rust H2 probe/server CPU ratios are
1.258 / 1.357; unchanged Caddy H2 server CPU ratio is 1.135. These are actual
control variations, not a complete causal explanation of the candidate's
throughput difference. Native serial H2 acceptance remains open.

## Blocked notification timer isolation

The first notification experiment's deadline is based on the most recently
received packet. Three local strict-TLS reproductions with client keepalive
10 ms and server keepalive 50 ms observe only one notification in 400 ms;
all three fail the expected repetition check. Peer activity can indefinitely
postpone this experimental notification. In the native control stall, packet
counters continue increasing by approximately one packet per direction every
20 seconds while connection credit and the blocked counter remain fixed.
The aggregate capture does not identify those packets' frame types.

A diagnostic-only follow-up, run 43504865652 at
`c671f010bb76c6b6634c5002c86a9accc0f3364e`, adds a blocked-duration clock that
is reset when receiver credit increases, not on unrelated peer traffic. It
uses the same keepalive interval and existing congestion/timer path. It sends
accurate metadata only when credit is exhausted and data remains queued;
receiver credit, connection caps, timeouts, TLS and authentication are preserved.
The original Apple schema and RFC 9000 sections 4.1-4.2 were checked before
the overlay edits. Production sources are unchanged.

Local race-enabled tests observe eight notifications with a quiet peer and
eight with an active peer, at the same 16,384-byte credit. Disabling server
keepalive leaves exactly one notification. Each test then verifies 131,072
resumed bytes and verifies notifications cease after transfer completion.
Unchanged controls pass all three modes three times with one notification
each. Race-enabled H1/H2/H3 64 MiB bidirectional transfers and early datagrams
also pass. The completed native outcome below rejects this as a repair.

Patched connection SHA256:
`f8538cb15e4b04c39f7a1305b5a191a6eda1192f859c33ac5a9a1cbb150b1018`.

Strict flow-control test SHA256:
`ef77fb0fa351a0c45edb00376aa047153164def7a4ec9083d3878545e3bc8b00`.

The blocked-duration overlay's complete Linux root-package race suite passes
567 test/subtest events and 183 top-level tests in 499.852 seconds. One external
E2E test is skipped, not passed. This is the diagnostic overlay, not a product
change. Log SHA256:
`b37cad4cff53f5463cfef7f53626e336d011cb09a8c8d3fafa127d09b13b9644`.

Original idle-timer repeat 43503924416 on macOS 15 completes with failure.
Control passes 96 cases / 336 samples / 48 exact rejections; periodic collects
the same counts but one four-stream H3 case times out at 120.531 seconds.
Peer MAX_DATA and summed offsets stay at 139,164,128 bytes for 80.297 seconds;
the DATA_BLOCKED counter stays at 12. Source/overlay identities pass and free
disk remains above 42.32 GiB. Independent periodic-arm H1/H2/H3 bulk-data
subtests pass, but their parent test fails with one tunnel still open at its
final assertion. This cleanup failure is retained and investigated separately;
it is not relabeled a pass. Artifact 14075573887 ZIP SHA256:
`ded70b5800fe5db9ddc0269eb333c798a57c47d38a012fbb6c0a871bc991e8e7`.

## Large-transfer cleanup assertion

The macOS 15 parent-test failure prompted an unchanged-server control. With
GOMAXPROCS=4, 50 race-enabled repetitions pass. With GOMAXPROCS=1, 47 pass and
three retain the original failure. A diagnostic observation added only after
the failed assertion records the counter falling from one to zero after
1.269, 1.164 and 1.152 ms. Each original failure remains a failure. This
demonstrates that client close does not synchronize the server handler's
deferred quota release. It does not retroactively measure cleanup duration
in the native failure.

Caddy follow-up `795912b` changes only TestLargeTransfers: wait at most two
seconds for the counter to become zero, then retain the failure if it does
not. The same single-worker race test passes 50/50 with the correction, and
64 MiB bidirectional H1/H2/H3 integrity checks pass. Payload assertions and
server runtime are unchanged. Apple Relay schema and RFC 9110 section 9.3.6
were rechecked before editing. No native artifact is relabeled as passing;
those artifacts use the earlier test. The current production inputs still
match the native candidates; this one newer test file is recorded separately
in the source correspondence manifest.

The macOS 15 Go controls in both arms also retain the same UDP socket-buffer
observation: requested 7,168 KiB, actual 6,144 KiB, initially 768 KiB. This is
a measured platform limit relevant to interpreting loopback throughput, not
an established cause of connection-credit exhaustion. No host socket limit
is changed. Packet-loss declarations in a trace do not measure exact wire
loss, and the earlier credit stalls include traces with no loss declarations.

The macOS 27 repeat 43503936645 also completes with failure. Control passes
96 cases / 336 samples / 48 exact rejections. Periodic has the same counts
with two four-stream H3 timeouts at 120.886 and 120.706 seconds. Connection
credit stays at 80,858,937 and 43,527,077 bytes for 80.307 and 80.359 seconds;
DATA_BLOCKED counters stay at two and four. Both traces have zero recorded
loss declarations, which does not prove zero wire loss. All six independent
Go controls and all exact rejection controls pass, and all source/overlay
identities match. Free disk remains above 32.53 GiB. Artifact 14076591929
ZIP SHA256:
`b0ad5dafc39c72432a3e067fc947294970377630226839733d450aa6e0a73325`.
Together with the local active-peer reproduction and macOS 15 repeat, this
rejects the original idle-timer experiment as a repair. The blocked-duration
follow-up 43504865652 is evaluated separately below.

## Final blocked-duration result

Run 43504865652 completes with failure. Both arms collect 96 positive cases /
336 samples / 48 exact rejection controls. Each arm has one four-stream H3
download timeout: control 120.409 seconds and periodic 120.346 seconds. All
six race-enabled independent Go controls pass, including quiet-peer, active-peer
and disabled-keepalive credit/resumption controls, H1/H2/H3 bulk transfers and
24 concurrent tunnels. All source, overlay, prepared-Go and binary identities
match. Free disk stays above 32.54 GiB in each arm. Artifact 14077497664 ZIP
SHA256:
`c0ff110c6aa0b0055833edb0ba4f2d5988ad949c8b52942563019a22a1f95a23`.

Control remains blocked at 70,837,980 bytes for 80.377 seconds with notification
count four. The periodic arm stays at 118,468,148 bytes for 89.994 seconds,
while its DATA_BLOCKED count grows from 11 to 16. All four data streams retain
individual credit and have no FIN or STOP_SENDING before cancellation. No
valid periodic case exceeds 4.147 seconds; there is no hidden slow recovery
being counted as a success. The periodic blocked snapshots are preserved here:

| UTC timestamp | DATA_BLOCKED count | Packets sent | Packets received | Largest sent 1-RTT | Largest ACKed 1-RTT |
| --- | ---: | ---: | ---: | ---: | ---: |
| 2026-11-13T21:08:10.490244Z | 11 | 84517 | 8704 | 84521 | 84521 |
| 2026-11-13T21:08:20.456465Z | 12 | 84519 | 8704 | 84523 | 84521 |
| 2026-11-13T21:08:40.583847Z | 14 | 84521 | 8707 | 84526 | 84526 |
| 2026-11-13T21:08:50.458733Z | 15 | 84523 | 8707 | 84528 | 84526 |
| 2026-11-13T21:09:10.609327Z | 15 | 84523 | 8709 | 84528 | 84528 |
| 2026-11-13T21:09:20.464367Z | 16 | 84525 | 8709 | 84530 | 84528 |
| 2026-11-13T21:09:40.483776Z | 16 | 84525 | 8711 | 84530 | 84530 |

The send counter establishes repeated metadata emission, while peer credit
remains unchanged. Aggregate largest-ACK values do not establish delivery of
every preceding packet or explain receiver behavior. Zero recorded loss
declarations do not prove zero wire loss. This experiment rejects repeated
blocked notification at the tested interval as a repair for the reproduced
stall. It is not promoted into product code. Sender credit limits, quotas and
security policy remain intact. Why peer credit updates stop, native H2 UDP
63-byte truncation, the Rust serial H2 performance concern and actual installed
profile/iPhone/WAN acceptance remain open.
