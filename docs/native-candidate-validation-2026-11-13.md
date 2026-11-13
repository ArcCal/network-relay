# Native candidate validation, 2026-11-13

Snapshot updated 2026-11-13 20:25 UTC. Validation remains in progress. The user authorizes candidate branch commits
and pushes, with no merge into main and no release or production deployment.
Both repositories use `audit/security-performance-candidate-20261113`.

The [evidence snapshot](native-candidate-evidence-2026-11-13.md) preserves
verified artifact digests, focused throughput distributions and captured stall
counts after hosted artifacts expire.

## Exact inputs

| Repository | Baseline | Candidate |
| --- | --- | --- |
| network-relay | `44fd9515e0f9b90d2af7a186fa7e169458d93b70` | `5a7c2c00404dd77ee5a95af2570663f42263e786` |
| caddy-network-relay | `a691271ac5362cec324231234f38990680630fda` | `169dc2f66416c30893a90c8abd9f6bd193429cd6` |

Caddy follow-up `49549117e643ad4a05bb1a639ca17cf8521a4356` changes only the early
datagram test's synchronization. Its runtime inputs match 169dc2f exactly.
All commits use the required anonymous author/committer and are unsigned.

The authorized Rust workflow input reconstructs 209 exact source files from
54,448 encoded bytes. Its compressed SHA256 is
`aef849921e4e214ea816ef4986acc333460aa8e823036f931f5570665f2074d0`.
Six additional unchanged h3-quinn inputs match the baseline independently.
The Caddy workflow checks the full pinned commit and hashes all 975 tracked
files. The client build checks all 1,031 tracked files of the main candidate.
The diagnostic branch changes only its workflow, Swift probe and Python driver.

## Execution record

| Runs | Scope | Current result |
| --- | --- | --- |
| [43475156977](https://github.com/ArcCal/network-relay/actions/runs/43475156977) / [43475164225](https://github.com/ArcCal/network-relay/actions/runs/43475164225) | Initial Rust comparison, macOS 27 / 15 | Both baseline phases pass 96 positive cases, 608 samples and 16 negative controls. Candidate reconstruction fails because shallow checkout lacks the baseline commit. |
| [43476893492](https://github.com/ArcCal/network-relay/actions/runs/43476893492) | Rust reconstruction and native units, macOS 27 | All 209 input hashes match. Baseline matrix passes. Candidate units: 161 passed, 12 failed. Candidate throughput did not run. |
| [43476903821](https://github.com/ArcCal/network-relay/actions/runs/43476903821) | Same initial rerun on macOS 15 | Cancelled while queued and replaced by the complete baseline/unit comparison below; not a pass. |
| [43478717847](https://github.com/ArcCal/network-relay/actions/runs/43478717847) / [43478722436](https://github.com/ArcCal/network-relay/actions/runs/43478722436) | Rust full baseline units and TCP matrix | macOS 27: baseline units 159 passed, same 12 failures; baseline Caddy H3 download times out. Candidate did not run. macOS 15 cancelled while queued. |
| [43476585602](https://github.com/ArcCal/network-relay/actions/runs/43476585602) | Caddy macOS 27 full race suite and ABBA matrix | Race suite fails one early-datagram test; 558 test/subtest events pass, two deployment tests are skipped. ABBA phases did not run. |
| [43476603192](https://github.com/ArcCal/network-relay/actions/runs/43476603192) | Caddy macOS 15 full race suite and ABBA matrix | Race suite passes 559 events / 180 top-level tests; two deployment tests skipped. Baseline and candidate each pass 96/608/16. Candidate-repeat H3 download times out; final baseline-repeat missing, ABBA incomplete. |
| [43479666699](https://github.com/ArcCal/network-relay/actions/runs/43479666699) / [43479672591](https://github.com/ArcCal/network-relay/actions/runs/43479672591) | Initial synchronized controls | Both cancelled while queued and superseded; not passes. |
| [43478006183](https://github.com/ArcCal/network-relay/actions/runs/43478006183) / [43478011129](https://github.com/ArcCal/network-relay/actions/runs/43478011129) | Caddy baseline/candidate UDP boundaries and inner HTTP/3 | Both fail; all four phase/suite outcomes retained. Details below. |
| [43479807369](https://github.com/ArcCal/network-relay/actions/runs/43479807369) | NF and RS candidate native build entrypoints on macOS 27 | Pass; all 1,031 source hashes match. NF: 115 Rust, 71 Swift, 17 native lifecycle checks. RS: 132 Rust. Four/five fixture-dependent Rust tests remain ignored. |
| [43480886469](https://github.com/ArcCal/network-relay/actions/runs/43480886469) / [43480891905](https://github.com/ArcCal/network-relay/actions/runs/43480891905) | Rust complete-phase collection, macOS 27 / 15 | Both OS versions: baseline and candidate each pass 96/608/16; full units fail the same 12 tests (159/161 passed). Both workflows fail their final unit gate. |
| [43480897922](https://github.com/ArcCal/network-relay/actions/runs/43480897922) / [43480903425](https://github.com/ArcCal/network-relay/actions/runs/43480903425) | Caddy synchronized controls, full race and ABBA, macOS 27 / 15 | Both full race suites pass; synchronized variants pass 20/20 each. Both ABBA runs fail H3 downloads. macOS 27 baseline-repeat fails; macOS 15 baseline Rust and both Caddy candidate phases fail. |
| [43482779652](https://github.com/ArcCal/network-relay/actions/runs/43482779652) / [43482785124](https://github.com/ArcCal/network-relay/actions/runs/43482785124) | Baseline/candidate H3 download flow observation, macOS 27 / 15 | Both OS versions pass 32/112/16 per phase, with no stall reproduced. Instrumented timings excluded. |
| [43484311466](https://github.com/ArcCal/network-relay/actions/runs/43484311466) | Rust four-phase ABBA on macOS 27 | All 384 positive cases / 2,432 samples pass. One baseline trust rejection reports generic connection loss instead of the expected certificate error; 63/64 exact negative controls pass. Same 12 unit failures remain. Overall failure. |
| [43488457625](https://github.com/ArcCal/network-relay/actions/runs/43488457625) | Initial unchanged-binary watchdog, macOS 27 | Baseline passes 96/336/48 and both Go controls; no stall captured. Candidate evidence writing and Go linking fail with filesystem ENOSPC. Incomplete environment failure, not candidate acceptance. |
| [43490427677](https://github.com/ArcCal/network-relay/actions/runs/43490427677) | Initial watchdog, macOS 15 | Cancelled during build and superseded after the macOS 27 disk failure; not a pass. |
| [43491444643](https://github.com/ArcCal/network-relay/actions/runs/43491444643) | Initial disk safeguard workflow | Rejected before execution because `runner.temp` is unavailable in job-level `env`. Fixed using a runner step; actionlint then passes. |
| [43491680899](https://github.com/ArcCal/network-relay/actions/runs/43491680899) / [43491697222](https://github.com/ArcCal/network-relay/actions/runs/43491697222) | Watchdog with bounded disk usage, macOS 27 / 15 | Both fail on native H3 stalls: macOS 27 baseline; macOS 15 baseline and candidate. All independent Go controls pass. Minimum phase disk reserves exceed 32 GiB; candidate source and controls match. |
| [43494363421](https://github.com/ArcCal/network-relay/actions/runs/43494363421) / [43494379234](https://github.com/ArcCal/network-relay/actions/runs/43494379234) | Sustained uploads, Rust/macOS 27 and Caddy/macOS 15 | Both pass all four ABBA phases: 96/2304/64 per run. Source, controls, payloads and disk reserves independently verified; performance attribution remains limited. |

The 12 Rust unit failures exercise code and tests already present in the
baseline: three Linux-only UDP cases, a Linux kernel minimum-buffer assumption,
and eight website cases requiring `/proc/self/fd`. README documents Linux-only
server operation, with Mac support for `check` and `profile`. This is not a
reason to count the failed native suite as passing or weaken file-path and UDP
safety checks. The complete-phase runs retain both unfiltered unit suites and their exact
failure sets while collecting TCP evidence independently.

The Caddy test formerly assumed stream registration after five milliseconds.
RFC 9297 section 2.1 allows dropping a datagram arriving before registration.
The revised test observes actual authentication admission with a fresh secret,
holds the existing authentication slots, verifies that no target datagram
escapes before authentication, and retains the single-packet, three-second
echo requirement. Twenty local race repetitions pass. Original-test failures
and the discarded test-gate experiment's race reports remain separate records.

The NF and RS run uses their actual production build entrypoints with the
existing fresh-source handoff guard, Rust 1.99.1 and Xcode 27. Both arm64 app
bundles pass strict ad-hoc signature verification; archive and executable
hashes are retained. RS has 132 native Rust passes versus 133 in the earlier
Linux UI-typecheck suite because its simulated network-change callback test
is explicitly compiled only on non-macOS hosts. The native NF controls cover
trust callback outcomes, recoverable/terminal connection states, real local
TCP and SOCKS5 traffic, cancellation, instance isolation and log secrecy.
They do not replace remote Network.framework interoperability, GUI or
sleep/wake acceptance. No system trust-store fixture is installed by this run.

Completed Rust comparisons on macOS 27 and 15 each independently verify all
209 candidate inputs and both full TCP matrices. The same 12 baseline unit
failures remain in the candidate, with two additional passing Capsule tests.
Unchanged Caddy/direct controls show substantial timing drift; for example,
Caddy H2 serial-upload throughput ratios across the two phases are 0.655 and
0.620 despite the Caddy binary being identical. Rust throughput ratios cannot
therefore be treated as causal performance improvements or regressions from
this run alone. Run 43484311466 adds reversed binary order with the same frozen
binaries. All native unit failures remain visible in the final workflow gate.

The completed Rust ABBA run independently verifies all 209 source inputs and
unchanged control binaries across four phases. All positive cases pass, and
both candidate phases plus baseline-repeat pass their 16 rejection controls.
Initial baseline `rust-0-h3-reject-trust` returns `NSURLErrorDomain -1005`
instead of the required `-1202`, with zero origin requests. This does not show
a trust bypass, but also does not establish the expected certificate rejection;
the analysis retains a failed negative control and does not certify the ABBA.
The two native unit suites retain exactly the same 12 failed test names.

Timing concerns remain open. In this Rust ABBA, H2 serial and parallel upload
median ratios are 0.878 and 0.875, while the unchanged Caddy control ratios are
1.474 and 1.182. Individual Rust serial-upload observations range from 301 to
705 MiB/s in the candidate. In the Caddy macOS 27 ABBA, H3 parallel-upload
median throughput ratio is 0.815, while server CPU per GiB falls from 11.68 to
10.96 seconds. Caddy H2 serial-download ratio is 0.847, almost identical to
the unchanged Rust control's 0.845. These short loopback transfers, control
drift, limited observations and retained failures prevent a blanket speedup or
no-performance-regression claim. Security fixes and allocation savings are
supported separately; end-to-end performance acceptance remains incomplete.

## Protocol failures and new download-stall evidence

On macOS 27, baseline and candidate UDP each pass 35/36 positive cases and
4/4 rejection controls; both fail H2 UDP payload length 63. Inner HTTP/3
baseline passes 36 of 43 attempted positive cases; candidate passes 34 of 40.
Each has two H2 upload timeout cases. The other failures select inner H2,
which is not counted as successful inner H3. Both pass 8/8 rejection controls.

On macOS 15, baseline and candidate UDP each pass 33/36 positives and 4/4
rejections. Both fail H2 UDP 63 and the H3/auto 1200-byte cases. Inner HTTP/3
each passes 22 of 32 attempted positives and 8/8 rejections. Each has two
H2 upload timeout cases and eight cases selecting inner H2. Missing cases
following a failed case are not passes. Differences in fallback case names
alone do not establish a candidate regression. All 975 source hashes and
prepared-Go policy checks pass independently on both operating systems.

A distinct TCP download stall occurred on the unchanged Caddy baseline in
run 43478717847: four concurrent 64 MiB downloads over one native H3 Relay
connection all time out at about 120.85 seconds, after roughly 44-47 MiB per
stream had been forwarded. The TLS origin is HTTP/1.1; this is separate from
the H2 UDP Capsule defect. Candidate-repeat on macOS 15 in run 43476603192
also has one 64 MiB serial download timeout over the actual H3 auto route;
two other samples in that case succeed. Responsibility remains unresolved.

After reviewing RFC 9000 sections 4.1-4.3 and Apple's Relay schema, the flow
observer records peer flow-control limits, stream offsets, packet/ACK progress
and bounded nonzero RTT/congestion observations. It changes no transport
limits, authentication or TLS verification. It collects no payloads, headers
or keys. Go qlog uses partial metric updates; the retained nonzero metrics
are explicitly not asserted to represent current bytes in flight. Local
race-enabled early-datagram and 16 MiB bidirectional H1/H2/H3 controls pass;
independent inspection confirms advancing peer credit and stream/ACK offsets.
macOS 27 observation passes 32 positive cases, 112 samples and 16 rejections
per binary. Both produce 24 trace files; 377 snapshots have no truncation or
recorded offset-over-credit indications. The observer and prepared-Go policy
match local inputs. No stall is reproduced, so this does not close the earlier
timeouts or identify their cause. macOS 15 also passes 32 positive cases, 112 samples and 16 rejections per
binary, with 24 trace files each and verified observer/source/policy inputs.
Neither observation run reproduces the stall. These instrumented results are
not benchmark evidence.

The complete Caddy macOS 27 run 43480897922 retains all four phases. Its
baseline, candidate and candidate-repeat each pass 96 cases / 608 samples /
16 rejections. Baseline-repeat attempts the same complete matrix, but all four
samples in `caddy-0-auto-67108864-4-download` time out after about 120.06 seconds.
The actual outer route is H3, on one connection, after 5,198,901-6,839,725 bytes
per stream are forwarded. This further unchanged-baseline reproduction is not
a fixed 44-47 MiB threshold. The full candidate race suite passes 559 events /
180 top-level tests, with two deployment-specific skips. Original early-datagram
controls pass 20/20 on baseline and 19/20 on candidate; both synchronized variants
pass 20/20. Original-test failures are retained, not relabelled as passes or
presented as a proven production repair.

The complete macOS 15 run 43480903425 also passes 559 race events / 180 top-level
tests, with the same two deployment skips. Original early controls pass 20/20
on baseline and 18/20 on candidate; both synchronized variants pass 20/20.
All four native phases and 64 rejection controls are retained. Initial baseline
has 95 attempted positive cases / 604 samples: the unchanged Rust H3 serial
download times out on its first sample, then its other two samples succeed.
The skipped four-way case following that failure is not a pass. Caddy candidate
and candidate-repeat each attempt 96 cases / 608 samples, but four concurrent
downloads on a single H3 connection time out in each phase. Baseline-repeat
passes 96/608/16. Caddy forwards 19,954,888-22,751,857 bytes per stream in the
first failed candidate case and 4,176,443-5,166,390 bytes in the second, with
only 0.63 and 0.21 CPU seconds over the respective 120-second waits.
This extends the intermittent stall observations to the unchanged Rust server;
it does not identify the responsible endpoint or establish a common cause.

Valid macOS 15 Caddy H3 serial/parallel-upload median ratios are 0.667/0.881;
the unchanged Rust controls are 0.840/0.967. The candidate serial-upload
observations span 85.8-202.6 MiB/s. Together with the macOS 27 parallel-upload
ratio, this remains an unresolved performance concern rather than an accepted
improvement. Failed and missing cases are excluded from timings and retained
as functional failures.

Because the uninstrumented baseline still stalls, run 43488457625 uses unchanged
binaries and gathers server stacks, client samples and filtered UDP socket
queues only after a transfer exceeds 15 seconds. Twelve bounded download rounds
per binary increase exposure without raising the 120-second request timeout.
The same native host also runs existing independent Go serial 64 MiB and
24-tunnel controls (64 MiB each way per tunnel, eight H3 streams on one connection)
on both pinned server sources. The latter passes locally in 6.950 seconds.
No transport limit or security policy is changed. The initial macOS 27 baseline
passes 96 download cases / 336 samples / 48 rejections and both Go controls,
without a stall capture. Candidate reaches 57 recorded positive cases / 199
samples before filesystem ENOSPC interrupts evidence writing. Its final server
log is empty; retained successful native reports cannot establish the missing
outer-route evidence. Both candidate Go controls fail while linking, before
test execution. The overall run fails. There is no retained disk telemetry to
identify what consumed space or explain earlier download stalls.

Diagnostic revision `3857bc2fac674065205ccb9032c8f51c8cb82d05` preserves exact
server binaries, prebuilds both independent Go test executables and removes only
the job-owned compilation caches before measurements. It requires 4 GiB free
initially and records a 2 GiB reserve before/after each positive case. The probe
explicitly removes its completed download file, and the driver owns and removes
each completed probe's temporary directory. These are diagnostic lifecycle
changes, not product fixes. Local checks validate the low-space failure record,
workflow expressions, shell/Python syntax and the prebuilt Go invocation with
64 MiB bidirectional H1/H2/H3 transfers. Both native reruns complete with
96 cases / 336 samples / 48 rejection controls per binary. All exact rejection
controls and all eight independent Go controls pass across the two hosts.
macOS 15 has one four-stream H3 timeout in each binary; macOS 27 has one in
baseline, while candidate passes. Every phase retains at least 32.85 GiB free;
macOS 15 retains at least 42.22 GiB. These three stalls are not ENOSPC failures.

Each stalled case has four snapshots showing four server goroutines waiting in
`quic-go.SendStream.write` at `send_stream.go:316`. The origin's write counters
do not advance for about 47 seconds. On macOS 15, client and server CPU are
idle, socket queues are zero and small amounts of bidirectional UDP traffic
continue. The macOS 27 filtered UDP capture is empty despite exit zero, so no
queue claim is made for that host. Native stack samples show the main thread
waiting for task completion and an idle worker; they do not expose enough of
Apple's network internals to assign fault. QUIC write waiting alone does not
prove exhausted flow credit or identify a scheduling/congestion defect.

Extended read-only flow runs 43495250468 / 43495255618 use 16 download rounds
per binary, both observers built before measurement, owned compilation-cache
cleanup and disk reserves. macOS 27 completes with five four-stream timeouts:
one baseline and four candidate. Every captured stall exhausts exactly the
peer's connection-level MAX_DATA while all four streams retain individual
credit. DATA_BLOCKED is observed and the equality persists for at least 80
seconds. This establishes the immediate flow-control blockage, not why peer
credit updates stop or which endpoint is responsible.

The longer fixture also accumulates 64 still-open H3 connections, matching the
per-client security cap. Late immediate setup failures occur in the macOS 27
baseline and both macOS 15 phases at that count. Their closure error code is
not retained, so attribution to the cap is strongly consistent but indirect.
The macOS 15 first attempt fails runner allocation; its completed retry has no
long download stall. Both extended comparisons fail; missing cases and
incorrect rejection errors remain failures. Exact counts and artifact digests
are preserved in the linked evidence snapshot.

Experiment 43500071883 tests periodic DATA_BLOCKED notifications at the
existing keepalive cadence using the same candidate source in both arms,
after RFC 9000 sections 4.1-4.2 and Apple schema review. It preserves receiver
credit, quotas and security checks. Local credit/resumption and race/bulk
controls pass; native execution is pending and no product repair is adopted.

Sustained upload runs 43494363421 (Rust/macOS 27) and 43494379234 (Caddy/macOS
15) both complete successfully. Each independently verified ABBA has 96 cases,
2,304 samples and 64 exact rejection controls, with 24 uploads of 64 MiB per
case across direct/H2/H3 routes and concurrency one/four. Rust's 209 and Caddy's
975 source inputs match, repeated binary hashes and unchanged controls match,
and minimum disk reserves are 33.19 / 43.06 GiB. Each host transfers 144 GiB.
Prior full unit and race outcomes are not rerun or relabelled by this matrix.

| Tested candidate | Route / concurrency | Baseline MiB/s | Candidate MiB/s | Ratio | Unchanged other-server ratio |
| --- | --- | ---: | ---: | ---: | ---: |
| Rust / macOS 27 | H2 / 1 | 647.2 | 599.9 | 0.927 | 1.050 |
| Rust / macOS 27 | H2 / 4 | 571.5 | 602.5 | 1.054 | 0.933 |
| Rust / macOS 27 | H3 / 1 | 121.0 | 142.7 | 1.180 | 0.818 |
| Rust / macOS 27 | H3 / 4 | 114.4 | 138.9 | 1.215 | 0.920 |
| Caddy / macOS 15 | H2 / 1 | 292.2 | 346.3 | 1.185 | 1.057 |
| Caddy / macOS 15 | H2 / 4 | 305.8 | 319.3 | 1.044 | 1.126 |
| Caddy / macOS 15 | H3 / 1 | 111.6 | 119.5 | 1.071 | 1.106 |
| Caddy / macOS 15 | H3 / 4 | 108.7 | 113.8 | 1.047 | 1.090 |

These are medians of four case observations per binary/configuration. The
previous Rust H2 parallel and large Caddy H3 upload declines are not reproduced
in this focused run. Rust H2 serial remains an unresolved timing concern;
unchanged Caddy H2 serial improves while tested Rust declines. On macOS 27,
unchanged Caddy H3 serial observations range from 103.0 to 218.8 MiB/s and
several direct controls also drift. On macOS 15, unchanged Rust H3 improves
more than the Caddy candidate. These controls prevent assigning all differences
to the candidate or claiming universal no-regression. All raw distributions and
server CPU/GiB are retained. This upload-only result does not close H3 download
stalls, native UDP failures, or installed-profile/WAN acceptance.

Run 43497806792 further isolates the unresolved Rust H2 serial concern. Both
executables are built before any measurements, then eight phases use
baseline/candidate order ABBABAAB with direct and H2 routes, concurrency one
and four, and 24 uploads of 64 MiB per case. The unchanged Caddy control,
source/binary checks, exact rejection controls and disk reserves remain. This
run completes successfully: 128 cases / 3,072 samples / 128 exact rejection
controls, all 209 source inputs and eight-phase binary/provenance checks pass,
with at least 33.55 GiB free. It uploads 192 GiB. Rust H2 serial median is
612.0 -> 512.2 MiB/s (ratio 0.837), versus unchanged Caddy 0.958 and direct
Rust 0.875. Rust H2 parallel ratio is 0.994. Server CPU/GiB for Rust H2 serial
rises from 1.027 to 1.393 seconds, while unchanged Caddy rises from 1.280 to
1.453. Both source and control distributions vary substantially. The repeated
serial concern remains unresolved; functional success is not performance
acceptance, and no previous failures are waived.

## Post-update local client interoperability

A separate Linux run rebuilds both current candidate servers and executes all
nine fixture-dependent RS/NF test names ignored by ordinary native builds.
RS passes both full server matrices, 80 concurrent H2 and H3 streams per
server, cancellation, two 125-second H3 soaks, and actual automatic fallback
when Caddy offers TCP only. NF's protocol core passes its server matrix,
13-second idle stream-0 check, 64 MiB large-transfer cases and simultaneous
H2/H3 persistent-flow checks spanning two probe renewals, against both servers.
All five fixture invocations succeed; 1,915 non-Markdown tracked input hashes
and both server binary hashes are unchanged across the run. NF uses its
explicit test-only rustls/Quinn bridge here. These results do not convert the
native ignored tests into native passes or certify GUI/WAN behavior.

## Interpretation rules

Each complete TCP phase contains 96 positive cases, 608 checked samples and
16 authentication/trust rejection controls, with opposite transport orders.
Independent analysis validates payload length/hash, upload acknowledgements,
native proxy metrics, timestamp-matched server CONNECT logs and zero origin
requests for rejected connections. Negative cases must report the expected
native error, not merely a nonzero process exit. Caddy comparisons use four
phases in baseline-candidate-candidate-baseline order. Rust comparisons keep
the same Caddy binary as a control. Timing distributions and control drift
must be inspected; an isolated ratio is not proof of a speedup or regression.

The Caddy candidate uses the reviewed prepared Go 1.27.4 TLS/HTTP policy with
an explicit GOROOT and local toolchain selection. Its policy manifest and
binary build information are retained. The stock baseline is identified
separately. A compiler success is not a race-suite or native-client pass.

These fixtures parse generated mobileconfig into explicit per-connection
native Relay configuration. They do not install system profiles or validate
physical iPhone, production WAN, GUI interaction, sleep/wake, or live WARP.
The separately reproduced native H2 63-byte Capsule truncation remains open;
TCP success does not repair or waive it. No payload guessing, parser
resynchronization, unknown-Capsule rejection or relaxed TLS verification is
introduced. See [the boundary report](native-relay-capsule-boundary-2026-11-13.md).

## Retained local evidence

- `/workspace/scratch/macos-resume/candidate-runs.json`
- `/workspace/scratch/macos-resume/shallow-reconstruction-proof.json`
- `/workspace/scratch/macos-resume/rust-macos-platform-failure-review.json`
- `/workspace/scratch/macos-resume/rust-candidate27-rerun-baseline-analysis.json`
- `/workspace/scratch/macos-resume/caddy-candidate27-failure-analysis.json`
- `/workspace/scratch/macos-resume/early-datagram-spec-review.json`
- `/workspace/scratch/macos-resume/early-datagram-slots-linux.log`
- `/workspace/scratch/macos-resume/caddy-candidate15-analysis.json`
- `/workspace/scratch/macos-resume/caddy-protocols15-analysis.json`
- `/workspace/scratch/macos-resume/caddy-protocols27-analysis.json`
- `/workspace/scratch/macos-resume/native-h3-parallel-download-stall.json`
- `/workspace/scratch/macos-resume/h3-flow-spec-review.json`
- `/workspace/scratch/macos-resume/h3-flow-observer-bulk.log`
- `/workspace/scratch/macos-resume/native-clients27-analysis.json`
- `/workspace/scratch/macos-resume/rust-candidate27-complete-analysis.json`
- `/workspace/scratch/macos-resume/rust-candidate15-complete-analysis.json`
- `/workspace/scratch/macos-resume/rust-abba27-analysis.json`
- `/workspace/scratch/macos-resume/caddy-candidate27-complete-analysis.json`
- `/workspace/scratch/macos-resume/caddy-candidate15-complete-analysis.json`
- `/workspace/scratch/macos-resume/caddy-candidate15-stall-observations.json`
- `/workspace/scratch/macos-resume/h3-flow27-analysis.json`
- `/workspace/scratch/macos-resume/h3-flow15-analysis.json`
- `/workspace/scratch/macos-resume/h3-flow27-credit-observations.json`
- `/workspace/scratch/macos-resume/h3-watchdog27-analysis.json`
- `/workspace/scratch/macos-resume/h3-watchdog27-disk-failure-review.json`
- `/workspace/scratch/macos-resume/prebuilt-go-control-validation.jsonl`
- `/workspace/scratch/macos-resume/final-client-interop-analysis.json`

Downloaded workflow artifacts are checked against GitHub's ZIP SHA256 before
extraction. Failed, skipped, cancelled and unexecuted checks remain distinct
from passes. This record is not an exhaustive certification of every possible
execution path or deployment.

Latest focused evidence:

- `/workspace/scratch/macos-resume/sustained-rust27-analysis.json`
- `/workspace/scratch/macos-resume/sustained-caddy15-analysis.json`
- `/workspace/scratch/macos-resume/h3-watchdog15-bounded-analysis.json`
- `/workspace/scratch/macos-resume/h3-watchdog27-bounded-analysis.json`
- `/workspace/scratch/macos-resume/bounded-h3-stall-stack-observations.json`
