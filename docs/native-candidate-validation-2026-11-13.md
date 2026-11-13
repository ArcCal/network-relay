# Native candidate validation, 2026-11-13

Snapshot updated 2026-11-13 19:05 UTC. Validation remains in progress. The user authorizes candidate branch commits
and pushes, with no merge into main and no release or production deployment.
Both repositories use `audit/security-performance-candidate-20261113`.

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
| [43480897922](https://github.com/ArcCal/network-relay/actions/runs/43480897922) / [43480903425](https://github.com/ArcCal/network-relay/actions/runs/43480903425) | Caddy synchronized controls, full race and ABBA, macOS 27 / 15 | macOS 27: full race passes; original candidate early test fails 1/20, synchronized variants pass 20/20 each. Baseline-repeat H3 download times out; other three TCP phases pass. macOS 15 running. |
| [43482779652](https://github.com/ArcCal/network-relay/actions/runs/43482779652) / [43482785124](https://github.com/ArcCal/network-relay/actions/runs/43482785124) | Baseline/candidate H3 download flow observation, macOS 27 / 15 | Both OS versions pass 32/112/16 per phase, with no stall reproduced. Instrumented timings excluded. |
| [43484311466](https://github.com/ArcCal/network-relay/actions/runs/43484311466) | Rust four-phase ABBA on macOS 27 | Running after substantial control drift in the two-phase result; same frozen binaries reused in reverse order. |
| [43488457625](https://github.com/ArcCal/network-relay/actions/runs/43488457625) | Unchanged-binary download watchdog, macOS 27 | Queued; 12 download rounds per binary, snapshots only after 15 seconds, plus independent native Go large/concurrent controls. |

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

Because the uninstrumented baseline still stalls, run 43488457625 uses unchanged
binaries and gathers server stacks, client samples and filtered UDP socket
queues only after a transfer exceeds 15 seconds. Twelve bounded download rounds
per binary increase exposure without raising the 120-second request timeout.
The same native host also runs existing independent Go serial 64 MiB and
24-tunnel controls (64 MiB each way per tunnel, eight H3 streams on one connection)
on both pinned server sources. The latter passes locally in 6.950 seconds.
No transport limit or security policy is changed; findings remain pending.

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
- `/workspace/scratch/macos-resume/caddy-candidate27-complete-analysis.json`
- `/workspace/scratch/macos-resume/h3-flow27-analysis.json`
- `/workspace/scratch/macos-resume/h3-flow15-analysis.json`
- `/workspace/scratch/macos-resume/h3-flow27-credit-observations.json`
- `/workspace/scratch/macos-resume/final-client-interop-analysis.json`

Downloaded workflow artifacts are checked against GitHub's ZIP SHA256 before
extraction. Failed, skipped, cancelled and unexecuted checks remain distinct
from passes. This record is not an exhaustive certification of every possible
execution path or deployment.
