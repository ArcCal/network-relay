# Validation record

All source and output belongs to this child project. Fixtures use ephemeral
keys; user enrollment lives only in ignored `.secrets/` (0700 directory,
0600 file). Tracked evidence excludes its token, license, private key and
device identifier.

## Configuration change

The current one-file configuration, optional IPv6 and migration behavior are
specified in [CONFIGURATION.md](CONFIGURATION.md) and [SPEC.md](SPEC.md).
Historical test counts and frozen source hashes below predate this change;
they must not be presented as its regression results. Configuration checks
must cover inline credentials, IPv4-only H2/H3, explicit mode selection,
legacy loading, unknown fields, redacted errors and private migration output.
The [2026-10-15 regression record](evidence/single-config-regression-20261015.json)
records 342 passing workspace tests, no failures and two intentionally ignored
long-running tests. The final focused CLI suite passes both tests, including
the additional IPv4 listener migration edges; these overlap the workspace
run and must not be added as independent test counts. Strict Clippy, owned
source formatting, the independent crate consumer and vendor provenance pass.

The actual CLI runs with one TOML after both old WARP files are deleted,
using IPv4-only credentials and both explicit WARP modes. It checks all three
ingress protocols, offline validation, private/non-overwriting migration,
password reload, rejected invalid reloads, restart-only WARP changes and
failure-closed shutdown. The full regression also passes current/historical
NF/RS core interoperability, 64 MiB file integrity, repeated bulk/half-close,
idle keepalive and protocol/security checks. This is synthetic evidence, not
a new live Cloudflare, native Apple or hour-long stability acceptance run.

## Executed evidence

- `crates/warp-egress/test-evidence/results.json`: core tests, strict lint,
  formatting and the diagnostic follow-up; independent review also runs the
  complete final core suite.
- `docs/evidence/functional-matrix-*.json`: explicit six-pair ingress/WARP
  modes, standard client's TCP/UDP outcomes, inner DNS, authentication and
  packet counters.
- `docs/evidence/bulk-matrix-*.json`: exact known-pattern SHA-256 and byte
  counts for 12 repeated 64 MiB transfers, both directions, half-close and
  measured resource bounds.
- [PID 138810 soak manifest](evidence/soak-manifest-20261014T225555Z-138810.json)
  and [independent summary](evidence/soak-summary-20261014T225555Z-138810.json):
  completed synthetic 3900-second target, actual test exit 0 and independent
  verification passed, with six retained TCP and six retained UDP flows.
- `docs/evidence/live-warp-attempts.json`: newly built module attempted
  both egress modes with the authorized existing enrollment. H2 was refused;
  H3 timed out during setup. Neither reached account/exit validation.
- `docs/review/`: independent source review and separately reproduced
  shutdown/controller-drop regressions.
- `docs/evidence/parent-baseline.json`: all 387 original parent files and
  the pre-existing working-tree changes. Final verification compares their
  exact content, missing-file state and outside-project inventory.
- [Final parent verification](evidence/parent-final-verification.json): all
  387 baseline files unchanged, with no outside-project changes.
- [Release/source binding](evidence/release-soak-source-binding.json): the
  retained release binary matches its build hash and all 112 production files
  match the passed soak's production source. This binds the release to tested
  source; it does not turn a synthetic result into live validation.
- [Final soak evidence/cleanup audit](evidence/soak-final-audit-138810.json):
  fresh independent verification of retained evidence and a late external
  cleanup observation, with explicit process-reaping limitations.

The frontend suite preserves copied protocol/security tests; its loopback
test backend is explicitly test-only. The full WARP matrix instead crosses
the actual userspace stack and IP packet pump. Standalone H3 validation
passes 260 unit tests and 9 doctests, while H3-Quinn's structured transport
regression passes separately. These counts are distinct suites, not live
Cloudflare results. The preserved profile-ownership regression has a conditional
root-only branch; that branch is not exercised in this non-root environment
(which has no sudo). Mode-0600 profile-file behavior is independently asserted.

## Build workflow correction

The first whole-workflow run passed its tests and strict lint, then stopped
on `cargo fmt --all --check`: Cargo traversed immutable vendored dependencies
with this project's formatting settings. The script now checks the three
owned packages explicitly and preserves pinned vendor/client source bytes.
The corrected workflow is rerun rather than treating that failed command as
a pass. No protocol source was reformatted to hide the mismatch.

## Final finite workflow

The final corrected `bash scripts/test.sh` completed with exit 0: **604 test-runner
passes, zero failures**, strict owned-package all-target/all-feature Clippy,
owned-package formatting, vendored H3 checks and independent consumer build.
Exactly two tests are intentionally ignored in this finite phase: the long
soak and H3 diagnostic stress. Both were executed separately with passing
actual exits. A matrix test contains many distinct assertions; the 604
runner count should not be added to the client case count as if they were
independent tests. See `docs/evidence/final-workflow.json`.

This final workflow includes the resource-availability guard, three H3 boolean
frame regressions and two exact QUIC-wire settings tests. The earlier 598-pass
workflow is retained as pre-correction evidence. An intermediate post-correction
run passed 334 tests and strict lint, then stopped on test-import formatting;
only that test file was formatted before the complete successful rerun.
After the final workflow, a test-only change moved the ignored diagnostic's
passing-artifact write after successful cleanup. Formatting and strict Clippy
for that change and the explicitly invoked diagnostic follow-up passed. The
completed soak uses this later snapshot; production source was unchanged.

## Sustained tests

**The completed synthetic soak passed.** PID 138810 finished on
2026-10-15T00:01:47Z with actual test exit 0 and independent verification
passed. Its [manifest](evidence/soak-manifest-20261014T225555Z-138810.json) binds
the exact frozen executable/source and [131-sample metric log](evidence/soak-1792018581928-138810.jsonl).
The [independent summary](evidence/soak-summary-20261014T225555Z-138810.json)
records 3925.266063896 measured seconds against a 3900-second target. All six
TCP and six UDP flows remained held, with minimum age 3920.017192809 seconds
and at least 394 pings each. Each WARP mode retained one outer generation,
and no production packet/queue drops were reported. Observed process RSS was
118632–130004 KiB and descriptors were 40–43. These measured bounds describe
this workload and duration, not every deployment's memory or capacity.

This result establishes local synthetic acceptance for that run. The earlier
PID 128443 timeout remains unresolved; neither this pass nor the separate
diagnostic stress proves its cause was corrected. Actual Cloudflare and native
Apple behavior remain unverified. The bounded [timeout source review](review/SOAK-TIMEOUT-REVIEW.md)
records the retained evidence, pinned dependency timers and diagnostic limits.

The [final evidence audit](evidence/soak-final-audit-138810.json) reran the
independent verifier successfully and checked all 398 frozen source-file
hashes. At its late 2026-10-15T05:27:38Z cleanup observation, the test runner
and matrix launcher were absent, the 33 captured socket inodes and 31 endpoint
tuples no longer appeared, and both ephemeral fixture directories were gone.
This was hours after exit and does not establish immediate external cleanup
timing. Detached Python wrapper PID 136477 remained an unreaped zombie adopted
by PID 1 with reported `FDSize: 0`; direct descriptor enumeration was denied.
The product workers and wrapper process-table entry have distinct outcomes.

Long tests require actual wall-clock time. Their immutable executable and
source hash manifest accompanies each run. Persistent TCP and UDP channels
for H1/H2/H3 are held for both WARP transports, with sequence/hash checks,
periodic large transfers and 30-second RSS/file-descriptor/socket/task/packet
samples. An initial run exposed the standard check client's 30-second QUIC
idle timeout racing a 30-second ping cadence. It is recorded as failed, not
passed. The final harness uses regular activity within that client's idle
limit; this tests active long connections, not unlimited idle tolerance.

The subsequent run bound to PID 91781 was interrupted by `SIGKILL` after
3390.309663 measured seconds (56.5 minutes). Its incomplete manifest and
114-sample log do not establish a one-hour pass. The process became a zombie
adopted by PID 1, and the original tool session was unavailable; cgroup OOM
counters were zero. A tool-session lifetime limit is a possible explanation,
not an established cause or evidence of a transport assertion failure.
The completed PID 138810 run uses the independently corrected H3 SETTINGS
parser and the later test-only diagnostic/cleanup-order changes; its source
and executable identities are retained rather than inferred from current files.

The earlier corrected-parser replacement, PID 128443, completed with test exit code 101 at
2026-10-14T22:35:59Z: `Connection error: Timeout`. Its last of 20 metric rows
records 570.216823 measured seconds, with both outer modes still available,
one generation each, and no reported packet drops. The failure occurred before
the next row, during the cycle containing the next periodic H3 bulk transfer;
the precise failing operation and cause require diagnosis. This is an actual
failed test, unlike the earlier unexplained SIGKILL, and is not a stability
pass. The completed failed manifest and log are retained separately.

The separately invoked H3 diagnostic stress then passed with test exit 0:
16 rounds per WARP mode, 32 transfers of 64 MiB, 2 GiB in each direction and
twelve retained flows, in 434.01 seconds. A cleanup-order follow-up also passed
two 64 MiB transfers with actual exit 0. These results are retained in
`h3-bulk-diagnostic-summary-131141.json` and
`h3-bulk-cleanup-order-summary.json`; neither is an hour-plus soak. All client
and operation timeouts were preserved for the diagnostic and completed soak.

Final sustained results and any source revisions after a snapshot must remain
distinct. A synthetic hour-plus pass does not establish live Cloudflare
hour-plus stability or resolve an earlier unexplained failure.

## Live test blocker

GitHub Actions on draft PR #31 did not start its lint/test job because of an
Actions budget restriction; the job executed zero steps. See
`docs/evidence/github-ci-20261014.json`. This is a separate publication check
blocker, not an additional test pass or a code-test failure.
The parent workflow was deliberately left unchanged and does not invoke this
independent child's `scripts/test.sh`; even a successful parent workflow would
not replace this project's separate acceptance checks.

The retained 2026-10-14 live attempts failed during WARP setup: numeric H2
returned immediate `Connection refused`, and H3 QUIC setup timed out. The
original cf-masque baseline and the newly extracted module both failed at
setup. Historical environment notes recorded HTTP proxy access, no configured
VPN and an empty raw TCP allowlist; those notes are not a current network-policy
or reachability assertion. The actual failures left real account acceptance,
exit IP, live large-download integrity and extended Cloudflare stability
unverified. They do not prove invalid credentials or a Cloudflare protocol bug.
No network-policy bypass or direct business-traffic workaround was used.

The [2026-10-15 environment recheck](evidence/environment-recheck-20261015.json)
records enforced unrestricted HTTP policy, zero raw TCP domain/IP grants and
no configured VPN. HTTP access does not establish the required raw WARP
TCP/UDP route. No unchanged live attempt was repeated; actual Cloudflare
validation remains blocked pending usable authorized connectivity.

## Reproduction and outstanding deployment gates

Run `scripts/test.sh`, then `scripts/soak.sh`, from this directory. The scripts
set all temporary/build/cache paths inside the project. Review each retained
JSON/JSONL result and exact executable/source identity rather than treating
an ignored long test as passed.

Keep investigation of PID 128443's timeout open. Retain stage/byte/FIN/EOF,
client close reason and peer/egress diagnostics if it recurs; the successful
synthetic run alone is insufficient to mark that defect resolved. A longer
synthetic soak and deployment capacity/loss/NAT/PMTU stress remain further
validation beyond the completed 65-minute target.

On the authorized deployment machine, first run the `live-warp` probe
separately with explicit H2 and H3. It must return `warp=on/plus`, a valid
exit IP, tunneled DNS and UDP evidence. Then run the independent relay
process with its ordinary certificate and credentials, and test unchanged
clients over each chosen ingress mode. A device site's HTTP status alone
does not identify the outer relay protocol; retain matching client/server
logs.

Use the live download helper with an independently verified checksum for
an artifact at least 64 MiB. Complete a real hour-plus run and a longer run
with held TCP/UDP connections, both active and within the actual client's
negotiated idle/keepalive policy. Monitor memory, descriptors, socket/task
counts, packet drops and terminal reasons. Do not enable automatic fallback
to make a failing mode look successful. Native Apple device/profile trust,
mobility and Network.framework behavior must be exercised on those devices.
