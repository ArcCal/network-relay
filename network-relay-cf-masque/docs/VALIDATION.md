# Validation record

All source and output belongs to this child project. Fixtures use ephemeral
keys; user enrollment lives only in ignored `.secrets/` (0700 directory,
0600 file). Tracked evidence excludes its token, license, private key and
device identifier.

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
- `docs/evidence/live-warp-attempts.json`: newly built module attempted
  both egress modes with the authorized existing enrollment. H2 was refused;
  H3 timed out during setup. Neither reached account/exit validation.
- `docs/review/`: independent source review and separately reproduced
  shutdown/controller-drop regressions.
- `docs/evidence/parent-baseline.json`: all 387 original parent files and
  the pre-existing working-tree changes. Final verification compares their
  exact content, missing-file state and outside-project inventory.

The frontend suite preserves copied protocol/security tests; its loopback
test backend is explicitly test-only. The full WARP matrix instead crosses
the actual userspace stack and IP packet pump. Standalone H3 validation
passes 257 unit tests and 9 doctests, while H3-Quinn's structured transport
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
Exactly one long-soak test is intentionally ignored in this finite phase and
run separately. A matrix test contains many distinct assertions; the 604
runner count should not be added to the client case count as if they were
independent tests. See `docs/evidence/final-workflow.json`.

This final workflow includes the resource-availability guard, three H3 boolean
frame regressions and two exact QUIC-wire settings tests. The earlier 598-pass
workflow is retained as pre-correction evidence. An intermediate post-correction
run passed 334 tests and strict lint, then stopped on test-import formatting;
only that test file was formatted before the complete successful rerun.

## Sustained tests

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
After the independently found H3 SETTINGS validation correction, a replacement
run must use the corrected fixed binary and retain its actual completion.

That replacement, PID 128443, completed with test exit code 101 at
2026-10-14T22:35:59Z: `Connection error: Timeout`. Its last of 20 metric rows
records 570.216823 measured seconds, with both outer modes still available,
one generation each, and no reported packet drops. The failure occurred before
the next row, during the cycle containing the next periodic H3 bulk transfer;
the precise failing operation and cause require diagnosis. This is an actual
failed test, unlike the earlier unexplained SIGKILL, and is not a stability
pass. The completed failed manifest and log are retained separately.

Final sustained results and any source revisions after the snapshot must be
reported explicitly. In particular a synthetic hour-plus run is not a live
Cloudflare hour-plus run. The status table is updated only when the actual
run completes.

## Live test blocker

GitHub Actions on draft PR #31 did not start its lint/test job because of an
Actions budget restriction; the job executed zero steps. See
`docs/evidence/github-ci-20261014.json`. This is a separate publication check
blocker, not an additional test pass or a code-test failure.

The cloud environment reports HTTP proxy connectivity, no configured VPN,
and an empty raw TCP domain/IP allowlist. Numeric WARP H2 connection attempts
return immediate `Connection refused`; public QUIC setup times out. The
original cf-masque baseline and the newly extracted module both fail at
setup. This prevents confirming real account acceptance, exit IP, live
large-download integrity and extended Cloudflare stability here. These
observations do not prove invalid credentials or a Cloudflare protocol bug.
No network-policy bypass or direct business-traffic workaround was used.

## Reproduction and outstanding deployment gates

Run `scripts/test.sh`, then `scripts/soak.sh`, from this directory. The scripts
set all temporary/build/cache paths inside the project. Review each retained
JSON/JSONL result and exact executable/source identity rather than treating
an ignored long test as passed.

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
