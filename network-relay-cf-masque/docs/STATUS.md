# Implementation status

Updated on 2026-10-15 UTC; retained evidence is in [VALIDATION.md](VALIDATION.md).

The current configuration design uses one TOML file with inline WARP
registration values and optional IPv6. `serve --config` needs no additional
WARP file; `migrate-config` converts an existing three-file setup without
printing credentials or overwriting the originals. See
[configuration and migration](CONFIGURATION.md). The historical test counts
below describe their retained snapshots, not new validation of this change.
For this change, the [new regression record](evidence/single-config-regression-20261015.json)
records a passing 342-test workspace run, a final two-test configuration CLI
suite, strict lint and the independent module consumer. Both existing long
tests remain intentionally ignored in this configuration-only run.

| Requirement | Implementation | Validation |
| --- | --- | --- |
| Standalone project, parent unchanged | Implemented | All 387 parent baseline files unchanged in final verification |
| Standard relay H1/H2/H3, TCP/UDP/auth/policy | Implemented from pinned snapshot | Copied regressions and six-pair real-packet matrix passed |
| Independent reusable Rust WARP module | Implemented | Standalone external Cargo consumer compiles without patches |
| Explicit WARP H2 and H3 | Implemented | Synthetic pinned/mTLS peers passed; live connection setup failed |
| Server DNS through WARP | Implemented | Peer-observed DNS, TCP fallback, negatives and post-failure denial passed |
| No direct forwarding fallback | Implemented | Mandatory egress, source boundary guards and terminal-failure tests |
| Large file integrity/half-close | Implemented | 64 MiB × two rounds × six pairings, 768 MiB each direction passed |
| Abnormal reset, revocation and resource cleanup | Implemented | Protocol/stack/independent adversarial tests; final synthetic audit confirms late release of captured sockets/directories; detached wrapper zombie remains |
| Unchanged current NF/RS client cores | Implemented test harnesses | 24 current/historical pairings, 192 functional cases and 48 rejection checks passed; NF uses a Linux bridge for native hooks, not native Apple execution |
| Long-held TCP/UDP connection stability | Synthetic acceptance passed; earlier failure investigation open | PID 138810 passed its 3900-second target with 3925.266 measured seconds, six TCP and six UDP flows and independent verification; PID 128443's earlier timeout remains unresolved |
| Actual Cloudflare exit IP | Not established in this environment | H2 refused, H3 setup timeout before trace |
| Real Cloudflare large download and hour-plus soak | Not executed successfully | Blocked by live setup; tools/instructions provided, no pass claim |
| Native Apple NF GUI/profile/device execution | Not executed here | Linux portable/core tests cannot substitute for it |

## Known limitations and deliberate behavior

1. Single selected-mode WARP generation. No in-process automatic reconnect;
   the server exits on terminal loss. A supervisor retries that same mode.
2. The userspace stack has 64 sockets. This is smaller than the standard
   relay's potential kernel-backed capacity. DNS and connecting/closing TCP
   use this same budget; reserve capacity in the relay configuration.
3. IPv4/IPv6 UDP payloads are bounded by the WARP MTU, 1252/1232 bytes at
   MTU 1280. Oversize packets are dropped without fragmentation; this can
   affect applications that send larger datagrams. They are not silently
   redirected to a native VPS UDP socket.
4. The Cloudflare enrollment must already exist. Registration/refresh,
   account lifecycle and license management are outside this module.
5. Linux x86_64 runtime is the development target. The crate has a known
   Windows-only `AsFd` portability limitation inherited from the transport;
   Windows support is not claimed. macOS/ARM deployment requires its own
   native runtime checks.
6. Local protocol peers reproduce a reviewed Cloudflare dialect, not every
   deployment condition at Cloudflare. They cannot validate account
   acceptance, real PMTU/loss/NAT behavior or remote long-term stability.
7. PID 128443 failed during periodic H3 bulk work with the unchanged client's
   QUIC timeout. Later diagnostic stress and PID 138810's hour-plus pass did
   not reproduce or resolve it. The earlier 56.5-minute SIGKILL interruption
   also remains an incomplete run. See the [timeout review](review/SOAK-TIMEOUT-REVIEW.md).

## Review findings and disposition

- The copied H3 parser originally accepted nonboolean DATAGRAM/extended-CONNECT
  settings. A minimal guard in this project's vendor copy now rejects them
  with the exact required settings-error code. Old-fail/new-pass tests and the
  corrected 604-test workflow pass; sustained acceptance uses this new snapshot.
- Paused/rate-limited TCP and idle UDP originally lacked an independent
  egress-death watch. They now fail and release permits on terminal loss.
- Canceling server ownership originally left detached accepted TLS/website
  handlers alive temporarily. A reproduced independent test guards the
  required immediate cancellation; the fix and passing rerun are recorded by
  the [independent source review](review/INDEPENDENT-FINAL-REVIEW.md).
- IPv6 MTU loss now wakes blocked UDP operations and filters in-flight DNS
  results; status preserves assigned addresses separately from usable families.
- Validation utilities now bound the complete trace/download operation, not
  just individual reads. Independent Cargo path reuse and provenance are
  checked in the final review.

The final finite workflow passed 604 tests with zero failures, strict lint,
owned-source formatting and the standalone consumer build. Its vendored H3
portion passed 260 unit tests and 9 doctests. The two ignored tests were run separately: H3
diagnostic stress passed 32 transfers totaling 2 GiB in each direction, and
the completed synthetic soak passed. Exact source/binary identities and the
prior failed/interrupted outcomes are retained in the [evidence matrix](evidence/MATRIX.md).
The [final soak audit](evidence/soak-final-audit-138810.json) records a late
cleanup observation, not immediate process reaping; an adopted detached
launcher zombie remains. The [release/source binding](evidence/release-soak-source-binding.json)
confirms the release binary's production source matches the passed soak.

No claim is made that these checks eliminate every possible defect.
