# Implementation status

Updated during development on 2026-10-14; final evidence is in VALIDATION.md.

| Requirement | Implementation | Validation |
| --- | --- | --- |
| Standalone project, parent unchanged | Implemented | Parent baseline and final verification script |
| Standard relay H1/H2/H3, TCP/UDP/auth/policy | Implemented from pinned snapshot | Copied regressions and six-pair real-packet matrix passed |
| Independent reusable Rust WARP module | Implemented | Standalone external Cargo consumer compiles without patches |
| Explicit WARP H2 and H3 | Implemented | Synthetic pinned/mTLS peers passed; live connection setup failed |
| Server DNS through WARP | Implemented | Peer-observed DNS, TCP fallback, negatives and post-failure denial passed |
| No direct forwarding fallback | Implemented | Mandatory egress, source boundary guards and terminal-failure tests |
| Large file integrity/half-close | Implemented | 64 MiB × two rounds × six pairings, 768 MiB each direction passed |
| Abnormal reset, revocation and resource cleanup | Implemented | Protocol/stack/independent adversarial tests; final review fixes tracked |
| Unchanged current NF/RS client cores | Implemented test harnesses | 24 current/historical pairings, 192 functional cases and 48 rejection checks passed; no native macOS claim |
| Long-held TCP/UDP connection stability | Implemented test harness; investigation open | Replacement run PID 128443 failed with a connection timeout at about ten minutes; earlier scheduling failure and 56.5-minute SIGKILL interruption are not passes |
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

## Review findings addressed or undergoing final verification

- The copied H3 parser originally accepted nonboolean DATAGRAM/extended-CONNECT
  settings. A minimal guard in this project's vendor copy now rejects them
  with the exact required settings-error code. Old-fail/new-pass tests and the
  corrected 604-test workflow pass; sustained acceptance uses this new snapshot.
- Paused/rate-limited TCP and idle UDP originally lacked an independent
  egress-death watch. They now fail and release permits on terminal loss.
- Canceling server ownership originally left detached accepted TLS/website
  handlers alive temporarily. A reproduced independent test guards the
  required immediate cancellation; final fix and rerun are recorded by review.
- IPv6 MTU loss now wakes blocked UDP operations and filters in-flight DNS
  results; status preserves assigned addresses separately from usable families.
- Validation utilities now bound the complete trace/download operation, not
  just individual reads. Independent Cargo path reuse and provenance are
  checked in the final review.

No claim is made that these checks eliminate every possible defect.
