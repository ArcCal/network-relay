# Implementation and acceptance status

Revision: 0.1.0 development, 2026-10-12. This is an independent Rust application.
NF observations are reference evidence; they are not RS test results.

## Status meanings

**Implemented** means the code exists. **PASS** requires a recorded executed
check. **FAIL** identifies an observed failing check. **NOT RUN** is an unmet
acceptance gate. A potential risk is not a confirmed runtime defect.

## Implementation matrix

| Area | Status | Evidence and limit |
| --- | --- | --- |
| Independent application identity and directory | Implemented | Own bundle ID, Cargo workspace, lockfile, code, documents and private settings path |
| NF-compatible settings workflow | Implemented; model checks PASS | 18 model regressions include import/export, selection and private storage |
| Active server/transport automatic restart | Implemented; controller checks PASS | Rust cancellation and generation ownership; actual Mac interactions not executed |
| Five-level retained log workflow | Implemented; controller checks PASS | Bounded retention and filters; Mac appearance/interaction not executed |
| NF icon and native GUI behavior | Implemented; NOT RUN on Mac | Shared PNG, Rust AppKit UI; exact visual parity needs a Mac comparison |
| Rust production sockets/TLS/QUIC | Implemented; transport checks PASS | Tokio, rustls and Quinn; no production Network.framework bridge |
| HTTP/1.1, HTTP/2 and HTTP/3 core | Implemented; real-server matrix PASS | Both Rust and Caddy binaries; forced transports and Automatic |
| Local SOCKS TCP and UDP | Implemented; real-server matrix PASS | Actual CLI app exercised against both servers; 1 MiB TCP, UDP, cancellation |
| macOS ARM64 bundle and signing | Build script implemented; NOT RUN | Linux cannot execute AppKit, iconutil or Mac codesign |
| Actual remote server and Mac stability | NOT RUN | Requires separate Rust/Caddy runs and real traffic, plus idle/active soak |

## Appearance acceptance

The NF workflow and source-visible presentation requirements are implemented:
resizable 940 by 660 initial window and NF's 820 by 600 minimum, responsive panes, settings/log/About,
scoped import/export menus, an ellipsis menu in the menu-bar popover, the shared
icon and a circular power control with a busy arc that respects Reduce Motion.
Native AppKit replaces SwiftUI. Exact text/layout, hover/glow, animation,
light/dark appearance and interaction parity remain **NOT RUN** on a Mac.
Type checking and source comparison do not establish pixel equivalence. The
standard Edit shortcuts, window Close/Minimize and application menus are
implemented; the settings body scrolls while its footer remains accessible.
Three focused UI save/selection helper tests and non-Mac UI type checking pass;
they do not execute AppKit window or menu interactions.
The final UI check uses `cargo check --locked --offline --features ui-typecheck`
and passes without warnings. Selector review also checked the relevant symbol
configuration and rounded-box APIs against objc2's generated Apple bindings at
revision `248bc7075cfb8caf12a861069da11d4a9aa1f0fd`. This is an independent API
cross-check, not an AppKit runtime result or an additional production dependency.

## Executed unit and transport checks

The app/core package checks passed on the Linux development host. Coverage
includes controller lifecycle, 18 model regressions, core protocol tests and
production transport regressions: settings selection and NF imports/exports,
private storage, retained-log behavior, protocol parsing, successful 2xx CONNECT
responses, Structured Fields Capsule negotiation, half-close/error propagation,
invalid configuration, trusted-CA parsing and cancellation of blocked TLS/read
operations. Mac ABI linking and GUI execution remain separate gates.

The final combined package check with the UI type-check feature passed 78
tests: 7 controller, 18 model, 47 core, 3 production transport and 3 pure UI
save/selection helpers. A repeated-callsite regression verifies runtime verbosity
can increase from Normal to Everything and then decrease to Errors Only without
reconnecting. Headless output applies the same severity filter while advancing
its cursor across hidden retained lines. The additional Everything diagnostics record transport
metadata only, including event kind/resource/byte counts and read EOF. Headless
`--log-level` selects the same five levels without changing saved preferences.
The strict app/core Clippy check also passes with warnings treated as errors.

The locked transport versions include Quinn 0.11.12, quinn-proto 0.11.19,
quinn-udp 0.5.16, rustls 0.23.45, Tokio 1.53.2, h2 0.4.20 and SFV 0.14.0.
Cargo.lock is authoritative; these checks used stable Rust 1.99.

## Automated compatibility matrix

The real-server harness must record both the exact server revision/binary and
transport-specific results. Test fixtures are local and disposable; they do
not use the user's production credentials or alter server source.

| Server | HTTP/1.1 TCP/UDP | HTTP/2 TCP/UDP | HTTP/3 TCP/UDP | Outcome |
| --- | --- | --- | --- | --- |
| network-relay 1.5.0, source `a8cc0e8f` | PASS | PASS | PASS | Protocol/security and actual CLI matrix; 125.31-second HTTP/3 soak PASS |
| Caddy 2.11.6 + caddy-network-relay, source `ef245375` | PASS | PASS | PASS | Protocol/security and actual CLI matrix; 125.25-second HTTP/3 soak PASS |

Automatic mode selected available HTTP/3 successfully for each server; failed
QUIC-to-TCP fallback was separately tested against an actual TCP-only Caddy
endpoint: QUIC failed, Automatic selected HTTP/2, and TCP plus 65,000-byte UDP
Capsules succeeded. The actual headless app's Automatic choice also passed
against that endpoint. The initial matrix exercised
2 MiB binary TCP with half-close, UDP Capsules from empty payload through
65,000 bytes, wrong credentials, certificate-name mismatch, an untrusted CA
over HTTP/2, blocked-port policy rejection, SOCKS sender pinning, fragmented UDP
rejection and cancellation resource cleanup. Nine actual headless app checks
covered all four transport choices against both servers and TCP-only fallback,
NF-compatible config import, 1 MiB SOCKS TCP, SOCKS UDP and Control-C shutdown.

The full protocol and 125-second stability artifact is
[evidence/interop-results.json](evidence/interop-results.json). The final app
rebuild's repeated protocol and nine headless cases are separately recorded in
[evidence/app-smoke-results.json](evidence/app-smoke-results.json), with the
distinction explained in [evidence/README.md](evidence/README.md). Each HTTP/3 soak
kept persistent TCP and UDP traffic alive, renewed the idle admission probe,
observed no reconnect and ended with zero production transport resources.
The host was Linux x86_64; the same production Rust transport is used by RS,
but no Mac GUI or remote production-server soak is claimed. Server SHA-256:

- Rust: `e93c28942bf2a634e498b2f1ae14623a870c4670bfd1b95e7322ca425104defe`.
- Caddy: `dbf473abe26ccc838e3260a4f49ead4a48b81ce4750c1de0f0eb9d4ebc297787`.

No native Mac launch or ten-minute remote-soak success is inferred from a
portable PASS. The Caddy pairing is the deployed baseline, not an unmerged
HTTP/3 first-byte-timeout repair.

The stability run's headless app was version 0.1.0/core 0.1.0, built
`2026-10-12T16:53:52Z`, source
`27bccd28f97d6c45067abb6495b50321061de1c5-dirty`, SHA-256
`3f9c2acf719cf19a3b1eb5adb75845f57fa1ad8201251b7849b89cedf7c6b03d`.
The dirty suffix identifies the in-progress new RS directory; core, test,
lockfile and binary digests in the artifact pin what the suite exercised.
The headless cases run at Everything and verify that Rust I/O request/read
metadata is present while both plaintext fixture passwords and their HTTP Basic
tokens are absent. A subsequent application-only runtime logging-control repair
has a passing repeated-callsite regression. Its rebuilt short protocol/CLI
retest is recorded separately; the unchanged core, h3 and lockfile fingerprints
keep the original Core stability evidence applicable. The 125-second record
remains evidence for its original inputs, not a new-binary or native Mac soak.

The final app-control artifact was executed at `2026-10-12T17:09:06.109557Z`
with app/core 0.1.0, built `2026-10-12T17:09:03Z`, source
`27bccd28f97d6c45067abb6495b50321061de1c5-dirty`, binary SHA-256
`5c64e18d32479b3178804aa2bc29c8f7ffbeff2efcfe3120ec2b1708ebe62929`.
Its nine Everything CLI cases pass trace-generation and credential-exclusion
assertions. Six additional Errors Only cases verify a healthy run exits zero
without INFO/WARN/DEBUG/TRACE output and wrong credentials produce ERROR and
exit one, across HTTP/1.1, HTTP/2 and HTTP/3. The final app source fingerprint
differs from the preserved stability run; the core, h3, test, manifest and
lockfile fingerprints remain identical.

## Confirmed scope limits

- Apple silicon macOS 13+ is the initial GUI target; Intel GUI is not implemented.
- No system-wide proxy/VPN integration, privileged helper or mobileconfig is
  generated. The app exposes a local SOCKS service.
- Custom CONNECT-UDP templates are not exposed by GUI or headless settings
  import; both require the standard endpoint. Mutual-TLS-only authentication
  is not implemented. The protocol library retains its restricted template parser.
- The client requires explicit true Capsule-Protocol in UDP responses. RFC 9297
  says the peer SHOULD send the response field, rather than universally MUST;
  a compliant peer omitting it may be rejected. Both tested servers send it.
- SOCKS BIND and fragmented UDP are unsupported; internationalized SOCKS names
  require ASCII/Punycode. Full IPv6 UDP maximum size and per-drop UI counters
  are outside the initial profile.
- No Developer ID notarization or installed release binary is included.
- The all-Rust transport has different TLS/QUIC behavior and fingerprints from
  Network.framework; it does not preserve Apple's network fingerprint.

## Potential issues and remaining verification

AppKit is called through an unsafe platform ABI. Type checking and source
review reduce errors but cannot establish lifetime/selector correctness under
real UI interaction. Packaging, signing, dark/light rendering, accessibility,
file panels and exact NF appearance require a Mac run. Network changes, suspend/
resume, prolonged cancellation/reconnect cycles and many concurrent flows need
separate stress validation.

IPv6 endpoints and the full ten-minute remote acceptance run require separate
recorded results. Automatic fallback now has separate real-server evidence;
a PASS with available HTTP/3 alone does not establish that behavior.
The matrix exercises client write-half-close followed by a remote response;
the inverse remote-write-half-close with continuing client writes remains
NOT RUN and must be tested independently.

The historic NF HTTP/3 failures do not establish an RS defect or prove that
changing transport alone fixes every server issue. Server policy, header
timeouts and protocol behavior remain relevant. A short local matrix does not
prove indefinite compatibility with arbitrary deployment versions. Applicable
IETF normative requirements and Apple platform rules remain mandatory.

## Defects found and repaired (2026-10-13)

Both reproduced with the production Rust transport against network-relay
`a842cb6` and caddy-network-relay `8a0df41`, over HTTP/1.1, HTTP/2 and HTTP/3:

- **A full relay ended the client.** Every HTTP refusal was terminal, so a 503
  from a server at its tunnel limit (with `max_tunnels_per_user = 1` and one
  tunnel held) made the readiness monitor return and the whole client stop;
  502/504 (temporary destination or DNS failures) did the same. 502, 503 and
  504 are now retried with backoff; credential, request and TLS rejections stay
  terminal. Regression: `client::probe_tests::temporary_relay_refusals_are_retried`.
- **A cut-off download looked complete.** When the destination reset mid-download,
  the relays reset the HTTP stream or connection, but the SOCKS program's
  connection was closed with FIN (it read 3–6 MiB of 8 MiB, then a clean end).
  The SOCKS session now aborts it (`native::ABORT`) and the backend resets the
  accepted socket; the program sees ECONNRESET on every transport with both
  servers. A clean tunnel end still sends FIN. Regression:
  `backend::tests::an_aborted_local_connection_is_reset_and_a_released_one_finished`.

The same two defects were found and repaired in Network Realy NF's core.

Known failed checks, if any, must be added here with a reproducer, exact versions
and the smallest justified repair. A failure that cannot be safely repaired
must remain visible rather than being relabeled as unsupported or a success.
