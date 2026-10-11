# Implementation status

As of 2026-10-11, version 0.1.0 development. This status belongs only to Network
Realy NF. Historical Masque NF failures are evidence of an inherited risk, not
proof that this new binary has failed or succeeded.

## Implemented and checked in this environment

- Independent Rust core, C ABI, bounded native bridge and copied QUIC adapter.
- HTTP/1.1 CONNECT/CONNECT-UDP Upgrade, HTTP/2 and HTTP/3 request framing, Basic
  authorization and DATAGRAM Capsule parsing/encoding.
- SOCKS5 CONNECT and UDP ASSOCIATE source enforcement and bounded destination
  flow management. Server-side DNS forwarding; no client IP-stack dependency.
- 30 protocol/parser unit tests, 21 native-boundary tests and 4 FFI lifecycle
  tests passed. They cover malformed Capsule handling, queue bounds, EOF/error
  propagation, half-close, cancellation isolation and terminal security failures.
- `cargo check` and project-only Clippy with warnings denied passed on Linux.
  This establishes Rust compilation, not Swift
  compilation, application packaging or Apple runtime behavior.

The real Rust and Go/Caddy server matrices passed all three transports, including
SOCKS TCP/UDP, certificate-name rejection, source pinning, fragment rejection and
native-resource cleanup in the emulator. Real-server results are recorded in [evidence/interop-results.json](evidence/interop-results.json).
Only cases actually reported PASS in that file count as verified. The emulator
uses test-only rustls/Quinn in place of Network.framework; its PASS cannot be
promoted to a native interoperability claim.

## Implemented, awaiting Mac verification

- SwiftUI/AppKit window, icon, menu bar, independent store and TOML import/export.
- Automatic restart after server/transport selection; retaining the active server
  when saving a new blank server. Copied portable model tests are included.
- Native TCP/TLS, local SOCKS TCP/UDP and NWConnectionGroup QUIC adapter.
- Streams-only HTTP/3 Capsules, no DATAGRAM extraction, actual SID diagnostic log.
- macOS build, signing/bundling script and native boundary smoke runner.

No macOS SDK is available in this environment. These Swift sources and Mac
commands have **not** been compiled or executed here. A source copy or shell
syntax check is insufficient evidence that the app builds.

## Confirmed issues and limitations

- **Original-client HTTP/3 fault remains unresolved.** The user confirmed Masque
  NF and the removed Masque Swift fail with native HTTP/3 while HTTP/2 works on
  the same Rust masque-server. This is a CONNECT-IP observation; the new relay
  application has not undergone that native test. [Research](QUIC-RESEARCH.md).
- The latest original NF log, 08:50–08:53 UTC, records two natural H3 response
  timeouts in `1AC94CBF`; HTTP/2 immediately works afterwards. A separate
  `caddy-masuqe` profile times out before TLS readiness even over HTTP/2. Its
  actual endpoint is absent, so it is not evidence of the same QUIC mechanism.
- Native application build and complete Apple-to-both-server acceptance matrix
  are missing. Therefore “perfect interoperability” has not been delivered.
- One outer connection per flow can exhaust restrictive server connection limits
  and adds handshake overhead. Shared HTTP/2/3 connections are not implemented.
- The idle UDP readiness probe can be rejected by destination policy or closed by
  server idle timeout. It does not verify end-to-end access and sends no heartbeat.
- Custom UDP templates are accepted only by core configuration, not by the GUI.
  Mutual TLS/client-certificate identity, BIND, SOCKS UDP fragments, Intel builds
  and pre-macOS-27 support are not implemented.
- Reliable UDP Capsules have head-of-line blocking. Native QUIC DATAGRAMs, path
  MTU optimization and full-size IPv6 UDP are intentionally absent.
- Passwords use the copied private-file store; Keychain integration and independent
  security audit are pending. Ad-hoc signing is not notarization.

## Possible issues, not established root causes

- Old NWConnectionGroup stream ownership, child options and initial implicit
  stream allocation may still prevent a server accepting the intended H3 request.
- Stream-only extraction may avoid DATAGRAM lifecycle coupling, but no Mac A/B
  has shown that it fixes the earlier failure. Disabling GREASE is also unproven.
- Native UDP overflow, address rebinding, network migration, long idle sessions
  and EOF/cancellation races need real Apple runtime testing.
- Copying tested Masque NF UI code does not prove renamed imports, linker flags
  and this new bundle work together. The first Mac build is a required gate.

## Deferred work and QUIC stopping rule

Prioritize a first Mac build and native HTTP/2 TCP/UDP validation against both
servers. Try one fixed-configuration H3 run with actual SIDs and stage logs. If
H3 still fails, retain its evidence and mark the transport experimental; continue
using forced HTTP/2. Do not spend further time rewriting the QUIC backend merely
to complete this initial delivery. A future repairer can choose a bounded A/B
from the research report without changing either server in this task.
