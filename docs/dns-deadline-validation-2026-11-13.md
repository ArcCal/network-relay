# VLESS DNS deadline follow-up

## Problem and repair

Two silent DNS resolvers each consume up to 2.5 seconds. The relay's outer
five-second timeout previously cancelled the lookup before it could cache a
completed failure. Retrying the same name then reopened upstream VLESS
connections. An earlier admission wait made the mismatch larger.

The destination policy now passes its existing absolute deadline through a
defaulted `Egress::resolve_until` method. VLESS uses that same deadline to
complete and cache a timeout before returning to the policy. Other egresses
retain their existing behavior and the policy still enforces the deadline.
Earlier caller cancellation and admission-only timeouts do not cache a failure.
A slower failed lookup cannot replace an unexpired successful cache entry.

No timeout, query order, concurrency limit, destination check, transport,
certificate policy, or DNS wire format is relaxed. The failure cache remains
bounded to 4096 names and one second for completed failures.

## Specification review before editing

- [RFC 9520 sections 3.1 and 3.2](https://www.rfc-editor.org/rfc/rfc9520.html#section-3):
  retry bounds and failure caching, including at least one second of caching
  and no repeat upstream query while a matching failure remains cached.
- [RFC 1035 section 4.2.2](https://www.rfc-editor.org/rfc/rfc1035.html#section-4.2.2):
  DNS over TCP framing remains unchanged.
- Apple's published `com.apple.relay.managed` schema: relay URLs, TCP/UDP
  CONNECT support, and trust settings remain unchanged. The retained original
  schema and IETF documents were checked before server changes.

## Regression evidence

The original code failed both the silent-resolver deadline test and a separate
eight-resolver fallback test at approximately five seconds. Only the former
is repaired here. The final regression uses the real destination policy,
VLESS egress, and a loopback WebSocket peer. After the first timeout, 100
case-insensitive same-name retries complete from the cache with two upstream
requests total. A healthy first resolver taking one second still succeeds
when eight resolvers are configured. Caller cancellation does not cache a
failure, and an overlapping timeout preserves a successful cached answer.

The policy tests also retain the original five-second total limit after a
four-second permit wait and verify cancellation releases the permit.

Local validation passed:

- 174 root server unit tests, including 15 destination-policy tests.
- 78 TLS/H1/H2/H3 integration tests with direct connections and the same 78
  tests with `NETWORK_RELAY_TEST_EGRESS=loopback`.
- 43 VLESS unit tests; after strengthening the end-to-end policy regression,
  all 20 DNS tests were run again and passed.
- All seven real Xray v26.10.31 interoperability tests, explicitly enabled
  rather than counted as ignored passes.
- Root server and VLESS all-target Clippy with warnings denied; CF/WARP
  all-target compilation with the default egress deadline implementation.

Dedicated macOS validation of this repair is pending separately from the
instrumented native H3 investigation. No macOS acceptance is claimed here.

## Remaining limits

Sequential earlier resolvers can still consume the entire budget before later
entries are tried. Dividing the budget shortened a healthy preferred resolver's
wait and failed a regression. Overlapping resolver attempts would require
additional admission accounting to preserve existing per-user and global
resource bounds. Neither scheduling candidate is included in this repair.

This addresses repeated failed VLESS DNS work, not the native Apple H2 Capsule
boundary defect, H3 download stalls, or the unresolved Rust H2 throughput
comparison. Local fixtures do not establish iPhone, installed-profile, or WAN
acceptance.
