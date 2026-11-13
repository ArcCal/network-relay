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

No timeout, concurrency limit, destination check, transport,
certificate policy, or DNS wire format is relaxed. The failure cache remains
bounded to 4096 names and one second for completed failures.

The sequential selection follow-up remembers the last successful resolver.
New names start there instead of waiting 2.5 seconds for a previously failing
first entry again. If the total deadline interrupts a lookup, the next uncached
lookup continues after the interrupted resolver. All fallback attempts remain
sequential and wrap around the configured list. A generation counter prevents
an older timeout from overriding a newer successful selection, including when
the successful resolver has the same index. Duplicate addresses are tried once.

## Specification review before editing

- [RFC 9520 sections 3.1 and 3.2](https://www.rfc-editor.org/rfc/rfc9520.html#section-3):
  retry bounds and failure caching, including at least one second of caching
  and no repeat upstream query while a matching failure remains cached.
- [RFC 1035 section 4.2.2](https://www.rfc-editor.org/rfc/rfc1035.html#section-4.2.2):
  DNS over TCP framing remains unchanged.
- [RFC 1035 section 7.2](https://www.rfc-editor.org/rfc/rfc1035.html#section-7.2):
  server selection should use response history and avoid selecting an address
  again before other addresses are tried. The original text was checked before
  adding adaptive sequential selection.
- Apple's published `com.apple.relay.managed` schema: relay URLs, TCP/UDP
  CONNECT support, and trust settings remain unchanged. The retained original
  schema and IETF documents were checked before server changes.

## Regression evidence

The original code failed both the silent-resolver deadline test and a separate
eight-resolver fallback test at approximately five seconds. Only the former
is repaired within one lookup. Later resolvers become reachable across successive
uncached lookups with the sequential selection follow-up. The deadline regression uses the real destination policy,
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

The selection regression was also run against the exact production portion of
commit `649cd2532d0d047f20d25826809eabe7060c2e12` with the new test. After the
backup answered, resolving a distinct name failed a one-second bound because
it restarted at the silent first resolver. The final candidate passes this
case, wraparound recovery, eight-resolver progress across short deadlines,
stale-timeout protection, cancellation, and duplicate-address suppression.
All 48 VLESS unit tests pass after the selection change.
The distinct-name lookup took 1.817 ms in the local debug fixture after the
backup had succeeded, versus the old path failing the one-second bound while
waiting for its 2.5-second timeout. This is a controlled DNS failure fixture,
not a WAN latency claim. All seven real Xray cases and all-target VLESS Clippy
also pass again with the final selection implementation.

## Remaining limits

One lookup can still consume the entire budget before all configured resolvers
are tried; progress to later entries occurs on subsequent uncached lookups.
Configured resolvers must be interchangeable for destination names; the most
recently successful one is preferred rather than permanently preferring the
first configured address. Dividing the budget shortened a healthy preferred resolver's
wait and failed a regression. Overlapping resolver attempts would require
additional admission accounting to preserve existing per-user and global
resource bounds. Neither scheduling candidate is included in this repair.

This addresses repeated failed VLESS DNS work, not the native Apple H2 Capsule
boundary defect, H3 download stalls, or the unresolved Rust H2 throughput
comparison. Local fixtures do not establish iPhone, installed-profile, or WAN
acceptance.
