# Rustls TLS 1.3 key-update correction

This is Rustls 0.23.46 with a narrow RFC 9846 correction. The official crate
archive, upstream commit, complete input file hashes, packaged hashes and
reproducible patch are recorded in UPSTREAM.json and rfc9846.patch. Original
licenses, attribution, manifests and unchanged source bytes are preserved.
The upstream library development Cargo.lock is omitted; application locks
resolve the security dependencies actually built.

RFC 9846 section 4.7.3 forbids another update_requested until a subsequent
valid peer KeyUpdate. It caps sending epochs at 2^48-1 without imposing a
receive cap. Section 5.5 requires rekeying or safe closure before key exhaustion.
The private state tracks these requirements and prevents further application
encryption after exhaustion, including unbuffered and hard-refusal alert paths.
Cipher suites, trust verification, provider defaults and public APIs are unchanged.

The original automatic-update behavior failed an actual encrypted-record test
with a reduced test-only record limit. The correction passed 15 focused cases,
the complete upstream ring/TLS12 suite (555 tests) and both-provider suite
(951 tests), strict production Clippy, Rust 1.88 compilation and no_std checks.
Original external Bogo and documentation skips remain skips. The full upstream
fixtures are in the original release checkout; they are not published in the
upstream crate archive. Application and native-device tests are separate gates.

The unused dangerous external kTLS secret-extraction API delegates record
handling to its caller and is outside this buffered/unbuffered correction.
No claim is made about caller-controlled external record implementations.

Canonical, RS and NF copies must remain byte-identical. Workspaces use a root
[patch.crates-io] entry and retain registry version requirements for direct
Rustls dependencies, preserving membership and feature selection.
