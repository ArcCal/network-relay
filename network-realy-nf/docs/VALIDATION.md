# Validation and reproducible evidence

Date: 2026-10-11. Results must identify whether the actual native transport ran.

## Executed here

Linux x86_64, Rust 1.99.0, Python 3.12, OpenSSL fixture CA. The test runner starts
unmodified standalone binaries, not mocks of HTTP server responses. It records
binary SHA-256 in [interop-results.json](evidence/interop-results.json).

| Check | Result | Coverage boundary |
| --- | --- | --- |
| Rust parser/protocol unit tests | 30 passed | In-memory protocol/parser behavior |
| Native bridge tests | 21 passed | Rust side and synthetic native events |
| C ABI lifecycle tests | 4 passed | Exported ABI, cancellation and security error policy |
| Project Clippy, warnings denied | Passed | `--no-deps --lib`; vendored upstream lint debt excluded |
| Real network-relay matrix | Passed | Production core over test-only rustls/Quinn bridge |
| Real caddy-network-relay matrix | Passed | Same core/backend and separate Go/Caddy process |
| macOS Swift model tests | Not run | No Swift toolchain currently available here |
| macOS full GUI build and signature | Not run | No Apple SDK/runtime here |
| Native Apple-to-server H1/H2/H3 matrix | Not run | Required before a native compatibility claim |

Each real-server matrix independently exercises HTTP/1.1, HTTP/2 and HTTP/3:
remote-name TCP forwarding; exact 2 MiB binary echo with client write half-close
and complete response EOF; remote-name UDP Capsules with payloads 0, 1, 1,200,
32,768 and 65,000 bytes; wrong-password rejection; local SOCKS CONNECT. The test
also asserts that the core does not request native QUIC DATAGRAM transmission.
SOCKS UDP ASSOCIATE echo, source-port pinning, fragment rejection, certificate
name mismatch rejection and complete native-resource cleanup also passed. No result extends to production Internet routing or Apple
TLS/QUIC behavior.

An initial fixture used IPv4-only UDP echo while `localhost` resolved to IPv6
first. That timed out on UDP receive. The fixture was corrected to bind a dual
stack socket; the same production code then passed both server matrices. A prior
link failure was caused by a full cloud filesystem; removing generated incremental
build cache restored the build. Neither incident established an application or
Network.framework defect. Final evidence supersedes these setup attempts.

## Repeat portable validation

```bash
cargo test --locked --manifest-path Core/Cargo.toml
cargo clippy --locked --manifest-path Core/Cargo.toml --no-deps --lib -- -D warnings
python3 scripts/test-interop.py \
  --rust-server /absolute/path/to/network-relay \
  --caddy /absolute/path/to/caddy-with-network-relay
```

The real-server test is ignored in ordinary `cargo test` because it requires
live fixtures. Only `test-interop.py` starts those fixtures and invokes
`--test server_interop -- --ignored --nocapture`. A normal Cargo run showing that
test as ignored does not verify server interoperability. Keep disposable test
credentials and CA keys out of version control.

## Required Mac gates

1. Run `bash build-macos.sh` on Apple silicon macOS 27 with the appropriate Xcode
   SDK. Record OS/build, Xcode version, Rust version and source commit. Record
   any compiler or linker error as a blocking defect, not a skipped pass.
2. Run the included native listener/cancellation/half-close smoke checks; these
   validate the bridge but do not authenticate a real relay connection.
3. Start the GUI with the same known server/IP/SNI/account and forced HTTP/2.
   Exercise SOCKS TCP, domain forwarding, UDP ASSOCIATE and actual target responses
   independently against each server. Verify the domain certificate with an IP
   override, then negative trust and password cases.
4. Verify active server/transport changes, inactive server edits, blank-server
   save, rapid switching, explicit Disconnect during restart and listener reuse.
   Verify the settings directory is independent from Masque NF.
5. Try one forced HTTP/3 run without changing settings until success or natural
   failure. Collect actual stream IDs, direction, parent and request/response
   phases. If it fails, retain the trace and use HTTP/2; QUIC repair is deferred.
6. Separately test Automatic mode's natural timeout/fallback. Manual switching
   to HTTP/2 is not evidence of automatic fallback.

The broader acceptance matrix in [SPEC.md](SPEC.md) also requires IPv6, reverse
half-close, server-disconnect cleanup, sleep/wake, network changes, long-idle
behavior, concurrency and destination-policy rejection. Those items have not all
been tested by this initial emulator matrix.
