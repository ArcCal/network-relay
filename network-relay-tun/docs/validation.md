# Validation record

Development environment: Linux, Rust 1.99.1. No privileged networking changes
were executed. All fixtures and compiler outputs stayed within this project.

| Check | Result |
| --- | --- |
| Independent relay core | 115 tests passed; 4 external-fixture tests explicitly ignored |
| Host ownership, rollback, IPC and boot recovery | 47 tests passed |
| Engine wrapper | 1 test passed |
| Fragment reassembly | 3 tests passed |
| TCP packet path | 1 test passed, covering TCP/443, TCP/53 and combined data/FIN |
| UDP packet path | 7 tests passed, covering IPv4/IPv6, empty/large replies, target checks, DNS ports and out-of-order fragments |
| Vendored adapter | 21 inherited library tests passed |
| Vendored IP stack | 61 tests passed, including queue saturation and checksum rejection |
| Isolation checks | 4 checks passed |
| macOS Rust helper/worker | Cross-target type checking; no Apple SDK linking or execution |
| Swift GUI/model build | Not executed: Swift and macOS SDK unavailable |
| Privileged installation and real utun | Not executed |
| Native Network.framework, WAN throughput, sleep/wake | Not executed |

The first full-core run failed during rustdoc dependency loading while another
Cargo graph was replacing artifacts in the same target directory. A sequential
rerun passed. The final portable test script deliberately runs graphs sequentially.

An inherited HTTP/3 frame test intermittently accepted a previous case's retry
connection before sending its test frames. Each case now has a fresh listener
and awaits cancellation of its opening task. Ten consecutive targeted runs and
the subsequent full portable script passed.

The UDP tests use a loopback SOCKS fixture, not a real relay. TCP/53 exercises
transparent TCP forwarding rather than recursive DNS service behavior. IPv6
packet tests use a real IPv6 IP header/checksum over an IPv4 loopback SOCKS
association. Portable success does not establish IPv6-only uplink support.

Regression evidence includes a failing packet-level half-close test before the
TCP fix and a passing test afterward. The earlier 8192-to-4096 UDP truncation was
also reproduced before repair. Tests assert complete payloads and route ownership,
not just absence of exceptions. There is no claim of exhaustive absence of bugs
or verified production throughput.

Run `scripts/test-portable.sh` to reproduce the portable checks. Build and native
acceptance instructions are in README.md and macos-acceptance.md. Development
logs are retained locally under the ignored `.validation/` directory.
