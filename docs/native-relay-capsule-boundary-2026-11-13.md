# Native H2 Relay Capsule boundary failure

This is a reproduced baseline defect, not a claim that the user's installed
profile or WAN slowdown has been completely diagnosed. No server workaround
has been applied. Candidate branch commits and pushes are now authorized;
main merges and releases are not.

## Reproduction and evidence

On macOS 15.8.2 and 27.0.1 arm64, Apple's Network.framework Relay path sends a truncated
Capsule when an NWConnection sends exactly 63 UDP payload bytes through an H2
Relay. The diagnostic reads the generated mobileconfig and uses its endpoints
and authentication in an explicit per-connection ProxyConfiguration. It does
not install a system profile. TLS chain and hostname verification stay enabled.

The unchanged Caddy baseline is a691271ac5362cec324231234f38990680630fda.
Uninstrumented run 43444033849 fails the first 63-byte H2 echo, with zero origin
datagrams. Payloads 62, 64 and 65 each pass 100 exact echoes; direct, H3 and
automatic 63-byte cases also pass 100. A separate automatic 1200-byte first
reply loss is retained independently of this framing defect.

Read-only tracing run 43445672816 reproduces the 63-byte failure. All other 35
positive cases and all four authentication/trust rejection controls pass.
Before the H2 request-body pipe, the complete received data is 66 bytes:

| Field | Expected | Received |
| --- | --- | --- |
| Capsule type | `00` | `00` |
| Capsule value length | `40 40` (64) | `40 40` (64) |
| Context ID | `00` | `00` |
| Synthetic UDP payload | `00 01 ... 3d 3e` (63 bytes) | `00 01 ... 3d` (62 bytes) |
| Total Capsule stream bytes | 67 | 66 |

There is one DATA input chunk, followed by cancellation about ten seconds
later. The server correctly waits for the missing byte and forwards no
incomplete UDP packet. Runs 43447935315 (macOS 15.8.2) and 43447941138
(macOS 27.0.1) independently capture the same bytes immediately after reading
the raw H2 DATA payload, before frame parsing or padding removal. Both frames
declare length 66 with flags 0x0: there is no PADDED flag. This excludes the
server's DATA padding parser and request-body pipe as the source of the missing
byte. It does not identify an internal Apple function or establish behavior on
every intervening OS release.

The macOS 27 raw-frame run passes the other 35 positive cases. The macOS 15
run passes 34 of 36; its additional H3 1200-byte first-reply loss is retained
separately. Both runs pass all four trust/authentication rejection controls
with zero origin datagrams. macOS 15 initially exposed a fixture PKI defect:
the old OpenSSL 1.1.1 CLI generated duplicate certificate extensions. Selecting
the installed OpenSSL 3.5.9 fixes the fixture while preserving strict chain and
hostname verification; that failed first run is not a Relay test result.

This boundary explains the recorded continuous-stream failure mechanism.
Run 43440899910 has six affected upload streams. Each first unusual Capsule
is type 1450, length zero, with raw header `45 aa 00`, immediately after a
DATAGRAM Capsule of length 64. Consuming the next Capsule's leading `00` as
the missing payload byte produces exactly that next misaligned header.
Twenty unusual header records agree between an independent observer before
the H2 body pipe and the existing parser. Later interpreted lengths are huge,
and the parser waits while streaming the unknown Capsule away. Earlier H2
flow-control logs independently show receive credit still available.

## Controls and limits

Independent Go clients pass 42 native macOS baseline uploads of 64 MiB through
direct, H2 and H3 paths. Expanded Go UDP boundary controls pass ten local
repetitions across H1, H2, H3 and H3 Capsules; the tracing workflow also runs
the expanded control before building its observed baseline. The synthetic
packet data, routing logs, exact payload hashes and negative controls are
retained. Instrumented timings are excluded from throughput comparisons.

Both one-click installers already produce H2-only profiles. Thus the H2
failure is relevant to that configuration, while the measured lower H3
loopback throughput alone cannot explain the report. H3 avoids the 63-byte
failure in these tests, but its separate startup/PMTU losses and different CPU
cost prevent treating a global transport-default change as regression-free.
Physical iPhone, installed-system-profile, current uncommitted candidates and
the user's real network remain separate acceptance scopes.

## Standards constraint

RFC 9297 sections 3.2-3.3 define the declared Capsule value length and require
unknown Capsule types to be skipped. RFC 9000 section 16 allows non-minimal
varint encodings. RFC 9113 section 6.1 distinguishes DATA and padding. Apple's
Relay payload schema requires the advertised endpoints to proxy TCP and UDP.
Guessing a missing payload byte, resynchronizing on apparent headers or
rejecting otherwise valid unknown Capsule types is not a justified repair.
No authentication, TLS, destination-policy or resource bound is relaxed.

## Retained local records

- `/workspace/scratch/macos-resume/native-udp-boundaries-analysis.json`
- `/workspace/scratch/macos-resume/native-udp-wire-analysis.json`
- `/workspace/scratch/macos-resume/native-capsule-trace-analysis.json`
- `/workspace/scratch/macos-resume/upload-stall-h2-credit.json`
- `/workspace/scratch/macos-resume/authorized-diagnostic-commit.json`
- `/workspace/scratch/macos-resume/udp-raw-macos15-analysis.json`
- `/workspace/scratch/macos-resume/udp-raw-macos27-analysis.json`

Local Rust and Caddy regression tests preserve incomplete-message withholding,
exact final-byte delivery, legal non-minimal varints and unknown-type skipping.
The Rust tests pass; the Caddy test passes with race detection and the reviewed
prepared Go toolchain. These enforce server correctness, not a repair of the
native encoder. No product source was submitted to the diagnostic branch.

Wire artifact SHA256:
`54dd3aa58192b759b3fa7b6a4437768113d8668f0661ea972a870da7791d1b11`.
Uninstrumented boundary artifact SHA256:
`e13b3a7ed3f5259d32379cd0758845c5083f6c5c5b68bba26c7bf503679d073a`.
