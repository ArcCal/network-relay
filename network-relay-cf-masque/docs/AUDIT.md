# WARP adapter audit

## November 13, 2026 local follow-up

The current uncommitted tree includes the reviewed TCP persist correction and
bounded IPv4/IPv6 receive reassembly. Original Apple Relay schemas and RFCs
791, 1122, 3168, 4443, 5722, 6946, 7112, 8200 and 9673 were checked before
server changes. Fixed context and packet bounds, overlap poisoning, absolute
expiry, complete first-header validation, extension-header order and bounded
ICMP responses retain security constraints. Outbound UDP MTU limits are unchanged.

The accepted frozen synthetic soak runs for 3950.46 seconds. Independent
verification checks 131 samples spanning 3924.03 seconds, six TCP and six UDP
held flows, exact TCP hashes, one outer generation per transport and zero
reported packet queue drops. RSS is 116636-131476 KiB and FD count is 40-43.
The previous 3842.91-second reset and older ten-minute timeout remain unexplained.
This is not live Cloudflare acceptance or proof that all historical failures
share the repaired TCP cause.

See [the parent audit](../../docs/audit-2026-11-13.md) and [VALIDATION.md](VALIDATION.md)
for source-specific gates. The historical review below describes its original
inputs and must not be read as the current dependency or native-device inventory.

## Original review

Initial review October 31-November 1, 2026 (America/Los_Angeles). This review concerns
`network-relay-cf-masque/`, with parent commit
`136fbae9bdf07cd49219fe71af4094eba7384de8` treated as immutable. The
parent's source, configuration, documentation, manifests, lockfiles and
vendored implementations were unchanged in that audit. Its SHA-256 snapshots
covered all 392 tracked files outside this subproject.

## Architecture and reuse

The application already used the canonical server. This audit preserves
that architecture and removes remaining local implementations of shared
utilities.

| Functionality | Canonical implementation used |
| --- | --- |
| H1/H2/H3 ingress, CONNECT/CONNECT-UDP, website, authentication, revocation, policy and limits | `network_relay::server::Relay::with_egress` and `server::run_variant` |
| Relay configuration, command helpers, logging, runtime and Apple profiles | Parent `Config`, `cli::Tools`/`Program`, `logging` and profile APIs |
| Business connections and terminal failure notification | Parent `egress::Egress`, `TcpStream`, `UdpSocket` and `DatagramIo` |
| Hostname rules and live-tool URL authorities | Parent `policy::Target` constructors |
| QUIC integers, Capsule encoding and Capsule content-header validation | Parent `proto::varint`, `proto::capsule::encode` and `proto::valid_capsule_headers` |
| HTTP/3 and Quinn integration | Existing dependencies on the immutable parent `vendor/h3` and `vendor/h3-quinn`; no copied implementation |
| Endpoint public-key PEM decoding | Rustls `SubjectPublicKeyInfoDer` / `PemObject` |
| TCP/IP loss and zero-window recovery | Pinned smoltcp revision `336a1dd1aaf0eeb1afab5e3b4b479e818a23c03e` with the later reviewed local TCP conformance patch in `../vendor/smoltcp` |

The WARP adapter retains only the behavior the parent does not supply:
enrollment loading, pinned device-authenticated WARP transport, IP packet
pumping, smoltcp sockets and DNS over those sockets. The parent resolver
uses host networking; invoking it here would violate isolation. Its public
Capsule decoder returns DATAGRAM capsules and skips other types, so it
cannot replace the bounded WARP control-capsule parser without losing
address-control validation. Its normal TLS client constructor loads CA
roots; WARP requires its enrolled SPKI trust anchor independently of host
CA availability. The small pinned TLS builder therefore remains local.

Removed code includes the independent QUIC integer algorithm, Capsule
encoders, PEM-body decoder, one-variant `Net` wrapper, unreachable CA/Basic
authentication and generic RFC-server modes, and unused transport diagnostic
methods/fields. `serde_json` is now a test dependency of the adapter. The
standalone consumer's lockfile drops the corresponding production edge.
Independent synthetic-peer wire encoders remain test fixtures.

## Defects and fixes

1. **DNS name confusion.** The decoder joined raw labels with dots, making
   one label containing `wanted.test` compare equal to the two-label name
   `wanted.test`. A new regression failed on the original code. Binary
   octets now have unambiguous escaped representations; the decoder enforces
   the 255-octet expanded wire-name limit and backward compression pointers.
   Normal query names use the parent's hostname validation. Tests cover
   forged questions/answer owners, binary labels, maximum lengths,
   compression, CNAMEs and mutated responses.
2. **Missing DNS resolution-failure cache.** The existing resolver retried
   every failed lookup immediately. RFC 9520 section 3.2 requires at least
   one second of caching. Failures now retain `NoAnswer` for one second,
   using the bounded cache, then retry. They never become NXDOMAIN/NODATA;
   those still use SOA-derived lifetimes. The new regression failed before
   the fix and verifies both query suppression and expiry afterward.
   Successful zero-TTL answers remain uncached. The minimum permitted
   failure delay favors prompt recovery; adaptive backoff is not implemented.
3. **Credential framing hardening.** Endpoint pins now require a public-key
   PEM object, and leaf certificates with trailing DER bytes are refused.
   Valid registered SPKI pins and P-256 SEC1/PKCS#8 device keys still work.
   Wrong server pins and unenrolled client keys fail before business traffic.
4. **IPv6 validation URLs.** The live-download helper passed bracketed IPv6
   URL hosts to DNS/TLS. It now obtains the unbracketed host and validated
   port from the parent's authority parser. Tests cover domain, IPv4 and
   IPv6 URLs and reject credentials, plain HTTP and port zero. This is a
   local helper regression test, not a live WARP result.
5. **Premature TCP TIME-WAIT cleanup.** Dropped streams were removed as
   soon as they entered TIME-WAIT. A deterministic wire test proved that
   losing the final ACK then made a retransmitted peer FIN elicit RST.
   Cleanup now lets smoltcp retain and expire TIME-WAIT, even if the
   application's normal close deadline has expired. The regression covers
   IPv4 and IPv6 and actual ACK loss. Closing sockets remain within the
   64-socket budget; atomic total/lingering counts distinguish them from
   live business flows. The soak verifier checks both held-flow continuity
   and the full socket limit rather than mistaking valid close state for
   an added business flow.
6. **Intermittent bulk-transfer deadlock.** Repeated H3 transfers reproduced
   a timeout while WARP and all other retained flows remained healthy.
   Independent TCP tests then reproduced the same stall without any HTTP
   frontend: receive windows filled under duplex backpressure and packet
   loss, and a zero-window probe timer replaced retransmission while bytes
   remained unacknowledged. The resulting sequence/window state stopped both
   directions. Registry smoltcp 0.14.0 lacked the official upstream
   [RTO/probe interaction fix](https://github.com/smoltcp-rs/smoltcp/commit/bfe5f95404c0f2d0fb26836183869ad7a5d90295).
   The initial repair pinned the official revision containing that fix,
   fast-retransmit retry corrections and the subsequent scaled-window/FIN
   correction. The later conformance follow-up below retains that upstream
   base and records its additional local TCP patch explicitly.
   The new IPv4/IPv6 regression transfers 40 MiB each way with receive
   backpressure and deterministic 1% packet loss. It failed repeatedly before
   the dependency change and passed afterward. Client idle limits and the
   parent server are unchanged. Test-only snapshots and an independent observer
   retain future stall evidence without periodically repolling the transfer.
7. **Unbounded HTTP/3 stream initialization.** A pinned, device-authenticated
   QUIC peer withholding unidirectional stream credit while sending keepalives
   kept public `WarpEgress::connect` pending beyond 20 seconds with a 5-second
   idle timeout. The HTTP/3 builder now has a 15-second deadline and explicitly
   closes QUIC on expiry. Tests cover credit limits 0/1/2, the existing SETTINGS
   timeout and caller cancellation. The latter two cleanup paths already worked.
   This is an availability issue requiring an authenticated outer peer; it does
   not establish a direct attack by unauthenticated frontend clients. The
   follow-up treats parent revision `5b58468b3c9358ffabbb7e28bba59d856b0a2fd9`
   as immutable and changes only this subproject.

## TCP conformance follow-up, November 13, 2026

A local wire audit found that congestion control used the peer's advertised
MSS while segmentation used the smaller path/option limit. With MTU 1280 and
peer MSS 1460, the first timeout emitted 1240+220 bytes before an ACK,
exceeding the actual 1240-byte SMSS. Small peer MSS also exposed excessive
initial bytes, and separate small writes exceeded RFC 5681's initial segment
count despite staying within its byte limit. Lost-SYN fallback, IPv6 omitted
MSS, unusable small-MSS offers and the actual sent-data frontier needed
corresponding corrections.

The pinned upstream source is now vendored with four Rust-file changes. A
fifth packaging-only ignore adjustment keeps all ten upstream parser seeds
visible for normal source export. It updates
effective MSS before ACK/loss handling, preserves grown congestion windows,
caps only startup/fallback, and avoids recomputing CUBIC's cube root for
unchanged MSS. A bounded startup packet gate is released only by an ACK of
new DATA. Explicit MSS 0-47 is refused with cleanup and listener reuse;
omission uses 536 for IPv4 and 1220 for IPv6. ACK validation and fast
retransmission use the actually transmitted frontier, separate from the
rewindable retransmission cursor; ACK/RST replies retain the correct SND.NXT.
No larger experimental initial window or buffer increase was adopted.

Official RFC 9293 section 3.7.1 and ACK-processing requirements, RFC 5681
sections 2/3.1/3.2 and RFC 9438 section 4.8 were checked before changes,
alongside Apple's relay profile/DDM TCP+UDP CONNECT definitions. Independent
in-memory wire fixtures passed 150 cases on the frozen candidate, including
both timestamp modes, tiny writes, SYN loss, safe refusal and hash/EOF
progress. Focused socket units cover acknowledgement bounds, retransmission,
sequence wrap and lifecycle cases. Full product gates and the subsequent
real-time soak are recorded separately in [VALIDATION.md](VALIDATION.md).

The earlier requested 3900-second baseline soak failed after 3842.91 seconds
process runtime during an H1-ingress/WARP-H3 bulk transfer. Its 120 completed
samples do not constitute a pass. A separate unchanged-runtime diagnostic
passed 32 H1 bulk transfers, but did not establish the reset's cause. All
ingress modes now retain progress and failure snapshots without relaxing
the existing deadlines or repolling a stalled transfer.

## Standards and private protocol boundary

The RFC Editor's current index, published texts and Verified errata were
reviewed, including formal updates. Relevant finalized documents include
HTTP RFCs 9110-9114, Extended CONNECT 8441/9220, Capsules/Datagrams
9297/9298/9221, CONNECT-IP 9484 and the 9931 update to 9112/9298. TLS 1.3's
current specification is RFC 9846, replacing 8446. DNS review included
1035, 2181, 2308, 4343, 5452, 6604, 6891, 7766, 8020, 8490, 9103,
9499, 9520 and 9619. TCP/IP behavior is delegated to smoltcp and QUIC/TLS
behavior to Quinn/rustls; RFC 9293 and IPv6 RFC 8200 with update 9673 were
considered. RFC 9267 is informational parser-security guidance, not a new
mandatory protocol. Reported errata and unfinished drafts were not treated
as finalized requirements.

WARP is a private dialect, not generic RFC 9484 CONNECT-IP. H2 uses plain
CONNECT, private headers and bare-IP DATAGRAM Capsules. H3 uses
`cf-connect-ip`, quarter-stream/context framing and native QUIC DATAGRAM.
The existing draft-00 setting, 20-byte connection IDs and pinned H2
absent-ALPN allowance are retained solely as documented WARP compatibility
behavior. They are not offered as standards modes. Removing the unused
generic mode makes pinning and device mTLS mandatory in the transport
options. No transport downgrade, host DNS or direct business connection
path was introduced. Unrecognized traffic remains bounded or discarded.

Official Apple [Relay payload documentation](https://developer.apple.com/documentation/devicemanagement/relay),
[NetworkExtension relays](https://developer.apple.com/documentation/networkextension/relays),
and the published [profile](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.relay.managed.yaml)
and [DDM declaration](https://github.com/apple/device-management/blob/release/declarative/declarations/configurations/network.relay.yaml)
schemas were reviewed. The release-tree snapshot was
`9e7fdbe23990b2551c4b29b39bc8b0de956805eb`. The parent supplies all
client-facing protocol and profile behavior, including H2-only profiles,
domain/FQDN rules, identity references and current DDM output. This audit
changes none of those schemas or interfaces. Linux core tests do not prove
native Apple device routing or trust behavior.

## Verification and limits

[VALIDATION.md](VALIDATION.md) records the completed final-code runs and
their measured results. Logs, official standards snapshots, their hashes,
parent-file hashes and fixed-runner soak evidence are retained under
`target/evidence/audit/` and `target/evidence/`. Interrupted and superseded
runs are not acceptance evidence. Synthetic peers are explicitly not
Cloudflare.

No WARP enrollment credentials or Mac runtime are configured in this
environment. Live account acceptance, exit IP, `warp=on`/`warp=plus`, live
downloads, external PMTU/NAT behavior and native Apple execution remain
unverified. No enrollment or transport fallback was attempted. The existing
64-socket budget, MTU-dependent UDP ceilings, absence of IP fragmentation
and process-restart recovery remain deliberate deployment constraints.
TIME-WAIT duration remains smoltcp 0.14's 10-second timer; the adapter no
longer shortens it. Changing that timer would need a supported upstream
interface. Short-lived TCP connections consume socket capacity during this
period, as well as while connecting or closing.
Privileged installer tests requiring root are unavailable in this non-root
Linux session; this does not establish a WARP transport failure.

The tested behaviors and source review do not constitute an exhaustive
certification of every dependency or deployment condition.
