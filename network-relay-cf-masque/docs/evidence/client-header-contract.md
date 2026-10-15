# Unchanged NF / RS client header and framing contract

This is a read-only source audit recorded on 2026-10-14. It does not claim a native Apple run, a live WARP result, or execution of the client tests. The implementation and integration runs have separate evidence. References to parent working trees are bound to the SHA-256 inventories below; a repository HEAD alone does not identify their pre-existing local changes.

## Identity and scope

| Alias | Exact audited location | Identity |
| --- | --- | --- |
| NF | `/workspace/network-relay/network-realy-nf/Core` | Actual unchanged parent NF core; package `network-realy-nf-core` 0.1.0, edition 2024. The directory and package have the legacy `realy` spelling. |
| RS | `/workspace/network-relay/network-relay-rs/Core` | Actual unchanged parent RS core; package `network-relay-rs-core` 0.1.0, edition 2024, Rust >=1.88. |
| CNF | `PROJECT/.research/upstream/network-relay/network-relay-nf/Core` | Canonical snapshot at `cc7ea4df2924d0454ab5075e089cbb53d94b178e`; package spelling is corrected to `network-relay-nf-core`. |
| CRS | `PROJECT/.research/upstream/network-relay/network-relay-rs/Core` | Canonical RS snapshot at the same commit. It is not byte-identical to actual RS. |
| H3 | `PROJECT/vendor/h3` | Project ingress/WARP union, upstream base `43745ad87e95b0c035ac9c547aad467303213425`, canonical Network Relay input `cc7ea4df2924d0454ab5075e089cbb53d94b178e`, cf-masque client input `a65c600494cd50fed2c621b8538be7abda5e7fa4`. |

`PROJECT` is `/workspace/network-relay/network-relay-cf-masque`. Parent repository HEAD at inspection was `27bccd28f97d6c45067abb6495b50321061de1c5`; canonical checkout HEAD was `cc7ea4df2924d0454ab5075e089cbb53d94b178e`. Parent VERSION files both say 0.1.0. Treat their source hashes, not that shared version string, as the exact client identity.

The actual NF lock is `NF/Cargo.lock`; RS uses its enclosing `network-relay-rs/Cargo.lock`. Both resolve h2 0.4.20, hyper 1.12.0, tokio 1.53.2, local h3 0.0.8 and an additional git h3 0.0.8 at the upstream base. NF's dev Quinn is 0.11.8; actual RS uses Quinn 0.11.12 and sfv 0.14.0. The registry/git h3 entry does not make the local path h3 source interchangeable with the project union. See [NF manifest](../../tests/client-fixtures/nf/core/Cargo.toml:18), [RS manifest](../../tests/client-fixtures/rs/core/Cargo.toml:19), and the lock fingerprints below.

## Accepted responses: actual clients versus canonical snapshots

| Contract | Actual NF | Actual RS | Snapshot differences |
| --- | --- | --- | --- |
| H1 classic TCP CONNECT | Exactly 200. | The status check permits every 2xx. | CNF now permits every 2xx and manually takes back Hyper's connection to handle the 204 tunnel handoff; CRS already permits 2xx but retains automatic upgrade. |
| H1 UDP Upgrade | Exactly 101; `Upgrade: connect-udp` case-insensitive; `Connection` contains an `upgrade` token. | Exactly 101; exactly one Upgrade field containing only `connect-udp` after surrounding ASCII whitespace; Connection includes `upgrade`. | CNF now also checks exactly one Upgrade field. |
| H2/H3 classic TCP | Exactly 200. | Every 2xx. | CNF now permits every 2xx; CRS permits every 2xx. |
| H2/H3 UDP | Exactly 200. | 2xx except 204, 205, 206. | CNF permits 2xx except 204–206; CRS permits 2xx without actual RS's additional 204–206 rejection. |
| UDP Capsule-Protocol | A looked-up field value must be byte-exact `?1`; parameters/whitespace/missing value fail. It does not explicitly count repeated fields. | Exactly one Structured Field Item with Boolean true; valid unknown parameters accepted; lists/repeated fields, false, malformed item fail. | CNF now ignores the Capsule-Protocol field because the protocol token determines framing. CRS still requires the parsed Item. |
| UDP content headers | Reject Content-Length, Content-Type and Transfer-Encoding, including zero length. | Same. | Common to both canonical copies too. |
| H3 informational HEADERS | Calls `recv_response()` once; a 1xx response fails its exact-200 check. | Reads repeated informational HEADERS under one deadline, rejects H3 101 with H3_MESSAGE_ERROR, then validates final status. | CNF and CRS each currently call `recv_response()` once; actual RS contains later response handling repairs. |

Evidence: [NF expected status and Capsule check](../../tests/client-fixtures/nf/core/src/client.rs:434), [NF H1 request/response/upgrade](../../tests/client-fixtures/nf/core/src/client.rs:227), [NF H2 result](../../tests/client-fixtures/nf/core/src/client.rs:206), [NF H3 result](../../tests/client-fixtures/nf/core/src/client.rs:328), [NF content headers](../../tests/client-fixtures/nf/core/src/proto/mod.rs:46); [RS status and Capsule check](../../tests/client-fixtures/rs/core/src/client.rs:497), [RS structured Item parser](../../tests/client-fixtures/rs/core/src/proto/mod.rs:32), [RS single Upgrade parser](../../tests/client-fixtures/rs/core/src/client.rs:533), [RS H1 Upgrade handoff](../../tests/client-fixtures/rs/core/src/client.rs:264), [RS informational handling](../../tests/client-fixtures/rs/core/src/client.rs:340). Snapshot evidence: [CNF expanded response check](../../tests/client-fixtures/nf-current/core/src/client.rs:487), [CNF manual H1 takeover](../../tests/client-fixtures/nf-current/core/src/client.rs:242), [CRS current status check](../../tests/client-fixtures/rs-current/core/src/client.rs:439).

The project's actual frontend sends 200 for successful TCP and extended UDP, exact `capsule-protocol: ?1` for UDP, and 101 plus Connection/Upgrade/Capsule-Protocol for H1 UDP. It therefore satisfies the actual-client intersection. [H2 response](/workspace/network-relay/network-relay-cf-masque/crates/relay-frontend/src/server/over_tcp.rs:384), [H1 response](/workspace/network-relay/network-relay-cf-masque/crates/relay-frontend/src/server/over_tcp.rs:511), [H3 response](/workspace/network-relay/network-relay-cf-masque/crates/relay-frontend/src/server/over_h3.rs:471). Do not substitute a newer snapshot's acceptance rules for evidence about unchanged parent NF.

Actual RS's permissive status check is not evidence that every H1 2xx completes the full upgrade handoff. Its H1 path still calls `hyper::upgrade::on`, while CNF's manual takeover comment specifically identifies automatic Hyper's 204 exclusion. This audit has not executed an RS H1 204 peer fixture; the current frontend's 200 avoids that path.

## Reliable Capsules and QUIC DATAGRAM negotiation

Both actual clients configure H3 with Extended CONNECT enabled, HTTP DATAGRAM disabled, grease disabled and a 16 KiB field-section limit. They wait for peer Extended CONNECT SETTINGS before sending UDP, put `connect-udp` into the H2/H3 protocol extension, and send `capsule-protocol: ?1`. [NF H3 settings/request](../../tests/client-fixtures/nf/core/src/client.rs:288), [NF H2 settings/request](../../tests/client-fixtures/nf/core/src/client.rs:185), [RS H3 settings/request](../../tests/client-fixtures/rs/core/src/client.rs:294), [RS request header](../../tests/client-fixtures/rs/core/src/client.rs:129).

Their UdpFlow implementation writes DATAGRAM Capsule type 0, containing context ID 0 followed by payload, through the reliable CONNECT stream. It does not send QUIC DATAGRAM frames. The send-side payload bound is 65,507 bytes. Receive decoding skips unknown contexts, and an empty UDP payload is accepted when context 0 is present. A DATAGRAM Capsule with an empty value is malformed for UDP because it has no context ID; that is distinct from a valid zero-length UDP payload. [NF UdpFlow send/recv](../../tests/client-fixtures/nf/core/src/client.rs:468), [RS UdpFlow send/recv](../../tests/client-fixtures/rs/core/src/client.rs:667), [common UDP context decoder](../../tests/client-fixtures/nf/core/src/proto/capsule.rs:122).

Unknown Capsule types and unknown UDP contexts are skipped incrementally, including values above the UDP buffering bound. Partial Capsule headers/values may span reads; a FIN with buffered bytes or unfinished skip state is a malformed Capsule stream. NF returns the decoding error through `?`; actual RS additionally calls `abort_malformed`, selecting H2 PROTOCOL_ERROR / H3 H3_MESSAGE_ERROR teardown. [common skip and bound handling](../../tests/client-fixtures/nf/core/src/proto/capsule.rs:95), [common Capsule finish](../../tests/client-fixtures/nf/core/src/proto/capsule.rs:156), [NF FIN check](../../tests/client-fixtures/nf/core/src/client.rs:487), [RS malformed handling](../../tests/client-fixtures/rs/core/src/client.rs:677), [RS stream malformed abort](../../tests/client-fixtures/rs/core/src/stream.rs:324).

The frontend advertises DATAGRAM capability, but its send path checks peer SETTINGS and uses reliable DATAGRAM Capsules when peer DATAGRAM is disabled or the transport has no DATAGRAM capability. [frontend H3 SETTINGS](/workspace/network-relay/network-relay-cf-masque/crates/relay-frontend/src/server/over_h3.rs:264), [peer setting fallback](/workspace/network-relay/network-relay-cf-masque/crates/relay-frontend/src/tunnel.rs:281). Thus successful unchanged NF/RS UDP exercises Capsule delivery, not peer QUIC DATAGRAM support. Separate datagram-enabled clients are needed for the QUIC DATAGRAM branch.

## DATA, trailers, FIN and stream 0

| Case | Source contract and implication |
| --- | --- |
| H2 empty DATA | NF/RS receive loops process zero-length bytes without closing their sink and continue reading. Only end-of-stream triggers sink shutdown. Upload EOF explicitly sends an empty DATA frame with END_STREAM. [NF H2 receive](../../tests/client-fixtures/nf/core/src/stream.rs:102), [NF H2 upload FIN](../../tests/client-fixtures/nf/core/src/stream.rs:130), [RS equivalent](../../tests/client-fixtures/rs/core/src/stream.rs:158). |
| H3 empty DATA | Both actual clients' vendored RequestStream implementations loop over DATA frames until there are body bytes or transport FIN. Empty DATA is not `None`/EOF. These DATA/FIN rules and frame handling are retained by the project union. [common vendored loop](../../tests/client-fixtures/nf/core/vendor/h3/src/connection.rs:865). |
| Truncated DATA at FIN | Vendored `FrameStream::poll_data` reports UnexpectedEnd if a finite DATA payload remains, including a frame header followed by FIN without payload. A FIN with partial frame bytes also fails. [common finite-frame boundary](../../tests/client-fixtures/nf/core/vendor/h3/src/frame.rs:86), [DATA payload boundary](../../tests/client-fixtures/nf/core/vendor/h3/src/frame.rs:111). |
| CONNECT trailers | NF/RS H2 receive loops reject trailers after DATA; actual RS explicitly resets with PROTOCOL_ERROR. H3 calls `forbid_trailers()` before splitting; later HEADERS cause H3_FRAME_UNEXPECTED immediately. [NF H2 trailers](../../tests/client-fixtures/nf/core/src/stream.rs:108), [RS H2 trailers reset](../../tests/client-fixtures/rs/core/src/stream.rs:164), [NF H3 setup](../../tests/client-fixtures/nf/core/src/stream.rs:168), [RS H3 setup](../../tests/client-fixtures/rs/core/src/stream.rs:238), [common H3 HEADERS rejection](../../tests/client-fixtures/nf/core/vendor/h3/src/connection.rs:875). |
| Clean half-close | H3 upload drains stream bytes before `send.finish`; the QUIC backend flushes pending writes and invokes native shutdown. H2 upload emits END_STREAM only after draining its local pipe. Actual RS additionally waits for upload-pump completion before exposing Stream shutdown success; actual NF lacks that later pump-drain wait. [NF H3 upload](../../tests/client-fixtures/nf/core/src/stream.rs:215), [NF QUIC finish](../../tests/client-fixtures/nf/core/src/quic.rs:81), [RS shutdown acknowledgement](../../tests/client-fixtures/rs/core/src/stream.rs:394). |
| Transport loss versus EOF | Both actual cores drain already received bytes before surfacing non-security transport errors, and never treat failure-induced channel closure as clean EOF. Security rejection bypasses buffered payload. [NF native read](../../tests/client-fixtures/nf/core/src/native.rs:483), [RS native read](../../tests/client-fixtures/rs/core/src/native.rs:497), [NF Stream error propagation](../../tests/client-fixtures/nf/core/src/stream.rs:252), [RS equivalent](../../tests/client-fixtures/rs/core/src/stream.rs:361). |
| Native callback DATA versus FIN | Native READY metadata accepts all stream IDs below 2^62, including 0. DATA uses flags=1 for EOF; an empty flags=0 callback is not application data/EOF. Encoded HTTP empty DATA still has nonempty frame-header bytes and must be passed as ordinary native DATA. [NF READY/DATA input](../../tests/client-fixtures/nf/core/src/native.rs:239), [RS READY/DATA input](../../tests/client-fixtures/rs/core/src/native.rs:239). |
| Stream 0 | Core QUIC stream IDs come from READY and are converted directly to H3 StreamId; 0 is not a sentinel. The platform can own an unwritten lower stream while a later request uses ID 4. The frontend now waits for a stream's first bytes before starting the header deadline, preserving implicit/unwritten lower IDs. [common QUIC StreamId](../../tests/client-fixtures/nf/core/src/quic.rs:29), [frontend resolver scheduling](/workspace/network-relay/network-relay-cf-masque/crates/relay-frontend/src/server/over_h3.rs:302), [union wait_for_data](/workspace/network-relay/network-relay-cf-masque/vendor/h3/src/server/request.rs:81). |

CNF's explicit stream-zero diagnostic states that its Quinn emulator represents the server-side question, not Network.framework's reaction to its group-owned stream. Its `idle_group_stream_zero` is ignored by default and requires an external fixture; its presence is not evidence of a run here. [diagnostic scope](../../tests/client-fixtures/nf-current/core/tests/idle_stream_zero.rs:1), [ignored test](../../tests/client-fixtures/nf-current/core/tests/idle_stream_zero.rs:12), [13-second observation](../../tests/client-fixtures/nf-current/core/tests/idle_stream_zero.rs:40). Do not claim native NWConnectionGroup stream-0 lifetime from portable backend tests alone.

## H3 union compatibility and concrete differences

The project union preserves the canonical server/protocol files and adds a static outbound custom protocol constructor, independent opt-in draft-00 DATAGRAM setting 0x276, peer-SETTINGS readiness and diagnostic connection-error access. `Protocol::from_static` does not widen inbound FromStr; valid unknown inbound tokens still reach `OtherProtocol`. The draft flag defaults false and is independent of standard 0x33. [union protocol constructor/parser](/workspace/network-relay/network-relay-cf-masque/vendor/h3/src/ext.rs:25), [draft client builder](/workspace/network-relay/network-relay-cf-masque/vendor/h3/src/client/builder.rs:104), [draft setting default](/workspace/network-relay/network-relay-cf-masque/vendor/h3/src/config.rs:142), [peer settings accessor](/workspace/network-relay/network-relay-cf-masque/vendor/h3/src/client/connection.rs:149), [union provenance](/workspace/network-relay/network-relay-cf-masque/docs/H3-PATCH-PROVENANCE.md:1).

Actual NF and RS use known `connect-udp` and disable DATAGRAM; these additions do not change their request token or Capsule framing. There is no source-evidenced success-path conflict between their existing 200/101 exchanges and the union. A source compatibility conclusion is not a substitute for the parent's unchanged-core wire harness.

One concrete error-path difference matters: actual RS vendored `client/stream.rs` sends STOP_SENDING(H3_MESSAGE_ERROR) when response header parsing or pseudo-header validation fails. The union retains the canonical NF/base behavior sending H3_REQUEST_CANCELLED while returning a typed H3_MESSAGE_ERROR. [actual RS malformed response](../../tests/client-fixtures/rs/core/vendor/h3/src/client/stream.rs:175), [union malformed response](/workspace/network-relay/network-relay-cf-masque/vendor/h3/src/client/stream.rs:184), [actual NF inherited behavior](../../tests/client-fixtures/nf/core/vendor/h3/src/client/stream.rs:176). Replacing RS's path dependency with the union would remove that RS repair. The union's additional PUSH_PROMISE guard correctly rejects unauthorized push IDs with H3_ID_ERROR; the actual client copies have the older first-response-frame behavior. [union push guard](/workspace/network-relay/network-relay-cf-masque/vendor/h3/src/client/stream.rs:122).

The actual NF/RS vendored H3 `frame.rs` are identical to the union, and the inspected CONNECT trailer/empty-DATA behavior is retained; the whole `connection.rs` is not identical because canonical later repairs include control/push/grease behavior. The full changed-file lists and hashes below distinguish retained behavior from byte identity. The independent union test results already recorded in its provenance are 257 H3 unit tests plus 9 doctests and 1 H3-Quinn test; this audit did not rerun them.

## Recommendations for the actual-core harness

1. Keep actual NF and RS source/package/vendor identities separate from CNF/CRS. Preserve the existing 200 TCP/extended UDP, 101 H1 UDP and exact singleton `capsule-protocol: ?1` response intersection; send no UDP content metadata.
2. Link each core against its own unchanged path-vendored H3. Separate harness workspaces avoid collisions between same-name/version path crates. A source-only core copy with manifest adaptations must record those adaptations; using one shared H3 for both is a distinct variant, especially on malformed RS responses.
3. Exercise H1/H2/H3 TCP and reliable UDP Capsules against both selected WARP H2/H3 packet paths. Record Capsule fallback explicitly: neither unchanged core negotiates HTTP DATAGRAM. Add empty UDP payload, unknown Capsule/context skipping, truncated Capsule FIN, empty H3 DATA, TCP tail hash/half-close/reset, and an unwritten lower-stream-ID case.
4. Separate actual NF's exact-status/strict-header behavior and RS's broader acceptance/error repairs in peer fixtures. H3 informational responses and H1 204 handoff need their own assertions; do not infer those from successful frontend 200 exchanges.
5. Portable native-bridge/Quinn emulation validates protocol-core behavior with that backend. It does not certify Apple Network.framework callback timing, group-owned stream-0 reactions, entitlements, GUI/device behavior, or live Cloudflare connectivity.

## Fingerprints and complete tree deltas

The tree digest is SHA-256 of UTF-8 lines `sha256  relative/path\n`, sorted by relative POSIX path, for every regular file below the root except paths containing a `target` component. It includes manifests, locks where present, tests, vendored source and patch documentation. Per-file manifests below bind the files used for the contract; full-tree digests and exhaustive delta lists detect differences elsewhere without claiming their uninspected behavior.

| Tree | Regular files | Complete manifest SHA-256 |
| --- | ---: | --- |
| NF | 73 | `4341359edb28444c0b0cac35ed40ff253af14f40cf5aac81845d202553bf32c8` |
| RS | 74 | `2774bedaed0fcafa5d3532a54d4be51208888c87dea8b2150d5b87aebf9b83d9` |
| CNF | 78 | `d9c7f5c13ff9410f61ea1bf341e4e9eb08a497e6b7efc9d6e40910fd88f223f9` |
| CRS | 71 | `bce0179a9e1dd4c145ca9415ef5c1518fd34e6eeb9a56862451761a6be8a4a06` |
| H3 | 57 | `7a457fd4dc379e17cb43b6e87b04594e8a9c04001c2cd29d7a44bcf24599fc8d` |

Actual-parent minus canonical deltas (all names relative to each Core):

- NF: added none; absent tests/idle_stream_zero.rs, tests/large_transfer.rs, tests/push_frames.rs, tests/response_compat.rs, tests/socks_methods.rs. Changed common files: Cargo.lock, Cargo.toml, src/client.rs, src/lib.rs, src/native.rs, src/socks.rs, src/stream.rs, tests/ffi_lifecycle.rs, tests/native_boundary.rs, tests/server_interop.rs, tests/support/mod.rs, vendor/h3/PATCH.md, vendor/h3/src/client/connection.rs, vendor/h3/src/client/stream.rs, vendor/h3/src/connection.rs, vendor/h3/src/proto/frame.rs, vendor/h3/src/tests/connection.rs.
- RS: added tests/capsule_errors.rs, tests/h2_drain.rs, tests/informational.rs; absent none. Changed common files: src/backend.rs, src/client.rs, src/native.rs, src/socks.rs, src/stream.rs, tests/server_interop.rs, vendor/h3/PATCH.md, vendor/h3/src/client/stream.rs, vendor/h3/src/proto/headers.rs.

Project-union H3 minus actual-client H3 deltas:

- Versus NF: added Cargo.lock, UNION-SOURCE-HASHES.json; absent none. Changed common files: Cargo.toml, PATCH.md, src/client/builder.rs, src/client/connection.rs, src/client/stream.rs, src/config.rs, src/connection.rs, src/ext.rs, src/proto/frame.rs, src/server/builder.rs, src/server/connection.rs, src/server/request.rs, src/shared_state.rs, src/tests/connection.rs.
- Versus RS: added Cargo.lock, UNION-SOURCE-HASHES.json; absent none. Changed common files: Cargo.toml, PATCH.md, src/client/builder.rs, src/client/connection.rs, src/client/stream.rs, src/config.rs, src/connection.rs, src/ext.rs, src/proto/frame.rs, src/proto/headers.rs, src/server/builder.rs, src/server/connection.rs, src/server/request.rs, src/shared_state.rs, src/tests/connection.rs.

### Audited-source per-file SHA-256 manifests

**NF**

```text
925cd96e691a23af005dcb446ccaebfb51a341c86fa5ecc79b4d85e07530e82d  Cargo.toml
40f1b95b2ea05c9daf230875cf641b2fbf0eec57291d83c3bd297d68821ed7f2  src/client.rs
b131b42c6f49cd98b147e204c8459ec34fc69fa4d2535725f8850840bf776bdd  src/native.rs
899a8c9f3af600828e03c08bace54d46504edf9303aa9386bee938d4292ae2a9  src/quic.rs
f2fd17cd1dfa46d2c64f27dfb6a647410ccef23c06085f725fd3ece511fcb6f2  src/stream.rs
5bfb8026ccdc1813a054e5620aca84626f145c22fee8fe0bbec20995fa2e6e95  src/proto/mod.rs
14f2dcd8bdbcc1121336cce27e3cfcbb063db7c14d94160c8a9722fc31432161  src/proto/capsule.rs
8e503d6c4c65f3c25c5170a75db48694c1d4b392d0c3b68df987ac124e968e95  vendor/h3/Cargo.toml
a7841581440cb8b5b42019d314e4c00eed5ba871ae30279265b078f0c4149842  vendor/h3/PATCH.md
929373211718e211defe1150ed2b9e1e3265c31941d9ba2cb8e74df51931298e  vendor/h3/src/client/stream.rs
5ddd49ece41ee9ca87230be3edc1c7fb7e445cfb10c70d32c0b5d8837bc44386  vendor/h3/src/connection.rs
feaa654c3925ff44b11e9dc8136c67740292fc395dd77074d5e6fbc207abd55f  vendor/h3/src/frame.rs
```

**RS**

```text
de33fed7e1b0b7ee8bedaec1ffc809675a6ecafd9e9b57c617867d3e17cbee27  Cargo.toml
697434c46f4c26dfe634e9f64c23892d20a3bcf0bb21aa5f6a1dc64432ab64f1  src/client.rs
c01c5d821242e08a704030285ce4f355707523e9951b358d136001b17b5fe10d  src/native.rs
899a8c9f3af600828e03c08bace54d46504edf9303aa9386bee938d4292ae2a9  src/quic.rs
6cc99848906c0d34353ed752c3a400bb665bf715193c1ed0bba98db847672ea3  src/stream.rs
647d841589b5c71a0e08c799f9eee6e918a035fa45c4abfd933888ea801b43cf  src/proto/mod.rs
14f2dcd8bdbcc1121336cce27e3cfcbb063db7c14d94160c8a9722fc31432161  src/proto/capsule.rs
8e503d6c4c65f3c25c5170a75db48694c1d4b392d0c3b68df987ac124e968e95  vendor/h3/Cargo.toml
681447f55aaa246842492303dfad0e6ef49827796345fba3f9afc0ee0382330e  vendor/h3/PATCH.md
294feba5852e88d0f96f0dfd481fdc77f908a489fac7200d2225b06c29fbf024  vendor/h3/src/client/stream.rs
5ddd49ece41ee9ca87230be3edc1c7fb7e445cfb10c70d32c0b5d8837bc44386  vendor/h3/src/connection.rs
feaa654c3925ff44b11e9dc8136c67740292fc395dd77074d5e6fbc207abd55f  vendor/h3/src/frame.rs
```

**CNF**

```text
ffe6395f651d566b8a0dd95785d39e6316cc1d5a1b57f5269554617e6a009fcb  Cargo.toml
71ecc3c584b3ba44254eff2c53acf5ef9b5843bf850e06c422e58962fd673207  src/client.rs
c6d3a0f7bdc19547b6f0492705da561d532f753abb806fc6e644cc5be3eaf2d6  src/native.rs
899a8c9f3af600828e03c08bace54d46504edf9303aa9386bee938d4292ae2a9  src/quic.rs
a874b0165db0f8f30b182d72684b588557d9ab0b3b7cdedd3d993771534eace9  src/stream.rs
5bfb8026ccdc1813a054e5620aca84626f145c22fee8fe0bbec20995fa2e6e95  src/proto/mod.rs
14f2dcd8bdbcc1121336cce27e3cfcbb063db7c14d94160c8a9722fc31432161  src/proto/capsule.rs
8e503d6c4c65f3c25c5170a75db48694c1d4b392d0c3b68df987ac124e968e95  vendor/h3/Cargo.toml
554cc79fa25b1f4d0257cdfb8c41b0bfdb34d61ef9d2a1c6e417631e0c598858  vendor/h3/PATCH.md
a5a8b01be592319c86545c8cf42a2f4e962d1692dc230578ab8c8b7c44ace0c6  vendor/h3/src/client/stream.rs
838261573897eddb5de0e1d18d9c099d42d8f54c17b8d0918f5b03e84862ad38  vendor/h3/src/connection.rs
feaa654c3925ff44b11e9dc8136c67740292fc395dd77074d5e6fbc207abd55f  vendor/h3/src/frame.rs
```

**CRS**

```text
de33fed7e1b0b7ee8bedaec1ffc809675a6ecafd9e9b57c617867d3e17cbee27  Cargo.toml
2794b98030383a52be24b4802fc12065bc8e0064b776b3ccf200dedfcbcb48ab  src/client.rs
965ecb61e327651e96336929a3a016476580188da534ae67749b03c5b159572f  src/native.rs
899a8c9f3af600828e03c08bace54d46504edf9303aa9386bee938d4292ae2a9  src/quic.rs
f2fd17cd1dfa46d2c64f27dfb6a647410ccef23c06085f725fd3ece511fcb6f2  src/stream.rs
647d841589b5c71a0e08c799f9eee6e918a035fa45c4abfd933888ea801b43cf  src/proto/mod.rs
14f2dcd8bdbcc1121336cce27e3cfcbb063db7c14d94160c8a9722fc31432161  src/proto/capsule.rs
8e503d6c4c65f3c25c5170a75db48694c1d4b392d0c3b68df987ac124e968e95  vendor/h3/Cargo.toml
a7841581440cb8b5b42019d314e4c00eed5ba871ae30279265b078f0c4149842  vendor/h3/PATCH.md
929373211718e211defe1150ed2b9e1e3265c31941d9ba2cb8e74df51931298e  vendor/h3/src/client/stream.rs
5ddd49ece41ee9ca87230be3edc1c7fb7e445cfb10c70d32c0b5d8837bc44386  vendor/h3/src/connection.rs
feaa654c3925ff44b11e9dc8136c67740292fc395dd77074d5e6fbc207abd55f  vendor/h3/src/frame.rs
```

**Locks and project union**

```text
9dde1639a405e827572b5d0036b79032a8a214bfb95703b38d7f467cedfc2015  NF/Cargo.lock
846ecbb078b0eda86f13634959558aa32ff49111bbe521b41d3b0059103891f4  RS enclosing Cargo.lock
f0d6009da29291d8b5d08fb5c8a0a7070ec66cab6dc8f0a162df7ecb39d686f4  CNF/Cargo.lock
846ecbb078b0eda86f13634959558aa32ff49111bbe521b41d3b0059103891f4  CRS enclosing Cargo.lock
725786df0e4818e395ff920a6328688cb10150323c995042c417a17ac8cfa96d  H3/UNION-SOURCE-HASHES.json
f3a4412ebdfe096b1dc1d83f9b9dfe937bef7682dda992ee8b41874e7335e5db  H3/Cargo.toml
f6c2e7ae858708601af5bf0687f17524df26543de299bfc4f0f57002e4c0635a  H3/PATCH.md
ce19a5e43be3044a6a488afd5405f64016cf4f1d11e8dfffd7cf266f11375d6a  H3/src/ext.rs
ae925f5c3744d9729c7820dc30e2f81d4bf23382cdb25c0504c72c4fe47de366  H3/src/client/builder.rs
b033c2d7599834aa5154e4c861113145edc30c5913087fc30c5a7a992022b1f3  H3/src/client/connection.rs
a5a8b01be592319c86545c8cf42a2f4e962d1692dc230578ab8c8b7c44ace0c6  H3/src/client/stream.rs
9712f360a6a30ad9bac4608612f6db33c6880fc7606d2a4583b40f6ea15cb6b3  H3/src/config.rs
838261573897eddb5de0e1d18d9c099d42d8f54c17b8d0918f5b03e84862ad38  H3/src/connection.rs
feaa654c3925ff44b11e9dc8136c67740292fc395dd77074d5e6fbc207abd55f  H3/src/frame.rs
fea14cfdf85eaae4fd5e06dd6e721a2b69311f79f9692f47063b3bbfbf70823b  H3/src/proto/frame.rs
8d323bf5b45c7fd6b47082d390973c03473d9cdd8369598a72c864821d33adc3  H3/src/proto/headers.rs
c718fd89d7309a3b6ec0d338843d279310d3203300d54a6fd394079515a869ee  H3/src/server/request.rs
23d548f260edcc8f3bfe6f6bf763af5376299837862dd8ff30e1ca0cbb3d3e8e  H3/src/shared_state.rs
```

**Frontend response/framing snapshot** (line evidence reflects these file versions)

```text
832a3b444703cb3913de3947c39a6aba01836aa5f4feb2848dee8cab929b62a5  FE/server/over_tcp.rs
d3cc983a94fe7cd8571e28dd3473ddecdbb9cbcb78be1c99563ab7fafcf39aef  FE/server/over_h3.rs
c8360126e7ae7715eccba65d5302302ccbe23551bae3eb5ec4c390d370a010ea  FE/tunnel.rs
```
