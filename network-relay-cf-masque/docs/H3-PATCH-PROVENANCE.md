# Shared H3 patch provenance

This project uses one standalone H3 source union for Network Relay ingress and
Cloudflare WARP egress. It preserves the Network Relay server correctness and
native asynchronous transport patches while adding the client extensions
required by Cloudflare's MASQUE dialect. It does not substitute cf-masque's
older server files for the canonical ingress fork.

## Pinned inputs and licenses

| Input | Revision | Retained source |
| --- | --- | --- |
| Original hyperium H3 / H3-Quinn | [`43745ad87e95b0c035ac9c547aad467303213425`](https://github.com/hyperium/h3/tree/43745ad87e95b0c035ac9c547aad467303213425) | Both crate PATCH files cite this upstream base |
| Canonical Network Relay source snapshot | `cc7ea4df2924d0454ab5075e089cbb53d94b178e` | `.research/upstream/network-relay/vendor/h3` and `vendor/h3-quinn` |
| Cloudflare client-extension source snapshot | `a65c600494cd50fed2c621b8538be7abda5e7fa4` | `.research/upstream/cf-masque/vendor/h3` |

Both crate LICENSE files retain the original MIT license verbatim. The project
contains complete standalone crate manifests, not dependencies on sibling
working trees. All production dependencies use explicit project-owned path dependencies;
external consumers need no Cargo patch table. Independent workspaces and
lockfiles permit separate regression runs. The unchanged production
`h3-datagram` source is copied from that exact upstream revision into
`vendor/h3-datagram`, with its H3 dependency resolving to the same local union.
`docs/evidence/h3-datagram-source.json` records its original file hashes.

Exact SHA-256 hashes and file inventories for the canonical, cf-masque, and
resulting union files are recorded in
[`vendor/h3/UNION-SOURCE-HASHES.json`](../vendor/h3/UNION-SOURCE-HASHES.json).
The manifest includes before/after hashes for every retained source file, all
modified manifests and patch documentation, licenses, and independent lockfiles.
Its `source_changes` list is checked against the intended seven-file delta.

## Added APIs and affected files

| File | Addition |
| --- | --- |
| `h3/src/ext.rs` | `Protocol::from_static(&'static str)` constructs outbound custom protocol tokens, including `cf-connect-ip`; existing known constants and inbound parsing remain |
| `h3/src/proto/frame.rs` | Recognize SETTINGS identifier `0x276`; reject invalid boolean values for `0x33`, `0x8`, and `0x276` using the existing settings-error mapping; retain exact frame payload and recognized duplicate SETTINGS checks |
| `h3/src/config.rs` | Preserve the independent draft-00 flag through SETTINGS serialization/deserialization; expose `Settings::enable_datagram_draft00()` |
| `h3/src/client/builder.rs` | Opt-in `Builder::enable_datagram_draft00(bool)` |
| `h3/src/shared_state.rs` | Read peer settings directly from `OnceLock`, distinguishing unreceived settings from received default values |
| `h3/src/client/connection.rs` | `SendRequest::peer_settings()` and diagnostic `connection_error()`; normal typed driver and stream errors are retained |
| `h3/src/tests/connection.rs` | Local QUIC regression for the new APIs and custom extended CONNECT wire roundtrip |

The draft-00 setting is absent by default. Standard HTTP DATAGRAM `0x33` and
draft-00 `0x276` are independently configured and observed. Adding support for
this known identifier does not assign meaning to arbitrary unknown SETTINGS.
The existing eight-entry SETTINGS capacity fits all eight recognized identifiers,
including the draft identifier; the regression suite checks this bound.

The final independent review reproduced an inherited decoder issue: standard
`SETTINGS_H3_DATAGRAM=2` was accepted as true, although
[RFC 9297 section 2.1.1](https://www.rfc-editor.org/rfc/rfc9297#section-2.1.1)
requires the receiver to close with `H3_SETTINGS_ERROR` for any value other than
zero or one. The smallest fix validates the three understood boolean settings
in `Settings::insert`, shared by local construction and wire decoding. Extended
CONNECT's zero-or-one requirement follows [RFC 9220 section 3](https://www.rfc-editor.org/rfc/rfc9220#section-3)
through [RFC 8441 section 3](https://www.rfc-editor.org/rfc/rfc8441#section-3).
The WARP-specific `0x276` value is a legacy draft setting, whose corresponding
[draft-00 section 5](https://www.ietf.org/archive/id/draft-ietf-masque-h3-datagram-00.html#section-5)
has the same boolean restriction; it is not a standardized RFC identifier.
The fix adds no retained allocation and changes no frame capacity, error
mapping, connection driver, or unknown-value handling. In particular,
[RFC 9114 section 7.2.4](https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4)
says receivers **MAY** reject duplicate identifiers, so rejection of unknown
duplicates was not added as a supposed mandatory receiver requirement.

The new protocol constructor does not widen `Protocol::from_str`. A received
valid unknown token continues to reach the server application through
`OtherProtocol`, while malformed tokens and invalid CONNECT pseudoheaders
continue to fail the existing validation. Outbound custom tokens still traverse
the same QPACK/header machinery as registered protocols.

Peer-settings getters do not drive network I/O. The HTTP/3 connection driver
must be polled before received SETTINGS become visible. The getter returns
`None` beforehand, including when fallback settings would otherwise appear as
false values. Shared cloned request senders observe the same SETTINGS and
connection-error state. `connection_error()` is a string diagnostic for the
cf-masque compatibility API; `ConnectionError`, `StreamError`, local protocol
codes, and structured QUIC close variants remain intact.

No `h3/src/server/**`, `h3/src/proto/headers.rs`, `h3/src/connection.rs`,
`h3/src/error/**`, or `h3-quinn/src/**` file differs from the canonical source
snapshot. In particular the union retains malformed frame detection, valid
unknown inbound protocol handling, forbidden CONNECT trailers, push error
codes, correct GOAWAY boundaries, asynchronous grease-frame handling, request
deadline/cancellation behavior, STOP_SENDING propagation, idle cancellation
notifications, and structured transport errors. Both original PATCH files
describe those changes in detail.

## Validation on 2026-10-14

The independent H3 test suite ran with all features and the original canonical
`src/tests` harness: **260 passed, zero failed, zero ignored**, plus **9 passed
doctests**. This includes the full existing frame, QPACK, request validation,
push, GOAWAY, trailers, request cancellation, and transport tests. Seven new
regressions check the custom static protocol constructor, independent draft/RFC
SETTINGS wire roundtrip, explicit draft zero, duplicate draft settings, complete
SETTINGS capacity, absent-versus-received defaults, and the local QUIC API
roundtrip/error visibility.

Three additional frame regressions reject values `2`, `63`, `64`, and
`2^62-1` for each understood boolean identifier; retain zero/one and ignored
unknown maximum values; and verify rejected local insertion consumes no
capacity. The separate root `h3_settings_validation` suite exercises raw QUIC
control streams against the standard relay frontend: all three invalid boolean
settings close with application code `0x109`, and valid zero/one plus an unknown
maximum value still serves the cover site. The same wire test failed against
the original insertion body and passed after the minimal guard. Detailed
before/after evidence is in `docs/evidence/h3-settings-validation.json`.

The independent H3-Quinn all-features suite passed its structured close-error
test: **1 passed, zero failed**. Optional datagram support compiled with the
pinned `h3-datagram` and this H3 union. H3-Quinn had no doctests to execute.

Reproduction from this project directory:

```sh
source scripts/env.sh
cargo test --locked --manifest-path vendor/h3/Cargo.toml --all-features
cargo test --locked --manifest-path vendor/h3-quinn/Cargo.toml --all-features
```

These are local protocol tests and standalone dependency validation. Live WARP
interoperability, full relay integration, large transfers, and soak results are
reported by the project's separate validation work.
