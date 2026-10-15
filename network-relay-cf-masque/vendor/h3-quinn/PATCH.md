# Local transport fixes

Source: https://github.com/hyperium/h3/tree/43745ad87e95b0c035ac9c547aad467303213425/h3-quinn

The original MIT license is retained. The H3 union and unmodified H3-Datagram
source originate from that same pinned commit. Explicit sibling path dependencies
make this project independently reusable; no transport source is replaced.

This patch exposes Quinn's existing `SendStream::stopped()` future for accepted
bidirectional streams. Without it, an idle HTTP/3 CONNECT tunnel only learns
about STOP_SENDING when it next writes, contrary to RFC 9114 section 4.4. The relay
takes the future when resolving the request and selects it alongside forwarding.
Unclaimed futures are removed when the corresponding send stream is dropped.

Regression coverage is in `tests/in_process.rs` (idle cancellation, connection
loss and normal half-close). Remove this patch when the upstream transport and
HTTP/3 APIs expose equivalent cancellation notifications.

`RecvStream` keeps its `quinn::RecvStream` in place and polls a fresh
`read_chunk` future (cancel-safe, it only borrows the stream) each time.
Upstream moved the stream into a stored future while a read was pending, and
`stop_sending` called meanwhile was only remembered for when the read
completed: a stream dropped first, as an aborted request or tunnel nearly
always is, sent STOP_SENDING with code 0 instead of the requested HTTP/3
error code (RFC 9114 section 4.1.1). The unused `tokio-util` dependency went
with it. `tests/in_process.rs` checks the codes clients receive
(`http3_aborted_tunnels_stop_the_client_with_the_abort_code`,
`http3_request_whose_headers_never_arrive_is_rejected`); h3's own test suite,
which compiles this file, passes with it. Remove this change when upstream
applies `stop_sending` during a pending read.

This project's shared H3 union retains every transport source file above
unchanged. Only the independent manifest declares its own workspace and uses paths
`../h3` and `../h3-datagram`, so optional datagram support and standalone
checks use the same client/server union. The retained MIT license is unchanged.
See `../../docs/H3-PATCH-PROVENANCE.md` and the source hash manifest in
`../h3/UNION-SOURCE-HASHES.json`.
