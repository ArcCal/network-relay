# Local transport fix

Source: https://github.com/hyperium/h3/tree/43745ad87e95b0c035ac9c547aad467303213425/h3-quinn

The original MIT license is retained. The h3 and h3-datagram dependencies remain
pinned to that same commit; no protocol implementation is replaced.

This patch exposes Quinn's existing `SendStream::stopped()` future for accepted
bidirectional streams. Without it, an idle HTTP/3 CONNECT tunnel only learns
about STOP_SENDING when it next writes, contrary to RFC 9114 section 4.4. The relay
takes the future when resolving the request and selects it alongside forwarding.
Unclaimed futures are removed when the corresponding send stream is dropped.

Regression coverage is in `tests/in_process.rs` (idle cancellation, connection
loss and normal half-close). Remove this patch when the upstream transport and
HTTP/3 APIs expose equivalent cancellation notifications.
