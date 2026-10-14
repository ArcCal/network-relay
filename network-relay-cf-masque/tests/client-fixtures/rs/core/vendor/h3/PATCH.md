# Local HTTP/3 fixes and RS copy history

Source: https://github.com/hyperium/h3/tree/43745ad87e95b0c035ac9c547aad467303213425/h3

Original source and MIT license retained. This independent RS copy began with
the NF vendored h3 directory at network-relay revision
`a8cc0e8f3b3949de83634f52ff422c41cb87615d`. The baseline revision identifies the
copy's origin, not byte-for-byte identity after RS changes. Neither the NF copy
nor either server was modified for the RS repairs below.

## Inherited NF patches

Changes inherited from that baseline are confined to:

- `frame.rs`: a FIN with outstanding DATA bytes is a truncated frame, including
  when no payload bytes arrived.
- `connection.rs`, `client/stream.rs`, `server/stream.rs`: an opt-in
  `forbid_trailers()` rejects HEADERS on established CONNECT tunnels immediately
  with H3_FRAME_UNEXPECTED, without waiting for FIN (RFC 9114 section 4.4).
  Empty DATA frames no longer report end-of-body.
- `Cargo.toml`: make the README and development dependency paths standalone.
- `proto/headers.rs`, `server/request.rs`, `ext.rs`: requests are checked as
  RFC 9114 sections 4.3, 4.3.1 and 4.4 and RFC 8441 section 4 require, and
  malformed ones get H3_MESSAGE_ERROR: a pseudo-header field twice, `:status`
  in a request, a classic CONNECT with `:scheme` or `:path` or without
  `:authority`, an extended CONNECT without `:scheme`, `:path` or
  `:authority`, `:protocol` without CONNECT, other requests without `:scheme`
  or `:path`, an empty `:path`, and connection-specific fields
  (`Connection`, `Keep-Alive`, `Proxy-Connection`, `Transfer-Encoding`,
  `Upgrade`, `TE` other than `trailers`; RFC 9114 section 4.2, as h2 checks
  for HTTP/2). A `:protocol` token the library does not
  know (`connect-tcp`, say) is passed to the server as `ext::OtherProtocol`
  instead of failing the request, so the application can answer it (501).
  Upstream accepted most of these malformed forms.
- `server/connection.rs`: the GOAWAY a server sends carries the first request
  stream it will not process, and streams with that ID or higher are
  rejected (RFC 9114 section 5.2). Upstream sent the last accepted ID, the
  HTTP/2 meaning, so a client could retry a request that was processed.
- `server/request.rs`: `RequestResolver::resolve_request_before(deadline)`
  rejects a request whose HEADERS frame has not arrived by `deadline`,
  cancelling both directions of its stream with H3_REQUEST_REJECTED (RFC 9114
  section 4.1.1), so the client may retry it. Dropping the resolver, the only
  way upstream to give up, ends the stream with a FIN and no response.
- `proto/headers.rs`: `TE: trailers` is matched without regard to case, as
  ABNF literals are (RFC 5234 section 2.3).
- `server/request.rs`: the 431 answer to a request whose field section is
  over the limit stops the client's sending with H3_NO_ERROR and finishes the
  response (RFC 9114 section 4.1); upstream dropped the stream, which stopped
  it with code 0.

The inherited source includes `proto::headers` unit tests for these rules.
Ordinary HTTP responses still allow trailers. Their presence is not a claim
that RS executed the standalone upstream test harness; RS package tests and
real-server results are recorded in `../../../docs/STATUS.md`.

## RS-specific patches

- `client/stream.rs`: malformed response header parsing and response pseudo-header
  validation send `STOP_SENDING(H3_MESSAGE_ERROR)`, matching the returned stream
  error. The inherited code sent `H3_REQUEST_CANCELLED` while reporting
  `H3_MESSAGE_ERROR`. RFC 9114 section 4.1.2 requires detected malformed responses
  to be treated as a stream error of type H3_MESSAGE_ERROR. This correction is
  scoped to the independent RS copy; it does not change normal request
  cancellation or the separate field-section-size limit handling.
- `proto/headers.rs`: a named `RequestParts` tuple alias replaces the complex
  `into_request_parts` return signature to satisfy the strict Clippy check.
  The tuple fields, parsed values and protocol behavior are unchanged.

Focused on-wire malformed-response and Capsule-error tests must distinguish
request resets from connection closure; parser rejection alone is insufficient.
HTTP/3 connection-error promotion, where used, follows RFC 9114 section 8 and
retains the detected error code. The focused RS peer suite has passed 12 cases
across HTTP/1.1, HTTP/2 and HTTP/3, including a QPACK-valid response missing
`:status`; final integration results remain separately recorded.
Executed outcomes, exact source fingerprints and remaining gates belong in
`../../../docs/STATUS.md` and `../../../docs/evidence/`.
Remove local changes when equivalent fixes are available upstream.
