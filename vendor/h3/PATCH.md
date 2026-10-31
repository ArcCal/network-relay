# Local HTTP/3 fixes

Source: https://github.com/hyperium/h3/tree/43745ad87e95b0c035ac9c547aad467303213425/h3

Original source and MIT license retained. Changes are confined to:

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
  `RequestResolver::wait_for_data()` waits, without a deadline, for a
  request stream's first byte or end, so a server can start that deadline
  there and leave unwritten streams (implicitly opened lower IDs, RFC 9000
  section 3.2) alone.
- `server/connection.rs`: a CANCEL_PUSH on the client's control stream is a
  connection error of type H3_ID_ERROR, because the server never sends
  PUSH_PROMISE and so has mentioned no push ID (RFC 9114 section 7.2.3), and
  so is a MAX_PUSH_ID smaller than one received before (section 7.2.7).
  Upstream ignored both frames; `tests/connection.rs` covers both and an
  increasing MAX_PUSH_ID.
- `proto/headers.rs`: `TE: trailers` is matched without regard to case, as
  ABNF literals are (RFC 5234 section 2.3).
- `server/request.rs`: the 431 answer to a request whose field section is
  over the limit stops the client's sending with H3_NO_ERROR and finishes the
  response (RFC 9114 section 4.1); upstream dropped the stream, which stopped
  it with code 0.
- `proto/frame.rs`: a frame payload must hold exactly the fields of its type
  (RFC 9114 section 7.1). A CANCEL_PUSH, GOAWAY, MAX_PUSH_ID, SETTINGS or
  PUSH_PROMISE payload that ends inside a field, or has bytes after the last
  one, is a connection error of type H3_FRAME_ERROR. Upstream read a field
  across the end of the payload into the next frame, or left the extra bytes
  to be parsed as one.
- `client/connection.rs`, `client/stream.rs`, `connection.rs`: the client never
  sends MAX_PUSH_ID, so its maximum push ID stays unset (RFC 9114 section
  7.2.7) and no push ID is allowed: a CANCEL_PUSH on the control stream
  (section 7.2.3) and a PUSH_PROMISE on a request stream (section 7.2.5) are
  connection errors of type H3_ID_ERROR. Upstream closed the connection with
  H3_FRAME_UNEXPECTED. `tests/connection.rs` checks both, and the other
  push-frame errors, as the server observes the client's close.
- `connection.rs`: a control frame is no longer lost when the optional grease
  stream (RFC 9114 section 6.2.3) is still being opened. Upstream returned
  Pending after reading the frame and dropped it; where streams open
  asynchronously, as through Network.framework, the first frames after
  SETTINGS (a GOAWAY, or a CANCEL_PUSH that must close the connection) were
  silently ignored.

- `proto/frame.rs`: SETTINGS_H3_DATAGRAM (RFC 9297 section 2.1.1) and
  SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 9220 section 3, RFC 8441 section 3)
  only take the values 0 and 1; any other value is a connection error of type
  H3_SETTINGS_ERROR. Upstream accepted any value and read it as a boolean.
- Client extensions used by network-relay-cf-masque for its Cloudflare WARP
  egress, all off unless a client asks for them: `ext.rs` adds
  `Protocol::from_static` for an outbound vendor `:protocol` (`cf-connect-ip`)
  without changing how received tokens are parsed; `proto/frame.rs`,
  `config.rs` and `client/builder.rs` recognize, and optionally send, the
  draft-00 datagram setting `0x276` (draft-ietf-masque-h3-datagram-00
  section 5, also only 0 or 1); `shared_state.rs` and `client/connection.rs`
  expose the peer's SETTINGS once they have arrived and the error that ended
  the connection. A server never sends `0x276` and treats it as before.

The relay integration tests cover trailers without FIN, empty DATA, ordinary
half-close, bulk transfers and the malformed requests above; `proto::headers`
has unit tests for each rule (run the crate's tests with `--all-features`). Ordinary HTTP responses still allow trailers.
Remove these changes when equivalent fixes are available upstream.
