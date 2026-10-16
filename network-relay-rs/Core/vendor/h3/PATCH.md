# Local HTTP/3 fixes

Source: https://github.com/hyperium/h3/tree/43745ad87e95b0c035ac9c547aad467303213425/h3

Original source and MIT license retained. Changes are confined to:

- `client/connection.rs`: recheck GOAWAY after waiting for request-stream
  capacity, before writing HEADERS (RFC 9114 section 5.2).
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

The relay integration tests cover trailers without FIN, empty DATA, ordinary
half-close, bulk transfers and the malformed requests above; `proto::headers`
has unit tests for each rule (run the crate's tests with `--all-features`). Ordinary HTTP responses still allow trailers.
Remove these changes when equivalent fixes are available upstream.
