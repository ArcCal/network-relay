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
  or `:path`, and an empty `:path`. A `:protocol` token the library does not
  know (`connect-tcp`, say) is passed to the server as `ext::OtherProtocol`
  instead of failing the request, so the application can answer it (501).
  Upstream accepted most of these malformed forms.

The relay integration tests cover trailers without FIN, empty DATA, ordinary
half-close, bulk transfers and the malformed requests above; `proto::headers`
has unit tests for each rule (run the crate's tests with `--all-features`). Ordinary HTTP responses still allow trailers.
Remove these changes when equivalent fixes are available upstream.
