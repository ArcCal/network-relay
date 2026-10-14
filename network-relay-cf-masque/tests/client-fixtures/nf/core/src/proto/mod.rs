//! Wire formats: QUIC variable-length integers, the HTTP Capsule Protocol
//! and HTTP Datagrams (RFC 9297), and URI Templates as CONNECT-UDP uses them
//! (RFC 9298). Nothing here does I/O, so every rule is unit tested in
//! isolation.

pub mod capsule;
pub mod datagram;
pub mod uri_template;
pub mod varint;

pub use capsule::CapsuleDecoder;
pub use uri_template::UriTemplate;

/// `:protocol` pseudo-header value for CONNECT-UDP requests over HTTP/2 and
/// HTTP/3, and `Upgrade` token over HTTP/1.1 (RFC 9298 §3).
pub const CONNECT_UDP_PROTOCOL: &str = "connect-udp";

/// `:protocol` of draft-ietf-httpbis-connect-tcp ("Template-Driven HTTP
/// CONNECT Proxying for TCP"). Not implemented: such requests are logged so
/// that a client starting to use it is noticed.
pub const CONNECT_TCP_PROTOCOL: &str = "connect-tcp";

/// Path and query of the default URI template: the "masque" well-known URI
/// with the RFC 9298 suffix (RFC 9298 §3.4). Clients configured with just
/// `https://host/` use it.
pub const DEFAULT_UDP_PATH_TEMPLATE: &str = "/.well-known/masque/udp/{target_host}/{target_port}/";

/// Header that marks a request or response as using the Capsule Protocol
/// (RFC 9297 §3.4). Its value is the structured-field boolean `?1`.
pub const CAPSULE_PROTOCOL_HEADER: &str = "capsule-protocol";

/// Errors produced while decoding.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The input ends before the item is complete. Only returned where more
    /// input can legitimately follow (for example a capsule split across
    /// several stream reads).
    #[error("incomplete input")]
    Incomplete,
    /// The input violates the protocol. RFC 9297 §3.3 requires treating a
    /// malformed capsule as a malformed HTTP message, which aborts the stream.
    #[error("malformed: {0}")]
    Malformed(&'static str),
}

/// RFC 9297 section 3.2: Capsule messages cannot carry HTTP content metadata.
pub fn valid_capsule_headers(headers: &http::HeaderMap) -> bool {
    use http::header::{CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING};
    ![CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING]
        .iter()
        .any(|name| headers.contains_key(name))
}
