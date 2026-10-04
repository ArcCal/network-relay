//! Extensions for the HTTP/3 protocol.

use std::str::FromStr;

/// Describes the `:protocol` pseudo-header for extended connect
///
/// See: <https://www.rfc-editor.org/rfc/rfc8441#section-4>
#[derive(Copy, PartialEq, Debug, Clone)]
pub struct Protocol(ProtocolInner);

impl Protocol {
    /// WebTransport protocol
    pub const WEB_TRANSPORT: Protocol = Protocol(ProtocolInner::WebTransport);
    /// RFC 9298 protocol
    pub const CONNECT_UDP: Protocol = Protocol(ProtocolInner::ConnectUdp);
    /// RFC 9484 protocol
    pub const CONNECT_IP: Protocol = Protocol(ProtocolInner::ConnectIp);
    /// RFC 9220 (WebSocket) protocol
    pub const WEBSOCKET: Protocol = Protocol(ProtocolInner::WebSocket);

    /// Return a &str representation of the `:protocol` pseudo-header value
    #[inline]
    pub fn as_str(&self) -> &str {
        match self.0 {
            ProtocolInner::WebTransport => "webtransport",
            ProtocolInner::ConnectUdp => "connect-udp",
            ProtocolInner::ConnectIp => "connect-ip",
            ProtocolInner::WebSocket => "websocket",
        }
    }
}

#[derive(Copy, PartialEq, Debug, Clone)]
enum ProtocolInner {
    WebTransport,
    ConnectUdp,
    ConnectIp,
    WebSocket,
}

/// Error when parsing the protocol
pub struct InvalidProtocol;

/// A `:protocol` of an extended CONNECT that is a valid token but not one of
/// the [`Protocol`] values this library knows, such as `connect-tcp`. Server
/// requests carry it as an extension instead of [`Protocol`], so the
/// application can answer it (RFC 8441 section 4 lets any upgrade token
/// appear) rather than the request being rejected as malformed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OtherProtocol(pub(crate) String);

impl OtherProtocol {
    /// The token as received.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Protocol {
    type Err = InvalidProtocol;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "webtransport" => Ok(Self(ProtocolInner::WebTransport)),
            "connect-udp" => Ok(Self(ProtocolInner::ConnectUdp)),
            "connect-ip" => Ok(Self(ProtocolInner::ConnectIp)),
            "websocket" => Ok(Self(ProtocolInner::WebSocket)),
            _ => Err(InvalidProtocol),
        }
    }
}
