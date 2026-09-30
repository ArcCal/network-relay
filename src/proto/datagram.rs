//! HTTP Datagram payloads for CONNECT-UDP (RFC 9298 §5).
//!
//! ```text
//! UDP Proxying HTTP Datagram Payload {
//!   Context ID (i),
//!   UDP Proxying Payload (..),
//! }
//! ```
//!
//! Context ID 0 carries the payload of one UDP datagram. Other context IDs
//! are reserved for extensions; receivers drop datagrams with context IDs
//! they do not know (RFC 9298 §4).

use bytes::{BufMut, Bytes, BytesMut};

use super::{varint, Error};

/// Context ID of datagrams that carry a UDP payload.
pub const CONTEXT_ID_UDP_PAYLOAD: u64 = 0;

/// Splits an HTTP Datagram payload into its context ID and the rest.
pub fn split_context_id(payload: &[u8]) -> Result<(u64, &[u8]), Error> {
    let mut view = payload;
    match varint::decode(&mut view) {
        Ok(id) => Ok((id, view)),
        Err(_) => Err(Error::Malformed("datagram too short for a context ID")),
    }
}

/// An HTTP Datagram payload carrying `udp_payload` with context ID 0.
pub fn udp_payload(udp_payload: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(1 + udp_payload.len());
    out.put_u8(CONTEXT_ID_UDP_PAYLOAD as u8);
    out.put_slice(udp_payload);
    out.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_context_zero() {
        assert_eq!(split_context_id(&[0x00, 0x45, 0x00]), Ok((0, &[0x45, 0x00][..])));
        assert_eq!(split_context_id(&[0x00]), Ok((0, &[][..])), "an empty UDP payload is valid");
    }

    #[test]
    fn splits_multi_byte_context_id() {
        assert_eq!(split_context_id(&[0x40, 0x02, 0xff]), Ok((2, &[0xff][..])));
    }

    #[test]
    fn empty_payload_is_malformed() {
        assert!(split_context_id(&[]).is_err());
    }

    #[test]
    fn builds_context_zero_payloads() {
        assert_eq!(&udp_payload(b"hi")[..], b"\x00hi");
        assert_eq!(split_context_id(&udp_payload(b"")), Ok((0, &[][..])));
    }
}
