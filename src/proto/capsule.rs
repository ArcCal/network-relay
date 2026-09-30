//! Capsule framing (RFC 9297 §3.2).
//!
//! ```text
//! Capsule {
//!   Capsule Type (i),
//!   Capsule Length (i),
//!   Capsule Value (..),
//! }
//! ```

use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::{varint, Error};

/// Capsule type codepoints.
pub mod types {
    /// DATAGRAM capsule (RFC 9297 §3.5). CONNECT-UDP uses no other capsule;
    /// receivers skip capsule types they do not know (RFC 9297 §3.2).
    pub const DATAGRAM: u64 = 0x00;
}

/// A capsule whose value has not been interpreted yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCapsule {
    pub capsule_type: u64,
    pub value: Bytes,
}

/// Appends a capsule with the given type and value.
pub fn encode(capsule_type: u64, value: &[u8], out: &mut BytesMut) {
    out.reserve(varint::encoded_len(capsule_type) + varint::encoded_len(value.len() as u64) + value.len());
    varint::encode(capsule_type, out);
    varint::encode(value.len() as u64, out);
    out.put_slice(value);
}

/// Largest capsule value [`CapsuleDecoder::new`] accepts by default: enough
/// for a DATAGRAM capsule carrying a maximum-size UDP payload and its
/// context ID.
pub const DEFAULT_MAX_VALUE_LEN: usize = 65_535 + 8;

/// Reassembles capsules from a byte stream that may split them at any point,
/// such as the DATA frames of an HTTP request stream.
#[derive(Debug)]
pub struct CapsuleDecoder {
    buf: BytesMut,
    max_value_len: usize,
}

impl Default for CapsuleDecoder {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_VALUE_LEN)
    }
}

impl CapsuleDecoder {
    /// Creates a decoder that rejects capsules whose value is longer than
    /// `max_value_len`, so a peer cannot make us buffer without bound.
    pub fn new(max_value_len: usize) -> Self {
        Self { buf: BytesMut::new(), max_value_len }
    }

    /// Appends newly received stream data.
    pub fn push(&mut self, mut data: impl Buf) {
        while data.has_remaining() {
            let chunk = data.chunk();
            self.buf.extend_from_slice(chunk);
            let n = chunk.len();
            data.advance(n);
        }
    }

    /// Returns the next complete capsule, or `None` if more data is needed.
    pub fn next_capsule(&mut self) -> Result<Option<RawCapsule>, Error> {
        let mut view = &self.buf[..];
        let capsule_type = match varint::decode(&mut view) {
            Ok(v) => v,
            Err(Error::Incomplete) => return Ok(None),
            Err(e) => return Err(e),
        };
        let len = match varint::decode(&mut view) {
            Ok(v) => v,
            Err(Error::Incomplete) => return Ok(None),
            Err(e) => return Err(e),
        };
        if len > self.max_value_len as u64 {
            return Err(Error::Malformed("capsule value exceeds size limit"));
        }
        let len = len as usize;
        if view.len() < len {
            return Ok(None);
        }
        let header_len = self.buf.len() - view.len();
        self.buf.advance(header_len);
        let value = self.buf.split_to(len).freeze();
        Ok(Some(RawCapsule { capsule_type, value }))
    }

    /// Call when the stream has ended. A capsule cut off by the end of the
    /// stream makes the message malformed (RFC 9297 §3.3).
    pub fn finish(&self) -> Result<(), Error> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed("stream ended inside a capsule"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(capsule_type: u64, value: &[u8]) -> BytesMut {
        let mut out = BytesMut::new();
        encode(capsule_type, value, &mut out);
        out
    }

    #[test]
    fn reassembles_capsules_split_at_every_byte() {
        let mut wire = encoded(0x01, b"hello");
        wire.extend_from_slice(&encoded(0x1234_5678, &[0xaa; 300]));
        let mut dec = CapsuleDecoder::default();
        let mut got = Vec::new();
        for byte in wire.iter() {
            dec.push(&[*byte][..]);
            while let Some(c) = dec.next_capsule().unwrap() {
                got.push(c);
            }
        }
        dec.finish().unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], RawCapsule { capsule_type: 0x01, value: Bytes::from_static(b"hello") });
        assert_eq!(got[1].capsule_type, 0x1234_5678);
        assert_eq!(got[1].value.len(), 300);
    }

    #[test]
    fn empty_value_is_allowed() {
        let mut dec = CapsuleDecoder::default();
        dec.push(&encoded(0x03, &[])[..]);
        let c = dec.next_capsule().unwrap().unwrap();
        assert!(c.value.is_empty());
    }

    #[test]
    fn oversized_capsule_is_rejected_before_buffering_it() {
        let mut dec = CapsuleDecoder::new(10);
        let mut header = BytesMut::new();
        varint::encode(0x00, &mut header);
        varint::encode(11, &mut header);
        dec.push(&header[..]);
        assert!(matches!(dec.next_capsule(), Err(Error::Malformed(_))));
    }

    #[test]
    fn truncated_capsule_at_end_of_stream_is_malformed() {
        let wire = encoded(0x01, b"hello");
        let mut dec = CapsuleDecoder::default();
        dec.push(&wire[..wire.len() - 1]);
        assert_eq!(dec.next_capsule(), Ok(None));
        assert!(dec.finish().is_err());
    }
}
