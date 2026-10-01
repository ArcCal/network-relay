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
    skip_remaining: u64,
}

impl Default for CapsuleDecoder {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_VALUE_LEN)
    }
}

impl CapsuleDecoder {
    /// Limits buffered DATAGRAM values to `max_value_len`. Unknown capsule
    /// values are skipped as they arrive and are not subject to this limit.
    pub fn new(max_value_len: usize) -> Self {
        Self { buf: BytesMut::new(), max_value_len, skip_remaining: 0 }
    }

    /// Appends newly received stream data.
    pub fn push(&mut self, mut data: impl Buf) {
        let n = self.skip_remaining.min(data.remaining() as u64) as usize;
        data.advance(n);
        self.skip_remaining -= n as u64;
        while data.has_remaining() {
            let chunk = data.chunk();
            self.buf.extend_from_slice(chunk);
            let n = chunk.len();
            data.advance(n);
        }
    }

    /// Returns the next DATAGRAM capsule. Unknown types are skipped without
    /// accumulating their values, including values larger than our UDP limit.
    pub fn next_capsule(&mut self) -> Result<Option<RawCapsule>, Error> {
        self.next(false)
    }

    /// CONNECT-UDP only implements context zero. Discard unknown contexts
    /// incrementally, including payloads larger than a UDP packet (RFC 9298 §4).
    pub fn next_udp_capsule(&mut self) -> Result<Option<RawCapsule>, Error> {
        self.next(true)
    }

    fn next(&mut self, udp: bool) -> Result<Option<RawCapsule>, Error> {
        loop {
            if self.skip_remaining != 0 {
                let n = self.skip_remaining.min(self.buf.len() as u64) as usize;
                self.buf.advance(n);
                self.skip_remaining -= n as u64;
                if self.skip_remaining != 0 {
                    return Ok(None);
                }
            }
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
            let header_len = self.buf.len() - view.len();
            if capsule_type != types::DATAGRAM {
                self.buf.advance(header_len);
                self.skip_remaining = len;
                continue;
            }
            if udp {
                let mut context = &view[..view.len().min(usize::try_from(len).unwrap_or(usize::MAX))];
                let before = context.len();
                let id = match varint::decode(&mut context) {
                    Ok(id) => id,
                    Err(Error::Incomplete) if (before as u64) < len => return Ok(None),
                    Err(_) => return Err(Error::Malformed("missing or truncated UDP context ID")),
                };
                if id != super::datagram::CONTEXT_ID_UDP_PAYLOAD {
                    self.buf.advance(header_len);
                    self.skip_remaining = len;
                    continue;
                }
                let context_len = before - context.len();
                if len - context_len as u64 > super::datagram::MAX_UDP_PAYLOAD as u64 {
                    return Err(Error::Malformed("UDP payload exceeds 65527 bytes"));
                }
            }
            if len > self.max_value_len as u64 {
                return Err(Error::Malformed("capsule value exceeds size limit"));
            }
            let len = len as usize;
            if view.len() < len {
                return Ok(None);
            }
            self.buf.advance(header_len);
            return Ok(Some(RawCapsule { capsule_type, value: self.buf.split_to(len).freeze() }));
        }
    }

    /// Call when the stream has ended. A capsule cut off by the end of the
    /// stream makes the message malformed (RFC 9297 §3.3).
    pub fn finish(&self) -> Result<(), Error> {
        if self.buf.is_empty() && self.skip_remaining == 0 {
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
        let mut wire = encoded(0x00, b"hello");
        wire.extend_from_slice(&encoded(0x00, &[0xaa; 300]));
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
        assert_eq!(got[0], RawCapsule { capsule_type: 0x00, value: Bytes::from_static(b"hello") });
        assert_eq!(got[1].capsule_type, 0x00);
        assert_eq!(got[1].value.len(), 300);
    }

    #[test]
    fn empty_value_is_allowed() {
        let mut dec = CapsuleDecoder::default();
        dec.push(&encoded(0x00, &[])[..]);
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
    fn unknown_capsules_are_skipped_across_chunks_without_udp_size_limit() {
        let mut wire = encoded(0x12345, &[0xaa; 70_000]);
        wire.extend_from_slice(&encoded(types::DATAGRAM, &[0, b'x']));
        let mut decoder = CapsuleDecoder::default();
        let mut got = Vec::new();
        for chunk in wire.chunks(127) {
            decoder.push(chunk);
            while let Some(capsule) = decoder.next_capsule().unwrap() {
                got.push(capsule);
            }
            assert!(decoder.buf.len() < 127, "unknown value is streamed past");
        }
        decoder.finish().unwrap();
        assert_eq!(got, vec![RawCapsule { capsule_type: types::DATAGRAM, value: Bytes::from_static(&[0, b'x']) }]);
    }

    #[test]
    fn truncated_unknown_value_is_malformed() {
        let wire = encoded(0x12345, &[0xaa; 100]);
        let mut decoder = CapsuleDecoder::default();
        decoder.push(&wire[..wire.len() - 1]);
        assert!(decoder.next_capsule().unwrap().is_none());
        assert!(decoder.finish().is_err());
    }

    #[test]
    fn truncated_capsule_at_end_of_stream_is_malformed() {
        let wire = encoded(0x00, b"hello");
        let mut dec = CapsuleDecoder::default();
        dec.push(&wire[..wire.len() - 1]);
        assert_eq!(dec.next_capsule(), Ok(None));
        assert!(dec.finish().is_err());
    }

    #[test]
    fn udp_unknown_contexts_are_skipped_without_a_size_limit() {
        let mut value = vec![1];
        value.extend_from_slice(&[0xaa; 70_000]);
        let mut wire = encoded(types::DATAGRAM, &value);
        wire.extend_from_slice(&encoded(types::DATAGRAM, &[0, b'x']));
        for size in [1, 127, 16_384] {
            let mut decoder = CapsuleDecoder::default();
            let mut values = Vec::new();
            for chunk in wire.chunks(size) {
                decoder.push(chunk);
                while let Some(raw) = decoder.next_udp_capsule().unwrap() {
                    values.push(raw.value);
                }
                assert!(decoder.buf.len() < 16, "unknown contexts must not accumulate");
            }
            decoder.finish().unwrap();
            assert_eq!(values, [Bytes::from_static(&[0, b'x'])]);
        }
    }

    #[test]
    fn udp_context_is_required_and_length_is_checked_early() {
        for value in [&[][..], &[0xc0, 0][..]] {
            let mut decoder = CapsuleDecoder::default();
            decoder.push(encoded(types::DATAGRAM, value));
            assert!(decoder.next_udp_capsule().is_err());
        }
        let mut decoder = CapsuleDecoder::default();
        let mut wire = BytesMut::new();
        varint::encode(0, &mut wire);
        varint::encode(65_529, &mut wire);
        wire.extend_from_slice(&[0]);
        decoder.push(wire);
        assert!(decoder.next_udp_capsule().is_err(), "length and context suffice to reject");
    }

    #[test]
    fn udp_maximum_payload_accepts_nonminimal_context_encoding() {
        let mut value = vec![0xc0, 0, 0, 0, 0, 0, 0, 0];
        value.extend_from_slice(&[0xaa; super::super::datagram::MAX_UDP_PAYLOAD]);
        let wire = encoded(types::DATAGRAM, &value);
        let mut decoder = CapsuleDecoder::default();
        for chunk in wire[..wire.len() - 1].chunks(17) {
            decoder.push(chunk);
            assert!(decoder.next_udp_capsule().unwrap().is_none());
        }
        decoder.push(&wire[wire.len() - 1..]);
        assert_eq!(&decoder.next_udp_capsule().unwrap().unwrap().value[..], value);
        decoder.finish().unwrap();
    }
}
