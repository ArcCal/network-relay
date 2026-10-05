//! QUIC variable-length integers (RFC 9000 §16), used throughout the
//! Capsule Protocol and HTTP Datagrams.

use bytes::BufMut;

use super::Error;

/// Largest value a variable-length integer can hold (2^62 - 1).
pub const MAX: u64 = (1 << 62) - 1;

/// Number of bytes the minimal encoding of `v` takes.
pub fn encoded_len(v: u64) -> usize {
    match v {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    }
}

/// Appends the minimal encoding of `v`.
///
/// # Panics
///
/// Panics if `v` exceeds [`MAX`]. Every caller encodes values it produced
/// itself, so an out-of-range value is a programming error.
pub fn encode(v: u64, out: &mut impl BufMut) {
    assert!(v <= MAX, "varint {v} out of range");
    match encoded_len(v) {
        1 => out.put_u8(v as u8),
        2 => out.put_u16(0x4000 | v as u16),
        4 => out.put_u32(0x8000_0000 | v as u32),
        _ => out.put_u64(0xc000_0000_0000_0000 | v),
    }
}

/// Decodes a variable-length integer from the front of `buf` and advances
/// `buf` past it. Non-minimal encodings are accepted, as RFC 9000 allows.
pub fn decode(buf: &mut &[u8]) -> Result<u64, Error> {
    let first = *buf.first().ok_or(Error::Incomplete)?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return Err(Error::Incomplete);
    }
    let v = buf[1..len].iter().fold(u64::from(first & 0x3f), |acc, b| (acc << 8) | u64::from(*b));
    *buf = &buf[len..];
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(v: u64) {
        let mut out = Vec::new();
        encode(v, &mut out);
        assert_eq!(out.len(), encoded_len(v));
        let mut view = &out[..];
        assert_eq!(decode(&mut view), Ok(v));
        assert!(view.is_empty());
    }

    #[test]
    fn rfc9000_sample_decodings() {
        // RFC 9000 Appendix A.1.
        let cases: [(&[u8], u64); 5] = [
            (&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c], 151_288_809_941_952_652),
            (&[0x9d, 0x7f, 0x3e, 0x7d], 494_878_333),
            (&[0x7b, 0xbd], 15_293),
            (&[0x25], 37),
            (&[0x40, 0x25], 37),
        ];
        for (bytes, expected) in cases {
            let mut view = bytes;
            assert_eq!(decode(&mut view), Ok(expected));
            assert!(view.is_empty());
        }
    }

    #[test]
    fn boundaries_roundtrip() {
        for v in [0, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824, MAX] {
            roundtrip(v);
        }
    }

    #[test]
    fn truncated_input_is_incomplete() {
        let mut view: &[u8] = &[];
        assert_eq!(decode(&mut view), Err(Error::Incomplete));
        let mut view: &[u8] = &[0x80, 0x01];
        assert_eq!(decode(&mut view), Err(Error::Incomplete));
        assert_eq!(view.len(), 2, "input must not advance on error");
    }

    #[test]
    #[should_panic]
    fn encoding_above_max_panics() {
        encode(MAX + 1, &mut Vec::new());
    }
}
