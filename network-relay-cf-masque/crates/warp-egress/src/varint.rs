//! QUIC variable-length integers (RFC 9000 §16).

/// Appends the encoding of `v` (at most 2^62 - 1).
pub fn encode(out: &mut Vec<u8>, v: u64) {
    assert!(v < 1 << 62, "varint out of range");
    match v {
        0..=0x3f => out.push(v as u8),
        0x40..=0x3fff => out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes()),
        0x4000..=0x3fff_ffff => out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

/// Returns the value and the number of bytes it took, or None if `b` is
/// too short.
pub fn decode(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    let len = 1usize << (first >> 6);
    if b.len() < len {
        return None;
    }
    let mut v = u64::from(first & 0x3f);
    for &x in &b[1..len] {
        v = v << 8 | u64::from(x);
    }
    Some((v, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for v in [0, 1, 63, 64, 16383, 16384, 0x3fff_ffff, 0x4000_0000, (1 << 62) - 1] {
            let mut out = vec![];
            encode(&mut out, v);
            assert_eq!(decode(&out), Some((v, out.len())));
        }
        assert_eq!(decode(&[0x40]), None);
    }
}
