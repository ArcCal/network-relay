//! Signature adapters for the canonical server's QUIC integer API.

pub fn encode(out: &mut Vec<u8>, value: u64) {
    network_relay::proto::varint::encode(value, out);
}

pub fn decode(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut rest = bytes;
    let value = network_relay::proto::varint::decode(&mut rest).ok()?;
    Some((value, bytes.len() - rest.len()))
}
