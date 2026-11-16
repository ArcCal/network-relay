//! Bounded IP fragment reassembly at the packet boundary. Overlapping fragments
//! discard the context; incomplete packets cannot create transport sessions.
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
#[derive(Clone, Hash, PartialEq, Eq)]
struct Key(Vec<u8>);
struct Pending {
    start: Instant,
    bytes: Vec<u8>,
    used: Vec<bool>,
    end: Option<usize>,
    header: Option<Vec<u8>>,
}
#[derive(Default)]
pub(crate) struct Reassembly {
    packets: HashMap<Key, Pending>,
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes.chunks(2).map(|p| ((p[0] as u32) << 8) | p.get(1).copied().unwrap_or(0) as u32).sum();
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
impl Reassembly {
    pub fn push(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        let now = Instant::now();
        self.packets.retain(|_, p| now.duration_since(p.start) < Duration::from_secs(30));
        let (key, offset, more, data, mut header, v6) = match packet.first().map(|b| b >> 4)? {
            4 => {
                if packet.len() < 20 {
                    return None;
                }
                let h = (packet[0] as usize & 15) * 4;
                let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
                if h < 20 || total < h || total > packet.len() || checksum(&packet[..h]) != 0 {
                    return None;
                }
                let flags = u16::from_be_bytes([packet[6], packet[7]]);
                if flags & 0x8000 != 0 {
                    return None;
                }
                let offset = (flags as usize & 0x1fff) * 8;
                let more = flags & 0x2000 != 0;
                if offset == 0 && !more {
                    return Some(packet[..total].to_vec());
                }
                if flags & 0x4000 != 0 {
                    return None;
                }
                let mut key = vec![4, packet[9], packet[4], packet[5]];
                key.extend_from_slice(&packet[12..20]);
                (Key(key), offset, more, &packet[h..total], packet[..h].to_vec(), false)
            }
            6 => {
                if packet.len() < 40 {
                    return None;
                }
                let total = 40 + u16::from_be_bytes([packet[4], packet[5]]) as usize;
                if total > packet.len() {
                    return None;
                }
                let mut next = packet[6];
                let mut at = 40;
                let mut previous = 6;
                let mut hops = 0;
                while next != 44 {
                    if !matches!(next, 0 | 43 | 60 | 51) {
                        return Some(packet[..total].to_vec());
                    }
                    hops += 1;
                    if hops > 8 || at + 2 > total {
                        return None;
                    }
                    let len =
                        if next == 51 { (packet[at + 1] as usize + 2) * 4 } else { (packet[at + 1] as usize + 1) * 8 };
                    if at + len > total {
                        return None;
                    }
                    previous = at;
                    next = packet[at];
                    at += len;
                }
                if at + 8 > total || packet[at + 1] != 0 {
                    return None;
                }
                let flags = u16::from_be_bytes([packet[at + 2], packet[at + 3]]);
                if flags & 6 != 0 {
                    return None;
                }
                let offset = (flags & 0xfff8) as usize;
                let more = flags & 1 != 0;
                let mut key = vec![6, packet[at]];
                key.extend_from_slice(&packet[8..40]);
                key.extend_from_slice(&packet[at + 4..at + 8]);
                let mut header = packet[..at].to_vec();
                header[previous] = packet[at];
                (Key(key), offset, more, &packet[at + 8..total], header, true)
            }
            _ => return None,
        };
        let end = offset.checked_add(data.len())?;
        if data.is_empty() || end > 65535 || (more && data.len() % 8 != 0) {
            self.packets.remove(&key);
            return None;
        }
        if !self.packets.contains_key(&key) && self.packets.len() >= 64 {
            return None;
        }
        let pending = self.packets.entry(key.clone()).or_insert_with(|| Pending {
            start: now,
            bytes: Vec::new(),
            used: Vec::new(),
            end: None,
            header: None,
        });
        if pending.end.is_some_and(|last| end > last || (!more && end != last)) || (!more && pending.used.len() > end) {
            pending.end = Some(0);
            return None;
        }
        if pending.end == Some(0) {
            return None;
        }
        if pending.used.get(offset..end).is_some_and(|range| range.iter().any(|used| *used))
            || pending.used.get(offset..).is_some_and(|range| range.iter().take(data.len()).any(|used| *used))
        {
            // Keep a tombstone until expiry so later overlapping fragments cannot
            // reconstruct a different interpretation of the same datagram.
            pending.bytes.clear();
            pending.used.clear();
            pending.end = Some(0);
            return None;
        }
        pending.bytes.resize(end.max(pending.bytes.len()), 0);
        pending.used.resize(end.max(pending.used.len()), false);
        pending.bytes[offset..end].copy_from_slice(data);
        pending.used[offset..end].fill(true);
        if offset == 0 {
            pending.header = Some(std::mem::take(&mut header));
        }
        if !more {
            pending.end = Some(end);
        }
        let final_len = pending.end?;
        if pending.header.is_none()
            || pending.used.len() < final_len
            || !pending.used[..final_len].iter().all(|used| *used)
        {
            return None;
        }
        let mut result = pending.header.take()?;
        result.extend_from_slice(&pending.bytes[..final_len]);
        if v6 {
            let length = u16::try_from(result.len() - 40).ok()?;
            result[4..6].copy_from_slice(&length.to_be_bytes());
        } else {
            let length = u16::try_from(result.len()).ok()?;
            result[2..4].copy_from_slice(&length.to_be_bytes());
            result[6..8].fill(0);
            result[10..12].fill(0);
            let h = (result[0] as usize & 15) * 4;
            let sum = checksum(&result[..h]);
            result[10..12].copy_from_slice(&sum.to_be_bytes());
        }
        // A completed identifier can be reused immediately by the source.
        self.packets.remove(&key);
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fragment(offset: usize, more: bool, data: &[u8]) -> Vec<u8> {
        let mut p = vec![0; 20];
        p[0] = 0x45;
        p[8] = 64;
        p[9] = 17;
        p[2..4].copy_from_slice(&((20 + data.len()) as u16).to_be_bytes());
        p[4..6].copy_from_slice(&12u16.to_be_bytes());
        p[6..8].copy_from_slice(&(((offset / 8) as u16) | if more { 0x2000 } else { 0 }).to_be_bytes());
        p[12..20].copy_from_slice(&[192, 0, 2, 1, 198, 51, 100, 2]);
        let c = checksum(&p);
        p[10..12].copy_from_slice(&c.to_be_bytes());
        p.extend_from_slice(data);
        p
    }
    #[test]
    fn out_of_order_reassembly_and_overlap_rejection() {
        let mut r = Reassembly::default();
        assert!(r.push(&fragment(8, false, b"tail")).is_none());
        let p = r.push(&fragment(0, true, b"12345678")).unwrap();
        assert_eq!(&p[20..], b"12345678tail");
        assert_eq!(checksum(&p[..20]), 0);
        assert!(r.packets.is_empty());
        assert!(r.push(&fragment(0, true, b"12345678")).is_none());
        assert!(r.push(&fragment(0, true, b"changed!")).is_none());
        assert!(r.push(&fragment(8, false, b"tail")).is_none());
    }
    #[test]
    fn independent_reassemblies_survive_completion_and_capacity_is_bounded() {
        let mut r = Reassembly::default();
        for id in 0u16..80 {
            let mut p = fragment(0, true, b"12345678");
            p[4..6].copy_from_slice(&id.to_be_bytes());
            p[10..12].fill(0);
            let c = checksum(&p[..20]);
            p[10..12].copy_from_slice(&c.to_be_bytes());
            assert!(r.push(&p).is_none());
        }
        assert_eq!(r.packets.len(), 64);
        assert!(r.push(&fragment(8, false, b"tail")).is_some());
        assert_eq!(r.packets.len(), 63);
    }
    #[test]
    fn ipv6_fragments_remove_fragment_header_and_restore_payload_length() {
        fn packet(offset: u16, more: bool, payload: &[u8]) -> Vec<u8> {
            let mut p = vec![0; 48];
            p[0] = 0x60;
            p[6] = 44;
            p[7] = 64;
            p[8] = 0x20;
            p[24] = 0x20;
            p[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
            p[40] = 17;
            p[42..44].copy_from_slice(&(offset | u16::from(more)).to_be_bytes());
            p[47] = 1;
            p.extend_from_slice(payload);
            p
        }
        let mut r = Reassembly::default();
        assert!(r.push(&packet(8, false, b"abcd")).is_none());
        let p = r.push(&packet(0, true, b"12345678")).unwrap();
        assert_eq!(p[6], 17);
        assert_eq!(u16::from_be_bytes([p[4], p[5]]), 12);
        assert_eq!(&p[40..], b"12345678abcd");
    }
}
