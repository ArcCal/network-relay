//! Scratch-only bounded IPv6 receive reassembly after per-fragment HBH validation.
use crate::time::Instant;
use crate::wire::{IpProtocol, Ipv6Address, Ipv6Repr};
const COUNT: usize = 16;
const PACKET: usize = 1500;
const DATA: usize = 1460;
const FREE: u8 = 0;
const ACTIVE: u8 = 1;
const POISON: u8 = 2;
const EXPIRED: u8 = 3;
#[derive(Clone, Copy, PartialEq, Eq)]
struct Key {
    src: Ipv6Address,
    dst: Ipv6Address,
    id: u32,
}
struct Entry {
    state: u8,
    key: Option<Key>,
    deadline: i64,
    data: [u8; DATA],
    seen: [u8; (DATA + 7) / 8],
    first: [u8; PACKET + 8],
    first_len: usize,
    prefix: usize,
    previous_nh: usize,
    next: u8,
    end: Option<usize>,
    max_end: usize,
    ecns: u8,
    has_first: bool,
}
impl Entry {
    const fn new() -> Self {
        Self {
            state: FREE,
            key: None,
            deadline: 0,
            data: [0; DATA],
            seen: [0; (DATA + 7) / 8],
            first: [0; PACKET + 8],
            first_len: 0,
            prefix: 0,
            previous_nh: 0,
            next: 0,
            end: None,
            max_end: 0,
            ecns: 0,
            has_first: false,
        }
    }
    fn start(&mut self, key: Key, now: i64) {
        self.state = ACTIVE;
        self.key = Some(key);
        self.deadline = now.saturating_add(60_000);
        self.seen.fill(0);
        self.first_len = 0;
        self.end = None;
        self.max_end = 0;
        self.ecns = 0;
        self.has_first = false;
    }
}
pub(crate) struct Assembled<'a> {
    pub packet: &'a [u8],
    pub next: IpProtocol,
    pub offset: usize,
    pub previous_nh: usize,
}
pub(crate) enum Accepted<'a> {
    Complete(Assembled<'a>),
    Pending,
    Error { code: u8, pointer: usize },
}
pub(crate) struct Ipv6Reassembly {
    entries: [Entry; COUNT],
    complete: [u8; PACKET],
    next_deadline: i64,
}
impl Ipv6Reassembly {
    const EMPTY: Entry = Entry::new();
    pub(crate) fn new() -> Self {
        Self {
            entries: [Self::EMPTY; COUNT],
            complete: [0; PACKET],
            next_deadline: i64::MAX,
        }
    }
    fn refresh_deadline(&mut self) {
        self.next_deadline = self
            .entries
            .iter()
            .filter_map(|e| match e.state {
                ACTIVE | POISON => Some(e.deadline),
                EXPIRED => Some(0),
                _ => None,
            })
            .min()
            .unwrap_or(i64::MAX);
    }
    pub(crate) fn next_expiry(&self) -> Option<Instant> {
        (self.next_deadline != i64::MAX).then(|| Instant::from_millis(self.next_deadline))
    }
    pub(crate) fn mark_expired(&mut self, now: Instant) {
        if now.total_millis() < self.next_deadline {
            return;
        }
        for e in &mut self.entries {
            if now.total_millis() >= e.deadline {
                match e.state {
                    ACTIVE => e.state = EXPIRED,
                    POISON => {
                        e.state = FREE;
                        e.key = None;
                    }
                    _ => {}
                }
            }
        }
        self.refresh_deadline();
    }
    pub(crate) fn take_expired(&mut self, now: Instant) -> Option<&[u8]> {
        self.mark_expired(now);
        let slot = self.entries.iter().position(|e| e.state == EXPIRED)?;
        self.entries[slot].state = FREE;
        self.entries[slot].key = None;
        self.refresh_deadline();
        let e = &self.entries[slot];
        if e.has_first {
            Some(&e.first[..e.first_len])
        } else {
            Some(&[])
        }
    }
    /// Called only after all preceding per-fragment options have been validated.
    pub(crate) fn accept<'a>(
        &'a mut self,
        now: Instant,
        repr: Ipv6Repr,
        raw: &[u8],
        prefix: usize,
        previous_nh: usize,
        fragment: &[u8],
    ) -> Accepted<'a> {
        if fragment.len() < 8 || prefix < 40 || prefix > PACKET || previous_nh >= prefix {
            return Accepted::Pending;
        }
        let flags = u16::from_be_bytes([fragment[2], fragment[3]]);
        let offset = usize::from(flags & 0xfff8);
        let more = flags & 1 != 0;
        let data = &fragment[8..];
        let next = fragment[0];
        let ecn = (raw[1] >> 4) & 3;
        let key = Key {
            src: repr.src_addr,
            dst: repr.dst_addr,
            id: u32::from_be_bytes(fragment[4..8].try_into().unwrap()),
        };
        // Reserved byte and reserved flag bits are deliberately ignored.
        if offset == 0 && !more {
            if prefix + data.len() > PACKET {
                return Accepted::Pending;
            }
            self.complete[..prefix].copy_from_slice(&raw[..prefix]);
            self.complete[prefix..prefix + data.len()].copy_from_slice(data);
            self.complete[previous_nh] = next;
            let len = prefix + data.len();
            self.complete[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
            return Accepted::Complete(Assembled {
                packet: &self.complete[..len],
                next: IpProtocol::from(next),
                offset: prefix,
                previous_nh,
            });
        }
        // RFC 8200 section 4.5 distinguishes an impossible wire length from
        // the local reassembly capacity. The pointer names this fragment's
        // Offset field, even when the first fragment has not arrived.
        if offset + data.len() > usize::from(u16::MAX) {
            return Accepted::Error {
                code: 0,
                pointer: prefix + 2,
            };
        }
        let now = now.total_millis();
        let slot = match self
            .entries
            .iter()
            .position(|e| e.state != FREE && e.key == Some(key))
        {
            Some(i) => i,
            None => {
                let Some(i) = self.entries.iter().position(|e| e.state == FREE) else {
                    return Accepted::Pending;
                };
                self.entries[i].start(key, now);
                self.next_deadline = self.next_deadline.min(self.entries[i].deadline);
                i
            }
        };
        let e = &mut self.entries[slot];
        if e.state != ACTIVE || now >= e.deadline {
            return Accepted::Pending;
        }
        let Some(end) = offset.checked_add(data.len()) else {
            e.state = POISON;
            return Accepted::Pending;
        };
        let original_prefix = if offset == 0 {
            prefix
        } else if e.has_first {
            e.prefix
        } else {
            40
        };
        if original_prefix - 40 + end > usize::from(u16::MAX) {
            e.state = POISON;
            return Accepted::Error {
                code: 0,
                pointer: prefix + 2,
            };
        }
        if more && data.len() % 8 != 0 {
            e.state = POISON;
            return Accepted::Error {
                code: 0,
                pointer: 4,
            };
        }
        if offset == 0 && !first_complete(next, data) {
            e.state = POISON;
            return Accepted::Error {
                code: 3,
                pointer: 0,
            };
        }
        if end > DATA || (offset == 0 && (prefix + end > PACKET || raw.len() > PACKET + 8)) {
            e.state = POISON;
            return Accepted::Pending;
        }
        if e.end.is_some_and(|last| end > last)
            || (!more && e.end.is_some_and(|last| last != end))
            || (!more && e.max_end > end)
            || (offset..end).any(|n| e.seen[n / 8] & (1 << (n % 8)) != 0)
        {
            e.state = POISON;
            return Accepted::Pending;
        }
        e.ecns |= 1 << ecn;
        if e.ecns & 9 == 9 {
            e.state = POISON;
            return Accepted::Pending;
        }
        e.data[offset..end].copy_from_slice(data);
        for n in offset..end {
            e.seen[n / 8] |= 1 << (n % 8);
        }
        e.max_end = e.max_end.max(end);
        if !more {
            e.end = Some(end);
        }
        if offset == 0 {
            e.first[..raw.len()].copy_from_slice(raw);
            e.first_len = raw.len();
            e.prefix = prefix;
            e.previous_nh = previous_nh;
            e.next = next;
            e.has_first = true;
        }
        let Some(last) = e.end else {
            return Accepted::Pending;
        };
        if !e.has_first {
            return Accepted::Pending;
        }
        if e.prefix + last > PACKET {
            e.state = POISON;
            return Accepted::Pending;
        }
        if !(0..last).all(|n| e.seen[n / 8] & (1 << (n % 8)) != 0) {
            return Accepted::Pending;
        }
        let len = e.prefix + last;
        self.complete[..e.prefix].copy_from_slice(&e.first[..e.prefix]);
        self.complete[e.prefix..len].copy_from_slice(&e.data[..last]);
        self.complete[e.previous_nh] = e.next;
        self.complete[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
        if e.ecns & 8 != 0 {
            self.complete[1] = (self.complete[1] & 0xcf) | 0x30;
        }
        let next = IpProtocol::from(e.next);
        let offset = e.prefix;
        let previous_nh = e.previous_nh;
        e.state = FREE;
        e.key = None;
        Accepted::Complete(Assembled {
            packet: &self.complete[..len],
            next,
            offset,
            previous_nh,
        })
    }
}
fn first_complete(mut next: u8, mut data: &[u8]) -> bool {
    loop {
        let len = match next {
            6 => {
                return data.len() >= 20
                    && data[12] >> 4 >= 5
                    && usize::from(data[12] >> 4) * 4 <= data.len()
            }
            17 => return data.len() >= 8,
            58 => return data.len() >= 4,
            50 => return data.len() >= 8,
            41 => return data.len() >= 40,
            59 => return true,
            0 | 43 | 60 => {
                if data.len() < 2 {
                    return false;
                }
                (usize::from(data[1]) + 1) * 8
            }
            51 => {
                if data.len() < 2 {
                    return false;
                }
                (usize::from(data[1]) + 2) * 4
            }
            44 => {
                // RFC 8200 requires the complete chain through the first
                // upper-layer header in a real first fragment. Atomic
                // packets bypass this check and are processed independently.
                if data.len() < 8 || u16::from_be_bytes([data[2], data[3]]) & 0xfff8 != 0 {
                    return false;
                }
                8
            }
            _ => return true,
        };
        if data.len() < len {
            return false;
        }
        next = data[0];
        data = &data[len..];
    }
}
#[cfg(test)]
mod proof {
    use super::*;
    use crate::wire::Ipv6Packet;
    fn packet(id: u32, offset: usize, data: &[u8], more: bool, ecn: u8) -> alloc::vec::Vec<u8> {
        let mut p = alloc::vec![0;48+data.len()];
        p[0] = 0x6f;
        p[1] = (ecn << 4) | 0xb;
        p[2] = 0x12;
        p[3] = 0x34;
        p[4..6].copy_from_slice(&((8 + data.len()) as u16).to_be_bytes());
        p[6] = 44;
        p[7] = 64;
        p[8..24].copy_from_slice(&Ipv6Address::LOCALHOST.octets());
        p[24..40].copy_from_slice(&Ipv6Address::LOCALHOST.octets());
        p[40] = 17;
        p[42..44].copy_from_slice(&((offset as u16) | u16::from(more)).to_be_bytes());
        p[44..48].copy_from_slice(&id.to_be_bytes());
        p[48..].copy_from_slice(data);
        p
    }
    fn input<'a>(r: &'a mut Ipv6Reassembly, p: &[u8], now: i64) -> Accepted<'a> {
        let wire = Ipv6Packet::new_checked(p).unwrap();
        let repr = Ipv6Repr::parse(&wire).unwrap();
        r.accept(Instant::from_millis(now), repr, p, 40, 6, &p[40..])
    }
    fn payload() -> [u8; DATA] {
        let mut data = [0x5a; DATA];
        data[4..6].copy_from_slice(&(DATA as u16).to_be_bytes());
        data
    }
    #[test]
    fn reassembly_sixteen_contexts_and_old_progress() {
        let mut r = Ipv6Reassembly::new();
        let data = payload();
        for id in 0..16 {
            assert!(matches!(
                input(&mut r, &packet(id, 0, &data[..512], true, 0), 0),
                Accepted::Pending
            ));
        }
        assert_eq!(r.entries.iter().filter(|e| e.state == ACTIVE).count(), 16);
        input(&mut r, &packet(99, 0, &data[..512], true, 0), 1);
        assert!(!r.entries.iter().any(|e| e.key.is_some_and(|k| k.id == 99)));
        assert!(matches!(
            input(&mut r, &packet(0, 512, &data[512..], false, 0), 2),
            Accepted::Complete(_)
        ));
        input(&mut r, &packet(99, 0, &data[..512], true, 0), 3);
        assert!(r.entries.iter().any(|e| e.key.is_some_and(|k| k.id == 99)));
    }
    #[test]
    fn reassembly_overlap_tombstone_atomic_and_late_fragments() {
        let mut r = Ipv6Reassembly::new();
        let data = payload();
        input(&mut r, &packet(1, 0, &data[..512], true, 0), 0);
        input(&mut r, &packet(1, 256, &data[256..768], true, 0), 1);
        assert_eq!(r.entries[0].state, POISON);
        assert!(matches!(
            input(&mut r, &packet(1, 0, &data[..8], false, 0), 2),
            Accepted::Complete(_)
        ));
        assert_eq!(r.entries[0].state, POISON);
        assert!(matches!(
            input(&mut r, &packet(1, 512, &data[512..], false, 0), 3),
            Accepted::Pending
        ));
        assert_eq!(r.entries[0].deadline, 60_000);
        r.mark_expired(Instant::from_millis(60_000));
        assert_eq!(r.entries[0].state, FREE);
    }
    #[test]
    fn reassembly_atomic_does_not_destroy_normal_context() {
        let mut r = Ipv6Reassembly::new();
        let data = payload();
        input(&mut r, &packet(1, 0, &data[..512], true, 0), 0);
        assert!(matches!(
            input(&mut r, &packet(1, 0, &data[..8], false, 0), 1),
            Accepted::Complete(_)
        ));
        assert_eq!(r.entries[0].state, ACTIVE);
        assert!(matches!(
            input(&mut r, &packet(1, 512, &data[512..], false, 0), 2),
            Accepted::Complete(_)
        ));
    }
    #[test]
    fn reassembly_eight_byte_fragments_more_than_thirty_two_holes() {
        let mut r = Ipv6Reassembly::new();
        let data = payload();
        input(&mut r, &packet(1, 1456, &data[1456..], false, 2), 0);
        for i in (1..182).step_by(2) {
            input(
                &mut r,
                &packet(1, i * 8, &data[i * 8..i * 8 + 8], true, 2),
                1,
            );
        }
        for i in (2..182).step_by(2) {
            input(
                &mut r,
                &packet(1, i * 8, &data[i * 8..i * 8 + 8], true, 2),
                2,
            );
        }
        let Accepted::Complete(full) = input(&mut r, &packet(1, 0, &data[..8], true, 2), 3) else {
            panic!("183-fragment valid packet was not completed")
        };
        assert_eq!(full.packet.len(), 1500);
        assert_eq!(&full.packet[40..], data);
        assert_eq!(full.packet[6], 17);
    }
    #[test]
    fn reassembly_deadline_nonrefresh_and_missing_first() {
        let mut r = Ipv6Reassembly::new();
        let data = payload();
        let first = packet(1, 0, &data[..512], true, 0);
        input(&mut r, &first, 10);
        input(&mut r, &packet(1, 512, &data[512..1024], true, 0), 59_999);
        assert_eq!(r.next_expiry(), Some(Instant::from_millis(60_010)));
        assert!(matches!(
            input(&mut r, &packet(1, 1024, &data[1024..], false, 0), 60_010),
            Accepted::Pending
        ));
        assert_eq!(r.take_expired(Instant::from_millis(60_010)).unwrap(), first);
        assert!(r.take_expired(Instant::from_millis(60_010)).is_none());
        input(&mut r, &packet(2, 512, &data[512..], false, 0), 60_011);
        assert_eq!(r.take_expired(Instant::from_millis(120_011)), Some(&[][..]));
    }
    #[test]
    fn reassembly_reserved_bits_and_nonfirst_nextheader() {
        let mut r = Ipv6Reassembly::new();
        let data = payload();
        let mut last = packet(1, 512, &data[512..], false, 0);
        last[40] = 253;
        last[41] = 255;
        last[43] |= 6;
        input(&mut r, &last, 0);
        let mut first = packet(1, 0, &data[..512], true, 0);
        first[41] = 255;
        first[43] |= 6;
        let Accepted::Complete(full) = input(&mut r, &first, 1) else {
            panic!("reserved bits or differing nonfirst NH rejected")
        };
        assert_eq!(full.packet[6], 17);
        assert_eq!(&full.packet[40..], data);
    }
    #[test]
    fn reassembly_ecn_all_identical_ce_preserved_unsafe_mix_drops() {
        let data = payload();
        for ecn in 0..4 {
            let mut r = Ipv6Reassembly::new();
            input(&mut r, &packet(1, 0, &data[..512], true, ecn), 0);
            let Accepted::Complete(full) =
                input(&mut r, &packet(1, 512, &data[512..], false, ecn), 1)
            else {
                panic!("same ECN rejected")
            };
            assert_eq!((full.packet[1] >> 4) & 3, ecn);
        }
        for (first, last, accept) in [
            (2, 3, true),
            (3, 2, true),
            (1, 3, true),
            (3, 1, true),
            (0, 3, false),
            (3, 0, false),
        ] {
            let mut r = Ipv6Reassembly::new();
            input(&mut r, &packet(1, 0, &data[..512], true, first), 0);
            let result = input(&mut r, &packet(1, 512, &data[512..], false, last), 1);
            match result {
                Accepted::Complete(full) => {
                    assert!(accept);
                    assert_eq!((full.packet[1] >> 4) & 3, 3);
                }
                _ => assert!(!accept),
            }
        }
    }
    #[test]
    fn reassembly_first_header_and_nonfinal_alignment() {
        let mut r = Ipv6Reassembly::new();
        let data = payload();
        assert!(matches!(
            input(&mut r, &packet(1, 0, &data[..7], true, 0), 0),
            Accepted::Error {
                code: 0,
                pointer: 4
            }
        ));
        let mut tcp = packet(2, 0, &data[..16], true, 0);
        tcp[40] = 6;
        assert!(matches!(
            input(&mut r, &tcp, 0),
            Accepted::Error {
                code: 3,
                pointer: 0
            }
        ));
        let mut unknown = packet(3, 0, &data[..8], true, 0);
        unknown[40] = 253;
        assert!(matches!(input(&mut r, &unknown, 0), Accepted::Pending));
    }
    #[test]
    fn reassembly_true_wire_length_overflow_reports_fragment_offset() {
        let mut r = Ipv6Reassembly::new();
        let data = [0x5a; 16];
        let wire = packet(73, 65528, &data, false, 0);
        assert!(matches!(
            input(&mut r, &wire, 0),
            Accepted::Error {
                code: 0,
                pointer: 42
            }
        ));
        // The protocol error is distinct from the bounded local capacity.
        let wire = packet(74, 1480, &data, false, 0);
        assert!(matches!(input(&mut r, &wire, 1), Accepted::Pending));
    }
}
