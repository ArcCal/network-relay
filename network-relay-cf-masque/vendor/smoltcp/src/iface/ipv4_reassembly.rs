//! Scratch bounded IPv4 receive reassembly; see RFC1122 sections3.2.2 and3.3.2.
use crate::time::Instant;
use crate::wire::*;
const COUNT: usize = 16;
const PACKET: usize = 1500;
const DATA: usize = 1480;
const FREE: u8 = 0;
const ACTIVE: u8 = 1;
const POISON: u8 = 2;
const EXPIRED: u8 = 3;
#[derive(Clone, Copy, PartialEq, Eq)]
struct Key {
    src: Ipv4Address,
    dst: Ipv4Address,
    protocol: IpProtocol,
    id: u16,
}
struct Entry {
    state: u8,
    key: Option<Key>,
    deadline: i64,
    data: [u8; DATA],
    seen: [u8; (DATA + 7) / 8],
    first: [u8; PACKET],
    first_len: usize,
    prefix: usize,
    has_first: bool,
    end: Option<usize>,
    max_end: usize,
    ecns: u8,
}
impl Entry {
    const fn new() -> Self {
        Self {
            state: FREE,
            key: None,
            deadline: 0,
            data: [0; DATA],
            seen: [0; (DATA + 7) / 8],
            first: [0; PACKET],
            first_len: 0,
            prefix: 0,
            has_first: false,
            end: None,
            max_end: 0,
            ecns: 0,
        }
    }
    fn start(&mut self, key: Key, now: i64) {
        self.state = ACTIVE;
        self.key = Some(key);
        self.deadline = now.saturating_add(60_000);
        self.seen.fill(0);
        self.first_len = 0;
        self.prefix = 0;
        self.has_first = false;
        self.end = None;
        self.max_end = 0;
        self.ecns = 0;
    }
}
pub(crate) struct Ipv4Reassembly {
    entries: [Entry; COUNT],
    complete: [u8; PACKET],
    next_deadline: i64,
}
impl Ipv4Reassembly {
    const EMPTY: Entry = Entry::new();
    pub(crate) fn new() -> Self {
        Self {
            entries: [Self::EMPTY; COUNT],
            complete: [0; PACKET],
            next_deadline: i64::MAX,
        }
    }
    fn refresh(&mut self) {
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
        self.refresh();
    }
    pub(crate) fn take_expired(&mut self, now: Instant) -> Option<&[u8]> {
        self.mark_expired(now);
        let i = self.entries.iter().position(|e| e.state == EXPIRED)?;
        self.entries[i].state = FREE;
        self.entries[i].key = None;
        self.refresh();
        let e = &self.entries[i];
        Some(if e.has_first {
            &e.first[..e.first_len]
        } else {
            &[]
        })
    }
    pub(crate) fn accept<'a>(
        &'a mut self,
        now: Instant,
        p: &Ipv4Packet<&[u8]>,
    ) -> Option<&'a [u8]> {
        let prefix = usize::from(p.header_len());
        let raw = &p.as_ref()[..usize::from(p.total_len())];
        let offset = usize::from(p.frag_offset());
        let more = p.more_frags();
        let data = p.payload();
        let key = Key {
            src: p.src_addr(),
            dst: p.dst_addr(),
            protocol: p.next_header(),
            id: p.ident(),
        };
        let now = now.total_millis();
        let slot = match self
            .entries
            .iter()
            .position(|e| e.state != FREE && e.key == Some(key))
        {
            Some(i) => i,
            None => {
                let i = self.entries.iter().position(|e| e.state == FREE)?;
                self.entries[i].start(key, now);
                self.next_deadline = self.next_deadline.min(self.entries[i].deadline);
                i
            }
        };
        let e = &mut self.entries[slot];
        if e.state != ACTIVE || now >= e.deadline {
            return None;
        }
        let Some(end) = offset.checked_add(data.len()) else {
            e.state = POISON;
            return None;
        };
        if data.is_empty()
            || (more && data.len() % 8 != 0)
            || end > DATA
            || (offset == 0 && (prefix + end > PACKET || raw.len() > PACKET))
        {
            e.state = POISON;
            return None;
        }
        if e.end.is_some_and(|last| end > last)
            || (!more && e.end.is_some_and(|last| last != end))
            || (!more && e.max_end > end)
        {
            e.state = POISON;
            return None;
        }
        // RFC1122 explicitly allows identical overlap from retransmission/repacketizing.
        // Conflicting overlap is ambiguous attack traffic: discard the datagram, retain tombstone.
        if (offset..end)
            .any(|n| e.seen[n / 8] & (1 << (n % 8)) != 0 && e.data[n] != data[n - offset])
        {
            e.state = POISON;
            return None;
        }
        e.ecns |= 1 << (raw[1] & 3);
        if e.ecns & 9 == 9 {
            e.state = POISON;
            return None;
        }
        e.data[offset..end].copy_from_slice(data);
        for n in offset..end {
            e.seen[n / 8] |= 1 << (n % 8);
        }
        e.max_end = e.max_end.max(end);
        if !more {
            e.end = Some(end);
        }
        if offset == 0 && !e.has_first {
            e.first[..raw.len()].copy_from_slice(raw);
            e.first_len = raw.len();
            e.prefix = prefix;
            e.has_first = true;
        }
        let last = e.end?;
        if !e.has_first {
            return None;
        }
        if e.prefix + last > PACKET {
            e.state = POISON;
            return None;
        }
        if !(0..last).all(|n| e.seen[n / 8] & (1 << (n % 8)) != 0) {
            return None;
        }
        let len = e.prefix + last;
        self.complete[..e.prefix].copy_from_slice(&e.first[..e.prefix]);
        self.complete[e.prefix..len].copy_from_slice(&e.data[..last]);
        self.complete[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        self.complete[6..8].fill(0);
        if e.ecns & 8 != 0 {
            self.complete[1] = (self.complete[1] & !3) | 3;
        }
        Ipv4Packet::new_unchecked(&mut self.complete[..len]).fill_checksum();
        e.state = FREE;
        e.key = None;
        Some(&self.complete[..len])
    }
}
pub(crate) struct ErrorSlot {
    buffer: [u8; 556],
    tokens: u64,
    last: i64,
}
impl ErrorSlot {
    pub(crate) fn new() -> Self {
        Self {
            buffer: [0; 556],
            tokens: 10_000,
            last: 0,
        }
    }
    pub(crate) fn make<'a>(
        &'a mut self,
        now: Instant,
        raw: &[u8],
        ty: u8,
        code: u8,
    ) -> Option<(Ipv4Repr, &'a [u8])> {
        let p = Ipv4Packet::new_checked(raw).ok()?;
        if p.src_addr().is_unspecified()
            || p.src_addr().is_multicast()
            || p.src_addr().is_broadcast()
            || p.dst_addr().is_unspecified()
            || p.dst_addr().is_multicast()
            || p.dst_addr().is_broadcast()
            || p.frag_offset() != 0
        {
            return None;
        }
        if p.next_header() == IpProtocol::Icmp
            && !p
                .payload()
                .first()
                .is_some_and(|t| matches!(*t, 0 | 8 | 13 | 14 | 15 | 16 | 17 | 18))
        {
            return None;
        }
        let now = now.total_millis();
        let elapsed = now.saturating_sub(self.last).max(0) as u64;
        self.tokens = self
            .tokens
            .saturating_add(elapsed.saturating_mul(5))
            .min(10_000);
        self.last = now;
        if self.tokens < 1000 {
            return None;
        }
        self.tokens -= 1000;
        let quote = raw.len().min(548);
        let len = 8 + quote;
        self.buffer[..8].fill(0);
        self.buffer[0] = ty;
        self.buffer[1] = code;
        self.buffer[8..len].copy_from_slice(&raw[..quote]);
        Icmpv4Packet::new_unchecked(&mut self.buffer[..len]).fill_checksum();
        Some((
            Ipv4Repr {
                src_addr: p.dst_addr(),
                dst_addr: p.src_addr(),
                next_header: IpProtocol::Icmp,
                payload_len: len,
                hop_limit: 64,
            },
            &self.buffer[..len],
        ))
    }
}
pub(crate) struct Ipv4Ingress {
    pub assembler: Ipv4Reassembly,
    pub error: ErrorSlot,
}
impl Ipv4Ingress {
    pub(crate) fn new() -> Self {
        Self {
            assembler: Ipv4Reassembly::new(),
            error: ErrorSlot::new(),
        }
    }
}
#[cfg(test)]
mod proof {
    use super::*;
    fn p(id: u16, offset: usize, len: usize, more: bool, ecn: u8) -> alloc::vec::Vec<u8> {
        let mut p = alloc::vec![0;20+len];
        p[0] = 0x45;
        p[1] = ecn;
        p[2..4].copy_from_slice(&((20 + len) as u16).to_be_bytes());
        p[4..6].copy_from_slice(&id.to_be_bytes());
        p[6..8].copy_from_slice(
            &(((offset / 8) as u16) | if more { 0x2000 } else { 0 }).to_be_bytes(),
        );
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&[10, 0, 0, 2]);
        p[16..20].copy_from_slice(&[10, 0, 0, 1]);
        p[20..].fill(0x5a);
        Ipv4Packet::new_unchecked(&mut p[..]).fill_checksum();
        p
    }
    fn accept<'a>(r: &'a mut Ipv4Reassembly, p: &[u8], now: i64) -> Option<&'a [u8]> {
        r.accept(
            Instant::from_millis(now),
            &Ipv4Packet::new_checked(p).unwrap(),
        )
    }
    #[test]
    fn capacity_16_existing_progress_and_no_eviction() {
        let mut r = Ipv4Reassembly::new();
        for id in 0..16 {
            assert!(accept(&mut r, &p(id, 0, 512, true, 0), 0).is_none());
        }
        accept(&mut r, &p(99, 0, 512, true, 0), 1);
        assert!(!r.entries.iter().any(|e| e.key.is_some_and(|k| k.id == 99)));
        assert_eq!(
            accept(&mut r, &p(0, 512, 968, false, 0), 2).unwrap().len(),
            1500
        );
        accept(&mut r, &p(99, 0, 512, true, 0), 3);
        assert!(r.entries.iter().any(|e| e.key.is_some_and(|k| k.id == 99)));
    }
    #[test]
    fn ecn_and_true_nonrefresh() {
        for ecn in 0..4 {
            let mut r = Ipv4Reassembly::new();
            accept(&mut r, &p(1, 0, 512, true, ecn), 10);
            let full = accept(&mut r, &p(1, 512, 968, false, ecn), 20).unwrap();
            assert_eq!(full[1] & 3, ecn);
            assert!(Ipv4Packet::new_checked(full).unwrap().verify_checksum());
        }
        for (a, b, yes) in [
            (2, 3, true),
            (3, 2, true),
            (1, 3, true),
            (0, 3, false),
            (3, 0, false),
        ] {
            let mut r = Ipv4Reassembly::new();
            accept(&mut r, &p(1, 0, 512, true, a), 10);
            let result = accept(&mut r, &p(1, 512, 968, false, b), 20);
            assert_eq!(result.is_some(), yes);
            if let Some(full) = result {
                assert_eq!(full[1] & 3, 3);
            }
        }
        let mut r = Ipv4Reassembly::new();
        let first = p(1, 0, 512, true, 0);
        accept(&mut r, &first, 10);
        accept(&mut r, &p(1, 512, 512, true, 0), 59999);
        assert_eq!(r.next_expiry(), Some(Instant::from_millis(60010)));
        assert!(accept(&mut r, &p(1, 1024, 456, false, 0), 60010).is_none());
        assert_eq!(r.take_expired(Instant::from_millis(60010)).unwrap(), first);
    }
    #[test]
    fn protocol_id_isolation_first_tcp_can_be_eight_bytes() {
        let mut r = Ipv4Reassembly::new();
        let mut a = p(1, 0, 8, true, 0);
        a[9] = 6;
        assert!(accept(&mut r, &a, 0).is_none());
        let b = p(1, 0, 8, true, 0);
        accept(&mut r, &b, 1);
        assert_eq!(r.entries.iter().filter(|e| e.state == ACTIVE).count(), 2);
        let mut last = p(1, 8, 12, false, 0);
        last[9] = 6;
        assert!(accept(&mut r, &last, 2).is_some());
    }
    #[test]
    fn bound_options_and_resource_reject() {
        let mut r = Ipv4Reassembly::new();
        accept(&mut r, &p(1, 0, 512, true, 0), 0);
        assert!(accept(&mut r, &p(1, 1480, 8, false, 0), 1).is_none());
        assert_eq!(r.entries[0].state, POISON);
        let mut large = p(2, 0, 1480, true, 0);
        large[0] = 0x4f;
        large[20..60].fill(1);
        assert!(accept(&mut r, &large, 1).is_none());
        assert!(accept(&mut r, &p(2, 1440, 8, false, 0), 2).is_none());
        assert_eq!(r.entries[1].state, POISON);
    }
}
