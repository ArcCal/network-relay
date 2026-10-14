//! Bits of IP header handling for forwarded packets.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The smallest MTU an IPv6 link may have (RFC 8200 §5).
pub const IPV6_MIN_MTU: usize = 1280;

/// Ones' complement sum, as IP, ICMP and UDP use.
pub fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    for part in parts {
        let (words, rest) = part.as_chunks::<2>();
        for w in words {
            sum += u32::from(u16::from_be_bytes(*w));
        }
        // Each part is padded to an even length.
        if let [last] = rest {
            sum += u32::from(u16::from_be_bytes([*last, 0]));
        }
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The pseudo-header that TCP, UDP and ICMPv6 checksums cover.
pub fn pseudo_header(src: IpAddr, dst: IpAddr, proto: u8, len: usize) -> Vec<u8> {
    let mut p = vec![];
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            p.extend_from_slice(&[0, proto]);
            p.extend_from_slice(&(len as u16).to_be_bytes());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            p.extend_from_slice(&(len as u32).to_be_bytes());
            p.extend_from_slice(&[0, 0, 0, proto]);
        }
        _ => unreachable!("mixed families"),
    }
    p
}

/// The destination address of an IP packet.
pub fn destination(pkt: &[u8]) -> Option<IpAddr> {
    match pkt.first()? >> 4 {
        4 if pkt.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&pkt[16..20]).ok()?))),
        6 if pkt.len() >= 40 => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).ok()?))),
        _ => None,
    }
}

/// Decrements the TTL or Hop Limit of a packet about to be forwarded into
/// the tunnel, as RFC 9484 §7.2 asks of IP proxying endpoints (which act
/// as routers), fixing the IPv4 header checksum. False: the packet has no
/// hops left, or is not IP, and must be dropped.
pub fn decrement_hops(pkt: &mut [u8]) -> bool {
    match pkt.first().map(|b| b >> 4) {
        Some(4) if pkt.len() >= 20 => {
            if pkt[8] <= 1 {
                return false;
            }
            pkt[8] -= 1;
            // RFC 1624 incremental update, as the Linux kernel does it: the
            // TTL is the high byte of a header word, so the ones' complement
            // checksum grows by 0x0100, with an end-around carry.
            let old = u16::from_be_bytes([pkt[10], pkt[11]]);
            let mut sum = u32::from(old) + 0x0100;
            if sum >= 0xffff {
                sum += 1;
            }
            pkt[10..12].copy_from_slice(&(sum as u16).to_be_bytes());
            true
        }
        Some(6) if pkt.len() >= 40 => {
            if pkt[7] <= 1 {
                return false;
            }
            pkt[7] -= 1;
            true
        }
        _ => false,
    }
}

/// The ICMP error a router sends when `pkt` is too large for the next hop,
/// which carries IP packets of at most `mtu` bytes: "fragmentation needed"
/// (RFC 1191) or "packet too big" (RFC 4443). RFC 9484 §10.1 asks a tunnel
/// endpoint for it when a packet does not fit a QUIC datagram, so the
/// sender's path MTU discovery finds the size that does.
///
/// The error comes from the packet's destination: one from an address of
/// our own would be a martian to the kernel. None when no error may be sent
/// (RFC 1812 §4.3.2.7, RFC 4443 §2.4): for an ICMP error, a fragment other
/// than the first, a packet to a multicast or broadcast address or from an
/// unspecified one, or when IPv6 cannot be carried at all (below 1280).
pub fn packet_too_big(pkt: &[u8], mtu: usize) -> Option<Vec<u8>> {
    match pkt.first()? >> 4 {
        4 => {
            let hl = usize::from(pkt[0] & 0xf) * 4;
            if hl < 20 || pkt.len() < hl {
                return None;
            }
            let src = Ipv4Addr::from(<[u8; 4]>::try_from(&pkt[12..16]).ok()?);
            let dst = Ipv4Addr::from(<[u8; 4]>::try_from(&pkt[16..20]).ok()?);
            let offset = u16::from_be_bytes([pkt[6] & 0x1f, pkt[7]]);
            if offset != 0
                || src.is_unspecified()
                || dst.is_multicast()
                || dst.is_broadcast()
                || (pkt[9] == 1 && matches!(pkt.get(hl), None | Some(3 | 4 | 5 | 11 | 12)))
            {
                return None;
            }
            // As much of the packet as keeps the error within 576 bytes.
            let quoted = &pkt[..pkt.len().min(576 - 20 - 8)];
            let mut icmp = vec![3, 4, 0, 0, 0, 0];
            icmp.extend_from_slice(&(mtu.clamp(68, 0xffff) as u16).to_be_bytes());
            icmp.extend_from_slice(quoted);
            let c = checksum(&[&icmp]);
            icmp[2..4].copy_from_slice(&c.to_be_bytes());
            let mut p = vec![0u8; 20];
            p[0] = 0x45;
            p[1] = 0xc0; // internetwork control, as Linux marks its ICMP errors
            p[2..4].copy_from_slice(&((20 + icmp.len()) as u16).to_be_bytes());
            p[8] = 64;
            p[9] = 1;
            p[12..16].copy_from_slice(&dst.octets());
            p[16..20].copy_from_slice(&src.octets());
            let c = checksum(&[&p]);
            p[10..12].copy_from_slice(&c.to_be_bytes());
            p.extend_from_slice(&icmp);
            Some(p)
        }
        6 => {
            if pkt.len() < 40 || mtu < IPV6_MIN_MTU {
                return None;
            }
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).ok()?);
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).ok()?);
            // ICMPv6 errors have types below 128.
            if src.is_unspecified() || (pkt[6] == 58 && pkt.get(40).is_some_and(|&t| t < 128)) {
                return None;
            }
            // As much of the packet as keeps the error within 1280 bytes.
            let quoted = &pkt[..pkt.len().min(IPV6_MIN_MTU - 40 - 8)];
            let mut icmp = vec![2, 0, 0, 0];
            icmp.extend_from_slice(&(mtu.min(u32::MAX as usize) as u32).to_be_bytes());
            icmp.extend_from_slice(quoted);
            let c = checksum(&[&pseudo_header(IpAddr::V6(dst), IpAddr::V6(src), 58, icmp.len()), &icmp]);
            icmp[2..4].copy_from_slice(&c.to_be_bytes());
            let mut p = vec![0u8; 40];
            p[0] = 0x60;
            p[4..6].copy_from_slice(&(icmp.len() as u16).to_be_bytes());
            p[6] = 58;
            p[7] = 64;
            p[8..24].copy_from_slice(&dst.octets());
            p[24..40].copy_from_slice(&src.octets());
            p.extend_from_slice(&icmp);
            Some(p)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_checksum(h: &[u8]) -> u16 {
        let mut copy = h.to_vec();
        copy[10] = 0;
        copy[11] = 0;
        checksum(&[&copy])
    }

    #[test]
    fn ipv4_checksum_stays_right() {
        for ttl in [64u8, 2, 255, 128] {
            for id in [0u16, 0x1234, 0xffff, 0xfeff] {
                let mut h = [0u8; 20];
                h[0] = 0x45;
                h[2..4].copy_from_slice(&20u16.to_be_bytes());
                h[4..6].copy_from_slice(&id.to_be_bytes());
                h[8] = ttl;
                h[9] = 17;
                h[12..16].copy_from_slice(&[10, 0, 0, 1]);
                h[16..20].copy_from_slice(&[1, 1, 1, 1]);
                let c = header_checksum(&h);
                h[10..12].copy_from_slice(&c.to_be_bytes());
                assert!(decrement_hops(&mut h));
                assert_eq!(h[8], ttl - 1);
                assert_eq!(u16::from_be_bytes([h[10], h[11]]), header_checksum(&h));
            }
        }
    }

    #[test]
    fn exhausted_and_junk_are_dropped() {
        let mut v4 = [0u8; 20];
        v4[0] = 0x45;
        v4[8] = 1;
        assert!(!decrement_hops(&mut v4));
        let mut v6 = [0u8; 40];
        v6[0] = 0x60;
        v6[7] = 64;
        assert!(decrement_hops(&mut v6));
        assert_eq!(v6[7], 63);
        v6[7] = 1;
        assert!(!decrement_hops(&mut v6));
        assert!(!decrement_hops(&mut [0x45, 0, 0]));
        assert!(!decrement_hops(&mut [0x12; 40]));
    }

    /// A TCP segment of `len` bytes in all, from 10.0.0.2 to 1.1.1.1.
    fn tcp4(len: usize) -> Vec<u8> {
        let mut p = vec![0u8; len];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        p[6] = 0x40; // don't fragment
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&[10, 0, 0, 2]);
        p[16..20].copy_from_slice(&[1, 1, 1, 1]);
        p[20..22].copy_from_slice(&40000u16.to_be_bytes());
        p
    }

    fn tcp6(len: usize) -> Vec<u8> {
        let mut p = vec![0u8; len];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
        p[6] = 6;
        p[7] = 64;
        p[8..24].copy_from_slice(&"fd00::2".parse::<Ipv6Addr>().unwrap().octets());
        p[24..40].copy_from_slice(&"2606:4700::1111".parse::<Ipv6Addr>().unwrap().octets());
        p
    }

    #[test]
    fn destinations() {
        assert_eq!(destination(&tcp4(40)), Some("1.1.1.1".parse().unwrap()));
        assert_eq!(destination(&tcp6(60)), Some("2606:4700::1111".parse().unwrap()));
        assert_eq!(destination(&tcp4(40)[..19]), None);
        assert_eq!(destination(&tcp6(60)[..39]), None);
        assert_eq!(destination(&[0x12; 60]), None);
        assert_eq!(destination(&[]), None);
    }

    #[test]
    fn fragmentation_needed_for_ipv4() {
        let pkt = tcp4(1280);
        let e = packet_too_big(&pkt, 1190).unwrap();
        assert_eq!(checksum(&[&e[..20]]), 0, "IP header checksum");
        assert_eq!(usize::from(u16::from_be_bytes([e[2], e[3]])), e.len());
        assert!(e.len() <= 576);
        assert_eq!(e[9], 1);
        assert_eq!(&e[12..16], &[1, 1, 1, 1], "from the destination");
        assert_eq!(&e[16..20], &[10, 0, 0, 2], "to the sender");
        let icmp = &e[20..];
        assert_eq!(checksum(&[icmp]), 0, "ICMP checksum");
        assert_eq!(icmp[..2], [3, 4]);
        assert_eq!(u16::from_be_bytes([icmp[6], icmp[7]]), 1190);
        assert_eq!(&icmp[8..8 + 28], &pkt[..28], "quotes the header and more");
    }

    #[test]
    fn packet_too_big_for_ipv6() {
        let pkt = tcp6(1400);
        let e = packet_too_big(&pkt, 1300).unwrap();
        assert_eq!(e.len(), IPV6_MIN_MTU);
        assert_eq!(usize::from(u16::from_be_bytes([e[4], e[5]])), e.len() - 40);
        assert_eq!((e[6], e[7]), (58, 64));
        assert_eq!(&e[8..24], &pkt[24..40]);
        assert_eq!(&e[24..40], &pkt[8..24]);
        let icmp = &e[40..];
        let pseudo = pseudo_header(
            IpAddr::from(<[u8; 16]>::try_from(&e[8..24]).unwrap()),
            IpAddr::from(<[u8; 16]>::try_from(&e[24..40]).unwrap()),
            58,
            icmp.len(),
        );
        assert_eq!(checksum(&[&pseudo, icmp]), 0, "ICMPv6 checksum");
        assert_eq!(icmp[..2], [2, 0]);
        assert_eq!(u32::from_be_bytes(icmp[4..8].try_into().unwrap()), 1300);
        // Below the IPv6 minimum nothing helps: no error.
        assert_eq!(packet_too_big(&pkt, 1200), None);
    }

    /// Random packets from the TUN device never panic the helpers, and the
    /// errors they make stay within the size limits.
    #[test]
    fn random_packets_never_panic() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x1b7e5);
        for _ in 0..50_000 {
            let len = rng.random_range(0..120);
            let mut p: Vec<u8> = (0..len).map(|_| rng.random()).collect();
            if !p.is_empty() && rng.random_bool(0.8) {
                p[0] = if rng.random_bool(0.5) { 0x40 } else { 0x60 } | (p[0] & 0x0f);
            }
            let _ = destination(&p);
            if let Some(e) = packet_too_big(&p, rng.random_range(0..70_000)) {
                assert!(e.len() <= IPV6_MIN_MTU);
            }
            let _ = decrement_hops(&mut p);
        }
    }

    #[test]
    fn no_errors_about_errors_fragments_or_groups() {
        // An ICMP error (destination unreachable) and an ICMP echo.
        let mut icmp_err = tcp4(1300);
        icmp_err[9] = 1;
        icmp_err[20] = 3;
        assert_eq!(packet_too_big(&icmp_err, 1200), None);
        icmp_err[20] = 8;
        assert!(packet_too_big(&icmp_err, 1200).is_some());
        // A later fragment.
        let mut frag = tcp4(1300);
        frag[6] = 0x20;
        frag[7] = 0x10;
        assert_eq!(packet_too_big(&frag, 1200), None);
        // Multicast and broadcast.
        let mut group = tcp4(1300);
        group[16..20].copy_from_slice(&[224, 0, 0, 251]);
        assert_eq!(packet_too_big(&group, 1200), None);
        group[16..20].copy_from_slice(&[255, 255, 255, 255]);
        assert_eq!(packet_too_big(&group, 1200), None);
        // An ICMPv6 error, and an echo request.
        let mut icmp6 = tcp6(1400);
        icmp6[6] = 58;
        icmp6[40] = 1;
        assert_eq!(packet_too_big(&icmp6, 1300), None);
        icmp6[40] = 128;
        assert!(packet_too_big(&icmp6, 1300).is_some());
        // Junk.
        assert_eq!(packet_too_big(&[0x45, 0, 0], 1200), None);
        assert_eq!(packet_too_big(&[0x12; 60], 1200), None);
    }
}
