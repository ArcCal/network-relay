//! Scratch bounded extension-header walking and faithful ICMPv6 error quoting.
use crate::time::Instant;
use crate::wire::*;
#[derive(Debug, Clone, Copy)]
pub(crate) enum HeaderError {
    Drop,
    Parameter {
        code: u8,
        pointer: usize,
        multicast: bool,
    },
}
pub(crate) fn walk<'a>(
    mut next: IpProtocol,
    mut payload: &'a [u8],
    mut at: usize,
    mut previous: usize,
) -> core::result::Result<(IpProtocol, &'a [u8], usize, usize), HeaderError> {
    loop {
        let is_hbh = next == IpProtocol::HopByHop;
        if is_hbh && at != 40 {
            return Err(HeaderError::Parameter {
                code: 1,
                pointer: previous,
                multicast: false,
            });
        }
        if !matches!(
            next,
            IpProtocol::HopByHop | IpProtocol::Ipv6Opts | IpProtocol::Ipv6Route
        ) {
            return Ok((next, payload, at, previous));
        }
        if payload.len() < 8 {
            return Err(HeaderError::Drop);
        }
        let len = (usize::from(payload[1]) + 1) * 8;
        if payload.len() < len {
            return Err(HeaderError::Drop);
        }
        if next == IpProtocol::Ipv6Route {
            // RFC5095 treats deprecated RH0 like an unrecognized routing type.
            if payload[3] != 0 {
                return Err(HeaderError::Parameter {
                    code: 0,
                    pointer: at + 2,
                    multicast: false,
                });
            }
        } else {
            let options = &payload[2..len];
            let mut offset = 0;
            while offset < options.len() {
                let option =
                    Ipv6Option::new_checked(&options[offset..]).map_err(|_| HeaderError::Drop)?;
                let kind = option.option_type();
                let option_len = if kind == Ipv6OptionType::Pad1 {
                    1
                } else {
                    2 + usize::from(option.data_len())
                };
                let recognized = if is_hbh {
                    matches!(
                        Ipv6OptionRepr::parse(&option).map_err(|_| HeaderError::Drop)?,
                        Ipv6OptionRepr::Pad1
                            | Ipv6OptionRepr::PadN(_)
                            | Ipv6OptionRepr::RouterAlert(_)
                    )
                    // RPL is deliberately handled below when its feature is present.
                } else {
                    matches!(kind, Ipv6OptionType::Pad1 | Ipv6OptionType::PadN)
                };
                #[cfg(feature = "proto-rpl")]
                let recognized = recognized || (is_hbh && kind == Ipv6OptionType::Rpl);
                if !recognized {
                    match Ipv6OptionFailureType::from(kind) {
                        Ipv6OptionFailureType::Skip => {}
                        Ipv6OptionFailureType::Discard => return Err(HeaderError::Drop),
                        Ipv6OptionFailureType::DiscardSendAll => {
                            return Err(HeaderError::Parameter {
                                code: 2,
                                pointer: at + 2 + offset,
                                multicast: true,
                            })
                        }
                        Ipv6OptionFailureType::DiscardSendUnicast => {
                            return Err(HeaderError::Parameter {
                                code: 2,
                                pointer: at + 2 + offset,
                                multicast: false,
                            })
                        }
                    }
                }
                offset += option_len;
            }
        }
        previous = at;
        next = IpProtocol::from(payload[0]);
        payload = &payload[len..];
        at += len;
    }
}
pub(crate) struct ErrorSlot {
    buffer: [u8; 1240],
    tokens: u64,
    last: i64,
    reply_source: Option<Ipv6Address>,
}
impl ErrorSlot {
    pub(crate) fn new() -> Self {
        Self {
            buffer: [0; 1240],
            tokens: 10_000,
            last: 0,
            reply_source: None,
        }
    }
    pub(crate) fn set_reply_source(&mut self, source: Option<Ipv6Address>) {
        self.reply_source =
            source.filter(|address| !address.is_unspecified() && !address.is_multicast());
    }
    pub(crate) fn make<'a>(
        &'a mut self,
        now: Instant,
        raw: &[u8],
        ty: u8,
        code: u8,
        pointer: usize,
        multicast: bool,
    ) -> Option<(Ipv6Repr, &'a [u8])> {
        let packet = Ipv6Packet::new_checked(raw).ok()?;
        let source = packet.src_addr();
        let destination = packet.dst_addr();
        if source.is_unspecified()
            || source.is_multicast()
            || (destination.is_multicast() && !multicast)
        {
            return None;
        }
        if !allows_error(packet.next_header(), packet.payload()) {
            return None;
        }
        // RFC 4443 section 2.2: multicast-triggered errors use an assigned
        // unicast address, never the multicast destination as their source.
        let reply_source = if destination.is_multicast() {
            self.reply_source?
        } else {
            destination
        };
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
        let quote = raw.len().min(1232);
        let len = 8 + quote;
        self.buffer[..8].fill(0);
        self.buffer[0] = ty;
        self.buffer[1] = code;
        if ty == 4 || ty == 2 {
            self.buffer[4..8].copy_from_slice(&(pointer as u32).to_be_bytes());
        }
        self.buffer[8..len].copy_from_slice(&raw[..quote]);
        Icmpv6Packet::new_unchecked(&mut self.buffer[..len]).fill_checksum(&reply_source, &source);
        Some((
            Ipv6Repr {
                src_addr: reply_source,
                dst_addr: source,
                next_header: IpProtocol::Icmpv6,
                payload_len: len,
                hop_limit: 64,
            },
            &self.buffer[..len],
        ))
    }
}
fn allows_error(mut next: IpProtocol, mut data: &[u8]) -> bool {
    loop {
        match next {
            IpProtocol::Icmpv6 => return data.first().is_some_and(|&ty| ty >= 128 && ty != 137),
            IpProtocol::HopByHop
            | IpProtocol::Ipv6Opts
            | IpProtocol::Ipv6Route
            | IpProtocol::IpSecAh => {
                if data.len() < 2 {
                    return false;
                }
                let len = if next == IpProtocol::IpSecAh {
                    (usize::from(data[1]) + 2) * 4
                } else {
                    (usize::from(data[1]) + 1) * 8
                };
                if data.len() < len {
                    return false;
                }
                next = IpProtocol::from(data[0]);
                data = &data[len..];
            }
            IpProtocol::Ipv6Frag => {
                if data.len() < 8 {
                    return false;
                }
                if u16::from_be_bytes([data[2], data[3]]) & 0xfff8 != 0 {
                    // RFC 4443 does not forbid errors about all nonfirst fragments.
                    // Direct TCP/UDP Next Header values identify a non-ICMP payload;
                    // otherwise the unavailable upper header cannot be inspected safely.
                    return matches!(IpProtocol::from(data[0]), IpProtocol::Tcp | IpProtocol::Udp);
                }
                next = IpProtocol::from(data[0]);
                data = &data[8..];
            }
            _ => return true,
        }
    }
}

pub(crate) struct Ipv6Ingress {
    pub assembler: super::ipv6_reassembly::Ipv6Reassembly,
    pub error: ErrorSlot,
    pub(super) normalized: [u8; 1500],
}
pub(crate) struct Resolved {
    pub length: Option<usize>,
    pub next: IpProtocol,
    pub offset: usize,
    pub previous: usize,
}
pub(crate) struct InputError {
    pub length: Option<usize>,
    pub header: HeaderError,
}
impl Ipv6Ingress {
    pub(crate) fn new() -> Self {
        Self {
            assembler: super::ipv6_reassembly::Ipv6Reassembly::new(),
            error: ErrorSlot::new(),
            normalized: [0; 1500],
        }
    }
    pub(crate) fn resolve(
        &mut self,
        now: Instant,
        original: &[u8],
    ) -> core::result::Result<Option<Resolved>, InputError> {
        use super::ipv6_reassembly::Accepted;
        let mut length = None;
        let mut next = IpProtocol::from(original[6]);
        let mut offset = 40;
        let mut previous = 6;
        loop {
            let raw = length.map_or(original, |len| &self.normalized[..len]);
            let (found, payload, at, prior) = walk(next, &raw[offset..], offset, previous)
                .map_err(|header| InputError { length, header })?;
            if found != IpProtocol::Ipv6Frag {
                return Ok(Some(Resolved {
                    length,
                    next: found,
                    offset: at,
                    previous: prior,
                }));
            }
            // Removing a Fragment header must not make a later Hop-by-Hop
            // header appear to have occupied the first position on the wire.
            if payload.len() >= 8 && payload[0] == 0 {
                return Err(InputError {
                    length,
                    header: HeaderError::Parameter {
                        code: 1,
                        pointer: at,
                        multicast: false,
                    },
                });
            }
            let packet = Ipv6Packet::new_unchecked(raw);
            let repr = Ipv6Repr::parse(&packet).map_err(|_| InputError {
                length,
                header: HeaderError::Drop,
            })?;
            match self.assembler.accept(now, repr, raw, at, prior, payload) {
                Accepted::Pending => return Ok(None),
                Accepted::Error { code, pointer } => {
                    return Err(InputError {
                        length,
                        header: HeaderError::Parameter {
                            code,
                            pointer,
                            multicast: false,
                        },
                    })
                }
                Accepted::Complete(complete) => {
                    // Each completed layer removes at least its eight-byte
                    // Fragment header. Continue in wire order using one fixed
                    // scratch packet and the same bounded context pool.
                    self.normalized[..complete.packet.len()].copy_from_slice(complete.packet);
                    length = Some(complete.packet.len());
                    next = complete.next;
                    offset = complete.offset;
                    previous = complete.previous_nh;
                }
            }
        }
    }
}
#[cfg(test)]
mod proof {
    use super::*;
    #[test]
    fn receive_destination_options_have_no_hbh_typed_semantics() {
        let p = [17, 0, 5, 1, 0, 0, 0, 0];
        assert!(walk(IpProtocol::Ipv6Opts, &p, 40, 6).is_ok());
        assert!(walk(IpProtocol::HopByHop, &p, 40, 6).is_err());
    }
    #[test]
    fn receive_unknown_routing_zero_left_and_nonzero_pointer() {
        let p = [17, 0, 253, 0, 0, 0, 0, 0];
        assert!(walk(IpProtocol::Ipv6Route, &p, 48, 40).is_ok());
        let p = [17, 0, 253, 1, 0, 0, 0, 0];
        assert!(matches!(
            walk(IpProtocol::Ipv6Route, &p, 48, 40),
            Err(HeaderError::Parameter {
                code: 0,
                pointer: 50,
                ..
            })
        ));
    }
    #[test]
    fn receive_option_and_next_header_offsets_follow_chain() {
        let p = [60, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0x80, 0];
        assert!(matches!(
            walk(IpProtocol::Ipv6Opts, &p, 40, 6),
            Err(HeaderError::Parameter {
                code: 2,
                pointer: 54,
                ..
            })
        ));
        let p = [59, 0, 0, 0, 0, 0, 0, 0];
        let (next, _, _, previous) = walk(IpProtocol::Ipv6Opts, &p, 40, 6).unwrap();
        assert_eq!(next, IpProtocol::Ipv6NoNxt);
        assert_eq!(previous, 40);
    }
    #[test]
    fn receive_error_quote_exact_first_header_and_rate() {
        let mut raw = alloc::vec![0;80];
        raw[0] = 0x6f;
        raw[1] = 0xab;
        raw[2] = 0x12;
        raw[3] = 0x34;
        raw[4..6].copy_from_slice(&40u16.to_be_bytes());
        raw[6] = 17;
        raw[7] = 64;
        raw[8..24].copy_from_slice(&Ipv6Address::LOCALHOST.octets());
        raw[24..40].copy_from_slice(&Ipv6Address::LOCALHOST.octets());
        let mut slot = ErrorSlot::new();
        for i in 0..10 {
            let (header, body) = slot
                .make(Instant::from_millis(60_000), &raw, 3, 1, 0, false)
                .unwrap();
            assert_eq!(&body[..2], &[3, 1]);
            assert_eq!(&body[8..], raw);
            assert!(Icmpv6Packet::new_checked(body)
                .unwrap()
                .verify_checksum(&header.src_addr, &header.dst_addr));
            assert!(i < 10);
        }
        assert!(slot
            .make(Instant::from_millis(60_000), &raw, 3, 1, 0, false)
            .is_none());
        assert!(slot
            .make(Instant::from_millis(60_200), &raw, 3, 1, 0, false)
            .is_some());
        raw[6] = 58;
        raw[40] = 1;
        assert!(slot
            .make(Instant::from_millis(60_400), &raw, 3, 1, 0, false)
            .is_none());
        raw[40] = 137;
        assert!(slot
            .make(Instant::from_millis(60_400), &raw, 3, 1, 0, false)
            .is_none());
    }
    #[test]
    fn receive_nonfirst_tcp_udp_error_eligibility_does_not_guess_icmp_type() {
        let mut raw = alloc::vec![0; 64];
        raw[0] = 0x60;
        raw[4..6].copy_from_slice(&24u16.to_be_bytes());
        raw[6] = 44;
        raw[7] = 64;
        raw[8..24].copy_from_slice(&Ipv6Address::LOCALHOST.octets());
        raw[24..40].copy_from_slice(&Ipv6Address::LOCALHOST.octets());
        raw[42..44].copy_from_slice(&65528u16.to_be_bytes());
        raw[48] = 1; // Fragment data must not be parsed as an ICMP header.
        for next in [6, 17] {
            raw[40] = next;
            let mut slot = ErrorSlot::new();
            let (header, body) = slot.make(Instant::ZERO, &raw, 4, 0, 42, false).unwrap();
            assert_eq!(&body[..2], &[4, 0]);
            assert_eq!(&body[4..8], &42u32.to_be_bytes());
            assert_eq!(&body[8..], raw);
            assert!(Icmpv6Packet::new_checked(body)
                .unwrap()
                .verify_checksum(&header.src_addr, &header.dst_addr));
        }
        for next in [58, 60, 44] {
            raw[40] = next;
            let mut slot = ErrorSlot::new();
            assert!(slot.make(Instant::ZERO, &raw, 4, 0, 42, false).is_none());
        }
    }
}
