use hickory_proto::{
    op::{Header, Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        DNSClass, Name, RData, Record, RecordType,
        rdata::{A, AAAA, opt::EdnsCode},
    },
    serialize::binary::{BinDecodable, BinDecoder},
};
use std::io::{Error, ErrorKind::InvalidData, ErrorKind::UnexpectedEof};
use std::{net::IpAddr, str::FromStr};

pub fn build_dns_response(mut request: Message, domain: &str, ip: IpAddr, ttl: u32) -> std::io::Result<Message> {
    let name = Name::from_str(domain).map_err(|e| Error::new(InvalidData, e))?;
    let record = match ip {
        IpAddr::V4(ip) => Record::from_rdata(name.clone(), ttl, RData::A(A(ip))),
        IpAddr::V6(ip) => Record::from_rdata(name, ttl, RData::AAAA(AAAA(ip))),
    };

    // We must indicate that this message is a response. Otherwise, implementations may not
    // recognize it.
    request.metadata.message_type = MessageType::Response;

    request.add_answer(record);
    Ok(request)
}

pub fn remove_ipv6_entries(message: &mut Message) {
    message.answers.retain(|answer| !matches!(&answer.data, RData::AAAA(_)));
}

pub fn extract_ipaddr_from_dns_message(message: &Message) -> std::io::Result<IpAddr> {
    if message.metadata.response_code != ResponseCode::NoError {
        return Err(Error::new(InvalidData, format!("{:?}", message.metadata.response_code)));
    }
    let mut cname = None;
    for answer in &message.answers {
        match &answer.data {
            RData::A(addr) => {
                return Ok(IpAddr::V4((*addr).into()));
            }
            RData::AAAA(addr) => {
                return Ok(IpAddr::V6((*addr).into()));
            }
            RData::CNAME(name) => {
                cname = Some(name.to_utf8());
            }
            _ => {}
        }
    }
    if let Some(cname) = cname {
        return Err(Error::new(InvalidData, cname));
    }
    Err(Error::new(InvalidData, format!("{:?}", message.answers)))
}

pub fn extract_domain_from_dns_message(message: &Message) -> std::io::Result<String> {
    use std::io::{Error, ErrorKind::InvalidData};
    let query = message.queries.first().ok_or(Error::new(InvalidData, "DnsRequest no query body"))?;
    let name = query.name().to_string();
    Ok(name)
}

pub fn parse_data_to_dns_message(data: &[u8], used_by_tcp: bool) -> std::io::Result<Message> {
    if used_by_tcp {
        if data.len() < 2 {
            return Err(Error::new(UnexpectedEof, "invalid dns data"));
        }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let data = data.get(2..len + 2).ok_or(Error::new(UnexpectedEof, "invalid dns data"))?;
        return parse_data_to_dns_message(data, false);
    }
    let message = Message::from_vec(data).map_err(|e| Error::new(InvalidData, e))?;
    Ok(message)
}

/// Only a completed, ordinary lookup is eligible for resource reclamation.
/// Tracking never modifies a packet. Overlapping questions, transfers,
/// other opcodes and opaque traffic keep the regular UDP lifetime.
pub(crate) enum Lookup {
    Idle,
    Waiting(u16, Query),
    Answered(tokio::time::Instant),
    Untracked,
}

impl Lookup {
    fn ordinary_edns(wire: &[u8]) -> bool {
        // RFC 6891 OPT has a root owner, type 41 and length-prefixed options.
        // Inspect only option headers so EDNS padding is never copied.
        let Some((header, mut options)) = wire.split_first_chunk::<11>() else { return false; };
        if header[..3] != [0, 0, 41] || header[5..7] != [0, 0]
            || usize::from(u16::from_be_bytes([header[9], header[10]])) != options.len()
        {
            return false;
        }
        while !options.is_empty() {
            let Some(([c0, c1, l0, l1], data)) = options.split_first_chunk::<4>() else { return false; };
            let code = EdnsCode::from(u16::from_be_bytes([*c0, *c1]));
            if !matches!(code, EdnsCode::Cookie | EdnsCode::Padding) { return false; }
            let Some(rest) = data.get(usize::from(u16::from_be_bytes([*l0, *l1]))..) else { return false; };
            options = rest;
        }
        true
    }

    fn question(data: &[u8], direction: MessageType) -> Option<(u16, Query)> {
        let mut reader = BinDecoder::new(data);
        let header = Header::read(&mut reader).ok()?;
        if header.message_type != direction || header.op_code != OpCode::Query || header.counts.queries != 1 {
            return None;
        }
        let question = Query::read(&mut reader).ok()?;
        if question.query_class != DNSClass::IN
            || !matches!(question.query_type, RecordType::A | RecordType::AAAA | RecordType::HTTPS)
        {
            return None;
        }
        if direction == MessageType::Query {
            if header.counts.answers != 0 || header.counts.authorities != 0 {
                return None;
            }
            match header.counts.additionals {
                0 if reader.is_empty() => {}
                1 if Self::ordinary_edns(&data[reader.index()..]) => {}
                _ => return None,
            }
        }
        Some((header.id, question))
    }

    pub(crate) fn sent(&mut self, data: &[u8]) {
        if matches!(self, Self::Idle | Self::Answered(_))
            && let Some((id, question)) = Self::question(data, MessageType::Query)
        {
            *self = Self::Waiting(id, question);
        } else {
            *self = Self::Untracked;
        }
    }

    pub(crate) fn received(&mut self, data: &[u8]) {
        if let Self::Waiting(id, question) = self
            && let Some((reply_id, echoed)) = Self::question(data, MessageType::Response)
            && reply_id == *id && echoed == *question
        {
            *self = Self::Answered(tokio::time::Instant::now());
        }
    }
}

#[cfg(test)]
mod lookup_tests {
    use super::Lookup;

    fn question(id: u16, qtype: u16) -> Vec<u8> {
        let mut wire = id.to_be_bytes().to_vec();
        wire.extend_from_slice(b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x00");
        wire.extend_from_slice(&qtype.to_be_bytes());
        wire.extend_from_slice(&1u16.to_be_bytes());
        wire
    }

    fn response(mut wire: Vec<u8>) -> Vec<u8> {
        wire[2] |= 0x80;
        wire
    }

    #[test]
    fn completion_requires_the_matching_question_and_id() {
        for qtype in [1, 28, 65] {
            let mut lookup = Lookup::Idle;
            let query = question(10, qtype);
            lookup.sent(&query);
            let mut other_name = query.clone();
            other_name[13] = b'x';
            let mut other_class = query.clone();
            *other_class.last_mut().unwrap() = 3;
            for wrong in [response(question(11, qtype)), response(question(10, 5)), response(other_name),
                          response(other_class), query.clone()] {
                lookup.received(&wrong);
                assert!(matches!(lookup, Lookup::Waiting(..)));
            }
            let mut truncated = response(query.clone());
            truncated[2] |= 2;
            lookup.received(&truncated);
            assert!(matches!(lookup, Lookup::Answered(_)));
            lookup.sent(&query);
            assert!(matches!(lookup, Lookup::Waiting(..)));
        }
    }

    #[test]
    fn preserve_pipelined_long_lived_and_opaque_traffic() {
        let query = question(1, 1);
        let mut lookup = Lookup::Idle;
        lookup.sent(&query);
        lookup.sent(&question(2, 1));
        lookup.received(&response(query.clone()));
        assert!(matches!(lookup, Lookup::Untracked));

        let mut with_option = query.clone();
        with_option[11] = 1;
        // OPT with one EDNS option. Code 1 is a long-lived query.
        with_option.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 4, 0, 1, 0, 0]);
        let mut padded = with_option.clone();
        let option_code = padded.len() - 3;
        padded[option_code] = 12;
        let mut lookup = Lookup::Idle;
        lookup.sent(&padded);
        assert!(matches!(lookup, Lookup::Waiting(..)));
        let mut malformed = padded;
        *malformed.last_mut().unwrap() = 8;
        for wire in [with_option, malformed, question(1, 252), vec![1, 2, 3], response(query)] {
            let mut lookup = Lookup::Idle;
            lookup.sent(&wire);
            assert!(matches!(lookup, Lookup::Untracked));
        }
    }
}
