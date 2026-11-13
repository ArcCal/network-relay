//! Name lookups through the VLESS server: DNS over TCP (RFC 1035 section
//! 4.2.2, RFC 7766) to the configured resolvers, each lookup over its own
//! VLESS connection. Names never reach this host's resolver, and the relay
//! checks the addresses found against its destination rules as usual.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::VlessConfig;
use crate::dns_wire::decode_answer;
use crate::transport::VlessStream;
use crate::vless::Command;

/// How long one resolver gets; the relay allows a lookup five seconds in
/// all, so a second resolver still has time when the first does not answer.
const PER_SERVER: Duration = Duration::from_millis(2500);
/// Answers are cached for their TTL, but no longer than this.
const MAX_TTL: Duration = Duration::from_secs(300);
const CACHE_ENTRIES: usize = 4096;
/// RFC 9520 section 3.2: cache completed resolution failures for at least
/// one second, separately from SOA-derived NXDOMAIN/NODATA lifetimes.
const FAILURE_TTL: Duration = Duration::from_secs(1);

type Lookup = Result<Vec<IpAddr>, Arc<io::Error>>;

pub struct Resolver {
    config: Arc<VlessConfig>,
    cache: Mutex<HashMap<String, (Lookup, Instant)>>,
}

/// Why a resolver could not answer.
enum Failure {
    /// The answer is final: asking another resolver would not change it.
    Final(io::Error, Duration),
    /// This resolver failed; another may answer.
    Retry(io::Error),
}

impl Resolver {
    pub fn new(config: Arc<VlessConfig>) -> Self {
        Self { config, cache: Mutex::default() }
    }

    /// The addresses of `host`, in the configured family order. An empty
    /// list means the name exists without addresses of those families.
    pub async fn lookup(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        let name = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        let now = Instant::now();
        if let Some((result, expires)) = self.cache.lock().unwrap_or_else(|e| e.into_inner()).get(&name) {
            if *expires > now {
                return result.clone().map_err(|error| copy_error(&error));
            }
        }
        let fqdn = Name::from_ascii(format!("{name}."))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "not a valid DNS name"))?;
        let mut last = io::Error::new(io::ErrorKind::TimedOut, "no resolver answered");
        for server in &self.config.dns_servers {
            match self.ask(*server, &fqdn).await {
                Ok((mut addrs, ttl)) => {
                    self.config.ip_preference.apply(&mut addrs);
                    self.remember(name, Ok(addrs.clone()), ttl);
                    return Ok(addrs);
                }
                Err(Failure::Final(e, ttl)) => {
                    self.remember(name, Err(Arc::new(copy_error(&e))), ttl);
                    return Err(e);
                }
                Err(Failure::Retry(e)) => {
                    tracing::debug!(%server, "DNS through VLESS failed: {e}");
                    last = e;
                }
            }
        }
        self.remember(name, Err(Arc::new(copy_error(&last))), FAILURE_TTL);
        Err(last)
    }

    /// Asks the resolvers for the root zone's NS records, which any
    /// recursive resolver answers: proof that the VLESS server accepts the
    /// user ID and relays to a resolver.
    pub async fn probe(&self) -> io::Result<()> {
        let mut last = io::Error::new(io::ErrorKind::TimedOut, "no resolver answered");
        for server in &self.config.dns_servers {
            let attempt = async {
                let mut stream = VlessStream::open(&self.config, Command::Tcp, *server).await?;
                let id = random_id();
                let mut message = Message::new(id, MessageType::Query, OpCode::Query);
                message.metadata.recursion_desired = true;
                message.add_query(Query::query(Name::root(), RecordType::NS));
                let bytes = message.to_vec().map_err(|e| io::Error::other(e.to_string()))?;
                stream.write_all(&(bytes.len() as u16).to_be_bytes()).await?;
                stream.write_all(&bytes).await?;
                stream.flush().await?;
                let mut answer = vec![0; stream.read_u16().await? as usize];
                stream.read_exact(&mut answer).await?;
                match decode_answer(&answer) {
                    Ok(answer)
                        if answer.metadata.id == id
                            && answer.metadata.message_type == MessageType::Response
                            && answer.metadata.op_code == OpCode::Query
                            && answer.queries == message.queries
                            && answer.metadata.response_code == ResponseCode::NoError
                            && !answer.metadata.truncation =>
                    {
                        Ok(())
                    }
                    _ => Err(io::Error::new(io::ErrorKind::InvalidData, "malformed DNS answer")),
                }
            };
            match tokio::time::timeout(PER_SERVER, attempt).await {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(e)) => last = io::Error::new(e.kind(), format!("{server}: {e}")),
                Err(_) => last = io::Error::new(io::ErrorKind::TimedOut, format!("{server}: no answer in time")),
            }
        }
        Err(last)
    }

    fn remember(&self, name: String, result: Lookup, ttl: Duration) {
        if ttl.is_zero() {
            return;
        }
        let now = Instant::now();
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache.len() >= CACHE_ENTRIES {
            cache.retain(|_, (_, expires)| *expires > now);
            if cache.len() >= CACHE_ENTRIES {
                cache.clear();
            }
        }
        cache.insert(name, (result, now + ttl.min(MAX_TTL)));
    }

    /// Asks one resolver for the A and/or AAAA records of `name`, both
    /// queries pipelined on one connection.
    async fn ask(&self, server: SocketAddr, name: &Name) -> Result<(Vec<IpAddr>, Duration), Failure> {
        let retry = Failure::Retry;
        let deadline = tokio::time::Instant::now() + PER_SERVER;
        let preference = self.config.ip_preference;
        let mut types = Vec::new();
        if preference.wants_ipv4() {
            types.push(RecordType::A);
        }
        if preference.wants_ipv6() {
            types.push(RecordType::AAAA);
        }
        let timeout_error = |_| retry(io::Error::new(io::ErrorKind::TimedOut, "DNS answer timed out"));
        let mut stream = tokio::time::timeout_at(deadline, VlessStream::open(&self.config, Command::Tcp, server))
            .await
            .map_err(timeout_error)?
            .map_err(retry)?;
        let mut queries = Vec::new();
        let mut wire = Vec::new();
        for qtype in &types {
            let id = unused_id(random_id(), &queries);
            let mut message = Message::new(id, MessageType::Query, OpCode::Query);
            message.metadata.recursion_desired = true;
            message.add_query(Query::query(name.clone(), *qtype));
            let bytes =
                message.to_vec().map_err(|e| Failure::Final(io::Error::other(e.to_string()), Duration::ZERO))?;
            wire.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            wire.extend_from_slice(&bytes);
            queries.push((id, *qtype));
        }
        tokio::time::timeout_at(deadline, async {
            stream.write_all(&wire).await?;
            stream.flush().await
        })
        .await
        .map_err(timeout_error)?
        .map_err(retry)?;
        let mut addrs = Vec::new();
        let mut expires = Instant::now() + MAX_TTL;
        let mut negative_expires = Instant::now() + MAX_TTL;
        let mut failure = None;
        let mut nxdomain = false;
        while !queries.is_empty() {
            let read = async {
                let length = stream.read_u16().await? as usize;
                let mut bytes = vec![0; length];
                stream.read_exact(&mut bytes).await?;
                Ok::<_, io::Error>(bytes)
            };
            let bytes = match tokio::time::timeout_at(deadline, read).await {
                Ok(Ok(bytes)) => bytes,
                Ok(Err(_)) | Err(_) if !addrs.is_empty() => break,
                Ok(Err(e)) => return Err(retry(e)),
                Err(_) => return Err(retry(io::Error::new(io::ErrorKind::TimedOut, "DNS answer timed out"))),
            };
            let answer = decode_answer(&bytes).map_err(retry)?;
            let Some(index) = queries.iter().position(|(id, qtype)| {
                answer.metadata.id == *id
                    && answer.metadata.message_type == MessageType::Response
                    && answer.metadata.op_code == OpCode::Query
                    && answer.queries.len() == 1
                    && answer.queries[0].query_type() == *qtype
                    && answer.queries[0].query_class() == DNSClass::IN
                    && answer.queries[0].name().to_ascii().eq_ignore_ascii_case(&name.to_ascii())
            }) else {
                continue;
            };
            let (_, qtype) = queries.remove(index);
            if answer.metadata.truncation {
                // Ignore only this incomplete answer (RFC 2181 section 9).
                // An independent complete answer from the other family is
                // still usable, regardless of which response arrived first.
                failure = Some(io::Error::new(io::ErrorKind::InvalidData, "truncated DNS answer over TCP"));
                continue;
            }
            match answer.metadata.response_code {
                ResponseCode::NoError => {}
                ResponseCode::NXDomain => nxdomain = true,
                code => {
                    failure = Some(io::Error::other(format!("the resolver answered {code}")));
                    continue;
                }
            }
            let (found, answer_ttl) = addresses(&answer, name, qtype).map_err(retry)?;
            if !found.is_empty() {
                expires = expires.min(Instant::now() + answer_ttl);
            } else {
                negative_expires = negative_expires.min(Instant::now() + answer_ttl);
            }
            for found in found {
                if !addrs.contains(&found) {
                    addrs.push(found);
                }
            }
        }
        if nxdomain && addrs.is_empty() {
            return Err(Failure::Final(
                io::Error::new(io::ErrorKind::NotFound, "no such name"),
                negative_expires.saturating_duration_since(Instant::now()),
            ));
        }
        if addrs.is_empty() {
            if let Some(error) = failure {
                return Err(retry(error));
            }
            expires = negative_expires;
        }
        Ok((addrs, expires.saturating_duration_since(Instant::now())))
    }
}

fn random_id() -> u16 {
    let mut b = [0u8; 2];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b).expect("system random numbers");
    u16::from_be_bytes(b)
}

/// RFC 7766 section 6.2.1 prohibits reusing any in-flight ID on the same
/// TCP connection, including for another record type. There are at most
/// two pending queries, so a collision needs only one increment.
fn unused_id(mut id: u16, queries: &[(u16, RecordType)]) -> u16 {
    while queries.iter().any(|(pending, _)| *pending == id) {
        id = id.wrapping_add(1);
    }
    id
}

fn copy_error(error: &io::Error) -> io::Error {
    match error.raw_os_error() {
        Some(code) => io::Error::from_raw_os_error(code),
        None => io::Error::new(error.kind(), error.to_string()),
    }
}

fn record_ttl(ttl: u32) -> Duration {
    // RFC 2181 section 8: the high bit of an RR's TTL must be zero.
    Duration::from_secs(if ttl & 0x8000_0000 == 0 { ttl.into() } else { 0 })
}

/// RFC 2308 sections 3 and 5: a negative result needs a relevant authority
/// SOA and lives no longer than either its TTL or its MINIMUM field.
fn negative_ttl(answer: &Message, name: &Name) -> Duration {
    answer
        .authorities
        .iter()
        .filter(|record| record.dns_class == DNSClass::IN && record.name.zone_of(name))
        .filter_map(|record| match &record.data {
            RData::SOA(soa) => Some(record_ttl(record.ttl).min(Duration::from_secs(soa.minimum.into()))),
            _ => None,
        })
        .min()
        .unwrap_or(Duration::ZERO)
}

/// Accept addresses only at the end of a bounded, acyclic CNAME chain.
fn addresses(answer: &Message, name: &Name, qtype: RecordType) -> io::Result<(Vec<IpAddr>, Duration)> {
    let mut owner = name.clone();
    let mut seen = Vec::new();
    let mut ttl = MAX_TTL;
    loop {
        if seen.contains(&owner) || seen.len() >= 128 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid DNS CNAME chain"));
        }
        seen.push(owner.clone());
        let records = || answer.answers.iter().filter(|r| r.dns_class == DNSClass::IN && r.name == owner);
        if let Some(record) = records().find(|r| matches!(r.data, RData::CNAME(_))) {
            let RData::CNAME(target) = &record.data else { unreachable!() };
            ttl = ttl.min(record_ttl(record.ttl));
            owner = target.0.clone();
            continue;
        }
        let mut addrs = Vec::new();
        for record in records() {
            let addr = match (qtype, &record.data) {
                (RecordType::A, RData::A(a)) => IpAddr::V4(a.0),
                (RecordType::AAAA, RData::AAAA(a)) => IpAddr::V6(a.0),
                _ => continue,
            };
            ttl = ttl.min(record_ttl(record.ttl));
            if !addrs.contains(&addr) {
                addrs.push(addr);
            }
        }
        if addrs.is_empty() {
            ttl = ttl.min(negative_ttl(answer, &owner));
        }
        return Ok((addrs, ttl));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IpPreference;
    use crate::vless::UserId;
    use futures_util::{SinkExt, StreamExt};
    use hickory_proto::rr::{rdata, Record};
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    #[test]
    fn recursive_questions_keep_the_standard_dns_wire_layout() {
        for (qtype, wire_type) in [(RecordType::A, 1u8), (RecordType::AAAA, 28)] {
            let mut question = Message::new(0x1234, MessageType::Query, OpCode::Query);
            question.metadata.recursion_desired = true;
            question.add_query(Query::query(Name::from_ascii("victim.test.").unwrap(), qtype));
            let mut expected = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06victim\x04test\x00".to_vec();
            expected.extend_from_slice(&[0, wire_type, 0, 1]);
            assert_eq!(question.to_vec().unwrap(), expected);
        }
    }

    #[test]
    fn pipelined_query_ids_remain_distinct_after_a_random_collision() {
        for candidate in [0, 1, 32768, u16::MAX] {
            let pending = [(candidate, RecordType::A)];
            assert_ne!(unused_id(candidate, &pending), candidate);
            assert_eq!(unused_id(candidate, &[]), candidate);
        }
    }

    #[test]
    fn negative_lifetimes_require_the_canonical_names_soa_and_respect_alias_ttl() {
        let name = Name::from_ascii("victim.test.").unwrap();
        let canonical = Name::from_ascii("target.other.").unwrap();
        let mut answer = Message::new(0, MessageType::Query, OpCode::Query);
        answer.add_answer(Record::from_rdata(name.clone(), 5, RData::CNAME(rdata::CNAME(canonical))));
        let soa = RData::SOA(rdata::SOA::new(Name::root(), Name::root(), 1, 60, 60, 60, 30));
        answer.add_authority(Record::from_rdata(Name::from_ascii("unrelated.").unwrap(), 60, soa.clone()));
        assert_eq!(addresses(&answer, &name, RecordType::A).unwrap().1, Duration::ZERO);
        answer.add_authority(Record::from_rdata(Name::from_ascii("other.").unwrap(), 60, soa));
        assert_eq!(addresses(&answer, &name, RecordType::A).unwrap().1, Duration::from_secs(5));
        answer.answers[0].ttl = 100;
        assert_eq!(addresses(&answer, &name, RecordType::A).unwrap().1, Duration::from_secs(30));
        answer.authorities[1].ttl = 10;
        assert_eq!(addresses(&answer, &name, RecordType::A).unwrap().1, Duration::from_secs(10));
        answer.authorities[1].ttl = 0x8000_0001;
        assert_eq!(addresses(&answer, &name, RecordType::A).unwrap().1, Duration::ZERO);
    }

    #[test]
    fn high_bit_positive_ttls_are_uncacheable_without_discarding_addresses() {
        let name = Name::from_ascii("victim.test.").unwrap();
        let mut answer = Message::new(0, MessageType::Query, OpCode::Query);
        answer.add_answer(Record::from_rdata(
            name.clone(),
            0x8000_0001,
            RData::A(rdata::A("198.51.100.77".parse().unwrap())),
        ));
        let (found, ttl) = addresses(&answer, &name, RecordType::A).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(ttl, Duration::ZERO);
    }

    #[tokio::test]
    async fn cancelling_a_lookup_does_not_cache_a_resolution_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (queried, query) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            assert!(matches!(ws.next().await, Some(Ok(WsMessage::Binary(_)))));
            assert!(matches!(ws.next().await, Some(Ok(WsMessage::Binary(_)))));
            queried.send(()).unwrap();
            assert!(matches!(ws.next().await, Some(Ok(WsMessage::Close(_)))));
            let _ = ws.flush().await;
        });
        let config = VlessConfig {
            server_host: "127.0.0.1".into(),
            server_port: port,
            user_id: UserId::parse("b4e4fad1-c320-428e-92dc-f8f6944a7dec").unwrap(),
            path: "/ws".into(),
            host_header: "vless.test".into(),
            dns_servers: vec!["127.0.0.1:53".parse().unwrap()],
            ip_preference: IpPreference::Ipv4Only,
        };
        let resolver = Resolver::new(Arc::new(config));
        {
            let lookup = resolver.lookup("victim.test");
            tokio::pin!(lookup);
            tokio::select! {
                result = &mut lookup => panic!("peer has not replied: {result:?}"),
                ready = query => ready.unwrap(),
            }
        }
        assert!(resolver.cache.lock().unwrap().is_empty());
        tokio::time::timeout(Duration::from_secs(2), server).await.unwrap().unwrap();
    }

    async fn caching_peer(
        code: ResponseCode,
        soa_ttl: Option<u32>,
        truncated: bool,
    ) -> (Resolver, Arc<std::sync::atomic::AtomicUsize>, tokio::task::JoinHandle<()>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let count = Arc::new(AtomicUsize::new(0));
        let requests = count.clone();
        let server = tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
                assert!(matches!(ws.next().await, Some(Ok(WsMessage::Binary(_)))));
                let mut wire = Vec::new();
                let mut answer = loop {
                    if let WsMessage::Binary(bytes) = ws.next().await.unwrap().unwrap() {
                        wire.extend_from_slice(&bytes);
                    }
                    if wire.len() >= 2 {
                        let length = u16::from_be_bytes([wire[0], wire[1]]) as usize;
                        if wire.len() >= length + 2 {
                            break Message::from_vec(&wire[2..length + 2]).unwrap();
                        }
                    }
                };
                requests.fetch_add(1, Ordering::SeqCst);
                answer.metadata.message_type = MessageType::Response;
                answer.metadata.response_code = code;
                answer.metadata.truncation = truncated;
                if let Some(ttl) = soa_ttl {
                    answer.add_authority(Record::from_rdata(
                        Name::from_ascii("test.").unwrap(),
                        ttl,
                        RData::SOA(rdata::SOA::new(
                            Name::from_ascii("ns.test.").unwrap(),
                            Name::from_ascii("hostmaster.test.").unwrap(),
                            1,
                            60,
                            60,
                            60,
                            ttl,
                        )),
                    ));
                }
                let bytes = answer.to_vec().unwrap();
                let mut frame = vec![0, 0];
                frame.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                frame.extend_from_slice(&bytes);
                ws.send(WsMessage::Binary(frame.into())).await.unwrap();
                // Complete the Close handshake so each sequential lookup
                // observes the same downstream behavior.
                while let Some(Ok(message)) = ws.next().await {
                    if matches!(message, WsMessage::Close(_)) {
                        let _ = ws.flush().await;
                        break;
                    }
                }
            }
        });
        let config = VlessConfig {
            server_host: "127.0.0.1".into(),
            server_port: port,
            user_id: UserId::parse("b4e4fad1-c320-428e-92dc-f8f6944a7dec").unwrap(),
            path: "/ws".into(),
            host_header: "vless.test".into(),
            dns_servers: vec!["127.0.0.1:53".parse().unwrap()],
            ip_preference: IpPreference::Ipv4Only,
        };
        (Resolver::new(Arc::new(config)), count, server)
    }

    #[tokio::test]
    async fn repeated_resolution_failures_are_cached_then_retried() {
        use std::sync::atomic::Ordering;
        let (resolver, requests, server) = caching_peer(ResponseCode::ServFail, None, false).await;
        let first = resolver.lookup("victim.test").await.unwrap_err();
        let start = Instant::now();
        for _ in 0..100 {
            let error = resolver.lookup("VICTIM.test.").await.unwrap_err();
            assert_eq!(error.kind(), first.kind());
            assert_eq!(error.to_string(), first.to_string());
        }
        eprintln!(
            "100 failed-lookup retries: {:?}, {} downstream DNS connections",
            start.elapsed(),
            requests.load(Ordering::SeqCst)
        );
        assert_eq!(requests.load(Ordering::SeqCst), 1, "cached failures must not query upstream");
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(resolver.lookup("victim.test").await.is_err());
        assert_eq!(requests.load(Ordering::SeqCst), 2, "failure expiry must permit recovery");
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn negative_answers_use_soa_lifetimes_and_missing_soa_is_not_cached() {
        use std::sync::atomic::Ordering;
        for code in [ResponseCode::NXDomain, ResponseCode::NoError] {
            for ttl in [None, Some(0), Some(1)] {
                let (resolver, requests, server) = caching_peer(code, ttl, false).await;
                for _ in 0..2 {
                    let result = resolver.lookup("victim.test").await;
                    if code == ResponseCode::NXDomain {
                        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
                    } else {
                        assert!(result.unwrap().is_empty());
                    }
                }
                assert_eq!(requests.load(Ordering::SeqCst), if ttl == Some(1) { 1 } else { 2 });
                if ttl == Some(1) {
                    tokio::time::sleep(Duration::from_millis(1100)).await;
                    let _ = resolver.lookup("victim.test").await;
                    assert_eq!(requests.load(Ordering::SeqCst), 2, "negative TTL expiry must be honored");
                }
                server.abort();
                let _ = server.await;
            }
        }
    }

    #[tokio::test]
    async fn truncated_tcp_response_is_not_a_successful_empty_answer() {
        let (resolver, _, server) = caching_peer(ResponseCode::NoError, None, true).await;
        let error = resolver.lookup("victim.test").await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        server.abort();
        let _ = server.await;
    }

    #[test]
    fn answers_require_the_queried_owner_or_a_valid_cname_chain() {
        let name = Name::from_ascii("victim.test.").unwrap();
        let other = Name::from_ascii("other.test.").unwrap();
        let ip = RData::A(rdata::A("198.51.100.77".parse().unwrap()));
        let mut answer = Message::new(0, MessageType::Query, OpCode::Query);
        answer.add_answer(Record::from_rdata(other.clone(), 300, ip.clone()));
        assert!(addresses(&answer, &name, RecordType::A).unwrap().0.is_empty());
        answer.add_answer(Record::from_rdata(name.clone(), 1, RData::CNAME(rdata::CNAME(other.clone()))));
        let (found, ttl) = addresses(&answer, &name, RecordType::A).unwrap();
        assert_eq!(found, vec!["198.51.100.77".parse::<IpAddr>().unwrap()]);
        assert_eq!(ttl, Duration::from_secs(1));
        answer.add_answer(Record::from_rdata(other, 5, RData::CNAME(rdata::CNAME(name.clone()))));
        assert!(addresses(&answer, &name, RecordType::A).is_err());
    }

    #[test]
    fn addresses_ignore_other_classes_and_honor_case_and_zero_ttl() {
        let name = Name::from_ascii("victim.test.").unwrap();
        let mut record = Record::from_rdata(
            Name::from_ascii("VICTIM.TEST.").unwrap(),
            0,
            RData::AAAA(rdata::AAAA("2001:db8::7".parse().unwrap())),
        );
        record.dns_class = DNSClass::CH;
        let mut answer = Message::new(0, MessageType::Query, OpCode::Query);
        answer.add_answer(record.clone());
        assert!(addresses(&answer, &name, RecordType::AAAA).unwrap().0.is_empty());
        record.dns_class = DNSClass::IN;
        answer.add_answer(record);
        let (found, ttl) = addresses(&answer, &name, RecordType::AAAA).unwrap();
        assert_eq!(found.len(), 1);
        assert!(ttl.is_zero());
    }

    // Exercise real framing and reply ordering through an independent WS peer.
    async fn partial_answer(qtype: RecordType, failure_first: Option<bool>, ttl: u32) {
        partial_answer_with_truncation(qtype, failure_first, ttl, false).await;
    }

    async fn partial_answer_with_truncation(qtype: RecordType, failure_first: Option<bool>, ttl: u32, truncated: bool) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let _header = ws.next().await.unwrap().unwrap();
            let mut wire = Vec::new();
            let mut queries = Vec::new();
            while queries.len() < 2 {
                if let WsMessage::Binary(data) = ws.next().await.unwrap().unwrap() {
                    wire.extend_from_slice(&data);
                    while wire.len() >= 2 {
                        let len = u16::from_be_bytes([wire[0], wire[1]]) as usize;
                        if wire.len() < len + 2 {
                            break;
                        }
                        queries.push(Message::from_vec(&wire[2..len + 2]).unwrap());
                        wire.drain(..len + 2);
                    }
                }
            }
            let query = queries.iter().find(|q| q.queries[0].query_type() == qtype).unwrap();
            let mut answer = Message::response(query.metadata.id, OpCode::Query);
            answer.add_query(query.queries[0].clone());
            let data = match qtype {
                RecordType::A => RData::A(rdata::A("198.51.100.77".parse().unwrap())),
                _ => RData::AAAA(rdata::AAAA("2001:db8::7".parse().unwrap())),
            };
            if ttl != 0 {
                answer.add_answer(Record::from_rdata(query.queries[0].name().clone(), ttl, data));
            }
            let other = queries.iter().find(|q| q.queries[0].query_type() != qtype).unwrap();
            let mut failure = Message::response(other.metadata.id, OpCode::Query);
            failure.metadata.response_code = if truncated { ResponseCode::NoError } else { ResponseCode::ServFail };
            failure.metadata.truncation = truncated;
            failure.add_query(other.queries[0].clone());
            let answers = match failure_first {
                Some(true) => vec![failure, answer],
                Some(false) => vec![answer, failure],
                None => vec![answer],
            };
            let mut frame = vec![0, 0]; // VLESS response header.
            for answer in answers {
                let bytes = answer.to_vec().unwrap();
                frame.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                frame.extend_from_slice(&bytes);
            }
            ws.send(WsMessage::Binary(frame.into())).await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let config = VlessConfig {
            server_host: "127.0.0.1".into(),
            server_port: port,
            user_id: UserId::parse("b4e4fad1-c320-428e-92dc-f8f6944a7dec").unwrap(),
            path: "/ws".into(),
            host_header: "vless.test".into(),
            dns_servers: vec!["127.0.0.1:53".parse().unwrap()],
            ip_preference: IpPreference::Ipv4First,
        };
        let resolver = Resolver::new(Arc::new(config));
        let result = tokio::time::timeout(Duration::from_secs(4), resolver.lookup("victim.test")).await.unwrap();
        if ttl == 0 {
            assert!(result.is_err(), "failed families must not become an empty success");
            server.abort();
            let _ = server.await;
            return;
        }
        let found = result.unwrap();
        let expected: IpAddr = if qtype == RecordType::A { "198.51.100.77" } else { "2001:db8::7" }.parse().unwrap();
        assert_eq!(found, vec![expected]);
        if ttl == 1 {
            assert!(
                resolver.cache.lock().unwrap().get("victim.test").is_none_or(|(_, expires)| *expires <= Instant::now()),
                "waiting for AAAA must not extend an expired A record's TTL"
            );
        } else {
            assert_eq!(resolver.lookup("victim.test").await.unwrap(), found); // Cached without another connection.
        }
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn ipv4_survives_an_unanswered_aaaa_query() {
        partial_answer(RecordType::A, None, 10).await;
    }

    #[tokio::test]
    async fn ipv6_survives_an_unanswered_a_query() {
        partial_answer(RecordType::AAAA, None, 10).await;
    }
    #[tokio::test]
    async fn successful_family_survives_servfail_in_either_reply_order() {
        for qtype in [RecordType::A, RecordType::AAAA] {
            for first in [true, false] {
                partial_answer(qtype, Some(first), 10).await;
            }
        }
    }

    #[tokio::test]
    async fn successful_family_survives_a_truncated_reply_in_either_order() {
        for qtype in [RecordType::A, RecordType::AAAA] {
            for first in [true, false] {
                partial_answer_with_truncation(qtype, Some(first), 10, true).await;
            }
        }
    }

    #[tokio::test]
    async fn waiting_for_the_other_family_does_not_extend_dns_ttl() {
        partial_answer(RecordType::A, None, 1).await;
    }
    #[tokio::test]
    async fn startup_probe_requires_a_matching_successful_dns_response() {
        let mut outcomes = Vec::new();
        for mode in 0..4 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
                let _header = ws.next().await.unwrap().unwrap();
                let mut wire = Vec::new();
                let mut answer = loop {
                    if let WsMessage::Binary(data) = ws.next().await.unwrap().unwrap() {
                        wire.extend_from_slice(&data);
                    }
                    if wire.len() >= 2 {
                        let n = u16::from_be_bytes([wire[0], wire[1]]) as usize;
                        if wire.len() >= n + 2 {
                            break Message::from_vec(&wire[2..n + 2]).unwrap();
                        }
                    }
                };
                if mode != 0 {
                    answer.metadata.message_type = MessageType::Response;
                }
                if mode == 1 {
                    answer.metadata.response_code = ResponseCode::ServFail;
                }
                if mode == 2 {
                    answer.queries[0].set_name(Name::from_ascii("unrelated.test.").unwrap());
                }
                let bytes = answer.to_vec().unwrap();
                let mut frame = vec![0, 0];
                frame.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                frame.extend_from_slice(&bytes);
                ws.send(WsMessage::Binary(frame.into())).await.unwrap();
                tokio::time::sleep(Duration::from_secs(2)).await;
            });
            let config = VlessConfig {
                server_host: "127.0.0.1".into(),
                server_port: port,
                user_id: UserId::parse("b4e4fad1-c320-428e-92dc-f8f6944a7dec").unwrap(),
                path: "/ws".into(),
                host_header: "vless.test".into(),
                dns_servers: vec!["127.0.0.1:53".parse().unwrap()],
                ip_preference: IpPreference::Ipv4Only,
            };
            let result = Resolver::new(Arc::new(config)).probe().await;
            server.abort();
            let _ = server.await;
            outcomes.push(result.is_ok());
        }
        assert_eq!(outcomes, vec![false, false, false, true]);
    }

    #[tokio::test]
    async fn a_family_error_without_usable_addresses_remains_an_error() {
        partial_answer(RecordType::A, Some(true), 0).await;
        partial_answer(RecordType::AAAA, Some(false), 0).await;
    }
}
