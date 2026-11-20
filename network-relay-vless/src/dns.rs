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
use indexmap::IndexMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::broadcast;

use crate::config::VlessConfig;
use crate::dns_wire::decode_answer;
use crate::transport::VlessStream;
use crate::vless::Command;

/// Upper bound for one resolver. The caller's deadline also bounds the
/// whole lookup, including any admission wait before it starts.
const PER_SERVER: Duration = Duration::from_millis(2500);
/// Answers are cached for their TTL, but no longer than this.
const MAX_TTL: Duration = Duration::from_secs(300);
const CACHE_ENTRIES: usize = 4096;
/// RFC 9520 section 3.2: cache completed resolution failures for at least
/// one second, separately from SOA-derived NXDOMAIN/NODATA lifetimes.
const FAILURE_TTL: Duration = Duration::from_secs(1);

type Lookup = Result<Vec<IpAddr>, Arc<io::Error>>;

struct CacheEntry {
    result: Lookup,
    expires: Instant,
    referenced: bool,
}

#[derive(Default)]
struct DnsCache {
    entries: IndexMap<String, CacheEntry>,
    hand: usize,
    pending: HashMap<String, broadcast::Sender<Lookup>>,
}

impl DnsCache {
    fn get(&mut self, name: &str, now: Instant) -> Option<&Lookup> {
        let entry = self.entries.get_mut(name)?;
        if entry.expires <= now {
            return None;
        }
        entry.referenced = true;
        Some(&entry.result)
    }

    fn insert(&mut self, name: String, result: Lookup, expires: Instant, now: Instant) {
        if let Some(entry) = self.entries.get_mut(&name) {
            // An earlier lookup can finish after a concurrent successful one.
            if result.is_err() && entry.result.is_ok() && entry.expires > now {
                return;
            }
            entry.result = result;
            entry.expires = expires;
            return;
        }
        if self.entries.len() == CACHE_ENTRIES {
            // Second-chance eviction. A cold or expired name frees one slot.
            // Even if every name was used, one sweep clears every reference bit.
            loop {
                let index = self.hand;
                self.hand = (self.hand + 1) % CACHE_ENTRIES;
                let (_, entry) = self.entries.get_index_mut(index).expect("full DNS cache");
                if entry.expires <= now || !entry.referenced {
                    self.entries.swap_remove_index(index);
                    break;
                }
                entry.referenced = false;
            }
        }
        self.entries.insert(name, CacheEntry { result, expires, referenced: false });
    }
}

/// One active DNS transaction. Removing it closes the channel on cancellation,
/// so another waiting caller can take over using its own remaining time.
struct PendingLookup<'a> {
    cache: &'a Mutex<DnsCache>,
    name: Option<&'a str>,
}

impl PendingLookup<'_> {
    fn remove(&mut self) -> Option<broadcast::Sender<Lookup>> {
        let name = self.name.take()?;
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).pending.remove(name)
    }

    fn complete(mut self, result: &io::Result<Vec<IpAddr>>) {
        // Remove before publishing. Only callers that joined this transaction
        // may consume its outcome, including an answer with a zero TTL.
        if let Some(sender) = self.remove().filter(|sender| sender.receiver_count() != 0) {
            let shared = result.as_ref().cloned().map_err(|error| Arc::new(copy_error(error)));
            let _ = sender.send(shared);
        }
    }
}

impl Drop for PendingLookup<'_> {
    fn drop(&mut self) {
        self.remove();
    }
}

pub struct Resolver {
    config: Arc<VlessConfig>,
    cache: Mutex<DnsCache>,
    preferred: Mutex<(usize, u64)>,
}

struct LookupOrder {
    start: (usize, u64),
    active: Option<usize>,
    deadline: Option<tokio::time::Instant>,
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
        Self { config, cache: Mutex::default(), preferred: Mutex::default() }
    }

    pub async fn lookup_until(&self, host: &str, deadline: tokio::time::Instant) -> io::Result<Vec<IpAddr>> {
        let mut order = self.lookup_order();
        order.deadline = Some(deadline);
        match tokio::time::timeout_at(deadline, self.lookup_ordered(host, &mut order)).await {
            Ok(result) => {
                if result.as_ref().is_err_and(|e| e.kind() == io::ErrorKind::TimedOut)
                    && tokio::time::Instant::now() >= deadline
                {
                    self.advance_after_timeout(&order);
                }
                result
            }
            Err(_) => {
                self.advance_after_timeout(&order);
                let error = io::Error::new(io::ErrorKind::TimedOut, "DNS lookup timed out");
                if order.active.is_some() {
                    let name = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
                    self.remember(name, Err(Arc::new(copy_error(&error))), FAILURE_TTL);
                }
                Err(error)
            }
        }
    }

    /// The addresses of `host`, in the configured family order. An empty
    /// list means the name exists without addresses of those families.
    pub async fn lookup(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        let mut order = self.lookup_order();
        self.lookup_ordered(host, &mut order).await
    }

    fn lookup_order(&self) -> LookupOrder {
        LookupOrder { start: *self.preferred.lock().unwrap_or_else(|e| e.into_inner()), active: None, deadline: None }
    }

    fn advance_after_timeout(&self, order: &LookupOrder) {
        // Continue beyond this attempt on the next uncached lookup,
        // unless another lookup has already selected a working peer.
        if let Some(index) = order.active {
            let next = (index + 1) % self.config.dns_servers.len();
            let mut preferred = self.preferred.lock().unwrap_or_else(|e| e.into_inner());
            if *preferred == order.start {
                *preferred = (next, preferred.1.wrapping_add(1));
            }
        }
    }

    fn prefer(&self, index: usize) {
        let mut preferred = self.preferred.lock().unwrap_or_else(|e| e.into_inner());
        // Increment even for the same index: an older timeout must not
        // displace a resolver which has since answered another lookup.
        *preferred = (index, preferred.1.wrapping_add(1));
    }

    async fn lookup_ordered(&self, host: &str, order: &mut LookupOrder) -> io::Result<Vec<IpAddr>> {
        let name = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        let pending = loop {
            let mut receiver = {
                let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(result) = cache.get(&name, Instant::now()) {
                    return result.clone().map_err(|error| copy_error(&error));
                }
                if let Some(sender) = cache.pending.get(&name) {
                    sender.subscribe()
                } else {
                    // A caller with a nearly exhausted admission budget must
                    // not impose a shorter resolver attempt on later callers.
                    if cache.pending.len() >= CACHE_ENTRIES
                        || order
                            .deadline
                            .is_some_and(|end| end.saturating_duration_since(tokio::time::Instant::now()) < PER_SERVER)
                    {
                        break None;
                    }
                    cache.pending.insert(name.clone(), broadcast::channel(1).0);
                    break Some(PendingLookup { cache: &self.cache, name: Some(&name) });
                }
            };
            if let Ok(answer) = receiver.recv().await {
                return answer.map_err(|error| copy_error(&error));
            }
        };
        let result = self.lookup_uncached(&name, order).await;
        if let Some(pending) = pending {
            pending.complete(&result);
        }
        result
    }

    async fn lookup_uncached(&self, name: &str, order: &mut LookupOrder) -> io::Result<Vec<IpAddr>> {
        let fqdn = Name::from_ascii(format!("{name}."))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "not a valid DNS name"))?;
        let mut last = io::Error::new(io::ErrorKind::TimedOut, "no resolver answered");
        let mut tried = Vec::with_capacity(self.config.dns_servers.len());
        for offset in 0..self.config.dns_servers.len() {
            if order.deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
                last = io::Error::new(io::ErrorKind::TimedOut, "DNS lookup timed out");
                break;
            }
            let index = (order.start.0 + offset) % self.config.dns_servers.len();
            let server = self.config.dns_servers[index];
            if tried.contains(&server) {
                continue;
            }
            tried.push(server);
            order.active = Some(index);
            match self.ask(server, &fqdn, order.deadline).await {
                Ok((mut addrs, ttl)) => {
                    self.prefer(index);
                    self.config.ip_preference.apply(&mut addrs);
                    self.remember(name.to_owned(), Ok(addrs.clone()), ttl);
                    return Ok(addrs);
                }
                Err(Failure::Final(e, ttl)) => {
                    if e.kind() == io::ErrorKind::NotFound {
                        self.prefer(index);
                    }
                    self.remember(name.to_owned(), Err(Arc::new(copy_error(&e))), ttl);
                    return Err(e);
                }
                Err(Failure::Retry(e)) => {
                    tracing::debug!(%server, "DNS through VLESS failed: {e}");
                    last = e;
                }
            }
        }
        if order.active.is_some() {
            self.remember(name.to_owned(), Err(Arc::new(copy_error(&last))), FAILURE_TTL);
        }
        Err(last)
    }

    /// Asks the resolvers for the root zone's NS records, which any
    /// recursive resolver answers: proof that the VLESS server accepts the
    /// user ID and relays to a resolver.
    pub async fn probe(&self) -> io::Result<()> {
        let mut last = io::Error::new(io::ErrorKind::TimedOut, "no resolver answered");
        let mut tried = Vec::with_capacity(self.config.dns_servers.len());
        for server in &self.config.dns_servers {
            if tried.contains(server) {
                continue;
            }
            tried.push(*server);
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
        cache.insert(name, result, now + ttl.min(MAX_TTL), now);
    }

    /// Asks one resolver for the A and/or AAAA records of `name`, both
    /// queries pipelined on one connection.
    async fn ask(
        &self,
        server: SocketAddr,
        name: &Name,
        lookup_deadline: Option<tokio::time::Instant>,
    ) -> Result<(Vec<IpAddr>, Duration), Failure> {
        let retry = Failure::Retry;
        let deadline = tokio::time::Instant::now() + PER_SERVER;
        let deadline = lookup_deadline.map_or(deadline, |outer| outer.min(deadline));
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
    use hickory_proto::rr::{Record, rdata};
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
            let lookup = resolver.lookup_until("victim.test", tokio::time::Instant::now() + Duration::from_secs(5));
            tokio::pin!(lookup);
            tokio::select! {
                result = &mut lookup => panic!("peer has not replied: {result:?}"),
                ready = query => ready.unwrap(),
            }
        }
        assert!(resolver.cache.lock().unwrap().entries.is_empty());
        assert_eq!(*resolver.preferred.lock().unwrap(), (0, 0), "cancellation must not change resolver preference");
        tokio::time::timeout(Duration::from_secs(2), server).await.unwrap().unwrap();
    }

    // A real WebSocket/VLESS peer: all configured DNS destinations are quiet
    // except the optional selected one. Read through Close on timed-out attempts.
    async fn timeout_peer(
        servers: u16,
        answer: Option<(u16, Duration)>,
    ) -> (Resolver, Arc<std::sync::atomic::AtomicUsize>, tokio::task::JoinHandle<()>) {
        delayed_peer(servers, answer, 10).await
    }

    async fn delayed_peer(
        servers: u16,
        answer: Option<(u16, Duration)>,
        ttl: u32,
    ) -> (Resolver, Arc<std::sync::atomic::AtomicUsize>, tokio::task::JoinHandle<()>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(AtomicUsize::new(0));
        let count = requests.clone();
        let server = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (tcp, _) = accepted.unwrap();
                        let count = count.clone();
                        connections.spawn(async move {
                            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
                            let header = ws.next().await.unwrap().unwrap().into_data();
                            let destination = u16::from_be_bytes([header[19], header[20]]);
                            let mut wire = Vec::new();
                            let mut response = loop {
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
                            count.fetch_add(1, Ordering::SeqCst);
                            if let Some((index, delay)) = answer.filter(|(index, _)| destination == 53 + index) {
                                assert!(index < servers);
                                tokio::time::sleep(delay).await;
                                response.metadata.message_type = MessageType::Response;
                                response.add_answer(Record::from_rdata(
                                    response.queries[0].name().clone(),
                                    ttl,
                                    RData::A(rdata::A("198.51.100.77".parse().unwrap())),
                                ));
                                let bytes = response.to_vec().unwrap();
                                let mut frame = vec![0, 0];
                                frame.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                                frame.extend_from_slice(&bytes);
                                ws.send(WsMessage::Binary(frame.into())).await.unwrap();
                            }
                            while let Some(Ok(message)) = ws.next().await {
                                if matches!(message, WsMessage::Close(_)) {
                                    let _ = ws.flush().await;
                                    break;
                                }
                            }
                        });
                    }
                    finished = connections.join_next(), if !connections.is_empty() => {
                        finished.unwrap().unwrap();
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
            dns_servers: (53..53 + servers).map(|port| SocketAddr::from(([127, 0, 0, 1], port))).collect(),
            ip_preference: IpPreference::Ipv4Only,
        };
        (Resolver::new(Arc::new(config)), requests, server)
    }

    #[tokio::test]
    async fn overlapping_lookups_share_one_transaction_even_when_the_ttl_is_zero() {
        use std::sync::atomic::Ordering;
        let (resolver, requests, server) = delayed_peer(1, Some((0, Duration::from_millis(35))), 0).await;
        let queries = (0..32).map(|i| resolver.lookup(if i % 2 == 0 { "burst.test" } else { "BURST.Test." }));
        let expected: IpAddr = "198.51.100.77".parse().unwrap();
        for answer in futures_util::future::join_all(queries).await {
            assert_eq!(answer.unwrap(), [expected]);
        }
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        assert!(resolver.cache.lock().unwrap().pending.is_empty());
        assert_eq!(resolver.lookup("burst.test").await.unwrap(), [expected]);
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn a_waiter_deadline_and_leader_cancellation_do_not_poison_other_callers() {
        use std::sync::atomic::Ordering;
        let (resolver, requests, server) = timeout_peer(1, Some((0, Duration::from_millis(200)))).await;
        let resolver = Arc::new(resolver);
        let leader = tokio::spawn({
            let resolver = resolver.clone();
            async move { resolver.lookup("busy.test").await }
        });
        let wait_for = |joined: bool| {
            let resolver = &resolver;
            let requests = &requests;
            async move {
                tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        let ready = if joined {
                            resolver
                                .cache
                                .lock()
                                .unwrap()
                                .pending
                                .get("busy.test")
                                .is_some_and(|s| s.receiver_count() > 0)
                        } else {
                            requests.load(Ordering::SeqCst) == 1
                        };
                        if ready {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
            }
        };
        wait_for(false).await;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(10);
        assert_eq!(resolver.lookup_until("busy.test", deadline).await.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(resolver.cache.lock().unwrap().entries.is_empty());
        assert_eq!(*resolver.preferred.lock().unwrap(), (0, 0));
        let follower = tokio::spawn({
            let resolver = resolver.clone();
            async move { resolver.lookup("BUSY.test.").await }
        });
        wait_for(true).await;
        leader.abort();
        assert!(leader.await.unwrap_err().is_cancelled());
        let address: IpAddr = "198.51.100.77".parse().unwrap();
        assert_eq!(tokio::time::timeout(Duration::from_secs(2), follower).await.unwrap().unwrap().unwrap(), [address]);
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        assert!(resolver.cache.lock().unwrap().pending.is_empty());
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn a_full_cache_retains_active_names_across_refresh_and_insertion() {
        use std::sync::atomic::Ordering;
        let address: IpAddr = "198.51.100.77".parse().unwrap();
        let (resolver, requests, server) = timeout_peer(1, Some((0, Duration::ZERO))).await;
        for i in 0..CACHE_ENTRIES {
            resolver.remember(format!("entry-{i}.test"), Ok(vec![address]), MAX_TTL);
        }
        for i in 0..128 {
            assert_eq!(resolver.lookup(&format!("entry-{i}.test")).await.unwrap(), [address]);
        }
        resolver.remember("entry-17.test".into(), Ok(vec![address]), MAX_TTL);
        for i in 0..256 {
            resolver.remember(format!("new-{i}.test"), Ok(vec![address]), MAX_TTL);
            assert_eq!(resolver.lookup(&format!("entry-{}.test", i % 128)).await.unwrap(), [address]);
        }
        assert_eq!(requests.load(Ordering::SeqCst), 0);
        assert_eq!(resolver.cache.lock().unwrap().entries.len(), CACHE_ENTRIES);
        server.abort();
        let _ = server.await;
    }

    #[test]
    fn referenced_entries_do_not_prevent_eviction_or_extend_ttls() {
        let mut cache = DnsCache::default();
        let now = Instant::now();
        for i in 0..CACHE_ENTRIES {
            let name = format!("entry-{i}.test");
            cache.insert(name.clone(), Ok(vec![]), now + FAILURE_TTL, now);
            assert!(cache.get(&name, now).is_some());
        }
        cache.insert("fresh.test".into(), Ok(vec![]), now + MAX_TTL, now);
        assert_eq!(cache.entries.len(), CACHE_ENTRIES);
        assert!(cache.get("fresh.test", now).is_some());
        assert!(cache.get("entry-1.test", now + FAILURE_TTL).is_none());
    }

    #[tokio::test]
    async fn silent_resolvers_cache_failure_at_the_relay_deadline() {
        use network_relay::policy::{Policy, Refusal, Target};
        use std::sync::atomic::Ordering;
        let (resolver, requests, server) = timeout_peer(2, None).await;
        let egress = crate::VlessEgress::new((*resolver.config).clone());
        let policy = Policy::new(&network_relay::config::Relay::default());
        let target = Target { host: "victim.test".into(), port: 443 };
        let result =
            tokio::time::timeout(Duration::from_secs(6), policy.resolve(&target, Some(&egress), async {})).await;
        assert_eq!(result.unwrap(), Err(Refusal::DnsTimeout));
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        let target = Target { host: "VICTIM.test.".into(), port: 443 };
        for _ in 0..100 {
            let cached =
                tokio::time::timeout(Duration::from_millis(100), policy.resolve(&target, Some(&egress), async {}))
                    .await;
            assert_eq!(cached.unwrap(), Err(Refusal::DnsTimeout));
        }
        assert_eq!(requests.load(Ordering::SeqCst), 2, "cached timeouts must not requery");
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn multiple_resolvers_do_not_shorten_a_healthy_first_attempt() {
        let (resolver, _, server) = timeout_peer(8, Some((0, Duration::from_secs(1)))).await;
        let deadline = tokio::time::Instant::now() + network_relay::policy::DNS_TIMEOUT;
        let result = tokio::time::timeout_at(deadline, resolver.lookup_until("victim.test", deadline)).await;
        assert_eq!(result.unwrap().unwrap(), vec!["198.51.100.77".parse::<IpAddr>().unwrap()]);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn a_working_backup_does_not_pay_the_dead_first_resolver_again() {
        use std::sync::atomic::Ordering;
        let (resolver, requests, server) = timeout_peer(2, Some((1, Duration::ZERO))).await;
        assert_eq!(resolver.lookup("first.test").await.unwrap().len(), 1);
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        let started = Instant::now();
        let next = tokio::time::timeout(Duration::from_secs(1), resolver.lookup("second.test")).await;
        assert_eq!(next.unwrap().unwrap().len(), 1);
        eprintln!("uncached name after backup success: {:?}", started.elapsed());
        assert_eq!(requests.load(Ordering::SeqCst), 3, "new names should use the working resolver first");
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn repeated_deadlines_eventually_reach_later_resolvers_without_overlap() {
        use std::sync::atomic::Ordering;
        let (resolver, requests, server) = timeout_peer(8, Some((7, Duration::ZERO))).await;
        for index in 0..8 {
            let name = format!("name{index}.test");
            let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
            let result = resolver.lookup_until(&name, deadline).await;
            if index == 7 {
                assert_eq!(result.unwrap().len(), 1);
            } else {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
            }
            assert_eq!(requests.load(Ordering::SeqCst), index + 1, "only one resolver fits this deadline");
        }
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn an_already_expired_budget_does_not_query_or_cache() {
        let (resolver, requests, server) = timeout_peer(1, None).await;
        let result = resolver.lookup_until("victim.test", tokio::time::Instant::now()).await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(resolver.cache.lock().unwrap().entries.is_empty());
        assert_eq!(*resolver.preferred.lock().unwrap(), (0, 0));
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn a_failed_preferred_resolver_wraps_to_a_recovered_earlier_one() {
        use std::sync::atomic::Ordering;
        let (resolver, requests, server) = timeout_peer(2, Some((0, Duration::ZERO))).await;
        resolver.prefer(1);
        assert_eq!(resolver.lookup("first.test").await.unwrap().len(), 1);
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        let next = tokio::time::timeout(Duration::from_secs(1), resolver.lookup("second.test")).await;
        assert_eq!(next.unwrap().unwrap().len(), 1);
        assert_eq!(requests.load(Ordering::SeqCst), 3);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn an_older_timeout_does_not_displace_a_newer_successful_preference() {
        let (resolver, requests, server) = timeout_peer(2, None).await;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
        let completed = async {
            while requests.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
            // The same index has answered another lookup after this one
            // started. A generation check, not just the index, protects it.
            resolver.prefer(0);
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(resolver.lookup_until("victim.test", deadline), completed)
        })
        .await
        .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(*resolver.preferred.lock().unwrap(), (0, 1));
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn repeated_configured_addresses_are_not_requeried_in_one_lookup() {
        use std::sync::atomic::Ordering;
        let (mut resolver, requests, server) = caching_peer(ResponseCode::ServFail, None, false).await;
        let config = Arc::make_mut(&mut resolver.config);
        config.dns_servers = vec![config.dns_servers[0]; 8];
        assert!(resolver.lookup("victim.test").await.is_err());
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        assert!(resolver.probe().await.is_err());
        assert_eq!(requests.load(Ordering::SeqCst), 2, "startup probes must also skip duplicate addresses");
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn a_timed_out_lookup_does_not_evict_a_concurrent_success() {
        let (resolver, requests, server) = timeout_peer(1, None).await;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
        let success = async {
            while requests.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
            resolver.remember(
                "victim.test".into(),
                Ok(vec!["198.51.100.77".parse().unwrap()]),
                Duration::from_secs(10),
            );
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(resolver.lookup_until("victim.test", deadline), success)
        })
        .await
        .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(resolver.lookup("victim.test").await.unwrap(), vec!["198.51.100.77".parse::<IpAddr>().unwrap()]);
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1);
        server.abort();
        let _ = server.await;
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
        partial_answer_with_budget(qtype, failure_first, ttl, truncated, None).await;
    }

    async fn partial_answer_with_budget(
        qtype: RecordType,
        failure_first: Option<bool>,
        ttl: u32,
        truncated: bool,
        budget: Option<Duration>,
    ) {
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
        let result = tokio::time::timeout(Duration::from_secs(4), async {
            match budget {
                Some(budget) => resolver.lookup_until("victim.test", tokio::time::Instant::now() + budget).await,
                None => resolver.lookup("victim.test").await,
            }
        })
        .await
        .unwrap();
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
                resolver.cache.lock().unwrap().get("victim.test", Instant::now()).is_none(),
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
    async fn a_usable_family_survives_the_callers_shorter_deadline() {
        for qtype in [RecordType::A, RecordType::AAAA] {
            partial_answer_with_budget(qtype, None, 10, false, Some(Duration::from_millis(300))).await;
        }
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
