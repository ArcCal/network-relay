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
use crate::transport::VlessStream;
use crate::vless::Command;

/// How long one resolver gets; the relay allows a lookup five seconds in
/// all, so a second resolver still has time when the first does not answer.
const PER_SERVER: Duration = Duration::from_millis(2500);
/// Answers are cached for their TTL, but no longer than this.
const MAX_TTL: Duration = Duration::from_secs(300);
const CACHE_ENTRIES: usize = 4096;

pub struct Resolver {
    config: Arc<VlessConfig>,
    cache: Mutex<HashMap<String, (Vec<IpAddr>, Instant)>>,
}

/// Why a resolver could not answer.
enum Failure {
    /// The answer is final: asking another resolver would not change it.
    Final(io::Error),
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
        if let Some((addrs, expires)) = self.cache.lock().unwrap_or_else(|e| e.into_inner()).get(&name) {
            if *expires > now {
                return Ok(addrs.clone());
            }
        }
        let fqdn = Name::from_ascii(format!("{name}."))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "not a valid DNS name"))?;
        let mut last = io::Error::new(io::ErrorKind::TimedOut, "no resolver answered");
        for server in &self.config.dns_servers {
            match self.ask(*server, &fqdn).await {
                Ok((mut addrs, ttl)) => {
                    self.config.ip_preference.apply(&mut addrs);
                    self.remember(name, &addrs, ttl);
                    return Ok(addrs);
                }
                Err(Failure::Final(e)) => return Err(e),
                Err(Failure::Retry(e)) => {
                    tracing::debug!(%server, "DNS through VLESS failed: {e}");
                    last = e;
                }
            }
        }
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
                let mut message = Message::new();
                message.set_id(id).set_message_type(MessageType::Query).set_recursion_desired(true);
                message.add_query(Query::query(Name::root(), RecordType::NS));
                let bytes = message.to_vec().map_err(|e| io::Error::other(e.to_string()))?;
                stream.write_all(&(bytes.len() as u16).to_be_bytes()).await?;
                stream.write_all(&bytes).await?;
                stream.flush().await?;
                let mut answer = vec![0; stream.read_u16().await? as usize];
                stream.read_exact(&mut answer).await?;
                match Message::from_vec(&answer) {
                    Ok(answer) if answer.id() == id => Ok(()),
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

    fn remember(&self, name: String, addrs: &[IpAddr], ttl: Duration) {
        if addrs.is_empty() || ttl.is_zero() {
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
        cache.insert(name, (addrs.to_vec(), now + ttl.min(MAX_TTL)));
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
            let id = random_id();
            let mut message = Message::new();
            message
                .set_id(id)
                .set_message_type(MessageType::Query)
                .set_op_code(OpCode::Query)
                .set_recursion_desired(true);
            message.add_query(Query::query(name.clone(), *qtype));
            let bytes = message.to_vec().map_err(|e| Failure::Final(io::Error::other(e.to_string())))?;
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
        let mut ttl = MAX_TTL;
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
            let Ok(answer) = Message::from_vec(&bytes) else {
                return Err(retry(io::Error::new(io::ErrorKind::InvalidData, "malformed DNS answer")));
            };
            let Some(index) = queries.iter().position(|(id, qtype)| {
                answer.id() == *id
                    && answer.message_type() == MessageType::Response
                    && answer.op_code() == OpCode::Query
                    && answer.queries().len() == 1
                    && answer.queries()[0].query_type() == *qtype
                    && answer.queries()[0].query_class() == DNSClass::IN
                    && answer.queries()[0].name().to_ascii().eq_ignore_ascii_case(&name.to_ascii())
            }) else {
                continue;
            };
            let (_, qtype) = queries.remove(index);
            match answer.response_code() {
                ResponseCode::NoError => {}
                ResponseCode::NXDomain => nxdomain = true,
                code => {
                    return Err(retry(io::Error::other(format!("the resolver answered {code}"))));
                }
            }
            let (found, answer_ttl) = addresses(&answer, name, qtype).map_err(retry)?;
            for found in found {
                if !addrs.contains(&found) {
                    addrs.push(found);
                }
            }
            ttl = ttl.min(answer_ttl);
        }
        if nxdomain && addrs.is_empty() {
            return Err(Failure::Final(io::Error::new(io::ErrorKind::NotFound, "no such name")));
        }
        Ok((addrs, ttl))
    }
}

fn random_id() -> u16 {
    let mut b = [0u8; 2];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b).expect("system random numbers");
    u16::from_be_bytes(b)
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
        let records = || answer.answers().iter().filter(|r| r.dns_class() == DNSClass::IN && r.name() == &owner);
        if let Some(record) = records().find(|r| matches!(r.data(), RData::CNAME(_))) {
            let RData::CNAME(target) = record.data() else { unreachable!() };
            ttl = ttl.min(Duration::from_secs(record.ttl().into()));
            owner = target.0.clone();
            continue;
        }
        let mut addrs = Vec::new();
        for record in records() {
            let addr = match (qtype, record.data()) {
                (RecordType::A, RData::A(a)) => IpAddr::V4(a.0),
                (RecordType::AAAA, RData::AAAA(a)) => IpAddr::V6(a.0),
                _ => continue,
            };
            ttl = ttl.min(Duration::from_secs(record.ttl().into()));
            if !addrs.contains(&addr) {
                addrs.push(addr);
            }
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
    fn answers_require_the_queried_owner_or_a_valid_cname_chain() {
        let name = Name::from_ascii("victim.test.").unwrap();
        let other = Name::from_ascii("other.test.").unwrap();
        let ip = RData::A(rdata::A("198.51.100.77".parse().unwrap()));
        let mut answer = Message::new();
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
        record.set_dns_class(DNSClass::CH);
        let mut answer = Message::new();
        answer.add_answer(record.clone());
        assert!(addresses(&answer, &name, RecordType::AAAA).unwrap().0.is_empty());
        record.set_dns_class(DNSClass::IN);
        answer.add_answer(record);
        let (found, ttl) = addresses(&answer, &name, RecordType::AAAA).unwrap();
        assert_eq!(found.len(), 1);
        assert!(ttl.is_zero());
    }

    // A real WS/VLESS peer returns only one of the pipelined DNS answers.
    async fn partial_answer(qtype: RecordType) {
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
            let query = queries.iter().find(|q| q.queries()[0].query_type() == qtype).unwrap();
            let mut answer = Message::new();
            answer.set_id(query.id()).set_message_type(MessageType::Response);
            answer.add_query(query.queries()[0].clone());
            let data = match qtype {
                RecordType::A => RData::A(rdata::A("198.51.100.77".parse().unwrap())),
                _ => RData::AAAA(rdata::AAAA("2001:db8::7".parse().unwrap())),
            };
            answer.add_answer(Record::from_rdata(query.queries()[0].name().clone(), 10, data));
            let bytes = answer.to_vec().unwrap();
            let mut frame = vec![0, 0]; // VLESS response header.
            frame.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            frame.extend_from_slice(&bytes);
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
        let found =
            tokio::time::timeout(Duration::from_secs(4), resolver.lookup("victim.test")).await.unwrap().unwrap();
        let expected: IpAddr = if qtype == RecordType::A { "198.51.100.77" } else { "2001:db8::7" }.parse().unwrap();
        assert_eq!(found, vec![expected]);
        assert_eq!(resolver.lookup("victim.test").await.unwrap(), found); // Cached without another connection.
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn ipv4_survives_an_unanswered_aaaa_query() {
        partial_answer(RecordType::A).await;
    }

    #[tokio::test]
    async fn ipv6_survives_an_unanswered_a_query() {
        partial_answer(RecordType::AAAA).await;
    }
}
