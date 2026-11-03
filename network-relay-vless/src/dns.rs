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
use hickory_proto::rr::{Name, RData, RecordType};
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
            match tokio::time::timeout(PER_SERVER, self.ask(*server, &fqdn)).await {
                Ok(Ok((mut addrs, ttl))) => {
                    self.config.ip_preference.apply(&mut addrs);
                    self.remember(name, &addrs, ttl);
                    return Ok(addrs);
                }
                Ok(Err(Failure::Final(e))) => return Err(e),
                Ok(Err(Failure::Retry(e))) => {
                    tracing::debug!(%server, "DNS through VLESS failed: {e}");
                    last = e;
                }
                Err(_) => {
                    tracing::debug!(%server, "DNS through VLESS timed out");
                    last = io::Error::new(io::ErrorKind::TimedOut, "the resolvers did not answer in time");
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
        let preference = self.config.ip_preference;
        let mut types = Vec::new();
        if preference.wants_ipv4() {
            types.push(RecordType::A);
        }
        if preference.wants_ipv6() {
            types.push(RecordType::AAAA);
        }
        let mut stream = VlessStream::open(&self.config, Command::Tcp, server).await.map_err(retry)?;
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
        stream.write_all(&wire).await.map_err(retry)?;
        stream.flush().await.map_err(retry)?;
        let mut addrs = Vec::new();
        let mut ttl = MAX_TTL;
        let mut nxdomain = false;
        while !queries.is_empty() {
            let length = stream.read_u16().await.map_err(retry)? as usize;
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes).await.map_err(retry)?;
            let Ok(answer) = Message::from_vec(&bytes) else {
                return Err(retry(io::Error::new(io::ErrorKind::InvalidData, "malformed DNS answer")));
            };
            let Some(index) = queries.iter().position(|(id, qtype)| {
                answer.id() == *id
                    && answer.message_type() == MessageType::Response
                    && answer.queries().len() == 1
                    && answer.queries()[0].query_type() == *qtype
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
            for record in answer.answers() {
                // Recursive resolvers put the records of a CNAME chain's
                // target in the same answer.
                let found = match (qtype, record.data()) {
                    (RecordType::A, RData::A(a)) => IpAddr::V4(a.0),
                    (RecordType::AAAA, RData::AAAA(a)) => IpAddr::V6(a.0),
                    _ => continue,
                };
                if !addrs.contains(&found) {
                    addrs.push(found);
                }
                ttl = ttl.min(Duration::from_secs(record.ttl().into()));
            }
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
