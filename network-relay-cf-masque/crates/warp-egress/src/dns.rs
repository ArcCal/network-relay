//! A stub resolver that asks the configured DNS servers through the tunnel
//! (RFC 1035, with the EDNS(0) of RFC 6891). SOCKS clients that send host
//! names get them resolved here, so names never reach the local network's
//! resolver. Queries go over UDP, and over TCP when an answer is truncated.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use indexmap::IndexMap;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;
use tracing::debug;

use crate::netstack::{self, NetStack};

const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
pub(crate) const TYPE_AAAA: u16 = 28;
const TYPE_OPT: u16 = 41;
const CLASS_IN: u16 = 1;
const RCODE_NXDOMAIN: u16 = 3;
/// EDNS(0) UDP payload size: the size recommended to avoid IP
/// fragmentation, which also fits the stack's MTU.
const EDNS_UDP_SIZE: u16 = 1232;
/// Per-server waits for an answer, one entry per round over all servers.
const UDP_TIMEOUTS: [Duration; 2] = [Duration::from_secs(2), Duration::from_secs(3)];
const TCP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_TTL: u32 = 3600;
const CACHE_SIZE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LookupError {
    #[error("not a valid host name")]
    InvalidName,
    #[error("no such host")]
    NotFound,
    #[error("the DNS servers did not answer")]
    NoAnswer,
    #[error("the WARP tunnel is unavailable")]
    Unavailable,
}

type Lookup = Result<Vec<IpAddr>, LookupError>;
/// A lookup result and when it expires.
struct Cached {
    result: Lookup,
    expires: Instant,
    referenced: bool,
}

#[derive(Default)]
struct DnsCache {
    entries: IndexMap<QueryKey, Cached>,
    hand: usize,
}

impl DnsCache {
    fn get(&mut self, key: &QueryKey, now: Instant) -> Option<Lookup> {
        let entry = self.entries.get_mut(key)?;
        if entry.expires <= now {
            return None;
        }
        entry.referenced = true;
        Some(entry.result.clone())
    }

    fn insert(&mut self, key: QueryKey, result: Lookup, expires: Instant, now: Instant) {
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.result = result;
            entry.expires = expires;
            return;
        }
        if self.entries.len() == CACHE_SIZE {
            // Give active answers one more turn. A full sweep clears every
            // reference bit, so inserting one result always frees one slot.
            loop {
                let index = self.hand;
                self.hand = (self.hand + 1) % CACHE_SIZE;
                let (_, entry) = self.entries.get_index_mut(index).expect("full DNS cache");
                if entry.expires <= now || !entry.referenced {
                    self.entries.swap_remove_index(index);
                    break;
                }
                entry.referenced = false;
            }
        }
        self.entries.insert(key, Cached { result, expires, referenced: false });
    }
}
/// A query under way, which lookups of the same name and type wait for.
type InFlight = Arc<tokio::sync::OnceCell<Lookup>>;
type QueryKey = (String, u16);
type PendingQueries = Mutex<HashMap<QueryKey, InFlight>>;

/// Removes a finished query, or an abandoned query's last waiter. In
/// particular, Happy Eyeballs drops the other family's lookup on success.
struct PendingLookup<'a> {
    queries: &'a PendingQueries,
    key: QueryKey,
    flight: InFlight,
}

impl Drop for PendingLookup<'_> {
    fn drop(&mut self) {
        let mut queries = self.queries.lock().unwrap_or_else(|e| e.into_inner());
        // The map and this guard are the last two owners if every other
        // waiter was cancelled. Keep an unfinished cell while another
        // waiter can still initialize it, so new callers share that query.
        if queries.get(&self.key).is_some_and(|f| Arc::ptr_eq(f, &self.flight))
            && (self.flight.get().is_some() || Arc::strong_count(&self.flight) == 2)
        {
            queries.remove(&self.key);
        }
    }
}

/// Resolves host names with the given servers, through `net`.
pub struct Resolver {
    net: NetStack,
    servers: Vec<SocketAddr>,
    cache: Mutex<DnsCache>,
    pending: PendingQueries,
}

impl Resolver {
    pub fn new(net: NetStack, servers: Vec<SocketAddr>) -> Self {
        Self { net, servers, cache: Mutex::default(), pending: Mutex::new(HashMap::new()) }
    }

    /// The addresses of `host` in the families the tunnel carries, IPv6
    /// first. An IP address literal is returned as it is.
    pub async fn lookup(&self, host: &str) -> Result<Vec<IpAddr>, LookupError> {
        self.net.check_available().map_err(|_| LookupError::Unavailable)?;
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let (a, aaaa) = tokio::join!(self.lookup_family(host, false), self.lookup_family(host, true));
        self.net.check_available().map_err(|_| LookupError::Unavailable)?;
        let mut addrs = Vec::new();
        let current_addresses = self.net.addresses();
        for list in [&aaaa, &a].into_iter().flatten() {
            addrs.extend(
                list.iter().copied().filter(|ip| current_addresses.iter().any(|own| own.is_ipv4() == ip.is_ipv4())),
            );
        }
        if !addrs.is_empty() {
            Ok(addrs)
        } else if a == Err(LookupError::InvalidName) {
            Err(LookupError::InvalidName)
        } else if a == Err(LookupError::NotFound) && aaaa == Err(LookupError::NotFound) {
            Err(LookupError::NotFound)
        } else {
            Err(LookupError::NoAnswer)
        }
    }

    /// Resolve each family independently so TCP can start using an answer
    /// without waiting for the other DNS query to time out (RFC 8305).
    pub(crate) async fn lookup_family(&self, host: &str, ipv6: bool) -> Result<Vec<IpAddr>, LookupError> {
        self.net.check_available().map_err(|_| LookupError::Unavailable)?;
        let name = normalize(host).ok_or(LookupError::InvalidName)?;
        if !self.net.addresses().iter().any(|ip| ip.is_ipv6() == ipv6) {
            return Err(LookupError::NotFound);
        }
        let qtype = if ipv6 { TYPE_AAAA } else { TYPE_A };
        let key = (name.clone(), qtype);
        let now = Instant::now();
        if let Some(result) = self.cache.lock().unwrap_or_else(|e| e.into_inner()).get(&key, now) {
            return result;
        }
        // Lookups of a name many clients want at once (a page's resources,
        // or many connections to one host) share one query rather than
        // sending as many, which would crowd each other out.
        let flight = self.pending.lock().unwrap_or_else(|e| e.into_inner()).entry(key.clone()).or_default().clone();
        let pending = PendingLookup { queries: &self.pending, key: key.clone(), flight };
        let result = tokio::select! {
            biased;
            _ = self.net.closed() => Err(LookupError::Unavailable),
            result = pending.flight.get_or_init(|| self.resolve(&name, qtype, key.clone())) => result.clone(),
        };
        self.net.check_available().map_err(|_| LookupError::Unavailable)?;
        result
    }

    /// Queries the servers and caches the answer.
    async fn resolve(&self, name: &str, qtype: u16, key: QueryKey) -> Lookup {
        let (result, ttl) = match self.query(name, qtype).await {
            Answer::Found(list, ttl) if !list.is_empty() => (Ok(list), ttl),
            Answer::Found(_, ttl) | Answer::NoSuchName(ttl) => (Err(LookupError::NotFound), ttl),
            // RFC 9520 section 3.2 requires at least one second of failure
            // caching. Keep the shortest permitted delay for rapid recovery;
            // a failed lookup must remain distinct from NXDOMAIN/NODATA.
            Answer::Failed => (Err(LookupError::NoAnswer), 1),
        };
        self.net.check_available().map_err(|_| LookupError::Unavailable)?;
        // Successful TTL 0 answers are uncacheable. NXDOMAIN/NODATA lifetimes
        // come from SOA records (RFC 2308); failure caching is separate above.
        if ttl > 0 {
            let now = Instant::now();
            let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.insert(key, result.clone(), now + Duration::from_secs(ttl.min(MAX_TTL).into()), now);
        }
        result
    }

    /// Asks the servers of families the tunnel carries, in turn.
    async fn query(&self, name: &str, qtype: u16) -> Answer {
        let own = self.net.addresses();
        let servers: Vec<SocketAddr> =
            self.servers.iter().copied().filter(|s| own.iter().any(|o| o.is_ipv4() == s.is_ipv4())).collect();
        for wait in UDP_TIMEOUTS {
            for &server in &servers {
                if self.net.check_available().is_err() {
                    return Answer::Failed;
                }
                match self.query_server(server, name, qtype, wait).await {
                    Ok(Some(answer)) => return answer,
                    Ok(None) => {}
                    Err(e) => debug!(%server, "DNS query for {name:?} failed: {e}"),
                }
            }
        }
        Answer::Failed
    }

    /// One query to one server. `Ok(None)` means no usable answer in time.
    async fn query_server(&self, to: SocketAddr, name: &str, qtype: u16, wait: Duration) -> io::Result<Option<Answer>> {
        let id = random_id();
        self.net.local_address(to.ip())?;
        let udp_size = netstack::max_udp_payload(self.net.mtu(), to.is_ipv4()).min(usize::from(EDNS_UDP_SIZE)) as u16;
        let query = build_query_with_udp_size(id, name, qtype, udp_size);
        let socket = self.net.bind_udp(0)?;
        socket.send_to(&query, to).await?;
        let deadline = Instant::now() + wait;
        let response = loop {
            let Ok(received) = tokio::time::timeout_at(deadline, socket.recv_from()).await else {
                return Ok(None);
            };
            let (msg, from) = received?;
            // Anything else is stray or forged.
            if from == to {
                if let Some(r) = parse_response(&msg, id, name, qtype) {
                    break r;
                }
            }
        };
        drop(socket);
        let response = if response.truncated {
            match tokio::time::timeout(TCP_TIMEOUT, self.query_tcp(to, &query, id, name, qtype)).await {
                Ok(Ok(Some(r))) => r,
                Ok(Ok(None)) | Err(_) => return Ok(None),
                Ok(Err(e)) => {
                    debug!(server = %to, "DNS over TCP failed: {e}");
                    return Ok(None);
                }
            }
        } else {
            response
        };
        Ok(Answer::from_response(response))
    }

    async fn query_tcp(
        &self,
        to: SocketAddr,
        query: &[u8],
        id: u16,
        name: &str,
        qtype: u16,
    ) -> io::Result<Option<Response>> {
        let mut stream = self.net.connect(to).await?;
        let mut framed = (query.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(query);
        stream.write_all(&framed).await?;
        let len = stream.read_u16().await?;
        let mut msg = vec![0; len.into()];
        stream.read_exact(&mut msg).await?;
        Ok(parse_response(&msg, id, name, qtype))
    }
}

/// What one query found out.
#[derive(Debug, PartialEq)]
enum Answer {
    /// The name exists; these addresses (possibly none) with this TTL.
    Found(Vec<IpAddr>, u32),
    NoSuchName(u32),
    /// No server gave a usable answer.
    Failed,
}

impl Answer {
    fn from_response(r: Response) -> Option<Self> {
        if r.truncated {
            return None;
        }
        match r.rcode {
            0 => Some(Answer::Found(r.addrs, r.ttl)),
            RCODE_NXDOMAIN => Some(Answer::NoSuchName(r.ttl)),
            // SERVFAIL, REFUSED and the like: try another server.
            _ => None,
        }
    }
}

fn random_id() -> u16 {
    let mut b = [0u8; 2];
    SystemRandom::new().fill(&mut b).expect("system RNG");
    u16::from_le_bytes(b)
}

/// Lower case without a trailing dot, if `host` is a valid DNS name of
/// ASCII labels (clients send internationalized names as punycode).
pub(crate) fn normalize(host: &str) -> Option<String> {
    let target = network_relay::policy::Target::from_template_vars(host, "53")?;
    // IP literals are handled before DNS. An IPv6 literal cannot be encoded
    // as a DNS query name; keep hostname rules identical to the relay's.
    (!target.host.contains(':')).then_some(target.host)
}

/// A recursive query for `name` (already normalized) with an EDNS(0) OPT
/// record.
#[cfg(test)]
fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    build_query_with_udp_size(id, name, qtype, EDNS_UDP_SIZE)
}

fn build_query_with_udp_size(id: u16, name: &str, qtype: u16, udp_size: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(name.len() + 30);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 1]); // QD 1, AN 0, NS 0, AR 1
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&CLASS_IN.to_be_bytes());
    q.push(0); // OPT: root name
    q.extend_from_slice(&TYPE_OPT.to_be_bytes());
    q.extend_from_slice(&udp_size.to_be_bytes());
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // extended RCODE, version, flags, RDLEN
    q
}

#[derive(Debug, PartialEq)]
struct Response {
    truncated: bool,
    rcode: u16,
    /// Addresses of the queried name or the end of its validated CNAME chain.
    addrs: Vec<IpAddr>,
    /// Smallest TTL across the CNAME chain and addresses, or the SOA
    /// negative lifetime. Zero means the response cannot be cached.
    ttl: u32,
}

/// Parses the answer to our query `id` for `name` and `qtype`; `None` if it
/// is malformed or answers something else.
fn parse_response(msg: &[u8], id: u16, name: &str, qtype: u16) -> Option<Response> {
    let u16_at = |i: usize| msg.get(i..i + 2).map(|b| u16::from_be_bytes([b[0], b[1]]));
    let flags = u16_at(2)?;
    let is_response = flags & 0x8000 != 0;
    let opcode = (flags >> 11) & 0xf;
    if u16_at(0)? != id || !is_response || opcode != 0 || u16_at(4)? != 1 {
        return None;
    }
    let ancount = u16_at(6)?;
    let nscount = u16_at(8)?;
    let arcount = u16_at(10)?;
    let (qname, mut pos) = read_name(msg, 12)?;
    if qname != name || u16_at(pos)? != qtype || u16_at(pos + 2)? != CLASS_IN {
        return None;
    }
    pos += 4;
    let mut rcode = flags & 0xf;
    if flags & 0x0200 != 0 {
        // Validate the question first, but do not require complete records
        // from a truncated UDP answer: retry the whole query over TCP.
        return Some(Response { truncated: true, rcode, addrs: Vec::new(), ttl: 0 });
    }
    let mut aliases: HashMap<String, (String, u32)> = HashMap::new();
    let mut addresses: HashMap<String, Vec<(IpAddr, u32)>> = HashMap::new();
    for _ in 0..ancount {
        let rr = read_record(msg, &mut pos)?;
        if rr.class != CLASS_IN {
            continue;
        }
        if rr.rtype == TYPE_CNAME {
            let (target, end) = read_name(msg, rr.data_start)?;
            if end != pos || target.is_empty() {
                return None;
            }
            if let Some((old, ttl)) = aliases.get_mut(&rr.name) {
                if *old != target {
                    return None;
                }
                *ttl = (*ttl).min(rr.ttl);
            } else {
                aliases.insert(rr.name, (target, rr.ttl));
            }
        } else if rr.rtype == qtype {
            let addr = match (rr.rtype, rr.data.len()) {
                (TYPE_A, 4) => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(rr.data).ok()?)),
                (TYPE_AAAA, 16) => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(rr.data).ok()?)),
                _ => return None,
            };
            addresses.entry(rr.name).or_default().push((addr, rr.ttl));
        }
    }
    let mut canonical = name.to_string();
    let mut ttl = MAX_TTL;
    let mut visited = HashSet::new();
    while let Some((target, lifetime)) = aliases.get(&canonical) {
        if !visited.insert(canonical.clone()) || addresses.contains_key(&canonical) {
            return None;
        }
        ttl = ttl.min(*lifetime);
        canonical.clone_from(target);
    }
    let mut addrs = Vec::new();
    if let Some(records) = addresses.get(&canonical) {
        for (addr, lifetime) in records {
            if !addrs.contains(addr) {
                addrs.push(*addr);
            }
            ttl = ttl.min(*lifetime);
        }
    }
    let mut negative_ttl = None::<u32>;
    for _ in 0..nscount {
        let rr = read_record(msg, &mut pos)?;
        if rr.class == CLASS_IN && rr.rtype == TYPE_SOA {
            let (_, after_primary) = read_name(msg, rr.data_start)?;
            let (_, after_mailbox) = read_name(msg, after_primary)?;
            if after_mailbox.checked_add(20)? != pos {
                return None;
            }
            let minimum = dns_ttl(u32::from_be_bytes(msg.get(after_mailbox + 16..pos)?.try_into().ok()?));
            if rr.name.is_empty() || canonical == rr.name || canonical.ends_with(&format!(".{}", rr.name)) {
                let lifetime = rr.ttl.min(minimum);
                negative_ttl = Some(negative_ttl.map_or(lifetime, |old| old.min(lifetime)));
            }
        }
    }
    for _ in 0..arcount {
        let rr = read_record(msg, &mut pos)?;
        if rr.rtype == TYPE_OPT {
            // The OPT TTL field is a bitfield, not a lifetime.
            rcode |= u16::from(msg[rr.data_start - 6]) << 4;
        }
    }
    if pos != msg.len() {
        return None;
    }
    if addrs.is_empty() || rcode != 0 {
        ttl = ttl.min(negative_ttl.unwrap_or(0));
    }
    Some(Response { truncated: false, rcode, addrs, ttl })
}

struct Record<'a> {
    name: String,
    rtype: u16,
    class: u16,
    ttl: u32,
    data_start: usize,
    data: &'a [u8],
}

fn read_record<'a>(msg: &'a [u8], pos: &mut usize) -> Option<Record<'a>> {
    let (name, after) = read_name(msg, *pos)?;
    let header = msg.get(after..after + 10)?;
    let rtype = u16::from_be_bytes([header[0], header[1]]);
    let class = u16::from_be_bytes([header[2], header[3]]);
    let ttl = dns_ttl(u32::from_be_bytes(header[4..8].try_into().ok()?));
    let len = usize::from(u16::from_be_bytes([header[8], header[9]]));
    let data_start = after + 10;
    let data = msg.get(data_start..data_start + len)?;
    *pos = data_start + len;
    Some(Record { name, rtype, class, ttl, data_start, data })
}

fn dns_ttl(ttl: u32) -> u32 {
    // RFC 2181 §8: TTLs with the high bit set are treated as zero.
    if ttl & 0x8000_0000 == 0 {
        ttl
    } else {
        0
    }
}

/// Reads a possibly compressed name at `pos`: the name in lower case and
/// the position after it.
pub(crate) fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut end = None;
    let mut wire_len = 1; // Include the terminating root label (RFC 1035 section 2.3.4).
    for _ in 0..128 {
        let len = *msg.get(pos)?;
        match len & 0xc0 {
            0x00 if len == 0 => return Some((name, end.unwrap_or(pos + 1))),
            0x00 => {
                let label = msg.get(pos + 1..pos + 1 + usize::from(len))?;
                if !name.is_empty() {
                    name.push('.');
                }
                wire_len += 1 + label.len();
                if wire_len > 255 {
                    return None;
                }
                // RFC 2181 section 11 permits binary labels. Escape octets
                // outside our hostname alphabet so embedded dots cannot turn
                // one wire label into several question/CNAME/owner labels.
                for &b in label {
                    if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_') {
                        name.push(char::from(b.to_ascii_lowercase()));
                    } else {
                        use std::fmt::Write;
                        write!(name, "\\{b:03}").expect("writing to String");
                    }
                }
                pos += 1 + usize::from(len);
            }
            0xc0 => {
                let target = usize::from(u16::from_be_bytes([len, *msg.get(pos + 1)?]) & 0x3fff);
                // RFC 1035 section 4.1.4 points to a prior occurrence.
                if target < 12 || target >= pos {
                    return None;
                }
                end.get_or_insert(pos + 2);
                pos = target;
            }
            _ => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    /// Builds the answer a server would give to `query`.
    fn answer(query: &[u8], rcode: u16, truncated: bool, addrs: &[IpAddr], ttl: u32) -> Vec<u8> {
        // Question section: from byte 12 to the end of QTYPE and QCLASS.
        let (_, qend) = read_name(query, 12).unwrap();
        let qtype = u16::from_be_bytes([query[qend], query[qend + 1]]);
        let mut r = query[..2].to_vec();
        let flags = 0x8180 | rcode | if truncated { 0x0200 } else { 0 };
        r.extend_from_slice(&flags.to_be_bytes());
        let records: Vec<&IpAddr> =
            addrs.iter().filter(|a| if qtype == TYPE_A { a.is_ipv4() } else { a.is_ipv6() }).collect();
        r.extend_from_slice(&[0, 1]);
        r.extend_from_slice(&((records.len() + 1) as u16).to_be_bytes());
        r.extend_from_slice(&[0, 0, 0, 0]);
        r.extend_from_slice(&query[12..qend + 4]);
        // A CNAME first, as resolvers often answer: name -> "real.test".
        r.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1]);
        r.extend_from_slice(&300u32.to_be_bytes());
        let target = b"\x04real\x04test\x00";
        r.extend_from_slice(&(target.len() as u16).to_be_bytes());
        let cname_at = r.len();
        r.extend_from_slice(target);
        for a in records {
            r.extend_from_slice(&[0xc0, cname_at as u8]);
            r.extend_from_slice(&qtype.to_be_bytes());
            r.extend_from_slice(&[0, 1]);
            r.extend_from_slice(&ttl.to_be_bytes());
            match a {
                IpAddr::V4(v4) => {
                    r.extend_from_slice(&[0, 4]);
                    r.extend_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    r.extend_from_slice(&[0, 16]);
                    r.extend_from_slice(&v6.octets());
                }
            }
        }
        r
    }

    #[test]
    fn query_format() {
        let q = build_query(0xabcd, "www.example.com", TYPE_AAAA);
        let mut expected = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1];
        expected.extend_from_slice(b"\x03www\x07example\x03com\x00\x00\x1c\x00\x01");
        expected.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(q, expected);
    }

    #[test]
    fn responses() {
        let q = build_query(7, "echo.test", TYPE_A);
        let addrs: Vec<IpAddr> = vec!["192.0.2.80".parse().unwrap(), "192.0.2.81".parse().unwrap()];
        let r = parse_response(&answer(&q, 0, false, &addrs, 60), 7, "echo.test", TYPE_A).unwrap();
        assert_eq!(r, Response { truncated: false, rcode: 0, addrs: addrs.clone(), ttl: 60 });

        let r = parse_response(&answer(&q, RCODE_NXDOMAIN, false, &[], 60), 7, "echo.test", TYPE_A).unwrap();
        assert_eq!((r.rcode, r.addrs.len()), (RCODE_NXDOMAIN, 0));
        assert!(parse_response(&answer(&q, 0, true, &[], 60), 7, "echo.test", TYPE_A).unwrap().truncated);

        // Not ours: another ID, another name, another type, or not a response.
        let good = answer(&q, 0, false, &addrs, 60);
        assert!(parse_response(&good, 8, "echo.test", TYPE_A).is_none());
        assert!(parse_response(&good, 7, "other.test", TYPE_A).is_none());
        assert!(parse_response(&good, 7, "echo.test", TYPE_AAAA).is_none());
        assert!(parse_response(&q, 7, "echo.test", TYPE_A).is_none());
        // Cut short anywhere: rejected, never a panic.
        for len in 0..good.len() {
            let _ = parse_response(&good[..len], 7, "echo.test", TYPE_A);
        }
        assert!(parse_response(&good[..good.len() - 1], 7, "echo.test", TYPE_A).is_none());
    }

    /// Mangled answers are rejected or parsed, never a panic.
    #[test]
    fn mangled_responses_never_panic() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xd15ea5e);
        let q = build_query(7, "echo.test", TYPE_A);
        let addrs: Vec<IpAddr> = vec!["192.0.2.80".parse().unwrap()];
        let mut soa = wire_name("ns.test");
        soa.extend_from_slice(&wire_name("hostmaster.test"));
        for value in [1u32, 60, 60, 60, 12] {
            soa.extend_from_slice(&value.to_be_bytes());
        }
        let samples = [
            answer(&q, 0, false, &addrs, 60),
            response_records(
                &[record("wanted.test", TYPE_CNAME, 5, &wire_name("real.test"))],
                &[record("test", TYPE_SOA, 45, &soa)],
                0,
            ),
        ];
        for _ in 0..20_000 {
            let mut msg = samples[rng.random_range(0..samples.len())].clone();
            for _ in 0..rng.random_range(1..6) {
                let i = rng.random_range(0..msg.len());
                match rng.random_range(0..3) {
                    0 => msg[i] = rng.random(),
                    1 => msg.truncate(i.max(1)),
                    _ => msg.insert(i, rng.random()),
                }
            }
            let _ = parse_response(&msg, 7, "echo.test", TYPE_A);
            let _ = parse_response(&msg, 9, "wanted.test", TYPE_A);
            let _ = read_name(&msg, rng.random_range(0..msg.len()));
        }
    }

    #[test]
    fn compression_loops_are_rejected() {
        let mut msg = vec![0u8; 12];
        msg.extend_from_slice(&[0xc0, 12]);
        assert!(read_name(&msg, 12).is_none());
    }

    #[test]
    fn wire_label_boundaries_cannot_impersonate_the_question_or_answer() {
        let mut response = response_records(&[], &[], 0);
        // One label containing a dot is distinct from the two queried labels.
        response.splice(12..25, b"\x0bwanted.test\x00".iter().copied());
        assert!(parse_response(&response, 9, "wanted.test", TYPE_A).is_none());

        let mut forged = b"\x0bwanted.test\x00".to_vec();
        forged.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 99]);
        let response = response_records(&[forged], &[], 0);
        assert!(parse_response(&response, 9, "wanted.test", TYPE_A).unwrap().addrs.is_empty());
    }

    #[test]
    fn binary_labels_are_unambiguous_and_wire_name_limits_are_enforced() {
        let mut msg = vec![0; 12];
        msg.extend_from_slice(b"\x04A.\\\xff\x00");
        assert_eq!(read_name(&msg, 12).unwrap().0, r"a\046\092\255");
        let longest = format!("{}.{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61));
        let mut msg = vec![0; 12];
        msg.extend_from_slice(&wire_name(&longest));
        assert_eq!(read_name(&msg, 12).unwrap().0, longest);
        let mut msg = vec![0; 12];
        msg.extend_from_slice(&wire_name(&format!("{longest}d")));
        assert!(read_name(&msg, 12).is_none(), "256 wire octets exceed the DNS name limit");
        let mut msg = vec![0; 12];
        msg.extend_from_slice(b"\xc0\x0e\x01a\x00");
        assert!(read_name(&msg, 12).is_none(), "compression must refer to a prior occurrence");
    }

    fn wire_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.').filter(|l| !l.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn record(name: &str, rtype: u16, ttl: u32, data: &[u8]) -> Vec<u8> {
        let mut out = wire_name(name);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    fn response_records(records: &[Vec<u8>], authority: &[Vec<u8>], rcode: u16) -> Vec<u8> {
        let q = build_query(9, "wanted.test", TYPE_A);
        let (_, end) = read_name(&q, 12).unwrap();
        let mut out = q[..end + 4].to_vec();
        out[2..4].copy_from_slice(&(0x8180 | rcode).to_be_bytes());
        out[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
        out[8..10].copy_from_slice(&(authority.len() as u16).to_be_bytes());
        out[10..12].copy_from_slice(&0u16.to_be_bytes());
        for r in records.iter().chain(authority) {
            out.extend_from_slice(r);
        }
        out
    }

    #[test]
    fn only_answers_linked_to_the_question_are_used() {
        let unrelated = record("other.test", TYPE_A, 60, &[192, 0, 2, 99]);
        let response = response_records(std::slice::from_ref(&unrelated), &[], 0);
        let parsed = parse_response(&response, 9, "wanted.test", TYPE_A).unwrap();
        assert!(parsed.addrs.is_empty());
        assert_eq!(parsed.ttl, 0);
        let linked = record("real.test", TYPE_A, 120, &[192, 0, 2, 80]);
        let alias = record("wanted.test", TYPE_CNAME, 5, &wire_name("alias.test"));
        let alias2 = record("alias.test", TYPE_CNAME, 10, &wire_name("real.test"));
        // The records need not arrive in CNAME-chain order.
        let response = response_records(&[linked, unrelated, alias2, alias], &[], 0);
        let parsed = parse_response(&response, 9, "wanted.test", TYPE_A).unwrap();
        assert_eq!(parsed.addrs, ["192.0.2.80".parse::<IpAddr>().unwrap()]);
        assert_eq!(parsed.ttl, 5, "the short CNAME must limit the address cache");
    }

    #[test]
    fn cname_cycles_conflicts_and_bad_lengths_are_rejected() {
        let alias = record("wanted.test", TYPE_CNAME, 10, &wire_name("alias.test"));
        let cycle = record("alias.test", TYPE_CNAME, 10, &wire_name("wanted.test"));
        let conflict = record("wanted.test", TYPE_CNAME, 10, &wire_name("different.test"));
        let address = record("wanted.test", TYPE_A, 10, &[192, 0, 2, 80]);
        for other in [cycle, conflict, address] {
            let response = response_records(&[alias.clone(), other], &[], 0);
            assert!(parse_response(&response, 9, "wanted.test", TYPE_A).is_none());
        }
        let mut malformed = wire_name("alias.test");
        malformed.push(0);
        let response = response_records(&[record("wanted.test", TYPE_CNAME, 10, &malformed)], &[], 0);
        assert!(parse_response(&response, 9, "wanted.test", TYPE_A).is_none());
    }

    #[test]
    fn zero_and_invalid_ttls_are_not_extended() {
        for ttl in [0, 1, 9, 0x8000_0001] {
            let response = response_records(&[record("wanted.test", TYPE_A, ttl, &[192, 0, 2, 80])], &[], 0);
            let parsed = parse_response(&response, 9, "wanted.test", TYPE_A).unwrap();
            assert_eq!(parsed.ttl, if ttl & 0x8000_0000 == 0 { ttl } else { 0 });
        }
    }

    #[test]
    fn negative_cache_lifetime_comes_from_the_soa() {
        let mut soa = wire_name("ns.test");
        soa.extend_from_slice(&wire_name("hostmaster.test"));
        for value in [1u32, 60, 60, 60, 12] {
            soa.extend_from_slice(&value.to_be_bytes());
        }
        for rcode in [0, RCODE_NXDOMAIN] {
            let response = response_records(&[], &[], rcode);
            assert_eq!(parse_response(&response, 9, "wanted.test", TYPE_A).unwrap().ttl, 0);
            let response = response_records(&[], &[record("test", TYPE_SOA, 45, &soa)], rcode);
            assert_eq!(parse_response(&response, 9, "wanted.test", TYPE_A).unwrap().ttl, 12);
            let response = response_records(&[], &[record("unrelated.test", TYPE_SOA, 45, &soa)], rcode);
            assert_eq!(parse_response(&response, 9, "wanted.test", TYPE_A).unwrap().ttl, 0);
        }
    }

    #[test]
    fn truncated_partial_records_trigger_tcp_and_never_become_answers() {
        let mut response = response_records(&[record("wanted.test", TYPE_A, 60, &[192, 0, 2, 80])], &[], 0);
        response[2] |= 2; // TC
        for len in response.len() - 4..=response.len() {
            let parsed = parse_response(&response[..len], 9, "wanted.test", TYPE_A).unwrap();
            assert!(parsed.truncated);
            assert!(Answer::from_response(parsed).is_none());
        }
    }

    #[test]
    fn names() {
        assert_eq!(normalize("WWW.Example.COM.").as_deref(), Some("www.example.com"));
        assert_eq!(normalize("_dmarc.example.com").as_deref(), Some("_dmarc.example.com"));
        assert_eq!(normalize("xn--fiqs8s.example").as_deref(), Some("xn--fiqs8s.example"));
        let longest = vec!["a"; 127].join(".");
        assert_eq!(normalize(&longest).map(|n| n.len()), Some(253));
        for bad in [
            "",
            ".",
            "a..b",
            "exa mple.com",
            "-host.test",
            "host-.test",
            "bücher.example",
            &"a".repeat(64),
            &format!("{longest}b"),
        ] {
            assert_eq!(normalize(bad), None, "{bad:?}");
        }
    }

    /// A stack with a DNS server at 10.0.0.2 (UDP and TCP) that knows
    /// "echo.test", truncates answers for "big.test" over UDP, and counts
    /// the queries it gets.
    async fn setup(own: &[&str]) -> (Resolver, Arc<AtomicUsize>, Vec<tokio::task::JoinHandle<()>>) {
        setup_at_port(own, 53).await
    }

    async fn setup_at_port(own: &[&str], port: u16) -> (Resolver, Arc<AtomicUsize>, Vec<tokio::task::JoinHandle<()>>) {
        let client = NetStack::new(0);
        let server = NetStack::new(0);
        client.set_addresses(&own.iter().map(|a| a.parse().unwrap()).collect::<Vec<_>>());
        server.set_addresses(&["10.0.0.2".parse().unwrap(), "fd00::2".parse().unwrap()]);
        let (c_out, c_in_from_s) = (mpsc::channel::<Bytes>(256), mpsc::channel::<Bytes>(256));
        let (s_out, s_in_from_c) = (mpsc::channel::<Bytes>(256), mpsc::channel::<Bytes>(256));
        let (c2, s2) = (client.clone(), server.clone());
        let mut tasks = vec![
            tokio::spawn(async move { c2.run(c_in_from_s.1, c_out.0).await }),
            tokio::spawn(async move { s2.run(s_in_from_c.1, s_out.0).await }),
        ];
        let (mut c_wire, to_s) = (c_out.1, s_in_from_c.0);
        let (mut s_wire, to_c) = (s_out.1, c_in_from_s.0);
        tasks.push(tokio::spawn(async move {
            while let Some(p) = c_wire.recv().await {
                let _ = to_s.send(p).await;
            }
        }));
        tasks.push(tokio::spawn(async move {
            while let Some(p) = s_wire.recv().await {
                let _ = to_c.send(p).await;
            }
        }));
        let known: Vec<IpAddr> = vec!["192.0.2.80".parse().unwrap(), "2001:db8::80".parse().unwrap()];
        let count = Arc::new(AtomicUsize::new(0));
        let respond = move |q: &[u8], udp: bool| {
            let (name, _) = read_name(q, 12).unwrap();
            match name.as_str() {
                "echo.test" => answer(q, 0, false, &known, 120),
                "zero.test" => answer(q, 0, false, &known, 0),
                "alias-zero.test" => {
                    let mut r = answer(q, 0, false, &known, 120);
                    let (_, end) = read_name(q, 12).unwrap();
                    r[end + 10..end + 14].copy_from_slice(&0u32.to_be_bytes());
                    r
                }
                "partial.test" if udp => {
                    let mut r = answer(q, 0, true, &known, 120);
                    r.pop();
                    r
                }
                "partial.test" => answer(q, 0, false, &known, 120),
                "tcp-fails.test" | "tcp-truncated.test" => answer(q, 0, true, &[], 120),
                "big.test" if udp => answer(q, 0, true, &[], 120),
                "big.test" => answer(q, 0, false, &known[..1], 120),
                _ => answer(q, RCODE_NXDOMAIN, false, &[], 120),
            }
        };
        let udp = server.bind_udp(port).unwrap();
        let (r1, n1) = (respond.clone(), count.clone());
        tasks.push(tokio::spawn(async move {
            loop {
                let (q, from) = udp.recv_from().await.unwrap();
                n1.fetch_add(1, Ordering::SeqCst);
                udp.send_to(&r1(&q, true), from).await.unwrap();
            }
        }));
        let mut tcp = server.listen(port, 4).unwrap();
        tasks.push(tokio::spawn(async move {
            loop {
                let mut s = tcp.accept().await.unwrap();
                let len = s.read_u16().await.unwrap();
                let mut q = vec![0; len.into()];
                s.read_exact(&mut q).await.unwrap();
                if read_name(&q, 12).unwrap().0 == "tcp-fails.test" {
                    continue;
                }
                let r = respond(&q, false);
                s.write_all(&(r.len() as u16).to_be_bytes()).await.unwrap();
                s.write_all(&r).await.unwrap();
                s.shutdown().await.unwrap();
            }
        }));
        let servers = vec![
            SocketAddr::new("10.0.0.9".parse().unwrap(), port),
            SocketAddr::new("10.0.0.2".parse().unwrap(), port),
            SocketAddr::new("fd00::2".parse().unwrap(), port),
        ];
        (Resolver::new(client, servers), count, tasks)
    }

    #[tokio::test]
    async fn full_dns_cache_preserves_active_families_and_their_original_expiry() {
        let now = Instant::now();
        let good = Ok(vec!["192.0.2.80".parse::<IpAddr>().unwrap()]);
        let family = ("echo.test".to_owned(), TYPE_A);
        let negative = ("echo.test".to_owned(), TYPE_AAAA);
        let (mut resolver, count, _tasks) = setup(&["10.0.0.1"]).await;
        resolver.servers = vec!["10.0.0.2:53".parse().unwrap()];
        {
            let mut cache = resolver.cache.lock().unwrap();
            cache.insert(family.clone(), good.clone(), now + Duration::from_secs(90), now);
            cache.insert(negative.clone(), Err(LookupError::NotFound), now + Duration::from_secs(2), now);
            for i in 2..CACHE_SIZE {
                cache.insert((format!("cold-{i}.test"), TYPE_A), good.clone(), now + Duration::from_secs(90), now);
            }
            assert_eq!(cache.get(&negative, now), Some(Err(LookupError::NotFound)));
        }
        assert_eq!(resolver.lookup_family("ECHO.test.", false).await, good);
        let _ = resolver.lookup_family("big.test", false).await.unwrap();
        let after_insert = count.load(Ordering::SeqCst);
        assert!(after_insert > 0);
        assert_eq!(resolver.lookup_family("echo.test", false).await, good);
        assert_eq!(count.load(Ordering::SeqCst), after_insert);
        let mut cache = resolver.cache.lock().unwrap();
        assert_eq!(cache.entries.len(), CACHE_SIZE);
        assert_eq!(cache.get(&negative, now + Duration::from_secs(1)), Some(Err(LookupError::NotFound)));
        assert_eq!(cache.get(&negative, now + Duration::from_secs(2)), None);
        assert_eq!(cache.get(&family, now + Duration::from_secs(90)), None);
    }

    #[tokio::test]
    async fn configured_dns_port_is_used_for_udp_and_tcp_fallback() {
        let (mut resolver, count, _tasks) = setup_at_port(&["10.0.0.1"], 5353).await;
        resolver.servers = vec!["10.0.0.2:5353".parse().unwrap()];
        for host in ["echo.test", "big.test"] {
            let result = tokio::time::timeout(Duration::from_secs(3), resolver.lookup(host))
                .await
                .expect("configured DNS port was not reached")
                .unwrap();
            assert_eq!(result, ["192.0.2.80".parse::<IpAddr>().unwrap()]);
        }
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lookups_through_the_stack() {
        let (r, count, _tasks) = setup(&["10.0.0.1", "fd00::1"]).await;
        // 10.0.0.9 never answers, so the first lookup falls through to 10.0.0.2.
        let addrs = r.lookup("Echo.Test.").await.unwrap();
        assert_eq!(addrs, ["2001:db8::80".parse::<IpAddr>().unwrap(), "192.0.2.80".parse().unwrap()]);
        let queries = count.load(Ordering::SeqCst);
        assert_eq!(queries, 2);
        // Cached now.
        assert_eq!(r.lookup("echo.test").await.unwrap().len(), 2);
        assert_eq!(count.load(Ordering::SeqCst), queries);

        assert_eq!(r.lookup("nothing.test").await, Err(LookupError::NotFound));
        assert_eq!(r.lookup("bad name").await, Err(LookupError::InvalidName));
        assert_eq!(r.lookup("192.0.2.1").await.unwrap(), ["192.0.2.1".parse::<IpAddr>().unwrap()]);
        // Truncated over UDP: asked again over TCP.
        assert_eq!(r.lookup("big.test").await.unwrap(), ["192.0.2.80".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_dns_lookups_release_pending_names() {
        use std::future::Future;
        let (mut r, _count, _tasks) = setup(&["10.0.0.1"]).await;
        r.servers = vec!["10.0.0.9:53".parse().unwrap()]; // Never answers.
        for index in 0..64 {
            let name = format!("cancelled-{index}.test");
            let mut lookup = Box::pin(r.lookup_family(&name, false));
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(lookup.as_mut().poll(&mut cx).is_pending());
            assert_eq!(r.pending.lock().unwrap().len(), 1);
            drop(lookup);
            assert!(r.pending.lock().unwrap().is_empty(), "cancelled name {name} retained");
        }
    }

    #[tokio::test]
    async fn tunnel_failure_rejects_cached_and_literal_lookups() {
        let stack = NetStack::new(0);
        stack.set_addresses(&["10.0.0.1".parse().unwrap()]);
        let resolver = Resolver::new(stack.clone(), vec!["10.0.0.2:53".parse().unwrap()]);
        resolver.cache.lock().unwrap().insert(
            ("cached.test".to_owned(), TYPE_A),
            Ok(vec!["192.0.2.80".parse().unwrap()]),
            Instant::now() + Duration::from_secs(120),
            Instant::now(),
        );
        assert!(resolver.lookup("cached.test").await.is_ok());
        assert!(resolver.lookup("192.0.2.80").await.is_ok());
        stack.fail("fixture tunnel failure");
        for name in ["cached.test", "192.0.2.80", "2001:db8::80"] {
            assert_eq!(resolver.lookup(name).await, Err(LookupError::Unavailable));
        }
    }

    #[tokio::test]
    async fn tunnel_failure_wakes_shared_pending_queries_and_releases_names() {
        use std::future::Future;
        let stack = NetStack::new(0);
        stack.set_addresses(&["10.0.0.1".parse().unwrap()]);
        let resolver = Resolver::new(stack.clone(), vec!["10.0.0.9:5353".parse().unwrap()]);
        let mut first = Box::pin(resolver.lookup_family("pending.test", false));
        let mut second = Box::pin(resolver.lookup_family("pending.test", false));
        {
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(first.as_mut().poll(&mut cx).is_pending());
            assert!(second.as_mut().poll(&mut cx).is_pending());
        }
        assert_eq!(resolver.pending.lock().unwrap().len(), 1);
        stack.fail("fixture tunnel failure");
        let results = tokio::time::timeout(Duration::from_millis(100), async { tokio::join!(first, second) })
            .await
            .expect("DNS waiters did not observe tunnel failure promptly");
        assert_eq!(results, (Err(LookupError::Unavailable), Err(LookupError::Unavailable)));
        assert!(resolver.pending.lock().unwrap().is_empty());
        assert!(resolver.cache.lock().unwrap().entries.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_one_waiter_preserves_the_shared_query() {
        use std::future::Future;
        let (mut r, _count, _tasks) = setup(&["10.0.0.1"]).await;
        r.servers = vec!["10.0.0.9:53".parse().unwrap()];
        let key = ("echo.test".to_string(), TYPE_A);
        let mut first = Box::pin(r.lookup_family("echo.test", false));
        let mut second = Box::pin(r.lookup_family("echo.test", false));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(first.as_mut().poll(&mut cx).is_pending());
        assert!(second.as_mut().poll(&mut cx).is_pending());
        // Observe the identity without keeping the cell alive ourselves.
        let flight = Arc::downgrade(r.pending.lock().unwrap().get(&key).unwrap());
        drop(first);
        let mut third = Box::pin(r.lookup_family("echo.test", false));
        assert!(third.as_mut().poll(&mut cx).is_pending());
        assert_eq!(
            Arc::as_ptr(r.pending.lock().unwrap().get(&key).unwrap()),
            flight.as_ptr(),
            "a cancelled waiter split the remaining lookup group"
        );
        drop(second);
        assert_eq!(r.pending.lock().unwrap().len(), 1);
        drop(third);
        assert!(r.pending.lock().unwrap().is_empty());
    }

    // Keep the server tasks on this thread so they cannot answer between
    // the manual polls and cancellation. Once the survivor is awaited,
    // they run normally and exercise the real network lookup and cache.
    #[tokio::test]
    async fn a_waiter_completes_after_the_initial_lookup_is_cancelled() {
        use std::future::Future;
        let (mut r, count, _tasks) = setup(&["10.0.0.1"]).await;
        r.servers = vec!["10.0.0.2:53".parse().unwrap()];
        let mut first = Box::pin(r.lookup_family("echo.test", false));
        let mut second = Box::pin(r.lookup_family("echo.test", false));
        {
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(first.as_mut().poll(&mut cx).is_pending());
            assert!(second.as_mut().poll(&mut cx).is_pending());
        }
        drop(first);
        let result =
            tokio::time::timeout(Duration::from_secs(3), second).await.expect("the surviving waiter stalled").unwrap();
        assert_eq!(result, ["192.0.2.80".parse::<IpAddr>().unwrap()]);
        assert!(r.pending.lock().unwrap().is_empty());
        let queries = count.load(Ordering::SeqCst);
        assert_eq!(r.lookup_family("echo.test", false).await.unwrap(), result);
        assert_eq!(count.load(Ordering::SeqCst), queries);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_lookups_share_one_query() {
        let (mut r, count, _tasks) = setup(&["10.0.0.1"]).await;
        r.servers = vec!["10.0.0.2:53".parse().unwrap()];
        let r = Arc::new(r);
        let lookups: Vec<_> = (0..50)
            .map(|_| {
                let r = r.clone();
                tokio::spawn(async move { r.lookup("echo.test").await })
            })
            .collect();
        for l in lookups {
            assert_eq!(l.await.unwrap().unwrap(), ["192.0.2.80".parse::<IpAddr>().unwrap()]);
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(r.pending.lock().unwrap().is_empty());
    }

    // With TTL zero there is no cache to unite sequential queries. Keep
    // both initial polls on one thread so the test guarantees overlap
    // before the fixture server can complete either lookup.
    #[tokio::test]
    async fn uncacheable_overlapping_lookups_share_only_the_inflight_query() {
        let (mut r, count, _tasks) = setup(&["10.0.0.1"]).await;
        r.servers = vec!["10.0.0.2:53".parse().unwrap()];
        // Uncacheable answers are shared too, but asked again afterwards.
        let (a, b) = tokio::join!(r.lookup("zero.test"), r.lookup("zero.test"));
        assert!(a.is_ok() && b.is_ok());
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(r.lookup("zero.test").await.is_ok());
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn only_families_the_tunnel_carries() {
        let (r, _count, _tasks) = setup(&["10.0.0.1"]).await;
        assert_eq!(r.lookup("echo.test").await.unwrap(), ["192.0.2.80".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn zero_ttl_answers_are_not_cached() {
        let (mut r, count, _tasks) = setup(&["10.0.0.1"]).await;
        r.servers = vec!["10.0.0.2:53".parse().unwrap()];
        for name in ["zero.test", "alias-zero.test"] {
            let before = count.load(Ordering::SeqCst);
            assert!(r.lookup(name).await.is_ok());
            assert!(r.lookup(name).await.is_ok());
            assert_eq!(count.load(Ordering::SeqCst) - before, 2);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn partial_udp_answers_use_tcp_and_failures_are_briefly_cached_as_failures() {
        let (mut r, count, _tasks) = setup(&["10.0.0.1"]).await;
        r.servers = vec!["10.0.0.2:53".parse().unwrap()];
        assert_eq!(r.lookup("partial.test").await.unwrap(), ["192.0.2.80".parse::<IpAddr>().unwrap()]);
        for name in ["tcp-fails.test", "tcp-truncated.test"] {
            let before = count.load(Ordering::SeqCst);
            assert_eq!(r.lookup(name).await, Err(LookupError::NoAnswer));
            assert_eq!(r.lookup(name).await, Err(LookupError::NoAnswer));
            assert_eq!(count.load(Ordering::SeqCst) - before, 2, "RFC 9520 requires a brief failure cache");
            let expires = r.cache.lock().unwrap().entries.get(&(name.into(), TYPE_A)).unwrap().expires;
            assert!(expires <= Instant::now() + Duration::from_secs(1));
            tokio::time::sleep_until(expires + Duration::from_millis(1)).await;
            assert_eq!(r.lookup(name).await, Err(LookupError::NoAnswer));
            assert_eq!(count.load(Ordering::SeqCst) - before, 4, "expired failures must be retried");
        }
    }
}
