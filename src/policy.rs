//! Which destinations clients may reach.
//!
//! A relay that forwards to any address would let its users reach the
//! relay's own host and private network (RFC 9298 §7, RFC 9110 §9.3.6). Every
//! target is therefore resolved here, by the relay, and every address the
//! name resolves to is checked against the blocked list before connecting:
//! checking the name alone would let a DNS answer pointing to 127.0.0.1 or
//! 10.0.0.1 through ("DNS rebinding").

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use http::StatusCode;
use ipnet::IpNet;

use crate::config::Relay;
use crate::egress::Egress;

/// Longest a name lookup may take.
pub const DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// A destination as the client named it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// A DNS name, or an IP address (IPv6 without brackets).
    pub host: String,
    pub port: u16,
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

impl Target {
    /// Parses the authority of a classic CONNECT request, `host:port`, where
    /// the port is required (RFC 9110 §9.3.6) and IPv6 addresses are in
    /// brackets.
    pub fn from_authority(authority: &str) -> Option<Self> {
        let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
            let (host, rest) = rest.split_once(']')?;
            host.parse::<std::net::Ipv6Addr>().ok()?;
            (host, rest.strip_prefix(':')?)
        } else {
            let (host, port) = authority.rsplit_once(':')?;
            if host.contains(':') {
                return None;
            }
            (host, port)
        };
        Self::new(host, port)
    }

    /// Builds a target from the `target_host` and `target_port` variables of
    /// a CONNECT-UDP request, already percent-decoded (RFC 9298 §2): an IPv4
    /// address, an IPv6 address without brackets, or a DNS name.
    pub fn from_template_vars(host: &str, port: &str) -> Option<Self> {
        Self::new(host, port)
    }

    fn new(host: &str, port: &str) -> Option<Self> {
        if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let port: u16 = port.parse().ok().filter(|p| *p != 0)?;
        let host = host.strip_suffix('.').unwrap_or(host);
        if host.parse::<IpAddr>().is_err() && !is_dns_name(host) {
            return None;
        }
        Some(Self { host: host.to_ascii_lowercase(), port })
    }

    /// The address, when the host is an IP address literal.
    pub fn ip(&self) -> Option<IpAddr> {
        self.host.parse().ok()
    }
}

/// A DNS name in the form resolvers accept: labels of letters, digits, `-`
/// and `_`, 1-63 characters each, 253 in total.
fn is_dns_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

/// Why a target is not relayed. Each maps to a status code and a
/// Proxy-Status error type (RFC 9209), which only authenticated clients see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The request does not name a valid host and port.
    BadTarget,
    UserRevoked,
    /// The port is blocked by configuration.
    PortBlocked,
    /// Every address of the target is blocked by configuration.
    AddressBlocked,
    DnsTimeout,
    DnsError(String),
    /// Resolution succeeded but gave no addresses.
    NoAddresses,
    ConnectionRefused,
    ConnectionTimeout,
    Unreachable(String),
    /// The configured maximum number of tunnels is reached.
    TooManyTunnels,
    /// The user's share of tunnels is used up.
    TooManyUserTunnels,
    /// Some other capacity is used up: the relay's memory budget, or the
    /// sockets of the host or an egress. Says which.
    NoCapacity(String),
    /// An extended CONNECT for a protocol the relay does not implement.
    UnsupportedProtocol,
    /// A UDP proxying request that breaks RFC 9298 §3.
    MalformedRequest,
}

impl Refusal {
    /// The status code: the one RFC 9209 §2.3 recommends for the
    /// Proxy-Status error type, where there is one.
    pub fn status(&self) -> StatusCode {
        match self {
            Refusal::BadTarget | Refusal::MalformedRequest => StatusCode::BAD_REQUEST,
            Refusal::PortBlocked | Refusal::UserRevoked => StatusCode::FORBIDDEN,
            Refusal::DnsTimeout | Refusal::ConnectionTimeout => StatusCode::GATEWAY_TIMEOUT,
            Refusal::AddressBlocked
            | Refusal::DnsError(_)
            | Refusal::NoAddresses
            | Refusal::ConnectionRefused
            | Refusal::Unreachable(_) => StatusCode::BAD_GATEWAY,
            Refusal::TooManyTunnels | Refusal::TooManyUserTunnels | Refusal::NoCapacity(_) => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            Refusal::UnsupportedProtocol => StatusCode::NOT_IMPLEMENTED,
        }
    }

    /// Whether a limit or some capacity, not the request or the route,
    /// refused the request: what an operator may need to raise.
    pub fn is_limit(&self) -> bool {
        matches!(self, Refusal::TooManyTunnels | Refusal::TooManyUserTunnels | Refusal::NoCapacity(_))
    }

    /// The Proxy-Status error type (RFC 9209 §2.3), if one fits.
    pub fn error_type(&self) -> Option<&'static str> {
        Some(match self {
            Refusal::BadTarget | Refusal::MalformedRequest => "http_request_error",
            Refusal::UserRevoked | Refusal::PortBlocked => "http_request_denied",
            Refusal::AddressBlocked => "destination_ip_prohibited",
            Refusal::DnsTimeout => "dns_timeout",
            // A name without addresses is a DNS answer, not a gateway's
            // missing configuration (destination_not_found, §2.3.4).
            Refusal::DnsError(_) | Refusal::NoAddresses => "dns_error",
            Refusal::ConnectionRefused => "connection_refused",
            Refusal::ConnectionTimeout => "connection_timeout",
            Refusal::Unreachable(_) => "destination_ip_unroutable",
            Refusal::TooManyTunnels | Refusal::TooManyUserTunnels | Refusal::NoCapacity(_) => {
                "connection_limit_reached"
            }
            // No error type describes it; the 501 does.
            Refusal::UnsupportedProtocol => return None,
        })
    }

    /// The Proxy-Status header value.
    pub fn proxy_status(&self) -> String {
        let mut value = String::from("network-relay");
        if let Some(error) = self.error_type() {
            value.push_str("; error=");
            value.push_str(error);
        }
        match self {
            Refusal::NoAddresses => value.push_str("; details=\"no addresses\""),
            Refusal::UnsupportedProtocol => value.push_str("; details=\"unsupported :protocol\""),
            _ => {}
        }
        value
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::BadTarget => f.write_str("invalid target"),
            Refusal::UserRevoked => f.write_str("user removed or password changed"),
            Refusal::PortBlocked => f.write_str("port blocked by relay.blocked_ports"),
            Refusal::AddressBlocked => f.write_str("address blocked by relay.blocked_destinations"),
            Refusal::DnsTimeout => f.write_str("DNS lookup timed out"),
            Refusal::DnsError(e) => write!(f, "DNS lookup failed: {e}"),
            Refusal::NoAddresses => f.write_str("the name has no addresses"),
            Refusal::ConnectionRefused => f.write_str("connection refused"),
            Refusal::ConnectionTimeout => f.write_str("connection timed out"),
            Refusal::Unreachable(e) => write!(f, "unreachable: {e}"),
            Refusal::TooManyTunnels => f.write_str("relay.max_tunnels reached"),
            Refusal::TooManyUserTunnels => f.write_str("relay.max_tunnels_per_user reached"),
            Refusal::NoCapacity(e) => write!(f, "out of capacity: {e}"),
            Refusal::UnsupportedProtocol => f.write_str("unsupported :protocol"),
            Refusal::MalformedRequest => f.write_str("malformed UDP proxying request"),
        }
    }
}

/// How long the list of this machine's own addresses is reused.
const OWN_ADDRESSES_TTL: Duration = Duration::from_secs(10);

/// The addresses of this machine's network interfaces. A connection to one
/// of them stays on the machine, so it reaches services that only a cloud
/// or host firewall keeps from the internet (RFC 9298 §7).
pub struct OwnAddresses {
    read: fn() -> std::io::Result<Vec<IpAddr>>,
    cache: Mutex<Option<(Instant, Option<Vec<IpAddr>>)>>,
}

impl std::fmt::Debug for OwnAddresses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnAddresses").finish_non_exhaustive()
    }
}

impl OwnAddresses {
    /// The interface addresses of this machine, shared by all policies.
    pub fn system() -> Arc<Self> {
        static SYSTEM: OnceLock<Arc<OwnAddresses>> = OnceLock::new();
        SYSTEM.get_or_init(|| Arc::new(Self::with_reader(interface_addresses))).clone()
    }

    fn with_reader(read: fn() -> std::io::Result<Vec<IpAddr>>) -> Self {
        Self { read, cache: Mutex::new(None) }
    }

    /// The current list, read again at most every ten seconds so new
    /// addresses are noticed. Read failures are cached too and fail closed:
    /// an old list could miss a newly added local interface.
    fn get(&self) -> Option<Vec<IpAddr>> {
        let mut cache = self.cache.lock().unwrap();
        if let Some((at, list)) = cache.as_ref() {
            if at.elapsed() < OWN_ADDRESSES_TTL {
                return list.clone();
            }
        }
        match (self.read)() {
            Ok(list) => {
                let list: Vec<IpAddr> = list.into_iter().map(|ip| ip.to_canonical()).collect();
                *cache = Some((Instant::now(), Some(list.clone())));
                Some(list)
            }
            Err(e) => {
                tracing::warn!("reading this machine's addresses: {e}");
                *cache = Some((Instant::now(), None));
                None
            }
        }
    }
}

fn interface_addresses() -> std::io::Result<Vec<IpAddr>> {
    let mut out = Vec::new();
    for ifa in nix::ifaddrs::getifaddrs().map_err(std::io::Error::from)? {
        let Some(addr) = ifa.address else { continue };
        if let Some(v4) = addr.as_sockaddr_in() {
            out.push(IpAddr::V4(v4.ip()));
        } else if let Some(v6) = addr.as_sockaddr_in6() {
            out.push(IpAddr::V6(v6.ip()));
        }
    }
    Ok(out)
}

/// IPv4 addresses carried inside an IPv6 address that the network
/// translates or tunnels to that IPv4 address: the NAT64 well-known prefix
/// (RFC 6052), 6to4 (RFC 3056), Teredo server and client (RFC 4380), and
/// deprecated IPv4-compatible addresses (RFC 4291 §2.5.5.1).
pub fn embedded_ipv4(ip: Ipv6Addr) -> Vec<Ipv4Addr> {
    let o = ip.octets();
    let v4 = |b: &[u8]| Ipv4Addr::new(b[0], b[1], b[2], b[3]);
    match (o[0], o[1], o[2], o[3]) {
        (0x00, 0x64, 0xff, 0x9b) if o[4..12] == [0; 8] => vec![v4(&o[12..16])],
        (0x20, 0x02, _, _) => vec![v4(&o[2..6])],
        (0x20, 0x01, 0x00, 0x00) => {
            let client: Vec<u8> = o[12..16].iter().map(|b| !b).collect();
            vec![v4(&o[4..8]), v4(&client)]
        }
        _ if o[..12] == [0; 12] => vec![v4(&o[12..16])],
        _ => Vec::new(),
    }
}

/// The destination rules from the configuration.
#[derive(Debug, Clone)]
pub struct Policy {
    blocked: Vec<IpNet>,
    blocked_ports: Vec<u16>,
    own: Option<Arc<OwnAddresses>>,
}

impl Policy {
    pub fn new(relay: &Relay) -> Self {
        Self {
            blocked: relay.blocked_destinations.clone(),
            blocked_ports: relay.blocked_ports.clone(),
            own: relay.block_own_addresses.then(OwnAddresses::system),
        }
    }

    /// Whether clients may reach `ip`. IPv4-mapped IPv6 addresses are checked
    /// as the IPv4 addresses they are, and IPv6 addresses that carry an IPv4
    /// address (NAT64, 6to4, Teredo) also by that address. The machine's own
    /// addresses are refused too; if they cannot be read at all, everything
    /// is refused rather than risk reaching the machine itself.
    pub fn allows_ip(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        let mut candidates = vec![ip];
        if let IpAddr::V6(v6) = ip {
            candidates.extend(embedded_ipv4(v6).into_iter().map(IpAddr::V4));
        }
        if candidates.iter().any(|c| self.blocked.iter().any(|net| net.contains(c))) {
            return false;
        }
        match &self.own {
            None => true,
            Some(own) => own.get().is_some_and(|list| !candidates.iter().any(|c| list.contains(c))),
        }
    }

    /// Whether clients may reach `addr`: its port and its address.
    pub fn allows(&self, addr: SocketAddr) -> bool {
        !self.blocked_ports.contains(&addr.port()) && self.allows_ip(addr.ip())
    }

    /// Resolves `target` and returns the addresses clients may reach, in
    /// the resolver's order of preference (RFC 6724).
    ///
    /// A name lookup first waits for `permit`, a share of the lookups that
    /// may run at once, and holds it until the system resolver returns, even
    /// after [`DNS_TIMEOUT`] has given up on it: the resolver cannot be
    /// cancelled, so abandoned lookups still occupy a thread.
    ///
    /// With an `egress`, the egress looks the name up instead, within the
    /// same [`DNS_TIMEOUT`] and holding the permit only while it does; its
    /// answers are checked the same way.
    pub async fn resolve<P: Send + 'static>(
        &self,
        target: &Target,
        egress: Option<&dyn Egress>,
        permit: impl std::future::Future<Output = P>,
    ) -> Result<Vec<SocketAddr>, Refusal> {
        let unavailable = || Refusal::Unreachable("egress unavailable".into());
        if egress.is_some_and(|e| !e.available()) {
            return Err(unavailable());
        }
        if self.blocked_ports.contains(&target.port) {
            return Err(Refusal::PortBlocked);
        }
        let addrs: Vec<SocketAddr> = match (target.ip(), egress) {
            (Some(ip), _) => vec![SocketAddr::new(ip, target.port)],
            (None, Some(egress)) => {
                let deadline = tokio::time::Instant::now() + DNS_TIMEOUT;
                let lookup = async {
                    let _held = permit.await;
                    if !egress.available() {
                        return Err(unavailable());
                    }
                    let found = egress.resolve_until(&target.host, deadline).await;
                    if !egress.available() {
                        return Err(unavailable());
                    }
                    found.map_err(|e| match e.kind() {
                        std::io::ErrorKind::TimedOut => Refusal::DnsTimeout,
                        _ => Refusal::DnsError(e.to_string()),
                    })
                };
                match tokio::time::timeout_at(deadline, lookup).await {
                    Err(_) => return Err(Refusal::DnsTimeout),
                    Ok(found) => found?.into_iter().map(|ip| SocketAddr::new(ip, target.port)).collect(),
                }
            }
            (None, None) => {
                let deadline = tokio::time::Instant::now() + DNS_TIMEOUT;
                let held = tokio::time::timeout_at(deadline, permit).await.map_err(|_| Refusal::DnsTimeout)?;
                let (host, port) = (target.host.clone(), target.port);
                let lookup = tokio::task::spawn_blocking(move || {
                    let _held = held;
                    std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), port)).map(Iterator::collect::<Vec<_>>)
                });
                match tokio::time::timeout_at(deadline, lookup).await {
                    Err(_) => return Err(Refusal::DnsTimeout),
                    Ok(Err(e)) => return Err(Refusal::DnsError(e.to_string())),
                    Ok(Ok(Err(e))) => return Err(Refusal::DnsError(e.to_string())),
                    Ok(Ok(Ok(found))) => found,
                }
            }
        };
        if addrs.is_empty() {
            return Err(Refusal::NoAddresses);
        }
        let mut allowed: Vec<SocketAddr> = Vec::with_capacity(addrs.len());
        for a in addrs {
            let a = SocketAddr::new(a.ip().to_canonical(), a.port());
            if self.allows_ip(a.ip()) && !allowed.contains(&a) {
                allowed.push(a);
            }
        }
        if allowed.is_empty() {
            return Err(Refusal::AddressBlocked);
        }
        if egress.is_some_and(|e| !e.available()) {
            return Err(unavailable());
        }
        Ok(allowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(host: &str, port: u16) -> Target {
        Target { host: host.into(), port }
    }

    #[test]
    fn authorities_are_parsed() {
        assert_eq!(Target::from_authority("example.com:443"), Some(t("example.com", 443)));
        assert_eq!(Target::from_authority("Example.COM.:80"), Some(t("example.com", 80)));
        assert_eq!(Target::from_authority("192.0.2.1:8443"), Some(t("192.0.2.1", 8443)));
        assert_eq!(Target::from_authority("[2001:db8::1]:443"), Some(t("2001:db8::1", 443)));
        assert_eq!(Target::from_authority("_srv.example.com:5060"), Some(t("_srv.example.com", 5060)));
        for bad in [
            "example.com",
            "example.com:",
            "example.com:0",
            "example.com:65536",
            "example.com:+443",
            "example.com:44a",
            "2001:db8::1:443",
            "[2001:db8::1]",
            "[example.com]:443",
            "[2001:db8::1]443",
            ":443",
            "exa mple.com:443",
            "-bad.example:443",
            "a..b:443",
            "user@example.com:443",
        ] {
            assert_eq!(Target::from_authority(bad), None, "{bad}");
        }
        assert_eq!(t("2001:db8::1", 443).to_string(), "[2001:db8::1]:443");
        assert_eq!(t("example.com", 443).to_string(), "example.com:443");
    }

    #[test]
    fn template_variables_are_parsed() {
        assert_eq!(Target::from_template_vars("2001:db8::42", "53"), Some(t("2001:db8::42", 53)));
        assert_eq!(Target::from_template_vars("192.0.2.6", "443"), Some(t("192.0.2.6", 443)));
        assert_eq!(Target::from_template_vars("dns.example", "53"), Some(t("dns.example", 53)));
        assert_eq!(Target::from_template_vars("[2001:db8::42]", "53"), None, "no brackets in target_host");
        assert_eq!(Target::from_template_vars("", "53"), None);
        assert_eq!(Target::from_template_vars("a.example", ""), None);
        assert_eq!(Target::from_template_vars("fe80::1%eth0", "53"), None, "no zone identifiers");
    }

    fn policy(blocked: &[&str], ports: &[u16]) -> Policy {
        Policy {
            blocked: blocked.iter().map(|s| s.parse().unwrap()).collect(),
            blocked_ports: ports.to_vec(),
            own: None,
        }
    }

    #[test]
    fn embedded_ipv4_addresses_are_checked_as_ipv4() {
        let p = policy(&["10.0.0.0/8", "127.0.0.0/8", "192.0.2.0/24"], &[]);
        assert_eq!(embedded_ipv4("64:ff9b::a00:1".parse().unwrap()), ["10.0.0.1".parse::<Ipv4Addr>().unwrap()]);
        for blocked in [
            "64:ff9b::a00:1",  // NAT64 to 10.0.0.1
            "64:ff9b::7f00:1", // NAT64 to 127.0.0.1
            "2002:a00:1::1",   // 6to4 of 10.0.0.1
            "::a00:1",         // IPv4-compatible 10.0.0.1
            // RFC 4380 example: server 65.54.227.120, client 192.0.2.45.
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        ] {
            assert!(!p.allows_ip(blocked.parse().unwrap()), "{blocked}");
        }
        for allowed in ["64:ff9b::808:808", "2002:808:808::1", "2606:4700:4700::1111", "2001:db8::1"] {
            assert!(p.allows_ip(allowed.parse().unwrap()), "{allowed}");
        }
    }

    #[test]
    fn own_addresses_are_refused_and_unreadable_ones_fail_closed() {
        fn ours() -> std::io::Result<Vec<IpAddr>> {
            Ok(vec!["203.0.113.5".parse().unwrap(), "2001:db8:5::1".parse().unwrap()])
        }
        fn broken() -> std::io::Result<Vec<IpAddr>> {
            Err(std::io::Error::other("no"))
        }
        let mut p = policy(&[], &[]);
        p.own = Some(Arc::new(OwnAddresses::with_reader(ours)));
        assert!(!p.allows_ip("203.0.113.5".parse().unwrap()));
        assert!(!p.allows_ip("::ffff:203.0.113.5".parse().unwrap()));
        assert!(!p.allows_ip("64:ff9b::cb00:7105".parse().unwrap()), "NAT64 of our own address");
        assert!(!p.allows_ip("2001:db8:5::1".parse().unwrap()));
        assert!(p.allows_ip("203.0.113.6".parse().unwrap()));
        p.own = Some(Arc::new(OwnAddresses::with_reader(broken)));
        assert!(!p.allows_ip("1.1.1.1".parse().unwrap()), "fail closed");
        // The real interfaces of this machine include loopback.
        let system = OwnAddresses::system().get().unwrap();
        assert!(system.iter().any(|ip| ip.is_loopback()), "{system:?}");
    }

    #[test]
    fn a_failed_interface_refresh_does_not_trust_old_addresses_or_retry_every_request() {
        static READS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        fn broken() -> std::io::Result<Vec<IpAddr>> {
            READS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Err(std::io::Error::other("interface refresh failed"))
        }
        let own = OwnAddresses::with_reader(broken);
        *own.cache.lock().unwrap() =
            Some((Instant::now() - OWN_ADDRESSES_TTL, Some(vec!["203.0.113.5".parse().unwrap()])));
        assert!(own.get().is_none());
        assert!(own.get().is_none());
        assert_eq!(READS.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn default_list_covers_special_purpose_ranges() {
        let p = Policy::new(&Relay { block_own_addresses: false, ..Relay::default() });
        for blocked in ["192.88.99.1", "3fff::1", "5f00::1", "2001:2::1", "2001:10::1", "2001:20::1", "255.255.255.255"]
        {
            assert!(!p.allows_ip(blocked.parse().unwrap()), "{blocked}");
        }
    }

    #[test]
    fn blocked_addresses_include_mapped_ones() {
        let p = Policy::new(&Relay { block_own_addresses: false, ..Relay::default() });
        for blocked in ["127.0.0.1", "10.1.2.3", "::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "fd00::1", "fe80::1"] {
            assert!(!p.allows_ip(blocked.parse().unwrap()), "{blocked}");
        }
        for allowed in ["1.1.1.1", "2606:4700:4700::1111", "::ffff:1.1.1.1"] {
            assert!(p.allows_ip(allowed.parse().unwrap()), "{allowed}");
        }
        // Even with the mapped range unblocked, the IPv4 rule applies.
        assert!(!policy(&["127.0.0.0/8"], &[]).allows_ip("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn resolution_applies_the_rules() {
        let p = policy(&["127.0.0.0/8", "::1/128"], &[25]);
        assert_eq!(p.resolve(&t("192.0.2.1", 25), None, async {}).await, Err(Refusal::PortBlocked));
        assert_eq!(p.resolve(&t("127.0.0.1", 80), None, async {}).await, Err(Refusal::AddressBlocked));
        assert_eq!(
            p.resolve(&t("localhost", 80), None, async {}).await.unwrap_err(),
            Refusal::AddressBlocked,
            "rebinding"
        );
        assert_eq!(p.resolve(&t("192.0.2.1", 80), None, async {}).await, Ok(vec!["192.0.2.1:80".parse().unwrap()]));
        assert_eq!(
            p.resolve(&t("::ffff:192.0.2.1", 80), None, async {}).await,
            Ok(vec!["192.0.2.1:80".parse().unwrap()]),
            "mapped addresses are connected to as IPv4"
        );
        let open = policy(&[], &[]);
        let local = open.resolve(&t("localhost", 80), None, async {}).await.unwrap();
        assert!(local.iter().all(|a| a.ip().is_loopback() && a.port() == 80), "{local:?}");
        let e = open.resolve(&t("does-not-exist.invalid", 80), None, async {}).await.unwrap_err();
        assert!(matches!(e, Refusal::DnsError(_) | Refusal::DnsTimeout | Refusal::NoAddresses), "{e:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn name_lookups_wait_for_a_permit_within_the_dns_timeout() {
        let p = policy(&[], &[]);
        let literal = p.resolve(&t("192.0.2.1", 80), None, std::future::pending::<()>()).await;
        assert_eq!(literal, Ok(vec!["192.0.2.1:80".parse().unwrap()]), "an address needs no lookup");
        let name = p.resolve(&t("example.com", 80), None, std::future::pending::<()>()).await;
        assert_eq!(name, Err(Refusal::DnsTimeout), "no permit, no lookup");
    }

    #[test]
    fn refusals_map_to_rfc9209() {
        assert_eq!(Refusal::AddressBlocked.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(Refusal::AddressBlocked.proxy_status(), "network-relay; error=destination_ip_prohibited");
        assert_eq!(Refusal::DnsTimeout.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(Refusal::ConnectionRefused.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(Refusal::TooManyTunnels.status(), StatusCode::SERVICE_UNAVAILABLE);
        let full = Refusal::NoCapacity("the user-space socket limit was reached".into());
        assert_eq!(full.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(full.proxy_status(), "network-relay; error=connection_limit_reached");
        assert_eq!(full.to_string(), "out of capacity: the user-space socket limit was reached");
        assert_ne!(full.to_string(), Refusal::TooManyTunnels.to_string(), "an egress limit is not relay.max_tunnels");
        assert!(full.is_limit() && Refusal::TooManyTunnels.is_limit() && Refusal::TooManyUserTunnels.is_limit());
        assert!(!Refusal::ConnectionRefused.is_limit() && !Refusal::PortBlocked.is_limit());
        assert_eq!(Refusal::NoAddresses.proxy_status(), "network-relay; error=dns_error; details=\"no addresses\"");
        assert_eq!(Refusal::Unreachable("x".into()).proxy_status(), "network-relay; error=destination_ip_unroutable");
        assert_eq!(Refusal::UnsupportedProtocol.status(), StatusCode::NOT_IMPLEMENTED);
        assert_eq!(Refusal::UnsupportedProtocol.proxy_status(), "network-relay; details=\"unsupported :protocol\"");
        assert_eq!(Refusal::PortBlocked.status(), StatusCode::FORBIDDEN);
    }

    /// A controlled egress resolver; it never uses the system resolver or
    /// opens sockets.
    mod egress_dns {
        use super::*;
        use crate::egress::{IoFuture, TcpStream, UdpSocket};
        use std::collections::HashMap;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        enum Reply {
            Answers(Vec<IpAddr>),
            Error(std::io::ErrorKind),
            Pending,
        }

        struct TestEgress {
            replies: HashMap<&'static str, Reply>,
            calls: Mutex<Vec<String>>,
            deadlines: Mutex<Vec<tokio::time::Instant>>,
            available: AtomicBool,
            active: AtomicUsize,
            started: tokio::sync::Notify,
        }

        impl TestEgress {
            fn new() -> Self {
                Self {
                    replies: HashMap::new(),
                    calls: Mutex::default(),
                    deadlines: Mutex::default(),
                    available: AtomicBool::new(true),
                    active: AtomicUsize::new(0),
                    started: tokio::sync::Notify::new(),
                }
            }

            fn answering(mut self, host: &'static str, addresses: &[&str]) -> Self {
                self.replies.insert(host, Reply::Answers(addresses.iter().map(|ip| ip.parse().unwrap()).collect()));
                self
            }

            fn failing(mut self, host: &'static str, kind: std::io::ErrorKind) -> Self {
                self.replies.insert(host, Reply::Error(kind));
                self
            }

            fn pending(mut self, host: &'static str) -> Self {
                self.replies.insert(host, Reply::Pending);
                self
            }

            fn calls(&self) -> Vec<String> {
                self.calls.lock().unwrap().clone()
            }
        }

        struct Active<'a>(&'a AtomicUsize);

        impl Drop for Active<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::Relaxed);
            }
        }

        impl Egress for TestEgress {
            fn resolve_until<'a>(&'a self, host: &'a str, deadline: tokio::time::Instant) -> IoFuture<'a, Vec<IpAddr>> {
                self.deadlines.lock().unwrap().push(deadline);
                self.resolve(host)
            }

            fn resolve<'a>(&'a self, host: &'a str) -> IoFuture<'a, Vec<IpAddr>> {
                Box::pin(async move {
                    self.calls.lock().unwrap().push(host.into());
                    self.active.fetch_add(1, Ordering::Relaxed);
                    let _active = Active(&self.active);
                    self.started.notify_one();
                    match self.replies.get(host) {
                        Some(Reply::Answers(found)) => Ok(found.clone()),
                        Some(Reply::Error(kind)) => Err(std::io::Error::new(*kind, "test resolver error")),
                        Some(Reply::Pending) => std::future::pending().await,
                        None => Err(std::io::Error::new(std::io::ErrorKind::NotFound, "unknown test name")),
                    }
                })
            }

            fn connect_tcp(&self, _: SocketAddr) -> IoFuture<'_, TcpStream> {
                panic!("resolution must not open TCP connections")
            }

            fn connect_udp(&self, _: SocketAddr) -> IoFuture<'_, UdpSocket> {
                panic!("resolution must not open UDP flows")
            }

            fn available(&self) -> bool {
                self.available.load(Ordering::Acquire)
            }

            fn failed(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
                Box::pin(std::future::pending())
            }
        }

        #[tokio::test]
        async fn egress_resolution_applies_the_rules() {
            let p = policy(&["127.0.0.0/8", "::1/128"], &[25]);
            let egress = TestEgress::new()
                .answering("localhost", &["127.0.0.1", "::1"])
                .failing("does-not-exist.invalid", std::io::ErrorKind::NotFound);
            let e = Some(&egress as &dyn Egress);
            assert_eq!(p.resolve(&t("192.0.2.1", 25), e, async {}).await, Err(Refusal::PortBlocked));
            assert_eq!(p.resolve(&t("smtp.example", 25), e, async {}).await, Err(Refusal::PortBlocked));
            assert_eq!(p.resolve(&t("127.0.0.1", 80), e, async {}).await, Err(Refusal::AddressBlocked));
            assert_eq!(p.resolve(&t("192.0.2.1", 80), e, async {}).await, Ok(vec!["192.0.2.1:80".parse().unwrap()]));
            assert!(egress.calls().is_empty(), "addresses and blocked ports need no lookup");
            assert_eq!(p.resolve(&t("localhost", 80), e, async {}).await, Err(Refusal::AddressBlocked), "rebinding");
            assert_eq!(egress.calls(), ["localhost"]);
            let open = policy(&[], &[]);
            let local = open.resolve(&t("localhost", 80), e, async {}).await.unwrap();
            assert!(local.iter().all(|a| a.ip().is_loopback() && a.port() == 80), "{local:?}");
            let error = open.resolve(&t("does-not-exist.invalid", 80), e, async {}).await.unwrap_err();
            assert!(matches!(error, Refusal::DnsError(_)), "{error:?}");
            // An egress whose lookup timed out reports dns_timeout (RFC 9209
            // section 2.3.2), as the system resolver's timeout does.
            let slow = TestEgress::new().failing("slow.example", std::io::ErrorKind::TimedOut);
            assert_eq!(open.resolve(&t("slow.example", 80), Some(&slow), async {}).await, Err(Refusal::DnsTimeout));
        }

        #[tokio::test]
        async fn egress_answers_are_filtered_canonicalized_and_deduplicated_in_order() {
            fn ours() -> std::io::Result<Vec<IpAddr>> {
                Ok(vec!["203.0.113.5".parse().unwrap()])
            }
            let mut p = policy(&["127.0.0.0/8", "10.0.0.0/8"], &[]);
            p.own = Some(Arc::new(OwnAddresses::with_reader(ours)));
            let egress = TestEgress::new().answering(
                "mixed.example",
                &[
                    "127.0.0.1",
                    "::ffff:127.0.0.1",
                    "64:ff9b::a00:1",
                    "203.0.113.5",
                    "::ffff:203.0.113.5",
                    "64:ff9b::cb00:7105",
                    "192.0.2.1",
                    "::ffff:192.0.2.1",
                    "2001:db8::1",
                    "192.0.2.1",
                ],
            );
            assert_eq!(
                p.resolve(&t("mixed.example", 443), Some(&egress), async {}).await,
                Ok(vec!["192.0.2.1:443".parse().unwrap(), "[2001:db8::1]:443".parse().unwrap()])
            );
            let empty = TestEgress::new().answering("empty.example", &[]);
            assert_eq!(p.resolve(&t("empty.example", 80), Some(&empty), async {}).await, Err(Refusal::NoAddresses));
        }

        #[tokio::test(start_paused = true)]
        async fn an_unavailable_egress_refuses_at_once_without_lookups() {
            let p = policy(&[], &[]);
            let egress = TestEgress::new();
            egress.available.store(false, Ordering::Release);
            let start = tokio::time::Instant::now();
            for host in ["192.0.2.1", "example.com"] {
                assert_eq!(
                    p.resolve(&t(host, 80), Some(&egress), std::future::pending::<()>()).await,
                    Err(Refusal::Unreachable("egress unavailable".into()))
                );
            }
            assert_eq!(start.elapsed(), Duration::ZERO);
            assert!(egress.calls().is_empty());
            // Lost while waiting for a permit: no lookup starts.
            let egress = TestEgress::new().pending("example.com");
            let permit = async { egress.available.store(false, Ordering::Release) };
            assert_eq!(
                p.resolve(&t("example.com", 80), Some(&egress), permit).await,
                Err(Refusal::Unreachable("egress unavailable".into()))
            );
            assert!(egress.calls().is_empty());
        }

        #[tokio::test(start_paused = true)]
        async fn the_permit_and_the_lookup_share_one_deadline_and_release_the_permit() {
            let p = policy(&[], &[]);
            let egress = TestEgress::new().pending("slow.example");
            let start = tokio::time::Instant::now();
            let none = p.resolve(&t("slow.example", 80), Some(&egress), std::future::pending::<()>()).await;
            assert_eq!(none, Err(Refusal::DnsTimeout), "no permit, no lookup");
            assert_eq!(start.elapsed(), DNS_TIMEOUT);
            assert!(egress.calls().is_empty());
            assert!(egress.deadlines.lock().unwrap().is_empty());
            let permits = Arc::new(tokio::sync::Semaphore::new(1));
            let permit = async {
                tokio::time::sleep(Duration::from_secs(4)).await;
                permits.clone().acquire_owned().await.unwrap()
            };
            let start = tokio::time::Instant::now();
            assert_eq!(p.resolve(&t("slow.example", 80), Some(&egress), permit).await, Err(Refusal::DnsTimeout));
            assert_eq!(start.elapsed(), DNS_TIMEOUT);
            assert_eq!(egress.calls(), ["slow.example"]);
            assert_eq!(*egress.deadlines.lock().unwrap(), [start + DNS_TIMEOUT]);
            assert_eq!(egress.active.load(Ordering::Relaxed), 0, "the abandoned lookup was dropped");
            assert_eq!(permits.available_permits(), 1, "and its permit released");
        }

        #[tokio::test]
        async fn cancelling_a_lookup_drops_it_and_releases_its_permit() {
            let p = Arc::new(policy(&[], &[]));
            let egress = Arc::new(TestEgress::new().pending("cancel.example"));
            let permits = Arc::new(tokio::sync::Semaphore::new(1));
            let lookup = tokio::spawn({
                let (p, egress, permits) = (p.clone(), egress.clone(), permits.clone());
                async move { p.resolve(&t("cancel.example", 80), Some(egress.as_ref()), permits.acquire_owned()).await }
            });
            tokio::time::timeout(Duration::from_secs(1), egress.started.notified()).await.unwrap();
            assert_eq!(egress.active.load(Ordering::Relaxed), 1);
            assert_eq!(permits.available_permits(), 0);
            lookup.abort();
            assert!(lookup.await.unwrap_err().is_cancelled());
            assert_eq!(egress.active.load(Ordering::Relaxed), 0);
            assert_eq!(permits.available_permits(), 1);
        }
    }
}
