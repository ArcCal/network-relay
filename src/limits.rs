//! Admission control and rate limits.
//!
//! Everything a client can trigger before it has authenticated is bounded
//! per source address, so one host cannot use up what every device needs:
//! password verifications (`PerIp`), connections (`Connections`). Once
//! authenticated, a user's tunnels and traffic are bounded per user
//! (`UserTunnels`, `Budget`), so one device or one stolen profile cannot
//! starve the others.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The part of an address that identifies one client: the whole IPv4
/// address, or the /64 prefix of an IPv6 address (one subnet, which a single
/// host can usually spread itself over).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientKey([u8; 16]);

impl ClientKey {
    pub fn of(ip: IpAddr) -> Self {
        match ip.to_canonical() {
            IpAddr::V4(v4) => {
                let mut b = [0u8; 16];
                b[..4].copy_from_slice(&v4.octets());
                b[15] = 4;
                Self(b)
            }
            IpAddr::V6(v6) => {
                let mut b = [0u8; 16];
                b[..8].copy_from_slice(&v6.octets()[..8]);
                b[15] = 6;
                Self(b)
            }
        }
    }
}

/// A token bucket: `rate` tokens per second, at most `burst` saved up.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    /// A full bucket.
    pub fn new(rate: f64, burst: f64) -> Self {
        Self { rate, burst, tokens: burst, last: Instant::now() }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        self.last = now;
    }

    /// Takes `n` tokens if they are there.
    pub fn try_take(&mut self, n: f64, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }

    /// Takes `n` tokens, going into debt if needed, and returns how long the
    /// caller must wait until the debt is paid off.
    pub fn take_with_debt(&mut self, n: f64, now: Instant) -> Duration {
        self.refill(now);
        self.tokens -= n;
        if self.tokens >= 0.0 || self.rate <= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-self.tokens / self.rate)
        }
    }

    /// Whether the bucket is full, so forgetting it changes nothing.
    fn is_full(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.tokens >= self.burst
    }
}

/// One token bucket per client address, for things a client may do before
/// it has authenticated, such as having a password verified.
#[derive(Debug)]
pub struct PerIp {
    rate: f64,
    burst: f64,
    max_clients: usize,
    buckets: Mutex<HashMap<ClientKey, TokenBucket>>,
}

impl PerIp {
    pub fn new(rate: f64, burst: f64, max_clients: usize) -> Self {
        Self { rate, burst, max_clients, buckets: Mutex::default() }
    }

    /// Whether `ip` may do one more. When too many addresses are being
    /// tracked at once (a flood from many addresses), new addresses are
    /// refused until older buckets have filled up again and are forgotten.
    pub fn allow(&self, ip: IpAddr) -> bool {
        let key = ClientKey::of(ip);
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap();
        if !buckets.contains_key(&key) && buckets.len() >= self.max_clients {
            buckets.retain(|_, b| !b.is_full(now));
            if buckets.len() >= self.max_clients {
                return false;
            }
        }
        buckets.entry(key).or_insert_with(|| TokenBucket::new(self.rate, self.burst)).try_take(1.0, now)
    }
}

/// Concurrent connections, in total and per client address.
#[derive(Debug)]
pub struct Connections {
    max_total: usize,
    max_per_client: usize,
    state: Mutex<(usize, HashMap<ClientKey, usize>)>,
}

/// Held for as long as a connection is open.
#[derive(Debug)]
pub struct ConnectionPermit {
    limits: Arc<Connections>,
    key: ClientKey,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let mut state = self.limits.state.lock().unwrap();
        state.0 -= 1;
        if let Some(n) = state.1.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                state.1.remove(&self.key);
            }
        }
    }
}

impl Connections {
    pub fn new(max_total: usize, max_per_client: usize) -> Arc<Self> {
        Arc::new(Self { max_total, max_per_client, state: Mutex::default() })
    }

    /// A permit for a new connection from `ip`, or `None` when the total or
    /// that client's share is used up.
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<ConnectionPermit> {
        let key = ClientKey::of(ip);
        let mut state = self.state.lock().unwrap();
        if state.0 >= self.max_total || state.1.get(&key).copied().unwrap_or(0) >= self.max_per_client {
            return None;
        }
        state.0 += 1;
        *state.1.entry(key).or_insert(0) += 1;
        Some(ConnectionPermit { limits: self.clone(), key })
    }

    /// Connections open now.
    pub fn open(&self) -> usize {
        self.state.lock().unwrap().0
    }
}

/// Concurrent tunnels per user.
#[derive(Debug, Default)]
pub struct UserTunnels {
    counts: Mutex<HashMap<String, usize>>,
}

/// One of a user's tunnel slots, released when dropped.
#[derive(Debug)]
pub struct UserSlot {
    tunnels: Arc<UserTunnels>,
    user: String,
}

impl Drop for UserSlot {
    fn drop(&mut self) {
        let mut counts = self.tunnels.counts.lock().unwrap();
        if let Some(n) = counts.get_mut(&self.user) {
            *n -= 1;
            if *n == 0 {
                counts.remove(&self.user);
            }
        }
    }
}

impl UserTunnels {
    pub fn try_acquire(self: &Arc<Self>, user: &str, max: usize) -> Option<UserSlot> {
        let mut counts = self.counts.lock().unwrap();
        let n = counts.entry(user.to_string()).or_insert(0);
        if *n >= max {
            if *n == 0 {
                counts.remove(user);
            }
            return None;
        }
        *n += 1;
        Some(UserSlot { tunnels: self.clone(), user: user.to_string() })
    }

    pub fn count(&self, user: &str) -> usize {
        self.counts.lock().unwrap().get(user).copied().unwrap_or(0)
    }
}

/// One user's traffic budget, shared by all their tunnels and both
/// directions. It outlives the tunnels, so reconnecting does not renew it.
#[derive(Debug)]
pub struct Budget {
    bytes: Option<Mutex<TokenBucket>>,
    packets: Option<Mutex<TokenBucket>>,
    /// The settings it was made with, to keep it across unchanged reloads.
    pub settings: (u64, u64),
}

/// Burst of the byte budget: two TCP read buffers.
pub const BYTE_BURST: u64 = 128 * 1024;
/// Most saved-up UDP packets.
pub const PACKET_BURST: u64 = 1024;

impl Budget {
    /// `bytes_per_second` and `packets_per_second` of 0 mean unlimited.
    pub fn new(bytes_per_second: u64, packets_per_second: u64) -> Self {
        let bytes = (bytes_per_second > 0).then(|| {
            Mutex::new(TokenBucket::new(bytes_per_second as f64, BYTE_BURST.max(bytes_per_second / 10) as f64))
        });
        let packets = (packets_per_second > 0).then(|| {
            Mutex::new(TokenBucket::new(packets_per_second as f64, packets_per_second.min(PACKET_BURST) as f64))
        });
        Self { bytes, packets, settings: (bytes_per_second, packets_per_second) }
    }

    pub fn is_unlimited(&self) -> bool {
        self.bytes.is_none() && self.packets.is_none()
    }

    /// How long a stream must wait after moving `n` bytes; zero when the
    /// budget allows it now.
    pub fn charge_bytes(&self, n: usize) -> Duration {
        match &self.bytes {
            Some(b) => b.lock().unwrap().take_with_debt(n as f64, Instant::now()),
            None => Duration::ZERO,
        }
    }

    /// Waits until the stream may move on after `n` bytes.
    pub async fn spend_bytes(&self, n: usize) {
        let wait = self.charge_bytes(n);
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }

    /// Whether one UDP packet of `n` bytes fits the budget now; UDP drops
    /// what does not.
    pub fn allow_packet(&self, n: usize) -> bool {
        let now = Instant::now();
        if let Some(p) = &self.packets {
            if !p.lock().unwrap().try_take(1.0, now) {
                return false;
            }
        }
        match &self.bytes {
            Some(b) => b.lock().unwrap().try_take(n as f64, now),
            None => true,
        }
    }
}

/// Total memory of this machine, from /proc/meminfo (Linux).
pub fn total_memory() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = text.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib * 1024)
}

/// Memory planned per tunnel when sizing the default `max_tunnels`: read
/// buffers, flow-control windows in use and kernel socket buffers.
pub const MEMORY_PER_TUNNEL: u64 = 256 * 1024;

/// The default `max_tunnels` for a machine with `memory` bytes: a quarter of
/// the memory at [`MEMORY_PER_TUNNEL`] each, between 512 and 20 000.
pub fn default_max_tunnels(memory: Option<u64>) -> usize {
    match memory {
        Some(m) => ((m / 4 / MEMORY_PER_TUNNEL) as usize).clamp(512, 20_000),
        None => 4096,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_refill_up_to_the_burst() {
        let start = Instant::now();
        let mut b = TokenBucket::new(2.0, 3.0);
        b.last = start;
        assert!(b.try_take(3.0, start));
        assert!(!b.try_take(1.0, start));
        assert!(b.try_take(1.0, start + Duration::from_millis(500)));
        assert!(!b.try_take(1.0, start + Duration::from_millis(500)));
        assert!(b.try_take(3.0, start + Duration::from_secs(60)), "refilled to the burst");
        assert!(!b.try_take(0.5, start + Duration::from_secs(60)), "but not beyond");
    }

    #[test]
    fn debt_is_paid_off_by_waiting() {
        let start = Instant::now();
        let mut b = TokenBucket::new(1000.0, 1000.0);
        b.last = start;
        assert_eq!(b.take_with_debt(1000.0, start), Duration::ZERO);
        let wait = b.take_with_debt(500.0, start);
        assert!((wait.as_secs_f64() - 0.5).abs() < 1e-6, "{wait:?}");
    }

    #[test]
    fn per_ip_limits_each_client_and_ipv6_subnets_share() {
        let limiter = PerIp::new(0.0, 2.0, 100);
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        assert!(limiter.allow(a) && limiter.allow(a));
        assert!(!limiter.allow(a), "a's burst is spent");
        assert!(limiter.allow(b), "b has its own");
        let v6a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let v6b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        assert!(limiter.allow(v6a) && limiter.allow(v6b));
        assert!(!limiter.allow(v6a), "the same /64");
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        assert!(!limiter.allow(mapped), "mapped addresses are their IPv4 address");
    }

    #[test]
    fn per_ip_refuses_new_clients_when_full_of_busy_ones() {
        let limiter = PerIp::new(0.0, 1.0, 2);
        assert!(limiter.allow("192.0.2.1".parse().unwrap()));
        assert!(limiter.allow("192.0.2.2".parse().unwrap()));
        assert!(!limiter.allow("192.0.2.3".parse().unwrap()));
        let idle = PerIp::new(1000.0, 1.0, 1);
        assert!(idle.allow("192.0.2.1".parse().unwrap()));
        std::thread::sleep(Duration::from_millis(5));
        assert!(idle.allow("192.0.2.2".parse().unwrap()), "full buckets are forgotten to make room");
    }

    #[test]
    fn connections_are_limited_in_total_and_per_client() {
        let limits = Connections::new(3, 2);
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        let p1 = limits.try_acquire(a).unwrap();
        let _p2 = limits.try_acquire(a).unwrap();
        assert!(limits.try_acquire(a).is_none(), "per client");
        let _p3 = limits.try_acquire(b).unwrap();
        assert!(limits.try_acquire(b).is_none(), "in total");
        drop(p1);
        assert_eq!(limits.open(), 2);
        assert!(limits.try_acquire(b).is_some());
    }

    #[test]
    fn user_slots_are_released() {
        let tunnels = Arc::new(UserTunnels::default());
        let s1 = tunnels.try_acquire("alice", 2).unwrap();
        let _s2 = tunnels.try_acquire("alice", 2).unwrap();
        assert!(tunnels.try_acquire("alice", 2).is_none());
        assert!(tunnels.try_acquire("bob", 2).is_some());
        drop(s1);
        assert_eq!(tunnels.count("alice"), 1);
        assert!(tunnels.try_acquire("alice", 2).is_some());
        assert!(tunnels.try_acquire("carol", 0).is_none());
        assert_eq!(tunnels.count("carol"), 0);
    }

    #[test]
    fn budgets_limit_packets_and_bytes() {
        let unlimited = Budget::new(0, 0);
        assert!(unlimited.is_unlimited() && unlimited.allow_packet(65_000));
        let packets = Budget::new(0, 2);
        assert!(packets.allow_packet(1) && packets.allow_packet(1));
        assert!(!packets.allow_packet(1));
        let bytes = Budget::new(1000, 0);
        assert!(bytes.allow_packet(BYTE_BURST as usize));
        assert!(!bytes.allow_packet(100));
        assert!(bytes.charge_bytes(1000) > Duration::from_millis(900));
    }

    #[test]
    fn default_tunnels_follow_memory() {
        assert_eq!(default_max_tunnels(Some(1 << 30)), 1024);
        assert_eq!(default_max_tunnels(Some(4 << 30)), 4096);
        assert_eq!(default_max_tunnels(Some(256 << 20)), 512);
        assert_eq!(default_max_tunnels(Some(1 << 40)), 20_000);
        assert_eq!(default_max_tunnels(None), 4096);
    }
}
