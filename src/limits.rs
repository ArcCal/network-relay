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
use std::sync::atomic::{AtomicU64, Ordering};
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
///
/// Admission is by count only. A connection reserves its transport memory
/// from the [`MemoryBudget`] when it first opens a tunnel, not when it is
/// accepted: anyone can open connections, so a reservation taken before
/// authentication would let idle (or, for QUIC, spoofed) connections use up
/// the capacity that devices need.
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

/// At most `max` operations at once per key (a user name); more wait their
/// turn. Keys with nothing under way take no memory.
pub struct KeyedLimit {
    max: usize,
    keys: Mutex<HashMap<String, Arc<tokio::sync::Semaphore>>>,
}

/// One operation counted against its key until dropped.
pub struct KeyedPermit {
    limit: Arc<KeyedLimit>,
    key: String,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl KeyedLimit {
    pub fn new(max: usize) -> Arc<Self> {
        Arc::new(Self { max, keys: Mutex::default() })
    }

    pub async fn acquire(self: &Arc<Self>, key: &str) -> KeyedPermit {
        let semaphore = {
            let mut keys = self.keys.lock().unwrap();
            keys.entry(key.to_string()).or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(self.max))).clone()
        };
        // Construct cleanup before waiting. The acquire future drops its
        // semaphore reference first on cancellation, then this guard removes
        // a key whose last operation was that cancelled waiter.
        let mut held = KeyedPermit { limit: self.clone(), key: key.to_string(), permit: None };
        held.permit = Some(semaphore.acquire_owned().await.expect("never closed"));
        held
    }

    #[cfg(test)]
    fn keys(&self) -> usize {
        self.keys.lock().unwrap().len()
    }
}

impl Drop for KeyedPermit {
    fn drop(&mut self) {
        self.permit = None;
        let mut keys = self.limit.keys.lock().unwrap();
        // Only the map still holds it: nobody runs or waits under this key.
        if keys.get(&self.key).is_some_and(|s| Arc::strong_count(s) == 1) {
            keys.remove(&self.key);
        }
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

/// Memory available to this process: the host and every finite cgroup
/// ancestor limit. Containers must never be sized from host memory alone.
pub fn total_memory() -> Option<u64> {
    let host = std::fs::read_to_string("/proc/meminfo").ok().and_then(|text| {
        text.lines()
            .find(|l| l.starts_with("MemTotal:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|kib| kib.parse::<u64>().ok())
            .and_then(|kib| kib.checked_mul(1024))
    });
    let mut smallest = host;
    let mounts = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    let groups = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    for line in groups.lines() {
        let fields: Vec<_> = line.splitn(3, ':').collect();
        if fields.len() != 3 {
            continue;
        }
        let (root, file, fs_type) = if fields[1].is_empty() {
            ("/sys/fs/cgroup", "memory.max", "cgroup2")
        } else if fields[1].split(',').any(|v| v == "memory") {
            ("/sys/fs/cgroup/memory", "memory.limit_in_bytes", "cgroup")
        } else {
            continue;
        };
        let root = std::path::Path::new(root);
        smallest = cgroup_memory(smallest, root, fields[2], file);
        // Controller mounts need not use the conventional path, and may
        // expose only a subtree. Translate the hierarchy root to the mount.
        for (mount_root, mountpoint) in memory_mounts(&mounts, fs_type) {
            let group = std::path::Path::new(fields[2]);
            let relative = group.strip_prefix(&mount_root).unwrap_or(std::path::Path::new(""));
            smallest = cgroup_memory(smallest, &mountpoint, &relative.to_string_lossy(), file);
        }
    }
    smallest
}

fn memory_mounts(mountinfo: &str, fs_type: &str) -> Vec<(std::path::PathBuf, std::path::PathBuf)> {
    fn unescape(s: &str) -> String {
        s.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\")
    }
    mountinfo
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            let separator = fields.iter().position(|field| *field == "-")?;
            if separator < 6 || fields.get(separator + 1)? != &fs_type {
                return None;
            }
            if fs_type == "cgroup" && !fields.get(separator + 3)?.split(',').any(|option| option == "memory") {
                return None;
            }
            Some((unescape(fields[3]).into(), unescape(fields[4]).into()))
        })
        .collect()
}

fn cgroup_memory(mut smallest: Option<u64>, root: &std::path::Path, group: &str, file: &str) -> Option<u64> {
    let relative = std::path::Path::new(group.trim_start_matches('/'));
    if relative.components().any(|c| !matches!(c, std::path::Component::Normal(_))) {
        return smallest;
    }
    let mut dir = root.join(relative);
    loop {
        if let Ok(text) = std::fs::read_to_string(dir.join(file)) {
            if let Ok(n) = text.trim().parse::<u64>() {
                if n > 0 && n < (1 << 60) {
                    smallest = Some(smallest.map_or(n, |old| old.min(n)));
                }
            }
        }
        if dir == root || !dir.pop() || !dir.starts_with(root) {
            break;
        }
    }
    smallest
}

/// Reserves network buffer capacity before admitting work. This is a
/// conservative capacity reservation, not an RSS measurement. It covers
/// both transports and application queues and survives configuration reload.
#[derive(Debug)]
pub struct MemoryBudget {
    limit: u64,
    used: AtomicU64,
}

#[derive(Debug)]
pub struct MemoryPermit {
    budget: Arc<MemoryBudget>,
    bytes: u64,
}

impl MemoryBudget {
    pub fn new(limit: u64) -> Arc<Self> {
        Arc::new(Self { limit, used: AtomicU64::new(0) })
    }
    pub fn try_acquire(self: &Arc<Self>, bytes: u64) -> Option<MemoryPermit> {
        let mut old = self.used.load(Ordering::Acquire);
        loop {
            let next = old.checked_add(bytes).filter(|next| *next <= self.limit)?;
            match self.used.compare_exchange_weak(old, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some(MemoryPermit { budget: self.clone(), bytes }),
                Err(current) => old = current,
            }
        }
    }
}

impl Drop for MemoryPermit {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// Memory assumed when it cannot be detected.
pub const ASSUMED_MEMORY: u64 = 1 << 30;

/// Transport capacity of an HTTP/2 or HTTP/3 connection: its flow-control
/// windows (half for receiving; HTTP/3 also a quarter for sending, while
/// HTTP/2 queues sends per tunnel), datagram buffers, TLS and stream state. The windows are sized from it, so on small hosts
/// they shrink with it. The connection reserves it from the shared budget
/// when it opens its first tunnel (see [`Connections`]).
pub fn connection_memory(memory: Option<u64>) -> u64 {
    (memory.unwrap_or(ASSUMED_MEMORY) / 8).clamp(1 << 20, 8 << 20)
}

/// The same for an HTTP/1.1 connection, which carries a single tunnel and
/// has no flow-control windows: its TLS and read buffers.
pub const HTTP1_CONNECTION_MEMORY: u64 = 256 * 1024;

/// Memory a tunnel reserves: the relay's own buffers for it, each bounded.
/// A TCP tunnel has a 64 KiB read buffer per direction, and over HTTP/2 up
/// to 64 KiB of queued response data. A UDP flow has its HTTP/3 datagram
/// queue (64 datagrams, each within one QUIC packet), the capsule stream
/// queues (8 × 16 KiB in, 128 KiB out) and one capsule being decoded
/// (64 KiB). Data the client sends is bounded by the connection's windows,
/// reserved with the connection. Kernel socket buffers are fixed per socket
/// (see `sys`) and bounded system-wide by the kernel (`net.ipv4.tcp_mem`,
/// `net.ipv4.udp_mem`), so they are not part of this.
pub const MEMORY_PER_TUNNEL: u64 = 512 * 1024;

/// The default `max_tunnels` for a machine with `memory` bytes: a quarter of
/// the memory at [`MEMORY_PER_TUNNEL`] each, between 1 and 20 000.
pub fn default_max_tunnels(memory: Option<u64>) -> usize {
    ((memory.unwrap_or(ASSUMED_MEMORY) / 4 / MEMORY_PER_TUNNEL).min(20_000) as usize).max(1)
}

/// Memory planned per client connection when sizing the default
/// `max_connections`: what a connection holds before it authenticates
/// (QUIC and TLS state, header buffers), with room to spare.
pub const MEMORY_PER_CONNECTION: u64 = 512 * 1024;

/// The default `max_connections` for a machine with `memory` bytes: the
/// memory at [`MEMORY_PER_CONNECTION`] each, between 256 and 16 384.
pub fn default_max_connections(memory: Option<u64>) -> usize {
    (memory.unwrap_or(ASSUMED_MEMORY) / MEMORY_PER_CONNECTION).clamp(256, 16_384) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_ancestors_and_host_memory_all_constrain_capacity() {
        let root = std::env::temp_dir().join(format!("relay-cgroup-{}", crate::auth::generate_password()));
        std::fs::create_dir_all(root.join("parent/child")).unwrap();
        std::fs::write(root.join("memory.max"), "max").unwrap();
        std::fs::write(root.join("parent/memory.max"), "67108864").unwrap();
        std::fs::write(root.join("parent/child/memory.max"), "max").unwrap();
        assert_eq!(cgroup_memory(Some(16 << 30), &root, "/parent/child", "memory.max"), Some(64 << 20));
        assert_eq!(cgroup_memory(Some(32 << 20), &root, "/parent/child", "memory.max"), Some(32 << 20));
        std::fs::write(root.join("parent/child/memory.limit_in_bytes"), "33554432").unwrap();
        std::fs::write(root.join("parent/memory.limit_in_bytes"), "9223372036854771712").unwrap();
        assert_eq!(cgroup_memory(None, &root, "/parent/child", "memory.limit_in_bytes"), Some(32 << 20));
        assert_eq!(cgroup_memory(None, &root, "/../../", "memory.max"), None);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn memory_controller_mounts_can_have_custom_paths_and_subtree_roots() {
        let mounts = "29 23 0:26 /parent /custom\\040memory rw - cgroup cgroup rw,memory\n\
                      30 23 0:27 / /cpu rw - cgroup cgroup rw,cpu\n\
                      31 23 0:28 /container /unified rw - cgroup2 cgroup rw\n";
        assert_eq!(memory_mounts(mounts, "cgroup"), vec![("/parent".into(), "/custom memory".into())]);
        assert_eq!(memory_mounts(mounts, "cgroup2"), vec![("/container".into(), "/unified".into())]);
        assert!(memory_mounts("malformed", "cgroup2").is_empty());
    }

    #[test]
    fn memory_reservations_are_capped_and_refunded() {
        let memory = MemoryBudget::new(100);
        let first = memory.try_acquire(40).unwrap();
        let second = memory.try_acquire(30).unwrap();
        assert!(memory.try_acquire(31).is_none());
        assert!(memory.try_acquire(u64::MAX).is_none(), "overflow must not bypass the cap");
        drop(first);
        let third = memory.try_acquire(70).unwrap();
        drop((second, third));
        assert!(memory.try_acquire(100).is_some());
    }

    #[test]
    fn accepting_connections_reserves_no_memory() {
        // Anyone can open connections: admitting them must not use up what
        // authenticated tunnels need.
        let connections = Connections::new(10_000, 10_000);
        let permits: Vec<_> =
            (0..5000).map(|i| connections.try_acquire(std::net::Ipv4Addr::from(i as u32).into()).unwrap()).collect();
        assert_eq!(connections.open(), 5000);
        drop(permits);
        assert_eq!(connections.open(), 0);
    }

    #[tokio::test]
    async fn cancelling_all_keyed_waiters_removes_the_key() {
        let limit = KeyedLimit::new(1);
        let held = limit.acquire("alice").await;
        let mut waiting = Box::pin(limit.acquire("alice"));
        assert!(futures_poll(&mut waiting).is_none());
        drop(held);
        assert_eq!(limit.keys(), 1);
        drop(waiting);
        assert_eq!(limit.keys(), 0, "a cancelled last waiter must clean up its key");
    }

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

    #[tokio::test]
    async fn keyed_limits_queue_per_key_and_forget_idle_keys() {
        let limit = KeyedLimit::new(2);
        let a1 = limit.acquire("alice").await;
        let _a2 = limit.acquire("alice").await;
        let mut third = Box::pin(limit.acquire("alice"));
        assert!(futures_poll(&mut third).is_none(), "alice waits for her own share");
        let _b = tokio::time::timeout(Duration::from_secs(1), limit.acquire("bob")).await.expect("bob does not wait");
        drop(a1);
        let a3 = tokio::time::timeout(Duration::from_secs(1), third).await.expect("alice's turn comes");
        drop((a3, _a2, _b));
        assert_eq!(limit.keys(), 0, "idle keys are removed");
    }

    fn futures_poll<F: std::future::Future + Unpin>(f: &mut F) -> Option<F::Output> {
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        match std::pin::Pin::new(f).poll(&mut cx) {
            std::task::Poll::Ready(v) => Some(v),
            std::task::Poll::Pending => None,
        }
    }

    #[test]
    fn budgets_limit_packets_and_bytes() {
        let unlimited = Budget::new(0, 0);
        assert!(unlimited.allow_packet(65_000) && unlimited.charge_bytes(1 << 30).is_zero());
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
        assert_eq!(default_max_tunnels(Some(1 << 30)), 512, "a 1 GiB VPS carries a few devices' traffic");
        assert_eq!(default_max_tunnels(Some(4 << 30)), 2048);
        assert_eq!(default_max_tunnels(Some(256 << 20)), 128);
        assert_eq!(default_max_tunnels(Some(2 << 40)), 20_000);
        assert_eq!(default_max_tunnels(None), default_max_tunnels(Some(ASSUMED_MEMORY)));
        assert_eq!(default_max_tunnels(Some(1 << 20)), 1, "no floor on a tiny container");
        // The default fits in the budget the relay reserves tunnels from
        // (half the memory), next to connections and the website.
        for memory in [64 << 20, 1 << 30, 16 << 30] {
            assert!(default_max_tunnels(Some(memory)) as u64 * MEMORY_PER_TUNNEL <= memory / 4);
        }
    }

    #[test]
    fn default_connections_follow_memory() {
        assert_eq!(default_max_connections(Some(1 << 30)), 2048);
        assert_eq!(default_max_connections(Some(64 << 20)), 256);
        assert_eq!(default_max_connections(Some(64 << 30)), 16_384);
        assert_eq!(default_max_connections(None), default_max_connections(Some(ASSUMED_MEMORY)));
    }
}
