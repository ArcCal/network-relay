//! The relay: HTTP CONNECT for TCP (RFC 9110 §9.3.6) and CONNECT-UDP
//! (RFC 9298), over HTTP/3 on UDP and HTTP/2 and HTTP/1.1 on TCP, as Apple's
//! Network Relay uses them.
//!
//! The server looks like an ordinary website: every request that is not a
//! proxy request with valid credentials gets the website's answer (see
//! `web`), so failed attempts reveal nothing. Status codes and Proxy-Status
//! details (RFC 9209) only ever reach authenticated users.

mod h2_stream;
mod over_h3;
mod over_tcp;
mod pump;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use http::header::{HeaderName, HeaderValue, AUTHORIZATION, PROXY_AUTHORIZATION};
use http::{HeaderMap, Method};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{watch, Notify, OwnedSemaphorePermit, Semaphore};
use tracing::{debug, info, warn};

use crate::auth::{self, Authenticator, CacheTag, Denied, User};
use crate::certs::{CertStore, Schedule};
use crate::config::{Config, Web};
use crate::limits::{Budget, Connections, TokenBucket, UserSlot, UserTunnels};
use crate::policy::{Policy, Refusal, Target};
use crate::proto::{UriTemplate, CONNECT_TCP_PROTOCOL, CONNECT_UDP_PROTOCOL};
use crate::web::Website;
use crate::{connect, sys};

pub use over_h3::quic_endpoint;
pub use over_tcp::tcp_tls_config;

/// Longest a client may take to send its request headers.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a connection that never authenticated may stay open without a
/// request.
const UNAUTHENTICATED_IDLE: Duration = Duration::from_secs(30);
/// New QUIC handshakes per second from addresses not yet validated, beyond
/// which clients must first prove their address with a Retry (RFC 9000 §8.1).
const HANDSHAKE_RATE: f64 = 200.0;
const HANDSHAKE_BURST: f64 = 400.0;

/// Settings that a reload (SIGHUP) replaces.
struct Settings {
    udp_template: UriTemplate,
    policy: Policy,
    connect_timeout: Duration,
    udp_idle_timeout: Duration,
    log_requests: bool,
    max_tunnels_per_user: usize,
    /// Per-user traffic budget: bytes and UDP packets per second (0: none).
    budget: (u64, u64),
    idle_timeout: Duration,
}

impl Settings {
    fn new(config: &Config) -> Result<Self> {
        Ok(Self {
            udp_template: config.relay.udp_template()?,
            policy: Policy::new(&config.relay),
            connect_timeout: config.relay.connect_timeout(),
            udp_idle_timeout: config.relay.udp_idle_timeout(),
            log_requests: config.debug.log_requests,
            max_tunnels_per_user: config.relay.max_tunnels_per_user,
            budget: (config.relay.max_bytes_per_second_per_user, config.relay.max_udp_packets_per_second_per_user),
            idle_timeout: config.relay.idle_timeout(),
        })
    }
}

struct Inner {
    settings: RwLock<Arc<Settings>>,
    auth: Arc<Authenticator>,
    site: RwLock<Option<Arc<Website>>>,
    /// One permit per relayed TCP connection or UDP flow.
    tunnels: Arc<Semaphore>,
    max_tunnels: usize,
    /// Tunnels per user.
    user_tunnels: Arc<UserTunnels>,
    /// Traffic budgets per user; they survive reloads that leave the limits
    /// alone, so reconnecting or reloading does not renew a budget.
    budgets: Mutex<HashMap<String, Arc<Budget>>>,
    /// Client connections, in total and per address. Fixed at start-up.
    connections: Arc<Connections>,
    /// New QUIC handshakes from unvalidated addresses.
    handshakes: Mutex<TokenBucket>,
    /// Advertises HTTP/3 in responses over TCP, as websites that offer it do.
    alt_svc: HeaderValue,
    /// One-time profile links already downloaded (see `web`).
    consumed: Arc<Mutex<std::collections::HashSet<String>>>,
}

/// The relay, independent of sockets so tests can run it in-process.
#[derive(Clone)]
pub struct Relay {
    inner: Arc<Inner>,
}

fn load_site(
    web: Option<&Web>,
    consumed: &Arc<Mutex<std::collections::HashSet<String>>>,
) -> Result<Option<Arc<Website>>> {
    web.map(|w| Website::load_with(&w.root, &w.headers, consumed.clone()).map(Arc::new)).transpose()
}

impl Relay {
    pub fn new(config: &Config) -> Result<Self> {
        config.validate()?;
        let alt_svc = HeaderValue::try_from(format!("h3=\":{}\"; ma=86400", config.listen.port())).expect("valid");
        let max_tunnels = config.relay.max_tunnels();
        let consumed = Arc::default();
        Ok(Self {
            inner: Arc::new(Inner {
                settings: RwLock::new(Arc::new(Settings::new(config)?)),
                auth: Arc::new(Authenticator::new(&config.users)?),
                site: RwLock::new(load_site(config.web.as_ref(), &consumed)?),
                tunnels: Arc::new(Semaphore::new(max_tunnels)),
                max_tunnels,
                user_tunnels: Arc::default(),
                budgets: Mutex::default(),
                connections: Connections::new(config.relay.max_connections, config.relay.max_connections_per_ip),
                handshakes: Mutex::new(TokenBucket::new(HANDSHAKE_RATE, HANDSHAKE_BURST)),
                alt_svc,
                consumed,
            }),
        })
    }

    /// Applies a changed configuration: users (ending the tunnels of users
    /// who were removed or whose password changed), destination rules,
    /// timeouts, logging and the website. The listen address and
    /// `relay.max_tunnels` need a restart.
    pub fn reload(&self, config: &Config) -> Result<()> {
        config.validate()?;
        let settings = Settings::new(config)?;
        let site = load_site(config.web.as_ref(), &self.inner.consumed);
        self.inner.auth.replace(&config.users)?;
        *self.inner.settings.write().unwrap() = Arc::new(settings);
        match site {
            Ok(site) => *self.inner.site.write().unwrap() = site,
            Err(e) => warn!("keeping the current website: {e:#}"),
        }
        Ok(())
    }

    /// Relayed TCP connections and UDP flows open right now.
    pub fn active_tunnels(&self) -> usize {
        self.inner.max_tunnels - self.inner.tunnels.available_permits()
    }

    fn settings(&self) -> Arc<Settings> {
        self.inner.settings.read().unwrap().clone()
    }

    fn site(&self) -> Option<Arc<Website>> {
        self.inner.site.read().unwrap().clone()
    }

    /// Tunnels open for `user` right now.
    pub fn user_tunnels(&self, user: &str) -> usize {
        self.inner.user_tunnels.count(user)
    }

    /// Client connections open right now.
    pub fn open_connections(&self) -> usize {
        self.inner.connections.open()
    }

    /// A user's traffic budget under the current limits, if there is one.
    fn budget(&self, user: &str, limits: (u64, u64)) -> Option<Arc<Budget>> {
        if limits == (0, 0) {
            return None;
        }
        let mut budgets = self.inner.budgets.lock().unwrap();
        let budget = budgets.entry(user.to_string()).or_insert_with(|| Arc::new(Budget::new(limits.0, limits.1)));
        if budget.settings != limits {
            *budget = Arc::new(Budget::new(limits.0, limits.1));
        }
        Some(budget.clone())
    }

    /// Whether a new QUIC connection from an unvalidated address should
    /// first be sent a Retry: only when handshakes arrive faster than usual.
    fn handshake_needs_retry(&self) -> bool {
        !self.inner.handshakes.lock().unwrap().try_take(1.0, Instant::now())
    }
}

/// What kind of tunnel a request asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Classic CONNECT: the authority names a TCP destination.
    Tcp,
    /// CONNECT-UDP: the path names a UDP destination.
    Udp,
    /// An extended CONNECT for a protocol this relay does not implement,
    /// such as `connect-tcp` or `connect-ip`: 501 once authenticated.
    Unsupported,
    /// A UDP proxying request that breaks RFC 9298 §3 (an HTTP/1.1
    /// `Upgrade: connect-udp` that is not a GET with `Connection: Upgrade`,
    /// or a `:scheme` other than https): 400 once authenticated.
    Malformed,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Tcp => "TCP",
            Kind::Udp => "UDP",
            Kind::Unsupported => "unsupported",
            Kind::Malformed => "malformed",
        }
    }

    /// The kind of an HTTP/2 or HTTP/3 request: CONNECT, with or without
    /// `:protocol` (RFC 8441, RFC 9220).
    fn of_connect(is_connect: bool, protocol: Option<&str>, scheme: Option<&str>) -> Option<Self> {
        match (is_connect, protocol) {
            (false, _) => None,
            (true, None) => Some(Kind::Tcp),
            // RFC 9298 §3.4: the scheme of a UDP proxying request is https.
            (true, Some(CONNECT_UDP_PROTOCOL)) if scheme == Some("https") => Some(Kind::Udp),
            (true, Some(CONNECT_UDP_PROTOCOL)) => Some(Kind::Malformed),
            (true, Some(_)) => Some(Kind::Unsupported),
        }
    }
}

/// The parts of a request the relay looks at, whatever the HTTP version.
struct Incoming<'a> {
    method: &'a Method,
    /// `:protocol` of an extended CONNECT, or the `Upgrade` token.
    protocol: Option<&'a str>,
    kind: Option<Kind>,
    authority: Option<&'a str>,
    path_and_query: &'a str,
    headers: &'a HeaderMap,
}

/// Per-connection bookkeeping, logged when the connection and all its
/// tunnels are gone.
struct ConnInfo {
    transport: &'static str,
    remote: SocketAddr,
    started: Instant,
    user: OnceLock<String>,
    tcp: AtomicU64,
    udp: AtomicU64,
    refused: AtomicU64,
    up: AtomicU64,
    down: AtomicU64,
    /// SHA-256 of the client certificate, if the client presented one.
    client_cert: Option<[u8; 32]>,
    /// Uncached password verifications under way on this connection.
    pending_auth: AtomicUsize,
    /// The credentials this connection authenticated with.
    bound: Mutex<Option<(CacheTag, User)>>,
    /// Requests (streams) open on this connection, for the idle timeout.
    active: AtomicUsize,
    idle_since: Mutex<tokio::time::Instant>,
    activity: Notify,
}

/// Counts a request as open on its connection until dropped.
struct ActiveRequest(Arc<ConnInfo>);

impl Drop for ActiveRequest {
    fn drop(&mut self) {
        if self.0.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            *self.0.idle_since.lock().unwrap() = tokio::time::Instant::now();
        }
        self.0.activity.notify_waiters();
    }
}

impl ConnInfo {
    fn new(transport: &'static str, remote: SocketAddr, client_cert: Option<[u8; 32]>) -> Arc<Self> {
        Arc::new(Self {
            transport,
            remote,
            started: Instant::now(),
            user: OnceLock::new(),
            tcp: AtomicU64::new(0),
            udp: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            client_cert,
            pending_auth: AtomicUsize::new(0),
            bound: Mutex::new(None),
            active: AtomicUsize::new(0),
            idle_since: Mutex::new(tokio::time::Instant::now()),
            activity: Notify::new(),
        })
    }

    fn authenticated(&self, user: &str) {
        if self.user.set(user.to_string()).is_ok() {
            info!(user, remote = %self.remote, transport = self.transport, "client connected");
        }
    }

    /// Marks a request as open until the returned guard is dropped.
    fn request_started(self: &Arc<Self>) -> ActiveRequest {
        self.active.fetch_add(1, Ordering::AcqRel);
        self.activity.notify_waiters();
        ActiveRequest(self.clone())
    }

    /// Resolves once the connection has had no open request for `limit`
    /// (or [`UNAUTHENTICATED_IDLE`] while it never authenticated).
    async fn idle(&self, limit: Duration) {
        loop {
            let changed = self.activity.notified();
            if self.active.load(Ordering::Acquire) == 0 {
                let limit = if self.user.get().is_some() { limit } else { limit.min(UNAUTHENTICATED_IDLE) };
                let since = *self.idle_since.lock().unwrap();
                tokio::select! {
                    _ = tokio::time::sleep_until(since + limit) => {
                        if self.active.load(Ordering::Acquire) == 0 && *self.idle_since.lock().unwrap() == since {
                            return;
                        }
                    }
                    _ = changed => {}
                }
            } else {
                changed.await;
            }
        }
    }
}

impl Drop for ConnInfo {
    fn drop(&mut self) {
        let Some(user) = self.user.get() else { return };
        info!(
            user,
            remote = %self.remote,
            transport = self.transport,
            "client disconnected after {}: TCP connections {}, UDP flows {}, refused {}, uploaded {}, downloaded {}",
            format_duration(self.started.elapsed()),
            self.tcp.load(Ordering::Relaxed),
            self.udp.load(Ordering::Relaxed),
            self.refused.load(Ordering::Relaxed),
            format_bytes(self.up.load(Ordering::Relaxed)),
            format_bytes(self.down.load(Ordering::Relaxed)),
        );
    }
}

fn format_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[unit])
    }
}

fn format_duration(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m{:02}s", s / 60, s % 60),
        _ => format!("{}h{:02}m", s / 3600, (s % 3600) / 60),
    }
}

/// An authenticated request, before its destination is resolved.
struct Authorized {
    kind: Kind,
    user: User,
    target: Result<Target, Refusal>,
}

/// A tunnel's destination socket.
enum Opened {
    Tcp(TcpStream),
    Udp(UdpSocket),
}

impl Opened {
    /// A failed HTTP handshake must not look like an orderly TCP close to
    /// a destination that was already connected (RFC 9113/9114 CONNECT).
    fn abort(&self) {
        if let Self::Tcp(tcp) = self {
            let _ = socket2::SockRef::from(tcp).set_linger(Some(Duration::ZERO));
        }
    }
}

/// Everything a running tunnel needs besides its streams.
struct TunnelCtx {
    user: User,
    target: Target,
    conn: Arc<ConnInfo>,
    auth: Arc<Authenticator>,
    changes: watch::Receiver<u64>,
    peer_closed: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
    udp_idle_timeout: Duration,
    /// The user's traffic budget, if limits are configured.
    budget: Option<Arc<Budget>>,
    _permit: OwnedSemaphorePermit,
    _user_slot: UserSlot,
}

impl TunnelCtx {
    /// Cancellation must remain observable even after one direction has FIN'd.
    async fn cancelled(&mut self) {
        tokio::select! {
            _ = wait_for_revocation(&self.auth, &self.user, &mut self.changes) => {}
            _ = &mut self.peer_closed => {}
        }
    }
}

/// Resolves when `user` is removed, their credential changes, or their
/// account expires.
async fn wait_for_revocation(auth: &Authenticator, user: &User, changes: &mut watch::Receiver<u64>) {
    let expiry = async {
        match user.time_left() {
            Some(left) => tokio::time::sleep(left).await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(expiry);
    loop {
        if !auth.is_current(user) {
            return;
        }
        tokio::select! {
            _ = &mut expiry => return,
            changed = changes.changed() => if changed.is_err() {
                return (&mut expiry).await;
            },
        }
    }
}

/// Process-wide budget for logging authentication failures: a burst, then a
/// few a second, with a count of what was left out.
static AUTH_LOGS: OnceLock<Mutex<(TokenBucket, u64)>> = OnceLock::new();

/// Whether to log one more authentication failure, and how many were left
/// out since the last one logged.
fn auth_log_allowed() -> Option<u64> {
    let mut state = AUTH_LOGS.get_or_init(|| Mutex::new((TokenBucket::new(5.0, 10.0), 0))).lock().unwrap();
    if state.0.try_take(1.0, Instant::now()) {
        Some(std::mem::take(&mut state.1))
    } else {
        state.1 += 1;
        None
    }
}

/// Logs why a proxy request was not authenticated. Failures carry the
/// client's chosen user name, so they are rate-limited: a flood of wrong
/// passwords must not flood the journal.
fn log_denied(denied: &Denied, conn: &ConnInfo) {
    let (what, name) = match denied {
        Denied::Missing | Denied::Malformed => {
            debug!(remote = %conn.remote, transport = conn.transport, "proxy request without valid credentials");
            return;
        }
        Denied::Rejected { user } => ("authentication failed", user),
        Denied::Throttled { user } => ("authentication refused: too many new credentials from this client", user),
    };
    let Some(suppressed) = auth_log_allowed() else { return };
    // The name is the client's text: quoted and escaped, so it cannot forge
    // log lines.
    let name: String = name.chars().take(64).collect();
    info!(remote = %conn.remote, user = ?name, transport = conn.transport, suppressed, "{what}");
}

/// Header values shown in request logs: credentials are reduced to the
/// scheme and, for Basic, the user name.
fn masked(name: &HeaderName, value: &HeaderValue) -> String {
    if *name == AUTHORIZATION || *name == PROXY_AUTHORIZATION {
        return match auth::parse_basic(value.as_bytes()) {
            Some((user, _)) => format!("Basic <user {user:?}, password hidden>"),
            None => "<hidden>".to_string(),
        };
    }
    String::from_utf8_lossy(value.as_bytes()).chars().take(200).collect()
}

impl Relay {
    /// Checks credentials. `None` means the request gets the website's
    /// answer: it is not a proxy request, does not match the template, or
    /// lacks valid credentials.
    async fn authorize(&self, req: &Incoming<'_>, conn: &ConnInfo, settings: &Settings) -> Option<Authorized> {
        let proxyish = req.kind.is_some() || *req.method == Method::CONNECT || req.protocol.is_some();
        if settings.log_requests && proxyish {
            let headers: Vec<String> = req.headers.iter().map(|(n, v)| format!("{n}: {}", masked(n, v))).collect();
            info!(
                remote = %conn.remote,
                transport = conn.transport,
                method = %req.method,
                protocol = req.protocol.unwrap_or("-"),
                authority = req.authority.unwrap_or("-"),
                path = req.path_and_query,
                "request headers: {}",
                headers.join(" | ")
            );
        }
        if req.protocol.is_some_and(|p| p.eq_ignore_ascii_case(CONNECT_TCP_PROTOCOL)) {
            static ONCE: AtomicBool = AtomicBool::new(false);
            if !ONCE.swap(true, Ordering::Relaxed) {
                info!(remote = %conn.remote, "a client asked for connect-tcp (draft-ietf-httpbis-connect-tcp), which this version does not support");
            }
        }
        let kind = req.kind?;
        let target = match kind {
            Kind::Tcp => req.authority.and_then(Target::from_authority).ok_or(Refusal::BadTarget),
            Kind::Udp => {
                let vars = settings.udp_template.matches(req.path_and_query)?;
                match (vars.get("target_host"), vars.get("target_port")) {
                    (Some(h), Some(p)) => Target::from_template_vars(h, p).ok_or(Refusal::BadTarget),
                    _ => Err(Refusal::BadTarget),
                }
            }
            Kind::Unsupported => Err(Refusal::UnsupportedProtocol),
            Kind::Malformed => Err(Refusal::MalformedRequest),
        };
        // A client certificate that belongs to a user authenticates on its
        // own; otherwise the password.
        if let Some(user) = conn.client_cert.and_then(|fp| self.inner.auth.verify_certificate(&fp)) {
            conn.authenticated(&user.name);
            return Some(Authorized { kind, user, target });
        }
        let header = req.headers.get(PROXY_AUTHORIZATION).or_else(|| req.headers.get(AUTHORIZATION));
        let header = header.map(HeaderValue::as_bytes);
        let client = auth::Client { ip: conn.remote.ip(), pending: &conn.pending_auth, bound: &conn.bound };
        let user = match self.inner.auth.verify(header, &client).await {
            Ok(user) => user,
            Err(denied) => {
                log_denied(&denied, conn);
                return None;
            }
        };
        conn.authenticated(&user.name);
        Some(Authorized { kind, user, target })
    }

    /// Resolves and connects to the destination of an authorized request.
    async fn open(
        &self,
        a: &Authorized,
        conn: &Arc<ConnInfo>,
        settings: &Settings,
    ) -> Result<(Opened, TunnelCtx), Refusal> {
        let result = self.try_open(a, conn, settings).await;
        if let Err(refusal) = &result {
            conn.refused.fetch_add(1, Ordering::Relaxed);
            let target = a.target.as_ref().map_or_else(|_| "-".to_string(), |t| t.to_string());
            if settings.log_requests {
                info!(user = %a.user.name, kind = a.kind.as_str(), %target, status = %refusal.status(), "refused: {refusal}");
            } else {
                debug!(user = %a.user.name, kind = a.kind.as_str(), %target, status = %refusal.status(), "refused: {refusal}");
            }
        }
        result
    }

    async fn try_open(
        &self,
        a: &Authorized,
        conn: &Arc<ConnInfo>,
        settings: &Settings,
    ) -> Result<(Opened, TunnelCtx), Refusal> {
        // Subscribe before any asynchronous work, then check the current user.
        let mut changes = self.inner.auth.changes();
        if !self.inner.auth.is_current(&a.user) {
            return Err(Refusal::UserRevoked);
        }
        let target = a.target.clone()?;
        let user_slot = self
            .inner
            .user_tunnels
            .try_acquire(&a.user.name, settings.max_tunnels_per_user)
            .ok_or(Refusal::TooManyUserTunnels)?;
        let permit = self.inner.tunnels.clone().try_acquire_owned().map_err(|_| Refusal::TooManyTunnels)?;
        let connecting = async {
            let addrs = settings.policy.resolve(&target).await?;
            if !self.inner.auth.is_current(&a.user) {
                return Err(Refusal::UserRevoked);
            }
            match a.kind {
                Kind::Tcp => Ok(Opened::Tcp(connect::tcp(&addrs, settings.connect_timeout).await?)),
                Kind::Udp => Ok(Opened::Udp(connect::udp(&addrs).await?)),
                // Their target is always a refusal, returned above.
                Kind::Unsupported => Err(Refusal::UnsupportedProtocol),
                Kind::Malformed => Err(Refusal::MalformedRequest),
            }
        };
        let opened = tokio::select! {
            biased;
            _ = wait_for_revocation(&self.inner.auth, &a.user, &mut changes) => return Err(Refusal::UserRevoked),
            opened = connecting => opened?,
        };
        if !self.inner.auth.is_current(&a.user) {
            return Err(Refusal::UserRevoked);
        }
        match a.kind {
            Kind::Tcp => &conn.tcp,
            Kind::Udp => &conn.udp,
            Kind::Unsupported | Kind::Malformed => &conn.refused,
        }
        .fetch_add(1, Ordering::Relaxed);
        debug!(user = %a.user.name, kind = a.kind.as_str(), %target, "tunnel opened");
        let ctx = TunnelCtx {
            user: a.user.clone(),
            target,
            conn: conn.clone(),
            auth: self.inner.auth.clone(),
            changes,
            peer_closed: Box::pin(std::future::pending()),
            udp_idle_timeout: settings.udp_idle_timeout,
            budget: self.budget(&a.user.name, settings.budget),
            _permit: permit,
            _user_slot: user_slot,
        };
        Ok((opened, ctx))
    }
}

fn http_date() -> HeaderValue {
    HeaderValue::try_from(chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()).expect("valid date")
}

/// Runs the server until SIGINT or SIGTERM. `config` was loaded from
/// `config_path`, which SIGHUP reads again.
pub async fn run(config_path: PathBuf, config: Config) -> Result<()> {
    sys::raise_open_file_limit(
        config.relay.max_tunnels().saturating_mul(2).saturating_add(config.relay.max_connections).saturating_add(1024)
            as _,
    );
    let certs = CertStore::open(&config.tls.cert, &config.tls.key)?;
    let relay = Relay::new(&config)?;
    let udp =
        std::net::UdpSocket::bind(config.listen).with_context(|| format!("listening on UDP {}", config.listen))?;
    let (rcv, snd) = sys::grow_buffers(socket2::SockRef::from(&udp), 8 << 20);
    if rcv < 4 << 20 {
        info!(
            "UDP receive buffer is {} KiB; for fast HTTP/3 raise net.core.rmem_max and wmem_max (see docs)",
            rcv / 1024
        );
    }
    debug!(rcv, snd, "UDP socket buffers");
    let endpoint = quic_endpoint(certs.clone(), udp, config.tls.client_certificates)?;
    let tcp = TcpListener::bind(config.listen).await.with_context(|| format!("listening on TCP {}", config.listen))?;
    let tcp_tls = tcp_tls_config(certs.clone(), config.tls.client_certificates)?;
    // Registered before the listeners start, so an early SIGHUP or SIGTERM is
    // handled rather than killing the process by default action.
    let mut sighup = signal(SignalKind::hangup())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut quic_task = tokio::spawn(relay.clone().serve_quic(endpoint.clone()));
    let mut tcp_task = tokio::spawn(relay.clone().serve_tcp(tcp, tcp_tls));
    let mut reload_task =
        tokio::spawn(certs.clone().run_schedule(Schedule::from_config(config.tls.reload_interval_days)));
    info!(
        listen = %config.listen,
        users = config.users.len(),
        website = %config.web.as_ref().map_or_else(|| "none (404)".to_string(), |w| w.root.display().to_string()),
        udp_template = %config.relay.udp_template,
        open_files = sys::open_file_limit().unwrap_or(0),
        max_tunnels = relay.inner.max_tunnels,
        "network-relay {} ready (HTTP/3 on UDP, HTTP/2 and HTTP/1.1 on TCP)",
        env!("CARGO_PKG_VERSION")
    );
    if config.users.is_empty() {
        warn!("no [[user]] configured: every request gets the website; add one with `network-relay passwd`");
    }
    // None for a requested shutdown; otherwise the task that ended. None of
    // these tasks returns on its own, so an exit (a panic, say) must not leave
    // the process running without a listener: fail and let systemd restart it.
    let failed = loop {
        tokio::select! {
            _ = sighup.recv() => match Config::load(&config_path) {
                Ok(c) => {
                    match relay.reload(&c) {
                        Ok(()) => info!(users = c.users.len(), "reloaded users, destination rules, timeouts and website"),
                        Err(e) => warn!("not reloading: {e:#}"),
                    }
                    if let Err(e) = certs.reload() {
                        warn!("keeping the current TLS certificate: {e:#}");
                    }
                    if c.listen != config.listen
                        || c.relay.max_tunnels != config.relay.max_tunnels
                        || c.relay.max_connections != config.relay.max_connections
                        || c.relay.max_connections_per_ip != config.relay.max_connections_per_ip
                        || c.tls.client_certificates != config.tls.client_certificates
                        || c.log_dir != config.log_dir
                        || c.tls.cert != config.tls.cert
                        || c.tls.key != config.tls.key
                        || c.tls.reload_interval_days != config.tls.reload_interval_days
                    {
                        warn!(
                            "listen, log_dir, relay.max_tunnels, relay.max_connections(_per_ip) and the [tls] \
                             settings take effect after a restart"
                        );
                    }
                }
                Err(e) => warn!("not reloading, configuration is invalid: {e:#}"),
            },
            _ = sigterm.recv() => { info!("SIGTERM received, shutting down"); break None; }
            _ = tokio::signal::ctrl_c() => { info!("interrupted, shutting down"); break None; }
            r = &mut quic_task => break Some(("HTTP/3 listener", r)),
            r = &mut tcp_task => break Some(("HTTP/2 and HTTP/1.1 listener", r)),
            r = &mut reload_task => break Some(("certificate reload task", r)),
        }
    };
    reload_task.abort();
    tcp_task.abort();
    quic_task.abort();
    endpoint.close(over_h3::H3_NO_ERROR.into(), b"server shutting down");
    let _ = tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle()).await;
    match failed {
        None => Ok(()),
        Some((what, result)) => anyhow::bail!("the {what} stopped unexpectedly: {result:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn revocation_is_detected_even_when_subscription_is_late() {
        let hash = auth::hash_password("test-password").unwrap();
        let user = User { name: "alice".into(), credential: hash.clone(), expires: None };
        let auth = Authenticator::new(&[crate::config::UserEntry::with_password(&user.name, &hash)]).unwrap();
        auth.replace(&[]).unwrap();
        let mut changes = auth.changes();
        tokio::time::timeout(Duration::from_secs(1), wait_for_revocation(&auth, &user, &mut changes)).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_revokes_tunnels_on_time() {
        let hash = auth::hash_password("test-password").unwrap();
        let expires = std::time::SystemTime::now() + Duration::from_secs(90);
        let mut entry = crate::config::UserEntry::with_password("alice", &hash);
        entry.expires = Some(chrono::DateTime::<chrono::Utc>::from(expires).to_rfc3339());
        let auth = Authenticator::new(&[entry]).unwrap();
        let user = User { name: "alice".into(), credential: hash, expires: Some(expires) };
        assert!(auth.is_current(&user));
        let mut changes = auth.changes();
        let started = tokio::time::Instant::now();
        wait_for_revocation(&auth, &user, &mut changes).await;
        assert!(started.elapsed() >= Duration::from_secs(89), "{:?}", started.elapsed());
    }

    #[tokio::test(start_paused = true)]
    async fn connections_go_idle_without_requests() {
        let conn = ConnInfo::new("HTTP/2", "192.0.2.1:1".parse().unwrap(), None);
        let started = tokio::time::Instant::now();
        conn.idle(Duration::from_secs(300)).await;
        assert_eq!(started.elapsed().as_secs(), 30, "unauthenticated connections get 30 s");
        conn.authenticated("alice");
        let request = conn.request_started();
        let waiting = tokio::spawn({
            let conn = conn.clone();
            async move {
                let started = tokio::time::Instant::now();
                conn.idle(Duration::from_secs(300)).await;
                started.elapsed()
            }
        });
        tokio::time::sleep(Duration::from_secs(1000)).await;
        assert!(!waiting.is_finished(), "an open request keeps the connection");
        drop(request);
        let elapsed = waiting.await.unwrap();
        assert_eq!(elapsed.as_secs(), 1300);
    }

    #[test]
    fn authentication_failure_logs_are_rate_limited() {
        let allowed = (0..100).filter(|_| auth_log_allowed().is_some()).count();
        assert!(allowed <= 11, "{allowed}");
    }

    #[test]
    fn sizes_and_durations_read_well() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(5 << 30), "5.0 GiB");
        assert_eq!(format_duration(Duration::from_secs(59)), "59s");
        assert_eq!(format_duration(Duration::from_secs(61)), "1m01s");
        assert_eq!(format_duration(Duration::from_secs(3 * 3600 + 120)), "3h02m");
    }

    #[test]
    fn credentials_are_masked_in_logs() {
        let v = HeaderValue::from_str(&auth::basic_authorization("iphone", "secret")).unwrap();
        let shown = masked(&AUTHORIZATION, &v);
        assert!(shown.contains("iphone") && !shown.contains("secret") && !shown.contains(v.to_str().unwrap()));
        assert_eq!(masked(&PROXY_AUTHORIZATION, &HeaderValue::from_static("Bearer abc")), "<hidden>");
        assert_eq!(masked(&http::header::USER_AGENT, &HeaderValue::from_static("x")), "x");
    }
}
