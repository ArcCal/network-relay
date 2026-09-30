//! The relay: HTTP CONNECT for TCP (RFC 9110 §9.3.6) and CONNECT-UDP
//! (RFC 9298), over HTTP/3 on UDP and HTTP/2 and HTTP/1.1 on TCP, as Apple's
//! Network Relay uses them.
//!
//! The server looks like an ordinary website: every request that is not a
//! proxy request with valid credentials gets the website's answer (see
//! `web`), so failed attempts reveal nothing. Status codes and Proxy-Status
//! details (RFC 9209) only ever reach authenticated users.

mod over_h3;
mod over_tcp;
mod pump;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use http::header::{HeaderName, HeaderValue, AUTHORIZATION, PROXY_AUTHORIZATION};
use http::{HeaderMap, Method};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tracing::{debug, info, warn};

use crate::auth::{self, Authenticator, User};
use crate::certs::{CertStore, Schedule};
use crate::config::{Config, Web};
use crate::policy::{Policy, Refusal, Target};
use crate::proto::{UriTemplate, CONNECT_TCP_PROTOCOL};
use crate::web::Website;
use crate::{connect, sys};

pub use over_h3::quic_endpoint;
pub use over_tcp::tcp_tls_config;

/// Longest a client may take to send its request headers.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// Settings that a reload (SIGHUP) replaces.
struct Settings {
    udp_template: UriTemplate,
    policy: Policy,
    connect_timeout: Duration,
    udp_idle_timeout: Duration,
    log_requests: bool,
}

impl Settings {
    fn new(config: &Config) -> Result<Self> {
        Ok(Self {
            udp_template: config.relay.udp_template()?,
            policy: Policy::new(&config.relay),
            connect_timeout: config.relay.connect_timeout(),
            udp_idle_timeout: config.relay.udp_idle_timeout(),
            log_requests: config.debug.log_requests,
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
    /// Advertises HTTP/3 in responses over TCP, as websites that offer it do.
    alt_svc: HeaderValue,
}

/// The relay, independent of sockets so tests can run it in-process.
#[derive(Clone)]
pub struct Relay {
    inner: Arc<Inner>,
}

fn load_site(web: Option<&Web>) -> Result<Option<Arc<Website>>> {
    web.map(|w| Website::load(&w.root, &w.headers).map(Arc::new)).transpose()
}

impl Relay {
    pub fn new(config: &Config) -> Result<Self> {
        let alt_svc = HeaderValue::try_from(format!("h3=\":{}\"; ma=86400", config.listen.port())).expect("valid");
        Ok(Self {
            inner: Arc::new(Inner {
                settings: RwLock::new(Arc::new(Settings::new(config)?)),
                auth: Arc::new(Authenticator::new(&config.users)?),
                site: RwLock::new(load_site(config.web.as_ref())?),
                tunnels: Arc::new(Semaphore::new(config.relay.max_tunnels)),
                max_tunnels: config.relay.max_tunnels,
                alt_svc,
            }),
        })
    }

    /// Applies a changed configuration: users (ending the tunnels of users
    /// who were removed or whose password changed), destination rules,
    /// timeouts, logging and the website. The listen address and
    /// `relay.max_tunnels` need a restart.
    pub fn reload(&self, config: &Config) -> Result<()> {
        let settings = Settings::new(config)?;
        let site = load_site(config.web.as_ref());
        *self.inner.settings.write().unwrap() = Arc::new(settings);
        self.inner.auth.replace(&config.users);
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
}

/// What kind of tunnel a request asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Classic CONNECT: the authority names a TCP destination.
    Tcp,
    /// CONNECT-UDP: the path names a UDP destination.
    Udp,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Tcp => "TCP",
            Kind::Udp => "UDP",
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
}

impl ConnInfo {
    fn new(transport: &'static str, remote: SocketAddr) -> Arc<Self> {
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
        })
    }

    fn authenticated(&self, user: &str) {
        if self.user.set(user.to_string()).is_ok() {
            info!(user, remote = %self.remote, transport = self.transport, "client connected");
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

/// Everything a running tunnel needs besides its streams.
struct TunnelCtx {
    user: User,
    target: Target,
    conn: Arc<ConnInfo>,
    auth: Arc<Authenticator>,
    changes: watch::Receiver<u64>,
    udp_idle_timeout: Duration,
    _permit: OwnedSemaphorePermit,
}

impl TunnelCtx {
    /// Resolves once the user is removed or their password changes.
    async fn revoked(&mut self) {
        loop {
            if self.changes.changed().await.is_err() {
                return std::future::pending().await;
            }
            if !self.auth.is_current(&self.user) {
                return;
            }
        }
    }
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
        };
        let header = req.headers.get(PROXY_AUTHORIZATION).or_else(|| req.headers.get(AUTHORIZATION));
        let header = header.map(HeaderValue::as_bytes);
        let Some(user) = self.inner.auth.verify(header).await else {
            match header.and_then(auth::parse_basic) {
                // The name is the client's text: quoted and escaped, so it
                // cannot forge log lines.
                Some((name, _)) => {
                    let name: String = name.chars().take(64).collect();
                    info!(remote = %conn.remote, user = ?name, transport = conn.transport, "authentication failed")
                }
                None => debug!(remote = %conn.remote, transport = conn.transport, "proxy request without credentials"),
            }
            return None;
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
        let target = a.target.clone()?;
        let permit = self.inner.tunnels.clone().try_acquire_owned().map_err(|_| Refusal::TooManyTunnels)?;
        let addrs = settings.policy.resolve(&target).await?;
        let opened = match a.kind {
            Kind::Tcp => Opened::Tcp(connect::tcp(&addrs, settings.connect_timeout).await?),
            Kind::Udp => Opened::Udp(connect::udp(&addrs).await?),
        };
        let counter = match a.kind {
            Kind::Tcp => &conn.tcp,
            Kind::Udp => &conn.udp,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        debug!(user = %a.user.name, kind = a.kind.as_str(), %target, "tunnel opened");
        let ctx = TunnelCtx {
            user: a.user.clone(),
            target,
            conn: conn.clone(),
            auth: self.inner.auth.clone(),
            changes: self.inner.auth.changes(),
            udp_idle_timeout: settings.udp_idle_timeout,
            _permit: permit,
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
    sys::raise_open_file_limit((config.relay.max_tunnels * 2 + 1024) as _);
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
    let endpoint = quic_endpoint(certs.clone(), udp)?;
    let tcp = TcpListener::bind(config.listen).await.with_context(|| format!("listening on TCP {}", config.listen))?;
    let quic_task = tokio::spawn(relay.clone().serve_quic(endpoint.clone()));
    let tcp_task = tokio::spawn(relay.clone().serve_tcp(tcp, tcp_tls_config(certs.clone())?));
    let reload_task = tokio::spawn(certs.clone().run_schedule(Schedule::from_config(config.tls.reload_interval_days)));
    info!(
        listen = %config.listen,
        users = config.users.len(),
        website = %config.web.as_ref().map_or_else(|| "none (404)".to_string(), |w| w.root.display().to_string()),
        udp_template = %config.relay.udp_template,
        open_files = sys::open_file_limit().unwrap_or(0),
        "network-relay {} ready (HTTP/3 on UDP, HTTP/2 and HTTP/1.1 on TCP)",
        env!("CARGO_PKG_VERSION")
    );
    if config.users.is_empty() {
        warn!("no [[user]] configured: every request gets the website; add one with `network-relay passwd`");
    }
    let mut sighup = signal(SignalKind::hangup())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    loop {
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
                    if c.listen != config.listen || c.relay.max_tunnels != config.relay.max_tunnels {
                        warn!("listen and relay.max_tunnels take effect after a restart");
                    }
                }
                Err(e) => warn!("not reloading, configuration is invalid: {e:#}"),
            },
            _ = sigterm.recv() => { info!("SIGTERM received, shutting down"); break; }
            _ = tokio::signal::ctrl_c() => { info!("interrupted, shutting down"); break; }
        }
    }
    reload_task.abort();
    tcp_task.abort();
    quic_task.abort();
    endpoint.close(0u32.into(), b"server shutting down");
    let _ = tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle()).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
