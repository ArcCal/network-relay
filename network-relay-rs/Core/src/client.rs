//! Relay protocols over Rust byte streams. Production network operations
//! are provided by the Tokio/rustls/Quinn backend through a bounded bridge.
use crate::{
    native, proto,
    stream::{H3Keep, Keep, Stream},
};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use http::{
    Method, Request, StatusCode,
    header::{AUTHORIZATION, CONNECTION, HOST, UPGRADE},
};
use http_body_util::Empty;
use hyper_util::rt::TokioIo;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, watch},
};

const WAIT: Duration = Duration::from_secs(10);
// The readiness probe sends no application datagrams. Refresh it before the
// Rust server's minimum supported UDP idle expiry (120 seconds), without
// changing any independent SOCKS flow or generating Internet probe traffic.
const PROBE_RENEW: Duration = Duration::from_secs(60);
const STABLE_SESSION: Duration = Duration::from_secs(30);
// One session accepts new requests; older GOAWAY sessions may still carry
// active flows. Bound those connections too, rather than creating one per flow.
const H3_CONNECTIONS: usize = 4;
// Flows on a shared HTTP/2 connection share its receive window. Each stream
// window (2 MiB) still bounds what an unread flow buffers, so the connection
// window is set to the protocol maximum: stalled flows must not use up the
// credit of every other flow on the connection (RFC 9113 section 6.9).
const H2_CONNECTION_WINDOW: u32 = (1 << 31) - 1;
// A shared connection can stop carrying packets without a TCP error, after a
// network change for example. PING it as QUIC keeps its connection alive, and
// end it when a PING is not answered, so new flows open a working connection.
const H2_KEEPALIVE: Duration = Duration::from_secs(20);

/// A relay's refusal of a request: its status code and, when the relay sent
/// a Proxy-Status field (RFC 9209), the reason it gave.
#[derive(Debug)]
pub struct Rejected(pub StatusCode, pub Option<String>);

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.1 {
            Some(reason) => write!(
                f,
                "relay refused the request with HTTP {}: {reason}",
                self.0
            ),
            None => write!(
                f,
                "relay rejected request with HTTP {}; check credentials, destination policy and server template",
                self.0
            ),
        }
    }
}

impl std::error::Error for Rejected {}

/// The reason in a Proxy-Status response field (RFC 9209 section 2): the
/// `error` parameter of the last member that has one, which is the
/// intermediary closest to this client, followed by its `details`. Only
/// printable ASCII is kept and the result is bounded, because the text comes
/// from the network and is shown in the interface and the log.
fn proxy_status_reason(headers: &http::HeaderMap) -> Option<String> {
    fn split_outside_quotes(value: &str, separator: char) -> Vec<&str> {
        let (mut parts, mut start, mut quoted, mut escaped) = (Vec::new(), 0, false, false);
        for (i, c) in value.char_indices() {
            match c {
                _ if escaped => escaped = false,
                '\\' if quoted => escaped = true,
                '"' => quoted = !quoted,
                _ if c == separator && !quoted => {
                    parts.push(&value[start..i]);
                    start = i + 1;
                }
                _ => {}
            }
        }
        parts.push(&value[start..]);
        parts
    }
    fn unquote(value: &str) -> String {
        let value = value.trim();
        let Some(inner) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) else {
            return value.to_string();
        };
        let (mut out, mut escaped) = (String::new(), false);
        for c in inner.chars() {
            if !escaped && c == '\\' {
                escaped = true;
            } else {
                out.push(c);
                escaped = false;
            }
        }
        out
    }
    let joined = headers
        .get_all("proxy-status")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(",");
    let reason = split_outside_quotes(&joined, ',')
        .into_iter()
        .rev()
        .find_map(|member| {
            let (mut error, mut details) = (None, None);
            for param in split_outside_quotes(member, ';').into_iter().skip(1) {
                if let Some((key, value)) = param.split_once('=') {
                    match key.trim() {
                        "error" => error = Some(unquote(value)),
                        "details" => details = Some(unquote(value)),
                        _ => {}
                    }
                }
            }
            let error = error.filter(|e| !e.is_empty())?;
            Some(match details.filter(|d| !d.is_empty()) {
                Some(details) => format!("{error} ({details})"),
                None => error,
            })
        })?;
    let clean: String = reason
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(200)
        .collect();
    (!clean.is_empty()).then_some(clean)
}

pub struct Client {
    pub bridge: Arc<native::Bridge>,
    template: proto::UriTemplate,
    authority: http::uri::Authority,
    certificate_name: String,
    authorization: http::HeaderValue,
    transport: String,
    selected: watch::Sender<Option<String>>,
    h2: Mutex<Option<Arc<H2Session>>>,
    h3: Mutex<Option<Arc<H3Session>>>,
    h3_slots: Arc<Semaphore>,
    pub probe_target: SocketAddr,
}
// Independent CONNECT streams share one HTTP/2 connection. Flows retain it
// through `Keep::connection` after a closed session leaves the cache.
struct H2Session {
    sender: Mutex<h2::client::SendRequest<Bytes>>,
    task: tokio::task::JoinHandle<()>,
    lease: Arc<native::Lease>,
}
impl Drop for H2Session {
    fn drop(&mut self) {
        self.task.abort();
    }
}
struct H3Session {
    sender: Mutex<h3::client::SendRequest<crate::quic::Opener, Bytes>>,
    keep: H3Keep,
    _slot: OwnedSemaphorePermit,
}
pub struct Opened {
    pub stream: Stream,
    pub transport: &'static str,
}
impl Client {
    pub fn new(config: &crate::Config, bridge: Arc<native::Bridge>) -> Result<Self> {
        config.validate()?;
        use base64::Engine;
        let template = proto::UriTemplate::parse(&config.uri_template)?;
        ensure!(
            template.has_variable("target_host") && template.has_variable("target_port"),
            "CONNECT-UDP template needs target_host and target_port"
        );
        template.check_round_trip()?;
        let rest = config
            .uri_template
            .strip_prefix("https://")
            .context("relay must use HTTPS")?;
        let authority: http::uri::Authority = rest
            .split('/')
            .next()
            .context("missing relay authority")?
            .parse()?;
        ensure!(
            !config.username.is_empty() && !config.password.is_empty(),
            "relay account is incomplete"
        );
        ensure!(
            config.username.len() <= 64
                && !config.username.starts_with('.')
                && config
                    .username
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_ .".contains(&c) && c != b' '),
            "invalid relay username"
        );
        ensure!(
            config.password.len() <= 1024 && !config.password.chars().any(char::is_control),
            "invalid relay password"
        );
        let mut authorization = http::HeaderValue::from_str(&format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", config.username, config.password))
        ))?;
        authorization.set_sensitive(true);
        let certificate_name = config
            .server_name
            .clone()
            .unwrap_or_else(|| authority.host().trim_matches(['[', ']']).into());
        let (selected, _) = watch::channel(None);
        Ok(Self {
            bridge,
            template,
            authority,
            certificate_name,
            authorization,
            transport: config.transport.clone(),
            selected,
            h2: Mutex::new(None),
            h3: Mutex::new(None),
            h3_slots: Arc::new(Semaphore::new(H3_CONNECTIONS)),
            probe_target: config.probe_target,
        })
    }
    fn options(&self, alpn: &[&str]) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"host":self.authority.host().trim_matches(['[', ']']),"port":self.authority.port_u16().unwrap_or(443),"server_name":self.certificate_name,"alpn":alpn})).unwrap()
    }
    fn request(&self, host: &str, port: u16, udp: bool) -> Result<Request<()>> {
        let uri = if udp {
            let path = self
                .template
                .expand(&[("target_host", host), ("target_port", &port.to_string())]);
            format!("https://{}{path}", self.authority)
        } else if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let mut builder = Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .header(AUTHORIZATION, &self.authorization);
        if udp {
            builder = builder.header(proto::CAPSULE_PROTOCOL_HEADER, "?1");
        }
        Ok(builder.body(())?)
    }
    pub async fn open(&self, host: &str, port: u16, udp: bool) -> Result<Opened> {
        ensure!(
            port != 0
                && !host.is_empty()
                && host.len() <= 253
                && host
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-._:".contains(&c)),
            "invalid target host or port"
        );
        let selected = self.selected.borrow().clone();
        let mode = selected.as_deref().unwrap_or(&self.transport);
        if mode == "h3" {
            return tokio::time::timeout(WAIT * 3, self.open_h3(host, port, udp))
                .await
                .context("HTTP/3 connect timed out")?;
        }
        if mode == "auto" {
            // Fallback is limited to setup. Never replay a CONNECT whose
            // HEADERS may already have reached the server.
            let setup = async {
                let session = self.h3_session().await?;
                self.h3_settings(&session, udp).await?;
                Ok::<_, anyhow::Error>(session)
            };
            match tokio::time::timeout(Duration::from_secs(5), setup).await {
                Ok(Ok(session)) => {
                    return tokio::time::timeout(
                        WAIT * 3,
                        self.h3_request(session, host, port, udp),
                    )
                    .await
                    .context("HTTP/3 connect timed out")?;
                }
                Ok(Err(e)) if terminal(&e) => return Err(e),
                _ => tracing::warn!("HTTP/3 unavailable; trying Rust TCP"),
            }
        }
        tokio::time::timeout(WAIT * 3, self.open_tcp(host, port, udp, mode))
            .await
            .context("TCP connect timed out")?
    }
    async fn open_tcp(&self, host: &str, port: u16, udp: bool, mode: &str) -> Result<Opened> {
        // Classic HTTP/1.1 CONNECT consumes its TLS connection, so it has no
        // shared session and does not wait behind another handshake.
        if mode == "http/1.1" {
            let io =
                tokio::time::timeout(WAIT, self.bridge.tcp(self.options(&["http/1.1"]))).await??;
            ensure!(
                io.ready.alpn == "http/1.1",
                "server did not negotiate the requested ALPN"
            );
            return self.open_h1(io, host, port, udp).await;
        }
        let mut cache = tokio::time::timeout(WAIT, self.h2.lock())
            .await
            .context("HTTP/2 connection setup busy")?;
        if let Some(session) = cache.as_ref() {
            let mut sender = session.sender.lock().await;
            // Only clones of the cached sender submit HEADERS, so this check
            // cannot replace the wake-up of a live request. h2 reports a
            // received GOAWAY or a connection error here.
            let open = self
                .bridge
                .resources
                .lock()
                .unwrap()
                .contains_key(&session.lease.id)
                && !session.task.is_finished()
                && !matches!(
                    sender
                        .poll_ready(&mut std::task::Context::from_waker(std::task::Waker::noop())),
                    std::task::Poll::Ready(Err(_))
                );
            if open {
                let session = session.clone();
                drop(sender);
                drop(cache);
                return self.open_h2(session, host, port, udp).await;
            }
        }
        *cache = None;
        let alpn = if mode == "h2" {
            vec!["h2"]
        } else {
            vec!["h2", "http/1.1"]
        };
        let io = tokio::time::timeout(WAIT, self.bridge.tcp(self.options(&alpn))).await??;
        match io.ready.alpn.as_str() {
            "h2" => {
                let session = self.connect_h2(io).await?;
                *cache = Some(session.clone());
                drop(cache);
                self.open_h2(session, host, port, udp).await
            }
            "http/1.1" if mode != "h2" => {
                drop(cache);
                self.open_h1(io, host, port, udp).await
            }
            _ => anyhow::bail!("server did not negotiate the requested ALPN"),
        }
    }
    async fn connect_h2(&self, io: native::Io) -> Result<Arc<H2Session>> {
        let lease = io.lease.clone();
        let mut builder = h2::client::Builder::new();
        builder
            .initial_window_size(2 << 20)
            .initial_connection_window_size(H2_CONNECTION_WINDOW)
            .max_header_list_size(16384);
        let (sender, mut connection) =
            tokio::time::timeout(WAIT, builder.handshake::<_, Bytes>(io)).await??;
        let mut ping = connection.ping_pong().context("HTTP/2 PING unavailable")?;
        let task = tokio::spawn(async move {
            let keepalive = async {
                loop {
                    tokio::time::sleep(H2_KEEPALIVE).await;
                    match tokio::time::timeout(H2_KEEPALIVE, ping.ping(h2::Ping::opaque())).await {
                        Ok(Ok(_)) => {}
                        Ok(Err(e)) => return e.to_string(),
                        Err(_) => return "PING not answered".to_string(),
                    }
                }
            };
            tokio::select! {
                result = connection => if let Err(e) = result {
                    tracing::debug!("HTTP/2 connection ended: {e}");
                },
                reason = keepalive => tracing::debug!("HTTP/2 connection closed: {reason}"),
            }
        });
        Ok(Arc::new(H2Session {
            sender: Mutex::new(sender),
            task,
            lease,
        }))
    }
    async fn open_h2(
        &self,
        session: Arc<H2Session>,
        host: &str,
        port: u16,
        udp: bool,
    ) -> Result<Opened> {
        let mut sender = session.sender.lock().await.clone();
        if udp {
            tokio::time::timeout(WAIT, async {
                while !sender.is_extended_connect_protocol_enabled() {
                    ensure!(
                        !session.task.is_finished(),
                        "HTTP/2 closed before Extended CONNECT settings"
                    );
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Ok::<_, anyhow::Error>(())
            })
            .await
            .context("server did not enable HTTP/2 Extended CONNECT")??;
        }
        sender = tokio::time::timeout(WAIT, sender.ready())
            .await
            .context("HTTP/2 stream capacity timed out")??;
        let mut request = self.request(host, port, udp)?;
        if udp {
            request
                .extensions_mut()
                .insert(h2::ext::Protocol::from_static(proto::CONNECT_UDP_PROTOCOL));
        }
        let (response, send) = sender.send_request(request, false)?;
        let response = tokio::time::timeout(WAIT, response).await??;
        check(response.status(), response.headers(), udp, StatusCode::OK)?;
        let keep = Keep {
            connection: Some(session),
            tasks: Vec::new(),
            sender: None,
            lease: None,
        };
        Ok(Opened {
            stream: Stream::h2(send, response.into_body(), keep),
            transport: "HTTP/2",
        })
    }
    async fn open_h1(&self, io: native::Io, host: &str, port: u16, udp: bool) -> Result<Opened> {
        let (mut sender, connection) = tokio::time::timeout(
            WAIT,
            hyper::client::conn::http1::handshake(TokioIo::new(io)),
        )
        .await??;
        let mut keep = Keep::default();
        keep.tasks.push(tokio::spawn(async move {
            if let Err(e) = connection.with_upgrades().await {
                tracing::debug!("HTTP/1.1 connection ended: {e}");
            }
        }));
        let request = if udp {
            Request::builder()
                .method(Method::GET)
                .uri(
                    self.template
                        .expand(&[("target_host", host), ("target_port", &port.to_string())]),
                )
                .header(HOST, self.authority.as_str())
                .header(AUTHORIZATION, &self.authorization)
                .header(CONNECTION, "Upgrade")
                .header(UPGRADE, proto::CONNECT_UDP_PROTOCOL)
                .header(proto::CAPSULE_PROTOCOL_HEADER, "?1")
                .body(Empty::<Bytes>::new())?
        } else {
            let request = self.request(host, port, false)?;
            let (parts, _) = request.into_parts();
            let mut request = Request::from_parts(parts, Empty::<Bytes>::new());
            let host_header = request.uri().authority().unwrap().as_str().parse()?;
            request.headers_mut().insert(HOST, host_header);
            request
        };
        let mut response = tokio::time::timeout(WAIT, sender.send_request(request)).await??;
        let expected = if udp {
            StatusCode::SWITCHING_PROTOCOLS
        } else {
            StatusCode::OK
        };
        check(response.status(), response.headers(), udp, expected)?;
        if udp {
            ensure!(
                single_udp_upgrade_header(response.headers()),
                "missing, invalid or repeated CONNECT-UDP Upgrade response"
            );
            ensure!(
                response
                    .headers()
                    .get(CONNECTION)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v
                        .split(',')
                        .any(|x| x.trim().eq_ignore_ascii_case("upgrade"))),
                "missing Connection: Upgrade response"
            );
        }
        let io = tokio::time::timeout(WAIT, hyper::upgrade::on(&mut response)).await??;
        keep.sender = Some(Box::new(sender));
        Ok(Opened {
            stream: Stream::new(TokioIo::new(io), keep),
            transport: "HTTP/1.1",
        })
    }
    async fn h3_session(&self) -> Result<Arc<H3Session>> {
        use h3::ConnectionState;
        let mut cache = tokio::time::timeout(WAIT, self.h3.lock())
            .await
            .context("HTTP/3 connection setup busy")?;
        if let Some(session) = cache.as_ref() {
            let sender = tokio::time::timeout(WAIT, session.sender.lock())
                .await
                .context("HTTP/3 request submission busy")?;
            if self
                .bridge
                .resources
                .lock()
                .unwrap()
                .contains_key(&session.keep.lease.id)
                && !session.keep.task.is_finished()
                && sender.get_conn_error().is_none()
                && !sender.is_closing()
            {
                return Ok(session.clone());
            }
        }
        *cache = None;
        let slot = tokio::time::timeout(WAIT, self.h3_slots.clone().acquire_owned())
            .await
            .context("HTTP/3 connections are still draining")??;
        let native = tokio::time::timeout(
            WAIT,
            native::Quic::open(self.bridge.clone(), self.options(&["h3"])),
        )
        .await??;
        let lease = native.io.lease.clone();
        let mut builder = h3::client::builder();
        builder
            .enable_extended_connect(true)
            .enable_datagram(false)
            .send_grease(false)
            .max_field_section_size(16384);
        let (driver, sender) = tokio::time::timeout(
            WAIT,
            builder.build::<_, _, Bytes>(crate::quic::Connection::new(native)),
        )
        .await??;
        let driver = Arc::new(std::sync::Mutex::new(driver));
        let driven = driver.clone();
        let task = tokio::spawn(async move {
            let error = std::future::poll_fn(|cx| driven.lock().unwrap().poll_close(cx)).await;
            tracing::debug!("HTTP/3 connection driver ended: {error}");
        });
        let session = Arc::new(H3Session {
            sender: Mutex::new(sender),
            keep: H3Keep {
                task,
                lease,
                driver,
            },
            _slot: slot,
        });
        *cache = Some(session.clone());
        Ok(session)
    }
    async fn h3_settings(&self, session: &H3Session, udp: bool) -> Result<()> {
        if udp {
            use h3::ConnectionState;
            tokio::time::timeout(WAIT, async {
                loop {
                    let sender = session.sender.lock().await;
                    if sender.settings().enable_extended_connect() {
                        return Ok::<_, anyhow::Error>(());
                    }
                    ensure!(
                        !session.keep.task.is_finished(),
                        "HTTP/3 closed before Extended CONNECT settings"
                    );
                    drop(sender);
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .context("server did not enable HTTP/3 Extended CONNECT")??;
        }
        Ok(())
    }
    async fn open_h3(&self, host: &str, port: u16, udp: bool) -> Result<Opened> {
        let session = self.h3_session().await?;
        self.h3_settings(&session, udp).await?;
        self.h3_request(session, host, port, udp).await
    }
    async fn h3_request(
        &self,
        session: Arc<H3Session>,
        host: &str,
        port: u16,
        udp: bool,
    ) -> Result<Opened> {
        let mut request = self.request(host, port, udp)?;
        if udp {
            request
                .extensions_mut()
                .insert(h3::ext::Protocol::CONNECT_UDP);
        }
        let mut sender = tokio::time::timeout(WAIT, session.sender.lock())
            .await
            .context("HTTP/3 request submission busy")?;
        let mut stream = tokio::time::timeout(WAIT, sender.send_request(request))
            .await
            .context("HTTP/3 stream capacity timed out")??;
        // Serialize stream creation, not response waits or business traffic.
        drop(sender);
        tracing::debug!(
            sid = stream.id().into_inner(),
            "HTTP/3 request HEADERS sent; waiting for response"
        );
        let response = tokio::time::timeout(WAIT, stream.recv_response())
            .await
            .context("no HTTP/3 response")??;
        check(response.status(), response.headers(), udp, StatusCode::OK)?;
        let keep = Keep {
            connection: Some(session),
            tasks: Vec::new(),
            sender: None,
            lease: None,
        };
        Ok(Opened {
            stream: Stream::h3(stream, keep),
            transport: "HTTP/3",
        })
    }
    /// An authenticated idle UDP flow verifies server-side CONNECT-UDP
    /// admission. This is not an Internet reachability or continuous DNS test.
    pub async fn monitor(&self) -> Result<()> {
        let mut backoff = Duration::from_secs(1);
        let mut ready_since = None;
        loop {
            let result: Result<ProbeEnd> = async {
                let Opened { stream, transport } = self
                    .open(&self.probe_target.ip().to_string(), self.probe_target.port(), true)
                    .await?;
                let mode = match transport {
                    "HTTP/3" => "h3",
                    "HTTP/2" => "h2",
                    _ => "http/1.1",
                };
                self.selected.send_replace(Some(mode.into()));
                if ready_since.is_none() {
                    ready_since = Some(tokio::time::Instant::now());
                    self.bridge
                        .emit(native::STATUS, 0, 0, 1, format!("Relay ready; {transport}; authenticated CONNECT-UDP"))
                        .await?;
                    tracing::info!("Relay ready; {transport}; authenticated CONNECT-UDP (destination reachability is not implied)");
                } else {
                    tracing::debug!("Readiness probe refreshed; {transport}; existing SOCKS flows continue");
                }
                let mut flow = UdpFlow::new(stream);
                watch_probe(&mut flow).await
            }
            .await;
            match result {
                Ok(end) => {
                    // A planned renewal or clean peer FIN only retires the
                    // admission probe. Re-open it without a failure status.
                    tracing::debug!(?end, "Refreshing relay readiness probe");
                    if end == ProbeEnd::PeerFinished {
                        // Bound retry traffic if a peer repeatedly admits a
                        // request and immediately finishes it.
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    continue;
                }
                Err(e) => {
                    self.selected.send_replace(None);
                    if terminal(&e) {
                        return Err(e);
                    }
                    if ready_since
                        .take()
                        .is_some_and(|since| since.elapsed() >= STABLE_SESSION)
                    {
                        backoff = Duration::from_secs(1);
                    }
                    tracing::warn!("Relay session failed: {e:#}");
                    self.bridge
                        .emit(native::STATUS, 0, 0, 2, format!("{e:#}"))
                        .await?;
                }
            }
            tracing::info!("Reconnecting in {:.1}s", backoff.as_secs_f64());
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ProbeEnd {
    RenewalDue,
    PeerFinished,
}
async fn watch_probe(flow: &mut UdpFlow) -> Result<ProbeEnd> {
    let renewal = tokio::time::sleep(PROBE_RENEW);
    tokio::pin!(renewal);
    loop {
        tokio::select! {
            result = flow.recv() => {
                if result?.is_none() {
                    return Ok(ProbeEnd::PeerFinished);
                }
            }
            _ = &mut renewal => return Ok(ProbeEnd::RenewalDue),
        }
    }
}
/// Failures that retrying cannot fix: rejected credentials or requests, and
/// TLS security failures. A gateway failure or a full relay (502, 503, 504:
/// RFC 9110 sections 15.6.3 to 15.6.5) is temporary, so the monitor retries.
pub fn terminal(error: &anyhow::Error) -> bool {
    error.downcast_ref::<Rejected>().is_some_and(|r| {
        !matches!(
            r.0,
            StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT
        )
    }) || error.chain().any(|e| {
        e.downcast_ref::<std::io::Error>()
            .is_some_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
    })
}
fn check(
    status: StatusCode,
    headers: &http::HeaderMap,
    udp: bool,
    expected: StatusCode,
) -> Result<()> {
    // RFC 9110 section 9.3.6 and RFC 9298 section 3.5 define successful
    // CONNECT responses as any 2xx. HTTP/1.1 CONNECT-UDP Upgrade instead
    // requires exactly 101 (RFC 9298 section 3.3).
    let successful = if expected == StatusCode::SWITCHING_PROTOCOLS {
        status == expected
    } else {
        status.is_success()
    };
    if !successful {
        return Err(Rejected(status, proxy_status_reason(headers)).into());
    }
    if udp {
        ensure!(
            proto::capsule_protocol_enabled(headers),
            "relay did not negotiate Capsule Protocol"
        );
        ensure!(
            proto::valid_capsule_headers(headers),
            "content headers on CONNECT-UDP response"
        );
    }
    Ok(())
}

/// RFC 9298 section 3.3 requires one Upgrade field containing connect-udp.
fn single_udp_upgrade_header(headers: &http::HeaderMap) -> bool {
    let mut values = headers.get_all(UPGRADE).iter();
    let Some(value) = values.next() else {
        return false;
    };
    values.next().is_none()
        && value
            .as_bytes()
            .trim_ascii()
            .eq_ignore_ascii_case(b"connect-udp")
}

#[cfg(test)]
mod response_tests {
    use super::*;

    #[test]
    fn connect_accepts_the_entire_successful_status_range() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            proto::CAPSULE_PROTOCOL_HEADER,
            "?1;future=42".parse().unwrap(),
        );
        for status in [200, 201, 204, 299] {
            let status = StatusCode::from_u16(status).unwrap();
            assert!(check(status, &headers, false, StatusCode::OK).is_ok());
            assert!(check(status, &headers, true, StatusCode::OK).is_ok());
        }
        for status in [101, 199, 300, 401, 404, 500] {
            let status = StatusCode::from_u16(status).unwrap();
            assert!(check(status, &headers, false, StatusCode::OK).is_err());
            assert!(check(status, &headers, true, StatusCode::OK).is_err());
        }
    }

    #[test]
    fn http1_udp_upgrade_requires_101_and_valid_capsule_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert(proto::CAPSULE_PROTOCOL_HEADER, "?1;future".parse().unwrap());
        assert!(
            check(
                StatusCode::SWITCHING_PROTOCOLS,
                &headers,
                true,
                StatusCode::SWITCHING_PROTOCOLS
            )
            .is_ok()
        );
        for status in [200, 201, 204, 404] {
            assert!(
                check(
                    StatusCode::from_u16(status).unwrap(),
                    &headers,
                    true,
                    StatusCode::SWITCHING_PROTOCOLS
                )
                .is_err()
            );
        }
        headers.insert(proto::CAPSULE_PROTOCOL_HEADER, "?0".parse().unwrap());
        assert!(check(StatusCode::OK, &headers, true, StatusCode::OK).is_err());
        headers.insert(proto::CAPSULE_PROTOCOL_HEADER, "?1".parse().unwrap());
        headers.insert(http::header::CONTENT_LENGTH, "0".parse().unwrap());
        assert!(check(StatusCode::OK, &headers, true, StatusCode::OK).is_err());
    }

    #[test]
    fn http1_udp_requires_a_single_upgrade_field() {
        let mut headers = http::HeaderMap::new();
        assert!(!single_udp_upgrade_header(&headers));
        for value in ["connect-udp", "ConNeCt-UdP", " connect-udp "] {
            headers.insert(UPGRADE, value.parse().unwrap());
            assert!(single_udp_upgrade_header(&headers), "{value}");
        }
        for value in ["websocket", "connect-udp, websocket", "connect-udp/1"] {
            headers.insert(UPGRADE, value.parse().unwrap());
            assert!(!single_udp_upgrade_header(&headers), "{value}");
        }
        headers.insert(UPGRADE, "connect-udp".parse().unwrap());
        headers.append(UPGRADE, "connect-udp".parse().unwrap());
        assert!(!single_udp_upgrade_header(&headers));
    }
}

pub struct UdpFlow {
    pub stream: Stream,
    decoder: proto::CapsuleDecoder,
}
impl UdpFlow {
    pub fn new(stream: Stream) -> Self {
        Self {
            stream,
            decoder: proto::CapsuleDecoder::default(),
        }
    }
    pub async fn send(&mut self, payload: &[u8]) -> Result<()> {
        ensure!(payload.len() <= 65507, "UDP payload exceeds IPv4 maximum");
        let mut value = bytes::BytesMut::with_capacity(payload.len() + 1);
        value.extend_from_slice(&[0]);
        value.extend_from_slice(payload);
        let mut wire = bytes::BytesMut::new();
        proto::capsule::encode(0, &value, &mut wire);
        self.stream.write_all(&wire).await?;
        Ok(())
    }
    pub async fn recv(&mut self) -> Result<Option<Bytes>> {
        loop {
            if let Some(capsule) = self.decoder.next_udp_capsule()? {
                let mut payload = &capsule.value[..];
                if proto::varint::decode(&mut payload)? == 0 {
                    return Ok(Some(Bytes::copy_from_slice(payload)));
                }
                continue;
            }
            let mut bytes = [0; 16384];
            let count = self.stream.read(&mut bytes).await?;
            if count == 0 {
                self.decoder.finish()?;
                return Ok(None);
            }
            self.decoder.push(&bytes[..count]);
        }
    }
}

#[cfg(test)]
mod probe_tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn idle_probe_renews_without_sending_application_datagrams() {
        let (stream, mut peer) = tokio::io::duplex(128);
        let mut flow = UdpFlow::new(Stream::new(stream, Keep::default()));
        let started = tokio::time::Instant::now();
        assert_eq!(watch_probe(&mut flow).await.unwrap(), ProbeEnd::RenewalDue);
        assert_eq!(started.elapsed(), PROBE_RENEW);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), peer.read_u8())
                .await
                .is_err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn incoming_capsules_do_not_extend_the_probe_renewal_deadline() {
        let (stream, mut peer) = tokio::io::duplex(128);
        let waiting = tokio::spawn(async move {
            let mut flow = UdpFlow::new(Stream::new(stream, Keep::default()));
            watch_probe(&mut flow).await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(PROBE_RENEW - Duration::from_secs(1)).await;
        peer.write_all(&[0, 2, 0, b'a']).await.unwrap();
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(waiting.await.unwrap().unwrap(), ProbeEnd::RenewalDue);
    }

    #[tokio::test]
    async fn clean_peer_fin_is_a_probe_refresh() {
        let (stream, mut peer) = tokio::io::duplex(128);
        let mut flow = UdpFlow::new(Stream::new(stream, Keep::default()));
        peer.shutdown().await.unwrap();
        assert_eq!(
            watch_probe(&mut flow).await.unwrap(),
            ProbeEnd::PeerFinished
        );
    }

    #[test]
    fn refusals_show_the_proxy_status_reason() {
        let reason = |values: &[&str]| {
            let mut headers = http::HeaderMap::new();
            for v in values {
                headers.append("proxy-status", http::HeaderValue::from_str(v).unwrap());
            }
            proxy_status_reason(&headers)
        };
        assert_eq!(
            reason(&["network-relay; error=connection_limit_reached"]).as_deref(),
            Some("connection_limit_reached")
        );
        assert_eq!(
            reason(&["network-relay; error=dns_error; details=\"no addresses\""]).as_deref(),
            Some("dns_error (no addresses)")
        );
        assert_eq!(
            reason(&[
                "origin; error=http_request_error",
                "\"relay, one\"; error=connection_refused"
            ])
            .as_deref(),
            Some("connection_refused"),
            "the member closest to the client wins"
        );
        assert_eq!(reason(&["network-relay"]), None);
        assert_eq!(reason(&[]), None);
        assert_eq!(
            reason(&["r; error=x; details=\"a\\\"b\t\""])
                .as_deref()
                .map(str::len),
            Some(7),
            "escapes are decoded and control characters dropped"
        );
        let full = Rejected(
            StatusCode::SERVICE_UNAVAILABLE,
            Some("connection_limit_reached".into()),
        );
        assert_eq!(
            full.to_string(),
            "relay refused the request with HTTP 503 Service Unavailable: connection_limit_reached"
        );
        assert!(!terminal(&full.into()));
        let bare = Rejected(StatusCode::FORBIDDEN, None).to_string();
        assert!(bare.contains("check credentials"), "{bare}");
    }

    #[test]
    fn temporary_relay_refusals_are_retried() {
        for code in [502, 503, 504] {
            let refusal = Rejected(StatusCode::from_u16(code).unwrap(), None);
            assert!(!terminal(&refusal.into()), "HTTP {code} is temporary");
        }
        for code in [400, 401, 403, 404, 405, 407, 500, 501] {
            let refusal = Rejected(StatusCode::from_u16(code).unwrap(), None);
            assert!(terminal(&refusal.into()), "HTTP {code} needs the user");
        }
        let tls = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "certificate");
        assert!(terminal(&anyhow::Error::from(tls).context("TLS")));
        assert!(!terminal(&anyhow::anyhow!("timed out")));
    }

    #[tokio::test]
    async fn truncated_capsule_at_fin_remains_a_failure() {
        let (stream, mut peer) = tokio::io::duplex(128);
        let mut flow = UdpFlow::new(Stream::new(stream, Keep::default()));
        peer.write_all(&[0, 2, 0]).await.unwrap();
        peer.shutdown().await.unwrap();
        assert!(watch_probe(&mut flow).await.is_err());
    }
}
