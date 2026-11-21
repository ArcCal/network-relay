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
// The relay can spend five seconds resolving and ten seconds connecting a
// destination. Keep response waiting separate from transport setup deadlines.
const RESPONSE_WAIT: Duration = Duration::from_secs(20);
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
    endpoint: http::uri::Authority,
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
    extended_connect: watch::Receiver<Option<bool>>,
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
        let endpoint = authority.clone();
        // The numeric socket endpoint must not replace the relay's HTTP host.
        let authority = if config.server_name.is_some()
            && endpoint
                .host()
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok()
        {
            let host = if certificate_name.contains(':') {
                format!("[{}]", certificate_name.trim_matches(['[', ']']))
            } else {
                certificate_name.clone()
            };
            match endpoint.port_u16() {
                Some(port) => format!("{host}:{port}"),
                None => host,
            }
            .parse()?
        } else {
            authority
        };
        let (selected, _) = watch::channel(None);
        Ok(Self {
            bridge,
            template,
            authority,
            endpoint,
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
        serde_json::to_vec(&serde_json::json!({"host":self.endpoint.host().trim_matches(['[', ']']),"port":self.endpoint.port_u16().unwrap_or(443),"server_name":self.certificate_name,"alpn":alpn})).unwrap()
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
        let response = tokio::time::timeout(RESPONSE_WAIT, response).await??;
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
        let mut response =
            tokio::time::timeout(RESPONSE_WAIT, sender.send_request(request)).await??;
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
        let (settings_tx, extended_connect) = watch::channel(None);
        let task = tokio::spawn(async move {
            let mut pending_settings = Some(settings_tx);
            let error = std::future::poll_fn(|cx| {
                let mut driver = driven.lock().unwrap();
                let result = driver.poll_close(cx);
                // The pinned h3 implementation borrows the peer's once-only
                // SETTINGS and returns owned defaults until the frame arrives.
                if let Some(tx) = &pending_settings
                    && let std::borrow::Cow::Borrowed(settings) = driver.settings()
                {
                    tx.send_replace(Some(settings.enable_extended_connect()));
                    pending_settings = None;
                }
                result
            })
            .await;
            tracing::debug!("HTTP/3 connection driver ended: {error}");
        });
        let session = Arc::new(H3Session {
            extended_connect,
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
            let mut capability = session.extended_connect.clone();
            let enabled = tokio::time::timeout(WAIT, capability.wait_for(Option::is_some))
                .await
                .context("timed out waiting for HTTP/3 Extended CONNECT settings")?
                .context("HTTP/3 closed before Extended CONNECT settings")?;
            ensure!(
                *enabled == Some(true),
                "server did not enable HTTP/3 Extended CONNECT"
            );
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
        let response = tokio::time::timeout(RESPONSE_WAIT, stream.recv_response())
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
        // The connect-udp token defines capsule framing (RFC 9298 section
        // 3). Capsule-Protocol is only recommended metadata for
        // intermediaries, not another negotiation requirement (RFC 9297
        // section 3.4). Ignore it, including unknown parameters and values
        // that have the same semantics as an absent field.
        ensure!(
            !matches!(
                status,
                StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT | StatusCode::PARTIAL_CONTENT
            ),
            "invalid status on CONNECT-UDP capsule response"
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
    fn connect_and_connect_udp_have_distinct_success_statuses() {
        let headers = http::HeaderMap::new();
        for code in 100..600 {
            let status = StatusCode::from_u16(code).unwrap();
            assert_eq!(
                check(status, &headers, false, StatusCode::OK).is_ok(),
                (200..300).contains(&code),
                "classic CONNECT HTTP {code}"
            );
            assert_eq!(
                check(status, &headers, true, StatusCode::OK).is_ok(),
                (200..300).contains(&code) && ![204, 205, 206].contains(&code),
                "Extended CONNECT-UDP HTTP {code}"
            );
            assert_eq!(
                check(status, &headers, true, StatusCode::SWITCHING_PROTOCOLS).is_ok(),
                code == 101,
                "HTTP/1.1 CONNECT-UDP Upgrade HTTP {code}"
            );
        }
    }

    #[test]
    fn connect_udp_capsule_protocol_field_does_not_select_framing() {
        for values in [
            vec![],
            vec!["?1"],
            vec!["?1;future=token;flag;quoted=\"a,b\""],
            vec!["?0"],
            vec!["token"],
            vec!["?1junk"],
            vec!["?1;broken=\""],
            vec!["?1, ?1"],
            vec!["?1", "?1"],
            vec!["?0", "?1"],
        ] {
            let mut headers = http::HeaderMap::new();
            for value in &values {
                headers.append(proto::CAPSULE_PROTOCOL_HEADER, value.parse().unwrap());
            }
            for status in [StatusCode::OK, StatusCode::CREATED] {
                assert!(
                    check(status, &headers, true, StatusCode::OK).is_ok(),
                    "{values:?}"
                );
            }
            assert!(
                check(
                    StatusCode::SWITCHING_PROTOCOLS,
                    &headers,
                    true,
                    StatusCode::SWITCHING_PROTOCOLS
                )
                .is_ok(),
                "{values:?}"
            );
        }
    }

    #[test]
    fn connect_udp_rejects_content_metadata_even_without_capsule_protocol_field() {
        for (name, value) in [
            (http::header::CONTENT_LENGTH, "0"),
            (http::header::CONTENT_TYPE, "application/octet-stream"),
            (http::header::TRANSFER_ENCODING, "chunked"),
        ] {
            let mut headers = http::HeaderMap::new();
            headers.insert(name, value.parse().unwrap());
            for status in [StatusCode::OK, StatusCode::CREATED] {
                assert!(check(status, &headers, true, StatusCode::OK).is_err());
            }
            assert!(
                check(
                    StatusCode::SWITCHING_PROTOCOLS,
                    &headers,
                    true,
                    StatusCode::SWITCHING_PROTOCOLS
                )
                .is_err()
            );
        }
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
        // Encode the Capsule and context directly, avoiding an intermediate
        // allocation and a second copy of every UDP payload.
        let value_len = payload.len() as u64 + 1;
        let mut wire = bytes::BytesMut::with_capacity(
            1 + proto::varint::encoded_len(value_len) + value_len as usize,
        );
        proto::varint::encode(proto::capsule::types::DATAGRAM, &mut wire);
        proto::varint::encode(value_len, &mut wire);
        proto::varint::encode(proto::datagram::CONTEXT_ID_UDP_PAYLOAD, &mut wire);
        wire.extend_from_slice(payload);
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

    #[test]
    fn explicit_ip_keeps_socket_certificate_and_http_hosts_separate() {
        for transport in ["auto", "h3", "h2", "http/1.1"] {
            for (endpoint, ip, port, authority) in [
                (
                    "192.0.2.1:8443",
                    "192.0.2.1",
                    8443,
                    "relay.test.invalid:8443",
                ),
                (
                    "[2001:db8::1]:443",
                    "2001:db8::1",
                    443,
                    "relay.test.invalid:443",
                ),
                ("192.0.2.1", "192.0.2.1", 443, "relay.test.invalid"),
            ] {
                let config = test_config(endpoint, transport);
                let (events, _) = tokio::sync::mpsc::channel(16);
                let client = Client::new(&config, native::Bridge::new(events)).unwrap();
                let options: serde_json::Value =
                    serde_json::from_slice(&client.options(&["h3"])).unwrap();
                assert_eq!(options["host"], ip);
                assert_eq!(options["port"], port);
                assert_eq!(options["server_name"], "relay.test.invalid");
                let udp = client.request("website.test.invalid", 53, true).unwrap();
                assert_eq!(udp.uri().authority().unwrap().as_str(), authority);
                assert!(udp.uri().path().contains("/website.test.invalid/53/"));
                let tcp = client.request("website.test.invalid", 443, false).unwrap();
                assert_eq!(
                    tcp.uri().authority().unwrap().as_str(),
                    "website.test.invalid:443"
                );
            }
        }
    }

    fn test_config(endpoint: &str, transport: &str) -> crate::Config {
        toml::from_str(&format!(
            r#"
uri_template = "https://{endpoint}/.well-known/masque/udp/{{target_host}}/{{target_port}}/"
server_name = "relay.test.invalid"
username = "test"
password = "test-password"
mode = "socks"
transport = "{transport}"
[socks]
listen = ["127.0.0.1:1080"]
"#
        ))
        .unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_connection_timeouts_keep_monitoring_until_cancelled() {
        for (transport, kind) in [("h2", native::OPEN_TCP), ("h3", native::OPEN_QUIC)] {
            let (events, mut requests) = tokio::sync::mpsc::channel(32);
            let bridge = native::Bridge::new(events);
            let client =
                Client::new(&test_config("192.0.2.1:443", transport), bridge.clone()).unwrap();
            let monitor = tokio::spawn(async move { client.monitor().await });
            for _ in 0..4 {
                let opening = loop {
                    let event = tokio::time::timeout(Duration::from_secs(45), requests.recv())
                        .await
                        .unwrap()
                        .unwrap();
                    if event.kind == kind {
                        break event;
                    }
                };
                assert!(bridge.input(native::ERROR, opening.id, 0, 3, b"connection timed out"));
                loop {
                    let event = tokio::time::timeout(Duration::from_secs(45), requests.recv())
                        .await
                        .unwrap()
                        .unwrap();
                    if event.kind == native::STATUS {
                        assert_eq!(event.flags, 2, "a timeout must report a retry");
                        break;
                    }
                }
                assert!(!monitor.is_finished(), "a timeout must not end the client");
            }
            monitor.abort();
            assert!(monitor.await.unwrap_err().is_cancelled());
        }
    }

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

#[cfg(test)]
mod udp_send_tests {
    use super::*;

    #[tokio::test]
    async fn outgoing_capsules_preserve_empty_maximum_and_varint_boundary_payloads() {
        for size in [0, 1, 62, 63, 16_382, 16_383, 65_507] {
            let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let (stream, mut peer) = tokio::io::duplex(65_536);
            let mut flow = UdpFlow::new(Stream::new(stream, Keep::default()));
            flow.send(&payload).await.unwrap();
            let mut wire = vec![0; 2 + proto::varint::encoded_len(size as u64 + 1) + size];
            peer.read_exact(&mut wire).await.unwrap();
            let mut view = &wire[..];
            assert_eq!(proto::varint::decode(&mut view).unwrap(), 0);
            assert_eq!(proto::varint::decode(&mut view).unwrap(), size as u64 + 1);
            assert_eq!(proto::varint::decode(&mut view).unwrap(), 0);
            assert_eq!(view, payload);
        }
        let (stream, _peer) = tokio::io::duplex(128);
        let mut flow = UdpFlow::new(Stream::new(stream, Keep::default()));
        assert!(flow.send(&vec![0; 65_508]).await.is_err());
    }
}
