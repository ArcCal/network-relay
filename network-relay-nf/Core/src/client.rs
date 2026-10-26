//! Relay protocols over native byte streams. Production network operations
//! are requested through the bridge; rustls/Quinn are test-only backends.
use crate::{
    native, proto,
    stream::{ConnectionKeep, Keep, Stream},
};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use http::{
    Method, Request, StatusCode,
    header::{AUTHORIZATION, CONNECTION, HOST, UPGRADE},
};
use http_body_util::Empty;
use hyper_util::rt::TokioIo;
use std::{
    error::Error as _, future::Future, net::SocketAddr, sync::Arc, task::Poll, time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, watch},
};

const WAIT: Duration = Duration::from_secs(10);
// The server can spend 5 seconds resolving and 10 seconds connecting a
// destination. That delay must not be mistaken for a broken outer transport.
const RESPONSE_WAIT: Duration = Duration::from_secs(20);
// The readiness probe sends no application datagrams. Refresh it before the
// Rust server's minimum supported UDP idle expiry (120 seconds), without
// changing any independent SOCKS flow or generating Internet probe traffic.
const PROBE_RENEW: Duration = Duration::from_secs(60);
const STABLE_SESSION: Duration = Duration::from_secs(30);
// Flows on a shared HTTP/2 connection share its receive window. Each stream
// window (2 MiB) still bounds what an unread flow buffers, so the connection
// window is set to the protocol maximum: stalled flows must not use up the
// credit of every other flow on the connection (RFC 9113 section 6.9).
const H2_CONNECTION_WINDOW: u32 = (1 << 31) - 1;

#[derive(Debug, thiserror::Error)]
#[error(
    "relay rejected request with HTTP {0}; check credentials, destination policy and server template"
)]
pub struct Rejected(pub StatusCode);

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
    pub probe_target: SocketAddr,
}
struct H2Session {
    sender: Mutex<h2::client::SendRequest<Bytes>>,
    keep: ConnectionKeep,
}
struct H3Session {
    sender: Mutex<h3::client::SendRequest<crate::quic::Opener, Bytes>>,
    keep: ConnectionKeep,
}
enum TcpSession {
    H1(native::Io),
    H2(Arc<H2Session>),
}
pub struct Opened {
    pub stream: Stream,
    pub transport: &'static str,
}
impl Client {
    pub fn new(config: &crate::Config, bridge: Arc<native::Bridge>) -> Result<Self> {
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
        tokio::time::timeout(WAIT * 3, self.open_inner(host, port, udp))
            .await
            .context("relay CONNECT timed out")?
    }
    async fn open_inner(&self, host: &str, port: u16, udp: bool) -> Result<Opened> {
        let selected = self.selected.borrow().clone();
        let mode = selected.as_deref().unwrap_or(&self.transport);
        if mode == "h3" {
            let session = self.h3_session().await?;
            self.h3_settings(&session, udp).await?;
            return self.open_h3(session, host, port, udp).await;
        }
        if mode == "auto" {
            // Only connection establishment and capability negotiation are
            // eligible for fallback. Never replay an already submitted CONNECT
            // because its destination is slow or the relay rejects it.
            let setup = async {
                let session = self.h3_session().await?;
                self.h3_settings(&session, udp).await?;
                Ok::<_, anyhow::Error>(session)
            };
            match tokio::time::timeout(Duration::from_secs(5), setup).await {
                Ok(Ok(session)) => return self.open_h3(session, host, port, udp).await,
                Ok(Err(e)) if terminal(&e) => return Err(e),
                _ => tracing::warn!("HTTP/3 unavailable; trying native TCP"),
            }
        }
        match self.tcp_session(mode).await? {
            TcpSession::H1(io) => self.open_h1(io, host, port, udp).await,
            TcpSession::H2(session) => self.open_h2(session, host, port, udp).await,
        }
    }
    async fn tcp_session(&self, mode: &str) -> Result<TcpSession> {
        // Classic HTTP/1.1 CONNECT consumes its TLS connection; it has no
        // pooled session and must not queue behind another TLS handshake.
        if mode == "http/1.1" {
            let io =
                tokio::time::timeout(WAIT, self.bridge.tcp(self.options(&["http/1.1"]))).await??;
            ensure!(
                io.ready.alpn == "http/1.1",
                "server did not negotiate the requested ALPN"
            );
            return Ok(TcpSession::H1(io));
        }
        let mut cache = tokio::time::timeout(WAIT, self.h2.lock())
            .await
            .context("HTTP/2 connection setup busy")?;
        if mode != "http/1.1" {
            if let Some(session) = cache.as_ref() {
                let mut sender = session.sender.lock().await;
                // The cached sender is never used to submit HEADERS: only
                // clones are. Its pending-open slot stays empty, so this
                // health check cannot replace a live request's wake-up.
                let closed = !self.native_session_open(&session.keep)
                    || session.keep.tasks[0].is_finished()
                    || matches!(
                        sender.poll_ready(&mut std::task::Context::from_waker(
                            std::task::Waker::noop()
                        )),
                        Poll::Ready(Err(_))
                    );
                if !closed {
                    return Ok(TcpSession::H2(session.clone()));
                }
            }
            *cache = None;
        }
        let alpn = match mode {
            "h2" => vec!["h2"],
            "http/1.1" => vec!["http/1.1"],
            _ => vec!["h2", "http/1.1"],
        };
        let io = tokio::time::timeout(WAIT, self.bridge.tcp(self.options(&alpn))).await??;
        let chosen = io.ready.alpn.clone();
        match chosen.as_str() {
            "h2" if mode != "http/1.1" => {
                let session = self.connect_h2(io).await?;
                *cache = Some(session.clone());
                Ok(TcpSession::H2(session))
            }
            "http/1.1" if mode != "h2" => Ok(TcpSession::H1(io)),
            _ => anyhow::bail!("server did not negotiate the requested ALPN"),
        }
    }
    fn native_session_open(&self, keep: &ConnectionKeep) -> bool {
        keep.lease.as_ref().is_some_and(|lease| {
            self.bridge
                .resources
                .lock()
                .unwrap()
                .contains_key(&lease.id)
        })
    }
    async fn connect_h2(&self, io: native::Io) -> Result<Arc<H2Session>> {
        let lease = io.lease.clone();
        let mut builder = h2::client::Builder::new();
        builder
            .initial_window_size(2 << 20)
            .initial_connection_window_size(H2_CONNECTION_WINDOW)
            .max_header_list_size(16384);
        let (sender, connection) =
            tokio::time::timeout(WAIT, builder.handshake::<_, Bytes>(io)).await??;
        let mut keep = ConnectionKeep::default();
        keep.lease = Some(lease);
        keep.tasks.push(tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::debug!("HTTP/2 connection ended: {e}");
            }
        }));
        Ok(Arc::new(H2Session {
            sender: Mutex::new(sender),
            keep,
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
                        !session.keep.tasks[0].is_finished(),
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
        let response = tokio::time::timeout(RESPONSE_WAIT, response)
            .await
            .context("no HTTP/2 CONNECT response")??;
        check(response.status(), response.headers(), udp, StatusCode::OK)?;
        let keep = Keep {
            connection: Some(session),
            tasks: Vec::new(),
        };
        Ok(Opened {
            stream: Stream::h2(send, response.into_body(), keep),
            transport: "HTTP/2",
        })
    }
    async fn open_h1(&self, io: native::Io, host: &str, port: u16, udp: bool) -> Result<Opened> {
        let (mut sender, mut connection) = tokio::time::timeout(
            WAIT,
            hyper::client::conn::http1::handshake(TokioIo::new(io)),
        )
        .await??;
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
        // Take the connection back manually after the response. Hyper's
        // automatic upgrade excludes 204 before checking the CONNECT method,
        // even though every 2xx establishes a classic CONNECT tunnel.
        let mut pending = std::pin::pin!(sender.send_request(request));
        let mut driver_error = None;
        let response = tokio::time::timeout(
            RESPONSE_WAIT,
            std::future::poll_fn(|cx| {
                if let Poll::Ready(result) = pending.as_mut().poll(cx) {
                    return Poll::Ready(result.map_err(anyhow::Error::from));
                }
                let driven = connection.poll_without_shutdown(cx);
                // Driving can deliver the response and then notice bytes of
                // a 204 tunnel as unsolicited HTTP. The response determines
                // the handoff; into_parts retains those buffered bytes.
                if let Poll::Ready(result) = pending.as_mut().poll(cx) {
                    if let Poll::Ready(Err(error)) = driven {
                        driver_error = Some(error);
                    }
                    return Poll::Ready(result.map_err(anyhow::Error::from));
                }
                match driven {
                    Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
                    Poll::Ready(Ok(())) => {
                        Poll::Ready(Err(anyhow::anyhow!("HTTP/1.1 closed before response")))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }),
        )
        .await??;
        let expected = if udp {
            StatusCode::SWITCHING_PROTOCOLS
        } else {
            StatusCode::OK
        };
        check(response.status(), response.headers(), udp, expected)?;
        if udp {
            ensure!(
                response
                    .headers()
                    .get(UPGRADE)
                    .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"connect-udp"))
                    && response.headers().get_all(UPGRADE).iter().count() == 1,
                "missing CONNECT-UDP Upgrade response"
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
        let parts = connection.into_parts();
        if let Some(error) = driver_error {
            // Only classic CONNECT 204 can reach Hyper's idle-HTTP check
            // after a successful tunnel response. Its buffered payload is
            // not an HTTP error. Preserve errors with a transport cause and
            // errors from every other response instead of masking them.
            if udp
                || response.status() != StatusCode::NO_CONTENT
                || parts.read_buf.is_empty()
                || error.source().is_some()
            {
                return Err(error.into());
            }
        }
        let mut io = parts.io.into_inner();
        // A peer can respond before the bridge acknowledges the request
        // write. Drain that acknowledgement before exposing tunnel writes.
        tokio::time::timeout(WAIT, io.flush()).await??;
        io.prepend(parts.read_buf);
        Ok(Opened {
            stream: Stream::new(io, Keep::default()),
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
            if self.native_session_open(&session.keep)
                && !session.keep.tasks[0].is_finished()
                && sender.get_conn_error().is_none()
                && !sender.is_closing()
            {
                return Ok(session.clone());
            }
        }
        *cache = None;
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
        let mut keep = ConnectionKeep::default();
        keep.lease = Some(lease);
        keep.h3_driver = Some(driver.clone());
        keep.tasks.push(tokio::spawn(async move {
            let error = std::future::poll_fn(|cx| driver.lock().unwrap().poll_close(cx)).await;
            tracing::debug!("HTTP/3 connection driver ended: {error}");
        }));
        let session = Arc::new(H3Session {
            sender: Mutex::new(sender),
            keep,
        });
        *cache = Some(session.clone());
        Ok(session)
    }
    async fn h3_settings(&self, session: &H3Session, udp: bool) -> Result<()> {
        if udp {
            use h3::ConnectionState;
            let mut sender = tokio::time::timeout(WAIT, session.sender.lock())
                .await
                .context("HTTP/3 capability negotiation busy")?;
            let waiter = &mut sender;
            let driver_task = &session.keep.tasks[0];
            tokio::time::timeout(WAIT, async move {
                while !waiter.settings().enable_extended_connect() {
                    ensure!(
                        !driver_task.is_finished(),
                        "HTTP/3 closed before Extended CONNECT settings"
                    );
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Ok::<_, anyhow::Error>(())
            })
            .await
            .context("server did not enable HTTP/3 Extended CONNECT")??;
        }
        Ok(())
    }
    async fn open_h3(
        &self,
        mut session: Arc<H3Session>,
        host: &str,
        port: u16,
        udp: bool,
    ) -> Result<Opened> {
        use h3::ConnectionState;
        let mut retried = false;
        let mut stream = loop {
            let mut sender = tokio::time::timeout(WAIT, session.sender.lock())
                .await
                .context("HTTP/3 request submission timed out")?;
            let mut request = self.request(host, port, udp)?;
            if udp {
                request
                    .extensions_mut()
                    .insert(h3::ext::Protocol::CONNECT_UDP);
            }
            let result = tokio::time::timeout(WAIT, sender.send_request(request)).await?;
            let closing = sender.is_closing();
            // Headers submission is serialized, not the destination response
            // or tunnel lifetime; unrelated requests continue concurrently.
            drop(sender);
            match result {
                Ok(stream) => break stream,
                Err(h3::error::StreamError::Undefined(error))
                    if !retried && !closing && error.is::<crate::quic::RequestNotSubmitted>() =>
                {
                    // A native group can fail between the cache health check
                    // and stream creation. The typed adapter error proves no
                    // HEADERS were sent, so one fresh same-protocol attempt
                    // is safe. Never replay response or stream-write errors.
                    let mut cache = self.h3.lock().await;
                    if cache
                        .as_ref()
                        .is_some_and(|cached| Arc::ptr_eq(cached, &session))
                    {
                        *cache = None;
                    }
                    drop(cache);
                    session = self.h3_session().await?;
                    self.h3_settings(&session, udp).await?;
                    retried = true;
                }
                Err(error) => return Err(error.into()),
            }
        };
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
    // Classic CONNECT accepts every 2xx (RFC 9110 section 9.3.6), as does
    // Extended CONNECT-UDP (RFC 9298 section 3.5). HTTP/1.1 CONNECT-UDP
    // instead uses GET plus Upgrade and must receive 101 (section 3.3).
    let successful = if expected == StatusCode::SWITCHING_PROTOCOLS {
        status == expected
    } else {
        status.is_success()
    };
    if !successful {
        return Err(Rejected(status).into());
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
    fn temporary_relay_refusals_are_retried() {
        for code in [502, 503, 504] {
            let refusal = Rejected(StatusCode::from_u16(code).unwrap());
            assert!(!terminal(&refusal.into()), "HTTP {code} is temporary");
        }
        for code in [400, 401, 403, 404, 405, 407, 500, 501] {
            let refusal = Rejected(StatusCode::from_u16(code).unwrap());
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
