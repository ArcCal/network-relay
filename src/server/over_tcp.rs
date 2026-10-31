//! HTTP/2 and HTTP/1.1 over TLS on TCP.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use http::header::{ALT_SVC, CONNECTION, DATE, HOST, UPGRADE};
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tracing::{debug, warn};

use super::{http_date, pump, ConnInfo, Incoming, Kind, Opened, Relay, HEADER_TIMEOUT, MAX_STREAMS_HTTP2};
use crate::certs::CertStore;
use crate::policy::Refusal;
use crate::proto::{CAPSULE_PROTOCOL_HEADER, CONNECT_UDP_PROTOCOL};
use crate::tunnel::Tunnel;
use crate::{sys, tls, web};

/// TLS configuration for HTTP/2 and HTTP/1.1 over TCP.
pub fn tcp_tls_config(certs: Arc<CertStore>, client_certificates: bool) -> Result<Arc<rustls::ServerConfig>> {
    Ok(Arc::new(tls::server_config(certs, &[tls::ALPN_H2, tls::ALPN_HTTP11], true, client_certificates)?))
}

type Builder = hyper::server::conn::http1::Builder;

/// Whether an HTTP/1.1 request offers an upgrade to connect-udp.
fn asks_for_udp_upgrade<B>(req: &Request<B>) -> bool {
    req.headers()
        .get_all(UPGRADE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(CONNECT_UDP_PROTOCOL)))
}

fn builder() -> Builder {
    let mut builder = Builder::new();
    // Bound the entire HTTP/1 read buffer, including headers and any bytes
    // read ahead for the upgrade. HTTP/2 and HTTP/3 field sections use 32 KiB.
    builder.timer(TokioTimer::new()).header_read_timeout(HEADER_TIMEOUT).max_buf_size(64 * 1024);
    builder
}

/// An HTTP/1.1 connection's TLS stream. A write that makes no progress for
/// `stall`, because the client does not read, fails, which ends the
/// connection: HTTP/1.1 has no other way to give up on a response. Once the
/// connection carries a tunnel, writes wait as long as TCP allows.
struct StallGuard<S> {
    io: S,
    conn: Arc<ConnInfo>,
    stall: Duration,
    stalled: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<S> StallGuard<S> {
    /// Called when a write is pending: whether it has waited too long.
    fn poll_stalled(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Error> {
        if self.conn.tunnel.load(Ordering::Relaxed) {
            self.stalled = None;
            return Poll::Pending;
        }
        let stall = self.stall;
        let timer = self.stalled.get_or_insert_with(|| Box::pin(tokio::time::sleep(stall)));
        std::task::ready!(timer.as_mut().poll(cx));
        Poll::Ready(std::io::Error::new(std::io::ErrorKind::TimedOut, "the client stopped reading"))
    }

    fn progress<T>(&mut self, cx: &mut Context<'_>, polled: Poll<std::io::Result<T>>) -> Poll<std::io::Result<T>> {
        match polled {
            Poll::Ready(result) => {
                self.stalled = None;
                Poll::Ready(result)
            }
            Poll::Pending => self.poll_stalled(cx).map(Err),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for StallGuard<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for StallGuard<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.io).poll_write(cx, buf);
        self.progress(cx, polled)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.io).poll_write_vectored(cx, bufs);
        self.progress(cx, polled)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let polled = Pin::new(&mut self.io).poll_flush(cx);
        self.progress(cx, polled)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let polled = Pin::new(&mut self.io).poll_shutdown(cx);
        self.progress(cx, polled)
    }
}

/// Sends a response body as slices of the website's own buffers, as the
/// client's flow control allows. A client that grants no credit, or stops
/// reading, for `stall` gets an error instead of holding the stream.
async fn send_body(send: &mut h2::SendStream<Bytes>, mut body: Bytes, stall: Duration) -> Result<(), ()> {
    while !body.is_empty() {
        send.reserve_capacity(body.len());
        let granted = match tokio::time::timeout(stall, std::future::poll_fn(|cx| send.poll_capacity(cx))).await {
            Ok(Some(Ok(granted))) => granted,
            _ => return Err(()),
        };
        if granted > 0 {
            let chunk = body.split_to(granted.min(body.len()));
            send.send_data(chunk, body.is_empty()).map_err(|_| ())?;
        }
    }
    Ok(())
}

impl Relay {
    /// Serves HTTP/2 and HTTP/1.1 over TLS on a TCP listener.
    pub async fn serve_tcp(self, listener: TcpListener, tls_config: Arc<rustls::ServerConfig>) {
        let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
        let builder = Arc::new(builder());
        let shutting_down = self.shutting_down();
        tokio::pin!(shutting_down);
        loop {
            let accepted = tokio::select! {
                accepted = listener.accept() => accepted,
                // Dropping the listener refuses new connections.
                _ = &mut shutting_down => return,
            };
            let (tcp, remote) = match accepted {
                Ok(c) => c,
                Err(e) => {
                    warn!("TCP accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            // Over the limit, in total or for this address: close at once,
            // before spending a TLS handshake on it.
            let Some(permit) = self.inner.connections.try_acquire(remote.ip()) else {
                debug!(%remote, "connection limit reached");
                drop(tcp);
                continue;
            };
            if let Err(e) = sys::limit_tcp_buffers(socket2::SockRef::from(&tcp), sys::CLIENT_TCP_BUFFER) {
                warn!(%remote, "cannot bound client TCP buffers: {e}");
                continue;
            }
            if let Err(e) = sys::tune_client_tcp(socket2::SockRef::from(&tcp)) {
                debug!(%remote, "could not set TCP options: {e}");
            }
            let (relay, acceptor, builder) = (self.clone(), acceptor.clone(), builder.clone());
            tokio::spawn(async move {
                let _permit = permit;
                let tls = match tokio::time::timeout(HEADER_TIMEOUT, acceptor.accept(tcp)).await {
                    Ok(Ok(tls)) => tls,
                    Ok(Err(e)) => return debug!(%remote, "TLS handshake failed: {e}"),
                    Err(_) => return,
                };
                let h2 = tls.get_ref().1.alpn_protocol() == Some(tls::ALPN_H2);
                let client_cert = tls::client_fingerprint(tls.get_ref().1.peer_certificates());
                let info = ConnInfo::new(if h2 { "HTTP/2" } else { "HTTP/1.1" }, remote, client_cert);
                *info.connection_permit.lock().unwrap() = Some(_permit);
                if h2 {
                    if let Err(e) = relay.serve_h2(tls, info).await {
                        debug!(%remote, "HTTP/2 connection ended: {e}");
                    }
                    return;
                }
                let shutting_down = relay.shutting_down();
                let idle_timeout = relay.settings().idle_timeout;
                let idle_info = info.clone();
                let io = StallGuard { io: tls, conn: info.clone(), stall: relay.send_stall(), stalled: None };
                let service = hyper::service::service_fn(move |req| {
                    let (relay, info) = (relay.clone(), info.clone());
                    async move {
                        let _active = info.request_started();
                        let is_connect = req.method() == Method::CONNECT;
                        let is_upgrade = asks_for_udp_upgrade(&req);
                        let mut resp = relay.handle_http(info, req).await;
                        // RFC 9931 section 8: a proxy MUST close the connection
                        // when it rejects a CONNECT, so that nothing the client
                        // sent after it is read as another request. A rejected
                        // connect-udp upgrade is closed for the same reason
                        // (RFC 9931 section 6.3).
                        let accepted = if is_connect {
                            resp.status().is_success()
                        } else {
                            resp.status() == StatusCode::SWITCHING_PROTOCOLS
                        };
                        if (is_connect || is_upgrade) && !accepted {
                            resp.headers_mut().insert(CONNECTION, http::HeaderValue::from_static("close"));
                        }
                        Ok::<_, Infallible>(resp)
                    }
                });
                let connection = builder.serve_connection(TokioIo::new(io), service).with_upgrades();
                let idle = idle_info.idle(idle_timeout);
                tokio::pin!(connection, shutting_down, idle);
                let result = tokio::select! {
                    result = &mut connection => result,
                    _ = &mut shutting_down => {
                        // Finishes a response under way, then closes; an
                        // upgraded tunnel has left the connection already.
                        connection.as_mut().graceful_shutdown();
                        connection.await
                    }
                    _ = &mut idle => {
                        connection.as_mut().graceful_shutdown();
                        connection.await
                    }
                };
                if let Err(e) = result {
                    debug!(%remote, "HTTP connection ended: {e}");
                }
            });
        }
    }

    async fn serve_h2<S>(&self, io: S, info: Arc<ConnInfo>) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut builder = h2::server::Builder::new();
        // Data the client sends is released only as a destination accepts
        // it, so a tunnel to a slow destination keeps its stream window.
        // The connection window holds four stream windows: three such
        // tunnels cannot leave the others on the connection without credit
        // (RFC 9113 section 5.2). Queued sends are bounded per tunnel
        // (`limits::MEMORY_PER_TUNNEL`), so HTTP/2 uses half of the
        // connection's reservation for receiving rather than a quarter.
        let window = (self.inner.connection_memory / 2) as u32;
        builder
            .enable_connect_protocol()
            .max_concurrent_streams(MAX_STREAMS_HTTP2)
            .max_header_list_size(32 * 1024)
            .initial_window_size((window / 4).min(1 << 20))
            .initial_connection_window_size(window)
            .max_send_buffer_size(64 * 1024);
        let mut conn = tokio::time::timeout(HEADER_TIMEOUT, builder.handshake::<_, Bytes>(io)).await??;
        let mut ping = conn.ping_pong().expect("one keepalive owner");
        let keepalive = async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                match tokio::time::timeout(Duration::from_secs(20), ping.ping(h2::Ping::opaque())).await {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => break Err(e.into()),
                    Err(e) => break Err(e.into()),
                }
            }
        };
        tokio::pin!(keepalive);
        // PINGs keep a connection alive as long as the peer answers them, so
        // a connection without requests is closed after the idle timeout
        // (sooner if it never authenticated), with GOAWAY first.
        let idle_timeout = self.settings().idle_timeout;
        let shutting_down = self.shutting_down();
        tokio::pin!(shutting_down);
        let mut closing = false;
        loop {
            tokio::select! {
                accepted = conn.accept() => match accepted {
                    Some(Ok((req, response))) => {
                        let (relay, info) = (self.clone(), info.clone());
                        let active = info.request_started();
                        tokio::spawn(async move {
                            let _active = active;
                            if let Err(e) = relay.handle_h2(info, req, response).await {
                                debug!("HTTP/2 request ended: {e:#}");
                            }
                        });
                    }
                    Some(Err(e)) => return Err(e.into()),
                    None => return Ok(()),
                },
                result = &mut keepalive => {
                    conn.abrupt_shutdown(h2::Reason::NO_ERROR);
                    return result;
                }
                _ = info.idle(idle_timeout), if !closing => {
                    debug!(remote = %info.remote, "closing idle HTTP/2 connection");
                    conn.graceful_shutdown();
                    closing = true;
                }
                // Server shutdown: GOAWAY (RFC 9113 §6.8); h2 closes the
                // connection once the open streams are done.
                _ = &mut shutting_down, if !closing => {
                    debug!(remote = %info.remote, "server shutting down: GOAWAY");
                    conn.graceful_shutdown();
                    closing = true;
                }
            }
        }
    }

    async fn handle_h2(
        &self,
        info: Arc<ConnInfo>,
        req: Request<h2::RecvStream>,
        mut response: h2::server::SendResponse<Bytes>,
    ) -> Result<()> {
        // h2 rejects malformed requests (RFC 9113 §8.1.1, §8.3, §8.5; RFC
        // 8441 §4) with a PROTOCOL_ERROR stream reset before they get here.
        let protocol = req.extensions().get::<h2::ext::Protocol>().map(|p| p.as_str());
        let is_connect = req.method() == Method::CONNECT;
        let kind = Kind::of_connect(is_connect, protocol, req.uri().scheme_str());
        let settings = self.settings();
        let incoming = Incoming {
            method: req.method(),
            protocol,
            kind,
            authority: req.uri().authority().map(|a| a.as_str()),
            path_and_query: req.uri().path_and_query().map_or("/", |p| p.as_str()),
            headers: req.headers(),
        };
        let authorized = tokio::select! {
            biased;
            _ = std::future::poll_fn(|cx| response.poll_reset(cx)) => return Ok(()),
            authorized = self.authorize(&incoming, &info, &settings) => authorized,
        };
        let Some(authorized) = authorized else {
            let cover = web::cover(self.site().as_deref(), req.method(), req.uri().path(), is_connect);
            // The answer never depends on a request body: drop it now, which
            // frees what the client sent and its flow control credit (h2
            // resets the rest with NO_ERROR once the response is complete,
            // RFC 9113 §8.1).
            drop(req);
            let mut resp = Response::builder()
                .status(cover.status)
                .header(DATE, http_date())
                .header(ALT_SVC, self.inner.alt_svc.clone());
            for (name, value) in cover.headers {
                resp = resp.header(name, value);
            }
            let mut send = response.send_response(resp.body(())?, cover.body.is_empty())?;
            if !cover.body.is_empty() && send_body(&mut send, cover.body, self.send_stall()).await.is_err() {
                send.send_reset(h2::Reason::CANCEL);
            }
            return Ok(());
        };
        if authorized.kind == Kind::Udp && !crate::proto::valid_capsule_headers(req.headers()) {
            response.send_reset(h2::Reason::PROTOCOL_ERROR);
            return Ok(());
        }
        let opened = tokio::select! {
            biased;
            _ = std::future::poll_fn(|cx| response.poll_reset(cx)) => return Ok(()),
            opened = self.open(&authorized, &info, &settings) => opened,
        };
        let (opened, mut ctx) = match opened {
            Ok(o) => o,
            Err(refusal) => {
                // A malformed request is a stream error of type
                // PROTOCOL_ERROR after its 400 (RFC 9298 section 3.4, RFC
                // 9113 section 8.1.1).
                let malformed = refusal == Refusal::MalformedRequest;
                let mut send = response.send_response(
                    Response::builder()
                        .status(refusal.status())
                        .header(DATE, http_date())
                        .header("proxy-status", refusal.proxy_status())
                        .body(())?,
                    !malformed,
                )?;
                if malformed {
                    send.send_reset(h2::Reason::PROTOCOL_ERROR);
                }
                return Ok(());
            }
        };
        let mut resp = Response::builder().status(StatusCode::OK).header(DATE, http_date());
        if authorized.kind == Kind::Udp {
            resp = resp.header(CAPSULE_PROTOCOL_HEADER, "?1");
        }
        let send = match response.send_response(resp.body(())?, false) {
            Ok(send) => send,
            Err(error) => {
                opened.abort();
                return Err(error.into());
            }
        };
        let (mut stream, reset) = super::h2_stream::Stream::new(req.into_body(), send);
        match opened {
            Opened::Tcp(tcp) => {
                let cancellation = reset.clone();
                ctx.peer_closed = Box::pin(async move { cancellation.cancelled().await });
                if !pump::tcp_over_stream(&mut stream, tcp, ctx).await {
                    reset.reset(h2::Reason::CONNECT_ERROR);
                }
            }
            Opened::Udp(sock) => {
                let tunnel = Tunnel::stream_with_reset(stream, Some(Box::new(move |why| reset.reset(why.h2_reason()))));
                pump::udp(tunnel, sock, ctx).await;
            }
        }
        Ok(())
    }

    async fn handle_http(&self, info: Arc<ConnInfo>, mut req: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
        // RFC 9112 §3.2: an HTTP/1.1 request without exactly one Host field
        // gets 400, as from any web server; RFC 9298 §3.2 asks the same of
        // CONNECT-UDP requests.
        // section 3.2 also asks for 400 when the Host value is invalid; an empty
        // one is valid (for a target URI without authority).
        let bad_host = req.headers().get(HOST).is_some_and(|host| {
            !host.is_empty() && host.to_str().ok().and_then(|h| h.parse::<http::uri::Authority>().ok()).is_none()
        });
        if bad_host || req.version() == http::Version::HTTP_11 && req.headers().get_all(HOST).iter().count() != 1 {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(CONNECTION, "close")
                .body(Full::default())
                .expect("valid");
        }
        let is_connect = req.method() == Method::CONNECT;
        // RFC 9298 §3.2: GET with "Connection: Upgrade" and "Upgrade: connect-udp".
        // Both fields are token lists (RFC 9110 §7.6.1, §7.8).
        let has_token = |name, token: &str| {
            req.headers()
                .get_all(name)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
        };
        let protocol = req.headers().get(UPGRADE).and_then(|v| v.to_str().ok()).map(str::to_string);
        // RFC 9110 §7.8: Upgrade in an HTTP/1.0 request MUST be ignored.
        let wants_udp = req.version() == http::Version::HTTP_11 && has_token(UPGRADE, CONNECT_UDP_PROTOCOL);
        let kind = if is_connect {
            Some(Kind::Tcp)
        } else if wants_udp && req.method() == Method::GET && has_token(CONNECTION, "upgrade") {
            Some(Kind::Udp)
        } else if wants_udp {
            // RFC 9298 §3.2: a malformed UDP proxying request MUST get an
            // error status (SHOULD 400), not the website's 200.
            Some(Kind::Malformed)
        } else {
            None
        };
        // A CONNECT's request target is in authority form, host and port
        // only (RFC 9112 section 3.2.3); in any other form it names no target.
        let authority_form = req.uri().scheme().is_none() && req.uri().path_and_query().is_none();
        let authority = req.uri().authority().filter(|_| !is_connect || authority_form).map(|a| a.as_str().to_string());
        let path_and_query = req.uri().path_and_query().map_or_else(|| "/".to_string(), |p| p.as_str().to_string());
        let settings = self.settings();
        let incoming = Incoming {
            method: req.method(),
            protocol: protocol.as_deref(),
            kind,
            authority: authority.as_deref(),
            path_and_query: &path_and_query,
            headers: req.headers(),
        };
        let Some(authorized) = self.authorize(&incoming, &info, &settings).await else {
            // An HTTP/1.1 upgrade request is answered as the plain GET it
            // also is; RFC 9110 §7.8 lets servers ignore Upgrade.
            let cover = web::cover(self.site().as_deref(), req.method(), req.uri().path(), is_connect);
            let mut resp = Response::builder().status(cover.status).header(ALT_SVC, self.inner.alt_svc.clone());
            for (name, value) in cover.headers {
                resp = resp.header(name, value);
            }
            return resp.body(Full::new(cover.body)).expect("valid");
        };
        if authorized.kind == Kind::Udp && !crate::proto::valid_capsule_headers(req.headers()) {
            return Response::builder().status(StatusCode::BAD_REQUEST).body(Full::default()).expect("valid");
        }
        let (opened, ctx) = match self.open(&authorized, &info, &settings).await {
            Ok(o) => o,
            Err(refusal) => {
                return Response::builder()
                    .status(refusal.status())
                    .header("proxy-status", refusal.proxy_status())
                    .body(Full::default())
                    .expect("valid");
            }
        };
        let on_upgrade = hyper::upgrade::on(&mut req);
        let remote = info.remote;
        info.tunnel.store(true, Ordering::Relaxed);
        tokio::spawn(async move {
            let mut ctx = ctx;
            let upgraded = tokio::select! {
                biased;
                _ = ctx.cancelled() => {
                    opened.abort();
                    return;
                }
                result = on_upgrade => result,
            };
            match upgraded {
                Ok(io) => match opened {
                    Opened::Tcp(tcp) => {
                        pump::tcp_over_stream(TokioIo::new(io), tcp, ctx).await;
                    }
                    Opened::Udp(sock) => pump::udp(Tunnel::upgraded(io), sock, ctx).await,
                },
                Err(e) => {
                    opened.abort();
                    debug!(%remote, "upgrade failed: {e}");
                }
            }
        });
        let builder = Response::builder().header(DATE, http_date());
        match authorized.kind {
            // RFC 9298 §3.3.
            Kind::Udp => builder
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header(CONNECTION, "Upgrade")
                .header(UPGRADE, CONNECT_UDP_PROTOCOL)
                .header(CAPSULE_PROTOCOL_HEADER, "?1"),
            // Only tunnels that opened get here.
            Kind::Tcp | Kind::Unsupported | Kind::Malformed => builder.status(StatusCode::OK),
        }
        .body(Full::default())
        .expect("valid")
    }
}
