//! HTTP/2 and HTTP/1.1 over TLS on TCP.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use http::header::{ALT_SVC, CONNECTION, DATE, UPGRADE};
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tracing::{debug, warn};

use super::{http_date, pump, ConnInfo, Incoming, Kind, Opened, Relay, HEADER_TIMEOUT};
use crate::certs::CertStore;
use crate::proto::{CAPSULE_PROTOCOL_HEADER, CONNECT_UDP_PROTOCOL};
use crate::tunnel::Tunnel;
use crate::{sys, tls, web};

/// TLS configuration for HTTP/2 and HTTP/1.1 over TCP.
pub fn tcp_tls_config(certs: Arc<CertStore>) -> Result<Arc<rustls::ServerConfig>> {
    Ok(Arc::new(tls::server_config(certs, &[tls::ALPN_H2, tls::ALPN_HTTP11], true)?))
}

type Builder = hyper::server::conn::http1::Builder;

fn builder() -> Builder {
    let mut builder = Builder::new();
    // The same bound on request headers as HTTP/2 and HTTP/3 have (32 KiB),
    // with room for what is buffered around them.
    builder.timer(TokioTimer::new()).header_read_timeout(HEADER_TIMEOUT).max_buf_size(64 * 1024);
    builder
}

impl Relay {
    /// Serves HTTP/2 and HTTP/1.1 over TLS on a TCP listener.
    pub async fn serve_tcp(self, listener: TcpListener, tls_config: Arc<rustls::ServerConfig>) {
        let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
        let builder = Arc::new(builder());
        loop {
            let (tcp, remote) = match listener.accept().await {
                Ok(c) => c,
                Err(e) => {
                    warn!("TCP accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            if let Err(e) = sys::tune_client_tcp(socket2::SockRef::from(&tcp)) {
                debug!(%remote, "could not set TCP options: {e}");
            }
            let (relay, acceptor, builder) = (self.clone(), acceptor.clone(), builder.clone());
            tokio::spawn(async move {
                let tls = match tokio::time::timeout(HEADER_TIMEOUT, acceptor.accept(tcp)).await {
                    Ok(Ok(tls)) => tls,
                    Ok(Err(e)) => return debug!(%remote, "TLS handshake failed: {e}"),
                    Err(_) => return,
                };
                let h2 = tls.get_ref().1.alpn_protocol() == Some(tls::ALPN_H2);
                let info = ConnInfo::new(if h2 { "HTTP/2" } else { "HTTP/1.1" }, remote);
                if h2 {
                    if let Err(e) = relay.serve_h2(tls, info).await {
                        debug!(%remote, "HTTP/2 connection ended: {e}");
                    }
                    return;
                }
                let service = hyper::service::service_fn(move |req| {
                    let (relay, info) = (relay.clone(), info.clone());
                    async move { Ok::<_, Infallible>(relay.handle_http(info, req).await) }
                });
                if let Err(e) = builder.serve_connection(TokioIo::new(tls), service).with_upgrades().await {
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
        builder
            .enable_connect_protocol()
            .max_concurrent_streams(1024)
            .max_header_list_size(32 * 1024)
            .initial_window_size(4 << 20)
            .initial_connection_window_size(32 << 20)
            .max_send_buffer_size(1 << 20);
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
        loop {
            tokio::select! {
                accepted = conn.accept() => match accepted {
                    Some(Ok((req, response))) => {
                        let (relay, info) = (self.clone(), info.clone());
                        tokio::spawn(async move {
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
            }
        }
    }

    async fn handle_h2(
        &self,
        info: Arc<ConnInfo>,
        req: Request<h2::RecvStream>,
        mut response: h2::server::SendResponse<Bytes>,
    ) -> Result<()> {
        let protocol = req.extensions().get::<h2::ext::Protocol>().map(|p| p.as_str());
        let is_connect = req.method() == Method::CONNECT;
        let kind = match (is_connect, protocol) {
            (true, None) => Some(Kind::Tcp),
            (true, Some(CONNECT_UDP_PROTOCOL)) => Some(Kind::Udp),
            _ => None,
        };
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
            let mut resp = Response::builder()
                .status(cover.status)
                .header(DATE, http_date())
                .header(ALT_SVC, self.inner.alt_svc.clone());
            for (name, value) in cover.headers {
                resp = resp.header(name, value);
            }
            let send = response.send_response(resp.body(())?, cover.body.is_empty())?;
            if !cover.body.is_empty() {
                let (mut stream, _) = super::h2_stream::Stream::new(req.into_body(), send);
                use tokio::io::AsyncWriteExt;
                stream.write_all(&cover.body).await?;
                stream.shutdown().await?;
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
                response.send_response(
                    Response::builder()
                        .status(refusal.status())
                        .header(DATE, http_date())
                        .header("proxy-status", refusal.proxy_status())
                        .body(())?,
                    true,
                )?;
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
        let udp =
            req.method() == Method::GET && has_token(CONNECTION, "upgrade") && has_token(UPGRADE, CONNECT_UDP_PROTOCOL);
        let kind = if is_connect {
            Some(Kind::Tcp)
        } else if udp {
            Some(Kind::Udp)
        } else {
            None
        };
        let authority = req.uri().authority().map(|a| a.as_str().to_string()).or_else(|| {
            // HTTP/1.1 CONNECT carries the target as the request target,
            // which hyper parses into the authority; Host is a fallback.
            is_connect.then(|| req.headers().get(http::header::HOST)?.to_str().ok().map(str::to_string))?
        });
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
        tokio::spawn(async move {
            match on_upgrade.await {
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
            Kind::Tcp => builder.status(StatusCode::OK),
            // RFC 9298 §3.3.
            Kind::Udp => builder
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header(CONNECTION, "Upgrade")
                .header(UPGRADE, CONNECT_UDP_PROTOCOL)
                .header(CAPSULE_PROTOCOL_HEADER, "?1"),
        }
        .body(Full::default())
        .expect("valid")
    }
}
