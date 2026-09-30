//! HTTP/2 and HTTP/1.1 over TLS on TCP.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use http::header::{ALT_SVC, CONNECTION, DATE, UPGRADE};
use http::{Method, Request, Response, StatusCode, Version};
use http_body_util::Full;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
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

type Builder = hyper_util::server::conn::auto::Builder<TokioExecutor>;

fn builder() -> Builder {
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http2()
        // RFC 8441: advertise extended CONNECT with SETTINGS_ENABLE_CONNECT_PROTOCOL.
        .enable_connect_protocol()
        // Every relayed TCP connection is a stream.
        .max_concurrent_streams(1024)
        .adaptive_window(true)
        .max_send_buf_size(1 << 20)
        .timer(TokioTimer::new())
        .keep_alive_interval(Some(Duration::from_secs(30)))
        .keep_alive_timeout(Duration::from_secs(20));
    builder.http1().timer(TokioTimer::new()).header_read_timeout(HEADER_TIMEOUT);
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
                let service = hyper::service::service_fn(move |req| {
                    let (relay, info) = (relay.clone(), info.clone());
                    async move { Ok::<_, Infallible>(relay.handle_http(info, req).await) }
                });
                if let Err(e) = builder.serve_connection_with_upgrades(TokioIo::new(tls), service).await {
                    debug!(%remote, "HTTP connection ended: {e}");
                }
            });
        }
    }

    async fn handle_http(&self, info: Arc<ConnInfo>, mut req: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
        let http1 = req.version() <= Version::HTTP_11;
        let is_connect = req.method() == Method::CONNECT;
        let (kind, protocol) = if http1 {
            // RFC 9298 §3.2: GET with "Connection: Upgrade" and "Upgrade: connect-udp".
            let upgrade = req.headers().get(UPGRADE).and_then(|v| v.to_str().ok()).map(str::to_string);
            let wants_upgrade = req
                .headers()
                .get_all(CONNECTION)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade")));
            let udp = req.method() == Method::GET
                && wants_upgrade
                && upgrade.as_deref().is_some_and(|u| u.eq_ignore_ascii_case(CONNECT_UDP_PROTOCOL));
            let kind = if is_connect {
                Some(Kind::Tcp)
            } else if udp {
                Some(Kind::Udp)
            } else {
                None
            };
            (kind, upgrade)
        } else {
            // RFC 9113 §8.5 CONNECT, and RFC 8441 extended CONNECT with
            // :protocol = connect-udp (RFC 9298 §3.4).
            let protocol = req.extensions().get::<hyper::ext::Protocol>().map(|p| p.as_str().to_string());
            let kind = match (is_connect, protocol.as_deref()) {
                (true, None) => Some(Kind::Tcp),
                (true, Some(CONNECT_UDP_PROTOCOL)) => Some(Kind::Udp),
                _ => None,
            };
            (kind, protocol)
        };
        let authority = req.uri().authority().map(|a| a.as_str().to_string()).or_else(|| {
            // HTTP/1.1 CONNECT carries the target as the request target,
            // which hyper parses into the authority; Host is a fallback.
            (http1 && is_connect).then(|| req.headers().get(http::header::HOST)?.to_str().ok().map(str::to_string))?
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
                    Opened::Tcp(tcp) => pump::tcp_over_stream(TokioIo::new(io), tcp, ctx).await,
                    Opened::Udp(sock) => pump::udp(Tunnel::upgraded(io), sock, ctx).await,
                },
                Err(e) => debug!(%remote, "upgrade failed: {e}"),
            }
        });
        let builder = Response::builder().header(DATE, http_date());
        match (authorized.kind, http1) {
            (Kind::Tcp, _) => builder.status(StatusCode::OK),
            // RFC 9298 §3.3.
            (Kind::Udp, true) => builder
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header(CONNECTION, "Upgrade")
                .header(UPGRADE, CONNECT_UDP_PROTOCOL)
                .header(CAPSULE_PROTOCOL_HEADER, "?1"),
            (Kind::Udp, false) => builder.status(StatusCode::OK).header(CAPSULE_PROTOCOL_HEADER, "?1"),
        }
        .body(Full::default())
        .expect("valid")
    }
}
