//! HTTP/3 on QUIC.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use bytes::Bytes;
use h3::quic::StreamId;
use h3_datagram::datagram_handler::{DatagramReader, HandleDatagramsExt};
use http::header::DATE;
use http::{Method, Response, StatusCode};
use quinn::{IdleTimeout, TransportConfig, VarInt};
use tokio::sync::{mpsc, oneshot};
use tracing::debug;

use super::{http_date, pump, ConnInfo, Incoming, Kind, Opened, Relay, HEADER_TIMEOUT};
use crate::certs::CertStore;
use crate::policy::Refusal;
use crate::proto::{CAPSULE_PROTOCOL_HEADER, CONNECT_UDP_PROTOCOL};
use crate::tls;
use crate::tunnel::{Datagrams, DgramSender, QuicDatagrams, Tunnel};
use crate::web::{self, Cover};

type H3Connection = h3::server::Connection<h3_quinn::Connection, Bytes>;
type H3Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type DgramReader = DatagramReader<h3_quinn::datagram::RecvDatagramHandler>;
type Routes = Arc<Mutex<Router>>;

/// Datagrams queued per UDP flow before new ones are dropped.
const FLOW_QUEUE: usize = 1024;
/// Datagrams held per connection for streams not yet set up.
const EARLY_DATAGRAMS: usize = 64;

/// Hands each datagram of a connection to the flow of its stream.
#[derive(Default)]
struct Router {
    flows: HashMap<StreamId, mpsc::Sender<Bytes>>,
    /// Clients may send datagrams right after the request, before the
    /// response (RFC 9298 §5); they can arrive before the relay has checked
    /// the request. A few are held, oldest dropped first.
    early: VecDeque<(StreamId, Bytes)>,
}

impl Router {
    fn deliver(&mut self, stream_id: StreamId, payload: Bytes) {
        match self.flows.get(&stream_id) {
            Some(tx) => {
                let _ = tx.try_send(payload);
            }
            None => {
                if self.early.len() == EARLY_DATAGRAMS {
                    self.early.pop_front();
                }
                self.early.push_back((stream_id, payload));
            }
        }
    }

    fn add(&mut self, stream_id: StreamId, tx: mpsc::Sender<Bytes>) {
        let early = std::mem::take(&mut self.early);
        for (id, payload) in early {
            if id == stream_id {
                let _ = tx.try_send(payload);
            } else {
                self.early.push_back((id, payload));
            }
        }
        self.flows.insert(stream_id, tx);
    }
}

/// QUIC transport settings. Every relayed TCP connection is a request
/// stream, so a device needs many at once; stream and connection windows are
/// sized for fast long-distance transfers. The initial MTU leaves room for
/// relayed QUIC packets, which are at least 1200 bytes (RFC 9000 §14.1),
/// inside a DATAGRAM frame; path MTU discovery raises it further.
pub(super) fn transport_config() -> TransportConfig {
    let mut t = TransportConfig::default();
    t.max_concurrent_bidi_streams(VarInt::from_u32(1024));
    t.stream_receive_window(VarInt::from_u32(4 << 20));
    t.receive_window(VarInt::from_u32(32 << 20));
    t.send_window(32 << 20);
    t.datagram_receive_buffer_size(Some(4 << 20));
    t.datagram_send_buffer_size(4 << 20);
    t.initial_mtu(1350);
    t.max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(300_000))));
    t
}

/// QUIC endpoint for HTTP/3.
pub fn quic_endpoint(certs: Arc<CertStore>, socket: std::net::UdpSocket) -> Result<quinn::Endpoint> {
    let tls_config = tls::server_config(certs, &[tls::ALPN_H3], false)?;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server_config.transport_config(Arc::new(transport_config()));
    let runtime = quinn::default_runtime().context("no async runtime")?;
    Ok(quinn::Endpoint::new(quinn::EndpointConfig::default(), Some(server_config), socket, runtime)?)
}

impl Relay {
    /// Serves HTTP/3 on a QUIC endpoint until it closes.
    pub async fn serve_quic(self, endpoint: quinn::Endpoint) {
        while let Some(incoming) = endpoint.accept().await {
            let relay = self.clone();
            tokio::spawn(async move {
                let remote = incoming.remote_address();
                if let Err(e) = relay.handle_quic_connection(incoming).await {
                    debug!(%remote, "connection ended: {e:#}");
                }
            });
        }
    }

    async fn handle_quic_connection(self, incoming: quinn::Incoming) -> Result<()> {
        let remote = incoming.remote_address();
        let conn = match incoming.await {
            Ok(conn) => conn,
            Err(e) => {
                debug!(%remote, "QUIC handshake failed: {e}");
                return Ok(());
            }
        };
        let mut h3_conn: H3Connection = h3::server::builder()
            .enable_extended_connect(true)
            .enable_datagram(true)
            .build(h3_quinn::Connection::new(conn.clone()))
            .await
            .context("HTTP/3 setup")?;
        let info = ConnInfo::new("HTTP/3", remote);

        // Exactly one datagram reader per connection; it hands each datagram
        // to the flow that owns the stream named by its quarter stream ID.
        let routes: Routes = Arc::default();
        let dispatcher = tokio::spawn(dispatch_datagrams(h3_conn.get_datagram_reader(), routes.clone()));
        // Request tasks ask the connection task for datagram senders, which
        // only the connection can create.
        let (sender_tx, mut sender_rx) = mpsc::channel::<(StreamId, oneshot::Sender<DgramSender>)>(64);

        let result = loop {
            tokio::select! {
                accepted = h3_conn.accept() => match accepted {
                    Ok(Some(resolver)) => {
                        let (relay, info, conn, routes, sender_tx) =
                            (self.clone(), info.clone(), conn.clone(), routes.clone(), sender_tx.clone());
                        tokio::spawn(async move {
                            let (req, stream) = match tokio::time::timeout(HEADER_TIMEOUT, resolver.resolve_request()).await {
                                Ok(Ok(r)) => r,
                                // Includes requests with a :protocol the h3
                                // library does not know, such as connect-tcp.
                                Ok(Err(e)) if relay.settings().log_requests => {
                                    return tracing::info!(remote = %info.remote, "malformed HTTP/3 request: {e}")
                                }
                                Ok(Err(e)) => return debug!(remote = %info.remote, "malformed HTTP/3 request: {e}"),
                                Err(_) => return,
                            };
                            relay.handle_h3_request(req, stream, info, conn, routes, sender_tx).await;
                        });
                    }
                    Ok(None) => break Ok(()),
                    Err(e) => break Err(anyhow::Error::new(e)),
                },
                Some((stream_id, reply)) = sender_rx.recv() => {
                    let _ = reply.send(h3_conn.get_datagram_sender(stream_id));
                }
            }
        };
        dispatcher.abort();
        result
    }

    async fn handle_h3_request(
        self,
        req: http::Request<()>,
        mut stream: H3Stream,
        info: Arc<ConnInfo>,
        conn: quinn::Connection,
        routes: Routes,
        sender_tx: mpsc::Sender<(StreamId, oneshot::Sender<DgramSender>)>,
    ) {
        let is_connect = req.method() == Method::CONNECT;
        let protocol = req.extensions().get::<h3::ext::Protocol>().copied();
        let kind = match (is_connect, protocol) {
            (true, None) => Some(Kind::Tcp),
            (true, Some(p)) if p.as_str() == CONNECT_UDP_PROTOCOL => Some(Kind::Udp),
            _ => None,
        };
        let authority = req.uri().authority().map(|a| a.as_str().to_string());
        let path_and_query = req.uri().path_and_query().map_or("/", |p| p.as_str()).to_string();
        let settings = self.settings();
        let incoming = Incoming {
            method: req.method(),
            protocol: protocol.as_ref().map(|p| p.as_str()),
            kind,
            authority: authority.as_deref(),
            path_and_query: &path_and_query,
            headers: req.headers(),
        };
        let Some(authorized) = self.authorize(&incoming, &info, &settings).await else {
            let cover = web::cover(self.site().as_deref(), req.method(), req.uri().path(), is_connect);
            return send_cover(stream, cover).await;
        };

        // Datagrams may arrive as soon as the client has sent the request,
        // before the response: route them to the flow from now on.
        let stream_id = stream.id();
        let flow = (authorized.kind == Kind::Udp).then(|| {
            let (tx, rx) = mpsc::channel(FLOW_QUEUE);
            routes.lock().unwrap().add(stream_id, tx);
            rx
        });
        let _route = RouteGuard { routes: routes.clone(), stream_id };

        let (opened, ctx) = match self.open(&authorized, &info, &settings).await {
            Ok(o) => o,
            Err(refusal) => return send_refusal(stream, &refusal).await,
        };
        let mut resp = Response::builder().status(StatusCode::OK).header(DATE, http_date());
        if authorized.kind == Kind::Udp {
            resp = resp.header(CAPSULE_PROTOCOL_HEADER, "?1");
        }
        if stream.send_response(resp.body(()).expect("valid")).await.is_err() {
            return;
        }
        match opened {
            Opened::Tcp(tcp) => pump::tcp_over_h3(stream, tcp, ctx).await,
            Opened::Udp(sock) => {
                let (reply_tx, reply_rx) = oneshot::channel();
                if sender_tx.send((stream_id, reply_tx)).await.is_err() {
                    return;
                }
                let Ok(sender) = reply_rx.await else { return };
                let rx = flow.expect("UDP flows have a route");
                let datagrams = Datagrams::Quic(QuicDatagrams::new(sender, conn, stream_id, rx));
                pump::udp(Tunnel::h3_server(stream, datagrams), sock, ctx).await;
            }
        }
    }
}

/// Removes a flow's datagram route when the request ends.
struct RouteGuard {
    routes: Routes,
    stream_id: StreamId,
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        self.routes.lock().unwrap().flows.remove(&self.stream_id);
    }
}

async fn send_cover(mut stream: H3Stream, cover: Cover) {
    // The answer never depends on a request body: stop the client sending
    // one, with the code RFC 9114 §4.1.2 asks for (dropping the stream
    // unread would send code 0).
    stream.stop_sending(h3::error::Code::H3_NO_ERROR);
    let mut resp = Response::builder().status(cover.status).header(DATE, http_date());
    for (name, value) in cover.headers {
        resp = resp.header(name, value);
    }
    if stream.send_response(resp.body(()).expect("valid")).await.is_err() {
        return;
    }
    if !cover.body.is_empty() && stream.send_data(cover.body).await.is_err() {
        return;
    }
    let _ = stream.finish().await;
}

async fn send_refusal(mut stream: H3Stream, refusal: &Refusal) {
    stream.stop_sending(h3::error::Code::H3_NO_ERROR);
    let resp = Response::builder()
        .status(refusal.status())
        .header(DATE, http_date())
        .header("proxy-status", refusal.proxy_status())
        .body(())
        .expect("valid");
    if stream.send_response(resp).await.is_ok() {
        let _ = stream.finish().await;
    }
}

async fn dispatch_datagrams(mut reader: DgramReader, routes: Routes) {
    while let Ok(datagram) = reader.read_datagram().await {
        let stream_id = datagram.stream_id();
        routes.lock().unwrap().deliver(stream_id, datagram.into_payload());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u64) -> StreamId {
        StreamId::try_from(n).unwrap()
    }

    #[test]
    fn early_datagrams_are_held_for_their_flow() {
        let mut r = Router::default();
        r.deliver(id(0), Bytes::from_static(b"a"));
        r.deliver(id(4), Bytes::from_static(b"b"));
        r.deliver(id(0), Bytes::from_static(b"c"));
        let (tx, mut rx) = mpsc::channel(8);
        r.add(id(0), tx);
        assert_eq!(rx.try_recv().unwrap(), "a");
        assert_eq!(rx.try_recv().unwrap(), "c");
        assert!(rx.try_recv().is_err());
        assert_eq!(r.early.len(), 1, "the other stream's datagram stays");
        r.deliver(id(0), Bytes::from_static(b"d"));
        assert_eq!(rx.try_recv().unwrap(), "d");
        for _ in 0..EARLY_DATAGRAMS + 10 {
            r.deliver(id(8), Bytes::from_static(b"x"));
        }
        assert_eq!(r.early.len(), EARLY_DATAGRAMS, "bounded");
    }
}
