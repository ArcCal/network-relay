//! HTTP/3 on QUIC.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use bytes::Bytes;
use h3::quic::StreamId;
use h3_datagram::datagram_handler::{DatagramReader, HandleDatagramsExt};
use http::header::DATE;
use http::{Method, Response, StatusCode};
use quinn::{IdleTimeout, MtuDiscoveryConfig, TransportConfig, VarInt};
use tokio::sync::{mpsc, oneshot};
use tracing::debug;

use super::{
    http_date, pump, ConnInfo, Incoming, Kind, Opened, Relay, HEADER_TIMEOUT, MAX_STREAMS, MAX_STREAMS_UNAUTHENTICATED,
};
use crate::certs::CertStore;
use crate::policy::Refusal;
use crate::proto::CAPSULE_PROTOCOL_HEADER;
use crate::tls;
use crate::tunnel::{Datagrams, DgramSender, QuicDatagrams, Tunnel};
use crate::web::{self, Cover};

type H3Connection = h3::server::Connection<h3_quinn::Connection, Bytes>;
type H3Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type DgramReader = DatagramReader<h3_quinn::datagram::RecvDatagramHandler>;
type Routes = Arc<Mutex<Router>>;

/// HTTP/3 error code for an orderly close (RFC 9114 §8.1).
pub(super) const H3_NO_ERROR: u32 = 0x100;

/// How long a draining connection waits for its last stream data to be
/// acknowledged before it is closed: three round trips, within these bounds.
const DRAIN_ACK_MIN: std::time::Duration = std::time::Duration::from_millis(100);
const DRAIN_ACK_MAX: std::time::Duration = std::time::Duration::from_secs(1);

/// How long sending GOAWAY may take. The control stream is flow controlled
/// like any other, so a client that grants it no more credit would otherwise
/// keep a connection it was asked to leave, and its slot, for ever.
const GOAWAY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Datagrams queued per UDP flow before new ones are dropped.
const FLOW_QUEUE: usize = 64;
/// Datagrams held per connection for streams not yet set up.
const EARLY_DATAGRAMS: usize = 64;
const EARLY_DATAGRAM_BYTES: usize = 256 * 1024;
/// How long they are held: RFC 9297 §2.1 asks for "on the order of a round
/// trip" for streams not yet created.
const EARLY_DATAGRAM_TTL: std::time::Duration = std::time::Duration::from_secs(1);
/// Closed streams remembered per connection, so their late datagrams are
/// dropped at once.
const CLOSED_STREAMS: usize = 1024;

/// Hands each datagram of a connection to the flow of its stream.
#[derive(Default)]
struct Router {
    flows: HashMap<StreamId, Flow>,
    /// Recently closed streams never need early delivery. Keep this bounded
    /// on long-lived connections; older late datagrams can only occupy the
    /// bounded early queue, since QUIC stream IDs are never reused.
    closed: VecDeque<StreamId>,
    closed_set: HashSet<StreamId>,
    /// Clients may send datagrams right after the request, before the
    /// response (RFC 9298 §5); they can arrive before the relay has checked
    /// the request. A few are held briefly, oldest dropped first.
    early: VecDeque<(StreamId, Bytes, std::time::Instant)>,
    early_bytes: usize,
}

enum Flow {
    PendingUdp,
    Udp(mpsc::Sender<Bytes>),
    Other(Option<oneshot::Sender<()>>),
}

impl Router {
    fn deliver(&mut self, stream_id: StreamId, payload: Bytes) {
        match self.flows.get_mut(&stream_id) {
            Some(Flow::Udp(tx)) => {
                let _ = tx.try_send(payload);
            }
            Some(Flow::Other(error)) => {
                if let Some(tx) = error.take() {
                    let _ = tx.send(());
                }
            }
            None if self.closed_set.contains(&stream_id) => {}
            Some(Flow::PendingUdp) | None => {
                if payload.len() > EARLY_DATAGRAM_BYTES {
                    return;
                }
                let now = std::time::Instant::now();
                while self.early.front().is_some_and(|(_, _, at)| now.duration_since(*at) > EARLY_DATAGRAM_TTL)
                    || self.early.len() >= EARLY_DATAGRAMS
                    || self.early_bytes + payload.len() > EARLY_DATAGRAM_BYTES
                {
                    if let Some((_, dropped, _)) = self.early.pop_front() {
                        self.early_bytes -= dropped.len();
                    }
                }
                self.early_bytes += payload.len();
                self.early.push_back((stream_id, payload, now));
            }
        }
    }

    fn add(&mut self, stream_id: StreamId, tx: mpsc::Sender<Bytes>) {
        self.register(stream_id, Flow::Udp(tx));
    }

    fn register(&mut self, stream_id: StreamId, flow: Flow) {
        let pending = matches!(flow, Flow::PendingUdp);
        self.flows.insert(stream_id, flow);
        let early = std::mem::take(&mut self.early);
        self.early_bytes = 0;
        for (id, payload, at) in early {
            if at.elapsed() > EARLY_DATAGRAM_TTL {
                continue;
            }
            // Resolving a request is not a new arrival: pending UDP packets
            // keep their original age until authentication finishes.
            if id == stream_id && !pending {
                self.deliver(id, payload);
            } else {
                self.early_bytes += payload.len();
                self.early.push_back((id, payload, at));
            }
        }
    }

    /// Forgets a request's stream: its flow and held datagrams go, and later
    /// datagrams for it are dropped (RFC 9297 §2.1).
    fn close(&mut self, stream_id: StreamId) {
        self.flows.remove(&stream_id);
        self.early.retain(|(id, _, _)| *id != stream_id);
        self.early_bytes = self.early.iter().map(|(_, payload, _)| payload.len()).sum();
        if self.closed.len() == CLOSED_STREAMS {
            if let Some(oldest) = self.closed.pop_front() {
                self.closed_set.remove(&oldest);
            }
        }
        if self.closed_set.insert(stream_id) {
            self.closed.push_back(stream_id);
        }
    }
}

/// Largest UDP payload path MTU discovery tries (a 1500-byte Ethernet MTU
/// minus IPv6 and UDP headers).
pub const MTU_UPPER_BOUND: u16 = 1452;

/// QUIC transport settings. Every relayed TCP connection and UDP flow is a
/// request stream, so a device needs many at once: the limit starts at
/// [`MAX_STREAMS_UNAUTHENTICATED`] and is raised to [`MAX_STREAMS`] once the
/// connection authenticates. The connection's windows are sized from its
/// memory reservation (`limits::connection_memory`).
///
/// Packets start at QUIC's guaranteed 1200 bytes (RFC 9000 §14), so the
/// handshake gets through on any path, including IPv6 minimum-MTU paths.
/// Relayed QUIC packets are at least 1200 bytes too and need about 1250 inside
/// a DATAGRAM frame, so path MTU discovery (DPLPMTUD, RFC 8899) starts right
/// after the handshake and raises the size within a few round trips; until
/// then, relayed packets that do not fit are dropped rather than sent
/// reliably (RFC 9298 §6.1), and the relayed protocol retransmits them.
pub(super) fn transport_config() -> TransportConfig {
    let mut t = TransportConfig::default();
    let reserved = crate::limits::connection_memory(crate::limits::total_memory());
    let window = (reserved / 4) as u32;
    t.max_concurrent_bidi_streams(VarInt::from_u32(MAX_STREAMS_UNAUTHENTICATED));
    t.stream_receive_window(VarInt::from_u32(window.min(1 << 20)));
    t.receive_window(VarInt::from_u32(window));
    t.send_window(u64::from(window));
    t.datagram_receive_buffer_size(Some((reserved / 32) as usize));
    t.datagram_send_buffer_size((reserved / 32) as usize);
    t.initial_mtu(1200);
    t.min_mtu(1200);
    let mut mtu = MtuDiscoveryConfig::default();
    mtu.upper_bound(MTU_UPPER_BOUND);
    t.mtu_discovery_config(Some(mtu));
    t.max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(300_000))));
    t
}

/// QUIC endpoint for HTTP/3.
pub fn quic_endpoint(
    certs: Arc<CertStore>,
    socket: std::net::UdpSocket,
    client_certificates: bool,
) -> Result<quinn::Endpoint> {
    let tls_config = tls::server_config(certs, &[tls::ALPN_H3], false, client_certificates)?;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server_config.transport_config(Arc::new(transport_config()));
    let runtime = quinn::default_runtime().context("no async runtime")?;
    Ok(quinn::Endpoint::new(quinn::EndpointConfig::default(), Some(server_config), socket, runtime)?)
}

impl Relay {
    /// Serves HTTP/3 on a QUIC endpoint until it closes.
    pub async fn serve_quic(self, endpoint: quinn::Endpoint) {
        let shutting_down = self.shutting_down();
        tokio::pin!(shutting_down);
        loop {
            let incoming = tokio::select! {
                incoming = endpoint.accept() => incoming,
                _ = &mut shutting_down => {
                    // New connections are refused; open ones carry on.
                    endpoint.set_server_config(None);
                    return;
                }
            };
            let Some(incoming) = incoming else { return };
            let remote = incoming.remote_address();
            // When handshakes arrive faster than usual, clients first prove
            // they can receive at their address (RFC 9000 §8.1), so spoofed
            // packets cannot hold connection slots.
            if !incoming.remote_address_validated() && incoming.may_retry() && self.handshake_needs_retry() {
                let _ = incoming.retry();
                continue;
            }
            let Some(permit) = self.inner.connections.try_acquire(remote.ip()) else {
                debug!(%remote, "connection limit reached");
                incoming.refuse();
                continue;
            };
            let relay = self.clone();
            tokio::spawn(async move {
                if let Err(e) = relay.handle_quic_connection(incoming, permit).await {
                    debug!(%remote, "connection ended: {e:#}");
                }
            });
        }
    }

    async fn handle_quic_connection(
        self,
        incoming: quinn::Incoming,
        permit: crate::limits::ConnectionPermit,
    ) -> Result<()> {
        let remote = incoming.remote_address();
        let conn = match tokio::time::timeout(HEADER_TIMEOUT, incoming).await {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                debug!(%remote, "QUIC handshake failed: {e}");
                return Ok(());
            }
            Err(_) => {
                debug!(%remote, "QUIC handshake timed out");
                return Ok(());
            }
        };
        let client_cert = conn
            .peer_identity()
            .and_then(|id| id.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>().ok())
            .and_then(|certs| tls::client_fingerprint(Some(&certs)));
        let transport = h3_quinn::Connection::new(conn.clone());
        let stopped = transport.send_stopped();
        let mut h3_conn: H3Connection = tokio::time::timeout(
            HEADER_TIMEOUT,
            h3::server::builder()
                .max_field_section_size(32 * 1024)
                .enable_extended_connect(true)
                .enable_datagram(true)
                .build(transport),
        )
        .await
        .context("HTTP/3 setup timed out")?
        .context("HTTP/3 setup")?;
        let info = ConnInfo::new("HTTP/3", remote, client_cert);
        *info.connection_permit.lock().unwrap() = Some(permit);
        let raise = conn.clone();
        *info.on_authenticated.lock().unwrap() =
            Some(Box::new(move || raise.set_max_concurrent_bi_streams(VarInt::from_u32(MAX_STREAMS))));
        let idle_timeout = self.settings().idle_timeout;

        // Exactly one datagram reader per connection; it hands each datagram
        // to the flow that owns the stream named by its quarter stream ID.
        let routes: Routes = Arc::default();
        let dispatcher = tokio::spawn(dispatch_datagrams(h3_conn.get_datagram_reader(), routes.clone()));
        // Request tasks ask the connection task for datagram senders, which
        // only the connection can create.
        let (sender_tx, mut sender_rx) = mpsc::channel::<(StreamId, oneshot::Sender<DgramSender>)>(64);

        let shutting_down = self.shutting_down();
        tokio::pin!(shutting_down);
        let mut draining = false;
        let result = loop {
            tokio::select! {
                accepted = h3_conn.accept() => match accepted {
                    Ok(Some(resolver)) => {
                        let (relay, info, conn, routes, sender_tx) =
                            (self.clone(), info.clone(), conn.clone(), routes.clone(), sender_tx.clone());
                        let stopped = stopped.clone();
                        let active = info.request_started();
                        tokio::spawn(async move {
                            let _active = active;
                            // Headers late: h3 rejects the request with
                            // H3_REQUEST_REJECTED (RFC 9114 §4.1.1). The outer
                            // bound covers a 431 response the client never
                            // takes.
                            let resolving = resolver.resolve_request_before(tokio::time::sleep(HEADER_TIMEOUT));
                            let (req, stream) = match tokio::time::timeout(2 * HEADER_TIMEOUT, resolving).await {
                                Ok(Ok(r)) => r,
                                // h3 has reset the stream: H3_MESSAGE_ERROR
                                // for a malformed request (RFC 9114 §4.1.2),
                                // H3_REQUEST_REJECTED for late headers.
                                Ok(Err(e)) if relay.settings().log_requests => {
                                    return tracing::info!(remote = %info.remote, "unusable HTTP/3 request: {e}")
                                }
                                Ok(Err(e)) => return debug!(remote = %info.remote, "unusable HTTP/3 request: {e}"),
                                Err(_) => return,
                            };
                            let notification = stopped.take(stream.id()).expect("accepted stream notification");
                            relay.handle_h3_request(req, stream, info, conn, routes, sender_tx, notification).await;
                        });
                    }
                    Ok(None) => break Ok(()),
                    Err(e) => break Err(anyhow::Error::new(e)),
                },
                Some((stream_id, reply)) = sender_rx.recv() => {
                    let _ = reply.send(h3_conn.get_datagram_sender(stream_id));
                }
                // QUIC keep-alives keep a connection open indefinitely; one
                // without requests is closed after the idle timeout (sooner
                // if it never authenticated), with GOAWAY first.
                _ = info.idle(idle_timeout), if !draining => {
                    debug!(%remote, "closing idle HTTP/3 connection");
                    send_goaway(&mut h3_conn).await;
                    conn.close(VarInt::from_u32(H3_NO_ERROR), b"");
                    break Ok(());
                }
                // Server shutdown: GOAWAY, so the client sends no new
                // requests here and may retry later ones elsewhere (RFC 9114
                // §5.2); the open ones go on until done or the process exits.
                _ = &mut shutting_down, if !draining => {
                    debug!(%remote, "server shutting down: GOAWAY");
                    send_goaway(&mut h3_conn).await;
                    draining = true;
                }
                _ = info.drained(), if draining => {
                    // Closing discards stream data the peer has not yet
                    // acknowledged, such as the last response's FIN: give it
                    // a few round trips, or until the client, which has had
                    // GOAWAY, closes the connection itself.
                    let grace = (conn.rtt() * 3).clamp(DRAIN_ACK_MIN, DRAIN_ACK_MAX);
                    let _ = tokio::time::timeout(grace, conn.closed()).await;
                    conn.close(VarInt::from_u32(H3_NO_ERROR), b"");
                    break Ok(());
                }
            }
        };
        dispatcher.abort();
        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_h3_request(
        self,
        req: http::Request<()>,
        mut stream: H3Stream,
        info: Arc<ConnInfo>,
        conn: quinn::Connection,
        routes: Routes,
        sender_tx: mpsc::Sender<(StreamId, oneshot::Sender<DgramSender>)>,
        stopped: h3_quinn::Stopped,
    ) {
        let closed_conn = conn.clone();
        let mut peer_closed: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> = Box::pin(async move {
            if matches!(stopped.await, Ok(None)) {
                // A fully acknowledged response FIN does not cancel the
                // other direction. Connection loss still must cancel it.
                closed_conn.closed().await;
            }
        });
        let is_connect = req.method() == Method::CONNECT;
        // The vendored h3 rejects malformed requests (RFC 9114 §4.1.2,
        // §4.3.1, §4.4) with H3_MESSAGE_ERROR before they get here, and passes
        // :protocol tokens it does not know as `OtherProtocol`.
        let protocol = req
            .extensions()
            .get::<h3::ext::Protocol>()
            .map(|p| p.as_str().to_string())
            .or_else(|| req.extensions().get::<h3::ext::OtherProtocol>().map(|p| p.as_str().to_string()));
        let kind = Kind::of_connect(is_connect, protocol.as_deref(), req.uri().scheme_str());
        let authority = req.uri().authority().map(|a| a.as_str().to_string());
        let path_and_query = req.uri().path_and_query().map_or("/", |p| p.as_str()).to_string();
        let settings = self.settings();
        let incoming = Incoming {
            method: req.method(),
            protocol: protocol.as_deref(),
            kind,
            authority: authority.as_deref(),
            path_and_query: &path_and_query,
            headers: req.headers(),
        };
        let stream_id = stream.id();
        let (bad_tx, mut bad_datagram) = oneshot::channel::<()>();
        let pending = if kind == Some(Kind::Udp) { Flow::PendingUdp } else { Flow::Other(Some(bad_tx)) };
        routes.lock().unwrap().register(stream_id, pending);
        let _route = RouteGuard { routes: routes.clone(), stream_id };
        let authorizing = self.authorize(&incoming, &info, &settings);
        tokio::pin!(authorizing);
        let authorized = loop {
            tokio::select! {
                biased;
                _ = &mut peer_closed => return cancel(&mut stream),
                Ok(()) = &mut bad_datagram => {
                    // A CONNECT's request stream stays open for its tunnel;
                    // reading it here would take the tunnel's first bytes.
                    if kind == Some(Kind::Tcp) || !receive_side_closed(&mut stream).await {
                        abort_datagram(&mut stream);
                        return;
                    }
                    bad_datagram = closed_receiver();
                }
                authorized = &mut authorizing => break authorized,
            }
        };
        let Some(authorized) = authorized else {
            let cover = web::cover(self.site().as_deref(), req.method(), req.uri().path(), is_connect);
            // `send_cover` stops the receive side first, so datagrams that
            // arrive meanwhile are dropped (RFC 9297 §2.1).
            tokio::select! {
                biased;
                _ = &mut peer_closed => {},
                _ = send_cover(&mut stream, cover, self.send_stall()) => {}
            }
            return;
        };

        if authorized.kind == Kind::Udp && !crate::proto::valid_capsule_headers(req.headers()) {
            stream.stop_stream(h3::error::Code::H3_MESSAGE_ERROR);
            stream.stop_sending(h3::error::Code::H3_MESSAGE_ERROR);
            return;
        }

        // Datagrams may arrive as soon as the client has sent the request,
        // before the response: route them to the flow from now on.
        let flow = (authorized.kind == Kind::Udp).then(|| {
            let (tx, rx) = mpsc::channel(FLOW_QUEUE);
            routes.lock().unwrap().add(stream_id, tx);
            rx
        });
        let opened = tokio::select! {
            biased;
            _ = &mut peer_closed => return cancel(&mut stream),
            Ok(()) = &mut bad_datagram => {
                abort_datagram(&mut stream);
                return;
            }
            opened = self.open(&authorized, &info, &settings) => opened,
        };
        let (opened, mut ctx) = match opened {
            Ok(o) => o,
            Err(refusal) => return send_refusal(stream, &refusal, self.send_stall()).await,
        };
        ctx.peer_closed = peer_closed;
        let mut resp = Response::builder().status(StatusCode::OK).header(DATE, http_date());
        if authorized.kind == Kind::Udp {
            resp = resp.header(CAPSULE_PROTOCOL_HEADER, "?1");
        }
        let sent = tokio::select! {
            biased;
            _ = ctx.cancelled() => {
                cancel(&mut stream);
                false
            },
            Ok(()) = &mut bad_datagram => {
                abort_datagram(&mut stream);
                false
            },
            result = stream.send_response(resp.body(()).expect("valid")) => result.is_ok(),
        };
        if !sent {
            opened.abort();
            return;
        }
        match opened {
            Opened::Tcp(tcp) => pump::tcp_over_h3(stream, tcp, ctx, bad_datagram).await,
            Opened::Udp(sock) => {
                let mut ctx = ctx;
                let (reply_tx, reply_rx) = oneshot::channel();
                let sender = tokio::select! {
                    biased;
                    _ = ctx.cancelled() => return cancel(&mut stream),
                    sender = async {
                        sender_tx.send((stream_id, reply_tx)).await.ok()?;
                        reply_rx.await.ok()
                    } => match sender { Some(sender) => sender, None => return },
                };
                let rx = flow.expect("UDP flows have a route");
                let datagrams = Datagrams::Quic(QuicDatagrams::new(sender, conn, stream_id, rx));
                pump::udp(Tunnel::h3_server(stream, datagrams), sock, ctx).await;
            }
        }
    }
}

/// Sends GOAWAY with the first request stream that will not be processed
/// (RFC 9114 §5.2), giving up after [`GOAWAY_TIMEOUT`]: requests at or past
/// it are rejected either way, and the connection is closed regardless.
async fn send_goaway(h3_conn: &mut H3Connection) {
    if tokio::time::timeout(GOAWAY_TIMEOUT, h3_conn.shutdown(0)).await.is_err() {
        debug!("GOAWAY could not be sent: the client grants no credit on the control stream");
    }
}

/// Removes a flow's datagram route when the request ends.
struct RouteGuard {
    routes: Routes,
    stream_id: StreamId,
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        self.routes.lock().unwrap().close(self.stream_id);
    }
}

/// Whether the client has finished sending on this request, reading and
/// discarding whatever body is already buffered. RFC 9297 §2.1: a datagram
/// on a request without datagram semantics aborts it with H3_DATAGRAM_ERROR,
/// unless the request's receive side is closed: then it is dropped.
async fn receive_side_closed(stream: &mut H3Stream) -> bool {
    let mut drained = 0;
    loop {
        {
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            match std::pin::pin!(stream.recv_data()).poll(&mut cx) {
                std::task::Poll::Ready(Ok(Some(_))) => {}
                std::task::Poll::Ready(Ok(None) | Err(_)) => return true,
                std::task::Poll::Pending => return false,
            }
        }
        drained += 1;
        if drained == 64 {
            // Empty DATA frames must not monopolise a runtime worker. Keep
            // checking for FIN instead of misclassifying a buffered closed side.
            tokio::task::yield_now().await;
            drained = 0;
        }
    }
}

/// Cancels a request in both directions with H3_REQUEST_CANCELLED (RFC 9114
/// §4.1.1): the client gave up on it (STOP_SENDING), its connection is gone,
/// or its user was revoked. Merely dropping the stream would stop the
/// client's sending with code 0, which HTTP/3 does not define.
fn cancel(stream: &mut H3Stream) {
    stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
    stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
}

/// A receiver that never yields a value, to disarm a datagram notification
/// that was already handled (a completed oneshot must not be polled again).
fn closed_receiver() -> oneshot::Receiver<()> {
    oneshot::channel().1
}

fn abort_datagram(stream: &mut H3Stream) {
    stream.stop_stream(h3::error::Code::H3_DATAGRAM_ERROR);
    stream.stop_sending(h3::error::Code::H3_DATAGRAM_ERROR);
}

/// Body bytes handed to the transport at a time, so that a response the
/// client stops reading is noticed within one [`super::SEND_STALL`].
const SEND_CHUNK: usize = 64 * 1024;

async fn send_cover(stream: &mut H3Stream, cover: Cover, stall: std::time::Duration) {
    // The answer never depends on a request body: stop the client sending
    // one, with the code RFC 9114 §4.1.2 asks for (dropping the stream
    // unread would send code 0).
    stream.stop_sending(h3::error::Code::H3_NO_ERROR);
    let mut resp = Response::builder().status(cover.status).header(DATE, http_date());
    for (name, value) in cover.headers {
        resp = resp.header(name, value);
    }
    send_response(stream, resp.body(()).expect("valid"), cover.body, stall).await;
}

async fn send_refusal(mut stream: H3Stream, refusal: &Refusal, stall: std::time::Duration) {
    stream.stop_sending(h3::error::Code::H3_NO_ERROR);
    let resp = Response::builder()
        .status(refusal.status())
        .header(DATE, http_date())
        .header("proxy-status", refusal.proxy_status())
        .body(())
        .expect("valid");
    send_response(&mut stream, resp, Bytes::new(), stall).await;
}

/// Sends a complete response. A client that leaves it unread (no flow
/// control credit) for `stall` gets the stream reset with
/// H3_REQUEST_CANCELLED instead of holding it open.
async fn send_response(stream: &mut H3Stream, resp: Response<()>, mut body: Bytes, stall: std::time::Duration) {
    let sent = async {
        tokio::time::timeout(stall, stream.send_response(resp)).await.ok()?.ok()?;
        while !body.is_empty() {
            let chunk = body.split_to(body.len().min(SEND_CHUNK));
            tokio::time::timeout(stall, stream.send_data(chunk)).await.ok()?.ok()?;
        }
        tokio::time::timeout(stall, stream.finish()).await.ok()?.ok()
    }
    .await;
    if sent.is_none() {
        stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
    }
}

async fn dispatch_datagrams(mut reader: DgramReader, routes: Routes) {
    while let Ok(datagram) = reader.read_datagram().await {
        let stream_id = datagram.stream_id();
        // The payload is a slice of the buffer Quinn received the packet in,
        // which can hold a whole batch of packets: copy it, so a queued
        // datagram holds only its own bytes.
        let payload = Bytes::copy_from_slice(&datagram.into_payload());
        routes.lock().unwrap().deliver(stream_id, payload);
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
        for _ in 0..100 {
            r.deliver(id(12), Bytes::from(vec![0; 65_535]));
        }
        assert!(r.early_bytes <= EARLY_DATAGRAM_BYTES, "counts alone do not bound bytes");
        assert!(r.early.len() < EARLY_DATAGRAMS);
        let (tx, _rx) = mpsc::channel(8);
        r.add(id(12), tx);
        assert_eq!(r.early_bytes, 0, "registering the flow refunds early capacity");
    }

    #[test]
    fn early_datagrams_are_held_only_briefly() {
        // No later datagram arrives to trigger deliver's pruning. Resolving
        // headers/authentication must not deliver or rejuvenate old packets.
        for pending in [false, true] {
            let mut r = Router::default();
            r.deliver(id(4), Bytes::from_static(b"stale"));
            let at = std::time::Instant::now() - EARLY_DATAGRAM_TTL * 2;
            r.early.front_mut().unwrap().2 = at;
            if pending {
                r.register(id(4), Flow::PendingUdp);
            }
            let (tx, mut rx) = mpsc::channel(8);
            r.add(id(4), tx);
            assert!(rx.try_recv().is_err(), "registration delivered an expired datagram");
            assert!(r.early.is_empty());
            assert_eq!(r.early_bytes, 0);
        }
        let mut r = Router::default();
        let Some(long_ago) = std::time::Instant::now().checked_sub(EARLY_DATAGRAM_TTL * 2) else { return };
        r.early.push_back((id(4), Bytes::from_static(b"stale"), long_ago));
        r.early_bytes = 5;
        r.deliver(id(8), Bytes::from_static(b"fresh"));
        assert_eq!(r.early.len(), 1, "a datagram older than the hold time is dropped");
        assert_eq!(r.early_bytes, 5);
        let (tx, mut rx) = mpsc::channel(8);
        r.add(id(4), tx);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn closed_streams_drop_late_datagrams_and_stay_bounded() {
        let mut r = Router::default();
        r.deliver(id(0), Bytes::from_static(b"held"));
        r.close(id(0));
        assert!(r.early.is_empty() && r.early_bytes == 0);
        r.deliver(id(0), Bytes::from_static(b"late"));
        assert!(r.early.is_empty(), "late datagrams for a closed stream are dropped");
        for n in 1..=(CLOSED_STREAMS as u64 + 10) {
            r.close(id(n * 4));
        }
        assert_eq!(r.closed.len(), CLOSED_STREAMS);
        assert_eq!(r.closed_set.len(), CLOSED_STREAMS);
        assert!(!r.closed_set.contains(&id(0)), "the oldest are forgotten");
    }

    #[test]
    fn requests_can_finish_authentication_out_of_order() {
        let mut r = Router::default();
        r.deliver(id(0), Bytes::from_static(b"early"));
        let arrived = r.early.front().unwrap().2;
        r.register(id(0), Flow::PendingUdp);
        assert_eq!(r.early.front().unwrap().2, arrived, "registration must not renew the hold time");
        let (tx4, _rx4) = mpsc::channel(8);
        r.add(id(4), tx4);
        r.deliver(id(0), Bytes::from_static(b"pending"));
        let (tx0, mut rx0) = mpsc::channel(8);
        r.add(id(0), tx0);
        assert_eq!(rx0.try_recv().unwrap(), "early");
        assert_eq!(rx0.try_recv().unwrap(), "pending");
        let (tx, mut rx) = oneshot::channel();
        r.deliver(id(8), Bytes::from_static(b"illegal"));
        r.register(id(8), Flow::Other(Some(tx)));
        assert!(rx.try_recv().is_ok(), "early datagram on a non-UDP request is rejected");
    }
}
