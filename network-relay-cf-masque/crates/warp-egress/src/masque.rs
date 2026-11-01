//! The tunnel: a CONNECT-IP request with IP packets in HTTP Datagrams
//! (RFC 9484, RFC 9297), over HTTP/3 (QUIC DATAGRAM frames) or HTTP/2
//! (DATAGRAM capsules on the request stream, for networks that block UDP).
//!
//! Cloudflare's servers differ from the RFC in a few ways (found by the
//! usque and mihomo projects): the `:protocol` is `cf-connect-ip`, the
//! server does not announce SETTINGS_ENABLE_CONNECT_PROTOCOL, and it
//! assigns no addresses and advertises no routes on the stream. The client
//! uses the addresses registration gave it and routes everything into the
//! tunnel. Over HTTP/2 the request is a plain CONNECT with the protocol in
//! a `cf-connect-proto` header, and DATAGRAM capsules carry the bare IP
//! packet without a Context ID. Like the official client, this one also
//! sends the datagram setting of draft 00; like usque and mihomo, it sends
//! no User-Agent (they set an empty one, which Go's HTTP stacks leave out)
//! and uses 20-byte connection IDs (shorter ones make the backend close
//! connections with PROTOCOL_VIOLATION now and then); like mihomo, it
//! advertises the default routes to the server once an HTTP/3 tunnel is
//! open (neither of them does so over HTTP/2).

use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use bytes::{Buf, Bytes, BytesMut};
use http::{Method, Request, StatusCode};
use quinn_proto::TransportErrorCode;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::varint;

pub const DEFAULT_SNI: &str = "consumer-masque.cloudflareclient.com";
pub const DEFAULT_URI: &str = "https://cloudflareaccess.com/";
pub const DEFAULT_PROTOCOL: &str = "cf-connect-ip";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// How long to wait for the server's SETTINGS, its first frame after the
/// handshake.
const SETTINGS_TIMEOUT: Duration = Duration::from_secs(5);
/// Packets waiting for the HTTP/2 stream, each way.
const H2_QUEUE: usize = 256;
/// How long the server may leave everything we sent it unanswered before
/// the connection counts as gone. QUIC itself waits for the idle timeout:
/// a server that restarted, or a path that went away, without a stateless
/// reset leaves the tunnel dead that long. The egress facade terminates its
/// socket generation on failure; a newly connected session uses fresh sockets.
const UNANSWERED: Duration = Duration::from_secs(10);
/// What mihomo uses; shorter connection IDs make Cloudflare's backend close
/// the connection with PROTOCOL_VIOLATION occasionally.
const CONNECTION_ID_LEN: u8 = 20;
/// The UDP payload size quinn starts with once the handshake is done (its
/// Initial packets are padded to `min_mtu`, 1200, whatever this is): room
/// for a 1280-byte IP packet, the IPv6 minimum link MTU that RFC 9484
/// §7.2 has a tunnel ensure, and the size Cloudflare's own client wants
/// (its documentation asks for 1333-byte UDP payloads: 1280 plus 53 bytes
/// of MASQUE). quinn reserves 1 + 20 (connection ID, at most) + 4 (packet
/// number) + 16 (AEAD tag) + 9 (DATAGRAM frame) bytes, and the Quarter
/// Stream ID and Context ID take 2 more. Path MTU discovery searches upward
/// from here; a path that cannot carry it makes quinn's black hole
/// detection fall back to 1200. (sing-box pads its Initial packets to 1331
/// for the same reason; mihomo starts at 1242 and relies on path MTU
/// discovery.)
const INITIAL_MTU: u16 = 1280 + 2 + 1 + 20 + 4 + 16 + 9;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Transport {
    H3,
    H2,
}

pub struct Options {
    pub endpoint: SocketAddr,
    pub sni: String,
    pub uri: String,
    pub protocol: &'static str,
    pub endpoint_spki: Vec<u8>,
    pub device_pkcs8: Vec<u8>,
    /// SO_MARK for the socket (Linux), so policy routing keeps the tunnel's
    /// own packets out of the tunnel.
    pub fwmark: Option<u32>,
    pub keepalive: Duration,
    pub idle_timeout: Duration,
    pub transport: Transport,
}

/// What became of a packet given to [`Tunnel::send_packet`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sent {
    Yes,
    /// Dropped: a QUIC datagram carries IP packets of at most this many
    /// bytes for now (it grows as path MTU discovery finds room).
    TooLarge(usize),
    /// Dropped: the queue to the HTTP/2 stream is full.
    QueueFull,
}

/// What carries the packets.
enum Link {
    Quic {
        conn: quinn::Connection,
        endpoint: quinn::Endpoint,
        /// The Quarter Stream ID that starts each datagram.
        qsid: Vec<u8>,
    },
    H2 {
        /// Capsules for the request stream; None once shut down.
        out: Mutex<Option<mpsc::Sender<Bytes>>>,
        /// IP packets from the response stream.
        inbound: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
        /// Why the stream ended, once it has.
        ended: watch::Receiver<Option<String>>,
    },
}

/// Cancel connection tasks if setup fails or its future is cancelled.
#[derive(Default)]
struct SetupTasks(Vec<JoinHandle<()>>);

impl SetupTasks {
    fn finish(mut self) -> Vec<JoinHandle<()>> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for SetupTasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

/// An open tunnel. Dropping it closes the connection.
pub struct Tunnel {
    link: Link,
    pub sent: AtomicU64,
    pub received: AtomicU64,
    pub dropped: Arc<AtomicU64>,
    closing: Arc<AtomicBool>,
    tasks: Vec<JoinHandle<()>>,
    /// Keeps the HTTP/3 connection open (dropping the last sender closes it).
    _send_request: Mutex<Option<Box<dyn std::any::Any + Send>>>,
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
        if let Link::Quic { conn, .. } = &self.link {
            conn.close(0u32.into(), b"");
        }
    }
}

impl Tunnel {
    pub async fn connect(opts: &Options) -> Result<Tunnel> {
        let r = match opts.transport {
            Transport::H3 => match connect_h3(opts).await {
                // Cloudflare's backend now and then closes a new connection
                // with PROTOCOL_VIOLATION; the next one works (usque retries
                // once too).
                Err(e) if mentions(&e, &TransportErrorCode::PROTOCOL_VIOLATION.to_string()) => {
                    warn!("{e:#}; trying once more");
                    connect_h3(opts).await
                }
                r => r,
            },
            Transport::H2 => connect_h2(opts).await,
        };
        r.map_err(explain)
    }

    /// "HTTP/3" or "HTTP/2".
    pub fn transport(&self) -> &'static str {
        match &self.link {
            Link::Quic { .. } => "HTTP/3",
            Link::H2 { .. } => "HTTP/2",
        }
    }

    /// The largest IP packet that fits one QUIC datagram right now; None
    /// over HTTP/2, where capsules have no such limit.
    pub fn max_packet(&self) -> Option<usize> {
        match &self.link {
            Link::Quic { conn, qsid, .. } => conn.max_datagram_size().map(|m| m.saturating_sub(qsid.len() + 1)),
            Link::H2 { .. } => None,
        }
    }

    /// Sends an IP packet (context ID 0).
    pub fn send_packet(&self, pkt: &[u8]) -> Result<Sent> {
        match &self.link {
            Link::Quic { conn, qsid, .. } => {
                let mut d = Vec::with_capacity(qsid.len() + 1 + pkt.len());
                d.extend_from_slice(qsid);
                d.push(0);
                d.extend_from_slice(pkt);
                match conn.send_datagram(Bytes::from(d)) {
                    Ok(()) => {
                        self.sent.fetch_add(1, Ordering::Relaxed);
                        Ok(Sent::Yes)
                    }
                    Err(quinn::SendDatagramError::TooLarge) => {
                        self.dropped.fetch_add(1, Ordering::Relaxed);
                        Ok(Sent::TooLarge(self.max_packet().unwrap_or(0)))
                    }
                    Err(e) => Err(anyhow!("sending a datagram: {e}")),
                }
            }
            Link::H2 { out, .. } => {
                let capsule = datagram_capsule(pkt);
                let out = out.lock().unwrap();
                let Some(out) = out.as_ref() else {
                    bail!("the tunnel is shut down");
                };
                match out.try_send(capsule) {
                    Ok(()) => {
                        self.sent.fetch_add(1, Ordering::Relaxed);
                        Ok(Sent::Yes)
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        self.dropped.fetch_add(1, Ordering::Relaxed);
                        Ok(Sent::QueueFull)
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        bail!("the tunnel stream is closed")
                    }
                }
            }
        }
    }

    /// The next IP packet from the server.
    pub async fn recv_packet(&self) -> Result<Bytes> {
        match &self.link {
            Link::Quic { conn, qsid, .. } => loop {
                let d = conn.read_datagram().await.map_err(|e| anyhow!("connection lost: {e}"))?;
                let Some(d) = h3_datagram_payload(d, qsid) else {
                    continue;
                };
                self.received.fetch_add(1, Ordering::Relaxed);
                return Ok(d);
            },
            Link::H2 { inbound, ended, .. } => {
                let pkt = inbound.lock().await.recv().await;
                match pkt {
                    Some(p) => {
                        self.received.fetch_add(1, Ordering::Relaxed);
                        Ok(p)
                    }
                    None => {
                        let why = ended.borrow().clone();
                        bail!("connection lost: {}", why.unwrap_or_else(|| "the stream ended".into()))
                    }
                }
            }
        }
    }

    /// Closes the connection and waits (briefly) for the close to be
    /// sent, so the server frees the session at once instead of at its
    /// idle timeout.
    pub async fn shutdown(&self) {
        self.closing.store(true, Ordering::Relaxed);
        match &self.link {
            // A connection that is already closed (by the server, or given
            // up on as unanswered) has nobody left to tell.
            Link::Quic { conn, endpoint, .. } if conn.close_reason().is_none() => {
                conn.close(0u32.into(), b"");
                let _ = tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle()).await;
            }
            Link::Quic { .. } => {}
            Link::H2 { out, ended, .. } => {
                // Dropping the sender ends the request stream.
                out.lock().unwrap().take();
                let mut ended = ended.clone();
                let _ = tokio::time::timeout(Duration::from_secs(2), ended.wait_for(|e| e.is_some())).await;
            }
        }
    }

    /// Resolves when the connection is gone.
    pub async fn closed(&self) -> String {
        match &self.link {
            Link::Quic { conn, .. } => tokio::select! {
                e = conn.closed() => e.to_string(),
                why = unanswered(conn) => {
                    conn.close(0u32.into(), b"no answer");
                    why
                }
            },
            Link::H2 { ended, .. } => {
                let mut ended = ended.clone();
                let why = ended.wait_for(|e| e.is_some()).await.map(|e| e.clone());
                match why {
                    Ok(e) => e.unwrap_or_default(),
                    Err(_) => "the tunnel ended".into(),
                }
            }
        }
    }
}

async fn connect_h3(opts: &Options) -> Result<Tunnel> {
    let mut tasks = SetupTasks::default();
    let tls = tls_config(opts, b"h3")?;
    let bind: SocketAddr = if opts.endpoint.is_ipv6() { "[::]:0".parse()? } else { "0.0.0.0:0".parse()? };
    let sock = std::net::UdpSocket::bind(bind).context("binding the UDP socket")?;
    if let Some(mark) = opts.fwmark {
        set_mark(&sock, mark)?;
    }
    let runtime = quinn::default_runtime().ok_or_else(|| anyhow!("no async runtime"))?;
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config
        .cid_generator(|| Box::new(quinn_proto::RandomConnectionIdGenerator::new(CONNECTION_ID_LEN as usize)));
    let mut endpoint = quinn::Endpoint::new(endpoint_config, None, sock, runtime)?;
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval((!opts.keepalive.is_zero()).then_some(opts.keepalive));
    transport.max_idle_timeout(Some(opts.idle_timeout.try_into().context("idle timeout")?));
    transport.initial_mtu(INITIAL_MTU);
    transport.datagram_receive_buffer_size(Some(4 << 20));
    transport.datagram_send_buffer_size(4 << 20);
    let mut client = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(tls)?));
    client.transport_config(Arc::new(transport));
    endpoint.set_default_client_config(client);

    info!("connecting to {} over QUIC (SNI {})", opts.endpoint, opts.sni);
    let connecting = endpoint.connect(opts.endpoint, &opts.sni).context("starting the QUIC connection")?;
    let conn = tokio::time::timeout(CONNECT_TIMEOUT, connecting)
        .await
        .context("the QUIC handshake timed out")?
        .map_err(|e| anyhow!("QUIC handshake: {e}"))?;
    debug!("QUIC connected; max datagram {:?}", conn.max_datagram_size());

    // SETTINGS_ENABLE_CONNECT_PROTOCOL says the sender accepts extended
    // CONNECT (RFC 9220), so only servers announce it (quic-go's client, in
    // usque and mihomo, does not); h3 sends :protocol either way.
    // Opening control/QPACK streams can wait indefinitely for peer credit;
    // keepalives can prevent QUIC's idle timeout throughout that wait.
    let setup = tokio::time::timeout(
        CONNECT_TIMEOUT,
        h3::client::builder()
            .enable_extended_connect(false)
            .enable_datagram(true)
            .enable_datagram_draft00(true)
            .build::<_, _, Bytes>(h3_quinn::Connection::new(conn.clone())),
    )
    .await;
    let (driver, mut send_request) = match setup {
        Ok(result) => result.context("HTTP/3 setup")?,
        Err(error) => {
            conn.close(0u32.into(), b"HTTP/3 setup timed out");
            return Err(error).context("HTTP/3 setup timed out");
        }
    };
    let mut driver = driver;
    tasks.0.push(tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    }));

    // RFC 9297 §2.1.1: no QUIC DATAGRAM frame until SETTINGS_H3_DATAGRAM
    // has been both sent and received with the value 1. The server's
    // SETTINGS are its first frame, so waiting costs no round trip.
    let settings = tokio::time::timeout(SETTINGS_TIMEOUT, async {
        loop {
            if let Some(s) = send_request.peer_settings() {
                return Ok(s);
            }
            if let Some(e) = send_request.connection_error() {
                return Err(anyhow!("HTTP/3 connection: {e}"));
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| Err(anyhow!("no SETTINGS frame from the server within {SETTINGS_TIMEOUT:?}")));
    let settings = match settings {
        Ok(s) => s,
        Err(e) => {
            conn.close(0u32.into(), b"");
            return Err(e);
        }
    };
    info!(
        "server settings: datagrams {}, draft-00 datagrams {}, extended CONNECT {}",
        settings.enable_datagram(),
        settings.enable_datagram_draft00(),
        settings.enable_extended_connect()
    );
    if !settings.enable_datagram() {
        conn.close(0u32.into(), b"");
        bail!("the server did not enable HTTP/3 datagrams (SETTINGS_H3_DATAGRAM), so it cannot carry a tunnel");
    }
    // No User-Agent: usque and mihomo set an empty one, which quic-go (like
    // Go's net/http) leaves out of the request.
    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(&opts.uri)
        .header("capsule-protocol", "?1")
        .extension(h3::ext::Protocol::from_static(opts.protocol));
    let req = req.body(()).context("building the request")?;
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, send_request.send_request(req))
        .await
        .context("sending the CONNECT request timed out")?
        .map_err(|e| anyhow!("sending the CONNECT request: {e}"))?;
    let resp = tokio::time::timeout(CONNECT_TIMEOUT, stream.recv_response())
        .await
        .context("waiting for the CONNECT response timed out")?
        .map_err(|e| anyhow!("CONNECT response: {e}"))?;
    let status = resp.status();
    let headers = resp.headers().clone();
    if let Err(e) = check_response(status, &headers) {
        conn.close(0u32.into(), b"");
        return Err(e);
    }
    let stream_id: u64 = stream.id().into_inner();
    let mut qsid = Vec::new();
    varint::encode(&mut qsid, stream_id / 4);
    info!("tunnel open over HTTP/3: {status}, stream {stream_id}, {}", describe(&headers));
    // Tell the server we take everything (RFC 9484 §4.7.3), as mihomo does.
    tokio::time::timeout(CONNECT_TIMEOUT, stream.send_data(route_advertisement()))
        .await
        .context("sending the ROUTE_ADVERTISEMENT capsule timed out")?
        .context("sending the ROUTE_ADVERTISEMENT capsule")?;

    // Capsules from the server, on the request stream.
    let conn2 = conn.clone();
    let assigned = Mutex::new(Vec::new());
    let closing = Arc::new(AtomicBool::new(false));
    let closing2 = closing.clone();
    let capsules = tokio::spawn(async move {
        let mut decoder = CapsuleDecoder::default();
        loop {
            match stream.recv_data().await {
                Ok(Some(mut data)) => {
                    while data.has_remaining() {
                        let chunk = data.chunk();
                        if let Err(e) = decoder.push(chunk, &assigned, &mut |_| {}) {
                            warn!("invalid capsule: {e:#}");
                            conn2.close(0u32.into(), b"invalid capsule");
                            return;
                        }
                        let n = chunk.len();
                        data.advance(n);
                    }
                }
                Ok(None) => {
                    if !closing2.load(Ordering::Relaxed) {
                        warn!("the server ended the request stream");
                    }
                    conn2.close(0u32.into(), b"stream ended");
                    return;
                }
                Err(e) => {
                    if !closing2.load(Ordering::Relaxed) {
                        warn!("request stream failed: {e}");
                    }
                    conn2.close(0u32.into(), b"stream failed");
                    return;
                }
            }
        }
    });

    tasks.0.push(capsules);
    Ok(Tunnel {
        link: Link::Quic { conn, endpoint, qsid },
        sent: AtomicU64::new(0),
        received: AtomicU64::new(0),
        dropped: Arc::new(AtomicU64::new(0)),
        closing,
        tasks: tasks.finish(),
        _send_request: Mutex::new(Some(Box::new(send_request))),
    })
}

async fn connect_h2(opts: &Options) -> Result<Tunnel> {
    let mut tasks = SetupTasks::default();
    let tls = tls_config(opts, b"h2")?;
    let socket =
        if opts.endpoint.is_ipv6() { tokio::net::TcpSocket::new_v6() } else { tokio::net::TcpSocket::new_v4() }
            .context("creating the TCP socket")?;
    if let Some(mark) = opts.fwmark {
        set_mark(&socket, mark)?;
    }
    info!("connecting to {} over TCP (SNI {})", opts.endpoint, opts.sni);
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(opts.endpoint))
        .await
        .context("the TCP connection timed out")?
        .context("TCP connection")?;
    tcp.set_nodelay(true).ok();
    let name = ServerName::try_from(opts.sni.clone()).context("the SNI is not a valid name")?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls));
    let tls_stream = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(name, tcp))
        .await
        .context("the TLS handshake timed out")?
        .map_err(|e| anyhow!("TLS handshake: {e}"))?;
    // Cloudflare's endpoint confirms no ALPN protocol at all, and speaks
    // HTTP/2 all the same; mihomo, too, speaks HTTP/2 whatever the server
    // answers. A pinned WARP endpoint must not confirm another protocol.
    let alpn = tls_stream.get_ref().1.alpn_protocol().map(|p| p.to_vec());
    match alpn.as_deref() {
        Some(b"h2") => {}
        None => debug!("the server confirmed no ALPN protocol; speaking HTTP/2"),
        _ => bail!(
            "the server did not negotiate HTTP/2 (ALPN {})",
            alpn.map(|a| String::from_utf8_lossy(&a).into_owned()).unwrap_or_else(|| "none".into())
        ),
    }
    let (send_request, mut connection) = tokio::time::timeout(
        CONNECT_TIMEOUT,
        h2::client::Builder::new()
            .initial_window_size(4 << 20)
            .initial_connection_window_size(8 << 20)
            .handshake::<_, Bytes>(tls_stream),
    )
    .await
    .context("HTTP/2 setup timed out")?
    .map_err(|e| anyhow!("HTTP/2 setup: {e}"))?;
    let (ended_tx, ended) = watch::channel::<Option<String>>(None);
    let mut ping = connection.ping_pong().context("HTTP/2 ping handle")?;
    let keepalive = opts.keepalive;
    let idle_timeout = opts.idle_timeout;
    tasks.0.push({
        let ended_tx = ended_tx.clone();
        tokio::spawn(async move {
            let health = async {
                if keepalive.is_zero() && idle_timeout.is_zero() {
                    return std::future::pending::<String>().await;
                }
                let interval = if keepalive.is_zero() { idle_timeout } else { keepalive };
                loop {
                    tokio::time::sleep(interval).await;
                    let pong = ping.ping(h2::Ping::opaque());
                    let result = if idle_timeout.is_zero() {
                        pong.await
                    } else {
                        match tokio::time::timeout(idle_timeout, pong).await {
                            Ok(result) => result,
                            Err(_) => return "HTTP/2 keepalive acknowledgement timed out".into(),
                        }
                    };
                    if let Err(e) = result {
                        return format!("HTTP/2 keepalive: {e}");
                    }
                }
            };
            drive_h2_connection(connection, health, ended_tx).await;
        })
    });
    // No User-Agent, as over HTTP/3.
    let uri: http::Uri = opts.uri.parse().context("the URI")?;
    let host = uri.host().context("the URI has no host")?;
    let authority = format!("{host}:{}", uri.port_u16().unwrap_or(443));
    // WARP uses plain CONNECT and private headers, not RFC 8441.
    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://{authority}/"))
        .header("cf-connect-proto", opts.protocol)
        .header("pq-enabled", "false");
    let req = req.body(()).context("building the request")?;
    let mut send_request = tokio::time::timeout(CONNECT_TIMEOUT, send_request.ready())
        .await
        .context("waiting for the HTTP/2 connection timed out")?
        .map_err(|e| anyhow!("HTTP/2 connection: {e}"))?;
    let (response, send_stream) =
        send_request.send_request(req, false).map_err(|e| anyhow!("sending the CONNECT request: {e}"))?;
    let resp = tokio::time::timeout(CONNECT_TIMEOUT, response)
        .await
        .context("waiting for the CONNECT response timed out")?
        .map_err(|e| anyhow!("CONNECT response: {e}"))?;
    let status = resp.status();
    let headers = resp.headers().clone();
    check_response(status, &headers)?;
    info!("tunnel open over HTTP/2: {status}, {}", describe(&headers));
    let mut recv_stream = resp.into_body();

    let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(H2_QUEUE);
    let (in_tx, in_rx) = mpsc::channel::<Bytes>(H2_QUEUE);
    let writer = {
        let ended_tx = ended_tx.clone();
        tokio::spawn(async move {
            let mut send_stream = send_stream;
            while let Some(capsule) = out_rx.recv().await {
                if let Err(e) = send_h2_capsule(&mut send_stream, capsule).await {
                    record_h2_failure(&ended_tx, format!("HTTP/2 stream: {e}"));
                    return;
                }
            }
            let _ = send_stream.send_data(Bytes::new(), true);
        })
    };
    let assigned = Mutex::new(Vec::new());
    let closing = Arc::new(AtomicBool::new(false));
    let closing2 = closing.clone();
    let dropped = Arc::new(AtomicU64::new(0));
    let receive_drops = dropped.clone();
    let reader = tokio::spawn(async move {
        let mut decoder = CapsuleDecoder::default();
        while let Some(chunk) = recv_stream.data().await {
            match chunk {
                Ok(data) => {
                    let _ = recv_stream.flow_control().release_capacity(data.len());
                    let parsed = decoder.push(&data, &assigned, &mut |payload: &[u8]| {
                        if in_tx.try_send(Bytes::copy_from_slice(payload)).is_err() {
                            receive_drops.fetch_add(1, Ordering::Relaxed);
                            debug!("dropped a packet from the server: the queue is full");
                        }
                    });
                    if let Err(e) = parsed {
                        record_h2_failure(&ended_tx, format!("invalid capsule: {e:#}"));
                        return;
                    }
                }
                Err(e) => {
                    if !closing2.load(Ordering::Relaxed) {
                        warn!("response stream failed: {e}");
                    }
                    record_h2_failure(&ended_tx, format!("HTTP/2 stream: {e}"));
                    return;
                }
            }
        }
        if !closing2.load(Ordering::Relaxed) {
            warn!("the server ended the response stream");
        }
        record_h2_failure(&ended_tx, "the server ended the stream".into());
    });

    tasks.0.extend([writer, reader]);
    Ok(Tunnel {
        link: Link::H2 { out: Mutex::new(Some(out_tx)), inbound: tokio::sync::Mutex::new(in_rx), ended },
        sent: AtomicU64::new(0),
        received: AtomicU64::new(0),
        dropped,
        closing,
        tasks: tasks.finish(),
        _send_request: Mutex::new(None),
    })
}

/// Resolves once the server has left an ack-eliciting packet of ours (a
/// datagram, a keepalive PING, stream data) without any answer for
/// [`UNANSWERED`]. An idle tunnel sends keepalives, so a silent server is
/// noticed within the keepalive interval plus that.
async fn unanswered(conn: &quinn::Connection) -> String {
    let mut silence = Silence::default();
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    loop {
        tick.tick().await;
        let s = conn.stats();
        let waited = silence.update(tokio::time::Instant::now(), s.udp_rx.datagrams, awaiting_answer(&s));
        if waited >= UNANSWERED {
            return format!("no answer from the server for {}s", waited.as_secs());
        }
    }
}

/// The ack-eliciting frames sent so far, but for path MTU probes: a probe
/// larger than the path is lost by design, and after the last one of a
/// search an idle tunnel may send nothing else for a while.
fn awaiting_answer(s: &quinn::ConnectionStats) -> u64 {
    s.frame_tx.datagram + s.frame_tx.stream + s.frame_tx.ping - s.path.sent_plpmtud_probes.min(s.frame_tx.ping)
}

/// How long the server has left what we sent unanswered, from counts of
/// the UDP datagrams received and of the ack-eliciting frames sent.
#[derive(Default)]
struct Silence {
    received: u64,
    sent: u64,
    since: Option<tokio::time::Instant>,
}

impl Silence {
    fn update(&mut self, now: tokio::time::Instant, received: u64, sent: u64) -> Duration {
        if received != self.received {
            *self = Silence { received, sent, since: None };
        } else if sent != self.sent && self.since.is_none() {
            self.since = Some(now);
        }
        self.since.map_or(Duration::ZERO, |t| now - t)
    }
}

fn record_h2_failure(ended: &watch::Sender<Option<String>>, why: String) {
    ended.send_if_modified(|first| {
        if first.is_some() {
            return false;
        }
        *first = Some(why);
        true
    });
}

async fn drive_h2_connection(
    connection: impl std::future::Future<Output = std::result::Result<(), h2::Error>>,
    health: impl std::future::Future<Output = String>,
    ended: watch::Sender<Option<String>>,
) {
    // Keep the connection alive until its original failure is recorded.
    // Dropping it inside select would wake stream tasks first; their broken
    // pipe errors could mask the health-check timeout that caused shutdown.
    tokio::pin!(connection);
    let why = tokio::select! {
        result = &mut connection => match result {
            Ok(()) => "the HTTP/2 connection ended".to_string(),
            Err(e) => format!("HTTP/2 connection: {e}"),
        },
        why = health => why,
    };
    record_h2_failure(&ended, why);
}

async fn send_h2_capsule(stream: &mut h2::SendStream<Bytes>, mut capsule: Bytes) -> Result<()> {
    while !capsule.is_empty() {
        stream.reserve_capacity(capsule.len());
        let capacity = poll_fn(|cx| stream.poll_capacity(cx)).await.context("the HTTP/2 stream closed")??;
        // Send what the peer permits now. Waiting for the entire capsule
        // would deadlock when it is larger than the peer's receive window:
        // the peer can only release capacity after receiving DATA.
        let chunk = capsule.split_to(capacity.min(capsule.len()));
        stream.send_data(chunk, false)?;
    }
    Ok(())
}

fn h3_datagram_payload(mut datagram: Bytes, qsid: &[u8]) -> Option<Bytes> {
    let (expected, _) = varint::decode(qsid)?;
    let (stream, n) = varint::decode(&datagram)?;
    if stream != expected {
        return None;
    }
    datagram.advance(n);
    let (context, n) = varint::decode(&datagram)?;
    if context != 0 {
        return None;
    }
    datagram.advance(n);
    Some(datagram)
}

fn mentions(e: &anyhow::Error, what: &str) -> bool {
    format!("{e:#}").contains(what)
}

/// Says what a failure means when its message does not: TLS alert 49,
/// access_denied, is how Cloudflare turns away a key it does not know (as
/// usque and mihomo report it).
fn explain(e: anyhow::Error) -> anyhow::Error {
    if mentions(&e, &TransportErrorCode::crypto(49).to_string()) || mentions(&e, "AccessDenied") {
        e.context(
            "the server turned the device key away (TLS access_denied): it is not enrolled, \
             or the device was deleted; renew enrollment and update [warp.registration]",
        )
    } else {
        e
    }
}

/// RFC 9484 §4.5: a 2xx response that meets the Capsule Protocol's
/// requirements, which exclude content (RFC 9297 §3.2). A website
/// answering a CONNECT it does not understand fails both.
fn check_response(status: StatusCode, headers: &http::HeaderMap) -> Result<()> {
    if !network_relay::proto::valid_capsule_headers(headers) {
        bail!(
            "the server answered the CONNECT like a website ({status}, with content metadata), not as a tunnel: \
             wrong credentials, path or protocol? ({})",
            describe(headers)
        );
    }
    if !status.is_success() {
        bail!("the server refused the tunnel: {status} ({})", describe(headers));
    }
    Ok(())
}

fn describe(h: &http::HeaderMap) -> String {
    h.iter()
        // Headers are peer-controlled and may contain credentials/cookies.
        // Names suffice for diagnostics; never log arbitrary header values.
        .map(|(k, _)| k.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// WARP's H2 DATAGRAM capsule carries bare IP, with no context ID.
fn datagram_capsule(pkt: &[u8]) -> Bytes {
    let mut wire = BytesMut::new();
    network_relay::proto::capsule::encode(0, pkt, &mut wire);
    wire.freeze()
}

/// A ROUTE_ADVERTISEMENT capsule (RFC 9484 §4.7.3) for all of IPv4 and
/// IPv6, any protocol.
fn route_advertisement() -> Bytes {
    let mut value = Vec::with_capacity(10 + 34);
    value.push(4);
    value.extend_from_slice(&[0; 4]);
    value.extend_from_slice(&[255; 4]);
    value.push(0);
    value.push(6);
    value.extend_from_slice(&[0; 16]);
    value.extend_from_slice(&[255; 16]);
    value.push(0);
    let mut wire = BytesMut::new();
    network_relay::proto::capsule::encode(0x03, &value, &mut wire);
    wire.freeze()
}

/// Bound known capsule payloads to one maximum-size IP packet plus framing.
const MAX_CAPSULE_SIZE: usize = 65_536 + 8;

#[derive(Default)]
struct CapsuleDecoder {
    buf: Vec<u8>,
    skip: u64,
}

impl CapsuleDecoder {
    /// Read incrementally: unknown capsule payloads are skipped without buffering.
    fn push(&mut self, mut data: &[u8], assigned: &Mutex<Vec<IpAddr>>, datagram: &mut dyn FnMut(&[u8])) -> Result<()> {
        loop {
            if self.skip != 0 {
                let n = self.skip.min(data.len() as u64) as usize;
                if n == 0 {
                    return Ok(());
                }
                self.skip -= n as u64;
                data = &data[n..];
                continue;
            }
            let n1 = self.buf.first().map_or(1, |b| 1 << (b >> 6));
            let header = if self.buf.len() < n1 {
                n1
            } else if self.buf.len() == n1 {
                n1 + 1
            } else {
                n1 + (1 << (self.buf[n1] >> 6))
            };
            if self.buf.len() < header {
                let n = (header - self.buf.len()).min(data.len());
                if n == 0 {
                    return Ok(());
                }
                self.buf.extend_from_slice(&data[..n]);
                data = &data[n..];
                continue;
            }
            let (typ, _) = varint::decode(&self.buf).expect("complete capsule type");
            let (len, _) = varint::decode(&self.buf[n1..]).expect("complete capsule length");
            if !matches!(typ, 0..=3) {
                self.skip = len;
                self.buf.clear();
                continue;
            }
            if len > MAX_CAPSULE_SIZE as u64 {
                bail!("capsule type {typ:#x} exceeds the {MAX_CAPSULE_SIZE}-byte limit");
            }
            let total = header + len as usize;
            if self.buf.len() < total {
                let n = (total - self.buf.len()).min(data.len());
                if n == 0 {
                    return Ok(());
                }
                self.buf.extend_from_slice(&data[..n]);
                data = &data[n..];
                continue;
            }
            let value = &self.buf[header..];
            match typ {
                0 => datagram(value),
                1 => {
                    let addrs = parse_addresses(value)?;
                    info!("ADDRESS_ASSIGN capsule: {}", describe_addresses(&addrs));
                    *assigned.lock().unwrap() =
                        addrs.into_iter().filter_map(|(a, bits)| usable_address(a, bits)).collect();
                }
                2 => info!("ADDRESS_REQUEST capsule ({} bytes)", value.len()),
                3 => info!("ROUTE_ADVERTISEMENT capsule ({} bytes)", value.len()),
                _ => unreachable!(),
            }
            self.buf.clear();
        }
    }
}

/// The (address, prefix length) entries of an ADDRESS_ASSIGN value.
fn parse_addresses(mut v: &[u8]) -> Result<Vec<(IpAddr, u8)>> {
    let mut out = vec![];
    while !v.is_empty() {
        let (_id, n) = varint::decode(v).context("truncated address request ID")?;
        v = &v[n..];
        let &version = v.first().context("missing address IP version")?;
        let alen = match version {
            4 => 4,
            6 => 16,
            _ => bail!("invalid address IP version: {version}"),
        };
        if v.len() < 1 + alen + 1 {
            bail!("truncated address assignment");
        }
        let addr = if alen == 4 {
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&v[1..5]).unwrap()))
        } else {
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&v[1..17]).unwrap()))
        };
        let prefix = v[1 + alen];
        let bits = (alen * 8) as u8;
        if prefix > bits {
            bail!("address prefix length {prefix} exceeds {bits} bits");
        }
        let trailing_zeros = match addr {
            IpAddr::V4(a) => u32::from(a).trailing_zeros(),
            IpAddr::V6(a) => u128::from(a).trailing_zeros(),
        };
        if trailing_zeros < u32::from(bits - prefix) {
            bail!("address prefix {addr}/{prefix} has nonzero host bits");
        }
        out.push((addr, prefix));
        v = &v[1 + alen + 1..];
    }
    Ok(out)
}

/// The address to use from an assigned prefix (RFC 9484 §4.7.1 lets the
/// client pick any in it): the address itself for a single one, else the
/// prefix's first host address, as sing-box picks; the all-zeros one is
/// IPv4's network address and IPv6's Subnet-Router anycast address. None for
/// a rejection, an all-zeros address.
fn usable_address(addr: IpAddr, bits: u8) -> Option<IpAddr> {
    match addr {
        _ if addr.is_unspecified() => None,
        IpAddr::V4(a) if bits < 32 && u32::from(a) & (u32::MAX >> bits) == 0 => {
            Some(IpAddr::V4(Ipv4Addr::from(u32::from(a) + 1)))
        }
        IpAddr::V6(a) if bits < 128 && u128::from(a) & (u128::MAX >> bits) == 0 => {
            Some(IpAddr::V6(Ipv6Addr::from(u128::from(a) + 1)))
        }
        // A single address, or one with host bits set (which the RFC
        // forbids): as given.
        _ => Some(addr),
    }
}

fn describe_addresses(addrs: &[(IpAddr, u8)]) -> String {
    if addrs.is_empty() {
        return "(empty)".into();
    }
    addrs.iter().map(|(a, bits)| format!("{a}/{bits}")).collect::<Vec<_>>().join(" ")
}

fn tls_config(opts: &Options, alpn: &[u8]) -> Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("TLS versions")?;
    let builder = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedKey { spki: opts.endpoint_spki.clone(), provider }));
    let (cert, key) = device_certificate(&opts.device_pkcs8)?;
    let mut cfg = builder.with_client_auth_cert(vec![cert], key).context("client certificate")?;
    cfg.alpn_protocols = vec![alpn.to_vec()];
    Ok(cfg)
}

/// A self-signed certificate for the device key, valid for a day, as the
/// official client makes for each connection.
fn device_certificate(pkcs8_der: &[u8]) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(pkcs8_der),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .context("the private key in the configuration")?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::minutes(5);
    params.not_after = now + time::Duration::hours(24);
    let cert = params.self_signed(&key).context("making the device certificate")?;
    Ok((cert.der().clone(), PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der.to_vec()))))
}

/// Accepts the server's certificate if it carries the expected public key.
#[derive(Debug)]
struct PinnedKey {
    spki: Vec<u8>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedKey {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let (remaining, cert) = x509_parser::parse_x509_certificate(end_entity.as_ref())
            .map_err(|e| rustls::Error::General(format!("parsing the server certificate: {e}")))?;
        if remaining.is_empty() && cert.tbs_certificate.subject_pki.raw == self.spki.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("the server's public key is not the endpoint key registration gave us".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(target_os = "linux")]
fn set_mark(sock: &impl std::os::fd::AsFd, mark: u32) -> Result<()> {
    socket2::SockRef::from(sock).set_mark(mark).context("setting SO_MARK (needs root)")
}

#[cfg(not(target_os = "linux"))]
fn set_mark(_sock: &impl std::os::fd::AsFd, _mark: u32) -> Result<()> {
    bail!("fwmark is only available on Linux")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_pin_rejects_trailing_certificate_der() {
        use rcgen::PublicKeyData;
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap().self_signed(&key).unwrap();
        let pin = PinnedKey {
            spki: key.subject_public_key_info(),
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        };
        let name = ServerName::try_from("localhost").unwrap();
        let now = UnixTime::since_unix_epoch(Duration::from_secs(1));
        assert!(pin.verify_server_cert(certificate.der(), &[], &name, &[], now).is_ok());
        let mut malformed = certificate.der().to_vec();
        malformed.push(0);
        assert!(pin.verify_server_cert(&CertificateDer::from(malformed), &[], &name, &[], now).is_err());
    }

    #[test]
    fn capsules_are_drained_and_partial_ones_kept() {
        let mut buf = vec![0x01, 7, 0, 4, 10, 0, 0, 2, 32]; // ADDRESS_ASSIGN 10.0.0.2/32
        buf.extend_from_slice(&[0x03, 50, 1, 2]); // a ROUTE_ADVERTISEMENT cut short
        let assigned = Mutex::new(vec![]);
        let mut decoder = CapsuleDecoder::default();
        decoder.push(&buf, &assigned, &mut |_| panic!("no datagram")).unwrap();
        assert_eq!(*assigned.lock().unwrap(), vec!["10.0.0.2".parse::<IpAddr>().unwrap()]);
        assert_eq!(decoder.buf, vec![0x03, 50, 1, 2]);
    }

    #[test]
    fn datagram_capsules_deliver_packets() {
        let pkt = [0x45u8, 0, 0, 20];
        let mut buf = datagram_capsule(&network_relay::proto::datagram::udp_payload(&pkt)).to_vec();
        buf.extend_from_slice(&datagram_capsule(&pkt));
        assert_eq!(buf[..3], [0x00, 5, 0]);
        let mut seen = vec![];
        let mut decoder = CapsuleDecoder::default();
        decoder.push(&buf, &Mutex::new(vec![]), &mut |p| seen.push(p.to_vec())).unwrap();
        assert_eq!(seen, vec![vec![0, 0x45, 0, 0, 20], pkt.to_vec()]);
        assert!(decoder.buf.is_empty());
    }

    #[test]
    fn a_key_turned_away_is_explained() {
        // How quinn reports the alert over QUIC, and rustls over TCP.
        let quic = anyhow!("QUIC handshake: aborted by peer: {}", TransportErrorCode::crypto(49));
        let tcp = anyhow!("TLS handshake: received fatal alert: AccessDenied");
        for e in [quic, tcp] {
            let shown = format!("{:#}", explain(e));
            assert!(shown.starts_with("the server turned the device key away"), "{shown}");
        }
        let other = format!("{:#}", explain(anyhow!("timed out")));
        assert_eq!(other, "timed out");
        assert!(mentions(
            &anyhow!("connection lost: {}", TransportErrorCode::PROTOCOL_VIOLATION),
            "detected an error with protocol compliance"
        ));
    }

    #[test]
    fn silence_counts_only_while_something_awaits_an_answer() {
        let t0 = tokio::time::Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let mut s = Silence::default();
        // The server talks; we answer with ACKs only: no waiting.
        assert_eq!(s.update(at(0), 5, 0), Duration::ZERO);
        assert_eq!(s.update(at(30), 5, 0), Duration::ZERO);
        // A keepalive goes out at 31 s and is answered at 32 s.
        assert_eq!(s.update(at(31), 5, 1), Duration::ZERO);
        assert_eq!(s.update(at(32), 6, 1), Duration::ZERO);
        // Datagrams from 40 s on, and nothing back: waiting since then,
        // however many more we send.
        assert_eq!(s.update(at(40), 6, 2), Duration::ZERO);
        assert_eq!(s.update(at(45), 6, 50), Duration::from_secs(5));
        assert_eq!(s.update(at(50), 6, 90), Duration::from_secs(10));
        // Anything from the server starts over.
        assert_eq!(s.update(at(51), 7, 91), Duration::ZERO);
        assert_eq!(s.update(at(70), 7, 91), Duration::ZERO);
    }

    #[test]
    fn path_mtu_probes_await_no_answer() {
        let mut s = quinn::ConnectionStats::default();
        s.frame_tx.datagram = 5;
        s.frame_tx.stream = 2;
        s.frame_tx.ping = 4;
        s.path.sent_plpmtud_probes = 3;
        assert_eq!(awaiting_answer(&s), 8);
        // A lost probe changes nothing.
        let before = awaiting_answer(&s);
        s.frame_tx.ping += 1;
        s.path.sent_plpmtud_probes += 1;
        assert_eq!(awaiting_answer(&s), before);
        // A keepalive does.
        s.frame_tx.ping += 1;
        assert_eq!(awaiting_answer(&s), before + 1);
    }

    #[test]
    fn assigned_prefixes_give_a_host_address() {
        let usable = |a: &str, bits| usable_address(a.parse().unwrap(), bits);
        let ip = |a: &str| Some(a.parse::<IpAddr>().unwrap());
        assert_eq!(usable("10.0.0.2", 32), ip("10.0.0.2"));
        assert_eq!(usable("10.0.0.0", 24), ip("10.0.0.1"));
        assert_eq!(usable("10.0.0.0", 31), ip("10.0.0.1"));
        assert_eq!(usable("10.0.0.5", 24), ip("10.0.0.5"));
        assert_eq!(usable("2001:db8:1::", 64), ip("2001:db8:1::1"));
        assert_eq!(usable("2001:db8::7", 128), ip("2001:db8::7"));
        // Rejections of an ADDRESS_REQUEST.
        assert_eq!(usable("0.0.0.0", 32), None);
        assert_eq!(usable("::", 128), None);
        // From the stream: a /24 is used by its first host address.
        let mut decoder = CapsuleDecoder::default();
        let assigned = Mutex::new(vec![]);
        decoder.push(&[0x01, 7, 0, 4, 10, 9, 8, 0, 24], &assigned, &mut |_| {}).unwrap();
        assert_eq!(*assigned.lock().unwrap(), [ip("10.9.8.1").unwrap()]);
    }

    #[test]
    fn route_advertisement_is_well_formed() {
        let c = route_advertisement();
        assert_eq!(c[0], 0x03);
        assert_eq!(c[1] as usize, c.len() - 2);
        assert_eq!(c.len(), 2 + 10 + 34);
        assert_eq!(c[2], 4);
        assert_eq!(c[12], 6);
    }
}

#[cfg(test)]
mod decoder_tests {
    use super::*;
    use rand::{Rng, SeedableRng};

    /// Mangled capsule streams, in fragments of any size, never panic the
    /// decoder or make it hold more than one capsule's worth of data.
    #[test]
    fn mangled_streams_never_panic() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5ca1ab1e);
        let mut valid = datagram_capsule(&network_relay::proto::datagram::udp_payload(&[0x45; 60])).to_vec();
        valid.extend_from_slice(&[0x01, 7, 0, 4, 10, 0, 0, 2, 32]);
        valid.extend_from_slice(&route_advertisement());
        valid.extend_from_slice(&datagram_capsule(&[0x60; 80]));
        for _ in 0..20_000 {
            let mut bytes = valid.clone();
            for _ in 0..rng.random_range(1..6) {
                let i = rng.random_range(0..bytes.len());
                match rng.random_range(0..3) {
                    0 => bytes[i] = rng.random(),
                    1 => bytes.truncate(i),
                    _ => bytes.insert(i, rng.random()),
                }
                if bytes.is_empty() {
                    break;
                }
            }
            let mut decoder = CapsuleDecoder::default();
            let assigned = Mutex::new(vec![]);
            let mut rest = &bytes[..];
            while !rest.is_empty() {
                let n = rng.random_range(1..=rest.len());
                if decoder.push(&rest[..n], &assigned, &mut |_| {}).is_err() {
                    break;
                }
                rest = &rest[n..];
                assert!(decoder.buf.len() <= MAX_CAPSULE_SIZE + 16);
            }
        }
    }

    #[test]
    fn h3_datagrams_accept_every_valid_integer_width() {
        let payload = [0x45, 1, 2, 3];
        for stream_len in [1, 2, 4, 8] {
            for context_len in [1, 2, 4, 8] {
                let wide = |value: u64, len: usize| {
                    let mut bytes = value.to_be_bytes()[8 - len..].to_vec();
                    bytes[0] |= match len {
                        1 => 0,
                        2 => 0x40,
                        4 => 0x80,
                        8 => 0xc0,
                        _ => unreachable!(),
                    };
                    bytes
                };
                let datagram = [wide(37, stream_len), wide(0, context_len), payload.to_vec()].concat();
                assert_eq!(h3_datagram_payload(Bytes::from(datagram), &[37]).unwrap().as_ref(), payload);
            }
        }
        for invalid in [vec![], vec![0x40], vec![37], vec![37, 0x80, 0], vec![38, 0], vec![37, 1]] {
            assert!(h3_datagram_payload(Bytes::from(invalid), &[37]).is_none());
        }
    }

    #[test]
    fn malformed_address_assignments_do_not_replace_existing_addresses() {
        let address: IpAddr = "10.0.0.9".parse().unwrap();
        for invalid in [
            vec![0x40],                  // Incomplete request ID.
            vec![0],                     // Missing IP version.
            vec![0, 7],                  // Unknown IP version.
            vec![0, 4, 10],              // Incomplete address.
            vec![0, 4, 10, 0, 0, 2, 33], // Invalid prefix length.
            vec![0, 4, 10, 0, 0, 2, 24], // Nonzero host bits.
            [vec![0, 6], vec![0; 16], vec![129]].concat(),
        ] {
            let value = [vec![0, 4, 10, 0, 0, 2, 32], invalid].concat();
            let capsule = [vec![1, value.len() as u8], value].concat();
            let addresses = Mutex::new(vec![address]);
            assert!(CapsuleDecoder::default().push(&capsule, &addresses, &mut |_| {}).is_err());
            assert_eq!(*addresses.lock().unwrap(), [address]);
        }
    }

    #[test]
    fn valid_address_prefixes_and_wide_request_ids_are_accepted() {
        let mut value = vec![0x40, 0, 4, 10, 0, 0, 0, 8];
        value.extend_from_slice(&[0, 6]);
        value.extend_from_slice(&"fd00::".parse::<Ipv6Addr>().unwrap().octets());
        value.push(8);
        assert_eq!(
            parse_addresses(&value).unwrap(),
            [("10.0.0.0".parse().unwrap(), 8), ("fd00::".parse().unwrap(), 8),]
        );
        assert!(parse_addresses(&[]).unwrap().is_empty());
    }

    #[test]
    fn oversized_known_capsules_fail_on_the_header() {
        for typ in 0..=3 {
            let mut bytes = vec![];
            varint::encode(&mut bytes, typ);
            varint::encode(&mut bytes, (1 << 62) - 1);
            let mut decoder = CapsuleDecoder::default();
            assert!(decoder.push(&bytes, &Mutex::new(vec![]), &mut |_| panic!("invalid frame")).is_err());
            assert!(decoder.buf.len() <= 16);
        }
    }
    #[test]
    fn huge_unknown_capsules_are_streamed_without_storage() {
        let mut header = vec![];
        varint::encode(&mut header, 99);
        varint::encode(&mut header, (1 << 62) - 1);
        let mut decoder = CapsuleDecoder::default();
        let addresses = Mutex::new(vec![]);
        decoder.push(&header, &addresses, &mut |_| panic!("unknown frame")).unwrap();
        for _ in 0..16 {
            decoder.push(&[0; 65_536], &addresses, &mut |_| panic!("unknown frame")).unwrap();
        }
        assert!(decoder.buf.is_empty());
        assert_eq!(decoder.skip, (1 << 62) - 1 - 16 * 65_536);
    }
    #[test]
    fn skipped_and_known_capsules_survive_every_fragment_size() {
        let mut bytes = vec![];
        varint::encode(&mut bytes, 99);
        bytes.extend_from_slice(&[4, 1, 2, 3, 4]);
        bytes.extend_from_slice(&datagram_capsule(&network_relay::proto::datagram::udp_payload(&[0x45, 1, 2, 3])));
        bytes.extend_from_slice(&[1, 7, 0, 4, 10, 0, 0, 2, 32]);
        for chunk in 1..=bytes.len() {
            let mut decoder = CapsuleDecoder::default();
            let addresses = Mutex::new(vec![]);
            let mut packets = vec![];
            for part in bytes.chunks(chunk) {
                decoder.push(part, &addresses, &mut |p| packets.push(p.to_vec())).unwrap();
            }
            assert_eq!(packets, [vec![0, 0x45, 1, 2, 3]]);
            assert_eq!(*addresses.lock().unwrap(), ["10.0.0.2".parse::<IpAddr>().unwrap()]);
            assert!(decoder.buf.is_empty());
            assert_eq!(decoder.skip, 0);
        }
    }
}

#[cfg(test)]
mod setup_tests {
    use super::*;

    #[tokio::test]
    async fn unsuccessful_setup_cancels_started_tasks() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        struct Completion(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for Completion {
            fn drop(&mut self) {
                let _ = self.0.take().unwrap().send(());
            }
        }
        let task = tokio::spawn(async move {
            let _completion = Completion(Some(dropped_tx));
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        let tasks = SetupTasks(vec![task]);
        started_rx.await.unwrap();
        drop(tasks);
        tokio::time::timeout(Duration::from_secs(1), dropped_rx).await.unwrap().unwrap();
    }
}

/// Against a server that behaves as Cloudflare's does as far as the client
/// can tell: it asks for a client certificate and accepts any, carries the
/// endpoint key in its own certificate, and takes the request forms of
/// Cloudflare (plain CONNECT and bare capsules over HTTP/2). What the
/// server sees is checked: the device key, the request headers, and the
/// framing of packets each way. (The local caddy-masque check uses HTTP
/// Basic and the standard forms instead.)
#[cfg(test)]
mod cloudflare_wire_tests {
    use super::*;
    use rcgen::PublicKeyData;
    use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
    use rustls::DistinguishedName;

    /// An IPv4 header, as far as the tunnel cares, each way.
    const PACKET: [u8; 20] = [0x45, 0, 0, 20, 0, 0, 0x40, 0, 64, 17, 0, 0, 10, 0, 0, 2, 1, 1, 1, 1];
    const REPLY: [u8; 20] = [0x45, 0, 0, 20, 0, 0, 0x40, 0, 60, 17, 0, 0, 1, 1, 1, 1, 10, 0, 0, 2];

    #[derive(Debug)]
    struct AnyClientCert(Arc<CryptoProvider>);

    impl ClientCertVerifier for AnyClientCert {
        fn root_hint_subjects(&self) -> &[DistinguishedName] {
            &[]
        }
        fn verify_client_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: UnixTime,
        ) -> Result<ClientCertVerified, rustls::Error> {
            Ok(ClientCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    struct Fixture {
        device_pkcs8: Vec<u8>,
        device_spki: Vec<u8>,
        server_spki: Vec<u8>,
        server_tls: rustls::ServerConfig,
    }

    fn fixture(alpn: &[u8]) -> Fixture {
        let device = crate::api::generate_keys().unwrap();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap().self_signed(&key).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(Arc::new(AnyClientCert(provider)))
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        server_tls.alpn_protocols = vec![alpn.to_vec()];
        Fixture {
            device_pkcs8: device.pkcs8_der,
            device_spki: device.spki_der,
            server_spki: key.subject_public_key_info(),
            server_tls,
        }
    }

    fn options(f: &Fixture, endpoint: SocketAddr, transport: Transport, protocol: &'static str) -> Options {
        Options {
            endpoint,
            sni: "localhost".into(),
            uri: DEFAULT_URI.into(),
            protocol,
            endpoint_spki: f.server_spki.clone(),
            device_pkcs8: f.device_pkcs8.clone(),
            fwmark: None,
            keepalive: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(30),
            transport,
        }
    }

    fn spki_of(cert: &CertificateDer<'_>) -> Vec<u8> {
        let (_, c) = x509_parser::parse_x509_certificate(cert.as_ref()).unwrap();
        c.tbs_certificate.subject_pki.raw.to_vec()
    }

    #[tokio::test]
    async fn http2_requests_and_capsules_are_cloudflares() {
        http2_exchange_with_cloudflare(fixture(b"h2")).await;
    }

    /// Cloudflare's HTTP/2 endpoint completes the TLS handshake without
    /// confirming an ALPN protocol and speaks HTTP/2 all the same (seen on
    /// the live service; mihomo speaks HTTP/2 whatever the server answers).
    #[tokio::test]
    async fn http2_goes_ahead_when_cloudflare_confirms_no_alpn() {
        let mut f = fixture(b"h2");
        f.server_tls.alpn_protocols.clear();
        http2_exchange_with_cloudflare(f).await;
    }

    async fn http2_exchange_with_cloudflare(f: Fixture) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(f.server_tls.clone()));
        let device_spki = f.device_spki.clone();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            let certs = tls.get_ref().1.peer_certificates().unwrap().to_vec();
            assert_eq!(spki_of(&certs[0]), device_spki, "the device key");
            let mut conn = h2::server::handshake(tls).await.unwrap();
            let (req, mut respond) = conn.accept().await.unwrap().unwrap();
            let driver = tokio::spawn(async move { while conn.accept().await.is_some() {} });
            assert_eq!(req.method(), Method::CONNECT);
            assert_eq!(req.uri().authority().map(|a| a.as_str()), Some("cloudflareaccess.com:443"));
            assert!(req.extensions().get::<h2::ext::Protocol>().is_none());
            let h = req.headers();
            assert_eq!(h["cf-connect-proto"], "cf-connect-ip");
            assert_eq!(h["pq-enabled"], "false");
            assert!(!h.contains_key("user-agent"));
            assert!(!h.contains_key("capsule-protocol"));
            let mut body = req.into_body();
            let mut send = respond.send_response(http::Response::new(()), false).unwrap();
            // Nothing but the packet, in a DATAGRAM capsule without a
            // Context ID: no ROUTE_ADVERTISEMENT before it.
            let want = datagram_capsule(&PACKET);
            let mut got = Vec::new();
            while got.len() < want.len() {
                let chunk = body.data().await.unwrap().unwrap();
                let _ = body.flow_control().release_capacity(chunk.len());
                got.extend_from_slice(&chunk);
            }
            assert_eq!(got, want);
            send.send_data(datagram_capsule(&REPLY), false).unwrap();
            while let Some(Ok(_)) = body.data().await {}
            driver.abort();
        });
        let t = Tunnel::connect(&options(&f, addr, Transport::H2, DEFAULT_PROTOCOL)).await.unwrap();
        assert_eq!(t.send_packet(&PACKET).unwrap(), Sent::Yes);
        let back = tokio::time::timeout(Duration::from_secs(5), t.recv_packet()).await.unwrap().unwrap();
        assert_eq!(&back[..], &REPLY);
        t.shutdown().await;
        server.await.unwrap();
    }

    /// The vendored h3 server parses only registered :protocol values, so
    /// this one asks for "connect-ip"; the rest is as for Cloudflare.
    #[tokio::test]
    async fn http3_requests_and_datagrams_are_cloudflares() {
        let f = fixture(b"h3");
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(f.server_tls.clone()).unwrap();
        let config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let device_spki = f.device_spki.clone();
        let server = tokio::spawn(async move {
            let conn = endpoint.accept().await.unwrap().await.unwrap();
            let certs = conn.peer_identity().unwrap().downcast::<Vec<CertificateDer<'static>>>().unwrap();
            assert_eq!(spki_of(&certs[0]), device_spki, "the device key");
            let mut h3 = h3::server::builder()
                .enable_extended_connect(true)
                .enable_datagram(true)
                .build::<_, Bytes>(h3_quinn::Connection::new(conn.clone()))
                .await
                .unwrap();
            let (req, mut stream) = h3.accept().await.unwrap().unwrap().resolve_request().await.unwrap();
            assert_eq!(req.method(), Method::CONNECT);
            assert_eq!(req.uri(), DEFAULT_URI);
            assert_eq!(req.extensions().get::<h3::ext::Protocol>().map(|p| p.as_str()), Some("connect-ip"));
            assert_eq!(req.headers()["capsule-protocol"], "?1");
            assert!(!req.headers().contains_key("user-agent"));
            stream.send_response(http::Response::new(())).await.unwrap();
            // The routes the client takes, first on the stream.
            let mut first = Vec::new();
            while first.len() < route_advertisement().len() {
                let mut data = stream.recv_data().await.unwrap().unwrap();
                while data.has_remaining() {
                    let n = data.chunk().len();
                    first.extend_from_slice(data.chunk());
                    data.advance(n);
                }
            }
            assert_eq!(first, route_advertisement());
            // Quarter Stream ID 0, Context ID 0, the packet.
            let d = conn.read_datagram().await.unwrap();
            assert_eq!(d[..2], [0, 0]);
            assert_eq!(d[2..], PACKET);
            let mut reply = vec![0, 0];
            reply.extend_from_slice(&REPLY);
            conn.send_datagram(Bytes::from(reply)).unwrap();
            conn.closed().await;
            drop(h3);
        });
        let t = Tunnel::connect(&options(&f, addr, Transport::H3, "connect-ip")).await.unwrap();
        assert_eq!(t.send_packet(&PACKET).unwrap(), Sent::Yes);
        let back = tokio::time::timeout(Duration::from_secs(5), t.recv_packet()).await.unwrap().unwrap();
        assert_eq!(&back[..], &REPLY);
        t.shutdown().await;
        server.await.unwrap();
    }

    /// A server whose key is not the registered endpoint key is refused.
    #[tokio::test]
    async fn another_server_key_is_refused() {
        let f = fixture(b"h2");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(f.server_tls.clone()));
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(tcp).await;
        });
        let mut o = options(&f, addr, Transport::H2, DEFAULT_PROTOCOL);
        o.endpoint_spki = crate::api::generate_keys().unwrap().spki_der;
        let e = Tunnel::connect(&o).await.err().expect("refused");
        assert!(format!("{e:#}").contains("not the endpoint key"), "{e:#}");
    }
}

#[cfg(test)]
mod h2_flow_tests {
    use super::*;

    #[tokio::test]
    async fn health_failure_is_published_before_connection_cleanup_and_is_not_overwritten() {
        struct Connection(watch::Sender<Option<String>>);
        impl std::future::Future for Connection {
            type Output = std::result::Result<(), h2::Error>;
            fn poll(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
                std::task::Poll::Pending
            }
        }
        impl Drop for Connection {
            fn drop(&mut self) {
                record_h2_failure(&self.0, "HTTP/2 stream: broken pipe".into());
            }
        }
        let (ended, reason) = watch::channel(None);
        let timeout = "HTTP/2 keepalive acknowledgement timed out";
        drive_h2_connection(Connection(ended.clone()), std::future::ready(timeout.to_string()), ended.clone()).await;
        record_h2_failure(&ended, "the server ended the stream".into());
        assert_eq!(reason.borrow().as_deref(), Some(timeout));
    }

    #[tokio::test]
    async fn capsules_larger_than_stream_and_connection_windows_are_sent_in_order() {
        for window in [16, 1024] {
            tokio::time::timeout(Duration::from_secs(5), async {
                let (client_io, server_io) = tokio::io::duplex(65536);
                let (received_tx, received_rx) = tokio::sync::oneshot::channel();
                let server = tokio::spawn(async move {
                    let mut connection = h2::server::Builder::new()
                        .initial_window_size(window)
                        .handshake::<_, Bytes>(server_io)
                        .await
                        .unwrap();
                    let (request, mut response) = connection.accept().await.unwrap().unwrap();
                    let _send = response.send_response(http::Response::new(()), false).unwrap();
                    let mut body = request.into_body();
                    tokio::spawn(async move {
                        let mut received = Vec::new();
                        while let Some(chunk) = body.data().await {
                            let chunk = chunk.unwrap();
                            received.extend_from_slice(&chunk);
                            body.flow_control().release_capacity(chunk.len()).unwrap();
                        }
                        received_tx.send(received).unwrap();
                    });
                    while connection.accept().await.is_some() {}
                });
                let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
                let connection = tokio::spawn(connection);
                let (response, mut stream) = client.send_request(http::Request::new(()), false).unwrap();
                response.await.unwrap();
                let advertisement = route_advertisement();
                let packet = datagram_capsule(&network_relay::proto::datagram::udp_payload(&vec![
                    0x5a;
                    (window as usize
                        * 128)
                        .min(65535)
                ]));
                send_h2_capsule(&mut stream, advertisement.clone()).await.unwrap();
                send_h2_capsule(&mut stream, packet.clone()).await.unwrap();
                stream.send_data(Bytes::new(), true).unwrap();
                let expected = [advertisement.as_ref(), packet.as_ref()].concat();
                assert_eq!(received_rx.await.unwrap(), expected);
                connection.abort();
                server.abort();
            })
            .await
            .expect("capsule transmission stalled under flow control");
        }
    }
}
