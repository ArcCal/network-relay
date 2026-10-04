//! `network-relay check`: tests a relay the way a device uses it, over every
//! HTTP version: TCP through CONNECT (an HTTP request to a web server) and
//! UDP through CONNECT-UDP (a DNS query). It also checks that the relay
//! stays hidden from requests without credentials.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, ensure, Context, Result};
use bytes::Bytes;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use http::header::{AUTHORIZATION, CONNECTION, HOST, PROXY_AUTHORIZATION, UPGRADE};
use http::{Method, Request, StatusCode};
use http_body_util::Empty;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::auth::basic_authorization;
use crate::proto::datagram::{self, CONTEXT_ID_UDP_PAYLOAD};
use crate::proto::{UriTemplate, CAPSULE_PROTOCOL_HEADER, CONNECT_UDP_PROTOCOL};
use crate::tls;
use crate::tunnel::{Datagrams, Event, QuicDatagrams, Tunnel};

/// What to check and how to reach the relay.
#[derive(Debug, Clone)]
pub struct Options {
    /// The relay's host name: TLS server name and request authority.
    pub host: String,
    pub port: u16,
    /// Where to connect; resolved from `host` when empty.
    pub addresses: Vec<SocketAddr>,
    pub user: String,
    pub password: String,
    /// Path and query of the CONNECT-UDP template.
    pub udp_template: String,
    /// `host:port` of a web server to fetch through the TCP tunnel.
    pub tcp_target: String,
    /// A DNS server to query through the UDP tunnel.
    pub udp_target: (String, u16),
    /// Name to look up in the DNS query.
    pub dns_name: String,
    /// Trust only this CA instead of the system's (for tests).
    pub ca: Option<PathBuf>,
    /// Present this client certificate and key (PEM files) to the relay.
    pub client_cert: Option<(PathBuf, PathBuf)>,
    pub timeout: Duration,
}

/// The result of one check.
#[derive(Debug)]
pub struct Outcome {
    pub name: &'static str,
    pub result: Result<String>,
    pub elapsed: Duration,
}

impl Options {
    fn authority(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    fn udp_path(&self) -> Result<String> {
        let t = UriTemplate::parse_path(&self.udp_template)?;
        Ok(t.expand(&[("target_host", &self.udp_target.0), ("target_port", &self.udp_target.1.to_string())]))
    }

    /// The Basic credentials, unless the check authenticates with a client
    /// certificate only (no password).
    fn basic(&self) -> Option<String> {
        (!self.password.is_empty()).then(|| basic_authorization(&self.user, &self.password))
    }

    fn tls(&self, alpn: &[&[u8]]) -> Result<rustls::ClientConfig> {
        let identity = match &self.client_cert {
            None => None,
            Some((cert, key)) => Some((tls::load_certs(cert)?, tls::load_key(key)?)),
        };
        tls::client_config_with_identity(self.ca.as_deref(), alpn, identity)
    }

    async fn addresses(&self) -> Result<Vec<SocketAddr>> {
        if !self.addresses.is_empty() {
            return Ok(self.addresses.clone());
        }
        let found: Vec<SocketAddr> = within(self, "resolving the relay", async {
            Ok(tokio::net::lookup_host((self.host.as_str(), self.port)).await?.collect())
        })
        .await
        .with_context(|| format!("resolving {}", self.host))?;
        ensure!(!found.is_empty(), "{} has no addresses", self.host);
        Ok(found)
    }
}

/// Runs every check and returns their outcomes in order.
pub async fn run(opts: &Options) -> Vec<Outcome> {
    let mut out = Vec::new();
    let addrs = match opts.addresses().await {
        Ok(a) => a,
        Err(e) => {
            out.push(Outcome { name: "resolve the relay", result: Err(e), elapsed: Duration::ZERO });
            return out;
        }
    };

    // HTTP/3: one QUIC connection for both checks, as a device would.
    let started = Instant::now();
    match H3::connect(opts, &addrs).await {
        Ok(mut h3) => {
            out.push(timed("HTTP/3 TCP (CONNECT)", h3.tcp(opts)).await);
            out.push(timed("HTTP/3 UDP (CONNECT-UDP)", h3.udp(opts)).await);
        }
        Err(e) => {
            let e = e.context("QUIC on UDP port blocked, or the relay is not running?");
            out.push(Outcome { name: "HTTP/3 connection", result: Err(e), elapsed: started.elapsed() });
        }
    }
    out.push(timed("HTTP/2 TCP (CONNECT)", h2_tcp(opts, &addrs)).await);
    out.push(timed("HTTP/2 UDP (CONNECT-UDP)", h2_udp(opts, &addrs)).await);
    out.push(timed("HTTP/1.1 TCP (CONNECT)", h1_tcp(opts, &addrs)).await);
    out.push(timed("HTTP/1.1 UDP (Upgrade: connect-udp)", h1_udp(opts, &addrs)).await);
    out.push(timed("hidden without password", hidden(opts, &addrs)).await);
    out
}

async fn timed(name: &'static str, f: impl std::future::Future<Output = Result<String>>) -> Outcome {
    let started = Instant::now();
    Outcome { name, result: f.await, elapsed: started.elapsed() }
}

async fn within<T>(opts: &Options, what: &str, f: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(opts.timeout, f).await.map_err(|_| anyhow!("{what} timed out"))?
}

/// Adds the Basic credentials, when the check uses a password.
trait Credentials {
    fn credentials(self, header: http::header::HeaderName, opts: &Options) -> Self;
}

impl Credentials for http::request::Builder {
    fn credentials(self, header: http::header::HeaderName, opts: &Options) -> Self {
        match opts.basic() {
            Some(value) => self.header(header, value),
            None => self,
        }
    }
}

/// Explains a status the relay answered a proxy request with.
fn check_status(status: StatusCode, expected: StatusCode, proxy_status: Option<&str>) -> Result<()> {
    if status == expected {
        return Ok(());
    }
    let detail = proxy_status.map(|p| format!(" [{p}]")).unwrap_or_default();
    match status {
        StatusCode::NOT_FOUND | StatusCode::OK => bail!(
            "the relay answered like a plain website ({status}): wrong user name or password, the user is not in \
             the server's configuration, or the UDP path differs from relay.udp_template"
        ),
        _ if status == StatusCode::FORBIDDEN
            || proxy_status.is_some_and(|p| p.contains("destination_ip_prohibited")) =>
        {
            bail!("the relay does not allow this destination ({status}){detail}")
        }
        s => bail!("the relay refused ({s}){detail}"),
    }
}

// ---------------------------------------------------------------- probes

fn http_get(target: &str) -> String {
    let host = target.rsplit_once(':').map_or(target, |(h, _)| h);
    format!("GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: network-relay-check\r\nConnection: close\r\n\r\n")
}

/// Sends an HTTP request through a TCP tunnel and returns the status line.
async fn fetch_status_line<S: AsyncRead + AsyncWrite + Unpin>(io: &mut S, target: &str) -> Result<String> {
    io.write_all(http_get(target).as_bytes()).await?;
    io.flush().await?;
    let mut got = Vec::new();
    let mut buf = [0u8; 1024];
    while !got.contains(&b'\n') && got.len() < 1024 {
        let n = io.read(&mut buf).await?;
        ensure!(n > 0, "the destination closed the connection without answering");
        got.extend_from_slice(&buf[..n]);
    }
    let line = got.split(|b| *b == b'\n').next().unwrap_or_default();
    Ok(format!("{target} answered {:?}", String::from_utf8_lossy(line).trim()))
}

/// A DNS query for an A record, with a random ID.
fn dns_query(name: &str) -> Result<(u16, Vec<u8>)> {
    ensure!(!name.is_empty() && name.is_ascii(), "DNS name must be nonempty ASCII (use IDNA for international names)");
    let name = name.strip_suffix('.').unwrap_or(name);
    ensure!(name.len() <= 253, "DNS name exceeds 255 wire bytes");
    let mut id = [0u8; 2];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut id).expect("system RNG");
    let id = u16::from_be_bytes(id);
    let mut q = Vec::with_capacity(32 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD; one question
    if !name.is_empty() {
        for label in name.split('.') {
            ensure!(!label.is_empty() && label.len() <= 63, "DNS labels must contain 1-63 bytes");
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]); // root; type A; class IN
    Ok((id, q))
}

/// Describes a reply to [`dns_query`]; any datagram that echoes the ID counts.
fn describe_dns_reply(id: u16, reply: &[u8], from: &(String, u16)) -> Result<String> {
    ensure!(reply.len() >= 12 && u16::from_be_bytes([reply[0], reply[1]]) == id, "unexpected datagram");
    let target = format!("{}:{}", from.0, from.1);
    if reply[2] & 0x80 == 0 {
        return Ok(format!("{target} echoed the datagram"));
    }
    let rcode = reply[3] & 0x0f;
    let answers = u16::from_be_bytes([reply[6], reply[7]]);
    Ok(format!("DNS server {target} answered (rcode {rcode}, {answers} records)"))
}

/// Sends a DNS query through a CONNECT-UDP tunnel and waits for the reply.
async fn dns_over(tunnel: &mut Tunnel, opts: &Options) -> Result<String> {
    let (id, query) = dns_query(&opts.dns_name)?;
    let deadline = tokio::time::Instant::now() + opts.timeout;
    let mut tries = 0;
    loop {
        // UDP may lose the datagram; resend a few times.
        if tries < 3 {
            tunnel.send_datagram(datagram::udp_payload(&query)).map_err(|e| anyhow!("{e}"))?;
            tries += 1;
        }
        let wait = tokio::time::sleep(Duration::from_secs(1));
        tokio::select! {
            ev = tunnel.next_event() => match ev.map_err(|e| anyhow!("{e}"))? {
                Event::Datagram(p) => {
                    if let Ok((CONTEXT_ID_UDP_PAYLOAD, reply)) = datagram::split_context_id(&p) {
                        if let Ok(desc) = describe_dns_reply(id, reply, &opts.udp_target) {
                            return Ok(desc);
                        }
                    }
                }
                Event::Closed => bail!("the relay closed the tunnel"),
            },
            _ = wait => {}
        }
        ensure!(tokio::time::Instant::now() < deadline, "no reply from {}:{}", opts.udp_target.0, opts.udp_target.1);
    }
}

// ---------------------------------------------------------------- HTTP/3

type H3Send = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type H3Driver = h3::client::Connection<h3_quinn::Connection, Bytes>;
/// A client request stream on an HTTP/3 connection.
pub type H3ClientStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// An HTTP/3 client connection with extended CONNECT and datagrams.
pub struct H3 {
    conn: quinn::Connection,
    send: H3Send,
    driver: Arc<std::sync::Mutex<H3Driver>>,
    _drive: AbortOnDrop,
}

/// Aborts a background task when dropped.
pub struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl H3 {
    /// Opens a QUIC connection to the first address that answers.
    pub async fn connect(opts: &Options, addrs: &[SocketAddr]) -> Result<Self> {
        let crypto = opts.tls(&[tls::ALPN_H3])?;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?;
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        // As a device would: QUIC's guaranteed 1200 bytes first, then path
        // MTU discovery (on by default) finds the real size.
        transport.initial_mtu(1200);
        config.transport_config(Arc::new(transport));
        let mut last = anyhow!("no address");
        for addr in addrs {
            let bind: SocketAddr = if addr.is_ipv6() { "[::]:0".parse()? } else { "0.0.0.0:0".parse()? };
            let endpoint = quinn::Endpoint::client(bind)?;
            let connecting = match endpoint.connect_with(config.clone(), *addr, &opts.host) {
                Ok(c) => c,
                Err(e) => {
                    last = anyhow!("{addr}: {e}");
                    continue;
                }
            };
            let conn = match within(opts, "QUIC handshake", async { Ok(connecting.await?) }).await {
                Ok(c) => c,
                Err(e) => {
                    last = e.context(format!("{addr}"));
                    continue;
                }
            };
            let (driver, send) = within(opts, "HTTP/3 setup", async {
                h3::client::builder()
                    .enable_extended_connect(true)
                    .enable_datagram(true)
                    .build::<_, _, Bytes>(h3_quinn::Connection::new(conn.clone()))
                    .await
                    .context("HTTP/3 setup")
            })
            .await?;
            let driver = Arc::new(std::sync::Mutex::new(driver));
            let drive = {
                let driver = driver.clone();
                AbortOnDrop(tokio::spawn(async move {
                    std::future::poll_fn(|cx| driver.lock().unwrap().poll_close(cx)).await;
                }))
            };
            return Ok(Self { conn, send, driver, _drive: drive });
        }
        Err(last)
    }

    /// The QUIC connection, for its path properties.
    pub fn connection(&self) -> &quinn::Connection {
        &self.conn
    }

    /// Sends a request; the response is read from the returned stream.
    pub async fn request(&mut self, req: Request<()>) -> Result<H3ClientStream> {
        Ok(self.send.send_request(req).await?)
    }

    /// Sends an HTTP Datagram on the stream `stream_id`.
    pub fn send_datagram(&self, stream_id: h3::quic::StreamId, payload: Bytes) -> Result<()> {
        self.driver.lock().unwrap().get_datagram_sender(stream_id).send_datagram(payload)?;
        Ok(())
    }

    /// Wraps an accepted CONNECT-UDP stream, with this connection's
    /// datagrams for it.
    pub fn udp_tunnel(&self, stream: H3ClientStream) -> (Tunnel, AbortOnDrop) {
        let stream_id = stream.id();
        let sender = self.driver.lock().unwrap().get_datagram_sender(stream_id);
        let mut reader = self.driver.lock().unwrap().get_datagram_reader();
        let (tx, rx) = mpsc::channel(1024);
        let filter = AbortOnDrop(tokio::spawn(async move {
            while let Ok(d) = reader.read_datagram().await {
                if d.stream_id() == stream_id {
                    let _ = tx.try_send(d.into_payload());
                }
            }
        }));
        let datagrams = Datagrams::Quic(QuicDatagrams::new(sender, self.conn.clone(), stream_id, rx));
        (Tunnel::h3_client(stream, datagrams), filter)
    }

    async fn tcp(&mut self, opts: &Options) -> Result<String> {
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri(opts.tcp_target.as_str())
            .credentials(AUTHORIZATION, opts)
            .body(())?;
        let mut stream = within(opts, "CONNECT", async { Ok(self.send.send_request(req).await?) }).await?;
        let resp = within(opts, "CONNECT response", async { Ok(stream.recv_response().await?) }).await?;
        let proxy_status = resp.headers().get("proxy-status").and_then(|v| v.to_str().ok());
        check_status(resp.status(), StatusCode::OK, proxy_status)?;
        stream.forbid_trailers();
        let (mut send, mut recv) = stream.split();
        within(opts, "sending the request", async {
            Ok(send.send_data(Bytes::from(http_get(&opts.tcp_target))).await?)
        })
        .await?;
        let mut got = Vec::new();
        within(opts, "reading the answer", async {
            while !got.contains(&b'\n') && got.len() < 1024 {
                match recv.recv_data().await? {
                    Some(mut buf) => {
                        use bytes::Buf;
                        got.extend_from_slice(&buf.copy_to_bytes(buf.remaining()));
                    }
                    None => bail!("the destination closed the connection without answering"),
                }
            }
            Ok(())
        })
        .await?;
        within(opts, "finishing the request", async { Ok(send.finish().await?) }).await?;
        let line = got.split(|b| *b == b'\n').next().unwrap_or_default();
        Ok(format!("{} answered {:?}", opts.tcp_target, String::from_utf8_lossy(line).trim()))
    }

    async fn udp(&mut self, opts: &Options) -> Result<String> {
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://{}{}", opts.authority(), opts.udp_path()?))
            .header(CAPSULE_PROTOCOL_HEADER, "?1")
            .credentials(AUTHORIZATION, opts)
            .extension(h3::ext::Protocol::CONNECT_UDP)
            .body(())?;
        let mut stream = within(opts, "CONNECT-UDP", async { Ok(self.send.send_request(req).await?) }).await?;
        let resp = within(opts, "CONNECT-UDP response", async { Ok(stream.recv_response().await?) }).await?;
        let proxy_status = resp.headers().get("proxy-status").and_then(|v| v.to_str().ok());
        check_status(resp.status(), StatusCode::OK, proxy_status)?;
        let (mut tunnel, _filter) = self.udp_tunnel(stream);
        dns_over(&mut tunnel, opts).await
    }
}

// ---------------------------------------------------------------- TCP

type Tls = tokio_rustls::client::TlsStream<TcpStream>;

async fn tls_connect(opts: &Options, addrs: &[SocketAddr], alpn: &[&[u8]]) -> Result<Tls> {
    let config = Arc::new(opts.tls(alpn)?);
    let mut last = anyhow!("no address");
    for addr in addrs {
        let tcp = match within(opts, "TCP connect", async { Ok(TcpStream::connect(addr).await?) }).await {
            Ok(t) => t,
            Err(e) => {
                last = e.context(format!("{addr}"));
                continue;
            }
        };
        let name = rustls::pki_types::ServerName::try_from(opts.host.clone())?;
        let connector = tokio_rustls::TlsConnector::from(config.clone());
        match within(opts, "TLS handshake", async { Ok(connector.connect(name, tcp).await?) }).await {
            Ok(tls) => return Ok(tls),
            Err(error) => last = error.context(format!("{addr}")),
        }
    }
    Err(last)
}

/// An HTTP/2 connection that has extended CONNECT enabled.
pub async fn h2_sender(
    opts: &Options,
    addrs: &[SocketAddr],
) -> Result<(hyper::client::conn::http2::SendRequest<Empty<Bytes>>, AbortOnDrop)> {
    let tls = tls_connect(opts, addrs, &[tls::ALPN_H2]).await?;
    ensure!(tls.get_ref().1.alpn_protocol() == Some(tls::ALPN_H2), "the server did not agree to HTTP/2");
    let (sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake::<_, Empty<Bytes>>(TokioIo::new(tls))
        .await?;
    let mut conn = Box::pin(conn);
    // RFC 8441 §3: extended CONNECT is allowed once the server's SETTINGS
    // enable it; let them arrive.
    let deadline = tokio::time::Instant::now() + opts.timeout;
    while !conn.is_extended_connect_protocol_enabled() && tokio::time::Instant::now() < deadline {
        tokio::select! {
            r = &mut conn => bail!("HTTP/2 connection closed: {r:?}"),
            _ = tokio::time::sleep(Duration::from_millis(5)) => {}
        }
    }
    let task = AbortOnDrop(tokio::spawn(async move {
        let _ = conn.await;
    }));
    Ok((sender, task))
}

async fn h2_tcp(opts: &Options, addrs: &[SocketAddr]) -> Result<String> {
    let (mut sender, _conn) = h2_sender(opts, addrs).await?;
    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(opts.tcp_target.as_str())
        .credentials(AUTHORIZATION, opts)
        .body(Empty::new())?;
    let mut resp = within(opts, "CONNECT", async { Ok(sender.send_request(req).await?) }).await?;
    let proxy_status = resp.headers().get("proxy-status").and_then(|v| v.to_str().ok()).map(str::to_string);
    check_status(resp.status(), StatusCode::OK, proxy_status.as_deref())?;
    let mut io = TokioIo::new(hyper::upgrade::on(&mut resp).await?);
    within(opts, "reading the answer", fetch_status_line(&mut io, &opts.tcp_target)).await
}

async fn h2_udp(opts: &Options, addrs: &[SocketAddr]) -> Result<String> {
    let (mut sender, _conn) = h2_sender(opts, addrs).await?;
    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://{}{}", opts.authority(), opts.udp_path()?))
        .header(CAPSULE_PROTOCOL_HEADER, "?1")
        .credentials(AUTHORIZATION, opts)
        .extension(hyper::ext::Protocol::from_static(CONNECT_UDP_PROTOCOL))
        .body(Empty::new())?;
    let mut resp = within(opts, "CONNECT-UDP", async { Ok(sender.send_request(req).await?) }).await?;
    let proxy_status = resp.headers().get("proxy-status").and_then(|v| v.to_str().ok()).map(str::to_string);
    check_status(resp.status(), StatusCode::OK, proxy_status.as_deref())?;
    let mut tunnel = Tunnel::upgraded(hyper::upgrade::on(&mut resp).await?);
    dns_over(&mut tunnel, opts).await
}

/// An HTTP/1.1 connection.
pub async fn h1_sender(
    opts: &Options,
    addrs: &[SocketAddr],
) -> Result<(hyper::client::conn::http1::SendRequest<Empty<Bytes>>, AbortOnDrop)> {
    let tls = tls_connect(opts, addrs, &[tls::ALPN_HTTP11]).await?;
    let (sender, conn) = hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(TokioIo::new(tls)).await?;
    let task = AbortOnDrop(tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    }));
    Ok((sender, task))
}

async fn h1_tcp(opts: &Options, addrs: &[SocketAddr]) -> Result<String> {
    let (mut sender, _conn) = h1_sender(opts, addrs).await?;
    // Classic proxy clients such as curl send Proxy-Authorization.
    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(opts.tcp_target.as_str())
        .header(HOST, opts.tcp_target.as_str())
        .credentials(PROXY_AUTHORIZATION, opts)
        .body(Empty::new())?;
    let mut resp = within(opts, "CONNECT", async { Ok(sender.send_request(req).await?) }).await?;
    let proxy_status = resp.headers().get("proxy-status").and_then(|v| v.to_str().ok()).map(str::to_string);
    check_status(resp.status(), StatusCode::OK, proxy_status.as_deref())?;
    let mut io = TokioIo::new(hyper::upgrade::on(&mut resp).await?);
    within(opts, "reading the answer", fetch_status_line(&mut io, &opts.tcp_target)).await
}

async fn h1_udp(opts: &Options, addrs: &[SocketAddr]) -> Result<String> {
    let (mut sender, _conn) = h1_sender(opts, addrs).await?;
    let req = Request::builder()
        .method(Method::GET)
        .uri(opts.udp_path()?)
        .header(HOST, opts.authority())
        .header(CONNECTION, "Upgrade")
        .header(UPGRADE, CONNECT_UDP_PROTOCOL)
        .header(CAPSULE_PROTOCOL_HEADER, "?1")
        .credentials(AUTHORIZATION, opts)
        .body(Empty::new())?;
    let mut resp = within(opts, "Upgrade request", async { Ok(sender.send_request(req).await?) }).await?;
    let proxy_status = resp.headers().get("proxy-status").and_then(|v| v.to_str().ok()).map(str::to_string);
    check_status(resp.status(), StatusCode::SWITCHING_PROTOCOLS, proxy_status.as_deref())?;
    let mut tunnel = Tunnel::upgraded(hyper::upgrade::on(&mut resp).await?);
    dns_over(&mut tunnel, opts).await
}

/// Without credentials, a CONNECT must get the website's 404, not a proxy
/// answer such as 407 or 200.
async fn hidden(opts: &Options, addrs: &[SocketAddr]) -> Result<String> {
    let (mut sender, _conn) = h2_sender(opts, addrs).await?;
    let req = Request::builder().method(Method::CONNECT).uri(opts.tcp_target.as_str()).body(Empty::new())?;
    let resp = within(opts, "CONNECT", async { Ok(sender.send_request(req).await?) }).await?;
    ensure!(
        resp.status() == StatusCode::NOT_FOUND,
        "a CONNECT without credentials got {}, which gives the relay away",
        resp.status()
    );
    Ok("a CONNECT without credentials gets 404 like any missing page".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_queries_are_well_formed() {
        let (id, q) = dns_query("example.com").unwrap();
        assert_eq!(u16::from_be_bytes([q[0], q[1]]), id);
        assert_eq!(&q[12..], b"\x07example\x03com\x00\x00\x01\x00\x01");
        let mut reply = q.clone();
        reply[2] |= 0x80;
        reply[7] = 2;
        let target = ("1.1.1.1".to_string(), 53);
        assert_eq!(
            describe_dns_reply(id, &reply, &target).unwrap(),
            "DNS server 1.1.1.1:53 answered (rcode 0, 2 records)"
        );
        assert!(describe_dns_reply(id, &q, &target).unwrap().contains("echoed"));
        assert!(describe_dns_reply(id.wrapping_add(1), &reply, &target).is_err());
    }

    #[test]
    fn dns_queries_validate_wire_lengths() {
        for name in [
            String::new(),
            "a..b".into(),
            "example.com..".into(),
            "x".repeat(64),
            "é.com".into(),
            format!("{}.{}.{}.{}", "x".repeat(63), "x".repeat(63), "x".repeat(63), "x".repeat(62)),
        ] {
            assert!(dns_query(&name).is_err(), "{name}");
        }
        assert_eq!(&dns_query(".").unwrap().1[12..], b"\0\0\x01\0\x01");
        assert_eq!(&dns_query("example.com.").unwrap().1[12..], &dns_query("example.com").unwrap().1[12..]);
    }

    #[test]
    fn statuses_are_explained() {
        assert!(check_status(StatusCode::OK, StatusCode::OK, None).is_ok());
        let e = check_status(StatusCode::NOT_FOUND, StatusCode::OK, None).unwrap_err().to_string();
        assert!(e.contains("password"), "{e}");
        let e = check_status(
            StatusCode::BAD_GATEWAY,
            StatusCode::OK,
            Some("network-relay; error=destination_ip_prohibited"),
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("does not allow") && e.contains("destination_ip_prohibited"), "{e}");
    }
}
