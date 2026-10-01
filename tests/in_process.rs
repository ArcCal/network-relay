//! The relay and clients in one process, over loopback with real TLS, QUIC
//! and TCP, relaying to local TCP and UDP servers.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use bytes::{Buf, Bytes};
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use network_relay::auth;
use network_relay::certs::CertStore;
use network_relay::check::{self, Options, H3};
use network_relay::config::{Config, UserEntry};
use network_relay::proto::datagram;
use network_relay::proto::{capsule, CapsuleDecoder};
use network_relay::server::{self, Relay};
use network_relay::tunnel::Event;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

const WAIT: Duration = Duration::from_secs(20);
const INDEX: &[u8] = b"<!doctype html><title>Cover page</title><h1>cover</h1>";
const ALICE: (&str, &str) = ("alice", "alice-password-123");

async fn within<T>(what: &str, fut: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, fut).await.unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).with_test_writer().try_init();
}

// ---------------------------------------------------------------- fixtures

/// A private CA standing in for a public one, and a certificate for
/// `relay.test`.
fn write_certificates(dir: &std::path::Path) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(rcgen::DnType::CommonName, "Test CA");
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["relay.test".into()]).unwrap().signed_by(&key, &issuer).unwrap();
    std::fs::write(dir.join("ca.pem"), ca_cert.pem()).unwrap();
    std::fs::write(dir.join("fullchain.pem"), cert.pem() + &ca_cert.pem()).unwrap();
    std::fs::write(dir.join("privkey.pem"), key.serialize_pem()).unwrap();
}

struct Env {
    dir: PathBuf,
}

impl Env {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "network-relay-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("site")).unwrap();
        std::fs::write(dir.join("site/index.html"), INDEX).unwrap();
        write_certificates(&dir);
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn user(name: &str, password: &str) -> UserEntry {
    UserEntry { name: name.into(), password_hash: auth::hash_password(password).unwrap() }
}

/// UDP and TCP sockets on the same loopback port.
async fn bind_pair() -> (std::net::UdpSocket, TcpListener) {
    for _ in 0..20 {
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        if let Ok(tcp) = TcpListener::bind(udp.local_addr().unwrap()).await {
            return (udp, tcp);
        }
    }
    panic!("no free port pair");
}

struct TestRelay {
    env: Env,
    relay: Relay,
    addr: SocketAddr,
    users: Vec<UserEntry>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl TestRelay {
    /// A relay for user alice. `relay_toml` goes into the `[relay]` section;
    /// by default only 10.0.0.0/8 and port 25 are blocked, so the local test
    /// servers on 127.0.0.1 are reachable.
    async fn start(relay_toml: &str) -> Self {
        init_logging();
        let env = Env::new();
        let users = vec![user(ALICE.0, ALICE.1)];
        let (udp, tcp) = bind_pair().await;
        let addr = udp.local_addr().unwrap();
        let config = config(&env, addr, relay_toml, &users);
        let certs = CertStore::open(&config.tls.cert, &config.tls.key).unwrap();
        let relay = Relay::new(&config).unwrap();
        let endpoint = server::quic_endpoint(certs.clone(), udp).unwrap();
        let tasks = vec![
            tokio::spawn(relay.clone().serve_quic(endpoint)),
            tokio::spawn(relay.clone().serve_tcp(tcp, server::tcp_tls_config(certs).unwrap())),
        ];
        Self { env, relay, addr, users, tasks }
    }

    fn options(&self, (user, password): (&str, &str), tcp_target: SocketAddr, udp_target: SocketAddr) -> Options {
        Options {
            host: "relay.test".into(),
            port: self.addr.port(),
            addresses: vec![self.addr],
            user: user.into(),
            password: password.into(),
            udp_template: network_relay::proto::DEFAULT_UDP_PATH_TEMPLATE.into(),
            tcp_target: tcp_target.to_string(),
            udp_target: (udp_target.ip().to_string(), udp_target.port()),
            dns_name: "example.com".into(),
            ca: Some(self.env.path("ca.pem")),
            timeout: Duration::from_secs(5),
        }
    }

    fn reload(&self, relay_toml: &str, users: &[UserEntry]) {
        self.relay.reload(&config(&self.env, self.addr, relay_toml, users)).unwrap();
    }
}

fn config(env: &Env, addr: SocketAddr, relay_toml: &str, users: &[UserEntry]) -> Config {
    let relay_toml = if relay_toml.is_empty() {
        "blocked_destinations = [\"10.0.0.0/8\"]\nblocked_ports = [25]"
    } else {
        relay_toml
    };
    let mut text = format!(
        "listen = \"{addr}\"\n[tls]\ncert = {:?}\nkey = {:?}\n[web]\nroot = {:?}\n[relay]\n{relay_toml}\n",
        env.path("fullchain.pem"),
        env.path("privkey.pem"),
        env.path("site"),
    );
    for u in users {
        text.push_str(&format!("[[user]]\nname = \"{}\"\npassword_hash = \"{}\"\n", u.name, u.password_hash));
    }
    let config: Config = toml::from_str(&text).unwrap();
    config.validate().unwrap();
    config
}

/// A TCP server that answers every connection with a short HTTP response
/// once it has read the request head, then closes.
async fn http_server() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let _ = s.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await;
            });
        }
    });
    (addr, task)
}

/// A TCP server that echoes everything back and closes its side once the
/// client has closed its side.
async fn echo_server() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.into_split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    (addr, task)
}

async fn udp_echo() -> (SocketAddr, JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 65_535];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], from).await;
        }
    });
    (addr, task)
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + i / 251) as u8).collect()
}

struct Driver(JoinHandle<()>);

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Use h2 directly when checking the actual RST_STREAM error code.
async fn raw_h2(relay: &TestRelay) -> (h2::client::SendRequest<Bytes>, Driver) {
    let tls = network_relay::tls::client_config(Some(&relay.env.path("ca.pem")), &[b"h2"]).unwrap();
    let tcp = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
    let io = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls))
        .connect("relay.test".try_into().unwrap(), tcp)
        .await
        .unwrap();
    let (sender, connection) = h2::client::handshake(io).await.unwrap();
    let driver = Driver(tokio::spawn(async move {
        let _ = connection.await;
    }));
    within("extended CONNECT settings", async {
        while !sender.is_extended_connect_protocol_enabled() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    (sender, driver)
}

async fn raw_h3(
    relay: &TestRelay,
    datagrams: bool,
) -> (h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>, quinn::Connection, Driver) {
    raw_h3_with_window(relay, datagrams, None).await
}

async fn raw_h3_with_window(
    relay: &TestRelay,
    datagrams: bool,
    receive_window: Option<u32>,
) -> (h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>, quinn::Connection, Driver) {
    let tls = network_relay::tls::client_config(Some(&relay.env.path("ca.pem")), &[b"h3"]).unwrap();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut cfg = quinn::ClientConfig::new(std::sync::Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(65_536));
    if let Some(window) = receive_window {
        transport.receive_window(window.into());
    }
    cfg.transport_config(std::sync::Arc::new(transport));
    let ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let conn = ep.connect_with(cfg, relay.addr, "relay.test").unwrap().await.unwrap();
    let (mut driver, send) = h3::client::builder()
        .enable_extended_connect(true)
        .enable_datagram(datagrams)
        .build::<_, _, Bytes>(h3_quinn::Connection::new(conn.clone()))
        .await
        .unwrap();
    let driver = Driver(tokio::spawn(async move {
        std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    }));
    (send, conn, driver)
}

fn udp_request(target: SocketAddr) -> http::request::Builder {
    Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://relay.test/.well-known/masque/udp/127.0.0.1/{}/", target.port()))
        .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
        .header("capsule-protocol", "?1")
}

async fn write_h2(send: &mut h2::SendStream<Bytes>, mut bytes: Bytes) {
    within("HTTP/2 flow control", async {
        while !bytes.is_empty() {
            send.reserve_capacity(bytes.len().min(16 * 1024));
            let capacity = std::future::poll_fn(|cx| send.poll_capacity(cx)).await.unwrap().unwrap();
            let n = capacity.min(bytes.len());
            send.send_data(bytes.split_to(n), false).unwrap();
        }
    })
    .await;
}

async fn read_h2_datagram(recv: &mut h2::RecvStream, decoder: &mut CapsuleDecoder) -> Bytes {
    within("DATAGRAM capsule", async {
        loop {
            if let Some(raw) = decoder.next_capsule().unwrap() {
                return raw.value;
            }
            let bytes = recv.data().await.expect("stream ended").unwrap();
            recv.flow_control().release_capacity(bytes.len()).unwrap();
            decoder.push(bytes);
        }
    })
    .await
}

// ---------------------------------------------------------------- tests

#[test]
fn profile_cli_writes_private_files_and_apple_controls() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    let env = Env::new();
    let output = env.path("existing.mobileconfig");
    std::fs::write(&output, "old").unwrap();
    std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o644)).unwrap();
    let run = |extra: &[&std::ffi::OsStr]| {
        let result = Command::new(env!("CARGO_BIN_EXE_network-relay"))
            .args([
                "profile",
                "--host",
                "relay.test",
                "--user",
                ALICE.0,
                "--password",
                ALICE.1,
                "--match-fqdn",
                "Api.Example.com.",
                "--exclude-fqdn",
                "direct.example.com",
                "--ui-toggle-enabled",
                "false",
                "--allow-dns-failover",
                "--relay-uuid",
                "01234567-89ab-4cde-8012-3456789abcde",
            ])
            .args(extra)
            .output()
            .unwrap();
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    };
    run(&["--out".as_ref(), output.as_os_str()]);
    let text = std::fs::read_to_string(&output).unwrap();
    for field in ["MatchFQDNs", "ExcludedFQDNs", "UIToggleEnabled", "AllowDNSFailover", "RelayUUID"] {
        assert!(text.contains(&format!("<key>{field}</key>")), "{field}");
    }
    assert!(text.contains("<string>api.example.com</string>"));
    assert!(text.contains("<key>UIToggleEnabled</key>\n      <false/>"));
    assert!(text.contains("<key>AllowDNSFailover</key>\n      <true/>"));
    assert_eq!(std::fs::metadata(&output).unwrap().permissions().mode() & 0o777, 0o600);

    let config = env.path("relay.toml");
    std::fs::write(
        &config,
        format!(
            "[tls]\ncert = {:?}\nkey = {:?}\n[web]\nroot = {:?}\n",
            env.path("fullchain.pem"),
            env.path("privkey.pem"),
            env.path("site")
        ),
    )
    .unwrap();
    run(&["--publish".as_ref(), "--config".as_ref(), config.as_os_str()]);
    let published: Vec<_> = std::fs::read_dir(env.path("site"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "mobileconfig"))
        .collect();
    assert_eq!(published.len(), 1);
    assert_eq!(std::fs::metadata(&published[0]).unwrap().permissions().mode() & 0o777, 0o600);
}

#[tokio::test]
async fn http2_tcp_reset_has_connect_error_code() {
    let relay = TestRelay::start("").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let (reset_tx, reset_rx) = tokio::sync::oneshot::channel();
    let target_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        reset_rx.await.unwrap();
        socket2::SockRef::from(&tcp).set_linger(Some(Duration::ZERO)).unwrap();
    });
    let (mut sender, _driver) = raw_h2(&relay).await;
    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(target.to_string())
        .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
        .body(())
        .unwrap();
    let (response, _send) = sender.send_request(req, false).unwrap();
    let response = within("CONNECT response", response).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut recv = response.into_body();
    reset_tx.send(()).unwrap();
    target_task.await.unwrap();
    let error = within("CONNECT_ERROR", recv.data()).await.expect("RST became EOF").unwrap_err();
    assert_eq!(error.reason(), Some(h2::Reason::CONNECT_ERROR));
}

#[tokio::test]
async fn http2_udp_oversize_payload_resets_stream() {
    let relay = TestRelay::start("").await;
    let (target, _echo) = udp_echo().await;
    let (mut sender, _driver) = raw_h2(&relay).await;
    let req = udp_request(target).extension(h2::ext::Protocol::from_static("connect-udp")).body(()).unwrap();
    let (response, mut send) = sender.send_request(req, false).unwrap();
    let response = within("CONNECT-UDP response", response).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut recv = response.into_body();
    let mut wire = bytes::BytesMut::new();
    capsule::encode(0, &datagram::udp_payload(&vec![0; 65_528]), &mut wire);
    // Reject as soon as the declared length and context ID are available.
    write_h2(&mut send, wire.freeze().slice(..16)).await;
    let error = within("oversize reset", recv.data()).await.expect("reset became EOF").unwrap_err();
    assert_eq!(error.reason(), Some(h2::Reason::PROTOCOL_ERROR));
}

#[tokio::test]
async fn http2_capsule_requests_reject_content_headers() {
    let relay = TestRelay::start("").await;
    let (target, _echo) = udp_echo().await;
    let (mut sender, _driver) = raw_h2(&relay).await;
    for (header, value) in [("content-type", "application/octet-stream"), ("content-length", "0")] {
        let req = udp_request(target)
            .header(header, value)
            .extension(h2::ext::Protocol::from_static("connect-udp"))
            .body(())
            .unwrap();
        let (response, _send) = sender.send_request(req, false).unwrap();
        let error = within("malformed request reset", response).await.unwrap_err();
        assert_eq!(error.reason(), Some(h2::Reason::PROTOCOL_ERROR), "{header}");
    }
}

#[tokio::test]
async fn http2_udp_skips_large_unknown_capsules_and_relays_empty_payloads() {
    let relay = TestRelay::start("").await;
    let (target, _echo) = udp_echo().await;
    let (mut sender, _driver) = raw_h2(&relay).await;
    let req = udp_request(target).extension(h2::ext::Protocol::from_static("connect-udp")).body(()).unwrap();
    let (response, mut send) = sender.send_request(req, false).unwrap();
    let response = within("CONNECT-UDP response", response).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut recv = response.into_body();
    let mut wire = bytes::BytesMut::new();
    capsule::encode(0x12345, &vec![0; 70_000], &mut wire);
    capsule::encode(0, &vec![1; 70_000], &mut wire); // unknown context, no UDP size limit
    capsule::encode(0, &datagram::udp_payload(b"after-unknown"), &mut wire);
    write_h2(&mut send, wire.freeze()).await;
    let mut decoder = CapsuleDecoder::default();
    assert_eq!(read_h2_datagram(&mut recv, &mut decoder).await, "\0after-unknown");
    let mut wire = bytes::BytesMut::new();
    capsule::encode(0, &datagram::udp_payload(b""), &mut wire);
    write_h2(&mut send, wire.freeze()).await;
    assert_eq!(read_h2_datagram(&mut recv, &mut decoder).await, "\0");
}

#[tokio::test]
async fn http2_connect_trailers_are_protocol_errors() {
    let relay = TestRelay::start("").await;
    let (tcp, _t) = echo_server().await;
    let (udp, _u) = udp_echo().await;
    let (mut sender, _driver) = raw_h2(&relay).await;
    for is_udp in [false, true] {
        let req = if is_udp {
            udp_request(udp).extension(h2::ext::Protocol::from_static("connect-udp")).body(()).unwrap()
        } else {
            Request::builder()
                .method(Method::CONNECT)
                .uri(tcp.to_string())
                .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
                .body(())
                .unwrap()
        };
        let (response, mut send) = sender.send_request(req, false).unwrap();
        let response = within("CONNECT response", response).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        send.send_trailers(http::HeaderMap::new()).unwrap();
        let error = within("trailers reset", response.into_body().data()).await.expect("reset became EOF").unwrap_err();
        assert_eq!(error.reason(), Some(h2::Reason::PROTOCOL_ERROR), "UDP: {is_udp}");
    }
}

#[tokio::test]
async fn http3_connect_trailers_are_connection_errors() {
    let relay = TestRelay::start("").await;
    let (tcp, _t) = echo_server().await;
    let (udp, _u) = udp_echo().await;
    for is_udp in [false, true] {
        let (mut sender, conn, _driver) = raw_h3(&relay, true).await;
        let req = if is_udp {
            udp_request(udp).extension(h3::ext::Protocol::CONNECT_UDP).body(()).unwrap()
        } else {
            Request::builder()
                .method(Method::CONNECT)
                .uri(tcp.to_string())
                .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
                .body(())
                .unwrap()
        };
        let mut stream = sender.send_request(req).await.unwrap();
        assert_eq!(stream.recv_response().await.unwrap().status(), StatusCode::OK);
        stream.send_trailers(http::HeaderMap::new()).await.unwrap();
        let error = within("H3_FRAME_UNEXPECTED", conn.closed()).await;
        assert!(
            matches!(error, quinn::ConnectionError::ApplicationClosed(ref close)
            if close.error_code.into_inner() == h3::error::Code::H3_FRAME_UNEXPECTED.value()),
            "{error:?}, UDP: {is_udp}"
        );
    }
}

#[tokio::test]
async fn http3_empty_data_does_not_half_close_tcp_or_udp() {
    let relay = TestRelay::start("").await;
    let (tcp, _t) = echo_server().await;
    let (udp, _u) = udp_echo().await;
    let (mut sender, _conn, _driver) = raw_h3(&relay, false).await;
    for is_udp in [false, true] {
        let req = if is_udp {
            udp_request(udp).extension(h3::ext::Protocol::CONNECT_UDP).body(()).unwrap()
        } else {
            Request::builder()
                .method(Method::CONNECT)
                .uri(tcp.to_string())
                .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
                .body(())
                .unwrap()
        };
        let mut stream = sender.send_request(req).await.unwrap();
        assert_eq!(stream.recv_response().await.unwrap().status(), StatusCode::OK);
        stream.send_data(Bytes::new()).await.unwrap();
        let expected = if is_udp {
            let mut wire = bytes::BytesMut::new();
            capsule::encode(0, &datagram::udp_payload(b"after-empty"), &mut wire);
            wire.freeze()
        } else {
            Bytes::from_static(b"after-empty")
        };
        stream.send_data(expected.clone()).await.unwrap();
        let mut received = Vec::new();
        within("echo after empty DATA", async {
            while received.len() < expected.len() {
                let mut data = stream.recv_data().await.unwrap().expect("empty DATA became EOF");
                received.extend_from_slice(&data.copy_to_bytes(data.remaining()));
            }
        })
        .await;
        assert_eq!(&received[..], &expected[..]);
        stream.finish().await.unwrap();
    }
}

#[tokio::test]
async fn http3_truncated_data_without_payload_is_frame_error() {
    let relay = TestRelay::start("").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let (_sender, conn, _driver) = raw_h3(&relay, true).await;
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    let mut block = bytes::BytesMut::new();
    h3::qpack::encode_stateless(
        &mut block,
        [
            h3::qpack::HeaderField::new(":method", "CONNECT"),
            h3::qpack::HeaderField::new(":authority", target.to_string()),
            h3::qpack::HeaderField::new("authorization", auth::basic_authorization(ALICE.0, ALICE.1)),
        ],
    )
    .unwrap();
    let mut wire = bytes::BytesMut::new();
    network_relay::proto::varint::encode(1, &mut wire); // HEADERS
    network_relay::proto::varint::encode(block.len() as u64, &mut wire);
    wire.extend_from_slice(&block);
    send.write_all(&wire).await.unwrap();
    let (mut tcp, _) = within("CONNECT target", listener.accept()).await.unwrap();
    send.write_all(&[0, 4]).await.unwrap(); // DATA length 4, no value before FIN
    send.finish().unwrap();
    let error = within("truncated DATA error", conn.closed()).await;
    assert!(
        matches!(error, quinn::ConnectionError::ApplicationClosed(ref close)
        if close.error_code.into_inner() == h3::error::Code::H3_FRAME_ERROR.value()),
        "{error:?}"
    );
    let error = within("target reset", tcp.read(&mut [0])).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
}

#[tokio::test]
async fn http2_truncated_udp_capsule_resets_stream() {
    let relay = TestRelay::start("").await;
    let (udp, _u) = udp_echo().await;
    let (mut sender, _driver) = raw_h2(&relay).await;
    let req = udp_request(udp).extension(h2::ext::Protocol::from_static("connect-udp")).body(()).unwrap();
    let (response, mut send) = sender.send_request(req, false).unwrap();
    let response = within("CONNECT response", response).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    send.send_data(Bytes::from_static(&[0, 10, 0, 1]), true).unwrap();
    let error =
        within("truncated capsule reset", response.into_body().data()).await.expect("reset became EOF").unwrap_err();
    assert_eq!(error.reason(), Some(h2::Reason::PROTOCOL_ERROR));
}

#[tokio::test]
async fn http3_half_closed_tunnel_detects_connection_loss() {
    let relay = TestRelay::start("").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let (mut sender, conn, _driver) = raw_h3(&relay, true).await;
    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(target.to_string())
        .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
        .body(())
        .unwrap();
    let mut stream = sender.send_request(req).await.unwrap();
    assert_eq!(stream.recv_response().await.unwrap().status(), StatusCode::OK);
    let (mut tcp, _) = listener.accept().await.unwrap();
    stream.finish().await.unwrap();
    assert_eq!(within("target half-close", tcp.read(&mut [0])).await.unwrap(), 0);
    conn.close(0u32.into(), b"test disconnect");
    within("released tunnel slot", async {
        while relay.relay.active_tunnels() != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
}

#[tokio::test]
async fn revocation_cancels_http3_response_blocked_by_flow_control() {
    let relay = TestRelay::start("").await;
    std::fs::write(relay.env.path("site/index.html"), vec![b'x'; 65_536]).unwrap();
    relay.reload("", &relay.users);
    let (mut sender, _conn, _driver) = raw_h3_with_window(&relay, true, Some(1024)).await;
    // Do not read this response: it consumes the connection's receive window.
    let _unread = sender.send_request(Request::builder().uri("https://relay.test/").body(()).unwrap()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(target.to_string())
        .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
        .body(())
        .unwrap();
    let mut stream = sender.send_request(request).await.unwrap();
    let (mut tcp, _) = within("target connected", listener.accept()).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), stream.recv_response()).await.is_err(),
        "test requires a response blocked by connection flow control"
    );
    relay.reload("", &[]);
    let error = within("revoked target reset", tcp.read(&mut [0])).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    within("released tunnel slot", async {
        while relay.relay.active_tunnels() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
}

#[tokio::test]
async fn http3_without_datagram_setting_uses_capsules() {
    let relay = TestRelay::start("").await;
    let (target, _echo) = udp_echo().await;
    let (mut send, conn, _driver) = raw_h3(&relay, false).await;
    let req = udp_request(target).extension(h3::ext::Protocol::CONNECT_UDP).body(()).unwrap();
    let mut stream = send.send_request(req).await.unwrap();
    assert_eq!(stream.recv_response().await.unwrap().status(), StatusCode::OK);
    let payload = datagram::udp_payload(&pattern(4_000));
    let mut wire = bytes::BytesMut::new();
    capsule::encode(0, &payload, &mut wire);
    stream.send_data(wire.freeze()).await.unwrap();
    let mut decoder = CapsuleDecoder::default();
    let received = within("HTTP/3 capsule fallback", async {
        loop {
            if let Some(raw) = decoder.next_capsule().unwrap() {
                break raw.value;
            }
            tokio::select! {
                data = stream.recv_data() => decoder.push(data.unwrap().expect("stream ended")),
                data = conn.read_datagram() => panic!("unnegotiated HTTP Datagram: {data:?}"),
            }
        }
    })
    .await;
    assert_eq!(received, payload);
}

#[tokio::test]
async fn http3_datagram_on_tcp_request_has_datagram_error_code() {
    let relay = TestRelay::start("").await;
    let (target, _echo) = echo_server().await;
    let opts = relay.options(ALICE, target, target);
    let mut h3 = H3::connect(&opts, &opts.addresses).await.unwrap();
    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(target.to_string())
        .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
        .body(())
        .unwrap();
    let mut stream = h3.request(req).await.unwrap();
    assert_eq!(stream.recv_response().await.unwrap().status(), StatusCode::OK);
    h3.send_datagram(stream.id(), Bytes::from_static(b"\0unnegotiated")).unwrap();
    let result = within("H3_DATAGRAM_ERROR", stream.recv_data()).await;
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("illegal datagram did not reset the TCP request"),
    };
    assert!(
        matches!(error, h3::error::StreamError::RemoteTerminate { code } if code == h3::error::Code::H3_DATAGRAM_ERROR),
        "{error:?}"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn target_udp_sockets_disable_ip_fragmentation() {
    use nix::libc;
    use std::os::fd::AsRawFd;
    for (address, level, option, expected) in [
        ("127.0.0.1:0", libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, libc::IP_PMTUDISC_DO),
        ("[::1]:0", libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER, libc::IPV6_PMTUDISC_DO),
    ] {
        let Ok(target) = UdpSocket::bind(address).await else {
            // A container or CI host without IPv6 loopback.
            assert!(address.starts_with("[::1]"), "{address} must be available");
            continue;
        };
        let sock = network_relay::connect::udp(&[target.local_addr().unwrap()]).await.unwrap();
        let mut mode: libc::c_int = 0;
        let mut len = std::mem::size_of_val(&mode) as libc::socklen_t;
        // SAFETY: the live descriptor and pointers refer to an integer and its length.
        let rc = unsafe {
            libc::getsockopt(sock.as_raw_fd(), level, option, (&mut mode as *mut libc::c_int).cast(), &mut len)
        };
        assert_eq!(rc, 0);
        assert_eq!(mode, expected, "{address}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_transport_relays_tcp_and_udp() {
    let relay = TestRelay::start("").await;
    let (web, _w) = http_server().await;
    let (dns, _d) = udp_echo().await;
    let outcomes = within("checks", check::run(&relay.options(ALICE, web, dns))).await;
    assert_eq!(outcomes.len(), 7);
    for o in &outcomes {
        let detail = o.result.as_ref().unwrap_or_else(|e| panic!("{}: {e:#}", o.name));
        if o.name.contains("TCP") {
            assert!(detail.contains("HTTP/1.1 204 No Content"), "{}: {detail}", o.name);
        }
        if o.name.contains("UDP") {
            assert!(detail.contains("echoed"), "{}: {detail}", o.name);
        }
    }
    assert_eq!(relay.relay.active_tunnels(), 0, "every tunnel was closed");
}

#[tokio::test]
async fn check_retries_next_address_after_tls_failure() {
    let relay = TestRelay::start("").await;
    let failing = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first = failing.local_addr().unwrap();
    let _accept = Driver(tokio::spawn(async move {
        while let Ok((mut tcp, _)) = failing.accept().await {
            let _ = tcp.write_all(b"not TLS").await;
        }
    }));
    let opts = relay.options(ALICE, relay.addr, relay.addr);
    let (mut sender, _driver) = check::h2_sender(&opts, &[first, relay.addr]).await.unwrap();
    let request = Request::builder().uri("https://relay.test/").body(Empty::<Bytes>::new()).unwrap();
    assert_eq!(
        within("fallback HTTP/2 response", sender.send_request(request)).await.unwrap().status(),
        StatusCode::OK
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_credentials_get_the_website() {
    let relay = TestRelay::start("").await;
    let (web, _w) = http_server().await;
    let (dns, _d) = udp_echo().await;
    for creds in [(ALICE.0, "wrong-password"), ("mallory", ALICE.1)] {
        let outcomes = within("checks", check::run(&relay.options(creds, web, dns))).await;
        for o in &outcomes {
            if o.name.starts_with("hidden") {
                o.result.as_ref().unwrap();
            } else {
                let e = format!("{:#}", o.result.as_ref().unwrap_err());
                assert!(e.contains("plain website"), "{}: {e}", o.name);
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocked_destinations_and_ports_are_refused() {
    // The default rules block loopback.
    let relay = TestRelay::start("blocked_ports = [25]").await;
    let (web, _w) = http_server().await;
    let (dns, _d) = udp_echo().await;
    let mut opts = relay.options(ALICE, web, dns);
    // A name that resolves to a blocked address is refused too.
    opts.tcp_target = format!("localhost:{}", web.port());
    let outcomes = within("checks", check::run(&opts)).await;
    for o in outcomes.iter().filter(|o| !o.name.starts_with("hidden")) {
        let e = format!("{:#}", o.result.as_ref().unwrap_err());
        assert!(e.contains("403") && e.contains("destination_ip_prohibited"), "{}: {e}", o.name);
    }

    relay.reload("blocked_destinations = []\nblocked_ports = [25]", &relay.users);
    let mut opts = relay.options(ALICE, web, dns);
    opts.tcp_target = "127.0.0.1:25".into();
    let e = format!("{:#}", within("check", check::run(&opts)).await[0].result.as_ref().unwrap_err());
    assert!(e.contains("403") && e.contains("http_request_denied"), "{e}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unreachable_destinations_get_proxy_status() {
    let relay = TestRelay::start("").await;
    let (dns, _d) = udp_echo().await;
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let opts = relay.options(ALICE, closed, dns);
    let mut h3 = H3::connect(&opts, &opts.addresses).await.unwrap();
    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(closed.to_string())
        .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
        .body(())
        .unwrap();
    let mut stream = h3.request(req).await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(resp.headers()["proxy-status"], "network-relay; error=connection_refused");

    let req = Request::builder()
        .method(Method::CONNECT)
        .uri("does-not-exist.invalid:80")
        .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
        .body(())
        .unwrap();
    let mut stream = h3.request(req).await.unwrap();
    // Wait longer than the server's DNS deadline. Giving the test client
    // the identical deadline races the error response on slow resolvers.
    let response = within("DNS refusal", stream.recv_response()).await.unwrap();
    assert!(matches!(response.status(), StatusCode::BAD_GATEWAY | StatusCode::GATEWAY_TIMEOUT));
    let status = response.headers()["proxy-status"].to_str().unwrap();
    assert!(
        matches!(
            status,
            "network-relay; error=dns_error"
                | "network-relay; error=dns_timeout"
                | "network-relay; error=destination_not_found"
        ),
        "{status}"
    );
}

/// Data flows both ways intact, and a FIN on either side reaches the other:
/// the client finishes its stream, the echo server then closes, and the
/// client sees the end of the stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http3_tcp_tunnel_carries_bulk_data_and_half_closes() {
    let relay = TestRelay::start("").await;
    let (echo, _e) = echo_server().await;
    let (dns, _d) = udp_echo().await;
    let opts = relay.options(ALICE, echo, dns);
    let mut h3 = H3::connect(&opts, &opts.addresses).await.unwrap();
    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(echo.to_string())
        .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
        .body(())
        .unwrap();
    let mut stream = h3.request(req).await.unwrap();
    assert_eq!(stream.recv_response().await.unwrap().status(), StatusCode::OK);
    let (mut send, mut recv) = stream.split();
    let data = pattern(4 << 20);
    let expected = data.clone();
    let writer = tokio::spawn(async move {
        for chunk in data.chunks(60_000) {
            send.send_data(Bytes::copy_from_slice(chunk)).await.unwrap();
        }
        send.finish().await.unwrap();
    });
    let mut got = Vec::with_capacity(expected.len());
    within("echoed data", async {
        while let Some(mut b) = recv.recv_data().await.unwrap() {
            got.extend_from_slice(&b.copy_to_bytes(b.remaining()));
        }
    })
    .await;
    writer.await.unwrap();
    assert_eq!(got.len(), expected.len());
    assert!(got == expected, "data corrupted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http2_tcp_tunnels_share_a_connection() {
    let relay = TestRelay::start("").await;
    let (echo, _e) = echo_server().await;
    let (dns, _d) = udp_echo().await;
    let opts = relay.options(ALICE, echo, dns);
    let (sender, _conn) = check::h2_sender(&opts, &opts.addresses).await.unwrap();
    let mut tasks = Vec::new();
    for i in 0..20 {
        let mut sender = sender.clone();
        tasks.push(tokio::spawn(async move {
            let req = Request::builder()
                .method(Method::CONNECT)
                .uri(echo.to_string())
                .header("proxy-authorization", auth::basic_authorization(ALICE.0, ALICE.1))
                .body(Empty::<Bytes>::new())
                .unwrap();
            let mut resp = sender.send_request(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let mut io = TokioIo::new(hyper::upgrade::on(&mut resp).await.unwrap());
            let data = pattern(100_000 + i);
            io.write_all(&data).await.unwrap();
            io.shutdown().await.unwrap();
            let mut got = Vec::new();
            io.read_to_end(&mut got).await.unwrap();
            assert!(got == data, "tunnel {i} corrupted data");
        }));
    }
    for t in tasks {
        within("tunnel", t).await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http2_tcp_tunnel_releases_flow_control_and_half_closes() {
    let relay = TestRelay::start("").await;
    let (echo, _e) = echo_server().await;
    let opts = relay.options(ALICE, echo, echo);
    let (mut sender, _driver) = check::h2_sender(&opts, &opts.addresses).await.unwrap();
    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(echo.to_string())
        .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let mut response = within("CONNECT response", sender.send_request(req)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let io = TokioIo::new(hyper::upgrade::on(&mut response).await.unwrap());
    let (mut rd, mut wr) = tokio::io::split(io);
    // Larger than the relay's per-stream window, and the client's window.
    let expected = pattern(8 << 20);
    let data = expected.clone();
    let writer = tokio::spawn(async move {
        wr.write_all(&data).await.unwrap();
        wr.shutdown().await.unwrap();
    });
    let mut received = Vec::new();
    within("flow-controlled echo and FIN", rd.read_to_end(&mut received)).await.unwrap();
    writer.await.unwrap();
    assert!(received == expected, "bulk data corrupted");
}

#[tokio::test]
async fn http2_client_reset_and_revocation_reset_the_target() {
    for revoke in [false, true] {
        let relay = TestRelay::start("").await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let (mut sender, _driver) = raw_h2(&relay).await;
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri(target.to_string())
            .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
            .body(())
            .unwrap();
        let (response, mut send) = sender.send_request(req, false).unwrap();
        let response = within("CONNECT response", response).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let (mut tcp, _) = within("target connection", listener.accept()).await.unwrap();
        if revoke {
            relay.reload("", &[]);
            let mut recv = response.into_body();
            let error = within("revocation reset", recv.data()).await.expect("revocation became EOF").unwrap_err();
            assert_eq!(error.reason(), Some(h2::Reason::CONNECT_ERROR));
        } else {
            send.send_reset(h2::Reason::CANCEL);
        }
        let mut data = [0; 1];
        let error = within("target reset", tcp.read(&mut data)).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset, "revoke={revoke}");
    }
}

#[tokio::test]
async fn http2_idle_half_closed_tunnel_detects_client_reset() {
    let relay = TestRelay::start("").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let (mut sender, _driver) = raw_h2(&relay).await;
    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(target.to_string())
        .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
        .body(())
        .unwrap();
    let (response, mut send) = sender.send_request(req, false).unwrap();
    let response = within("CONNECT response", response).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let (mut target, _) = listener.accept().await.unwrap();
    send.send_data(Bytes::new(), true).unwrap();
    assert_eq!(within("target FIN", target.read(&mut [0])).await.unwrap(), 0);
    send.send_reset(h2::Reason::CANCEL);
    within("idle half-closed tunnel cleanup", async {
        while relay.relay.active_tunnels() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
}

#[tokio::test]
async fn http3_idle_tunnel_detects_stop_sending() {
    let relay = TestRelay::start("").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let opts = relay.options(ALICE, target, target);
    let mut h3 = H3::connect(&opts, &opts.addresses).await.unwrap();
    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(target.to_string())
        .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
        .body(())
        .unwrap();
    let mut stream = h3.request(req).await.unwrap();
    assert_eq!(stream.recv_response().await.unwrap().status(), StatusCode::OK);
    let (mut target, _) = listener.accept().await.unwrap();
    // Cancel only the response direction, while the request and target are idle.
    stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
    let error = within("target RST after STOP_SENDING", target.read(&mut [0])).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
}

/// Datagrams sent right after the request, before the response, are not
/// lost; then many round trips work.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http3_udp_flow_accepts_early_datagrams() {
    let relay = TestRelay::start("").await;
    let (echo, _e) = udp_echo().await;
    let opts = relay.options(ALICE, echo, echo);
    let mut h3 = H3::connect(&opts, &opts.addresses).await.unwrap();
    let path = format!("/.well-known/masque/udp/127.0.0.1/{}/", echo.port());
    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://relay.test:{}{path}", relay.addr.port()))
        .header("capsule-protocol", "?1")
        .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
        .extension(h3::ext::Protocol::CONNECT_UDP)
        .body(())
        .unwrap();
    let mut stream = h3.request(req).await.unwrap();
    // Sent before the response, and likely before the relay has checked
    // the request.
    h3.send_datagram(stream.id(), datagram::udp_payload(b"early")).unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["capsule-protocol"], "?1");
    let (mut tunnel, _filter) = h3.udp_tunnel(stream);
    let mut received = Vec::new();
    within("early echo", async {
        loop {
            if let Event::Datagram(p) = tunnel.next_event().await.unwrap() {
                received.push(p);
                break;
            }
        }
    })
    .await;
    assert_eq!(&received[0][..], b"\x00early");
    for i in 0..200u32 {
        tunnel.send_datagram(datagram::udp_payload(&i.to_be_bytes())).unwrap();
        let Event::Datagram(p) = within("echo", tunnel.next_event()).await.unwrap() else { panic!("closed") };
        assert_eq!(&p[1..], i.to_be_bytes());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removing_a_user_ends_their_tunnels() {
    let relay = TestRelay::start("").await;
    let (echo, _e) = echo_server().await;
    let (dns, _d) = udp_echo().await;
    let opts = relay.options(ALICE, echo, dns);
    let mut h3 = H3::connect(&opts, &opts.addresses).await.unwrap();
    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(echo.to_string())
        .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
        .body(())
        .unwrap();
    let mut stream = h3.request(req).await.unwrap();
    assert_eq!(stream.recv_response().await.unwrap().status(), StatusCode::OK);
    stream.send_data(Bytes::from_static(b"ping")).await.unwrap();
    let mut b = within("echo", stream.recv_data()).await.unwrap().unwrap();
    assert_eq!(b.copy_to_bytes(b.remaining()), "ping");
    assert_eq!(relay.relay.active_tunnels(), 1);

    relay.reload("", &[]);
    let ended = within("the tunnel to end", stream.recv_data()).await;
    assert!(ended.is_err(), "the stream is reset, not finished: {:?}", ended.map(|b| b.is_some()));
    within("the permit to be returned", async {
        while relay.relay.active_tunnels() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn visitors_see_the_website() {
    let relay = TestRelay::start("").await;
    let (echo, _e) = echo_server().await;
    let opts = relay.options(ALICE, echo, echo);
    let (mut sender, _conn) = check::h2_sender(&opts, &opts.addresses).await.unwrap();
    let get = |path: &str| {
        Request::builder()
            .uri(format!("https://relay.test:{}{path}", relay.addr.port()))
            .body(Empty::<Bytes>::new())
            .unwrap()
    };
    let resp = sender.send_request(get("/")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers()["alt-svc"].to_str().unwrap().starts_with("h3=\":"));
    assert_eq!(&resp.into_body().collect().await.unwrap().to_bytes()[..], INDEX);
    let resp = sender.send_request(get("/some/page")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "single-page-app fallback");
    let resp = sender.send_request(get("/.well-known/pvd")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "no proxy configuration is advertised");

    let mut h3 = H3::connect(&opts, &opts.addresses).await.unwrap();
    let req = Request::builder().uri(format!("https://relay.test:{}/", relay.addr.port())).body(()).unwrap();
    let mut stream = h3.request(req).await.unwrap();
    stream.finish().await.unwrap();
    assert_eq!(stream.recv_response().await.unwrap().status(), StatusCode::OK);
    let mut body = Vec::new();
    while let Some(mut b) = stream.recv_data().await.unwrap() {
        body.extend_from_slice(&b.copy_to_bytes(b.remaining()));
    }
    assert_eq!(body, INDEX);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn max_tunnels_is_enforced() {
    let relay = TestRelay::start("blocked_destinations = []\nmax_tunnels = 1").await;
    let (echo, _e) = echo_server().await;
    let opts = relay.options(ALICE, echo, echo);
    let mut h3 = H3::connect(&opts, &opts.addresses).await.unwrap();
    let connect = || {
        Request::builder()
            .method(Method::CONNECT)
            .uri(echo.to_string())
            .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
            .body(())
            .unwrap()
    };
    let mut first = h3.request(connect()).await.unwrap();
    assert_eq!(first.recv_response().await.unwrap().status(), StatusCode::OK);
    let mut second = h3.request(connect()).await.unwrap();
    let resp = second.recv_response().await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.headers()["proxy-status"], "network-relay; error=connection_limit_reached");
    first.finish().await.unwrap();
    while first.recv_data().await.unwrap().is_some() {}
    within("the permit to be returned", async {
        while relay.relay.active_tunnels() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let mut third = h3.request(connect()).await.unwrap();
    assert_eq!(third.recv_response().await.unwrap().status(), StatusCode::OK);
}

/// RFC 9110 §9.3.6: a 2xx response to CONNECT carries no Content-Length or
/// Transfer-Encoding; RFC 9298 §3.2: the 101 names the upgrade token.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http1_success_responses_have_no_framing_headers() {
    let relay = TestRelay::start("").await;
    let (echo, _e) = echo_server().await;
    let (dns, _d) = udp_echo().await;
    let opts = relay.options(ALICE, echo, dns);
    let (mut sender, _conn) = check::h1_sender(&opts, &opts.addresses).await.unwrap();
    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(echo.to_string())
        .header("host", echo.to_string())
        .header("proxy-authorization", auth::basic_authorization(ALICE.0, ALICE.1))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = within("CONNECT", sender.send_request(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!resp.headers().contains_key("content-length"), "{:?}", resp.headers());
    assert!(!resp.headers().contains_key("transfer-encoding"), "{:?}", resp.headers());

    let (mut sender, _conn) = check::h1_sender(&opts, &opts.addresses).await.unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/.well-known/masque/udp/127.0.0.1/{}/", dns.port()))
        .header("host", "relay.test")
        .header("connection", "Upgrade")
        .header("upgrade", "connect-udp")
        .header("capsule-protocol", "?1")
        .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = within("Upgrade", sender.send_request(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(resp.headers()["upgrade"], "connect-udp");
    assert_eq!(resp.headers()["capsule-protocol"], "?1");
    assert!(!resp.headers().contains_key("content-length"), "{:?}", resp.headers());
}
