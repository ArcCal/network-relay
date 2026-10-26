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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http1_upgraded_tunnel_holds_connection_admission_and_shutdown_drain() {
    let relay = TestRelay::start("max_connections_per_ip = 1\nblocked_destinations = []").await;
    let (echo, task) = echo_server().await;
    let opts = relay.options(ALICE, echo, echo);
    let (mut sender, _driver) = check::h1_sender(&opts, &opts.addresses).await.unwrap();
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(echo.to_string())
        .header("host", echo.to_string())
        .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let mut response = within("HTTP/1 CONNECT", sender.send_request(request)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut tunnel = TokioIo::new(hyper::upgrade::on(&mut response).await.unwrap());
    tunnel.write_all(b"alive").await.unwrap();
    let mut reply = [0; 5];
    within("echo", tunnel.read_exact(&mut reply)).await.unwrap();
    assert_eq!(&reply, b"alive");
    assert_eq!(relay.relay.open_connections(), 1, "upgrading released the connection slot");
    assert!(check::h1_sender(&opts, &opts.addresses).await.is_err(), "upgrades bypassed admission");
    relay.relay.begin_shutdown();
    assert!(!relay.relay.drain(Duration::from_millis(100)).await, "shutdown forgot the upgraded tunnel");
    drop(tunnel);
    assert!(relay.relay.drain(WAIT).await);
    task.abort();
}

fn connect_request(target: SocketAddr) -> Request<()> {
    Request::builder()
        .method(Method::CONNECT)
        .uri(target.to_string())
        .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
        .body(())
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anonymous_connections_cannot_take_the_capacity_devices_need() {
    // Version 1.2 reserved a connection's transport memory when it was
    // accepted, before TLS: enough idle connections, from anyone, used up the
    // whole budget, and devices could no longer connect at all.
    let memory = network_relay::limits::total_memory().unwrap_or(1 << 30);
    let enough = (memory / 2 / network_relay::limits::connection_memory(Some(memory))) as usize + 8;
    let n = enough.min(3000);
    let relay = TestRelay::start(&format!(
        "blocked_destinations = []\nmax_connections = {}\nmax_connections_per_ip = {}",
        n + 64,
        n + 64
    ))
    .await;
    let mut idle = Vec::with_capacity(n);
    for _ in 0..n {
        idle.push(tokio::net::TcpStream::connect(relay.addr).await.unwrap());
    }
    within("idle connections accepted", async {
        while relay.relay.open_connections() < n {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    let (echo, task) = echo_server().await;
    let (mut h2, _h2_driver) = raw_h2(&relay).await;
    let (response, mut send) = h2.send_request(connect_request(echo), false).unwrap();
    assert_eq!(within("HTTP/2 tunnel", response).await.unwrap().status(), StatusCode::OK);
    send.send_reset(h2::Reason::CANCEL);
    let (mut h3, _conn, _h3_driver) = raw_h3(&relay, true).await;
    let mut stream = h3.send_request(connect_request(echo)).await.unwrap();
    assert_eq!(within("HTTP/3 tunnel", stream.recv_response()).await.unwrap().status(), StatusCode::OK);
    stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
    drop(idle);
    task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_connection_carries_hundreds_of_concurrent_tunnels() {
    // A device carries all its relayed connections and flows on one HTTP/3
    // (or HTTP/2) connection; version 1.2 allowed 32 at once.
    let relay = TestRelay::start("blocked_destinations = []\nmax_tunnels = 2000\nmax_tunnels_per_user = 2000").await;
    let (echo, task) = echo_server().await;
    let (mut h3, _conn, _h3_driver) = raw_h3(&relay, true).await;
    let mut streams = Vec::new();
    for _ in 0..300 {
        streams.push(within("HTTP/3 stream credit", h3.send_request(connect_request(echo))).await.unwrap());
    }
    for stream in &mut streams {
        assert_eq!(within("HTTP/3 tunnel", stream.recv_response()).await.unwrap().status(), StatusCode::OK);
    }
    let (mut h2, _h2_driver) = raw_h2(&relay).await;
    let mut tunnels = Vec::new();
    for _ in 0..200 {
        let (response, send) = h2.send_request(connect_request(echo), false).unwrap();
        tunnels.push((response, send));
    }
    let mut sends = Vec::new();
    for (response, send) in tunnels {
        assert_eq!(within("HTTP/2 tunnel", response).await.unwrap().status(), StatusCode::OK);
        sends.push(send);
    }
    assert_eq!(relay.relay.active_tunnels(), 500);
    for mut stream in streams {
        stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
    }
    for mut send in sends {
        send.send_reset(h2::Reason::CANCEL);
    }
    within("tunnels released", async {
        while relay.relay.active_tunnels() != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn website_responses_the_client_does_not_read_are_abandoned() {
    let relay = TestRelay::start("").await;
    relay.relay.set_send_stall(Duration::from_millis(300));
    std::fs::write(relay.env.path("site/big.bin"), pattern(8 << 20)).unwrap();
    relay.reload("", &relay.users);
    let ca = relay.env.path("ca.pem");

    // HTTP/2: no flow control credit for the response body.
    {
        let tls = network_relay::tls::client_config(Some(&ca), &[b"h2"]).unwrap();
        let tcp = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
        let io = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls))
            .connect("relay.test".try_into().unwrap(), tcp)
            .await
            .unwrap();
        let (mut sender, connection) =
            h2::client::Builder::new().initial_window_size(0).handshake::<_, Bytes>(io).await.unwrap();
        let _driver = Driver(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let request = Request::builder().uri("https://relay.test/").body(()).unwrap();
        let (response, _) = sender.send_request(request, true).unwrap();
        let response = within("HTTP/2 website headers", response).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let error = within("HTTP/2 abandoned response", response.into_body().data()).await.unwrap().unwrap_err();
        assert_eq!(error.reason(), Some(h2::Reason::CANCEL), "{error:?}");
    }

    // HTTP/3: little stream credit, and the client does not read.
    {
        let tls = network_relay::tls::client_config(Some(&ca), &[b"h3"]).unwrap();
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
        let mut config = quinn::ClientConfig::new(std::sync::Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.stream_receive_window(4096u32.into());
        config.transport_config(std::sync::Arc::new(transport));
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let conn = endpoint.connect_with(config, relay.addr, "relay.test").unwrap().await.unwrap();
        let (mut driver, mut sender) =
            h3::client::builder().build::<_, _, Bytes>(h3_quinn::Connection::new(conn.clone())).await.unwrap();
        let _driver = Driver(tokio::spawn(async move {
            std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        }));
        let mut stream =
            sender.send_request(Request::builder().uri("https://relay.test/big.bin").body(()).unwrap()).await.unwrap();
        let _ = stream.finish().await;
        assert_eq!(within("HTTP/3 website headers", stream.recv_response()).await.unwrap().status(), StatusCode::OK);
        // Not reading lets the stream window run out; reading only later
        // must find the response abandoned, not resumed.
        tokio::time::sleep(Duration::from_millis(1000)).await;
        let error = within("HTTP/3 abandoned response", async {
            loop {
                if let Err(e) = stream.recv_data().await {
                    return e;
                }
            }
        })
        .await;
        assert!(
            matches!(error, h3::error::StreamError::RemoteTerminate { code } if code == h3::error::Code::H3_REQUEST_CANCELLED),
            "{error:?}"
        );
        conn.close(0u32.into(), b"");
    }
    within("HTTP/2 and HTTP/3 connections closed", async {
        while relay.relay.open_connections() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;

    // HTTP/1.1: a large file the client never reads. Its receive buffer is
    // small, so the relay's writes soon wait on it.
    let tls = network_relay::tls::client_config(Some(&ca), &[b"http/1.1"]).unwrap();
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(4096).unwrap();
    let tcp = socket.connect(relay.addr).await.unwrap();
    let mut io = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls))
        .connect("relay.test".try_into().unwrap(), tcp)
        .await
        .unwrap();
    io.write_all(b"GET /big.bin HTTP/1.1\r\nHost: relay.test\r\n\r\n").await.unwrap();
    within("HTTP/1.1 connection with an unread response closed", async {
        while relay.relay.open_connections() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    drop(io);
}

async fn within<T>(what: &str, fut: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, fut).await.unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}

fn bodyless_request_finished(result: Result<(), h3::error::StreamError>) {
    // RFC 9114 §4.1: a server may stop the unused request body with
    // H3_NO_ERROR while returning its complete response. FIN can race that
    // STOP_SENDING; all other errors and response corruption still fail.
    match result {
        Ok(()) => {}
        Err(h3::error::StreamError::RemoteTerminate { code }) if code == h3::error::Code::H3_NO_ERROR => {}
        Err(error) => panic!("finishing bodyless request: {error:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expiry_reload_revokes_existing_http2_and_http3_tunnels_and_refreshes_connection_auth() {
    let relay = TestRelay::start("").await;
    let (echo, echo_task) = echo_server().await;
    let (mut h2, _h2_driver) = raw_h2(&relay).await;
    let (mut h3, _conn, _h3_driver) = raw_h3(&relay, true).await;
    let request = || {
        Request::builder()
            .method(Method::CONNECT)
            .uri(echo.to_string())
            .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
            .body(())
            .unwrap()
    };
    let (response, _send) = h2.send_request(request(), false).unwrap();
    let mut recv = response.await.unwrap().into_body();
    let mut stream = h3.send_request(request()).await.unwrap();
    assert_eq!(stream.recv_response().await.unwrap().status(), StatusCode::OK);
    let mut users = relay.users.clone();
    users[0].expires = Some((chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339());
    relay.reload("", &users);
    assert!(within("HTTP/2 expiry revocation", recv.data()).await.unwrap().is_err());
    assert!(within("HTTP/3 expiry revocation", stream.recv_data()).await.is_err());
    within("revoked slots", async {
        while relay.relay.active_tunnels() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    // The same transport sessions must authenticate again with the new expiry.
    let (response, mut send) = h2.send_request(request(), false).unwrap();
    assert_eq!(response.await.unwrap().status(), StatusCode::OK);
    send.send_reset(h2::Reason::CANCEL);
    let mut stream = h3.send_request(request()).await.unwrap();
    assert_eq!(stream.recv_response().await.unwrap().status(), StatusCode::OK);
    stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
    echo_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http2_udp_read_reset_aborts_both_directions_and_releases_capacity() {
    let relay = TestRelay::start("").await;
    let (udp, task) = udp_echo().await;
    let (mut sender, _driver) = raw_h2(&relay).await;
    let req = udp_request(udp).extension(h2::ext::Protocol::from_static("connect-udp")).body(()).unwrap();
    let (response, mut send) = sender.send_request(req, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut recv = response.into_body();
    send.send_reset(h2::Reason::CANCEL);
    assert!(within("reset UDP response", recv.data()).await.unwrap().is_err());
    within("UDP capacity refund", async {
        while relay.relay.active_tunnels() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    task.abort();
}

#[tokio::test]
async fn http3_udp_read_reset_is_an_error_not_a_clean_response_fin() {
    let relay = TestRelay::start("").await;
    let (udp, task) = udp_echo().await;
    let (mut sender, _conn, _driver) = raw_h3(&relay, false).await;
    let request = udp_request(udp).extension(h3::ext::Protocol::CONNECT_UDP).body(()).unwrap();
    let mut stream = sender.send_request(request).await.unwrap();
    assert_eq!(stream.recv_response().await.unwrap().status(), StatusCode::OK);
    stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
    let error = within("UDP receive reset", stream.recv_data()).await.err().expect("read reset became a clean FIN");
    assert!(
        matches!(error, h3::error::StreamError::RemoteTerminate { code }
        if code == h3::error::Code::H3_CONNECT_ERROR),
        "{error:?}"
    );
    within("UDP capacity refund", async {
        while relay.relay.active_tunnels() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    task.abort();
}

#[tokio::test]
async fn http3_setup_without_control_stream_credit_times_out_and_refunds_admission() {
    let relay = TestRelay::start("").await;
    let tls = network_relay::tls::client_config(Some(&relay.env.path("ca.pem")), &[b"h3"]).unwrap();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut config = quinn::ClientConfig::new(std::sync::Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_uni_streams(0u32.into());
    config.transport_config(std::sync::Arc::new(transport));
    let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let conn = endpoint.connect_with(config, relay.addr, "relay.test").unwrap().await.unwrap();
    within("server setup timeout", conn.closed()).await;
    within("setup connection slot refunded", async {
        while relay.relay.open_connections() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_transport_churn_preserves_payloads_and_refunds_all_slots() {
    use std::sync::Arc;
    let relay = Arc::new(TestRelay::start("blocked_destinations = []\nmax_tunnels = 1024").await);
    let (echo, echo_task) = echo_server().await;
    // Exercise an established user's traffic, rather than racing the
    // separate 30-attempt authentication burst limit with 32 new sessions.
    {
        let (mut sender, _driver) = raw_h2(&relay).await;
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri(echo.to_string())
            .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
            .body(())
            .unwrap();
        let (response, mut send) = sender.send_request(req, false).unwrap();
        assert_eq!(response.await.unwrap().status(), StatusCode::OK);
        send.send_reset(h2::Reason::CANCEL);
    }
    within("warm connection cleanup", async {
        while relay.relay.active_tunnels() != 0 || relay.relay.open_connections() != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    for use_h3 in [false, true] {
        let barrier = Arc::new(tokio::sync::Barrier::new(33));
        let mut clients = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let relay = relay.clone();
            let barrier = barrier.clone();
            clients.spawn(async move {
                let request = || {
                    Request::builder()
                        .method(Method::CONNECT)
                        .uri(echo.to_string())
                        .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
                        .body(())
                        .unwrap()
                };
                let payload = Bytes::from(pattern(64 * 1024));
                if use_h3 {
                    let (mut sender, _conn, _driver) = raw_h3(&relay, true).await;
                    let mut streams = Vec::new();
                    for _ in 0..4 {
                        let mut stream = sender.send_request(request()).await.unwrap();
                        assert_eq!(stream.recv_response().await.unwrap().status(), StatusCode::OK);
                        stream.send_data(payload.clone()).await.unwrap();
                        let mut received = Vec::new();
                        while received.len() < payload.len() {
                            let mut chunk = stream.recv_data().await.unwrap().unwrap();
                            received.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
                        }
                        assert_eq!(received.as_slice(), payload.as_ref());
                        streams.push(stream);
                    }
                    barrier.wait().await;
                    for mut stream in streams {
                        stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
                    }
                } else {
                    let (mut sender, _driver) = raw_h2(&relay).await;
                    let mut streams = Vec::new();
                    for _ in 0..4 {
                        let (response, mut send) = sender.send_request(request(), false).unwrap();
                        let response = response.await.unwrap();
                        assert_eq!(response.status(), StatusCode::OK);
                        write_h2(&mut send, payload.clone()).await;
                        let mut recv = response.into_body();
                        let mut received = Vec::new();
                        while received.len() < payload.len() {
                            let chunk = recv.data().await.unwrap().unwrap();
                            recv.flow_control().release_capacity(chunk.len()).unwrap();
                            received.extend_from_slice(&chunk);
                        }
                        assert_eq!(received.as_slice(), payload.as_ref());
                        streams.push((send, recv));
                    }
                    barrier.wait().await;
                    for (mut send, _) in streams {
                        send.send_reset(h2::Reason::CANCEL);
                    }
                }
            });
        }
        within("128 concurrent tunnels", barrier.wait()).await;
        while let Some(result) = within("client completion", clients.join_next()).await {
            result.unwrap();
        }
        within("all connection and tunnel slots refunded", async {
            while relay.relay.active_tunnels() != 0 || relay.relay.open_connections() != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert_eq!(relay.relay.user_tunnels(ALICE.0), 0);
    }
    echo_task.abort();
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
    UserEntry::with_password(name, &auth::hash_password(password).unwrap())
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
        Self::start_with(relay_toml, vec![user(ALICE.0, ALICE.1)]).await
    }

    async fn start_with(relay_toml: &str, users: Vec<UserEntry>) -> Self {
        init_logging();
        let env = Env::new();
        let (udp, tcp) = bind_pair().await;
        let addr = udp.local_addr().unwrap();
        let config = config(&env, addr, relay_toml, &users);
        let certs = CertStore::open(&config.tls.cert, &config.tls.key).unwrap();
        let relay = Relay::new(&config).unwrap();
        let client_certificates = config.tls.client_certificates;
        let endpoint = server::quic_endpoint(certs.clone(), udp, client_certificates).unwrap();
        let tasks = vec![
            tokio::spawn(relay.clone().serve_quic(endpoint)),
            tokio::spawn(relay.clone().serve_tcp(tcp, server::tcp_tls_config(certs, client_certificates).unwrap())),
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
            client_cert: None,
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
    // The test servers listen on this machine's loopback address, which the
    // relay blocks as one of its own unless told otherwise.
    let own = if relay_toml.contains("block_own_addresses") { "" } else { "block_own_addresses = false\n" };
    let client_certificates = users.iter().any(|u| u.certificate_sha256.is_some());
    let mut text = format!(
        "listen = \"{addr}\"\n[tls]\ncert = {:?}\nkey = {:?}\nclient_certificates = {client_certificates}\n\
         [web]\nroot = {:?}\n[relay]\n{own}{relay_toml}\n",
        env.path("fullchain.pem"),
        env.path("privkey.pem"),
        env.path("site"),
    );
    for u in users {
        text.push_str(&format!("[[user]]\nname = \"{}\"\n", u.name));
        if let Some(h) = &u.password_hash {
            text.push_str(&format!("password_hash = \"{h}\"\n"));
        }
        if let Some(c) = &u.certificate_sha256 {
            text.push_str(&format!("certificate_sha256 = \"{c}\"\n"));
        }
        if let Some(e) = &u.expires {
            text.push_str(&format!("expires = \"{e}\"\n"));
        }
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
    let published: Vec<_> = std::fs::read_dir(env.path("site").join(network_relay::web::PUBLISH_DIR))
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
        assert!(e.contains("502") && e.contains("destination_ip_prohibited"), "{}: {e}", o.name);
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
                | "network-relay; error=dns_error; details=\"no addresses\""
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
async fn http2_uploads_to_stalled_destinations_leave_room_for_other_tunnels() {
    let relay = TestRelay::start("").await;
    let (echo, _e) = echo_server().await;
    // A destination that accepts connections and never reads from them.
    let stalled = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = stalled.local_addr().unwrap();
    let _stalled = Driver(tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((tcp, _)) = stalled.accept().await {
            held.push(tcp);
        }
    }));
    let (mut sender, _driver) = raw_h2(&relay).await;
    // Each upload fills every buffer before its destination and then its
    // whole stream window, which the relay releases only as the destination
    // accepts data. Several such uploads on one connection must not leave the
    // other tunnels without connection credit (RFC 9113 section 5.2).
    let mut uploads = Vec::new();
    for _ in 0..3 {
        sender = within("HTTP/2 stream capacity", sender.ready()).await.unwrap();
        let (response, mut send) = sender.send_request(connect_request(target), false).unwrap();
        let response = within("CONNECT response", response).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        uploads.push((
            Driver(tokio::spawn(async move {
                let mut bytes = Bytes::from(pattern(16 << 20));
                while !bytes.is_empty() {
                    send.reserve_capacity(bytes.len().min(64 * 1024));
                    let Some(Ok(capacity)) = std::future::poll_fn(|cx| send.poll_capacity(cx)).await else {
                        return;
                    };
                    let n = capacity.min(bytes.len());
                    if send.send_data(bytes.split_to(n), false).is_err() {
                        return;
                    }
                }
            })),
            response,
        ));
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    sender = within("HTTP/2 stream capacity", sender.ready()).await.unwrap();
    let (response, mut send) = sender.send_request(connect_request(echo), false).unwrap();
    let response = within("CONNECT response", response).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut recv = response.into_body();
    let expected = pattern(256 * 1024);
    write_h2(&mut send, Bytes::from(expected.clone())).await;
    let mut received = Vec::new();
    within("echo beside stalled uploads", async {
        while received.len() < expected.len() {
            let data = recv.data().await.unwrap().unwrap();
            recv.flow_control().release_capacity(data.len()).unwrap();
            received.extend_from_slice(&data);
        }
    })
    .await;
    assert!(received == expected, "echoed data corrupted");
    drop(uploads);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http3_uploads_to_stalled_destinations_leave_room_for_other_tunnels() {
    let relay = TestRelay::start("").await;
    let (echo, _e) = echo_server().await;
    let stalled = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = stalled.local_addr().unwrap();
    let _stalled = Driver(tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((tcp, _)) = stalled.accept().await {
            held.push(tcp);
        }
    }));
    let (mut sender, conn, _driver) = raw_h3(&relay, false).await;
    // As over HTTP/2, uploads to destinations that do not read keep their
    // stream credit; they must not use up the connection's (RFC 9000
    // section 4.1).
    let mut uploads = Vec::new();
    for _ in 0..3 {
        let mut stream = within("CONNECT request", sender.send_request(connect_request(target))).await.unwrap();
        assert_eq!(within("CONNECT response", stream.recv_response()).await.unwrap().status(), StatusCode::OK);
        let (mut send, recv) = stream.split();
        uploads.push((
            Driver(tokio::spawn(async move {
                let chunk = Bytes::from(pattern(60_000));
                while send.send_data(chunk.clone()).await.is_ok() {}
            })),
            recv,
        ));
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let mut stream = within("CONNECT request", sender.send_request(connect_request(echo))).await.unwrap();
    assert_eq!(within("CONNECT response", stream.recv_response()).await.unwrap().status(), StatusCode::OK);
    let expected = pattern(256 * 1024);
    let mut received = Vec::new();
    within("echo beside stalled uploads", async {
        for chunk in expected.chunks(60_000) {
            stream.send_data(Bytes::copy_from_slice(chunk)).await.unwrap();
        }
        while received.len() < expected.len() {
            let mut data = stream.recv_data().await.unwrap().unwrap();
            received.extend_from_slice(&data.copy_to_bytes(data.remaining()));
        }
    })
    .await;
    assert!(received == expected, "echoed data corrupted");
    drop(uploads);
    conn.close(0u32.into(), b"");
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
    bodyless_request_finished(stream.finish().await);
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

/// Cancelling a UDP flow (here: the user is removed) is reported as a
/// cancellation, not as a malformed message.
#[tokio::test]
async fn revoked_udp_flows_are_cancelled_with_cancel_codes() {
    let relay = TestRelay::start("").await;
    let (udp, _u) = udp_echo().await;
    let (mut h3_sender, _conn, _h3_driver) = raw_h3(&relay, true).await;
    let req = udp_request(udp).extension(h3::ext::Protocol::CONNECT_UDP).body(()).unwrap();
    let mut h3_stream = h3_sender.send_request(req).await.unwrap();
    assert_eq!(h3_stream.recv_response().await.unwrap().status(), StatusCode::OK);
    let (mut h2_sender, _h2_driver) = raw_h2(&relay).await;
    let req = udp_request(udp).extension(h2::ext::Protocol::from_static("connect-udp")).body(()).unwrap();
    let (response, _send) = h2_sender.send_request(req, false).unwrap();
    let response = within("CONNECT-UDP response", response).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut h2_recv = response.into_body();
    assert_eq!(relay.relay.active_tunnels(), 2);

    relay.reload("", &[]);
    let error = match within("H3_REQUEST_CANCELLED", h3_stream.recv_data()).await {
        Err(error) => error,
        Ok(_) => panic!("revocation did not reset the HTTP/3 flow"),
    };
    assert!(
        matches!(error, h3::error::StreamError::RemoteTerminate { code } if code == h3::error::Code::H3_REQUEST_CANCELLED),
        "{error:?}"
    );
    let error = within("CANCEL", h2_recv.data()).await.expect("reset became EOF").unwrap_err();
    assert_eq!(error.reason(), Some(h2::Reason::CANCEL));
    within("released tunnel slots", async {
        while relay.relay.active_tunnels() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
}

/// RFC 9297 §2.1: a datagram that arrives after the request's receive side
/// is closed is dropped silently; it does not abort the response direction.
#[tokio::test]
async fn http3_datagram_after_request_fin_is_dropped_silently() {
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
    let (mut tcp, _) = within("target connection", listener.accept()).await.unwrap();
    stream.finish().await.unwrap();
    assert_eq!(within("target half-close", tcp.read(&mut [0])).await.unwrap(), 0);
    let mut late = bytes::BytesMut::new();
    network_relay::proto::varint::encode(stream.id().into_inner() / 4, &mut late);
    late.extend_from_slice(b"\0late");
    conn.send_datagram(late.freeze()).unwrap();
    tcp.write_all(b"still open").await.unwrap();
    let mut data = within("response data", stream.recv_data()).await.unwrap().expect("response direction ended");
    assert_eq!(data.copy_to_bytes(data.remaining()), "still open");
}

/// Connection and Upgrade are token lists (RFC 9110 §7.6.1, §7.8).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http1_upgrade_tokens_are_matched_in_lists() {
    let relay = TestRelay::start("").await;
    let (dns, _d) = udp_echo().await;
    let opts = relay.options(ALICE, dns, dns);
    let request = |upgrade: &'static str| {
        Request::builder()
            .method(Method::GET)
            .uri(format!("/.well-known/masque/udp/127.0.0.1/{}/", dns.port()))
            .header("host", "relay.test")
            .header("connection", "keep-alive, Upgrade")
            .header("upgrade", upgrade)
            .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
            .body(Empty::<Bytes>::new())
            .unwrap()
    };
    let (mut sender, _conn) = check::h1_sender(&opts, &opts.addresses).await.unwrap();
    let resp = within("Upgrade", sender.send_request(request("websocket, connect-udp"))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
    let (mut sender, _conn) = check::h1_sender(&opts, &opts.addresses).await.unwrap();
    let resp = within("other upgrade", sender.send_request(request("websocket"))).await.unwrap();
    // Answered as the plain GET it also is: a missing well-known file is 404.
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "an unknown upgrade token is not a proxy request");
    assert!(!resp.headers().contains_key("upgrade"));
    assert!(!resp.headers().contains_key("capsule-protocol"));
}

/// RFC 9112 §3.2: an HTTP/1.1 request with no Host field, or more than one,
/// gets 400 and no tunnel, whatever it asks for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http1_requests_need_exactly_one_host() {
    let relay = TestRelay::start("").await;
    let (echo, _e) = echo_server().await;
    let (dns, _d) = udp_echo().await;
    let ca = network_relay::tls::client_config(Some(&relay.env.path("ca.pem")), &[b"http/1.1"]).unwrap();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(ca));
    let auth = auth::basic_authorization(ALICE.0, ALICE.1);
    let udp_path = format!("/.well-known/masque/udp/127.0.0.1/{}/", dns.port());
    let cases = [
        format!("CONNECT {echo} HTTP/1.1\r\nProxy-Authorization: {auth}\r\n\r\n"),
        format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\nHost: {echo}\r\nProxy-Authorization: {auth}\r\n\r\n"),
        format!(
            "GET {udp_path} HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nAuthorization: {auth}\r\n\r\n"
        ),
        format!(
            "GET {udp_path} HTTP/1.1\r\nHost: relay.test\r\nHost: other.test\r\nConnection: Upgrade\r\n\
             Upgrade: connect-udp\r\nAuthorization: {auth}\r\n\r\n"
        ),
        "GET / HTTP/1.1\r\n\r\n".to_string(),
    ];
    for request in cases {
        let tcp = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
        let mut tls = connector.connect("relay.test".try_into().unwrap(), tcp).await.unwrap();
        tls.write_all(request.as_bytes()).await.unwrap();
        let mut head = Vec::new();
        within("response", async {
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n") && tls.read(&mut byte).await.unwrap() == 1 {
                head.push(byte[0]);
            }
        })
        .await;
        assert_eq!(String::from_utf8_lossy(&head).trim(), "HTTP/1.1 400 Bad Request", "{request:?}");
    }
    assert_eq!(relay.relay.active_tunnels(), 0);
}

// ------------------------------------------------- limits and credentials

/// A self-signed client certificate in `env`, and its fingerprint.
fn client_identity(env: &Env, name: &str) -> ((PathBuf, PathBuf), String) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec![format!("{name}.device")]).unwrap().self_signed(&key).unwrap();
    let (cert_path, key_path) = (env.path(&format!("{name}-cert.pem")), env.path(&format!("{name}-key.pem")));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    ((cert_path, key_path), auth::fingerprint_hex(&auth::fingerprint(cert.der())))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_certificates_authenticate_without_a_password() {
    let identity_env = Env::new();
    let (paths, fp) = client_identity(&identity_env, "ipad");
    let (other_paths, _) = client_identity(&identity_env, "stranger");
    let ipad = UserEntry { name: "ipad".into(), password_hash: None, certificate_sha256: Some(fp), expires: None };
    let relay = TestRelay::start_with("", vec![user(ALICE.0, ALICE.1), ipad]).await;
    let (web, _w) = http_server().await;
    let (dns, _d) = udp_echo().await;
    let mut opts = relay.options(("ipad", ""), web, dns);
    opts.client_cert = Some(paths);
    for o in within("checks", check::run(&opts)).await {
        if o.name.starts_with("hidden") {
            // The certificate authenticates even without a password.
            assert!(o.result.is_err(), "{}", o.name);
        } else {
            o.result.unwrap_or_else(|e| panic!("{}: {e:#}", o.name));
        }
    }
    // Password users on a relay that asks for certificates still work.
    let outcomes = within("checks", check::run(&relay.options(ALICE, web, dns))).await;
    assert!(outcomes.iter().all(|o| o.result.is_ok()), "{outcomes:?}");
    // An unknown certificate is just a visitor.
    let mut stranger = relay.options(("ipad", ""), web, dns);
    stranger.client_cert = Some(other_paths);
    let outcomes = within("checks", check::run(&stranger)).await;
    let e = format!("{:#}", outcomes[0].result.as_ref().unwrap_err());
    assert!(e.contains("plain website"), "{e}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_user_tunnel_limit_is_enforced() {
    let bob = ("bob", "bob-password-456");
    let relay = TestRelay::start_with(
        "blocked_destinations = []\nmax_tunnels_per_user = 1",
        vec![user(ALICE.0, ALICE.1), user(bob.0, bob.1)],
    )
    .await;
    let (echo, _e) = echo_server().await;
    let opts = relay.options(ALICE, echo, echo);
    let mut h3 = H3::connect(&opts, &opts.addresses).await.unwrap();
    let connect = |(name, password): (&str, &str)| {
        Request::builder()
            .method(Method::CONNECT)
            .uri(echo.to_string())
            .header("authorization", auth::basic_authorization(name, password))
            .body(())
            .unwrap()
    };
    let mut first = h3.request(connect(ALICE)).await.unwrap();
    assert_eq!(first.recv_response().await.unwrap().status(), StatusCode::OK);
    assert_eq!(relay.relay.user_tunnels(ALICE.0), 1);
    let mut second = h3.request(connect(ALICE)).await.unwrap();
    let resp = second.recv_response().await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.headers()["proxy-status"], "network-relay; error=connection_limit_reached");
    let mut other = h3.request(connect(bob)).await.unwrap();
    assert_eq!(other.recv_response().await.unwrap().status(), StatusCode::OK, "another user is unaffected");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connections_per_address_are_limited() {
    let relay = TestRelay::start("max_connections_per_ip = 2").await;
    let tls =
        std::sync::Arc::new(network_relay::tls::client_config(Some(&relay.env.path("ca.pem")), &[b"h2"]).unwrap());
    let connect = || async {
        let tcp = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
        tokio_rustls::TlsConnector::from(tls.clone()).connect("relay.test".try_into().unwrap(), tcp).await
    };
    let first = connect().await.unwrap();
    let second = connect().await.unwrap();
    assert!(within("refused handshake", connect()).await.is_err(), "a third connection is closed at once");
    within("count", async {
        while relay.relay.open_connections() != 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    drop((first, second));
    within("slots to be released", async {
        while relay.relay.open_connections() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(connect().await.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_user_byte_budget_slows_tcp_tunnels() {
    // 128 KiB/s with a 128 KiB burst; 192 KiB echoed is 384 KiB of traffic.
    let relay = TestRelay::start("blocked_destinations = []\nmax_bytes_per_second_per_user = 131072").await;
    let (echo, _e) = echo_server().await;
    let opts = relay.options(ALICE, echo, echo);
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
    let data = pattern(192 * 1024);
    let expected = data.clone();
    let started = std::time::Instant::now();
    let writer = tokio::spawn(async move {
        for chunk in data.chunks(16 * 1024) {
            send.send_data(Bytes::copy_from_slice(chunk)).await.unwrap();
        }
        send.finish().await.unwrap();
    });
    let mut got = Vec::new();
    within("echoed data", async {
        while let Some(mut b) = recv.recv_data().await.unwrap() {
            got.extend_from_slice(&b.copy_to_bytes(b.remaining()));
        }
    })
    .await;
    writer.await.unwrap();
    let elapsed = started.elapsed();
    assert!(got == expected, "data corrupted");
    assert!(elapsed >= Duration::from_millis(1500), "budget not applied: {elapsed:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_hosts_own_addresses_are_blocked_by_default() {
    // Nothing in the list: only the "own addresses" rule can refuse loopback.
    let relay = TestRelay::start("blocked_destinations = []\nblock_own_addresses = true").await;
    let (web, _w) = http_server().await;
    let (dns, _d) = udp_echo().await;
    let outcomes = within("checks", check::run(&relay.options(ALICE, web, dns))).await;
    for o in outcomes.iter().filter(|o| !o.name.starts_with("hidden")) {
        let e = format!("{:#}", o.result.as_ref().unwrap_err());
        assert!(e.contains("502") && e.contains("destination_ip_prohibited"), "{}: {e}", o.name);
    }
}

/// Relayed QUIC packets are at least 1200 bytes, more than fits in a
/// DATAGRAM frame of a 1200-byte packet: the connection starts small and
/// path MTU discovery makes room within moments.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_path_mtu_grows_to_carry_full_size_relayed_packets() {
    let relay = TestRelay::start("").await;
    let (echo, _e) = udp_echo().await;
    let opts = relay.options(ALICE, echo, echo);
    let mut h3 = H3::connect(&opts, &opts.addresses).await.unwrap();
    within("path MTU discovery", async {
        while h3.connection().max_datagram_size().unwrap_or(0) < 1300 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
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
    assert_eq!(stream.recv_response().await.unwrap().status(), StatusCode::OK);
    let (mut tunnel, _filter) = h3.udp_tunnel(stream);
    let packet = pattern(1250);
    within("a 1250-byte echo", async {
        loop {
            assert_eq!(
                tunnel.send_datagram(datagram::udp_payload(&packet)).unwrap(),
                network_relay::tunnel::Sent::Sent
            );
            let wait = tokio::time::sleep(Duration::from_millis(200));
            tokio::select! {
                ev = tunnel.next_event() => if let Event::Datagram(p) = ev.unwrap() {
                    assert_eq!(&p[1..], &packet[..]);
                    return;
                },
                _ = wait => {}
            }
        }
    })
    .await;
}

// ------------------------------------------------- request validation

/// A QPACK field section with literal names and values only (RFC 9204
/// §4.5.6), which needs no table: enough to send requests the h3 client
/// would refuse to build.
fn qpack_literal(fields: &[(&str, &str)]) -> Vec<u8> {
    fn prefixed(out: &mut Vec<u8>, flags: u8, bits: u8, mut v: usize) {
        let max = (1usize << bits) - 1;
        if v < max {
            out.push(flags | v as u8);
            return;
        }
        out.push(flags | max as u8);
        v -= max;
        while v >= 128 {
            out.push((v % 128) as u8 | 0x80);
            v /= 128;
        }
        out.push(v as u8);
    }
    let mut out = vec![0, 0];
    for (name, value) in fields {
        prefixed(&mut out, 0x20, 3, name.len());
        out.extend_from_slice(name.as_bytes());
        prefixed(&mut out, 0, 7, value.len());
        out.extend_from_slice(value.as_bytes());
    }
    out
}

/// Sends `fields` as a request on a new stream of `conn`, and returns what
/// came back: the type of the first frame, or the reset code.
async fn raw_h3_request(conn: &quinn::Connection, fields: &[(&str, &str)]) -> Result<u64, u64> {
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let block = qpack_literal(fields);
    let mut frame = bytes::BytesMut::new();
    network_relay::proto::varint::encode(1, &mut frame);
    network_relay::proto::varint::encode(block.len() as u64, &mut frame);
    frame.extend_from_slice(&block);
    send.write_all(&frame).await.unwrap();
    let _ = send.finish();
    within("response or reset", async {
        let mut first = [0u8; 1];
        match recv.read_exact(&mut first).await {
            Ok(()) => Ok(u64::from(first[0])),
            Err(quinn::ReadExactError::ReadError(quinn::ReadError::Reset(code))) => Err(code.into_inner()),
            Err(e) => panic!("{e}"),
        }
    })
    .await
}

#[tokio::test]
async fn malformed_http3_requests_are_message_errors() {
    let relay = TestRelay::start("").await;
    let (_sender, conn, _driver) = raw_h3(&relay, true).await;
    let auth = auth::basic_authorization(ALICE.0, ALICE.1);
    let message_error = h3::error::Code::H3_MESSAGE_ERROR.value();
    let udp_path = "/.well-known/masque/udp/127.0.0.1/53/";
    let cases: &[&[(&str, &str)]] = &[
        // RFC 9114 §4.4: a classic CONNECT has no :scheme or :path, and an
        // :authority.
        &[(":method", "CONNECT"), (":scheme", "https"), (":authority", "127.0.0.1:80"), ("authorization", &auth)],
        &[(":method", "CONNECT"), (":path", "/"), (":authority", "127.0.0.1:80"), ("authorization", &auth)],
        &[(":method", "CONNECT"), ("host", "127.0.0.1:80"), ("authorization", &auth)],
        // RFC 8441 §4 (RFC 9220): extended CONNECT carries :scheme and :path.
        &[(":method", "CONNECT"), (":protocol", "connect-udp"), (":authority", "relay.test"), (":path", udp_path)],
        &[(":method", "CONNECT"), (":protocol", "connect-udp"), (":authority", "relay.test"), (":scheme", "https")],
        // RFC 9114 §4.3.1: exactly one :method, :scheme and :path.
        &[(":method", "GET"), (":authority", "relay.test"), (":path", "/")],
        &[(":method", "GET"), (":scheme", "https"), (":authority", "relay.test")],
        &[(":method", "GET"), (":method", "GET"), (":scheme", "https"), (":authority", "relay.test"), (":path", "/")],
        // RFC 9114 §4.3: response pseudo-headers in a request.
        &[(":method", "GET"), (":scheme", "https"), (":authority", "relay.test"), (":path", "/"), (":status", "200")],
        // :protocol is only defined for CONNECT.
        &[(":method", "GET"), (":protocol", "connect-udp"), (":scheme", "https"), (":authority", "a"), (":path", "/")],
        // RFC 9114 §4.2: connection-specific fields.
        &[
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "relay.test"),
            (":path", "/"),
            ("connection", "close"),
        ],
        &[(":method", "GET"), (":scheme", "https"), (":authority", "relay.test"), (":path", "/"), ("te", "gzip")],
        &[
            (":method", "CONNECT"),
            (":protocol", "connect-udp"),
            (":scheme", "https"),
            (":authority", "relay.test"),
            (":path", udp_path),
            ("upgrade", "connect-udp"),
            ("authorization", &auth),
        ],
    ];
    for fields in cases {
        assert_eq!(raw_h3_request(&conn, fields).await, Err(message_error), "{fields:?}");
    }
    // A well-formed request on the same connection is answered: a HEADERS
    // frame (type 1) comes back.
    let ok = [(":method", "GET"), (":scheme", "https"), (":authority", "relay.test"), (":path", "/")];
    assert_eq!(raw_h3_request(&conn, &ok).await, Ok(1));
    // An extended CONNECT with a protocol h3 does not know is well-formed:
    // without credentials it gets the website, not a reset.
    let tcp = [
        (":method", "CONNECT"),
        (":protocol", "connect-tcp"),
        (":scheme", "https"),
        (":authority", "relay.test"),
        (":path", "/"),
    ];
    assert_eq!(raw_h3_request(&conn, &tcp).await, Ok(1));
    assert_eq!(relay.relay.active_tunnels(), 0);
}

#[tokio::test]
async fn unsupported_and_malformed_proxy_requests_get_errors_once_authenticated() {
    let relay = TestRelay::start("").await;
    let (udp, _u) = udp_echo().await;
    let auth_header = auth::basic_authorization(ALICE.0, ALICE.1);

    // HTTP/3: a protocol this relay does not implement gets 501; a UDP
    // proxying request whose scheme is not https gets 400 (RFC 9298 §3.4).
    let (mut sender, _conn, _driver) = raw_h3(&relay, true).await;
    let websocket = Request::builder()
        .method(Method::CONNECT)
        .uri("https://relay.test/chat")
        .header("authorization", &auth_header)
        .extension(h3::ext::Protocol::WEBSOCKET)
        .body(())
        .unwrap();
    let mut stream = sender.send_request(websocket).await.unwrap();
    let response = within("501", stream.recv_response()).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert!(response.headers()["proxy-status"].to_str().unwrap().contains("unsupported"));
    let http_scheme = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("http://relay.test/.well-known/masque/udp/127.0.0.1/{}/", udp.port()))
        .header("authorization", &auth_header)
        .header("capsule-protocol", "?1")
        .extension(h3::ext::Protocol::CONNECT_UDP)
        .body(())
        .unwrap();
    let mut stream = sender.send_request(http_scheme).await.unwrap();
    assert_eq!(within("400", stream.recv_response()).await.unwrap().status(), StatusCode::BAD_REQUEST);
    // Without credentials, the same requests get the website.
    let anonymous = Request::builder()
        .method(Method::CONNECT)
        .uri("https://relay.test/chat")
        .extension(h3::ext::Protocol::WEBSOCKET)
        .body(())
        .unwrap();
    let mut stream = sender.send_request(anonymous).await.unwrap();
    assert_eq!(within("website", stream.recv_response()).await.unwrap().status(), StatusCode::NOT_FOUND);

    // HTTP/2: connect-tcp (draft-ietf-httpbis-connect-tcp) is not implemented.
    let (mut h2, _driver2) = raw_h2(&relay).await;
    for (credentials, expected) in [(true, StatusCode::NOT_IMPLEMENTED), (false, StatusCode::NOT_FOUND)] {
        let mut req = Request::builder().method(Method::CONNECT).uri("https://relay.test/");
        if credentials {
            req = req.header("authorization", &auth_header);
        }
        let req = req.extension(h2::ext::Protocol::from("connect-tcp")).body(()).unwrap();
        let (response, _send) = h2.send_request(req, true).unwrap();
        assert_eq!(within("HTTP/2 answer", response).await.unwrap().status(), expected, "credentials: {credentials}");
    }
    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("http://relay.test/.well-known/masque/udp/127.0.0.1/{}/", udp.port()))
        .header("authorization", &auth_header)
        .header("capsule-protocol", "?1")
        .extension(h2::ext::Protocol::from(network_relay::proto::CONNECT_UDP_PROTOCOL))
        .body(())
        .unwrap();
    let (response, _send) = h2.send_request(req, false).unwrap();
    assert_eq!(within("HTTP/2 400", response).await.unwrap().status(), StatusCode::BAD_REQUEST);

    // HTTP/1.1 (RFC 9298 §3.2): connect-udp without "Connection: Upgrade",
    // or with a method other than GET, is malformed: 400, not the website.
    // HTTP/1.0 must ignore Upgrade (RFC 9110 §7.8): that is a plain GET.
    let ca = network_relay::tls::client_config(Some(&relay.env.path("ca.pem")), &[b"http/1.1"]).unwrap();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(ca));
    let path = format!("/.well-known/masque/udp/127.0.0.1/{}/", udp.port());
    let cases = [
        (format!("GET {path} HTTP/1.1\r\nHost: relay.test\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\nAuthorization: {auth_header}\r\n\r\n"), "400"),
        (format!("POST {path} HTTP/1.1\r\nHost: relay.test\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\nContent-Length: 0\r\nAuthorization: {auth_header}\r\n\r\n"), "400"),
        (format!("GET {path} HTTP/1.0\r\nHost: relay.test\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\nAuthorization: {auth_header}\r\n\r\n"), "404"),
        (format!("GET {path} HTTP/1.1\r\nHost: relay.test\r\nUpgrade: connect-udp\r\n\r\n"), "404"),
    ];
    for (request, status) in cases {
        let tcp = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
        let mut tls = connector.connect("relay.test".try_into().unwrap(), tcp).await.unwrap();
        tls.write_all(request.as_bytes()).await.unwrap();
        let mut head = Vec::new();
        within("response", async {
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n") && tls.read(&mut byte).await.unwrap() == 1 {
                head.push(byte[0]);
            }
        })
        .await;
        let line = String::from_utf8_lossy(&head);
        assert_eq!(line.split(' ').nth(1), Some(status), "{request:?}: {line}");
    }
    assert_eq!(relay.relay.active_tunnels(), 0);
}

/// RFC 9297 §2.1: a datagram on a request without datagram semantics, after
/// the request's receive side has closed, is dropped, not a stream error.
#[tokio::test]
async fn http3_datagram_on_finished_website_request_is_dropped() {
    let relay = TestRelay::start("").await;
    let (mut sender, conn, _driver) = raw_h3(&relay, true).await;
    for _ in 0..20 {
        let req = Request::builder().method(Method::GET).uri("https://relay.test/").body(()).unwrap();
        let mut stream = sender.send_request(req).await.unwrap();
        bodyless_request_finished(stream.finish().await);
        let mut datagram = bytes::BytesMut::new();
        network_relay::proto::varint::encode(stream.id().into_inner() / 4, &mut datagram);
        datagram.extend_from_slice(b"\0stray");
        conn.send_datagram(datagram.freeze()).unwrap();
        let response = within("website", stream.recv_response()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = Vec::new();
        while let Some(mut chunk) = within("body", stream.recv_data()).await.unwrap() {
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        assert_eq!(body, INDEX);
    }
}

/// RFC 9298 §3.1: when the OS reports the UDP socket unusable, as it does
/// after ICMP Destination Unreachable (here: port unreachable on loopback),
/// the request stream MUST be closed.
#[tokio::test]
async fn udp_flows_close_when_the_destination_is_unreachable() {
    let relay = TestRelay::start("").await;
    let closed = {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap()
    };

    let (mut sender, conn, _driver) = raw_h3(&relay, true).await;
    let req = udp_request(closed).extension(h3::ext::Protocol::CONNECT_UDP).body(()).unwrap();
    let mut stream = sender.send_request(req).await.unwrap();
    assert_eq!(stream.recv_response().await.unwrap().status(), StatusCode::OK);
    let error = within("H3_CONNECT_ERROR", async {
        loop {
            let mut packet = bytes::BytesMut::new();
            network_relay::proto::varint::encode(stream.id().into_inner() / 4, &mut packet);
            packet.extend_from_slice(&datagram::udp_payload(b"anyone there?"));
            let _ = conn.send_datagram(packet.freeze());
            tokio::select! {
                result = stream.recv_data() => match result {
                    Err(e) => return e,
                    Ok(_) => panic!("the flow ended without an error"),
                },
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
        }
    })
    .await;
    assert!(
        matches!(error, h3::error::StreamError::RemoteTerminate { code } if code == h3::error::Code::H3_CONNECT_ERROR),
        "{error:?}"
    );

    let (mut h2, _driver2) = raw_h2(&relay).await;
    let req = udp_request(closed).extension(h2::ext::Protocol::from_static("connect-udp")).body(()).unwrap();
    let (response, mut send) = h2.send_request(req, false).unwrap();
    let response = within("CONNECT-UDP response", response).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut recv = response.into_body();
    let reason = within("CONNECT_ERROR", async {
        loop {
            let mut wire = bytes::BytesMut::new();
            capsule::encode(0, &datagram::udp_payload(b"anyone there?"), &mut wire);
            write_h2(&mut send, wire.freeze()).await;
            tokio::select! {
                data = recv.data() => match data {
                    Some(Err(e)) => return e.reason(),
                    other => panic!("{other:?}"),
                },
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
        }
    })
    .await;
    assert_eq!(reason, Some(h2::Reason::CONNECT_ERROR));
    within("tunnel slots released", async {
        while relay.relay.active_tunnels() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
}

/// On shutdown every connection gets GOAWAY: open tunnels keep working,
/// new requests are refused (RFC 9113 §6.8, RFC 9114 §5.2), and once the
/// tunnels end the connections close and the drain completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_sends_goaway_and_drains_open_tunnels() {
    let relay = TestRelay::start("").await;
    let (echo, _e) = echo_server().await;
    let connect = || {
        Request::builder()
            .method(Method::CONNECT)
            .uri(echo.to_string())
            .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
            .body(())
            .unwrap()
    };
    let (mut h3, conn, _driver) = raw_h3(&relay, true).await;
    let mut h3_tunnel = h3.send_request(connect()).await.unwrap();
    assert_eq!(h3_tunnel.recv_response().await.unwrap().status(), StatusCode::OK);
    let (mut h2, _driver2) = raw_h2(&relay).await;
    let (response, mut h2_send) = h2.send_request(connect(), false).unwrap();
    let response = within("HTTP/2 CONNECT", response).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut h2_recv = response.into_body();

    relay.relay.begin_shutdown();
    assert!(!relay.relay.drain(Duration::from_millis(300)).await, "open tunnels hold their connections");

    // Both tunnels still carry data.
    h3_tunnel.send_data(Bytes::from_static(b"h3")).await.unwrap();
    let mut got = within("HTTP/3 echo", h3_tunnel.recv_data()).await.unwrap().unwrap();
    assert_eq!(got.copy_to_bytes(got.remaining()), "h3");
    write_h2(&mut h2_send, Bytes::from_static(b"h2")).await;
    let got = within("HTTP/2 echo", h2_recv.data()).await.unwrap().unwrap();
    assert_eq!(got, "h2");

    // New requests are refused: the clients have had GOAWAY, and a request
    // sent anyway is rejected with H3_REQUEST_REJECTED.
    match h3.send_request(connect()).await {
        Err(e) => assert!(matches!(e, h3::error::StreamError::RemoteClosing), "{e:?}"),
        Ok(mut late) => {
            let error = within("H3_REQUEST_REJECTED", late.recv_response()).await.unwrap_err();
            assert!(
                matches!(error, h3::error::StreamError::RemoteTerminate { code }
                    if code == h3::error::Code::H3_REQUEST_REJECTED),
                "{error:?}"
            );
        }
    }
    // A raw stream bypasses the client's own GOAWAY check: the server
    // rejects it (RFC 9114 §5.2).
    let rejected = raw_h3_request(
        &conn,
        &[(":method", "GET"), (":scheme", "https"), (":authority", "relay.test"), (":path", "/")],
    )
    .await;
    assert_eq!(rejected, Err(h3::error::Code::H3_REQUEST_REJECTED.value()));
    let refused = within("HTTP/2 after GOAWAY", async {
        match h2.clone().ready().await {
            Err(_) => true,
            Ok(mut ready) => match ready.send_request(connect(), true) {
                Err(_) => true,
                Ok((response, _)) => response.await.is_err(),
            },
        }
    })
    .await;
    assert!(refused, "HTTP/2 accepted a request after GOAWAY");

    // Ending the tunnels lets the connections close.
    h3_tunnel.finish().await.unwrap();
    while within("HTTP/3 end", h3_tunnel.recv_data()).await.unwrap().is_some() {}
    h2_send.send_data(Bytes::new(), true).unwrap();
    while within("HTTP/2 end", h2_recv.data()).await.is_some() {}
    assert!(relay.relay.drain(WAIT).await, "connections closed once their tunnels ended");
    let closed = within("HTTP/3 close", conn.closed()).await;
    assert!(
        matches!(closed, quinn::ConnectionError::ApplicationClosed(ref c)
            if c.error_code.into_inner() == h3::error::Code::H3_NO_ERROR.value()),
        "{closed:?}"
    );
}

/// RFC 9298 §7: destination rules apply to open tunnels. A reload that
/// blocks some other address leaves them alone; one that blocks their
/// destination closes them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reload_closes_tunnels_to_newly_blocked_destinations() {
    let relay = TestRelay::start("").await;
    let (echo, _e) = echo_server().await;
    let (dns, _d) = udp_echo().await;
    let users = relay.users.clone();
    let (mut sender, conn, _driver) = raw_h3(&relay, true).await;
    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(echo.to_string())
        .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
        .body(())
        .unwrap();
    let mut tcp = sender.send_request(req).await.unwrap();
    assert_eq!(tcp.recv_response().await.unwrap().status(), StatusCode::OK);
    let mut udp = sender
        .send_request(udp_request(dns).extension(h3::ext::Protocol::CONNECT_UDP).body(()).unwrap())
        .await
        .unwrap();
    assert_eq!(udp.recv_response().await.unwrap().status(), StatusCode::OK);
    assert_eq!(relay.relay.active_tunnels(), 2);

    relay.reload("blocked_destinations = [\"127.0.0.2/32\"]", &users);
    tcp.send_data(Bytes::from_static(b"still")).await.unwrap();
    let mut b = within("echo after an unrelated reload", tcp.recv_data()).await.unwrap().unwrap();
    assert_eq!(b.copy_to_bytes(b.remaining()), "still");
    let mut packet = bytes::BytesMut::new();
    network_relay::proto::varint::encode(udp.id().into_inner() / 4, &mut packet);
    packet.extend_from_slice(&datagram::udp_payload(b"ok"));
    conn.send_datagram(packet.freeze()).unwrap();
    within("UDP echo after an unrelated reload", async {
        loop {
            let d = conn.read_datagram().await.unwrap();
            if d.ends_with(b"ok") {
                break;
            }
        }
    })
    .await;
    assert_eq!(relay.relay.active_tunnels(), 2);

    relay.reload("blocked_destinations = [\"127.0.0.0/8\"]", &users);
    let tcp_end = within("TCP tunnel to end", tcp.recv_data()).await;
    assert!(tcp_end.is_err(), "the TCP tunnel is reset: {:?}", tcp_end.map(|b| b.is_some()));
    let udp_end = within("UDP flow to end", udp.recv_data()).await;
    assert!(udp_end.is_err(), "the UDP flow is reset: {:?}", udp_end.map(|b| b.is_some()));
    within("the permits to be returned", async {
        while relay.relay.active_tunnels() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
}

/// The relay runs as its own user: a profile that root publishes is given
/// to the owner of the `.publish` directory, or the relay could not read it.
/// Needs root to own a directory as another user; skipped otherwise.
#[test]
fn published_profiles_belong_to_the_publish_directory_owner() {
    use std::os::unix::fs::MetadataExt;
    let env = Env::new();
    let site = env.path("site");
    let publish = site.join(network_relay::web::PUBLISH_DIR);
    std::fs::create_dir_all(&publish).unwrap();
    let (uid, gid) = (65_534, 65_534);
    if std::os::unix::fs::chown(&publish, Some(uid), Some(gid)).is_err() {
        return; // not root
    }
    let config = env.path("relay.toml");
    std::fs::write(
        &config,
        format!(
            "[tls]\ncert = {:?}\nkey = {:?}\n[web]\nroot = {:?}\n",
            env.path("fullchain.pem"),
            env.path("privkey.pem"),
            site
        ),
    )
    .unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_network-relay"))
        .args(["profile", "--host", "relay.test", "--user", ALICE.0, "--password", ALICE.1, "--publish", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let published: Vec<_> = std::fs::read_dir(&publish).unwrap().map(|e| e.unwrap().path()).collect();
    assert_eq!(published.len(), 1);
    let meta = std::fs::metadata(&published[0]).unwrap();
    assert_eq!((meta.uid(), meta.gid(), meta.mode() & 0o777), (uid, gid, 0o600));
}

/// The relay's HTTP/3 control stream preamble (stream type, SETTINGS): a
/// client granting exactly this much credit, and reading nothing, leaves no
/// room for GOAWAY.
const CONTROL_PREAMBLE: u32 = 31;

#[tokio::test]
async fn http3_goaway_without_control_stream_credit_still_closes_the_connection() {
    // RFC 9114 §5.2: GOAWAY goes on the control stream, which is flow
    // controlled. A client that never grants credit for it must not keep a
    // connection open after the server asked it to leave.
    let relay = TestRelay::start("").await;
    let tls = network_relay::tls::client_config(Some(&relay.env.path("ca.pem")), &[b"h3"]).unwrap();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut config = quinn::ClientConfig::new(std::sync::Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.stream_receive_window(CONTROL_PREAMBLE.into());
    transport.keep_alive_interval(Some(Duration::from_millis(200)));
    config.transport_config(std::sync::Arc::new(transport));
    let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let conn = endpoint.connect_with(config, relay.addr, "relay.test").unwrap().await.unwrap();
    // The server's SETTINGS fit, so its HTTP/3 setup completes.
    let mut control = within("control stream", conn.accept_uni()).await.unwrap();
    let mut preamble = vec![0; CONTROL_PREAMBLE as usize];
    within("SETTINGS", control.read_exact(&mut preamble)).await.unwrap();
    relay.relay.begin_shutdown();
    assert!(relay.relay.drain(WAIT).await, "a GOAWAY the client grants no credit for held the connection open");
    let closed = within("connection close", conn.closed()).await;
    assert!(
        matches!(closed, quinn::ConnectionError::ApplicationClosed(ref c)
            if c.error_code.into_inner() == h3::error::Code::H3_NO_ERROR.value()),
        "{closed:?}"
    );
}

#[tokio::test]
async fn http3_request_whose_headers_never_arrive_is_rejected() {
    // RFC 9114 §4.1.1: a request the server cancels without processing it
    // is rejected with H3_REQUEST_REJECTED in both directions, so the client
    // may retry it; a bare FIN would read as a truncated response.
    let relay = TestRelay::start("").await;
    let (_sender, conn, _driver) = raw_h3(&relay, true).await;
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    // A HEADERS frame announcing 16 bytes, of which none follow.
    send.write_all(&[0x01, 0x10]).await.unwrap();
    let rejected = h3::error::Code::H3_REQUEST_REJECTED.value();
    let mut buf = [0u8; 16];
    match within("server gives up on the headers", recv.read(&mut buf)).await {
        Err(quinn::ReadError::Reset(code)) => assert_eq!(code.into_inner(), rejected),
        other => panic!("expected a reset with H3_REQUEST_REJECTED, got {other:?}"),
    }
    let stopped = within("STOP_SENDING", send.stopped()).await.unwrap();
    assert_eq!(stopped.map(|code| code.into_inner()), Some(rejected));
    assert_eq!(relay.relay.active_tunnels(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http3_unwritten_request_stream_is_left_open() {
    // Apple's QUIC connection group owns client bidirectional stream 0 and
    // never writes it; its first request uses stream 4, which implicitly
    // opens stream 0 (RFC 9000 §3.2). Cancelling stream 0 fails the client's
    // whole connection, so the header deadline starts at the first byte.
    let relay = TestRelay::start("").await;
    let (echo, _e) = echo_server().await;
    let (mut h3, conn, _driver) = raw_h3(&relay, true).await;
    let (unwritten, _unwritten_recv) = conn.open_bi().await.unwrap();
    assert_eq!(unwritten.id().index(), 0);
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(echo.to_string())
        .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
        .body(())
        .unwrap();
    let mut tunnel = h3.send_request(request).await.unwrap();
    assert_eq!(within("CONNECT response", tunnel.recv_response()).await.unwrap().status(), StatusCode::OK);
    let wait = Duration::from_secs(12); // past the ten-second header deadline
    assert!(tokio::time::timeout(wait, unwritten.stopped()).await.is_err(), "stream 0 was cancelled");
    tunnel.send_data(Bytes::from_static(b"after")).await.unwrap();
    let mut got = within("echo after the deadline", tunnel.recv_data()).await.unwrap().unwrap();
    assert_eq!(got.copy_to_bytes(got.remaining()), "after");
}

/// The relay's check client never sends MAX_PUSH_ID, so its maximum push ID
/// is unset (RFC 9114 §7.2.7): a server's CANCEL_PUSH (§7.2.3) or PUSH_PROMISE
/// (§7.2.5) names a push ID beyond it, H3_ID_ERROR. A MAX_PUSH_ID from a
/// server is H3_FRAME_UNEXPECTED (§7.2.7), and a malformed payload
/// H3_FRAME_ERROR (§7.1). A raw server observes the client close the
/// connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http3_check_client_checks_push_frames() {
    use h3::error::Code;
    let relay = TestRelay::start("").await;
    let certs = CertStore::open(&relay.env.path("fullchain.pem"), &relay.env.path("privkey.pem")).unwrap();
    let tls_config = network_relay::tls::server_config(certs, &[b"h3"], false, false).unwrap();
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).unwrap();
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(std::sync::Arc::new(crypto)),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let address = endpoint.local_addr().unwrap();
    let mut opts = relay.options(ALICE, address, address);
    opts.port = address.port();
    opts.addresses = vec![address];
    for (control, response, want) in [
        (&[0x03, 0x01, 0x00][..], None, Code::H3_ID_ERROR),
        (&[][..], Some(&[0x05, 0x04, 0x00, 0x00, 0x00, 0xd9][..]), Code::H3_ID_ERROR),
        (&[0x0d, 0x01, 0x00][..], None, Code::H3_FRAME_UNEXPECTED),
        (&[0x03, 0x02, 0x00, 0x00][..], None, Code::H3_FRAME_ERROR),
        (&[0x0d, 0x01, 0x40, 0x07, 0x01, 0x00][..], None, Code::H3_FRAME_ERROR),
    ] {
        let server = async {
            let conn = within("the client's connection", endpoint.accept()).await.unwrap().await.unwrap();
            let mut ctrl = conn.open_uni().await.unwrap();
            // Control stream: SETTINGS with SETTINGS_ENABLE_CONNECT_PROTOCOL
            // and SETTINGS_H3_DATAGRAM, then the frames under test.
            let mut bytes = vec![0x00, 0x04, 0x04, 0x08, 0x01, 0x33, 0x01];
            bytes.extend_from_slice(control);
            ctrl.write_all(&bytes).await.unwrap();
            if let Some(response) = response {
                let (mut send, _recv) = within("the client's request", conn.accept_bi()).await.unwrap();
                send.write_all(response).await.unwrap();
            }
            within("the client's close", conn.closed()).await
        };
        let client = async {
            let mut h3 = H3::connect(&opts, &opts.addresses).await.unwrap();
            let request = Request::builder().method(Method::GET).uri("https://relay.test/").body(()).unwrap();
            if let Ok(mut stream) = h3.request(request).await {
                let _ = tokio::time::timeout(Duration::from_secs(2), stream.recv_response()).await;
            }
            // The check is over: the client gives the connection up.
            drop(h3);
            std::future::pending::<()>().await;
        };
        let closed = tokio::select! { closed = server => closed, _ = client => unreachable!() };
        let want = want.value();
        assert!(
            matches!(closed, quinn::ConnectionError::ApplicationClosed(ref c) if c.error_code.into_inner() == want),
            "{control:02x?} {response:02x?}: {closed:?}, want {want:#x}"
        );
    }
}

#[tokio::test]
async fn http3_push_control_frames_are_checked() {
    // The relay never sends PUSH_PROMISE, so a CANCEL_PUSH names a push ID it
    // has not mentioned (RFC 9114 §7.2.3), and MAX_PUSH_ID cannot be reduced
    // (§7.2.7): both are H3_ID_ERROR. An increasing MAX_PUSH_ID is accepted.
    let relay = TestRelay::start("").await;
    let tls = network_relay::tls::client_config(Some(&relay.env.path("ca.pem")), &[b"h3"]).unwrap();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let cfg = quinn::ClientConfig::new(std::sync::Arc::new(crypto));
    let ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let id_error = h3::error::Code::H3_ID_ERROR.value();
    let frame_error = h3::error::Code::H3_FRAME_ERROR.value();
    for (frames, error) in [
        (&[0x03, 0x01, 0x00][..], Some(id_error)),
        (&[0x0d, 0x01, 0x01, 0x0d, 0x01, 0x00][..], Some(id_error)),
        (&[0x0d, 0x01, 0x00, 0x0d, 0x01, 0x01, 0x0d, 0x01, 0x01][..], None),
        // A payload with bytes after its push ID, or one that ends inside it,
        // is H3_FRAME_ERROR (§7.1).
        (&[0x03, 0x02, 0x00, 0x00][..], Some(frame_error)),
        (&[0x0d, 0x02, 0x00, 0x00][..], Some(frame_error)),
        (&[0x0d, 0x01, 0x40, 0x0d, 0x01, 0x00][..], Some(frame_error)),
    ] {
        let conn = ep.connect_with(cfg.clone(), relay.addr, "relay.test").unwrap().await.unwrap();
        let mut control = conn.open_uni().await.unwrap();
        // Control stream type, empty SETTINGS, then the frames under test.
        control.write_all(&[0x00, 0x04, 0x00]).await.unwrap();
        control.write_all(frames).await.unwrap();
        match error {
            Some(code) => {
                let closed = within("H3_ID_ERROR", conn.closed()).await;
                assert!(
                    matches!(closed, quinn::ConnectionError::ApplicationClosed(ref c) if c.error_code.into_inner() == code),
                    "{frames:02x?}: {closed:?}"
                );
            }
            None => assert!(
                tokio::time::timeout(Duration::from_secs(1), conn.closed()).await.is_err(),
                "{frames:02x?}: connection closed"
            ),
        }
    }
    // On a request stream these frames are unexpected however malformed
    // (§7.2.3, §7.2.6, §7.2.7); their malformed payloads are frame errors
    // too (§7.1). Either way the connection closes.
    let unexpected = h3::error::Code::H3_FRAME_UNEXPECTED.value();
    for frame in [&[0x03, 0x02, 0x00, 0x00][..], &[0x0d, 0x02, 0x00, 0x00][..], &[0x07, 0x02, 0x00, 0x00][..]] {
        let conn = ep.connect_with(cfg.clone(), relay.addr, "relay.test").unwrap().await.unwrap();
        let mut control = conn.open_uni().await.unwrap();
        control.write_all(&[0x00, 0x04, 0x00]).await.unwrap();
        let (mut request, _response) = conn.open_bi().await.unwrap();
        request.write_all(frame).await.unwrap();
        let closed = within("a connection error", conn.closed()).await;
        assert!(
            matches!(closed, quinn::ConnectionError::ApplicationClosed(ref c)
                if [unexpected, frame_error].contains(&c.error_code.into_inner())),
            "{frame:02x?}: {closed:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_udp_protocol_token_is_matched_without_case() {
    // RFC 9110 §7.8: upgrade tokens, and so :protocol (RFC 8441 §4), are
    // compared without regard to case.
    let relay = TestRelay::start("").await;
    let (udp, _u) = udp_echo().await;
    let auth_header = auth::basic_authorization(ALICE.0, ALICE.1);
    let path = format!("/.well-known/masque/udp/127.0.0.1/{}/", udp.port());
    let (_sender, conn, _driver) = raw_h3(&relay, true).await;
    let fields = [
        (":method", "CONNECT"),
        (":protocol", "CONNECT-UDP"),
        (":scheme", "https"),
        (":authority", "relay.test"),
        (":path", path.as_str()),
        ("capsule-protocol", "?1"),
        ("authorization", auth_header.as_str()),
    ];
    // The stream stays open: a FIN would end the flow (RFC 9298 §3).
    let (_send, _recv) = raw_h3_open(&conn, &fields).await;
    wait_for_tunnels(&relay, 1).await;
    let (mut h2, _driver2) = raw_h2(&relay).await;
    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://relay.test{path}"))
        .header("authorization", &auth_header)
        .header("capsule-protocol", "?1")
        .extension(h2::ext::Protocol::from("Connect-UDP"))
        .body(())
        .unwrap();
    let (response, _send) = h2.send_request(req, false).unwrap();
    let response = within("HTTP/2 answer", response).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["capsule-protocol"], "?1");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_udp_targets_with_unencoded_ipv6_colons_are_understood() {
    // RFC 9298 §2 has clients encode the colons, but a client that does not
    // still names an IPv6 target: it must reach the destination rules (here
    // blocked loopback), not get the website.
    let relay = TestRelay::start("blocked_destinations = [\"::1/128\"]").await;
    let (mut h2, _driver) = raw_h2(&relay).await;
    for path in ["/.well-known/masque/udp/::1/53/", "/.well-known/masque/udp/%3A%3A1/53/"] {
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://relay.test{path}"))
            .header("authorization", auth::basic_authorization(ALICE.0, ALICE.1))
            .header("capsule-protocol", "?1")
            .extension(h2::ext::Protocol::from(network_relay::proto::CONNECT_UDP_PROTOCOL))
            .body(())
            .unwrap();
        let (response, _send) = h2.send_request(req, false).unwrap();
        let response = within("HTTP/2 answer", response).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "{path}");
        assert_eq!(response.headers()["proxy-status"], "network-relay; error=destination_ip_prohibited", "{path}");
    }
}

/// Opens a request stream on `conn` with `fields`, and returns it once the
/// response's first frame (HEADERS) has begun to arrive. The send side stays
/// open, as a tunnel's does.
async fn raw_h3_open(conn: &quinn::Connection, fields: &[(&str, &str)]) -> (quinn::SendStream, quinn::RecvStream) {
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let block = qpack_literal(fields);
    let mut frame = bytes::BytesMut::new();
    network_relay::proto::varint::encode(1, &mut frame);
    network_relay::proto::varint::encode(block.len() as u64, &mut frame);
    frame.extend_from_slice(&block);
    send.write_all(&frame).await.unwrap();
    let mut first = [0u8; 1];
    within("response HEADERS", recv.read_exact(&mut first)).await.unwrap();
    assert_eq!(first[0], 1, "a HEADERS frame");
    (send, recv)
}

async fn wait_for_tunnels(relay: &TestRelay, n: usize) {
    within("tunnel count", async {
        while relay.relay.active_tunnels() != n {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
}

/// The STOP_SENDING code the relay sent for the client's side of `send`.
async fn stop_sending_code(send: &mut quinn::SendStream) -> Option<u64> {
    within("STOP_SENDING", send.stopped()).await.unwrap().map(|code| code.into_inner())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http3_aborted_tunnels_stop_the_client_with_the_abort_code() {
    // RFC 9114 §4.1.1: cancelling a request resets its sending part and
    // aborts reading its receiving part, both with the reason. The receiving
    // part used to lose the code whenever a read was pending, which is nearly
    // always for a tunnel, and the client got STOP_SENDING with code 0, which
    // HTTP/3 does not define.
    let relay = TestRelay::start("").await;
    let (echo, _e) = echo_server().await;
    let (udp, _u) = udp_echo().await;
    let (_sender, conn, _driver) = raw_h3(&relay, true).await;
    let auth_header = auth::basic_authorization(ALICE.0, ALICE.1);
    let target = echo.to_string();
    let tcp = [(":method", "CONNECT"), (":authority", target.as_str()), ("authorization", auth_header.as_str())];
    let path = format!("/.well-known/masque/udp/127.0.0.1/{}/", udp.port());
    let udp_flow = [
        (":method", "CONNECT"),
        (":protocol", "connect-udp"),
        (":scheme", "https"),
        (":authority", "relay.test"),
        (":path", path.as_str()),
        ("capsule-protocol", "?1"),
        ("authorization", auth_header.as_str()),
    ];

    // A datagram on a TCP tunnel: H3_DATAGRAM_ERROR (RFC 9297 §2).
    let (mut send, _recv) = raw_h3_open(&conn, &tcp).await;
    wait_for_tunnels(&relay, 1).await;
    let mut datagram = bytes::BytesMut::new();
    // The quarter stream ID (RFC 9297 §2.1) is the stream's index.
    network_relay::proto::varint::encode(send.id().index(), &mut datagram);
    datagram.extend_from_slice(b"\0stray");
    conn.send_datagram(datagram.freeze()).unwrap();
    assert_eq!(stop_sending_code(&mut send).await, Some(h3::error::Code::H3_DATAGRAM_ERROR.value()));
    wait_for_tunnels(&relay, 0).await;

    // Revocation: H3_REQUEST_CANCELLED, for a TCP tunnel and a UDP flow.
    let (mut tcp_send, _tcp_recv) = raw_h3_open(&conn, &tcp).await;
    let (mut udp_send, _udp_recv) = raw_h3_open(&conn, &udp_flow).await;
    wait_for_tunnels(&relay, 2).await;
    relay.reload("", &[]);
    let cancelled = h3::error::Code::H3_REQUEST_CANCELLED.value();
    assert_eq!(stop_sending_code(&mut tcp_send).await, Some(cancelled), "TCP tunnel");
    assert_eq!(stop_sending_code(&mut udp_send).await, Some(cancelled), "UDP flow");
}

/// A TCP destination that never completes a connection: its accept queue
/// is full, so Linux drops further SYNs and connecting stalls.
async fn stalled_destination() -> (SocketAddr, socket2::Socket, Vec<tokio::net::TcpStream>) {
    let listener = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    listener.bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into()).unwrap();
    listener.listen(0).unwrap();
    let addr = listener.local_addr().unwrap().as_socket().unwrap();
    let mut queued = Vec::new();
    for _ in 0..4 {
        match tokio::time::timeout(Duration::from_millis(200), tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => queued.push(stream),
            _ => break,
        }
    }
    (addr, listener, queued)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http3_request_the_client_cancels_while_connecting_is_cancelled_both_ways() {
    // RFC 9114 §4.1.1. The relay used to drop the stream, which stopped the
    // client's sending with code 0 instead of H3_REQUEST_CANCELLED.
    let (target, _listener, _queued) = stalled_destination().await;
    let relay = TestRelay::start("blocked_destinations = []\nconnect_timeout_secs = 60").await;
    let (_sender, conn, _driver) = raw_h3(&relay, true).await;
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let auth_header = auth::basic_authorization(ALICE.0, ALICE.1);
    let authority = target.to_string();
    let block = qpack_literal(&[
        (":method", "CONNECT"),
        (":authority", authority.as_str()),
        ("authorization", auth_header.as_str()),
    ]);
    let mut frame = bytes::BytesMut::new();
    network_relay::proto::varint::encode(1, &mut frame);
    network_relay::proto::varint::encode(block.len() as u64, &mut frame);
    frame.extend_from_slice(&block);
    send.write_all(&frame).await.unwrap();
    let mut first = [0u8; 1];
    let waited = tokio::time::timeout(Duration::from_millis(500), recv.read_exact(&mut first)).await;
    assert!(waited.is_err(), "the destination was supposed to stall the connect");
    let cancelled = h3::error::Code::H3_REQUEST_CANCELLED.value();
    recv.stop(cancelled.try_into().unwrap()).unwrap();
    assert_eq!(stop_sending_code(&mut send).await, Some(cancelled));
    assert_eq!(relay.relay.active_tunnels(), 0);
}

#[tokio::test]
async fn http3_request_headers_over_the_limit_get_431_and_no_error_stop() {
    // RFC 9114 §4.2.2 lets a server limit field sections; the 431 answer does
    // not need the rest of the request, so the client is asked to stop
    // sending with H3_NO_ERROR (§4.1), not the undefined code 0.
    let relay = TestRelay::start("").await;
    let (_sender, conn, _driver) = raw_h3(&relay, true).await;
    let big = "x".repeat(40 * 1024);
    let fields = [
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", "relay.test"),
        (":path", "/"),
        ("x-padding", big.as_str()),
    ];
    let (mut send, mut recv) = raw_h3_open(&conn, &fields).await;
    let rest = within("431 response and FIN", recv.read_to_end(64 * 1024)).await.unwrap();
    assert!(!rest.is_empty(), "the HEADERS frame of the 431 response");
    assert_eq!(stop_sending_code(&mut send).await, Some(h3::error::Code::H3_NO_ERROR.value()));
}
