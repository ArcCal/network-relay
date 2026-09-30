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

// ---------------------------------------------------------------- tests

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
    let mut opts = relay.options(ALICE, closed, dns);
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

    opts.tcp_target = "does-not-exist.invalid:80".into();
    let e = format!("{:#}", within("check", check::run(&opts)).await[0].result.as_ref().unwrap_err());
    assert!(e.contains("dns_error") || e.contains("dns_timeout") || e.contains("destination_not_found"), "{e}");
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
