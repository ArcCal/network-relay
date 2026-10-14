//! A lost egress generation must interrupt quota waits and idle flows.

#[path = "support/lifecycle.rs"]
mod lifecycle;
mod support;

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use http::{Method, Request, StatusCode};
use lifecycle::ControlledEgress;
use relay_frontend::auth;
use relay_frontend::certs::CertStore;
use relay_frontend::config::{Config, Web};
use relay_frontend::limits::BYTE_BURST;
use relay_frontend::server::{self, Relay};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

const WAIT: Duration = Duration::from_secs(5);
const PROMPT: Duration = Duration::from_secs(2);
const USER: &str = "lifecycle";
const PASSWORD: &str = "synthetic-lifecycle-fixture-secret";
const QUOTA_DEBT_THRESHOLD: usize = BYTE_BURST as usize + 16 * 1024;
const WEBSITE_BYTES: usize = 16 * 1024 * 1024;

struct Task<T>(JoinHandle<T>);

impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, future).await.expect("lifecycle test setup or data transfer stalled")
}

struct TestRelay {
    dir: PathBuf,
    relay: Relay,
    config: Config,
    addr: SocketAddr,
    egress: Arc<ControlledEgress>,
    _tasks: Vec<Task<()>>,
}

impl TestRelay {
    async fn start() -> Self {
        Self::prepare(true).await
    }

    async fn prepare(serve: bool) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/test-runtime").join(format!(
            "egress-lifecycle-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["relay.test".into()]).unwrap().signed_by(&key, &issuer).unwrap();
        let cert_path = dir.join("fullchain.pem");
        let key_path = dir.join("privkey.pem");
        std::fs::write(dir.join("ca.pem"), ca.pem()).unwrap();
        std::fs::write(&cert_path, cert.pem() + &ca.pem()).unwrap();
        std::fs::write(&key_path, key.serialize_pem()).unwrap();
        let (udp, tcp) = loop {
            let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            if let Ok(tcp) = TcpListener::bind(udp.local_addr().unwrap()).await {
                break (udp, tcp);
            }
        };
        let addr = udp.local_addr().unwrap();
        let hash = auth::hash_generated_secret(PASSWORD).unwrap();
        let config_text = format!(
            "listen = \"{addr}\"\n[tls]\ncert = {cert_path:?}\nkey = {key_path:?}\n\
             [relay]\nblocked_destinations = []\nblocked_ports = []\nblock_own_addresses = false\n\
             max_tunnels = 8\nmax_bytes_per_second_per_user = 1\n\
             [[user]]\nname = \"{USER}\"\npassword_hash = \"{hash}\"\n"
        );
        std::fs::write(dir.join("relay.toml"), &config_text).unwrap();
        let config: Config = toml::from_str(&config_text).unwrap();
        let egress = Arc::new(ControlledEgress::default());
        let relay = Relay::new(&config, egress.clone()).unwrap();
        let certs = CertStore::open(&cert_path, &key_path).unwrap();
        let tasks = if serve {
            let endpoint = server::quic_endpoint(certs.clone(), udp, false).unwrap();
            vec![
                Task(tokio::spawn(relay.clone().serve_quic(endpoint))),
                Task(tokio::spawn(relay.clone().serve_tcp(tcp, server::tcp_tls_config(certs, false).unwrap()))),
            ]
        } else {
            drop(udp);
            drop(tcp);
            Vec::new()
        };
        Self { dir, relay, config, addr, egress, _tasks: tasks }
    }

    async fn h2(&self) -> (h2::client::SendRequest<Bytes>, Task<()>) {
        let tls = relay_frontend::tls::client_config(Some(&self.dir.join("ca.pem")), &[b"h2"]).unwrap();
        let tcp = tokio::net::TcpStream::connect(self.addr).await.unwrap();
        let io = tokio_rustls::TlsConnector::from(Arc::new(tls))
            .connect("relay.test".try_into().unwrap(), tcp)
            .await
            .unwrap();
        let (sender, connection) = h2::client::handshake(io).await.unwrap();
        let driver = Task(tokio::spawn(async move {
            let _ = connection.await;
        }));
        within(async {
            while !sender.is_extended_connect_protocol_enabled() {
                tokio::task::yield_now().await;
            }
        })
        .await;
        (sender, driver)
    }

    async fn h3(&self) -> (h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>, quinn::Connection, Task<()>) {
        let tls = relay_frontend::tls::client_config(Some(&self.dir.join("ca.pem")), &[b"h3"]).unwrap();
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
        let config = quinn::ClientConfig::new(Arc::new(crypto));
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let conn = endpoint.connect_with(config, self.addr, "relay.test").unwrap().await.unwrap();
        let (mut driver, sender) = h3::client::builder()
            .enable_extended_connect(true)
            .enable_datagram(true)
            .build::<_, _, Bytes>(h3_quinn::Connection::new(conn.clone()))
            .await
            .unwrap();
        let driver = Task(tokio::spawn(async move {
            std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        }));
        (sender, conn, driver)
    }

    async fn assert_tcp_quota_wait(&self) {
        within(self.egress.wait_for_tcp_read_bytes(QUOTA_DEBT_THRESHOLD)).await.unwrap();
        let before = self.egress.counters().tcp_read_bytes;
        // At one byte/second, this transfer owes thousands of seconds.
        // Observing stable reads confirms the destination pump is paused.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(self.egress.counters().tcp_read_bytes, before, "quota did not pause destination reads");
        assert_eq!(self.egress.counters().tcp_write_bytes, 0, "this download fixture must leave the upload side idle");
        assert_eq!(self.relay.active_tunnels(), 1);
    }

    async fn assert_released(&self, tcp: bool) {
        tokio::time::timeout(PROMPT, async {
            while self.relay.active_tunnels() != 0 || self.relay.user_tunnels(USER) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("failed egress retained tunnel capacity");
        if tcp {
            assert!(self.egress.counters().tcp_aborts >= 1, "failed egress was treated as a graceful TCP close");
        } else {
            tokio::time::timeout(PROMPT, self.egress.wait_for_udp_drops(1))
                .await
                .expect("failed egress retained its UDP socket")
                .unwrap();
            assert!(self.egress.counters().udp_drops >= 1);
        }
    }

    async fn start_run(&self) -> Task<anyhow::Result<()>> {
        let task =
            Task(tokio::spawn(server::run(self.dir.join("relay.toml"), self.config.clone(), self.egress.clone())));
        within(async {
            loop {
                assert!(!task.0.is_finished(), "server run ended during startup");
                if tokio::net::TcpStream::connect(self.addr).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        task
    }

    async fn assert_listeners_released(&self) {
        tokio::time::timeout(PROMPT, async {
            loop {
                if let Ok(tcp) = relay_frontend::sys::bind_tcp(self.addr) {
                    if let Ok(udp) = relay_frontend::sys::bind_udp(self.addr) {
                        drop((tcp, udp));
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("canceling run leaked the TCP or UDP listener");
    }

    fn install_large_website(&mut self) {
        let root = self.dir.join("site");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("index.html"), vec![b'x'; WEBSITE_BYTES]).unwrap();
        self.config.web = Some(Web { root, headers: Default::default() });
    }

    async fn tls_with_small_receive_buffer(
        &self,
        alpn: &[u8],
    ) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
        let config = relay_frontend::tls::client_config(Some(&self.dir.join("ca.pem")), &[alpn]).unwrap();
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(8192).unwrap();
        let tcp = socket.connect(self.addr).await.unwrap();
        within(tokio_rustls::TlsConnector::from(Arc::new(config)).connect("relay.test".try_into().unwrap(), tcp))
            .await
            .unwrap()
    }
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        self.relay.begin_shutdown();
        self._tasks.clear();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn tcp_request(target: SocketAddr) -> Request<()> {
    Request::builder()
        .method(Method::CONNECT)
        .uri(target.to_string())
        .header("authorization", auth::basic_authorization(USER, PASSWORD))
        .body(())
        .unwrap()
}

fn udp_request(target: SocketAddr) -> http::request::Builder {
    Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://relay.test/.well-known/masque/udp/127.0.0.1/{}/", target.port()))
        .header("authorization", auth::basic_authorization(USER, PASSWORD))
        .header("capsule-protocol", "?1")
}

async fn sending_target() -> (SocketAddr, Task<std::io::Result<usize>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = Task(tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await?;
        tcp.write_all(&vec![0xa5; 512 * 1024]).await?;
        tcp.read(&mut [0; 1]).await
    }));
    (addr, task)
}

async fn assert_target_reset(target: &mut Task<std::io::Result<usize>>) {
    let result =
        tokio::time::timeout(PROMPT, &mut target.0).await.expect("destination was not promptly aborted").unwrap();
    assert!(
        matches!(result, Err(ref e) if matches!(e.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::BrokenPipe)),
        "destination saw a graceful close instead of reset: {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_egress_failure_interrupts_tcp_byte_quota_debt() {
    let relay = TestRelay::start().await;
    let (target, mut target_task) = sending_target().await;
    let (mut sender, _driver) = relay.h2().await;
    let (response, _send) = sender.send_request(tcp_request(target), false).unwrap();
    let response = within(response).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut recv = response.into_body();
    let mut receiver = Task(tokio::spawn(async move {
        loop {
            match recv.data().await {
                Some(Ok(chunk)) => recv.flow_control().release_capacity(chunk.len()).unwrap(),
                Some(Err(error)) => return error.reason(),
                None => panic!("egress failure became orderly HTTP/2 EOF"),
            }
        }
    }));
    relay.assert_tcp_quota_wait().await;
    assert!(!receiver.0.is_finished(), "tunnel ended before egress failed");
    relay.egress.fail();
    let reason = tokio::time::timeout(PROMPT, &mut receiver.0)
        .await
        .expect("HTTP/2 waited for quota debt after egress failure")
        .unwrap();
    assert_eq!(reason, Some(h2::Reason::CONNECT_ERROR));
    relay.assert_released(true).await;
    assert_target_reset(&mut target_task).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_egress_failure_interrupts_tcp_byte_quota_debt() {
    let relay = TestRelay::start().await;
    let (target, mut target_task) = sending_target().await;
    let (mut sender, _connection, _driver) = relay.h3().await;
    let mut stream = sender.send_request(tcp_request(target)).await.unwrap();
    assert_eq!(within(stream.recv_response()).await.unwrap().status(), StatusCode::OK);
    let mut receiver = Task(tokio::spawn(async move {
        loop {
            match stream.recv_data().await {
                Ok(Some(mut chunk)) => chunk.advance(chunk.remaining()),
                Err(error) => return error,
                Ok(None) => panic!("egress failure became orderly HTTP/3 EOF"),
            }
        }
    }));
    relay.assert_tcp_quota_wait().await;
    assert!(!receiver.0.is_finished(), "tunnel ended before egress failed");
    relay.egress.fail();
    let error = tokio::time::timeout(PROMPT, &mut receiver.0)
        .await
        .expect("HTTP/3 waited for quota debt after egress failure")
        .unwrap();
    assert!(
        matches!(error, h3::error::StreamError::RemoteTerminate { code } if code == h3::error::Code::H3_CONNECT_ERROR),
        "egress failure returned the wrong HTTP/3 error: {error:?}"
    );
    relay.assert_released(true).await;
    assert_target_reset(&mut target_task).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_idle_udp_egress_failure_resets_and_releases_the_flow() {
    let relay = TestRelay::start().await;
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (mut sender, _driver) = relay.h2().await;
    let request =
        udp_request(target.local_addr().unwrap()).extension(h2::ext::Protocol::from("connect-udp")).body(()).unwrap();
    let (response, _send) = sender.send_request(request, false).unwrap();
    let response = within(response).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut recv = response.into_body();
    assert_eq!(relay.relay.active_tunnels(), 1);
    relay.egress.fail();
    let error = tokio::time::timeout(PROMPT, recv.data())
        .await
        .expect("idle HTTP/2 UDP waited for its idle timeout after egress failure")
        .expect("egress failure became orderly HTTP/2 UDP EOF")
        .unwrap_err();
    assert_eq!(error.reason(), Some(h2::Reason::CONNECT_ERROR));
    relay.assert_released(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_idle_udp_egress_failure_resets_and_releases_the_flow() {
    let relay = TestRelay::start().await;
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (mut sender, _connection, _driver) = relay.h3().await;
    let request = udp_request(target.local_addr().unwrap()).extension(h3::ext::Protocol::CONNECT_UDP).body(()).unwrap();
    let mut stream = sender.send_request(request).await.unwrap();
    assert_eq!(within(stream.recv_response()).await.unwrap().status(), StatusCode::OK);
    assert_eq!(relay.relay.active_tunnels(), 1);
    relay.egress.fail();
    let error = tokio::time::timeout(PROMPT, stream.recv_data())
        .await
        .expect("idle HTTP/3 UDP waited for its idle timeout after egress failure")
        .err()
        .expect("egress failure became orderly HTTP/3 UDP EOF");
    assert!(
        matches!(error, h3::error::StreamError::RemoteTerminate { code } if code == h3::error::Code::H3_CONNECT_ERROR),
        "egress failure returned the wrong HTTP/3 UDP error: {error:?}"
    );
    relay.assert_released(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_run_aborts_open_targets_and_releases_both_listeners() {
    let fixture = TestRelay::prepare(false).await;
    let mut run =
        Task(tokio::spawn(server::run(fixture.dir.join("relay.toml"), fixture.config.clone(), fixture.egress.clone())));
    within(async {
        loop {
            assert!(!run.0.is_finished(), "server run ended during startup");
            if tokio::net::TcpStream::connect(fixture.addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let (target, mut target_task) = sending_target().await;
    let (mut sender, _driver) = fixture.h2().await;
    let (response, _send) = sender.send_request(tcp_request(target), false).unwrap();
    let response = within(response).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut recv = response.into_body();
    let mut receiver = Task(tokio::spawn(async move {
        loop {
            match recv.data().await {
                Some(Ok(chunk)) => recv.flow_control().release_capacity(chunk.len()).unwrap(),
                Some(Err(error)) => return error.reason(),
                None => panic!("server cancellation became orderly tunnel EOF"),
            }
        }
    }));
    within(fixture.egress.wait_for_tcp_read_bytes(QUOTA_DEBT_THRESHOLD)).await.unwrap();
    assert!(!receiver.0.is_finished());
    run.0.abort();
    assert!((&mut run.0).await.unwrap_err().is_cancelled());
    let reason = tokio::time::timeout(PROMPT, &mut receiver.0)
        .await
        .expect("canceling run did not interrupt the active tunnel")
        .unwrap();
    assert_eq!(reason, Some(h2::Reason::CONNECT_ERROR));
    assert!(fixture.egress.counters().tcp_aborts >= 1);
    assert_target_reset(&mut target_task).await;
    tokio::time::timeout(PROMPT, async {
        loop {
            // Match the server's listener options: accepted TCP connections
            // can still exist while a new reusable listener takes its port.
            if let Ok(tcp) = relay_frontend::sys::bind_tcp(fixture.addr) {
                if let Ok(udp) = relay_frontend::sys::bind_udp(fixture.addr) {
                    drop((tcp, udp));
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("canceling run leaked the TCP or UDP listener");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_run_closes_an_accepted_incomplete_tls_handshake() {
    let fixture = TestRelay::prepare(false).await;
    let mut run = fixture.start_run().await;
    let mut client = tokio::net::TcpStream::connect(fixture.addr).await.unwrap();
    client.write_all(&[0x16]).await.unwrap();
    // A later TLS handshake proves the accept loop processed this socket.
    drop(fixture.tls_with_small_receive_buffer(b"http/1.1").await);
    run.0.abort();
    assert!((&mut run.0).await.unwrap_err().is_cancelled());
    let closed = tokio::time::timeout(PROMPT, client.read(&mut [0; 1]))
        .await
        .expect("accepted TLS handshake survived cancellation of server run");
    assert!(matches!(closed, Ok(0) | Err(_)), "server unexpectedly sent TLS data: {closed:?}");
    fixture.assert_listeners_released().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_run_closes_a_stalled_http1_website_response() {
    let mut fixture = TestRelay::prepare(false).await;
    fixture.install_large_website();
    let mut run = fixture.start_run().await;
    let mut client = fixture.tls_with_small_receive_buffer(b"http/1.1").await;
    client.write_all(b"GET / HTTP/1.1\r\nHost: relay.test\r\n\r\n").await.unwrap();
    let mut headers = Vec::new();
    within(async {
        while !headers.ends_with(b"\r\n\r\n") {
            let byte = client.read_u8().await.unwrap();
            headers.push(byte);
            assert!(headers.len() <= 4096);
        }
    })
    .await;
    assert!(headers.starts_with(b"HTTP/1.1 200 "));
    tokio::time::sleep(Duration::from_millis(50)).await;
    run.0.abort();
    assert!((&mut run.0).await.unwrap_err().is_cancelled());
    let body_bytes = tokio::time::timeout(PROMPT, async {
        let mut bytes = 0;
        let mut buffer = [0; 64 * 1024];
        loop {
            match client.read(&mut buffer).await {
                Ok(0) | Err(_) => return bytes,
                Ok(n) => bytes += n,
            }
        }
    })
    .await
    .expect("stalled HTTP/1 website survived cancellation of server run");
    assert!(body_bytes < WEBSITE_BYTES, "server cancellation gracefully completed a response that had been stalled");
    fixture.assert_listeners_released().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_run_closes_a_stalled_http2_website_response() {
    let mut fixture = TestRelay::prepare(false).await;
    fixture.install_large_website();
    let mut run = fixture.start_run().await;
    let tls = fixture.tls_with_small_receive_buffer(b"h2").await;
    let (mut sender, connection) =
        h2::client::Builder::new().initial_window_size(0).handshake::<_, Bytes>(tls).await.unwrap();
    let mut driver = Task(tokio::spawn(connection));
    let (response, _send) =
        sender.send_request(Request::builder().uri("https://relay.test/").body(()).unwrap(), true).unwrap();
    let response = within(response).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut recv = response.into_body();
    // No receive credit is ever granted, so the website body cannot finish.
    assert!(tokio::time::timeout(Duration::from_millis(50), recv.data()).await.is_err());
    run.0.abort();
    assert!((&mut run.0).await.unwrap_err().is_cancelled());
    let reset = tokio::time::timeout(PROMPT, recv.data())
        .await
        .expect("stalled HTTP/2 website survived cancellation of server run");
    assert!(!matches!(reset, Some(Ok(_))), "server sent body bytes without HTTP/2 receive credit");
    let _ = tokio::time::timeout(PROMPT, &mut driver.0)
        .await
        .expect("website reset left the native HTTP/2 connection open")
        .unwrap();
    fixture.assert_listeners_released().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forced_shutdown_refunds_accepted_tls_connection_capacity() {
    let fixture = TestRelay::start().await;
    let mut client = tokio::net::TcpStream::connect(fixture.addr).await.unwrap();
    client.write_all(&[0x16]).await.unwrap();
    within(async {
        while fixture.relay.open_connections() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    fixture.relay.force_shutdown();
    assert!(fixture.relay.drain(PROMPT).await, "forced TLS shutdown retained connection admission");
    assert_eq!(fixture.relay.open_connections(), 0);
    let closed = tokio::time::timeout(PROMPT, client.read(&mut [0; 1])).await.unwrap();
    assert!(matches!(closed, Ok(0) | Err(_)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forced_shutdown_refunds_stalled_http2_website_connection_capacity() {
    let mut fixture = TestRelay::start().await;
    fixture.install_large_website();
    fixture.relay.reload(&fixture.config).unwrap();
    let tls = fixture.tls_with_small_receive_buffer(b"h2").await;
    let (mut sender, connection) =
        h2::client::Builder::new().initial_window_size(0).handshake::<_, Bytes>(tls).await.unwrap();
    let mut driver = Task(tokio::spawn(connection));
    let (response, _send) =
        sender.send_request(Request::builder().uri("https://relay.test/").body(()).unwrap(), true).unwrap();
    let response = within(response).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut recv = response.into_body();
    assert!(tokio::time::timeout(Duration::from_millis(50), recv.data()).await.is_err());
    assert_eq!(fixture.relay.open_connections(), 1);
    fixture.relay.force_shutdown();
    assert!(fixture.relay.drain(PROMPT).await, "forced website shutdown retained connection admission");
    assert_eq!(fixture.relay.open_connections(), 0);
    let _ = tokio::time::timeout(PROMPT, &mut driver.0).await.expect("held website connection did not close").unwrap();
}
