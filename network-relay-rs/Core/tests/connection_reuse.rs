//! HTTP/3 connection lifetime checks through the production Rust backend.
//! The loopback peer records request HEADERS, including forbidden post-GOAWAY
//! attempts, so a rejected request cannot be hidden by an automatic replay.
use network_relay_rs_core::{
    Config, Socks,
    backend::{Backend, BackendOptions},
    client::Client,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{
    net::SocketAddr,
    path::PathBuf,
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::watch,
    task::{JoinHandle, JoinSet},
};

static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

struct ObservedConnection {
    headers: Arc<Mutex<Vec<u64>>>,
}

struct Fixture {
    settings_frame: tokio::sync::watch::Sender<Option<&'static [u8]>>,
    address: SocketAddr,
    directory: PathBuf,
    endpoint: quinn::Endpoint,
    task: JoinHandle<()>,
    connections: Arc<Mutex<Vec<ObservedConnection>>>,
    goaway: watch::Sender<u64>,
}

impl Fixture {
    async fn start(stream_limit: u32) -> Self {
        Self::start_with_response_delay(stream_limit, Duration::ZERO).await
    }

    async fn start_with_response_delay(stream_limit: u32, response_delay: Duration) -> Self {
        Self::start_with_settings(stream_limit, response_delay, Some(&[0, 4, 2, 8, 1])).await
    }

    async fn start_with_settings(
        stream_limit: u32,
        response_delay: Duration,
        frame: Option<&'static [u8]>,
    ) -> Self {
        let (settings_frame, frames) = tokio::sync::watch::channel(frame);
        let directory = std::env::temp_dir().join(format!(
            "relay-rs-h3-reuse-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let openssl = |arguments: &[&str]| {
            let output = Command::new("openssl")
                .args(arguments)
                .current_dir(&directory)
                .output()
                .expect("OpenSSL is required by the relay interoperability tests");
            assert!(
                output.status.success(),
                "OpenSSL fixture setup failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        std::fs::write(
            directory.join("ca.cnf"),
            "[req]\nprompt=no\ndistinguished_name=subject\nx509_extensions=ca\n\
             [subject]\nCN=Disposable relay test CA\n\
             [ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n",
        )
        .unwrap();
        openssl(&[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-days",
            "2",
            "-config",
            "ca.cnf",
            "-keyout",
            "ca-key.pem",
            "-out",
            "ca.pem",
        ]);
        openssl(&[
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=relay.test",
            "-keyout",
            "key.pem",
            "-out",
            "request.pem",
        ]);
        std::fs::write(
            directory.join("leaf.cnf"),
            "basicConstraints=critical,CA:FALSE\n\
             keyUsage=critical,digitalSignature,keyEncipherment\n\
             extendedKeyUsage=serverAuth\nsubjectAltName=DNS:relay.test\n",
        )
        .unwrap();
        openssl(&[
            "x509",
            "-req",
            "-in",
            "request.pem",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca-key.pem",
            "-set_serial",
            "2",
            "-days",
            "2",
            "-sha256",
            "-extfile",
            "leaf.cnf",
            "-out",
            "cert.pem",
        ]);
        let certificates = CertificateDer::pem_file_iter(directory.join("cert.pem"))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_file(directory.join("key.pem")).unwrap();
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        Arc::get_mut(&mut config.transport)
            .unwrap()
            .max_concurrent_bidi_streams(stream_limit.into());
        let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let address = endpoint.local_addr().unwrap();
        let accepting = endpoint.clone();
        let connections = Arc::new(Mutex::new(Vec::new()));
        let observed = connections.clone();
        let (goaway, _) = watch::channel(0);
        let notices = goaway.clone();
        let task = tokio::spawn(async move {
            let mut workers = JoinSet::new();
            loop {
                tokio::select! {
                    _ = workers.join_next(), if !workers.is_empty() => {},
                    incoming = accepting.accept() => {
                        let Some(incoming) = incoming else { break; };
                        let connection = incoming.await.unwrap();
                        let headers = Arc::new(Mutex::new(Vec::new()));
                        observed.lock().unwrap().push(ObservedConnection { headers: headers.clone() });
                        let mut notices = notices.subscribe();
                        let mut frames = frames.clone();
                        workers.spawn(async move {
                            let mut control = connection.open_uni().await.unwrap();
                            let mut settings_sent = false;
                            let cutoff = Arc::new(AtomicU64::new(u64::MAX));
                            let mut streams = JoinSet::new();
                            loop {
                                tokio::select! {
                                    frame = async { frames.wait_for(Option::is_some).await.map(|v| v.unwrap()) }, if !settings_sent => {
                                        let Ok(frame) = frame else { break; };
                                        if control.write_all(frame).await.is_err() { break; }
                                        settings_sent = true;
                                    }
                                    _ = streams.join_next(), if !streams.is_empty() => {},
                                    _ = connection.closed() => break,
                                    result = notices.changed() => {
                                        if result.is_err() { break; }
                                        let first_rejected = headers.lock().unwrap().iter().max().map_or(0, |id| id + 4);
                                        cutoff.store(first_rejected, Ordering::Release);
                                        let mut wire = vec![7];
                                        let mut value = Vec::new();
                                        network_relay_rs_core::proto::varint::encode(first_rejected, &mut value);
                                        network_relay_rs_core::proto::varint::encode(value.len() as u64, &mut wire);
                                        wire.extend_from_slice(&value);
                                        if control.write_all(&wire).await.is_err() { break; }
                                    },
                                    next = connection.accept_bi() => match next {
                                        Ok((send, recv)) => {
                                            streams.spawn(h3_echo(send, recv, headers.clone(), cutoff.clone(), response_delay));
                                        },
                                        Err(_) => break,
                                    }
                                }
                            }
                        });
                    }
                }
            }
        });
        Self {
            settings_frame,
            address,
            directory,
            endpoint,
            task,
            connections,
            goaway,
        }
    }

    fn config(&self) -> Config {
        Config {
            uri_template: format!(
                "https://{}/.well-known/masque/udp/{{target_host}}/{{target_port}}/",
                self.address
            ),
            username: "alice".into(),
            password: "disposable-test-password".into(),
            server_name: Some("relay.test".into()),
            transport: "h3".into(),
            probe_target: "127.0.0.1:9".parse().unwrap(),
            mode: "socks".into(),
            socks: Socks {
                listen: vec!["127.0.0.1:0".parse().unwrap()],
            },
        }
    }

    fn backend(&self) -> Backend {
        Backend::start(BackendOptions {
            ca_file: Some(self.directory.join("ca.pem")),
        })
        .unwrap()
    }

    fn connection_count(&self) -> usize {
        self.connections.lock().unwrap().len()
    }

    fn request_ids(&self, connection: usize) -> Vec<u64> {
        self.connections.lock().unwrap()[connection]
            .headers
            .lock()
            .unwrap()
            .clone()
    }

    async fn send_goaway(&self) {
        self.goaway.send_modify(|generation| *generation += 1);
        // Let the loopback control frame reach the client's continuously
        // running H3 driver before testing a subsequent distinct request.
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
        self.endpoint.close(0x100u32.into(), b"fixture ended");
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

async fn varint(recv: &mut quinn::RecvStream) -> Option<u64> {
    let first = recv.read_u8().await.ok()?;
    let mut value = u64::from(first & 63);
    for _ in 1..(1 << (first >> 6)) {
        value = (value << 8) | u64::from(recv.read_u8().await.ok()?);
    }
    Some(value)
}

async fn h3_echo(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    headers: Arc<Mutex<Vec<u64>>>,
    cutoff: Arc<AtomicU64>,
    response_delay: Duration,
) {
    let id: u64 = recv.id().into();
    if varint(&mut recv).await != Some(1) {
        return;
    }
    let Some(length) = varint(&mut recv).await else {
        return;
    };
    let mut encoded = vec![0; length as usize];
    if recv.read_exact(&mut encoded).await.is_err() {
        return;
    }
    headers.lock().unwrap().push(id);
    if id >= cutoff.load(Ordering::Acquire) {
        // Record a forbidden request before rejecting it. An error alone
        // would not prove the client refrained from sending its HEADERS.
        let _ = send.reset(0x10bu32.into());
        let _ = recv.stop(0x10bu32.into());
        return;
    }
    tokio::time::sleep(response_delay).await;
    if send.write_all(&[1, 3, 0, 0, 0xd9]).await.is_err() {
        return;
    }
    while let Some(kind) = varint(&mut recv).await {
        let Some(length) = varint(&mut recv).await else {
            return;
        };
        let mut data = vec![0; length as usize];
        if recv.read_exact(&mut data).await.is_err() {
            return;
        }
        if kind == 0 {
            let mut wire = Vec::new();
            network_relay_rs_core::proto::varint::encode(0, &mut wire);
            network_relay_rs_core::proto::varint::encode(length, &mut wire);
            wire.extend_from_slice(&data);
            if send.write_all(&wire).await.is_err() {
                return;
            }
        }
    }
    let _ = send.finish();
}

async fn echo(stream: &mut network_relay_rs_core::stream::Stream, bytes: &[u8]) {
    tokio::time::timeout(Duration::from_secs(5), async {
        stream.write_all(bytes).await.unwrap();
        let mut reply = vec![0; bytes.len()];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, bytes);
    })
    .await
    .expect("existing CONNECT stream stopped making progress");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn goaway_retires_cached_connection_without_aborting_admitted_flows() {
    let fixture = Fixture::start(128).await;
    let mut backend = fixture.backend();
    let client = Client::new(&fixture.config(), backend.bridge.clone()).unwrap();
    let mut first = client.open("127.0.0.1", 7, false).await.unwrap();
    let mut second = client.open("127.0.0.1", 7, false).await.unwrap();
    echo(&mut first.stream, b"before GOAWAY").await;
    echo(&mut second.stream, b"another admitted stream").await;
    assert_eq!(
        fixture.connection_count(),
        1,
        "H3 did not reuse its connection"
    );
    fixture.send_goaway().await;
    echo(&mut first.stream, b"admitted stream survives GOAWAY").await;
    let mut fresh = client.open("127.0.0.1", 7, false).await.unwrap();
    echo(&mut fresh.stream, b"fresh request uses a new connection").await;
    assert_eq!(
        fixture.connection_count(),
        2,
        "GOAWAY connection was cached"
    );
    echo(&mut second.stream, b"old second stream remains alive").await;
    drop((first, second, fresh, client));
    backend.shutdown().await;
    assert_eq!(backend.resource_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queued_http3_request_never_sends_headers_after_goaway_or_replays() {
    let fixture = Fixture::start(1).await;
    let mut backend = fixture.backend();
    let client = Arc::new(Client::new(&fixture.config(), backend.bridge.clone()).unwrap());
    let mut first = client.open("127.0.0.1", 7, false).await.unwrap();
    echo(&mut first.stream, b"admitted stream zero").await;
    let owner = client.clone();
    let pending = tokio::spawn(async move { owner.open("127.0.0.1", 7, false).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !pending.is_finished(),
        "request bypassed the stream credit limit"
    );
    fixture.send_goaway().await;
    echo(&mut first.stream, b"GOAWAY does not abort this stream").await;
    drop(first);
    let result = tokio::time::timeout(Duration::from_secs(5), pending)
        .await
        .expect("queued request stayed blocked after stream capacity returned")
        .unwrap();
    assert!(result.is_err(), "queued request was sent after GOAWAY");
    assert_eq!(fixture.connection_count(), 1, "queued CONNECT was replayed");
    assert_eq!(fixture.request_ids(0), [0], "post-GOAWAY HEADERS were sent");
    let mut fresh = client.open("127.0.0.1", 7, false).await.unwrap();
    echo(&mut fresh.stream, b"distinct new request").await;
    assert_eq!(fixture.connection_count(), 2);
    drop((fresh, client));
    backend.shutdown().await;
    assert_eq!(backend.resource_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn draining_connections_remain_bounded_and_release_capacity_on_drop() {
    let fixture = Fixture::start(128).await;
    let mut backend = fixture.backend();
    let client = Arc::new(Client::new(&fixture.config(), backend.bridge.clone()).unwrap());
    let mut flows = Vec::new();
    for generation in 0..4 {
        let mut flow = client.open("127.0.0.1", 7, false).await.unwrap();
        echo(&mut flow.stream, &[generation]).await;
        flows.push(flow);
        fixture.send_goaway().await;
    }
    assert_eq!(fixture.connection_count(), 4);
    let owner = client.clone();
    let pending = tokio::spawn(async move { owner.open("127.0.0.1", 7, false).await });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !pending.is_finished(),
        "unbounded draining connections were created"
    );
    assert_eq!(fixture.connection_count(), 4);
    for flow in &mut flows {
        echo(&mut flow.stream, b"draining connection remains usable").await;
    }
    drop(flows.remove(0));
    let mut fresh = tokio::time::timeout(Duration::from_secs(5), pending)
        .await
        .expect("dropping a draining flow did not release connection capacity")
        .unwrap()
        .unwrap();
    echo(&mut fresh.stream, b"capacity recovered").await;
    assert_eq!(fixture.connection_count(), 5);
    drop((flows, fresh, client));
    backend.shutdown().await;
    assert_eq!(backend.resource_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelling_a_stream_credit_wait_preserves_connection_and_next_request() {
    let fixture = Fixture::start(1).await;
    let mut backend = fixture.backend();
    let client = Arc::new(Client::new(&fixture.config(), backend.bridge.clone()).unwrap());
    let mut first = client.open("127.0.0.1", 7, false).await.unwrap();
    echo(&mut first.stream, b"first stream owns available credit").await;
    let owner = client.clone();
    let pending = tokio::spawn(async move { owner.open("127.0.0.1", 7, false).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!pending.is_finished(), "request bypassed stream credit");
    pending.abort();
    assert!(matches!(pending.await, Err(error) if error.is_cancelled()));
    echo(
        &mut first.stream,
        b"cancelling a waiter must not close its connection",
    )
    .await;
    assert_eq!(fixture.request_ids(0), [0], "cancelled waiter sent HEADERS");
    drop(first);
    let mut fresh =
        tokio::time::timeout(Duration::from_secs(5), client.open("127.0.0.1", 7, false))
            .await
            .expect("cancelled stream-credit waiter blocked subsequent requests")
            .unwrap();
    echo(
        &mut fresh.stream,
        b"a distinct request acquires released capacity",
    )
    .await;
    assert_eq!(
        fixture.connection_count(),
        1,
        "cancellation discarded the connection"
    );
    assert_eq!(fixture.request_ids(0), [0, 4]);
    drop((fresh, client));
    backend.shutdown().await;
    assert_eq!(backend.resource_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn automatic_mode_does_not_replay_submitted_connect_when_response_is_slow() {
    let fixture = Fixture::start_with_response_delay(128, Duration::from_secs(6)).await;
    // A fully functioning H2 endpoint on the same address makes a forbidden
    // post-HEADERS fallback succeed, rather than hiding it behind a TCP error.
    let listener = tokio::net::TcpListener::bind(fixture.address)
        .await
        .unwrap();
    let certificates = CertificateDer::pem_file_iter(fixture.directory.join("cert.pem"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_file(fixture.directory.join("key.pem")).unwrap();
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certificates, key)
    .unwrap();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let tcp_requests = Arc::new(AtomicUsize::new(0));
    let observed = tcp_requests.clone();
    let tcp_server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(socket).await.unwrap();
        let mut connection = h2::server::handshake(tls).await.unwrap();
        if let Some(Ok((request, mut response))) = connection.accept().await {
            assert_eq!(request.method(), http::Method::CONNECT);
            observed.fetch_add(1, Ordering::Relaxed);
            let _send = response
                .send_response(
                    http::Response::builder().status(200).body(()).unwrap(),
                    false,
                )
                .unwrap();
            while connection.accept().await.is_some() {}
        }
    });
    let mut backend = fixture.backend();
    let mut config = fixture.config();
    config.transport = "auto".into();
    let client = Client::new(&config, backend.bridge.clone()).unwrap();
    let mut opened =
        tokio::time::timeout(Duration::from_secs(12), client.open("127.0.0.1", 7, false))
            .await
            .expect("slow accepted H3 request did not complete")
            .unwrap();
    assert_eq!(
        opened.transport, "HTTP/3",
        "submitted CONNECT fell back to TCP"
    );
    assert_eq!(
        tcp_requests.load(Ordering::Relaxed),
        0,
        "CONNECT was replayed on H2"
    );
    assert_eq!(fixture.request_ids(0), [0]);
    echo(&mut opened.stream, b"delayed H3 tunnel remains usable").await;
    drop((opened, client));
    backend.shutdown().await;
    assert_eq!(backend.resource_count(), 0);
    tcp_server.abort();
    let _ = tcp_server.await;
}

/// Forwards QUIC datagrams between clients and the fixture. Silencing drops
/// every later datagram of the clients seen so far, in both directions, as a
/// server that crashed or restarted without CONNECTION_CLOSE would; clients
/// from new addresses are still forwarded.
struct SilenceablePath {
    address: SocketAddr,
    seen: Arc<Mutex<Vec<SocketAddr>>>,
    blocked: Arc<Mutex<Vec<SocketAddr>>>,
    task: JoinHandle<()>,
}

impl SilenceablePath {
    async fn start(server: SocketAddr) -> Self {
        let front = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let address = front.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let blocked = Arc::new(Mutex::new(Vec::<SocketAddr>::new()));
        let (known, dropped) = (seen.clone(), blocked.clone());
        let task = tokio::spawn(async move {
            let mut upstreams =
                std::collections::HashMap::<SocketAddr, Arc<tokio::net::UdpSocket>>::new();
            let mut workers = JoinSet::new();
            let mut buffer = vec![0; 65535];
            while let Ok((length, client)) = front.recv_from(&mut buffer).await {
                if dropped.lock().unwrap().contains(&client) {
                    continue;
                }
                let upstream = match upstreams.entry(client) {
                    std::collections::hash_map::Entry::Occupied(entry) => entry.get().clone(),
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        let upstream =
                            Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
                        upstream.connect(server).await.unwrap();
                        known.lock().unwrap().push(client);
                        let (reply, front, dropped) =
                            (upstream.clone(), front.clone(), dropped.clone());
                        workers.spawn(async move {
                            let mut buffer = vec![0; 65535];
                            while let Ok(length) = reply.recv(&mut buffer).await {
                                if !dropped.lock().unwrap().contains(&client) {
                                    let _ = front.send_to(&buffer[..length], client).await;
                                }
                            }
                        });
                        entry.insert(upstream).clone()
                    }
                };
                let _ = upstream.send(&buffer[..length]).await;
            }
        });
        Self {
            address,
            seen,
            blocked,
            task,
        }
    }

    fn silence_existing_connections(&self) {
        let seen = self.seen.lock().unwrap().clone();
        self.blocked.lock().unwrap().extend(seen);
    }
}

impl Drop for SilenceablePath {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silently_dead_connection_is_replaced_for_the_next_flow() {
    let fixture = Fixture::start(128).await;
    let path = SilenceablePath::start(fixture.address).await;
    let mut backend = fixture.backend();
    let mut config = fixture.config();
    config.uri_template = format!(
        "https://{}/.well-known/masque/udp/{{target_host}}/{{target_port}}/",
        path.address
    );
    let client = Client::new(&config, backend.bridge.clone()).unwrap();
    let mut first = client.open("127.0.0.1", 7, false).await.unwrap();
    echo(&mut first.stream, b"before the server goes silent").await;
    let started = tokio::time::Instant::now();
    path.silence_existing_connections();
    // One keep-alive interval passes before a PING, then the idle timeout:
    // at most 40 seconds, as for the HTTP/2 PING keepalive. No
    // CONNECTION_CLOSE or stateless reset arrives in the meantime.
    tokio::time::sleep_until(started + Duration::from_secs(42)).await;
    let mut fresh =
        tokio::time::timeout(Duration::from_secs(15), client.open("127.0.0.1", 7, false))
            .await
            .expect("a new flow waited on the silent connection")
            .unwrap();
    echo(&mut fresh.stream, b"a new connection carries the next flow").await;
    assert_eq!(fixture.connection_count(), 2);
    drop((first, fresh, client));
    backend.shutdown().await;
    assert_eq!(backend.resource_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pending_udp_settings_allow_tcp_and_the_first_frame_decides_capability() {
    for (frame, enabled) in [
        (&[0, 4, 0][..], false),
        (&[0, 4, 2, 8, 0][..], false),
        (&[0, 4, 2, 8, 1][..], true),
    ] {
        let fixture = Fixture::start_with_settings(128, Duration::ZERO, None).await;
        let mut backend = fixture.backend();
        let client = Client::new(&fixture.config(), backend.bridge.clone()).unwrap();
        let first = client.open("127.0.0.1", 7, false).await.unwrap();
        let udp = client.open("127.0.0.1", 7, true);
        tokio::pin!(udp);
        tokio::select! {
            _ = &mut udp => panic!("UDP did not wait for SETTINGS"),
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
        let mut tcp =
            tokio::time::timeout(Duration::from_secs(2), client.open("127.0.0.1", 7, false))
                .await
                .expect("pending UDP negotiation blocked ordinary CONNECT")
                .unwrap();
        echo(&mut tcp.stream, b"before SETTINGS").await;
        fixture.settings_frame.send_replace(Some(frame));
        let result = tokio::time::timeout(Duration::from_secs(2), udp)
            .await
            .expect("waited after definitive SETTINGS");
        if enabled {
            let mut flow = result.unwrap();
            // Context zero DATAGRAM Capsule carrying one application byte.
            echo(&mut flow.stream, &[0, 2, 0, 42]).await;
        } else {
            let error = result.err().expect("unsupported CONNECT-UDP succeeded");
            assert!(
                format!("{error:#}").contains("did not enable HTTP/3 Extended CONNECT"),
                "{error:#}"
            );
        }
        echo(&mut tcp.stream, b"after SETTINGS").await;
        assert_eq!(
            fixture.request_ids(0),
            if enabled { vec![0, 4, 8] } else { vec![0, 4] }
        );
        drop((first, tcp));
        backend.shutdown().await;
    }
}
