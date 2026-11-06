//! HTTP/2 connection sharing through the production Rust backend. The
//! loopback relay counts outer TCP connections, so a flow that silently opens
//! its own connection cannot pass as a shared one.
use bytes::Bytes;
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
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::watch,
    task::{JoinHandle, JoinSet},
};

static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);
/// Target port whose tunnel sends this many bytes at once and never reads.
const FLOOD_PORT: u16 = 19;
const FLOOD: usize = 3 << 20;

struct Fixture {
    address: SocketAddr,
    directory: PathBuf,
    task: JoinHandle<()>,
    connections: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
    // 1 asks every connection for a graceful GOAWAY; 2 drops every connection;
    // 3 stops reading every connection while keeping TCP open, as a network
    // path that silently stopped carrying packets.
    control: watch::Sender<u64>,
}

impl Fixture {
    async fn start() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "relay-rs-h2-share-{}-{}",
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
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let (control, _) = watch::channel(0);
        let (counted, requested, notices) =
            (connections.clone(), requests.clone(), control.clone());
        let task = tokio::spawn(async move {
            let mut workers = JoinSet::new();
            loop {
                tokio::select! {
                    _ = workers.join_next(), if !workers.is_empty() => {},
                    accepted = listener.accept() => {
                        let Ok((tcp, _)) = accepted else { break };
                        counted.fetch_add(1, Ordering::SeqCst);
                        let acceptor = acceptor.clone();
                        let requested = requested.clone();
                        let notices = notices.subscribe();
                        workers.spawn(serve(acceptor, tcp, requested, notices));
                    }
                }
            }
        });
        Self {
            address,
            directory,
            task,
            connections,
            requests,
            control,
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
            transport: "h2".into(),
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
        self.connections.load(Ordering::SeqCst)
    }

    async fn signal(&self, action: u64) {
        self.control.send_replace(action);
        // Let the GOAWAY frame or the closed TCP connection reach the
        // client's connection task before a subsequent distinct request.
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

async fn serve(
    acceptor: tokio_rustls::TlsAcceptor,
    tcp: tokio::net::TcpStream,
    requests: Arc<AtomicUsize>,
    mut notices: watch::Receiver<u64>,
) {
    let Ok(tls) = acceptor.accept(tcp).await else {
        return;
    };
    let mut builder = h2::server::Builder::new();
    builder.enable_connect_protocol();
    let Ok(mut connection) = builder.handshake::<_, Bytes>(tls).await else {
        return;
    };
    let mut streams = JoinSet::new();
    let frozen = loop {
        tokio::select! {
            _ = streams.join_next(), if !streams.is_empty() => {},
            changed = notices.changed() => {
                if changed.is_err() { return; }
                match *notices.borrow_and_update() {
                    1 => connection.graceful_shutdown(),
                    3 => break true,
                    // Dropping the connection and its streams closes TCP.
                    _ => return,
                }
            },
            next = connection.accept() => match next {
                Some(Ok((request, respond))) => {
                    requests.fetch_add(1, Ordering::SeqCst);
                    streams.spawn(tunnel(request, respond));
                }
                _ => break false,
            }
        }
    };
    if frozen {
        // Keep the connection and its streams without polling them.
        std::future::pending::<()>().await;
    }
    // A gracefully closed connection keeps serving admitted streams.
    while streams.join_next().await.is_some() {}
}

async fn tunnel(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
) {
    let udp = request.extensions().get::<h2::ext::Protocol>().is_some();
    if udp {
        assert_eq!(
            request.uri().host(),
            Some("relay.test"),
            "pinned IP replaced relay :authority"
        );
    }
    let flood = request.uri().port_u16() == Some(FLOOD_PORT);
    let mut response = http::Response::builder().status(200);
    if udp {
        response = response.header("capsule-protocol", "?1");
    }
    let Ok(mut send) = respond.send_response(response.body(()).unwrap(), false) else {
        return;
    };
    let mut recv = request.into_body();
    if flood {
        // h2 queues the data and releases it as the client grants credit.
        let _ = send.send_data(Bytes::from(vec![0; FLOOD]), false);
        while let Some(Ok(_)) = recv.data().await {}
        return;
    }
    while let Some(Ok(data)) = recv.data().await {
        let _ = recv.flow_control().release_capacity(data.len());
        if send.send_data(data, false).is_err() {
            return;
        }
    }
    let _ = send.send_data(Bytes::new(), true);
}

async fn echo(stream: &mut network_relay_rs_core::stream::Stream, bytes: &[u8]) {
    tokio::time::timeout(Duration::from_secs(5), async {
        stream.write_all(bytes).await.unwrap();
        let mut reply = vec![0; bytes.len()];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, bytes);
    })
    .await
    .expect("CONNECT stream stopped making progress");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_tcp_and_udp_flows_share_one_connection() {
    let fixture = Fixture::start().await;
    let mut backend = fixture.backend();
    let client = Arc::new(Client::new(&fixture.config(), backend.bridge.clone()).unwrap());
    // More flows than network-relay's default 64 connections per client
    // address, opened concurrently so they race for the first session.
    let mut opening = JoinSet::new();
    for _ in 0..70 {
        let client = client.clone();
        opening.spawn(async move { client.open("127.0.0.1", 7, false).await });
    }
    let mut flows = Vec::new();
    while let Some(opened) = opening.join_next().await {
        let opened = opened.unwrap().unwrap();
        assert_eq!(opened.transport, "HTTP/2");
        flows.push(opened);
    }
    flows.push(client.open("127.0.0.1", 53, true).await.unwrap());
    for (index, flow) in flows.iter_mut().enumerate() {
        echo(&mut flow.stream, format!("flow {index}").as_bytes()).await;
    }
    assert_eq!(fixture.connection_count(), 1, "HTTP/2 flows did not share");
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 71);
    drop((flows, client));
    backend.shutdown().await;
    assert_eq!(backend.resource_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn goaway_retires_cached_connection_without_aborting_admitted_flows() {
    let fixture = Fixture::start().await;
    let mut backend = fixture.backend();
    let client = Client::new(&fixture.config(), backend.bridge.clone()).unwrap();
    let mut first = client.open("127.0.0.1", 7, false).await.unwrap();
    let mut second = client.open("127.0.0.1", 7, false).await.unwrap();
    echo(&mut first.stream, b"before GOAWAY").await;
    echo(&mut second.stream, b"another admitted stream").await;
    assert_eq!(fixture.connection_count(), 1);
    fixture.signal(1).await;
    echo(&mut first.stream, b"admitted stream survives GOAWAY").await;
    let mut fresh = client.open("127.0.0.1", 7, false).await.unwrap();
    echo(&mut fresh.stream, b"fresh request uses a new connection").await;
    assert_eq!(
        fixture.connection_count(),
        2,
        "GOAWAY connection was reused"
    );
    echo(&mut second.stream, b"old second stream remains alive").await;
    assert_eq!(
        fixture.requests.load(Ordering::SeqCst),
        3,
        "a request was replayed"
    );
    drop((first, second, fresh, client));
    backend.shutdown().await;
    assert_eq!(backend.resource_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lost_connection_is_replaced_for_the_next_flow() {
    let fixture = Fixture::start().await;
    let mut backend = fixture.backend();
    let client = Client::new(&fixture.config(), backend.bridge.clone()).unwrap();
    let mut first = client.open("127.0.0.1", 7, false).await.unwrap();
    echo(&mut first.stream, b"before the connection is lost").await;
    fixture.signal(2).await;
    let mut lost = [0; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), first.stream.read(&mut lost)).await;
    assert!(
        !matches!(read, Ok(Ok(1..))),
        "a flow on the lost connection received data"
    );
    let mut fresh = client.open("127.0.0.1", 7, false).await.unwrap();
    echo(&mut fresh.stream, b"a new connection carries the next flow").await;
    assert_eq!(fixture.connection_count(), 2);
    drop((first, fresh, client));
    backend.shutdown().await;
    assert_eq!(backend.resource_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unread_flows_do_not_stall_other_flows_on_the_connection() {
    let fixture = Fixture::start().await;
    let mut backend = fixture.backend();
    let client = Client::new(&fixture.config(), backend.bridge.clone()).unwrap();
    // Each unread flow fills its whole 2 MiB stream window. Four of them
    // exceed the 5 MiB connection window an unshared connection used.
    let mut unread = Vec::new();
    for _ in 0..4 {
        unread.push(client.open("127.0.0.1", FLOOD_PORT, false).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut active = client.open("127.0.0.1", 7, false).await.unwrap();
    echo(&mut active.stream, &vec![7; 256 << 10]).await;
    assert_eq!(fixture.connection_count(), 1);
    let mut first = vec![0; FLOOD];
    tokio::time::timeout(
        Duration::from_secs(5),
        unread[0].stream.read_exact(&mut first),
    )
    .await
    .expect("a stalled flow did not resume")
    .unwrap();
    drop((unread, active, client));
    backend.shutdown().await;
    assert_eq!(backend.resource_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silently_dead_connection_is_replaced_after_unanswered_ping() {
    let fixture = Fixture::start().await;
    let mut backend = fixture.backend();
    let client = Client::new(&fixture.config(), backend.bridge.clone()).unwrap();
    let started = tokio::time::Instant::now();
    let mut first = client.open("127.0.0.1", 7, false).await.unwrap();
    echo(&mut first.stream, b"before the path goes silent").await;
    fixture.signal(3).await;
    // One PING interval passes before a PING, and another before it counts
    // as unanswered. TCP reports no error in the meantime.
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
