//! Exact UDP payload counters through the production SOCKS runner and Rust
//! TCP/TLS/UDP backend, using only a disposable loopback relay fixture.
use network_relay_rs_core as relay;
use relay::{Config, Socks, client::Client, proto};
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
    net::{TcpListener, TcpStream, UdpSocket},
    task::{JoinHandle, JoinSet},
};

const WAIT: Duration = Duration::from_secs(10);
const TARGET_PORT: u16 = 53;
const REJECTED_PORT: u16 = 54;
const DNS_QUERY: &[u8] =
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
const DNS_ANSWER: &[u8] = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xcb\x00\x71\x07";
static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    address: SocketAddr,
    directory: PathBuf,
    rejected: Arc<AtomicUsize>,
    admitted: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}
impl Fixture {
    async fn start() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "relay-rs-udp-traffic-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed),
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
        openssl(&[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-sha256",
            "-days",
            "2",
            "-subj",
            "/CN=Disposable traffic CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            "ca-key.pem",
            "-out",
            "ca.pem",
        ]);
        openssl(&[
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
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
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n\
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
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let rejected = Arc::new(AtomicUsize::new(0));
        let admitted = Arc::new(AtomicUsize::new(0));
        let rejected_count = rejected.clone();
        let admitted_count = admitted.clone();
        let task = tokio::spawn(async move {
            let mut sessions = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (socket, _) = accepted.unwrap();
                        let acceptor = acceptor.clone();
                        let rejected = rejected_count.clone();
                        let admitted = admitted_count.clone();
                        sessions.spawn(async move {
                            let mut tls = acceptor.accept(socket).await?;
                            let mut headers = Vec::new();
                            while !headers.ends_with(b"\r\n\r\n") {
                                headers.push(tls.read_u8().await?);
                                anyhow::ensure!(headers.len() < 8192, "fixture headers too large");
                            }
                            let headers = String::from_utf8(headers)?;
                            anyhow::ensure!(headers.lines().any(|line| line.eq_ignore_ascii_case(
                                &format!("Host: relay.test:{}", address.port())
                            )), "the pinned IP replaced the HTTP relay host");
                            let request = headers.lines().next().unwrap();
                            anyhow::ensure!(request.starts_with("GET "), "expected CONNECT-UDP Upgrade");
                            if request.contains(&format!("/{REJECTED_PORT}/ ")) {
                                tls.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").await?;
                                tls.flush().await?;
                                rejected.fetch_add(1, Ordering::SeqCst);
                                return Ok::<_, anyhow::Error>(());
                            }
                            tls.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n").await?;
                            tls.flush().await?;
                            if request.contains(&format!("/{TARGET_PORT}/ ")) {
                                admitted.fetch_add(1, Ordering::SeqCst);
                            }
                            let mut decoder = proto::CapsuleDecoder::default();
                            let mut buffer = [0; 4096];
                            loop {
                                let count = tls.read(&mut buffer).await?;
                                if count == 0 { return Ok(()); }
                                decoder.push(&buffer[..count]);
                                while let Some(capsule) = decoder.next_udp_capsule()? {
                                    let mut payload = &capsule.value[..];
                                    anyhow::ensure!(proto::varint::decode(&mut payload)? == 0, "unexpected UDP context");
                                    let response = response(payload);
                                    let mut value = vec![0];
                                    value.extend_from_slice(&response);
                                    let mut wire = bytes::BytesMut::new();
                                    proto::capsule::encode(0, &value, &mut wire);
                                    tls.write_all(&wire).await?;
                                    tls.flush().await?;
                                }
                            }
                        });
                    }
                    _ = sessions.join_next(), if !sessions.is_empty() => {}
                }
            }
        });
        Self {
            address,
            directory,
            rejected,
            admitted,
            task,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn response(payload: &[u8]) -> Vec<u8> {
    if payload == DNS_QUERY {
        return DNS_ANSWER.to_vec();
    }
    if payload.is_empty() {
        vec![]
    } else {
        // Unequal directional totals catch reversed counters as well as
        // accidentally counting SOCKS headers or Capsule framing.
        let mut response = b"reply:".to_vec();
        response.extend_from_slice(payload);
        response
    }
}
fn packet(port: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, 0, 0, 3, 12];
    packet.extend_from_slice(b"example.test");
    packet.extend_from_slice(&port.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}
async fn association(address: SocketAddr) -> (TcpStream, SocketAddr) {
    let mut control = TcpStream::connect(address).await.unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0; 2];
    control.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0]);
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    let address = SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    (control, address)
}
fn totals(client: &Client) -> (u64, u64) {
    let snapshot = client.bridge.traffic.snapshot();
    (snapshot.upload_bytes, snapshot.download_bytes)
}
async fn expect_totals(client: &Client, expected: (u64, u64)) {
    tokio::time::timeout(WAIT, async {
        loop {
            let actual = totals(client);
            assert!(
                actual.0 <= expected.0 && actual.1 <= expected.1,
                "counted framing or rejected bytes: {actual:?}, expected {expected:?}"
            );
            if actual == expected {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("payload totals {:?}, expected {expected:?}", totals(client)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks_udp_counts_only_successfully_forwarded_payload() {
    tokio::time::timeout(Duration::from_secs(30), exercise())
        .await
        .expect("UDP traffic fixture stalled");
}
async fn exercise() {
    let fixture = Fixture::start().await;
    let mut backend = relay::backend::Backend::start(relay::backend::BackendOptions {
        ca_file: Some(fixture.directory.join("ca.pem")),
    })
    .unwrap();
    let config = Config {
        uri_template: format!(
            "https://{}/.well-known/masque/udp/{{target_host}}/{{target_port}}/",
            fixture.address
        ),
        username: "alice".into(),
        password: "disposable-traffic-fixture-password".into(),
        server_name: Some("relay.test".into()),
        transport: "http/1.1".into(),
        probe_target: "127.0.0.1:9".parse().unwrap(),
        mode: "socks".into(),
        socks: Socks {
            listen: vec!["127.0.0.1:0".parse().unwrap()],
        },
    };
    let client = Arc::new(Client::new(&config, backend.bridge.clone()).unwrap());
    let listener = backend.bridge.listen(config.socks.listen[0]).await.unwrap();
    let address = listener.local_addr().unwrap();
    let worker = tokio::spawn(relay::socks::run(client.clone(), vec![listener]));
    let mut status = backend.status.clone();
    while status.borrow_and_update().0 != 1 {
        status.changed().await.unwrap();
    }
    let (control, association) = association(address).await;
    let local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert_eq!(
        totals(&client),
        (0, 0),
        "SOCKS and readiness handshakes are not payload"
    );

    let mut fragmented = packet(TARGET_PORT, b"discarded fragment");
    fragmented[2] = 1;
    local.send_to(&fragmented, association).await.unwrap();
    let mut buffer = [0; 4096];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), local.recv_from(&mut buffer))
            .await
            .is_err()
    );
    assert_eq!(
        fixture.admitted.load(Ordering::SeqCst),
        0,
        "a fragment must not open a relay flow"
    );
    assert_eq!(
        totals(&client),
        (0, 0),
        "discarded fragments are not payload"
    );

    let mut expected = (0, 0);
    for payload in [0, 1, 63, 1025]
        .into_iter()
        .map(|size| {
            (0..size)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>()
        })
        .chain(std::iter::once(DNS_QUERY.to_vec()))
    {
        local
            .send_to(&packet(TARGET_PORT, &payload), association)
            .await
            .unwrap();
        let (count, source) = tokio::time::timeout(WAIT, local.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let response = response(&payload);
        assert_eq!(source, association);
        assert_eq!(&buffer[..count], packet(TARGET_PORT, &response));
        expected.0 += payload.len() as u64;
        expected.1 += response.len() as u64;
        expect_totals(&client, expected).await;
    }
    assert_ne!(expected.0, expected.1);
    assert_eq!(
        fixture.admitted.load(Ordering::SeqCst),
        1,
        "one target reuses one UDP flow"
    );

    local
        .send_to(&packet(REJECTED_PORT, b"never admitted"), association)
        .await
        .unwrap();
    tokio::time::timeout(WAIT, async {
        while fixture.rejected.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("rejected target was never attempted");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), local.recv_from(&mut buffer))
            .await
            .is_err()
    );
    assert_eq!(
        totals(&client),
        expected,
        "payload queued for a rejected tunnel is not forwarded"
    );

    drop(control);
    worker.abort();
    let _ = worker.await;
    assert_eq!(
        totals(&client),
        expected,
        "closing the association retains payload totals"
    );
    backend.shutdown().await;
}
