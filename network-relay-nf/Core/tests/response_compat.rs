//! Controlled loopback TLS responses through the production protocol client
//! and the test-only native transport emulator. No external relay is required.
mod support;

use bytes::{Bytes, BytesMut};
use network_relay_nf_core::{
    Config,
    client::{Client, UdpFlow},
    proto,
};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PAYLOAD: &[u8] = b"established tunnel payload";
const UPLOAD: &[u8] = b"client half-close still permits server-to-client bytes";
static FIXTURE_ID: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    tls: rustls::ServerConfig,
    ca: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["relay.test".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let ca = std::env::temp_dir().join(format!(
            "relay-nf-response-compat-{}-{}.pem",
            std::process::id(),
            FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&ca, cert.pem()).unwrap();
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls_pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
        .unwrap();
        Self { tls, ca }
    }

    fn settings(&self, address: SocketAddr, transport: &str) -> Config {
        Config {
            uri_template: format!(
                "https://{address}/.well-known/masque/udp/{{target_host}}/{{target_port}}/"
            ),
            username: "alice".into(),
            password: "disposable-fixture-password".into(),
            server_name: Some("relay.test".into()),
            transport: transport.into(),
            probe_target: "127.0.0.1:9".parse().unwrap(),
            mode: "socks".into(),
            socks: network_relay_nf_core::Socks {
                listen: vec!["127.0.0.1:0".parse().unwrap()],
                gssapi_keytab: None,
                gssapi_principals: Vec::new(),
            },
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.ca);
    }
}

#[derive(Debug)]
struct Case {
    status: u16,
    udp: bool,
    headers: Vec<(&'static str, &'static str)>,
    accepted: bool,
}

fn qpack_integer(bytes: &mut Vec<u8>, prefix: u8, bits: u8, value: usize) {
    let mask = (1 << bits) - 1;
    bytes.push(prefix | value.min(mask) as u8);
    if value >= mask {
        let mut rest = value - mask;
        while rest >= 128 {
            bytes.push((rest as u8 & 127) | 128);
            rest >>= 7;
        }
        bytes.push(rest as u8);
    }
}

/// QPACK literal names and values, with neither Huffman nor dynamic entries.
fn h3_response(case: &Case, payload: &[u8]) -> Vec<u8> {
    let mut fields = vec![0, 0]; // Required Insert Count and Delta Base.
    let status = case.status.to_string();
    for (name, value) in
        std::iter::once((":status", status.as_str())).chain(case.headers.iter().copied())
    {
        qpack_integer(&mut fields, 0x20, 3, name.len());
        fields.extend_from_slice(name.as_bytes());
        qpack_integer(&mut fields, 0, 7, value.len());
        fields.extend_from_slice(value.as_bytes());
    }
    let mut wire = BytesMut::new();
    proto::varint::encode(1, &mut wire); // HEADERS.
    proto::varint::encode(fields.len() as u64, &mut wire);
    wire.extend_from_slice(&fields);
    proto::varint::encode(0, &mut wire); // DATA.
    proto::varint::encode(payload.len() as u64, &mut wire);
    wire.extend_from_slice(payload);
    wire.to_vec()
}

async fn exercise(fixture: &Fixture, transport: &str, case: Case) {
    let payload = if case.udp {
        let mut wire = BytesMut::new();
        let value = [&[0][..], PAYLOAD].concat();
        proto::capsule::encode(0, &value, &mut wire);
        wire.to_vec()
    } else {
        PAYLOAD.to_vec()
    };
    let mut tls = fixture.tls.clone();
    tls.alpn_protocols = vec![transport.as_bytes().to_vec()];
    let status = case.status;
    let udp = case.udp;
    let headers = case.headers.clone();
    let (address, responder, endpoint) = if transport == "h3" {
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(crypto)),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        let accepting = endpoint.clone();
        let response = h3_response(&case, &payload);
        let responder = tokio::spawn(async move {
            let connection = accepting.accept().await.unwrap().await.unwrap();
            let mut control = connection.open_uni().await.unwrap();
            // Control stream: SETTINGS_ENABLE_CONNECT_PROTOCOL = 1.
            control.write_all(&[0, 4, 2, 8, 1]).await.unwrap();
            let (mut send, _recv) = connection.accept_bi().await.unwrap();
            send.write_all(&response).await.unwrap();
            let _ = connection.closed().await;
        });
        (address, responder, Some(endpoint))
    } else {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let h1 = transport == "http/1.1";
        let responder = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(tls))
                .accept(tcp)
                .await
                .unwrap();
            if h1 {
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    assert!(request.len() < 16384);
                    request.push(tls.read_u8().await.unwrap());
                }
                assert!(request.starts_with(if udp { b"GET " } else { b"CONNECT " }));
                let mut response = format!("HTTP/1.1 {status} fixture\r\n");
                for (name, value) in headers {
                    response.push_str(&format!("{name}: {value}\r\n"));
                }
                response.push_str("\r\n");
                // Coalesce the response and first tunnel bytes in one write.
                tls.write_all(&[response.as_bytes(), &payload].concat())
                    .await
                    .unwrap();
                if !udp && (200..300).contains(&status) {
                    let mut received = Vec::new();
                    tls.read_to_end(&mut received).await.unwrap();
                    assert_eq!(received, UPLOAD);
                    tls.write_all(&received).await.unwrap();
                    tls.shutdown().await.unwrap();
                } else {
                    let mut read = [0; 1];
                    let _ = tls.read(&mut read).await;
                }
            } else {
                let mut builder = h2::server::Builder::new();
                builder.enable_connect_protocol();
                let mut connection = builder.handshake::<_, Bytes>(tls).await.unwrap();
                let (request, mut respond) = connection.accept().await.unwrap().unwrap();
                assert_eq!(request.method(), http::Method::CONNECT);
                assert_eq!(
                    request.extensions().get::<h2::ext::Protocol>().is_some(),
                    udp
                );
                let mut response = http::Response::builder().status(status);
                for (name, value) in headers {
                    response = response.header(name, value);
                }
                let mut send = respond
                    .send_response(response.body(()).unwrap(), false)
                    .unwrap();
                send.send_data(payload.into(), false).unwrap();
                let _ = connection.accept().await;
            }
        });
        (address, responder, None)
    };

    let backend = support::Backend::start(fixture.ca.clone());
    let settings = fixture.settings(address, transport);
    let client = Client::new(&settings, backend.bridge.clone()).unwrap();
    let result = client.open("127.0.0.1", 7, case.udp).await;
    assert_eq!(
        result.is_ok(),
        case.accepted,
        "{transport} {case:?}: {:?}",
        result.as_ref().err()
    );
    // Open again is intentionally unnecessary: these bytes are on the exact
    // stream whose response established the tunnel.
    if let Ok(mut opened) = result {
        if case.udp {
            let mut flow = UdpFlow::new(opened.stream);
            assert_eq!(flow.recv().await.unwrap().unwrap().as_ref(), PAYLOAD);
        } else {
            let mut received = vec![0; PAYLOAD.len()];
            opened.stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, PAYLOAD);
            if transport == "http/1.1" {
                opened.stream.write_all(UPLOAD).await.unwrap();
                opened.stream.shutdown().await.unwrap();
                let mut echoed = Vec::new();
                opened.stream.read_to_end(&mut echoed).await.unwrap();
                assert_eq!(echoed, UPLOAD);
            }
        }
    }
    drop(backend);
    responder.abort();
    drop(endpoint);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controlled_tls_connect_response_matrix() {
    let fixture = Fixture::new();
    for transport in ["http/1.1", "h2", "h3"] {
        let mut cases = Vec::new();
        for status in [200, 201, 202, 204, 205, 206, 299, 300, 403, 503] {
            cases.push(Case {
                status,
                udp: false,
                headers: vec![],
                accepted: status < 300,
            });
        }
        let successful = if transport == "http/1.1" { 101 } else { 201 };
        let upgrade = if transport == "http/1.1" {
            vec![
                ("connection", "keep-alive, uPgRaDe"),
                ("upgrade", "connect-udp"),
            ]
        } else {
            vec![]
        };
        for values in [
            vec![],
            vec!["?1"],
            vec!["?1;future=token;flag;quoted=\"a,b\""],
            vec!["?0"],
            vec!["token"],
            vec!["?1junk"],
            vec!["?1;broken=\""],
            vec!["?1, ?1"],
            vec!["?1", "?1"],
            vec!["?0", "?1"],
        ] {
            let mut headers = upgrade.clone();
            headers.extend(
                values
                    .into_iter()
                    .map(|v| (proto::CAPSULE_PROTOCOL_HEADER, v)),
            );
            cases.push(Case {
                status: successful,
                udp: true,
                headers,
                accepted: true,
            });
        }
        for status in [204, 205, 206, 300, 403, 503] {
            cases.push(Case {
                status,
                udp: true,
                headers: upgrade.clone(),
                accepted: false,
            });
        }
        for field in [
            ("content-length", "0"),
            ("content-type", "application/octet-stream"),
            ("transfer-encoding", "chunked"),
        ] {
            // h2's server API refuses Transfer-Encoding before any response
            // reaches the client. Raw HTTP/1.1 and HTTP/3 plus unit tests
            // cover that forbidden field without a false-positive fixture.
            if transport == "h2" && field.0 == "transfer-encoding" {
                continue;
            }
            let mut headers = upgrade.clone();
            headers.push(field);
            cases.push(Case {
                status: successful,
                udp: true,
                headers,
                accepted: false,
            });
        }
        if transport == "http/1.1" {
            for headers in [
                vec![("connection", "Upgrade")],
                vec![("upgrade", "connect-udp")],
                vec![("connection", "keep-alive"), ("upgrade", "connect-udp")],
                vec![("connection", "Upgrade"), ("upgrade", "other")],
                vec![("connection", "Upgrade"), ("upgrade", "connect-udp, other")],
                vec![
                    ("connection", "Upgrade"),
                    ("upgrade", "connect-udp"),
                    ("upgrade", "connect-udp"),
                ],
            ] {
                cases.push(Case {
                    status: 101,
                    udp: true,
                    headers,
                    accepted: false,
                });
            }
            cases.push(Case {
                status: 200,
                udp: true,
                headers: upgrade,
                accepted: false,
            });
        }
        for case in cases {
            tokio::time::timeout(Duration::from_secs(10), exercise(&fixture, transport, case))
                .await
                .expect("controlled TLS response timed out");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controlled_tls_capsule_parameters_are_advisory() {
    let fixture = Fixture::new();
    for transport in ["http/1.1", "h2", "h3"] {
        let mut headers = vec![(proto::CAPSULE_PROTOCOL_HEADER, "?1;future=token;flag")];
        let status = if transport == "http/1.1" {
            headers.extend([("connection", "Upgrade"), ("upgrade", "connect-udp")]);
            101
        } else {
            200
        };
        tokio::time::timeout(
            Duration::from_secs(10),
            exercise(
                &fixture,
                transport,
                Case {
                    status,
                    udp: true,
                    headers,
                    accepted: true,
                },
            ),
        )
        .await
        .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h1_handoff_preserves_large_http_looking_payload_and_duplex_half_closes() {
    let fixture = Fixture::new();
    for (status, fragmented) in [
        (200, false),
        (201, false),
        (204, false),
        (200, true),
        (201, true),
        (204, true),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut tls = fixture.tls.clone();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut downstream =
            b"\r\nHTTP/1.1 403 this is tunnel data\r\nContent-Length: 2\r\n\r\nx".to_vec();
        downstream.extend((0..512 * 1024).map(|i| (i % 251) as u8));
        let upstream: Vec<u8> = (0..512 * 1024).map(|i| (i % 239) as u8).collect();
        let response = [
            format!("HTTP/1.1 {status} fixture\r\n\r\n").as_bytes(),
            &downstream,
        ]
        .concat();
        let expected_upload = upstream.clone();
        let responder = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(tls))
                .accept(tcp)
                .await
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(tls.read_u8().await.unwrap());
            }
            assert!(request.starts_with(b"CONNECT "));
            let (mut read, mut write) = tokio::io::split(tls);
            let receive = async {
                let mut data = Vec::new();
                read.read_to_end(&mut data).await.unwrap();
                assert_eq!(data, expected_upload);
            };
            let send = async {
                if fragmented {
                    write.write_all(&response[..10]).await.unwrap();
                    write.flush().await.unwrap();
                    tokio::task::yield_now().await;
                    write.write_all(&response[10..]).await.unwrap();
                } else {
                    write.write_all(&response).await.unwrap();
                }
                write.shutdown().await.unwrap();
            };
            tokio::join!(receive, send);
        });
        let backend = support::Backend::start(fixture.ca.clone());
        let client = Client::new(
            &fixture.settings(address, "http/1.1"),
            backend.bridge.clone(),
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut opened = client.open("127.0.0.1", 7, false).await.unwrap();
            let (mut read, mut write) = tokio::io::split(&mut opened.stream);
            let send = async {
                write.write_all(&upstream).await.unwrap();
                write.shutdown().await.unwrap();
            };
            let receive = async {
                let mut data = Vec::new();
                read.read_to_end(&mut data).await.unwrap();
                assert_eq!(data, downstream);
            };
            tokio::join!(send, receive);
            responder.await.unwrap();
        })
        .await
        .expect("large duplex handoff timed out");
    }
}

/// Delaying native acknowledgements is more deterministic at the bridge
/// boundary than with a TLS socket: the peer can respond before Swift reports
/// the request WRITE complete.
#[tokio::test]
async fn h1_handoff_waits_for_request_ack_and_preserves_ack_errors() {
    use network_relay_nf_core::native;
    for status in [200, 204] {
        for ack_error in [false, true] {
            let (events_tx, mut events) = tokio::sync::mpsc::channel::<native::Event>(32);
            let bridge = native::Bridge::new(events_tx);
            let worker_bridge = bridge.clone();
            let (started_tx, started) = tokio::sync::oneshot::channel();
            let (ack_tx, ack) = tokio::sync::oneshot::channel();
            let (closed_tx, closed) = tokio::sync::oneshot::channel();
            let worker = tokio::spawn(async move {
                let mut started = Some(started_tx);
                let mut ack = Some(ack);
                let mut first = true;
                while let Some(event) = events.recv().await {
                    match event.kind {
                        native::OPEN_TCP => {
                            worker_bridge.input(
                                native::READY,
                                event.id,
                                0,
                                0,
                                br#"{"alpn":"http/1.1"}"#,
                            );
                        }
                        native::WRITE if first => {
                            first = false;
                            assert!(event.data.starts_with(b"CONNECT "));
                            let response =
                                format!("HTTP/1.1 {status} fixture\r\n\r\nHTTP/1.1 tunnel bytes");
                            worker_bridge.input(native::DATA, event.id, 0, 0, response.as_bytes());
                            started.take().unwrap().send(()).unwrap();
                            ack.take().unwrap().await.unwrap();
                            worker_bridge.input(
                                native::ACK,
                                event.id,
                                event.token,
                                u64::from(ack_error),
                                b"request write failed",
                            );
                        }
                        native::WRITE => {
                            assert_eq!(
                                event.data.as_ref(),
                                b"x",
                                "header ACK leaked into tunnel write"
                            );
                            worker_bridge.input(native::ACK, event.id, event.token, 0, b"");
                        }
                        native::READ => {}
                        native::CLOSE => {
                            closed_tx.send(()).unwrap();
                            return;
                        }
                        other => panic!("unexpected bridge event {other}"),
                    }
                }
            });
            let fixture = Fixture::new();
            let settings = fixture.settings("127.0.0.1:9".parse().unwrap(), "http/1.1");
            let client = Client::new(&settings, bridge.clone()).unwrap();
            let mut opening = tokio::spawn(async move { client.open("127.0.0.1", 7, false).await });
            started.await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(25), &mut opening)
                    .await
                    .is_err(),
                "handoff preceded native request ACK"
            );
            ack_tx.send(()).unwrap();
            let result = opening.await.unwrap();
            if ack_error {
                assert!(
                    result.is_err(),
                    "request WRITE error was hidden by response"
                );
            } else {
                let mut opened = result.unwrap();
                let mut received = vec![0; b"HTTP/1.1 tunnel bytes".len()];
                opened.stream.read_exact(&mut received).await.unwrap();
                assert_eq!(received, b"HTTP/1.1 tunnel bytes");
                opened.stream.write_all(b"x").await.unwrap();
                drop(opened);
            }
            tokio::time::timeout(Duration::from_secs(1), closed)
                .await
                .unwrap()
                .unwrap();
            worker.await.unwrap();
        }
    }
}

#[tokio::test]
async fn h1_handoff_cancellation_and_native_reset_preserve_lifecycle() {
    use network_relay_nf_core::native;
    for status in [200, 204] {
        for action in ["cancel-before-ack", "drop-tunnel", "native-reset"] {
            let (events_tx, mut events) = tokio::sync::mpsc::channel::<native::Event>(32);
            let bridge = native::Bridge::new(events_tx);
            let worker_bridge = bridge.clone();
            let (started_tx, started) = tokio::sync::oneshot::channel();
            let (closed_tx, closed) = tokio::sync::oneshot::channel();
            let worker = tokio::spawn(async move {
                let mut started = Some(started_tx);
                while let Some(event) = events.recv().await {
                    match event.kind {
                        native::OPEN_TCP => {
                            worker_bridge.input(
                                native::READY,
                                event.id,
                                0,
                                0,
                                br#"{"alpn":"http/1.1"}"#,
                            );
                        }
                        native::WRITE => {
                            assert!(event.data.starts_with(b"CONNECT "));
                            let response = format!("HTTP/1.1 {status} fixture\r\n\r\npayload");
                            worker_bridge.input(native::DATA, event.id, 0, 0, response.as_bytes());
                            if action != "cancel-before-ack" {
                                worker_bridge.input(native::ACK, event.id, event.token, 0, b"");
                            }
                            started.take().unwrap().send(event.id).unwrap();
                        }
                        native::READ => {}
                        native::CLOSE => {
                            closed_tx.send(event.flags).unwrap();
                            return;
                        }
                        other => panic!("unexpected bridge event {other}"),
                    }
                }
            });
            let fixture = Fixture::new();
            let settings = fixture.settings("127.0.0.1:9".parse().unwrap(), "http/1.1");
            let client = Client::new(&settings, bridge.clone()).unwrap();
            let opening = tokio::spawn(async move { client.open("127.0.0.1", 7, false).await });
            let id = started.await.unwrap();
            if action == "cancel-before-ack" {
                opening.abort();
                match opening.await {
                    Err(error) => assert!(error.is_cancelled()),
                    Ok(_) => panic!("cancelled handshake returned a result"),
                }
            } else {
                let mut opened = opening.await.unwrap().unwrap();
                if action == "native-reset" {
                    let mut payload = [0; 7];
                    opened.stream.read_exact(&mut payload).await.unwrap();
                    assert_eq!(&payload, b"payload");
                    bridge.input(native::ERROR, id, 0, 0, b"controlled connection reset");
                    assert!(opened.stream.read_u8().await.is_err());
                    assert!(opened.stream.write_all(b"x").await.is_err());
                }
                drop(opened);
            }
            let flags = tokio::time::timeout(Duration::from_secs(1), closed)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(flags, 0, "handoff changed the existing native CLOSE mode");
            worker.await.unwrap();
        }
    }
}
