//! Multiplexing and lifetime checks through the production protocol core and
//! a loopback-only native transport emulator, not Network.framework itself.
mod support;

use bytes::Bytes;
use network_relay_nf_core::{Config, client::Client, native};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
};

static FIXTURE_ID: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    address: SocketAddr,
    ca: PathBuf,
    task: JoinHandle<()>,
    tcp: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
    quic: Arc<Mutex<Vec<quinn::Connection>>>,
    endpoint: Option<quinn::Endpoint>,
    goaway: tokio::sync::watch::Sender<bool>,
}

impl Fixture {
    async fn start(transport: &str, response_delay: Duration) -> Self {
        Self::start_with_limit(transport, response_delay, 128).await
    }
    async fn start_with_limit(transport: &str, response_delay: Duration, limit: u32) -> Self {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["relay.test".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let ca = std::env::temp_dir().join(format!(
            "relay-nf-reuse-{}-{}.pem",
            std::process::id(),
            FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&ca, cert.pem()).unwrap();
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
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
        tls.alpn_protocols = vec![transport.as_bytes().to_vec()];
        let tcp = Arc::new(Mutex::new(Vec::new()));
        let quic = Arc::new(Mutex::new(Vec::new()));
        let (goaway, _) = tokio::sync::watch::channel(false);
        let (address, task, endpoint) = if transport == "h3" {
            let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
            let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
            Arc::get_mut(&mut config.transport)
                .unwrap()
                .max_concurrent_bidi_streams(limit.into());
            let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
            let address = endpoint.local_addr().unwrap();
            let accepting = endpoint.clone();
            let connections = quic.clone();
            let shutdown = goaway.clone();
            let task = tokio::spawn(async move {
                while let Some(incoming) = accepting.accept().await {
                    let connection = incoming.await.unwrap();
                    connections.lock().unwrap().push(connection.clone());
                    let mut shutdown = shutdown.subscribe();
                    tokio::spawn(async move {
                        let mut control = connection.open_uni().await.unwrap();
                        control.write_all(&[0, 4, 2, 8, 1]).await.unwrap();
                        loop {
                            tokio::select! {
                                next = connection.accept_bi() => match next {
                                    Ok((send, recv)) => { tokio::spawn(h3_echo(send, recv, response_delay)); }
                                    Err(_) => break,
                                },
                                result = shutdown.changed() => {
                                    if result.is_err() { break; }
                                    // The GOAWAY test has admitted stream 0;
                                    // request stream 4 and later are rejected.
                                    if control.write_all(&[7, 1, 4]).await.is_err() { break; }
                                }
                            }
                        }
                        drop(control);
                    });
                }
            });
            (address, task, Some(endpoint))
        } else {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let workers = tcp.clone();
            let h1 = transport == "http/1.1";
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
            let shutdown = goaway.clone();
            let task = tokio::spawn(async move {
                loop {
                    let (tcp, _) = listener.accept().await.unwrap();
                    let acceptor = acceptor.clone();
                    let mut shutdown = shutdown.subscribe();
                    let worker = tokio::spawn(async move {
                        let Ok(mut tls) = acceptor.accept(tcp).await else {
                            return;
                        };
                        if h1 {
                            let mut request = Vec::new();
                            while !request.ends_with(b"\r\n\r\n") {
                                request.push(tls.read_u8().await.unwrap());
                            }
                            tokio::time::sleep(response_delay).await;
                            tls.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
                            let (mut read, mut write) = tokio::io::split(tls);
                            let _ = tokio::io::copy(&mut read, &mut write).await;
                            return;
                        }
                        let mut builder = h2::server::Builder::new();
                        builder
                            .enable_connect_protocol()
                            .max_concurrent_streams(limit);
                        let mut connection = builder.handshake::<_, Bytes>(tls).await.unwrap();
                        loop {
                            let next = tokio::select! {
                                next = connection.accept() => next,
                                result = shutdown.changed() => {
                                    if result.is_err() { break; }
                                    connection.graceful_shutdown();
                                    continue;
                                }
                            };
                            let Some(Ok((request, mut response))) = next else {
                                break;
                            };
                            tokio::spawn(async move {
                                tokio::time::sleep(response_delay).await;
                                let Ok(mut send) = response.send_response(
                                    http::Response::builder().status(200).body(()).unwrap(),
                                    false,
                                ) else {
                                    return;
                                };
                                let mut recv = request.into_body();
                                while let Some(Ok(bytes)) = recv.data().await {
                                    let len = bytes.len();
                                    if send.send_data(bytes, false).is_err() {
                                        return;
                                    }
                                    if recv.flow_control().release_capacity(len).is_err() {
                                        return;
                                    }
                                }
                                let _ = send.send_data(Bytes::new(), true);
                            });
                        }
                    });
                    workers.lock().unwrap().push(worker.abort_handle());
                }
            });
            (address, task, None)
        };
        Self {
            address,
            ca,
            task,
            tcp,
            quic,
            endpoint,
            goaway,
        }
    }

    fn settings(&self, mode: &str) -> Config {
        Config {
            uri_template: format!(
                "https://{}/.well-known/masque/udp/{{target_host}}/{{target_port}}/",
                self.address
            ),
            username: "alice".into(),
            password: "fixture-password".into(),
            server_name: Some("relay.test".into()),
            transport: mode.into(),
            probe_target: "127.0.0.1:9".parse().unwrap(),
            mode: "socks".into(),
            socks: network_relay_nf_core::Socks {
                listen: vec!["127.0.0.1:0".parse().unwrap()],
            },
        }
    }

    fn close_connections(&self) {
        for task in self.tcp.lock().unwrap().drain(..) {
            task.abort();
        }
        for connection in self.quic.lock().unwrap().drain(..) {
            connection.close(0_u32.into(), b"fixture restart");
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
        self.close_connections();
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(0_u32.into(), b"fixture ended");
        }
        let _ = std::fs::remove_file(&self.ca);
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

async fn h3_echo(mut send: quinn::SendStream, mut recv: quinn::RecvStream, delay: Duration) {
    if varint(&mut recv).await != Some(1) {
        return;
    }
    let Some(length) = varint(&mut recv).await else {
        return;
    };
    let mut headers = vec![0; length as usize];
    if recv.read_exact(&mut headers).await.is_err() {
        return;
    }
    tokio::time::sleep(delay).await;
    // HEADERS with QPACK static :status 200.
    if send.write_all(&[1, 3, 0, 0, 0xd9]).await.is_err() {
        return;
    }
    while let Some(kind) = varint(&mut recv).await {
        let Some(length) = varint(&mut recv).await else {
            return;
        };
        let mut bytes = vec![0; length as usize];
        if recv.read_exact(&mut bytes).await.is_err() {
            return;
        }
        if kind == 0 {
            let mut wire = bytes::BytesMut::new();
            network_relay_nf_core::proto::varint::encode(0, &mut wire);
            network_relay_nf_core::proto::varint::encode(length, &mut wire);
            wire.extend_from_slice(&bytes);
            if send.write_all(&wire).await.is_err() {
                return;
            }
        }
    }
    let _ = send.finish();
}

async fn echo(stream: &mut network_relay_nf_core::stream::Stream, payload: &[u8]) {
    stream.write_all(payload).await.unwrap();
    let mut bytes = vec![0; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bytes, payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multiplexed_flows_share_one_connection_and_cancel_independently() {
    for transport in ["h2", "h3"] {
        let fixture = Fixture::start(transport, Duration::ZERO).await;
        let backend = support::Backend::start_with(fixture.ca.clone(), transport == "h3");
        let client =
            Arc::new(Client::new(&fixture.settings(transport), backend.bridge.clone()).unwrap());
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..80 {
            let client = client.clone();
            tasks.spawn(async move { client.open("127.0.0.1", 7, false).await.unwrap() });
        }
        let mut flows = Vec::new();
        while let Some(flow) = tasks.join_next().await {
            flows.push(flow.unwrap());
        }
        assert_eq!(
            backend.opened.lock().unwrap().len(),
            1,
            "{transport}: connection storm"
        );
        for (index, flow) in flows.iter_mut().enumerate() {
            echo(&mut flow.stream, format!("flow-{index}").as_bytes()).await;
        }
        // Cancelling half of the requests must not abort the shared driver.
        flows.drain(..40);
        for flow in &mut flows {
            echo(&mut flow.stream, b"survives sibling cancellation").await;
        }
        // The last request, not the Client handle, owns the live connection.
        drop(client);
        for flow in &mut flows {
            echo(&mut flow.stream, b"survives client drop").await;
        }
        drop(flows);
        tokio::time::timeout(Duration::from_secs(5), async {
            while !backend.bridge.resources.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("pooled connection leaked after its last owner");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dead_connections_are_replaced_without_replaying_failed_streams() {
    for transport in ["h2", "h3"] {
        let fixture = Fixture::start(transport, Duration::ZERO).await;
        let backend = support::Backend::start(fixture.ca.clone());
        let client = Client::new(&fixture.settings(transport), backend.bridge.clone()).unwrap();
        let mut first = client.open("127.0.0.1", 7, false).await.unwrap();
        echo(&mut first.stream, b"before restart").await;
        fixture.close_connections();
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut byte = [0];
            assert!(
                first.stream.read(&mut byte).await.is_err(),
                "dead flow was hidden as clean EOF"
            );
        })
        .await
        .unwrap();
        // A subsequent, distinct CONNECT establishes a new connection. The
        // previous stream's application data is never retried.
        let mut second = client.open("127.0.0.1", 7, false).await.unwrap();
        echo(&mut second.stream, b"after restart").await;
        assert_eq!(backend.opened.lock().unwrap().len(), 2);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn goaway_retires_the_cached_connection_without_aborting_admitted_flows() {
    for transport in ["h2", "h3"] {
        let fixture = Fixture::start(transport, Duration::ZERO).await;
        let backend = support::Backend::start(fixture.ca.clone());
        let client = Client::new(&fixture.settings(transport), backend.bridge.clone()).unwrap();
        let mut first = client.open("127.0.0.1", 7, false).await.unwrap();
        echo(&mut first.stream, b"before GOAWAY").await;
        fixture.goaway.send_replace(true);
        // Drive both directions after the server schedules its GOAWAY.
        tokio::time::sleep(Duration::from_millis(100)).await;
        echo(&mut first.stream, b"admitted request survives GOAWAY").await;
        let mut second = client.open("127.0.0.1", 7, false).await.unwrap();
        echo(&mut second.stream, b"new request uses new connection").await;
        assert_eq!(
            backend.opened.lock().unwrap().len(),
            2,
            "{transport}: cached GOAWAY reused"
        );
        echo(&mut first.stream, b"old request still alive").await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_http3_request_does_not_send_headers_after_goaway() {
    let fixture = Fixture::start_with_limit("h3", Duration::ZERO, 1).await;
    let backend = support::Backend::start(fixture.ca.clone());
    let client = Arc::new(Client::new(&fixture.settings("h3"), backend.bridge.clone()).unwrap());
    let mut first = client.open("127.0.0.1", 7, false).await.unwrap();
    echo(&mut first.stream, b"admitted request zero").await;
    let owner = client.clone();
    let pending = tokio::spawn(async move { owner.open("127.0.0.1", 7, false).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !pending.is_finished(),
        "request did not wait for stream credit"
    );
    fixture.goaway.send_replace(true);
    tokio::time::sleep(Duration::from_millis(500)).await;
    echo(&mut first.stream, b"admitted request survives GOAWAY").await;
    drop(first);
    let result = tokio::time::timeout(Duration::from_secs(5), pending)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_err(), "queued request sent HEADERS after GOAWAY");
    assert_eq!(
        backend.opened.lock().unwrap().len(),
        1,
        "queued request was replayed"
    );
    let mut fresh = client.open("127.0.0.1", 7, false).await.unwrap();
    echo(&mut fresh.stream, b"new request on fresh connection").await;
    assert_eq!(backend.opened.lock().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn distinct_client_credentials_never_share_a_pooled_connection() {
    for transport in ["h2", "h3"] {
        let fixture = Fixture::start(transport, Duration::ZERO).await;
        let backend = support::Backend::start(fixture.ca.clone());
        let first = Client::new(&fixture.settings(transport), backend.bridge.clone()).unwrap();
        let mut other = fixture.settings(transport);
        other.username = "bob".into();
        other.password = "other-fixture-password".into();
        let second = Client::new(&other, backend.bridge.clone()).unwrap();
        let mut one = first.open("127.0.0.1", 7, false).await.unwrap();
        let mut two = second.open("127.0.0.1", 7, false).await.unwrap();
        echo(&mut one.stream, b"first account").await;
        echo(&mut two.stream, b"second account").await;
        assert_eq!(backend.opened.lock().unwrap().len(), 2);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_stream_limit_waits_for_capacity_without_opening_more_connections() {
    for transport in ["h2", "h3"] {
        let fixture = Fixture::start_with_limit(transport, Duration::ZERO, 2).await;
        let backend = support::Backend::start(fixture.ca.clone());
        let client =
            Arc::new(Client::new(&fixture.settings(transport), backend.bridge.clone()).unwrap());
        let one = client.open("127.0.0.1", 7, false).await.unwrap();
        let mut two = client.open("127.0.0.1", 7, false).await.unwrap();
        let owner = client.clone();
        let third = tokio::spawn(async move { owner.open("127.0.0.1", 7, false).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!third.is_finished(), "{transport}: peer limit bypassed");
        echo(
            &mut two.stream,
            b"capacity waiter cannot block established flows",
        )
        .await;
        drop(one);
        let mut three = tokio::time::timeout(Duration::from_secs(5), third)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        echo(&mut three.stream, b"released stream capacity reused").await;
        assert_eq!(backend.opened.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn forced_http1_tls_handshakes_remain_independent() {
    let fixture = Fixture::start("http/1.1", Duration::ZERO).await;
    let (events, mut native_requests) = tokio::sync::mpsc::channel(16);
    let bridge = native::Bridge::new(events);
    let client = Arc::new(Client::new(&fixture.settings("http/1.1"), bridge.clone()).unwrap());
    let one = client.clone();
    let first = tokio::spawn(async move { one.open("127.0.0.1", 7, false).await });
    let request = native_requests.recv().await.unwrap();
    assert_eq!(request.kind, native::OPEN_TCP);
    // Deliberately withhold READY for the first TLS handshake. An unrelated
    // forced-H1 flow must issue its own OPEN_TCP without waiting for that ACK.
    let two = client.clone();
    let second = tokio::spawn(async move { two.open("127.0.0.1", 7, false).await });
    let other = tokio::time::timeout(Duration::from_secs(1), native_requests.recv())
        .await
        .expect("HTTP/1.1 TLS establishment was serialized")
        .unwrap();
    assert_eq!(other.kind, native::OPEN_TCP);
    assert_ne!(request.id, other.id);
    first.abort();
    second.abort();
    let _ = first.await;
    let _ = second.await;
    assert!(bridge.resources.lock().unwrap().is_empty());
}

#[tokio::test]
async fn http3_retries_only_proven_unsent_stream_creation_and_only_once() {
    // Simulate native callback ordering directly: the cached QUIC group
    // passed its health check, but creating its first request stream fails.
    // No TLS/HTTP response or request write is involved in that failure.
    for (failures, flags, expected_opens, accepted) in [
        (1, 4, 2, true),
        (2, 4, 2, false),
        (1, 1, 1, false), // Permission/trust errors are never retried.
        (1, 3, 1, false), // Native deadlines are never retried.
    ] {
        let fixture = Fixture::start("h3", Duration::ZERO).await;
        let (events, mut requests) = tokio::sync::mpsc::channel(64);
        let bridge = native::Bridge::new(events);
        let client = Arc::new(Client::new(&fixture.settings("h3"), bridge.clone()).unwrap());
        let owner = client.clone();
        let opening = tokio::spawn(async move { owner.open("127.0.0.1", 7, false).await });
        tokio::pin!(opening);
        let mut opened = 0;
        let mut failures_left = failures;
        let mut next_uni = 2;
        let mut request_id = None;
        let mut request_writes = 0;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                tokio::select! {
                    result = &mut opening => break result.unwrap(),
                    event = requests.recv() => {
                        let event = event.unwrap();
                        match event.kind {
                            native::OPEN_QUIC => {
                                opened += 1;
                                next_uni = 2;
                                bridge.input(native::READY, event.id, 0, 0,
                                    &serde_json::to_vec(&native::Ready { alpn: "h3".into(), ..native::Ready::default() }).unwrap());
                            }
                            native::OPEN_STREAM => {
                                if event.flags == 0 && failures_left != 0 {
                                    failures_left -= 1;
                                    bridge.input(native::ERROR, event.id, 0, flags, b"injected request stream creation failure");
                                } else {
                                    let stream_id = if event.flags == 1 {
                                        let id = next_uni;
                                        next_uni += 4;
                                        id
                                    } else {
                                        request_id = Some(event.id);
                                        0
                                    };
                                    bridge.input(native::READY, event.id, 0, 0,
                                        &serde_json::to_vec(&native::Ready { stream_id, ..native::Ready::default() }).unwrap());
                                }
                            }
                            native::WRITE => {
                                if Some(event.id) == request_id { request_writes += 1; }
                                bridge.input(native::ACK, event.id, event.token, 0, b"");
                            }
                            native::READ if Some(event.id) == request_id => {
                                bridge.input(native::DATA, event.id, 0, 0, &[1, 3, 0, 0, 0xd9]);
                            }
                            native::CLOSE => {}
                            other => panic!("unexpected native operation {other}"),
                        }
                    }
                }
            }
        }).await.unwrap();
        assert_eq!(result.is_ok(), accepted);
        assert_eq!(opened, expected_opens);
        assert_eq!(
            request_writes,
            usize::from(accepted),
            "failed creation submitted HEADERS"
        );
        drop(result);
        drop(client);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_target_response_is_allowed_without_auto_transport_downgrade() {
    let mut checks = tokio::task::JoinSet::new();
    for transport in ["http/1.1", "h2", "h3", "auto"] {
        checks.spawn(async move {
            let fixture = Fixture::start(
                if transport == "auto" { "h3" } else { transport },
                Duration::from_secs(11),
            )
            .await;
            let backend = support::Backend::start(fixture.ca.clone());
            let client = Client::new(&fixture.settings(transport), backend.bridge.clone()).unwrap();
            let mut opened = client.open("127.0.0.1", 7, false).await.unwrap();
            echo(&mut opened.stream, b"slow destination accepted").await;
            if matches!(transport, "h3" | "auto") {
                assert_eq!(opened.transport, "HTTP/3");
                assert_eq!(
                    backend.opened.lock().unwrap().as_slice(),
                    &[(native::OPEN_QUIC, "127.0.0.1".into())]
                );
            }
        });
    }
    while let Some(check) = checks.join_next().await {
        check.unwrap();
    }
}
