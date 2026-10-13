//! Real-server interoperability through the production Rust transport backend.
//! No test transport emulator or Network.framework is used.
use network_relay_rs_core::{
    Config,
    backend::{Backend, BackendOptions},
    client::{Client, UdpFlow},
};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires scripts/test-interop.py fixture"]
async fn real_server_matrix() {
    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("RELAY_RS_FIXTURE").unwrap()).unwrap())
            .unwrap();
    let ca = config["ca"].as_str().unwrap();
    let tcp: std::net::SocketAddr = config["tcp"].as_str().unwrap().parse().unwrap();
    let udp: std::net::SocketAddr = config["udp"].as_str().unwrap().parse().unwrap();
    for transport in ["http/1.1", "h2", "h3", "auto"] {
        let settings = Config {
            uri_template: format!(
                "https://{}/.well-known/masque/udp/{{target_host}}/{{target_port}}/",
                config["server"].as_str().unwrap()
            ),
            username: "alice".into(),
            password: config["password"].as_str().unwrap().into(),
            server_name: Some("relay.test".into()),
            transport: transport.into(),
            probe_target: udp,
            mode: "socks".into(),
            socks: network_relay_rs_core::Socks {
                listen: vec!["127.0.0.1:0".parse().unwrap()],
            },
        };
        let mut backend = Backend::start(BackendOptions {
            ca_file: Some(ca.into()),
        })
        .unwrap();
        let client = Client::new(&settings, backend.bridge.clone()).unwrap();
        let mut tcp_flow = client
            .open("localhost", tcp.port(), false)
            .await
            .expect("remote DNS TCP CONNECT");
        if transport == "auto" {
            assert_eq!(
                tcp_flow.transport, "HTTP/3",
                "automatic mode did not select available HTTP/3"
            );
        }
        let payload: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        let (mut read, mut write) = tokio::io::split(&mut tcp_flow.stream);
        let send = async {
            write.write_all(&payload).await.unwrap();
            write.shutdown().await.unwrap();
        };
        let receive = async {
            let mut result = Vec::new();
            read.read_to_end(&mut result).await.unwrap();
            result
        };
        let (_, received) = tokio::time::timeout(Duration::from_secs(30), async {
            tokio::join!(send, receive)
        })
        .await
        .expect("bulk half-close timed out");
        assert_eq!(received, payload, "duplex/half-close corruption");
        drop(tcp_flow);
        let opened = client
            .open("localhost", udp.port(), true)
            .await
            .expect("remote DNS CONNECT-UDP");
        let mut flow = UdpFlow::new(opened.stream);
        for size in [0, 1, 1200, 32768, 65000] {
            let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            println!("UDP test transport={transport} size={size}");
            flow.send(&payload).await.unwrap();
            let reply = tokio::time::timeout(Duration::from_secs(10), flow.recv())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(&reply[..], &payload, "UDP Capsule corruption");
        }
        assert_eq!(
            backend.datagrams_sent(),
            0,
            "Capsule-only client emitted native QUIC DATAGRAMs"
        );
        drop(flow);
        let mut wrong = settings.clone();
        wrong.password = "wrong-disposable-fixture-password".into();
        let bad = Client::new(&wrong, backend.bridge.clone()).unwrap();
        assert!(
            bad.open("127.0.0.1", tcp.port(), false).await.is_err(),
            "wrong password accepted"
        );
        let refused = client
            .open("127.0.0.1", 1, false)
            .await
            .err()
            .expect("blocked destination port accepted");
        assert!(
            refused
                .downcast_ref::<network_relay_rs_core::client::Rejected>()
                .is_some_and(|reason| reason.0 == http::StatusCode::FORBIDDEN),
            "destination policy rejection was not preserved: {refused:#}"
        );
        let mut mismatch = settings.clone();
        mismatch.server_name = Some("wrong-name.test".into());
        let bad_certificate = Client::new(&mismatch, backend.bridge.clone()).unwrap();
        assert!(
            bad_certificate
                .open("127.0.0.1", tcp.port(), false)
                .await
                .is_err(),
            "certificate name mismatch accepted"
        );
        if transport == "h2" {
            let mut untrusted_backend = Backend::start(BackendOptions::default()).unwrap();
            let untrusted = Client::new(&settings, untrusted_backend.bridge.clone()).unwrap();
            assert!(
                untrusted
                    .open("127.0.0.1", tcp.port(), false)
                    .await
                    .is_err(),
                "fixture CA was trusted without explicit fixture trust"
            );
            drop(untrusted);
            untrusted_backend.shutdown().await;
        }
        let client = Arc::new(client);
        let listener = backend
            .bridge
            .listen("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let worker = tokio::spawn(network_relay_rs_core::socks::run(client, vec![listener]));
        let mut local = tokio::net::TcpStream::connect(address).await.unwrap();
        local.write_all(&[5, 1, 0]).await.unwrap();
        let mut greeting = [0; 2];
        local.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 0]);
        let mut request = vec![5, 1, 0, 3, 9];
        request.extend_from_slice(b"localhost");
        request.extend_from_slice(&tcp.port().to_be_bytes());
        local.write_all(&request).await.unwrap();
        let mut reply = [0; 10];
        local.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0);
        local.write_all(b"SOCKS test").await.unwrap();
        let mut reply = [0; 10];
        local.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"SOCKS test");
        drop(local);
        let mut control = tokio::net::TcpStream::connect(address).await.unwrap();
        control.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0; 2];
        control.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0]);
        control
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut reply = [0; 10];
        control.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0);
        let association: std::net::SocketAddr = std::net::SocketAddr::from((
            [reply[4], reply[5], reply[6], reply[7]],
            u16::from_be_bytes([reply[8], reply[9]]),
        ));
        let local_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut datagram = vec![0, 0, 0, 3, 9];
        datagram.extend_from_slice(b"localhost");
        datagram.extend_from_slice(&udp.port().to_be_bytes());
        datagram.extend_from_slice(b"SOCKS UDP");
        local_udp.send_to(&datagram, association).await.unwrap();
        let mut response = [0; 128];
        let (n, peer) =
            tokio::time::timeout(Duration::from_secs(10), local_udp.recv_from(&mut response))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(peer, association);
        assert_eq!(&response[..n], &datagram);
        let outsider = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        outsider.send_to(&datagram, association).await.unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(120),
                outsider.recv_from(&mut response)
            )
            .await
            .is_err(),
            "association admitted a different source port"
        );
        datagram[2] = 1;
        local_udp.send_to(&datagram, association).await.unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(120),
                local_udp.recv_from(&mut response)
            )
            .await
            .is_err(),
            "fragmented UDP accepted"
        );
        drop(control);
        worker.abort();
        let _ = worker.await;
        tokio::time::timeout(Duration::from_secs(3), async {
            while !backend.bridge.resources.lock().unwrap().is_empty()
                || backend.resource_count() != 0
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("Rust transport resource leak after cancellation");
        backend.shutdown().await;
        println!(
            "{} {transport}: TCP remote DNS + 2 MiB half-close, UDP Capsules (0..65000 bytes), wrong password, blocked destination, certificate-name rejection, SOCKS CONNECT/UDP, source pinning, fragment drop and resource cleanup passed",
            config["kind"].as_str().unwrap()
        );
    }
}

/// This crosses the former ten-second failure window, the sixty-second
/// readiness-probe renewal and the Rust server's 120-second UDP idle minimum.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires scripts/test-interop.py fixture; 125-second stability observation"]
async fn http3_stability_soak() {
    let fixture: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("RELAY_RS_FIXTURE").unwrap()).unwrap())
            .unwrap();
    let tcp: std::net::SocketAddr = fixture["tcp"].as_str().unwrap().parse().unwrap();
    let udp: std::net::SocketAddr = fixture["udp"].as_str().unwrap().parse().unwrap();
    let settings = Config {
        uri_template: format!(
            "https://{}/.well-known/masque/udp/{{target_host}}/{{target_port}}/",
            fixture["server"].as_str().unwrap()
        ),
        username: "alice".into(),
        password: fixture["password"].as_str().unwrap().into(),
        server_name: Some("relay.test".into()),
        transport: "h3".into(),
        probe_target: udp,
        mode: "socks".into(),
        socks: network_relay_rs_core::Socks {
            listen: vec!["127.0.0.1:0".parse().unwrap()],
        },
    };
    let mut backend = Backend::start(BackendOptions {
        ca_file: Some(fixture["ca"].as_str().unwrap().into()),
    })
    .unwrap();
    let mut status = backend.status.clone();
    let client = Arc::new(Client::new(&settings, backend.bridge.clone()).unwrap());
    let monitor_client = client.clone();
    let monitor = tokio::spawn(async move { monitor_client.monitor().await });
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if status.borrow().0 == 1 {
                break;
            }
            status.changed().await.expect("backend status closed");
            assert_ne!(status.borrow().0, 2, "readiness probe failed before soak");
        }
    })
    .await
    .expect("HTTP/3 readiness did not complete");
    let mut tcp_flow = client.open("localhost", tcp.port(), false).await.unwrap();
    let mut udp_flow = UdpFlow::new(
        client
            .open("localhost", udp.port(), true)
            .await
            .unwrap()
            .stream,
    );
    let started = tokio::time::Instant::now();
    let traffic = async {
        for sequence in 0u8..26 {
            let payload = vec![sequence; 4096];
            tcp_flow.stream.write_all(&payload).await.unwrap();
            let mut reply = vec![0; payload.len()];
            tcp_flow.stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, payload, "TCP corruption during HTTP/3 soak");
            udp_flow.send(&payload).await.unwrap();
            let reply = tokio::time::timeout(Duration::from_secs(10), udp_flow.recv())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(&reply[..], &payload, "UDP corruption during HTTP/3 soak");
            if sequence != 25 {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(160), async {
        tokio::pin!(traffic);
        loop {
            tokio::select! {
                _ = &mut traffic => break,
                changed = status.changed() => {
                    changed.expect("backend status closed during soak");
                    assert_ne!(status.borrow().0, 2, "readiness probe entered reconnect during soak");
                }
            }
        }
    }).await.expect("125-second HTTP/3 soak stalled");
    assert!(started.elapsed() >= Duration::from_secs(125));
    assert!(
        !monitor.is_finished(),
        "readiness monitor unexpectedly stopped"
    );
    assert_eq!(backend.datagrams_sent(), 0);
    tcp_flow.stream.shutdown().await.unwrap();
    drop(tcp_flow);
    drop(udp_flow);
    monitor.abort();
    let _ = monitor.await;
    drop(client);
    backend.shutdown().await;
    assert_eq!(backend.resource_count(), 0);
    println!(
        "{} h3: {:?} with idle admission-probe renewals, persistent TCP + UDP traffic, no reconnect and no production transport resources left",
        fixture["kind"].as_str().unwrap(),
        started.elapsed()
    );
}

/// The fixture deliberately listens on TLS/TCP only, so a real QUIC attempt
/// cannot succeed. Automatic mode must select HTTP/2 and retain UDP Capsules.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires scripts/test-interop.py TCP-only fixture"]
async fn auto_falls_back_when_quic_is_unavailable() {
    let fixture: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("RELAY_RS_FIXTURE").unwrap()).unwrap())
            .unwrap();
    let tcp: std::net::SocketAddr = fixture["tcp"].as_str().unwrap().parse().unwrap();
    let udp: std::net::SocketAddr = fixture["udp"].as_str().unwrap().parse().unwrap();
    let settings = Config {
        uri_template: format!(
            "https://{}/.well-known/masque/udp/{{target_host}}/{{target_port}}/",
            fixture["server"].as_str().unwrap()
        ),
        username: "alice".into(),
        password: fixture["password"].as_str().unwrap().into(),
        server_name: Some("relay.test".into()),
        transport: "auto".into(),
        probe_target: udp,
        mode: "socks".into(),
        socks: network_relay_rs_core::Socks {
            listen: vec!["127.0.0.1:0".parse().unwrap()],
        },
    };
    let mut backend = Backend::start(BackendOptions {
        ca_file: Some(fixture["ca"].as_str().unwrap().into()),
    })
    .unwrap();
    let mut status = backend.status.clone();
    let client = Arc::new(Client::new(&settings, backend.bridge.clone()).unwrap());
    let monitor_client = client.clone();
    let monitor = tokio::spawn(async move { monitor_client.monitor().await });
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if status.borrow().0 == 1 {
                break;
            }
            status.changed().await.unwrap();
            assert_ne!(
                status.borrow().0,
                2,
                "automatic mode did not complete TCP fallback"
            );
        }
    })
    .await
    .expect("automatic fallback did not complete");
    assert!(
        status.borrow().1.contains("HTTP/2"),
        "fallback did not select HTTP/2: {:?}",
        *status.borrow()
    );
    let mut tcp_flow = client.open("localhost", tcp.port(), false).await.unwrap();
    assert_eq!(tcp_flow.transport, "HTTP/2");
    tcp_flow.stream.write_all(b"TCP fallback").await.unwrap();
    let mut reply = [0; 12];
    tcp_flow.stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"TCP fallback");
    let udp_open = client.open("localhost", udp.port(), true).await.unwrap();
    assert_eq!(udp_open.transport, "HTTP/2");
    let mut udp_flow = UdpFlow::new(udp_open.stream);
    let payload = vec![0x73; 65000];
    udp_flow.send(&payload).await.unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(10), udp_flow.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(&reply[..], &payload);
    drop(tcp_flow);
    drop(udp_flow);
    monitor.abort();
    let _ = monitor.await;
    drop(client);
    backend.shutdown().await;
    assert_eq!(backend.resource_count(), 0);
    println!(
        "Automatic mode: real QUIC failure followed by HTTP/2 TCP and 65000-byte UDP Capsule success"
    );
}
