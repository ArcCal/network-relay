//! Real-server interoperability through the exact production protocol core.
//! The transport emulator verifies protocol bytes, not Network.framework.
mod support;
use network_relay_nf_core::{
    Config,
    client::{Client, UdpFlow},
};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires scripts/test-interop.py fixture"]
async fn real_server_matrix() {
    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("RELAY_NF_FIXTURE").unwrap()).unwrap())
            .unwrap();
    let ca = config["ca"].as_str().unwrap();
    let tcp: std::net::SocketAddr = config["tcp"].as_str().unwrap().parse().unwrap();
    let udp: std::net::SocketAddr = config["udp"].as_str().unwrap().parse().unwrap();
    for transport in ["http/1.1", "h2", "h3"] {
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
            socks: network_relay_nf_core::Socks {
                listen: vec!["127.0.0.1:0".parse().unwrap()],
            },
        };
        let backend = support::Backend::start(ca.into());
        let client = Arc::new(Client::new(&settings, backend.bridge.clone()).unwrap());
        let mut tcp_flow = client
            .open("localhost", tcp.port(), false)
            .await
            .expect("remote DNS TCP CONNECT");
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
            "client advertised an unsupported native QUIC DATAGRAM path"
        );
        drop(flow);
        if transport != "http/1.1" {
            // Exceed the Rust relay's default 64-outer-connection limit while
            // retaining every tunnel: only HTTP streams should multiply.
            let mut opening = tokio::task::JoinSet::new();
            for _ in 0..80 {
                let client = client.clone();
                opening.spawn(async move { client.open("127.0.0.1", tcp.port(), false).await });
            }
            let mut concurrent = Vec::new();
            while let Some(result) = opening.join_next().await {
                concurrent.push(result.unwrap().expect("80 concurrent tunnels"));
            }
            assert_eq!(backend.opened.lock().unwrap().len(), 1);
            concurrent.drain(..40);
            for (index, opened) in concurrent.iter_mut().enumerate() {
                let payload = format!("survives-sibling-cancellation-{index}");
                opened.stream.write_all(payload.as_bytes()).await.unwrap();
                let mut echoed = vec![0; payload.len()];
                tokio::time::timeout(
                    Duration::from_secs(5),
                    opened.stream.read_exact(&mut echoed),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(echoed, payload.as_bytes());
            }
            drop(concurrent);
            println!(
                "{} {transport}: 80 simultaneous tunnels used one outer connection; cancellation preserved siblings",
                config["kind"].as_str().unwrap()
            );
        }
        let mut wrong = settings.clone();
        wrong.password = "wrong-disposable-fixture-password".into();
        let bad = Client::new(&wrong, backend.bridge.clone()).unwrap();
        assert!(
            bad.open("127.0.0.1", tcp.port(), false).await.is_err(),
            "wrong password accepted"
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
        // Clients retain their idle multiplexed connection until dropped.
        // Retire the negative-test accounts before checking final cleanup.
        drop(bad);
        drop(bad_certificate);
        let listener = backend
            .bridge
            .listen("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let worker = tokio::spawn(network_relay_nf_core::socks::run(client, vec![listener]));
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
            while !backend.bridge.resources.lock().unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("native resource leak after cancellation");
        println!(
            "{} {transport}: TCP remote DNS + 2 MiB half-close, UDP Capsules (0..65000 bytes), wrong password, certificate-name rejection, SOCKS CONNECT/UDP, source pinning, fragment drop and resource cleanup passed",
            config["kind"].as_str().unwrap()
        );
    }
}
