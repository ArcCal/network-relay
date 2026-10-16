//! Real-server pooled TCP/UDP traffic across two 60-second probe renewals.
//! The portable TLS/QUIC bridge does not execute Apple Network.framework.
mod support;

use network_relay_nf_core::{
    Config,
    client::{Client, UdpFlow},
};
use std::{
    io::Write,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

async fn exercise(fixture: &serde_json::Value, mode: &str) {
    let tcp: SocketAddr = fixture["tcp"].as_str().unwrap().parse().unwrap();
    let udp: SocketAddr = fixture["udp"].as_str().unwrap().parse().unwrap();
    let config = Config {
        uri_template: format!(
            "https://{}/.well-known/masque/udp/{{target_host}}/{{target_port}}/",
            fixture["server"].as_str().unwrap()
        ),
        username: "alice".into(),
        password: fixture["password"].as_str().unwrap().into(),
        server_name: Some("relay.test".into()),
        transport: mode.into(),
        probe_target: udp,
        mode: "socks".into(),
        socks: network_relay_nf_core::Socks {
            listen: vec!["127.0.0.1:0".parse().unwrap()],
        },
    };
    let mut backend = support::Backend::start(fixture["ca"].as_str().unwrap().into());
    let client = Arc::new(Client::new(&config, backend.bridge.clone()).unwrap());
    let monitor_client = client.clone();
    let monitor = tokio::spawn(async move { monitor_client.monitor().await });
    backend.connected().await;
    let mut tcp_flow = client.open("127.0.0.1", tcp.port(), false).await.unwrap();
    let mut udp_flow = UdpFlow::new(
        client
            .open("127.0.0.1", udp.port(), true)
            .await
            .unwrap()
            .stream,
    );
    let started = tokio::time::Instant::now();
    let mut rounds = 0u32;
    while started.elapsed() < Duration::from_secs(125) {
        let payload = format!("persistent-{mode}-{rounds}-{}", "x".repeat(1200));
        tokio::time::timeout(Duration::from_secs(10), async {
            tcp_flow.stream.write_all(payload.as_bytes()).await.unwrap();
            let mut reply = vec![0; payload.len()];
            tcp_flow.stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, payload.as_bytes(), "persistent TCP corruption");
            udp_flow.send(payload.as_bytes()).await.unwrap();
            assert_eq!(
                udp_flow.recv().await.unwrap().unwrap().as_ref(),
                payload.as_bytes(),
                "persistent Capsule corruption"
            );
        })
        .await
        .expect("persistent data stalled across probe renewal");
        assert!(!monitor.is_finished(), "monitor exited during live traffic");
        assert_eq!(
            backend.status.borrow().0,
            1,
            "probe renewal reported failure"
        );
        assert_eq!(
            backend.opened.lock().unwrap().len(),
            1,
            "probe renewal replaced a healthy outer connection"
        );
        rounds += 1;
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    // Scheduling load may delay a round; duration and actual renewal counts
    // below are the lifecycle gates, not a precise loopback throughput target.
    assert!(rounds >= 50);
    assert_eq!(
        backend.datagrams_sent(),
        0,
        "UDP must retain Capsule framing"
    );
    monitor.abort();
    let _ = monitor.await;
    drop(tcp_flow);
    drop(udp_flow);
    drop(client);
    tokio::time::timeout(Duration::from_secs(5), async {
        while !backend.bridge.resources.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("pooled connection leaked native resources");
    println!(
        "{} {mode}: {rounds} verified TCP/UDP exchanges across {:.2}s; one outer connection; zero retained resources",
        fixture["kind"].as_str().unwrap(),
        started.elapsed().as_secs_f64()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires scripts/test-interop.py --test pooled_renewal fixture; takes 125 seconds"]
async fn persistent_flows_survive_two_pooled_probe_renewals() {
    let fixture: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("RELAY_NF_FIXTURE").unwrap()).unwrap())
            .unwrap();
    let logs = Arc::new(Mutex::new(Vec::new()));
    let captured = logs.clone();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .with_writer(move || Capture(captured.clone()))
        .init();
    tokio::time::timeout(Duration::from_secs(170), async {
        tokio::join!(exercise(&fixture, "h2"), exercise(&fixture, "h3"));
    })
    .await
    .expect("pooled probe renewal fixture exceeded its deadline");
    let logs = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
    for transport in ["HTTP/2", "HTTP/3"] {
        // The UI deliberately emits Ready only once; planned refreshes are
        // debug events rather than reconnects. Require two actual refreshes.
        assert!(
            logs.matches(&format!("Readiness probe refreshed; {transport};"))
                .count()
                >= 2,
            "fewer than two successful {transport} probe renewals: {logs}"
        );
    }
    assert!(
        !logs.contains("Relay session failed"),
        "probe renewal failed: {logs}"
    );
}
