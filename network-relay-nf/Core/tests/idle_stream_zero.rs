//! Diagnostic: how a real relay server treats the idle client bidirectional
//! stream 0 that an NWConnectionGroup owns, while the production protocol
//! core sends its request on stream 4. The Quinn emulator answers the server
//! question only; it cannot show how Network.framework reacts to the result.
mod support;
use network_relay_nf_core::{
    Config,
    client::{Client, UdpFlow},
};
use std::time::{Duration, Instant};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a RELAY_NF_FIXTURE written by scripts/test-interop.py"]
async fn idle_group_stream_zero() {
    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("RELAY_NF_FIXTURE").unwrap()).unwrap())
            .unwrap();
    let udp: std::net::SocketAddr = config["udp"].as_str().unwrap().parse().unwrap();
    let settings = Config {
        uri_template: format!(
            "https://{}/.well-known/masque/udp/{{target_host}}/{{target_port}}/",
            config["server"].as_str().unwrap()
        ),
        username: "alice".into(),
        password: config["password"].as_str().unwrap().into(),
        server_name: Some("relay.test".into()),
        transport: "h3".into(),
        probe_target: udp,
        mode: "socks".into(),
        socks: network_relay_nf_core::Socks {
            listen: vec!["127.0.0.1:0".parse().unwrap()],
            gssapi_keytab: None,
            gssapi_principals: Vec::new(),
        },
    };
    let backend = support::Backend::start_with(config["ca"].as_str().unwrap().into(), true);
    let client = Client::new(&settings, backend.bridge.clone()).unwrap();
    let opened = client
        .open("localhost", udp.port(), true)
        .await
        .expect("CONNECT-UDP admission on stream 4");
    let admitted = Instant::now();
    let mut flow = UdpFlow::new(opened.stream);
    echo(&mut flow, "before ten seconds").await;
    tokio::time::sleep(Duration::from_secs(13)).await;
    // Quinn keeps the connection when stream 0 is reset; Network.framework
    // behavior for its group-owned stream is not represented here.
    echo(&mut flow, "after thirteen seconds").await;
    let events = backend.stream_zero.lock().unwrap().clone();
    println!(
        "OBSERVATION server={} admission-to-check={:?} stream0={events:?}",
        config["kind"].as_str().unwrap(),
        admitted.elapsed()
    );
}

async fn echo(flow: &mut UdpFlow, label: &str) {
    flow.send(label.as_bytes()).await.unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(5), flow.recv())
        .await
        .unwrap_or_else(|_| panic!("{label}: no UDP echo"))
        .unwrap()
        .unwrap();
    assert_eq!(&reply[..], label.as_bytes());
}
