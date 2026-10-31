//! Portable harness around the client core in this repository.
//! NF uses its unchanged test-only native bridge emulator; RS uses its actual
//! production Tokio/rustls/Quinn backend. No macOS execution is claimed.
use network_relay_nf_core as core;
#[path = "../../../../../network-relay-nf/Core/tests/support/mod.rs"]
mod support;
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Deserialize)]
struct Fixture {
    server: String,
    ca: PathBuf,
    user: String,
    password: String,
    transport: String,
}

async fn within<T>(future: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(Duration::from_secs(30), future).await.context("client interoperability deadline")?
}

fn config(fixture: &Fixture) -> core::Config {
    core::Config {
        uri_template: format!("https://{}/.well-known/masque/udp/{{target_host}}/{{target_port}}/", fixture.server),
        username: fixture.user.clone(),
        password: fixture.password.clone(),
        server_name: Some("relay.test".into()),
        transport: fixture.transport.clone(),
        probe_target: "198.18.0.2:7".parse().unwrap(),
        mode: "socks".into(),
        socks: core::Socks { listen: vec!["127.0.0.1:0".parse().unwrap()] },
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    let fixture_path = std::env::args_os().nth(1).context("fixture JSON path required")?;
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(fixture_path)?)?;
    let settings = config(&fixture);
    let backend = support::Backend::start(fixture.ca.clone());
    let client = core::client::Client::new(&settings, backend.bridge.clone())?;
    let started = std::time::Instant::now();
    let mut rows = Vec::new();
    for (host, size) in [("fixture.test", 2 << 20), ("fd00::2", 16 << 10)] {
        let mut flow = within(client.open(host, 7, false)).await.context("client TCP CONNECT")?;
        let selected_transport = flow.transport;
        let payload: Vec<u8> = (0..size).map(|i| ((i * 31 + 17) % 251) as u8).collect();
        let (mut read, mut write) = tokio::io::split(&mut flow.stream);
        let send = async {
            write.write_all(&payload).await?;
            write.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        };
        let receive = async {
            let mut received = Vec::with_capacity(payload.len());
            read.read_to_end(&mut received).await?;
            Ok::<_, anyhow::Error>(received)
        };
        let (sent, received) = tokio::time::timeout(Duration::from_secs(30), async { tokio::join!(send, receive) })
            .await
            .context("TCP bulk and half-close deadline")?;
        sent?;
        let received = received?;
        ensure!(received == payload, "client TCP contents differ");
        rows.push(serde_json::json!({
            "protocol": "tcp", "target": host, "bytes": size,
            "transport": selected_transport,
            "sha256": format!("{:x}", Sha256::digest(&received)),
            "half_close": true
        }));
        drop(flow);
        let opened = within(client.open(host, 7, true)).await.context("client CONNECT-UDP")?;
        let mut flow = core::client::UdpFlow::new(opened.stream);
        for size in [0, 1, 1200] {
            let payload: Vec<u8> = (0..size).map(|i| ((i * 13 + 9) % 251) as u8).collect();
            flow.send(&payload).await?;
            let received = within(flow.recv()).await?.context("UDP flow closed before echo")?;
            ensure!(&received[..] == payload, "client UDP datagram contents differ");
            rows.push(serde_json::json!({"protocol": "udp", "target": host, "bytes": size,
                "sha256": format!("{:x}", Sha256::digest(&received)), "whole_datagram": true}));
        }
        drop(flow);
    }
    let mut wrong_password = settings.clone();
    wrong_password.password = "wrong-ephemeral-interop-password".into();
    let wrong = core::client::Client::new(&wrong_password, backend.bridge.clone())?;
    ensure!(within(wrong.open("fixture.test", 7, false)).await.is_err(), "wrong password accepted");
    drop(wrong);
    let mut wrong_name = settings.clone();
    wrong_name.server_name = Some("wrong-name.test".into());
    let wrong = core::client::Client::new(&wrong_name, backend.bridge.clone())?;
    ensure!(within(wrong.open("fixture.test", 7, false)).await.is_err(), "TLS name mismatch accepted");
    drop(wrong);
    ensure!(backend.datagrams_sent() == 0, "client used an unsupported QUIC DATAGRAM path");
    drop(client);
    let native_hosts = backend.opened.lock().unwrap().iter().map(|(_, host)| host.clone()).collect::<Vec<_>>();
    ensure!(native_hosts.iter().all(|host| host == "127.0.0.1"), "NF emulator contacted a business target directly");
    drop(backend);
    println!(
        "{}",
        serde_json::json!({"client": "nf", "core_version": "0.1.0",
        "ingress": fixture.transport, "rows": rows, "wrong_password_rejected": true,
        "certificate_name_rejected": true, "quic_datagrams_sent": 0,
        "elapsed_ms": started.elapsed().as_millis(), "native_bridge_emulated_on_linux": true})
    );
    Ok(())
}
