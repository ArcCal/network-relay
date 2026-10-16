//! Large downloads through real relay servers over every transport, directly
//! and through the SOCKS listener: the exact bytes arrive, a slow reader is
//! throttled rather than failed, and a destination that aborts mid-download
//! is reported as an error, and to the SOCKS program as a connection reset,
//! rather than as a clean end of data. Run by `scripts/test-interop.py --test
//! large_transfer`; `RELAY_NF_DOWNLOAD_MIB` sets the size (default 64). The
//! `RELAY_NF_TEST_TRANSPORT` optionally isolates one forced mode; the default
//! still checks all three. The Quinn/rustls emulator replaces Network.framework.
mod support;
use network_relay_nf_core::{Config, client::Client};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const CLEAN: u8 = 0;
const ABORT: u8 = 1;

fn pattern(offset: u64, out: &mut [u8]) {
    for (i, byte) in out.iter_mut().enumerate() {
        let n = offset + i as u64;
        *byte = (n ^ (n >> 8) ^ (n >> 16)) as u8;
    }
}

/// A destination that reads `mode` and a size, sends that many pattern bytes
/// and then either finishes cleanly or resets the connection.
async fn source() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut tcp, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mode = tcp.read_u8().await.unwrap();
                let size = tcp.read_u64().await.unwrap();
                let mut sent = 0;
                let mut chunk = vec![0; 64 << 10];
                while sent < size {
                    let n = chunk.len().min((size - sent) as usize);
                    pattern(sent, &mut chunk[..n]);
                    if tcp.write_all(&chunk[..n]).await.is_err() {
                        return;
                    }
                    sent += n as u64;
                }
                if mode == ABORT {
                    tcp.set_zero_linger().unwrap();
                    drop(tcp);
                    return;
                }
                tcp.shutdown().await.unwrap();
                let _ = tcp.read_u8().await;
            });
        }
    });
    address
}

/// Reads to the end, checking the pattern; the count, or the error with the
/// count reached. `pause` stalls the reader once, after its first 4 MiB.
async fn receive(
    mut io: impl AsyncRead + Unpin,
    pause: Option<Duration>,
) -> Result<u64, (u64, std::io::Error)> {
    let mut received = 0u64;
    let mut pause = pause;
    let mut buffer = vec![0; 64 << 10];
    let mut expected = vec![0; 64 << 10];
    loop {
        if received >= 4 << 20
            && let Some(pause) = pause.take()
        {
            tokio::time::sleep(pause).await;
        }
        let n = match io.read(&mut buffer).await {
            Ok(0) => return Ok(received),
            Ok(n) => n,
            Err(e) => return Err((received, e)),
        };
        pattern(received, &mut expected[..n]);
        assert!(buffer[..n] == expected[..n], "corrupt data at {received}");
        received += n as u64;
    }
}

fn settings(fixture: &serde_json::Value, transport: &str) -> Config {
    Config {
        uri_template: format!(
            "https://{}/.well-known/masque/udp/{{target_host}}/{{target_port}}/",
            fixture["server"].as_str().unwrap()
        ),
        username: "alice".into(),
        password: fixture["password"].as_str().unwrap().into(),
        server_name: Some("relay.test".into()),
        transport: transport.into(),
        probe_target: fixture["udp"].as_str().unwrap().parse().unwrap(),
        mode: "socks".into(),
        socks: network_relay_nf_core::Socks {
            listen: vec!["127.0.0.1:0".parse().unwrap()],
        },
    }
}

fn command(mode: u8, size: u64) -> Vec<u8> {
    let mut bytes = vec![mode];
    bytes.extend_from_slice(&size.to_be_bytes());
    bytes
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a RELAY_NF_FIXTURE written by scripts/test-interop.py"]
async fn large_downloads() {
    let fixture: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("RELAY_NF_FIXTURE").unwrap()).unwrap())
            .unwrap();
    let kind = fixture["kind"].as_str().unwrap().to_string();
    let size: u64 = std::env::var("RELAY_NF_DOWNLOAD_MIB").map_or(64, |v| v.parse().unwrap()) << 20;
    let target = source().await;
    let only = std::env::var("RELAY_NF_TEST_TRANSPORT").ok();
    assert!(
        only.as_deref()
            .is_none_or(|mode| ["http/1.1", "h2", "h3"].contains(&mode)),
        "RELAY_NF_TEST_TRANSPORT must be http/1.1, h2 or h3"
    );
    for transport in ["http/1.1", "h2", "h3"] {
        if only.as_deref().is_some_and(|mode| mode != transport) {
            continue;
        }
        let backend = support::Backend::start(fixture["ca"].as_str().unwrap().into());
        let client =
            Arc::new(Client::new(&settings(&fixture, transport), backend.bridge.clone()).unwrap());

        // A complete download, sent while the request side stays open.
        let mut opened = client
            .open("127.0.0.1", target.port(), false)
            .await
            .unwrap();
        opened
            .stream
            .write_all(&command(CLEAN, size))
            .await
            .unwrap();
        let started = Instant::now();
        let received =
            tokio::time::timeout(Duration::from_secs(120), receive(&mut opened.stream, None))
                .await
                .expect("download stalled");
        let elapsed = started.elapsed();
        assert_eq!(
            received.map_err(|(n, e)| format!("{e} after {n} bytes")),
            Ok(size),
            "{kind} {transport}"
        );
        println!(
            "{kind} {transport}: {} MiB download in {:.2}s ({:.1} MiB/s)",
            size >> 20,
            elapsed.as_secs_f64(),
            (size >> 20) as f64 / elapsed.as_secs_f64()
        );
        drop(opened);

        // A reader that stops for a while is held back by flow control.
        let mut opened = client
            .open("127.0.0.1", target.port(), false)
            .await
            .unwrap();
        opened
            .stream
            .write_all(&command(CLEAN, 32 << 20))
            .await
            .unwrap();
        let received = tokio::time::timeout(
            Duration::from_secs(120),
            receive(&mut opened.stream, Some(Duration::from_secs(5))),
        )
        .await
        .expect("paused download stalled");
        assert_eq!(
            received.map_err(|(n, e)| format!("{e} after {n} bytes")),
            Ok(32 << 20),
            "{kind} {transport} paused reader"
        );
        drop(opened);

        // A destination that resets mid-download must not look complete.
        let mut opened = client
            .open("127.0.0.1", target.port(), false)
            .await
            .unwrap();
        opened
            .stream
            .write_all(&command(ABORT, 8 << 20))
            .await
            .unwrap();
        let outcome =
            tokio::time::timeout(Duration::from_secs(60), receive(&mut opened.stream, None))
                .await
                .expect("aborted download stalled");
        println!(
            "{kind} {transport}: destination reset after 8 MiB -> {:?}",
            outcome.as_ref().map_err(|(n, e)| (n, e.to_string()))
        );
        assert!(
            outcome.is_err(),
            "{kind} {transport}: a cut-off download must not end cleanly"
        );
        drop(opened);

        // The same download through the local SOCKS listener.
        let listener = backend
            .bridge
            .listen("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let worker = tokio::spawn(network_relay_nf_core::socks::run(
            client.clone(),
            vec![listener],
        ));
        let mut local = TcpStream::connect(address).await.unwrap();
        local.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0; 2];
        local.read_exact(&mut reply).await.unwrap();
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&target.port().to_be_bytes());
        local.write_all(&request).await.unwrap();
        let mut reply = [0; 10];
        local.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0, "SOCKS CONNECT");
        local.write_all(&command(CLEAN, size)).await.unwrap();
        let started = Instant::now();
        let received = tokio::time::timeout(Duration::from_secs(180), receive(&mut local, None))
            .await
            .expect("SOCKS download stalled");
        let elapsed = started.elapsed();
        assert_eq!(
            received.map_err(|(n, e)| format!("{e} after {n} bytes")),
            Ok(size),
            "{kind} {transport} SOCKS"
        );
        println!(
            "{kind} {transport}: {} MiB SOCKS download in {:.2}s ({:.1} MiB/s)",
            size >> 20,
            elapsed.as_secs_f64(),
            (size >> 20) as f64 / elapsed.as_secs_f64()
        );
        drop(local);

        // A destination reset mid-download, seen by the SOCKS program.
        let mut local = TcpStream::connect(address).await.unwrap();
        local.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0; 2];
        local.read_exact(&mut reply).await.unwrap();
        local.write_all(&request).await.unwrap();
        let mut reply = [0; 10];
        local.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0, "SOCKS CONNECT");
        local.write_all(&command(ABORT, 8 << 20)).await.unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(60), receive(&mut local, None))
            .await
            .expect("aborted SOCKS download stalled");
        println!(
            "{kind} {transport}: destination reset after 8 MiB, SOCKS program sees {:?}",
            outcome.as_ref().map_err(|(n, e)| (n, e.to_string()))
        );
        assert!(
            matches!(&outcome, Err((_, e)) if e.kind() == std::io::ErrorKind::ConnectionReset),
            "{kind} {transport}: a cut-off SOCKS download must end in a reset, not a FIN"
        );
        drop(local);
        worker.abort();
        let _ = worker.await;
    }
}
