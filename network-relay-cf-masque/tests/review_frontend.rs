//! Owner cancellation also owns accepted clients that never finish TLS.
use std::{
    io,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use relay_frontend::{config::Config, server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use warp_masque_egress::egress::{Egress, IoFuture, TcpStream, UdpSocket};

struct NoIoEgress;

impl Egress for NoIoEgress {
    fn resolve<'a>(&'a self, _: &'a str) -> IoFuture<'a, Vec<IpAddr>> {
        Box::pin(async { Err(io::Error::other("test must not resolve a destination")) })
    }
    fn connect_tcp(&self, _: SocketAddr) -> IoFuture<'_, TcpStream> {
        Box::pin(async { Err(io::Error::other("test must not dial a destination")) })
    }
    fn connect_udp(&self, _: SocketAddr) -> IoFuture<'_, UdpSocket> {
        Box::pin(async { Err(io::Error::other("test must not open destination UDP")) })
    }
    fn available(&self) -> bool {
        true
    }
    fn failed(&self) -> IoFuture<'_, ()> {
        Box::pin(std::future::pending())
    }
}

struct Env(PathBuf);
impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_run_closes_an_accepted_partial_tls_handshake_promptly() {
    let env = Env(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/review/runtime")
        .join(format!("partial-tls-{}", std::process::id())));
    std::fs::create_dir_all(&env.0).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["relay.test".into()]).unwrap().self_signed(&key).unwrap();
    let cert_path = env.0.join("cert.pem");
    let key_path = env.0.join("key.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    let addr = loop {
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = udp.local_addr().unwrap();
        if let Ok(tcp) = std::net::TcpListener::bind(addr) {
            drop((tcp, udp));
            break addr;
        }
    };
    let text = format!("listen = \"{addr}\"\n[tls]\ncert = {cert_path:?}\nkey = {key_path:?}\n");
    let config: Config = toml::from_str(&text).unwrap();
    let path = env.0.join("relay.toml");
    std::fs::write(&path, text).unwrap();
    let run = tokio::spawn(server::run(path, config, Arc::new(NoIoEgress)));
    let mut client = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            assert!(!run.is_finished(), "server stopped before accepting a client");
            if let Ok(tcp) = tokio::net::TcpStream::connect(addr).await {
                break tcp;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("server did not start");
    // A partial TLS record keeps the accepted handshake task waiting for input.
    client.write_all(&[0x16]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!run.is_finished());
    run.abort();
    assert!(run.await.unwrap_err().is_cancelled());
    let started = std::time::Instant::now();
    let mut byte = [0; 1];
    let closed = tokio::time::timeout(Duration::from_millis(250), client.read(&mut byte)).await;
    assert!(
        matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
        "accepted partial TLS connection survived run cancellation for {:?}: {closed:?}",
        started.elapsed()
    );
}
