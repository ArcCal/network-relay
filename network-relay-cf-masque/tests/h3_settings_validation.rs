//! Raw QUIC control streams verify normative HTTP/3 SETTINGS close codes.
mod support;

use anyhow::{ensure, Context, Result};
use relay_frontend::{certs::CertStore, config::Config, server, tls};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use support::relay::TestEnv;
use warp_masque_egress::egress::{Egress, IoFuture, TcpStream, UdpSocket};

struct NoIoEgress;
impl Egress for NoIoEgress {
    fn resolve<'a>(&'a self, _: &'a str) -> IoFuture<'a, Vec<IpAddr>> {
        Box::pin(async { Err(io::Error::other("SETTINGS test must not resolve")) })
    }
    fn connect_tcp(&self, _: SocketAddr) -> IoFuture<'_, TcpStream> {
        Box::pin(async { Err(io::Error::other("SETTINGS test must not dial")) })
    }
    fn connect_udp(&self, _: SocketAddr) -> IoFuture<'_, UdpSocket> {
        Box::pin(async { Err(io::Error::other("SETTINGS test must not open UDP")) })
    }
    fn available(&self) -> bool {
        true
    }
    fn failed(&self) -> IoFuture<'_, ()> {
        Box::pin(std::future::pending())
    }
}

struct Fixture {
    _env: TestEnv,
    server: quinn::Endpoint,
    client: quinn::Endpoint,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.client.close(0u32.into(), b"test complete");
        self.server.close(0u32.into(), b"test complete");
        self.task.abort();
    }
}
impl Fixture {
    async fn new() -> Result<Self> {
        let env = TestEnv::new("raw-settings")?;
        let config: Config = toml::from_str(&format!(
            "[tls]\ncert = {:?}\nkey = {:?}\n[web]\nroot = {:?}\n",
            env.path.join("fullchain.pem"),
            env.path.join("privkey.pem"),
            env.path.join("site")
        ))?;
        let certs = CertStore::open(&config.tls.cert, &config.tls.key)?;
        let relay = server::Relay::new(&config, Arc::new(NoIoEgress))?;
        let server = server::quic_endpoint(certs, std::net::UdpSocket::bind("127.0.0.1:0")?, false)?;
        let task = tokio::spawn(relay.serve_quic(server.clone()));
        let crypto = tls::client_config(Some(&env.path.join("ca.pem")), &[b"h3"])?;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?;
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
        client.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        Ok(Self { _env: env, server, client, task })
    }
    async fn connect(&self) -> Result<quinn::Connection> {
        Ok(tokio::time::timeout(Duration::from_secs(5), self.client.connect(self.server.local_addr()?, "relay.test")?)
            .await??)
    }
}

fn varint(output: &mut Vec<u8>, value: u64) {
    match value {
        0..=63 => output.push(value as u8),
        64..=16383 => output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        16384..=1073741823 => output.extend_from_slice(&((value as u32) | 0x80000000).to_be_bytes()),
        _ => {
            assert!(value < (1 << 62));
            output.extend_from_slice(&(value | (3 << 62)).to_be_bytes());
        }
    }
}
fn control_frame(pairs: &[(u64, u64)]) -> Vec<u8> {
    let mut payload = Vec::new();
    for &(id, value) in pairs {
        varint(&mut payload, id);
        varint(&mut payload, value);
    }
    let mut wire = vec![0, 4]; // Control stream type, then SETTINGS frame type.
    varint(&mut wire, payload.len() as u64);
    wire.extend_from_slice(&payload);
    wire
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_boolean_settings_close_with_settings_error() -> Result<()> {
    let fixture = Fixture::new().await?;
    for pairs in [vec![(0x33, 2)], vec![(0x8, 2)], vec![(0x276, 2)]] {
        let connection = fixture.connect().await?;
        let mut control = connection.open_uni().await?;
        control.write_all(&control_frame(&pairs)).await?;
        let error = tokio::time::timeout(Duration::from_secs(2), connection.closed())
            .await
            .context("invalid SETTINGS did not close the connection")?;
        ensure!(
            matches!(&error, quinn::ConnectionError::ApplicationClosed(close) if close.error_code.into_inner() == 0x109),
            "invalid SETTINGS {pairs:?} produced {error:?}, expected H3_SETTINGS_ERROR (0x109)"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legal_boolean_and_unknown_settings_still_serve_the_standard_cover_site() -> Result<()> {
    let fixture = Fixture::new().await?;
    for value in [0, 1] {
        let connection = fixture.connect().await?;
        let pairs = [(0x33, value), (0x8, value), (0x276, value), (0x21, (1 << 62) - 1)];
        let mut control = connection.open_uni().await?;
        control.write_all(&control_frame(&pairs)).await?;
        let (mut request, mut response) = connection.open_bi().await?;
        // QPACK prefix followed by static GET, https, /, and literal authority.
        let mut headers = vec![0, 0, 0xd1, 0xd7, 0xc1, 0x50, 10];
        headers.extend_from_slice(b"relay.test");
        let mut wire = vec![1]; // HEADERS frame.
        varint(&mut wire, headers.len() as u64);
        wire.extend_from_slice(&headers);
        request.write_all(&wire).await?;
        request.finish()?;
        let reply = tokio::time::timeout(Duration::from_secs(2), response.read_to_end(4096)).await??;
        ensure!(
            reply.windows(b"matrix cover".len()).any(|bytes| bytes == b"matrix cover"),
            "legal SETTINGS prevented cover response"
        );
        ensure!(connection.close_reason().is_none(), "legal SETTINGS closed connection");
        connection.close(0x100u32.into(), b"test complete");
    }
    Ok(())
}
