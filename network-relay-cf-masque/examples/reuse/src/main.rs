//! Compile as an independent Cargo workspace; its only patch points h3 at
//! network-relay's vendored copy, as network-relay itself does.
use std::{net::SocketAddr, path::Path};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use warp_masque_egress::{Egress, WarpConfig, WarpEgress};
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let settings = std::env::args().nth(1).unwrap_or_else(|| "relay.toml".into());
    let config = WarpConfig::load(Path::new(&settings))?;
    let warp = WarpEgress::connect(&config).await?;
    let result = async {
        let addresses = warp.resolve("example.com").await?;
        let mut tcp = warp.connect_tcp(SocketAddr::new(addresses[0], 80)).await?;
        tcp.write_all(b"HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n").await?;
        let mut bounded = tcp.take(32 * 1024);
        let mut response = Vec::new();
        bounded.read_to_end(&mut response).await?;
        println!("{}", String::from_utf8_lossy(&response));
        Ok::<_, anyhow::Error>(())
    }
    .await;
    warp.shutdown().await;
    result
}
