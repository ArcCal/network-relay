//! Reusable Cloudflare WARP MASQUE egress, implementing network-relay's
//! tunnel [`Egress`] interface.
//!
//! ```no_run
//! use std::{net::SocketAddr, path::Path};
//! use warp_masque_egress::{Egress, WarpConfig, WarpEgress};
//! # async fn run() -> anyhow::Result<()> {
//! let config = WarpConfig::load(Path::new("relay.toml"))?;
//! let egress = WarpEgress::connect(&config).await?;
//! let addresses = egress.resolve("example.com").await?;
//! let stream = egress.connect_tcp(SocketAddr::new(addresses[0], 443)).await?;
//! let reset = stream.abort_handle();
//! # drop(reset);
//! # drop(stream);
//! egress.shutdown().await;
//! # Ok(()) }
//! ```
mod api;
mod config;
mod dns;
#[cfg(any(test, feature = "test-support"))]
mod ip;
mod masque;
mod net;
mod netstack;
mod runtime;
mod varint;

pub use config::WarpConfig;
pub use masque::Transport;
pub use network_relay::egress;
pub use network_relay::egress::{DatagramIo, Egress, IoFuture, TcpStream, UdpSocket};
pub use runtime::{WarpEgress, WarpStatus};

/// Synthetic peer primitives available only for explicit development builds.
#[cfg(feature = "test-support")]
pub mod test_support {
    pub use crate::ip::{checksum, decrement_hops, destination, packet_too_big, pseudo_header, IPV6_MIN_MTU};
    pub use crate::netstack::{max_udp_payload, NetStack, TcpListener, TcpStream, UdpSocket, MTU};
}
