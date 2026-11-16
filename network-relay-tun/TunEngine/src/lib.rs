//! Unprivileged TUN-to-SOCKS engine. No relay credentials, TLS,
//! route changes, DNS configuration, shell commands or privilege installation.
//! The host launches this worker with an inherited utun descriptor.
use std::{io, net::SocketAddr};
use tokio::io::{AsyncRead, AsyncWrite};
pub use tun2proxy::CancellationToken;

fn arguments(proxy: SocketAddr) -> io::Result<tun2proxy::Args> {
    if !proxy.ip().is_loopback() || proxy.port() == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "TUN requires a numeric loopback NF SOCKS endpoint"));
    }
    let mut args = tun2proxy::Args::default();
    args.proxy = format!("socks5://{proxy}")
        .as_str()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid local SOCKS endpoint"))?;
    args.setup = false;
    args.ipv6_enabled = true;
    // 'Direct' means normal DNS packet forwarding through the SOCKS handler,
    // not direct destination sockets. Virtual DNS requires separate acceptance.
    args.dns = tun2proxy::ArgDns::Direct;
    args.mtu = 1500;
    args.max_sessions = 128;
    args.udp_timeout = 120;
    Ok(args)
}

/// The caller supplies an IP packet device with native utun framing removed.
/// The helper owns the interface and configuration; this engine owns no routes.
pub async fn run<D>(device: D, proxy: SocketAddr, stop: CancellationToken) -> Result<usize, tun2proxy::BoxError>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    run_with_mtu(device, proxy, 1500, stop).await
}

/// MTU must match the configured packet device. Jumbo MTUs are optional.
pub async fn run_with_mtu<D>(
    device: D,
    proxy: SocketAddr,
    mtu: u16,
    stop: CancellationToken,
) -> Result<usize, tun2proxy::BoxError>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if !(1280..=9000).contains(&mtu) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "MTU outside supported range").into());
    }
    let mut args = arguments(proxy)?;
    args.mtu = mtu;
    tun2proxy::run(device, mtu, args, stop).await.map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn candidate_cannot_request_system_setup_or_nonlocal_proxy() {
        for endpoint in ["127.0.0.1:1080", "[::1]:1080"] {
            let args = arguments(endpoint.parse().unwrap()).unwrap();
            assert!(!args.setup);
            assert!(args.ipv6_enabled);
            assert!(args.bypass.is_empty());
            assert_eq!(args.udp_timeout, 120);
        }
        for endpoint in ["0.0.0.0:1080", "192.0.2.1:1080", "127.0.0.1:0"] {
            assert!(arguments(endpoint.parse().unwrap()).is_err());
        }
    }
}
