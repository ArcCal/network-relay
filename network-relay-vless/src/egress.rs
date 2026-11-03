//! network-relay's [`Egress`] through the VLESS server: every name lookup,
//! TCP connection and UDP flow, with no fallback to this host's network.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

use network_relay::egress::{DatagramIo, Egress, IoFuture, TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

use crate::config::VlessConfig;
use crate::dns::Resolver;
use crate::transport::VlessStream;
use crate::vless::{Command, MAX_UDP_PAYLOAD};

/// Datagrams queued per flow in each direction; more are dropped, as UDP
/// allows, rather than held.
const UDP_QUEUE: usize = 64;

pub struct VlessEgress {
    config: Arc<VlessConfig>,
    resolver: Resolver,
}

impl VlessEgress {
    pub fn new(config: VlessConfig) -> Self {
        let config = Arc::new(config);
        Self { resolver: Resolver::new(config.clone()), config }
    }

    /// Opens one lookup through the VLESS server, to check the whole path
    /// (the server, the user ID and a resolver) at start-up.
    pub async fn probe(&self) -> io::Result<()> {
        self.resolver.probe().await
    }
}

impl Egress for VlessEgress {
    fn resolve<'a>(&'a self, host: &'a str) -> IoFuture<'a, Vec<IpAddr>> {
        Box::pin(self.resolver.lookup(host))
    }

    fn connect_tcp(&self, peer: SocketAddr) -> IoFuture<'_, TcpStream> {
        Box::pin(async move {
            let stream = VlessStream::open(&self.config, Command::Tcp, peer).await?;
            let (local, reset) = (stream.local_addr(), stream.reset_handle());
            Ok(TcpStream::new(stream, local, peer, reset))
        })
    }

    fn connect_udp(&self, peer: SocketAddr) -> IoFuture<'_, UdpSocket> {
        Box::pin(async move {
            let stream = VlessStream::open(&self.config, Command::Udp, peer).await?;
            Ok(UdpSocket(Arc::new(VlessUdp::start(stream, peer))))
        })
    }

    /// Each tunnel opens its own VLESS connection, so a server that is down
    /// fails those tunnels (502/504) without making the egress unusable.
    fn available(&self) -> bool {
        true
    }

    fn failed(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(std::future::pending())
    }
}

/// A UDP flow over one VLESS connection. Background tasks frame and unframe
/// the datagrams, so that a dropped `send` or `recv` future never leaves
/// half a datagram on the stream.
struct VlessUdp {
    outgoing: mpsc::Sender<Vec<u8>>,
    incoming: Mutex<mpsc::Receiver<Vec<u8>>>,
    local: SocketAddr,
    peer: SocketAddr,
    tasks: [JoinHandle<()>; 2],
}

impl VlessUdp {
    fn start(stream: VlessStream, peer: SocketAddr) -> Self {
        let local = stream.local_addr();
        let (mut reader, mut writer) = tokio::io::split(stream);
        let (outgoing, mut to_send) = mpsc::channel::<Vec<u8>>(UDP_QUEUE);
        let (received, incoming) = mpsc::channel(UDP_QUEUE);
        let write = tokio::spawn(async move {
            while let Some(frame) = to_send.recv().await {
                if let Err(e) = async {
                    writer.write_all(&frame).await?;
                    writer.flush().await
                }
                .await
                {
                    tracing::debug!("VLESS UDP flow write failed: {e}");
                    return;
                }
            }
        });
        let read = tokio::spawn(async move {
            let result: io::Result<()> = async {
                loop {
                    let length = reader.read_u16().await? as usize;
                    let mut payload = vec![0; length];
                    reader.read_exact(&mut payload).await?;
                    if length == 0 || length > MAX_UDP_PAYLOAD {
                        continue;
                    }
                    match received.try_send(payload) {
                        Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                        Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
                    }
                }
            }
            .await;
            if let Err(e) = result {
                tracing::debug!("VLESS UDP flow ended: {e}");
            }
        });
        Self { outgoing, incoming: Mutex::new(incoming), local, peer, tasks: [write, read] }
    }
}

impl Drop for VlessUdp {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl DatagramIo for VlessUdp {
    fn send<'a>(&'a self, data: &'a [u8]) -> IoFuture<'a, usize> {
        Box::pin(async move {
            if data.is_empty() || data.len() > MAX_UDP_PAYLOAD {
                // Neither travels in VLESS framing; UDP may drop either.
                return Ok(data.len());
            }
            let mut frame = Vec::with_capacity(2 + data.len());
            frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
            frame.extend_from_slice(data);
            match self.outgoing.try_send(frame) {
                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(data.len()),
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    Err(io::Error::new(io::ErrorKind::BrokenPipe, "the VLESS UDP flow is closed"))
                }
            }
        })
    }

    fn recv<'a>(&'a self, data: &'a mut [u8]) -> IoFuture<'a, usize> {
        Box::pin(async move {
            let datagram = self.incoming.lock().await.recv().await.ok_or_else(|| {
                io::Error::new(io::ErrorKind::ConnectionReset, "the VLESS server closed the UDP flow")
            })?;
            let n = datagram.len().min(data.len());
            data[..n].copy_from_slice(&datagram[..n]);
            Ok(n)
        })
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer)
    }

    fn max_payload(&self) -> usize {
        MAX_UDP_PAYLOAD
    }
}
