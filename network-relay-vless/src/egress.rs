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
            let retain = stream.resource_retainer();
            Ok(TcpStream::new(stream, local, peer, reset).with_resource_retainer(retain))
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
    incoming: Mutex<mpsc::Receiver<io::Result<Vec<u8>>>>,
    local: SocketAddr,
    peer: SocketAddr,
    tasks: [JoinHandle<()>; 2],
    retain: Box<dyn Fn(network_relay::egress::ResourceGuard) + Send + Sync>,
}

impl VlessUdp {
    fn start(stream: VlessStream, peer: SocketAddr) -> Self {
        let local = stream.local_addr();
        let retain = Box::new(stream.resource_retainer());
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
                    if length > MAX_UDP_PAYLOAD {
                        continue;
                    }
                    match received.try_send(Ok(payload)) {
                        Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                        Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
                    }
                }
            }
            .await;
            if let Err(e) = result {
                tracing::debug!("VLESS UDP flow ended: {e}");
                // Preserve already queued datagrams before reporting the
                // terminal error. This is one bounded, per-flow wait and is
                // cancelled when the flow owner aborts its reader task.
                let _ = received.send(Err(e)).await;
            }
        });
        Self { outgoing, incoming: Mutex::new(incoming), local, peer, tasks: [write, read], retain }
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
    fn retain_resources(&self, guard: network_relay::egress::ResourceGuard) {
        (self.retain)(guard);
    }

    fn send<'a>(&'a self, data: &'a [u8]) -> IoFuture<'a, usize> {
        Box::pin(async move {
            if data.len() > MAX_UDP_PAYLOAD {
                // Keep packets within the supported downstream payload limit.
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
            })??;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IpPreference;
    use crate::vless::UserId;
    use futures_util::{SinkExt, StreamExt};
    use std::time::Duration;
    use tokio_tungstenite::tungstenite::{Bytes, Message};

    async fn peer(initial_reply: Option<Vec<u8>>) -> (VlessConfig, JoinHandle<()>) {
        peer_then(initial_reply, None).await
    }

    async fn peer_then(initial_reply: Option<Vec<u8>>, terminal: Option<Message>) -> (VlessConfig, JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = VlessConfig {
            server_host: "127.0.0.1".into(),
            server_port: listener.local_addr().unwrap().port(),
            user_id: UserId::parse("b4e4fad1-c320-428e-92dc-f8f6944a7dec").unwrap(),
            path: "/udp".into(),
            host_header: "vless.test".into(),
            dns_servers: vec!["127.0.0.1:53".parse().unwrap()],
            ip_preference: IpPreference::Ipv4First,
        };
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let Some(Ok(Message::Binary(request))) = ws.next().await else { panic!("missing request") };
            assert_eq!(request[18], Command::Udp as u8);
            let mut reply = vec![0, 0];
            if let Some(initial) = initial_reply {
                reply.extend(initial);
            }
            ws.send(Message::Binary(reply.into())).await.unwrap();
            if let Some(message) = terminal {
                ws.send(message).await.unwrap();
                return;
            }
            while let Some(Ok(message)) = ws.next().await {
                match message {
                    Message::Binary(data) => ws.send(Message::Binary(data)).await.unwrap(),
                    Message::Close(_) => return,
                    _ => {}
                }
            }
        });
        (config, task)
    }

    async fn receive(flow: &UdpSocket) -> Vec<u8> {
        let mut data = vec![0; MAX_UDP_PAYLOAD];
        let length = tokio::time::timeout(Duration::from_secs(2), flow.recv(&mut data))
            .await
            .expect("missing UDP datagram")
            .unwrap();
        data.truncate(length);
        data
    }

    #[tokio::test]
    async fn empty_datagrams_round_trip_between_nonempty_packets() {
        let (config, task) = peer(None).await;
        let flow = VlessEgress::new(config).connect_udp("192.0.2.1:53".parse().unwrap()).await.unwrap();
        for length in [0, 1, 0, 1200, 0] {
            let payload = vec![0xa5; length];
            assert_eq!(flow.send(&payload).await.unwrap(), length);
            assert_eq!(receive(&flow).await, payload);
        }
        drop(flow);
        tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn empty_reply_is_a_datagram_and_keeps_the_flow_open() {
        let (config, task) = peer(Some(vec![0, 0, 0, 1, 42])).await;
        let flow = VlessEgress::new(config).connect_udp("192.0.2.1:53".parse().unwrap()).await.unwrap();
        assert_eq!(receive(&flow).await, Bytes::new());
        assert_eq!(receive(&flow).await, [42]);
        assert_eq!(flow.send(b"still open").await.unwrap(), 10);
        assert_eq!(receive(&flow).await, b"still open");
        drop(flow);
        tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn buffered_datagram_precedes_the_original_read_error() {
        let (config, task) = peer_then(Some(vec![0, 1, 42]), Some(Message::Text("invalid UDP stream".into()))).await;
        let flow = VlessEgress::new(config).connect_udp("192.0.2.1:53".parse().unwrap()).await.unwrap();
        assert_eq!(receive(&flow).await, [42]);
        let mut data = [0; 16];
        let error = tokio::time::timeout(Duration::from_secs(2), flow.recv(&mut data)).await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert!(error.to_string().contains("text WebSocket message"), "{error}");
        drop(flow);
        tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn full_receive_queue_cancels_without_holding_a_socket_or_blocking_another_flow() {
        let (mut config, echo_task) = peer(None).await;
        let sibling = VlessEgress::new(config.clone()).connect_udp("192.0.2.2:53".parse().unwrap()).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        config.server_port = listener.local_addr().unwrap().port();
        let (sent, error_sent) = tokio::sync::oneshot::channel();
        let closing_peer = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            assert!(matches!(ws.next().await, Some(Ok(Message::Binary(_)))));
            let mut reply = vec![0, 0];
            for number in 0..UDP_QUEUE {
                reply.extend_from_slice(&[0, 1, number as u8]);
            }
            ws.send(Message::Binary(reply.into())).await.unwrap();
            ws.send(Message::Text("invalid after a full queue".into())).await.unwrap();
            sent.send(()).unwrap();
            assert!(matches!(ws.next().await, Some(Ok(Message::Close(_)))));
            match ws.flush().await {
                Ok(()) => {
                    let mut data = [0; 1];
                    match ws.get_mut().read(&mut data).await {
                        Ok(0) => {}
                        Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
                        other => panic!("the cancelled flow must release its TCP socket: {other:?}"),
                    }
                }
                // Cancellation need not keep the read half alive for our
                // Close acknowledgment; an unread reply can cause a reset.
                Err(tokio_tungstenite::tungstenite::Error::Io(e)) if e.kind() == io::ErrorKind::ConnectionReset => {}
                other => panic!("unexpected Close acknowledgment failure: {other:?}"),
            }
        });
        let stream = VlessStream::open(&config, Command::Udp, "192.0.2.1:53".parse().unwrap()).await.unwrap();
        let flow = VlessUdp::start(stream, "192.0.2.1:53".parse().unwrap());
        let admission = Arc::new(tokio::sync::Semaphore::new(1));
        flow.retain_resources(Arc::new(admission.clone().try_acquire_owned().unwrap()));
        error_sent.await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while flow.incoming.lock().await.len() != UDP_QUEUE {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(sibling.send(b"independent").await.unwrap(), 11);
        assert_eq!(receive(&sibling).await, b"independent");
        assert!(!flow.tasks[1].is_finished(), "the terminal error must wait behind buffered datagrams");
        drop(flow);
        tokio::time::timeout(Duration::from_secs(2), closing_peer).await.unwrap().unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while admission.available_permits() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(sibling.send(b"still independent").await.unwrap(), 17);
        assert_eq!(receive(&sibling).await, b"still independent");
        drop(sibling);
        tokio::time::timeout(Duration::from_secs(2), echo_task).await.unwrap().unwrap();
    }
}
