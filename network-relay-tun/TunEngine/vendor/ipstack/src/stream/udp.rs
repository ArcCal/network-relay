use crate::{
    IpStackError, PacketReceiver, PacketSender, TTL,
    packet::{IpHeader, NetworkPacket, TransportHeader},
};
use etherparse::{IpNumber, Ipv4Header, Ipv6FlowLabel, Ipv6Header, UdpHeader};
use std::{future::Future, net::SocketAddr, pin::Pin, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::Sleep,
};

/// A UDP stream in the IP stack.
///
/// This type represents a UDP connection and implements `AsyncRead` and `AsyncWrite`
/// for bidirectional data transfer. UDP streams have a configurable timeout and
/// retain datagram boundaries through the datagram-oriented methods.
///
/// # Examples
///
/// ```no_run
/// use ipstack::{IpStack, IpStackConfig, IpStackStream};
/// use tokio::io::{AsyncReadExt, AsyncWriteExt};
///
/// # async fn example(mut ip_stack: IpStack) -> Result<(), Box<dyn std::error::Error>> {
/// if let IpStackStream::Udp(mut udp_stream) = ip_stack.accept().await? {
///     println!("New UDP stream from {}", udp_stream.peer_addr());
///     
///     // Read data
///     let mut buffer = [0u8; 1024];
///     let n = udp_stream.read(&mut buffer).await?;
///     
///     // Write data
///     udp_stream.write_all(b"Response").await?;
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct IpStackUdpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    stream_sender: PacketSender,
    stream_receiver: PacketReceiver,
    up_pkt_sender: PacketSender,
    first_payload: Option<Vec<u8>>,
    timeout: Pin<Box<Sleep>>,
    timeout_interval: Duration,
    destroy_messenger: Option<::tokio::sync::oneshot::Sender<()>>,
}

impl IpStackUdpStream {
    pub fn new(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        payload: Vec<u8>,
        up_pkt_sender: PacketSender,
        _mtu: u16,
        timeout_interval: Duration,
        destroy_messenger: Option<::tokio::sync::oneshot::Sender<()>>,
    ) -> Self {
        let (stream_sender, stream_receiver) = crate::packet_channel();
        let deadline = tokio::time::Instant::now() + timeout_interval;
        IpStackUdpStream {
            src_addr,
            dst_addr,
            stream_sender,
            stream_receiver,
            up_pkt_sender,
            first_payload: Some(payload),
            timeout: Box::pin(tokio::time::sleep_until(deadline)),
            timeout_interval,
            destroy_messenger,
        }
    }

    pub(crate) fn stream_sender(&self) -> PacketSender {
        self.stream_sender.clone()
    }

    /// Datagram-oriented receive distinguishes an empty payload from EOF.
    pub async fn recv_datagram(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        if let Some(payload) = self.first_payload.take() {
            self.reset_timeout();
            return Ok(Some(payload));
        }
        tokio::select! {
            _ = &mut self.timeout => Err(std::io::ErrorKind::TimedOut.into()),
            packet = self.stream_receiver.recv() => {
                match packet {
                    Some(packet) => { self.reset_timeout(); Ok(Some(packet.payload.unwrap_or_default())) },
                    None => Ok(None),
                }
            }
        }
    }

    /// Preserve the entire datagram. The virtual receive path must not silently
    /// truncate payloads to an interface's outbound segmentation MTU.
    pub fn send_datagram(&mut self, payload: &[u8]) -> std::io::Result<()> {
        if payload.len() > 65507 { return Err(std::io::ErrorKind::InvalidInput.into()); }
        let packet = self.create_rev_packet(TTL, payload.to_vec())?;
        self.up_pkt_sender.send(packet).map_err(|_| std::io::ErrorKind::BrokenPipe)?;
        self.reset_timeout();
        Ok(())
    }

    fn create_rev_packet(&self, ttl: u8, payload: Vec<u8>) -> std::io::Result<NetworkPacket> {
        const UHS: usize = 8; // udp header size is 8
        match (self.dst_addr.ip(), self.src_addr.ip()) {
            (std::net::IpAddr::V4(dst), std::net::IpAddr::V4(src)) => {
                let mut ip_h = Ipv4Header::new(0, ttl, IpNumber::UDP, dst.octets(), src.octets()).map_err(IpStackError::from)?;

                ip_h.set_payload_len(payload.len() + UHS).map_err(IpStackError::from)?;
                let udp_header = UdpHeader::with_ipv4_checksum(self.dst_addr.port(), self.src_addr.port(), &ip_h, &payload)
                    .map_err(IpStackError::from)?;
                Ok(NetworkPacket {
                    ip: IpHeader::Ipv4(ip_h),
                    transport: TransportHeader::Udp(udp_header),
                    payload: Some(payload),
                })
            }
            (std::net::IpAddr::V6(dst), std::net::IpAddr::V6(src)) => {
                let mut ip_h = Ipv6Header {
                    traffic_class: 0,
                    flow_label: Ipv6FlowLabel::ZERO,
                    payload_length: 0,
                    next_header: IpNumber::UDP,
                    hop_limit: ttl,
                    source: dst.octets(),
                    destination: src.octets(),
                };


                ip_h.payload_length = (payload.len() + UHS) as u16;
                let udp_header = UdpHeader::with_ipv6_checksum(self.dst_addr.port(), self.src_addr.port(), &ip_h, &payload)
                    .map_err(IpStackError::from)?;
                Ok(NetworkPacket {
                    ip: IpHeader::Ipv6(ip_h),
                    transport: TransportHeader::Udp(udp_header),
                    payload: Some(payload),
                })
            }
            _ => unreachable!(),
        }
    }

    /// Returns the local socket address of the UDP stream.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use ipstack::IpStackUdpStream;
    /// # fn example(udp_stream: &IpStackUdpStream) {
    /// let local_addr = udp_stream.local_addr();
    /// println!("Local address: {}", local_addr);
    /// # }
    /// ```
    pub fn local_addr(&self) -> SocketAddr {
        self.src_addr
    }

    /// Returns the remote socket address of the UDP stream.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use ipstack::IpStackUdpStream;
    /// # fn example(udp_stream: &IpStackUdpStream) {
    /// let peer_addr = udp_stream.peer_addr();
    /// println!("Peer address: {}", peer_addr);
    /// # }
    /// ```
    pub fn peer_addr(&self) -> SocketAddr {
        self.dst_addr
    }

    fn reset_timeout(&mut self) {
        let deadline = tokio::time::Instant::now() + self.timeout_interval;
        self.timeout.as_mut().reset(deadline);
    }
}

impl AsyncRead for IpStackUdpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Some(p) = self.first_payload.take() {
            // Clamp to `buf.remaining()`: an oversized datagram would otherwise
            // panic `put_slice` (hit under `copy_bidirectional` write
            // backpressure). Unlike the TCP path the remainder is DROPPED, not buffered matches `recvfrom` without MSG_WAITALL.
            let n = p.len().min(buf.remaining());
            buf.put_slice(&p[..n]);
            return std::task::Poll::Ready(Ok(()));
        }
        if matches!(self.timeout.as_mut().poll(cx), std::task::Poll::Ready(_)) {
            return std::task::Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::TimedOut)));
        }

        self.reset_timeout();

        match self.stream_receiver.poll_recv(cx) {
            std::task::Poll::Ready(Some(p)) => {
                if let Some(payload) = p.payload {
                    // Clamp like the first_payload branch above (drop the tail).
                    let n = payload.len().min(buf.remaining());
                    buf.put_slice(&payload[..n]);
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl AsyncWrite for IpStackUdpStream {
    fn poll_write(mut self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        self.reset_timeout();
        let packet = self.create_rev_packet(TTL, buf.to_vec())?;
        let payload_len = packet.payload.as_ref().map(|p| p.len()).unwrap_or(0);
        self.up_pkt_sender.send(packet).or(Err(std::io::ErrorKind::UnexpectedEof))?;
        std::task::Poll::Ready(Ok(payload_len))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl Drop for IpStackUdpStream {
    fn drop(&mut self) {
        // Cleanup must observe a closed receiver as soon as it is notified.
        self.stream_receiver.close();

        if let Some(messenger) = self.destroy_messenger.take() {
            let _ = messenger.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn stream(first_payload: Vec<u8>) -> IpStackUdpStream {
        let (up_tx, _up_rx) = crate::packet_channel();
        IpStackUdpStream::new(
            "127.0.0.1:1234".parse().unwrap(),
            "127.0.0.1:53".parse().unwrap(),
            first_payload,
            up_tx,
            1500,
            Duration::from_secs(30),
            None,
        )
    }

    #[tokio::test]
    async fn receiver_is_closed_before_destroy_notification_wakes_waiter() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        use std::task::{Context, Poll, Wake, Waker};

        struct CheckClosedOnWake {
            sender: PacketSender,
            observed_closed: AtomicBool,
        }

        impl Wake for CheckClosedOnWake {
            fn wake(self: Arc<Self>) {
                // Inspect the channel synchronously inside notification delivery,
                // before Drop returns and Rust destroys the receiver field.
                self.observed_closed.store(self.sender.is_closed(), Ordering::SeqCst);
            }
        }

        let mut stream = stream(Vec::new());
        let (destroy_tx, mut destroy_rx) = tokio::sync::oneshot::channel();
        stream.destroy_messenger = Some(destroy_tx);
        let check = Arc::new(CheckClosedOnWake {
            sender: stream.stream_sender(),
            observed_closed: AtomicBool::new(false),
        });
        let waker = Waker::from(check.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(Pin::new(&mut destroy_rx).poll(&mut cx), Poll::Pending));

        drop(stream);

        assert!(check.observed_closed.load(Ordering::SeqCst));
        assert_eq!(destroy_rx.try_recv(), Ok(()));
    }

    // A datagram larger than the caller's buffer used to panic `put_slice`; it
    // must now truncate to the buffer instead. Covers both branches of poll_read.

    #[tokio::test]
    async fn poll_read_truncates_oversized_first_payload() {
        let mut s = stream(vec![7u8; 1250]);
        let mut small = [0u8; 502];
        assert_eq!(s.read(&mut small).await.unwrap(), 502);
        assert!(small.iter().all(|&b| b == 7));
    }

    #[tokio::test]
    async fn poll_read_truncates_oversized_relayed_datagram() {
        let mut s = stream(Vec::new());
        s.first_payload = None; // skip to the stream_receiver branch
        let pkt = s.create_rev_packet(64, vec![9u8; 1250]).unwrap();
        s.stream_sender().send(pkt).unwrap();
        let mut small = [0u8; 502];
        assert_eq!(s.read(&mut small).await.unwrap(), 502);
    }
}
