//! A CONNECT-UDP request stream, independent of the HTTP version beneath it.
//!
//! RFC 9298 runs over HTTP/1.1 (Upgrade), HTTP/2 and HTTP/3 (extended
//! CONNECT). In every case the request stream carries capsules; UDP payloads
//! travel as HTTP Datagrams, which HTTP/3 sends in QUIC DATAGRAM frames and
//! HTTP/1.1 and HTTP/2 send as DATAGRAM capsules on the stream (RFC 9297).
//! [`Tunnel`] hides those differences from the flow logic.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::{Buf, Bytes, BytesMut};
use h3::error::Code;
use h3::quic::StreamId;
use h3::ConnectionState;
use h3_datagram::datagram_handler::{DatagramSender, SendDatagramError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::debug;

use crate::proto::capsule::{self, types};
use crate::proto::{varint, CapsuleDecoder};

pub type DgramSender = DatagramSender<h3_quinn::datagram::SendDatagramHandler, Bytes>;

/// Stream chunks read ahead from the peer, each at most [`STREAM_CHUNK`].
const INBOUND_QUEUE: usize = 8;
/// Capsules queued for the peer, and their total size: a burst of ordinary
/// packets fits, while a few maximum-size UDP datagrams (64 KiB each) cannot
/// make one flow hold much (`limits::MEMORY_PER_TUNNEL`). UDP drops what does
/// not fit.
const OUTBOUND_QUEUE: usize = 16;
const OUTBOUND_BYTES: usize = 128 * 1024;
/// Split transport buffers before queueing them: a DATA frame can be as
/// large as an entire receive window, so a message-count limit alone is
/// insufficient to bound memory.
const STREAM_CHUNK: usize = 16 * 1024;
/// A peer with a closed request must not retain a blocked writer forever.
const CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// What the peer sent.
#[derive(Debug)]
pub enum Event {
    /// An HTTP Datagram payload, from a QUIC DATAGRAM frame or a DATAGRAM
    /// capsule: context ID followed by its payload.
    Datagram(Bytes),
    /// The peer finished the request stream, or the connection ended.
    Closed,
}

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    /// RFC 9297 §3.3: a malformed capsule makes the HTTP message malformed.
    #[error("malformed capsule stream: {0}")]
    Malformed(crate::proto::Error),
    #[error("tunnel closed")]
    Closed,
    #[error("connection error: {0}")]
    Connection(String),
}

/// Why a tunnel is torn down early, which decides the error code the peer
/// sees (RFC 9114 §4.4, RFC 9113 §8.5, RFC 9297 §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Abort {
    /// The peer sent a malformed capsule or datagram.
    Malformed,
    /// The destination socket failed.
    Failed,
    /// The peer cancelled, the user was revoked, or the peer stopped reading.
    Cancelled,
}

impl Abort {
    pub fn h3_code(self) -> Code {
        match self {
            Abort::Malformed => Code::H3_MESSAGE_ERROR,
            Abort::Failed => Code::H3_CONNECT_ERROR,
            Abort::Cancelled => Code::H3_REQUEST_CANCELLED,
        }
    }

    pub fn h2_reason(self) -> h2::Reason {
        match self {
            Abort::Malformed => h2::Reason::PROTOCOL_ERROR,
            Abort::Failed => h2::Reason::CONNECT_ERROR,
            Abort::Cancelled => h2::Reason::CANCEL,
        }
    }
}

/// Result of sending an HTTP Datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sent {
    Sent,
    /// Queue full; UDP tolerates the loss.
    Dropped,
    /// Larger than a QUIC DATAGRAM frame can carry on this path. The caller
    /// drops it rather than falling back to reliable delivery, which would
    /// defeat the congestion control of whatever runs over UDP (RFC 9298 §5).
    TooBig,
}

/// How HTTP Datagrams travel.
pub enum Datagrams {
    /// HTTP/3 with QUIC DATAGRAM frames.
    Quic(QuicDatagrams),
    /// DATAGRAM capsules on the request stream (HTTP/1.1, HTTP/2).
    Capsules,
}

pub struct QuicDatagrams {
    sender: DgramSender,
    conn: quinn::Connection,
    /// Length of the quarter stream ID prefix HTTP/3 adds.
    qsid_len: usize,
    inbound: mpsc::Receiver<Bytes>,
}

impl QuicDatagrams {
    pub fn new(
        sender: DgramSender,
        conn: quinn::Connection,
        stream_id: StreamId,
        inbound: mpsc::Receiver<Bytes>,
    ) -> Self {
        let qsid_len = varint::encoded_len(stream_id.into_inner() / 4);
        Self { sender, conn, qsid_len, inbound }
    }
}

/// Connects the two halves of an HTTP/3 request stream to a [`Tunnel`].
/// Server and client streams are different types with the same methods.
macro_rules! h3_pumps {
    ($send:ident, $recv:ident, $datagrams:ident) => {{
        let (mut send, mut recv) = ($send, $recv);
        let (in_tx, in_rx) = mpsc::channel(INBOUND_QUEUE);
        let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(OUTBOUND_QUEUE);
        let queued = Arc::new(AtomicUsize::new(0));
        let written = queued.clone();
        let (abort_tx, mut abort_rx) = tokio::sync::watch::channel(None::<Abort>);
        let mut read_abort = abort_rx.clone();
        tokio::spawn(async move {
            let reading = async {
                loop {
                    match recv.recv_data().await {
                        Ok(Some(mut buf)) => {
                            while buf.has_remaining() {
                                let n = buf.remaining().min(STREAM_CHUNK);
                                // `Bytes` slices retain their whole original
                                // allocation; copy so queued chunks really
                                // retain only STREAM_CHUNK bytes each.
                                let chunk = Bytes::copy_from_slice(&buf.copy_to_bytes(n));
                                if in_tx.send(Ok(chunk)).await.is_err() {
                                    return;
                                }
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            debug!("request stream read ended: {e}");
                            let _ = in_tx.send(Err(TunnelError::Connection(e.to_string()))).await;
                            break;
                        }
                    }
                }
            };
            tokio::select! {
                biased;
                // An abort carries its error code. A flow that ended on its
                // own (the tunnel was dropped) stops the client's sending
                // with H3_NO_ERROR; dropping the stream would use code 0.
                changed = read_abort.changed() => {
                    let code = match changed {
                        Ok(()) => read_abort.borrow().map(Abort::h3_code),
                        Err(_) => Some(Code::H3_NO_ERROR),
                    };
                    if let Some(code) = code {
                        recv.stop_sending(code);
                    }
                }
                _ = reading => {}
            }
        });
        tokio::spawn(async move {
            let aborted = {
                let writing = async {
                    while let Some(b) = out_rx.recv().await {
                        let len = b.len();
                        if send.send_data(b).await.is_err() {
                            return;
                        }
                        written.fetch_sub(len, Ordering::Relaxed);
                    }
                    let _ = send.finish().await;
                };
                tokio::pin!(writing);
                tokio::select! {
                    biased;
                    changed = abort_rx.changed() => match changed {
                        Ok(()) => *abort_rx.borrow(),
                        // The flow ended normally: drain for a while, then
                        // give up on a peer that stopped reading.
                        Err(_) => tokio::time::timeout(CLOSE_TIMEOUT, &mut writing).await.err().map(|_| Abort::Cancelled),
                    },
                    _ = &mut writing => None,
                }
            };
            if let Some(why) = aborted {
                send.stop_stream(why.h3_code());
            }
        });
        Self::new(in_rx, out_tx, queued, $datagrams, abort_tx)
    }};
}

pub struct Tunnel {
    inbound: mpsc::Receiver<Result<Bytes, TunnelError>>,
    outbound: mpsc::Sender<Bytes>,
    /// Bytes in `outbound` and in the writer, up to [`OUTBOUND_BYTES`].
    queued: Arc<AtomicUsize>,
    decoder: CapsuleDecoder,
    datagrams: Datagrams,
    /// Tells the reader and writer tasks how the tunnel ends: an abort, or,
    /// when dropped, normally. The writer then drains what is queued and
    /// finishes the stream; the reader stops reading.
    abort: tokio::sync::watch::Sender<Option<Abort>>,
}

impl Tunnel {
    fn new(
        inbound: mpsc::Receiver<Result<Bytes, TunnelError>>,
        outbound: mpsc::Sender<Bytes>,
        queued: Arc<AtomicUsize>,
        datagrams: Datagrams,
        abort: tokio::sync::watch::Sender<Option<Abort>>,
    ) -> Self {
        Self { inbound, outbound, queued, decoder: CapsuleDecoder::default(), datagrams, abort }
    }

    /// Waits for the next datagram from the peer. Capsules other than
    /// DATAGRAM are skipped, as RFC 9297 §3.2 requires for unknown types.
    pub async fn next_event(&mut self) -> Result<Event, TunnelError> {
        loop {
            if self.outbound.is_closed() {
                return Err(TunnelError::Closed);
            }
            if let Some(raw) = self.decoder.next_udp_capsule().map_err(TunnelError::Malformed)? {
                if raw.capsule_type == types::DATAGRAM {
                    return Ok(Event::Datagram(raw.value));
                }
                debug!(capsule_type = raw.capsule_type, "ignoring capsule");
                continue;
            }
            let Tunnel { inbound, outbound, decoder, datagrams, .. } = self;
            let quic = match datagrams {
                Datagrams::Quic(q) => Some(&mut q.inbound),
                Datagrams::Capsules => None,
            };
            let quic_datagram = async {
                match quic {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = outbound.closed() => return Err(TunnelError::Closed),
                chunk = inbound.recv() => match chunk {
                    Some(Ok(bytes)) => decoder.push(bytes),
                    Some(Err(error)) => return Err(error),
                    None => {
                        decoder.finish().map_err(TunnelError::Malformed)?;
                        return Ok(Event::Closed);
                    }
                },
                Some(payload) = quic_datagram => return Ok(Event::Datagram(payload)),
            }
        }
    }

    /// Sends an HTTP Datagram payload (context ID plus data).
    pub fn send_datagram(&mut self, payload: Bytes) -> Result<Sent, TunnelError> {
        let q = match &mut self.datagrams {
            Datagrams::Capsules => return self.send_datagram_capsule(payload),
            Datagrams::Quic(q) => q,
        };
        if !q.sender.settings().enable_datagram() {
            return self.send_datagram_capsule(payload);
        }
        let Some(max) = q.conn.max_datagram_size() else {
            // The peer does not accept QUIC DATAGRAM frames: RFC 9297 §3.5
            // lets us use DATAGRAM capsules instead.
            return self.send_datagram_capsule(payload);
        };
        if payload.len() > max.saturating_sub(q.qsid_len) {
            return Ok(Sent::TooBig);
        }
        match q.sender.send_datagram(payload.clone()) {
            Ok(()) => Ok(Sent::Sent),
            Err(SendDatagramError::TooLarge { .. }) => Ok(Sent::TooBig),
            Err(SendDatagramError::NotAvailable { .. }) => self.send_datagram_capsule(payload),
            Err(e) => Err(TunnelError::Connection(e.to_string())),
        }
    }

    fn send_datagram_capsule(&self, payload: Bytes) -> Result<Sent, TunnelError> {
        if self.outbound.is_closed() {
            return Err(TunnelError::Closed);
        }
        let mut out = BytesMut::new();
        capsule::encode(types::DATAGRAM, &payload, &mut out);
        let len = out.len();
        if self.queued.fetch_add(len, Ordering::Relaxed) + len > OUTBOUND_BYTES {
            self.queued.fetch_sub(len, Ordering::Relaxed);
            return Ok(Sent::Dropped);
        }
        match self.outbound.try_send(out.freeze()) {
            Ok(()) => Ok(Sent::Sent),
            Err(e) => {
                self.queued.fetch_sub(len, Ordering::Relaxed);
                match e {
                    mpsc::error::TrySendError::Full(_) => Ok(Sent::Dropped),
                    mpsc::error::TrySendError::Closed(_) => Err(TunnelError::Closed),
                }
            }
        }
    }

    /// Tears the request stream down in both directions, with the error
    /// code `why` maps to; a malformed message gets the one RFC 9297 §3.3
    /// requires.
    pub fn abort(&self, why: Abort) {
        self.abort.send_replace(Some(why));
    }

    /// Wraps an HTTP/3 request stream on the server.
    pub fn h3_server(
        mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
        datagrams: Datagrams,
    ) -> Self {
        stream.forbid_trailers();
        let (send, recv) = stream.split();
        h3_pumps!(send, recv, datagrams)
    }

    /// Wraps an HTTP/3 request stream on the client.
    pub fn h3_client(
        mut stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
        datagrams: Datagrams,
    ) -> Self {
        stream.forbid_trailers();
        let (send, recv) = stream.split();
        h3_pumps!(send, recv, datagrams)
    }

    /// Wraps the byte stream of an HTTP/1.1 Upgrade or HTTP/2 extended
    /// CONNECT, where datagrams travel as DATAGRAM capsules.
    pub fn upgraded(io: hyper::upgrade::Upgraded) -> Self {
        Self::stream(hyper_util::rt::TokioIo::new(io))
    }

    /// Wraps any byte stream that carries capsules.
    pub fn stream<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static>(io: S) -> Self {
        Self::stream_with_reset(io, None)
    }

    pub(crate) fn stream_with_reset<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static>(
        io: S,
        reset: Option<Box<dyn FnOnce(Abort) + Send>>,
    ) -> Self {
        let (mut rd, mut wr) = tokio::io::split(io);
        let (in_tx, in_rx) = mpsc::channel(INBOUND_QUEUE);
        let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(OUTBOUND_QUEUE);
        let queued = Arc::new(AtomicUsize::new(0));
        let written = queued.clone();
        let (abort_tx, mut abort_rx) = tokio::sync::watch::channel(None::<Abort>);
        let mut read_abort = abort_rx.clone();
        tokio::spawn(async move {
            let reading = async {
                loop {
                    let mut buf = BytesMut::with_capacity(STREAM_CHUNK);
                    match rd.read_buf(&mut buf).await {
                        Ok(0) => break,
                        Ok(_) => {
                            if in_tx.send(Ok(buf.freeze())).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            debug!("tunnel stream read ended: {e}");
                            let _ = in_tx.send(Err(TunnelError::Connection(e.to_string()))).await;
                            break;
                        }
                    }
                }
            };
            tokio::select! {
                biased;
                // Aborted, or the tunnel was dropped.
                _ = read_abort.changed() => {}
                _ = reading => {}
            }
        });
        tokio::spawn(async move {
            let aborted = {
                let writing = async {
                    while let Some(b) = out_rx.recv().await {
                        if wr.write_all(&b).await.is_err() {
                            return;
                        }
                        written.fetch_sub(b.len(), Ordering::Relaxed);
                        // Flush once the queue is drained, so bursts are
                        // batched but nothing waits in a buffer.
                        if out_rx.is_empty() && wr.flush().await.is_err() {
                            return;
                        }
                    }
                    let _ = wr.shutdown().await;
                };
                tokio::pin!(writing);
                tokio::select! {
                    biased;
                    changed = abort_rx.changed() => match changed {
                        Ok(()) => *abort_rx.borrow(),
                        Err(_) => tokio::time::timeout(CLOSE_TIMEOUT, &mut writing).await.err().map(|_| Abort::Cancelled),
                    },
                    _ = &mut writing => None,
                }
            };
            if let (Some(why), Some(reset)) = (aborted, reset) {
                reset(why);
            }
        });
        Self::new(in_rx, out_tx, queued, Datagrams::Capsules, abort_tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn stream_read_errors_do_not_become_clean_fin() {
        struct FailedRead;
        impl tokio::io::AsyncRead for FailedRead {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                _: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()))
            }
        }
        impl tokio::io::AsyncWrite for FailedRead {
            fn poll_write(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                data: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                std::task::Poll::Ready(Ok(data.len()))
            }
            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
        }
        let mut tunnel = Tunnel::stream(FailedRead);
        assert!(
            matches!(tunnel.next_event().await, Err(TunnelError::Connection(_))),
            "read failure was reported as orderly EOF"
        );
    }

    #[tokio::test]
    async fn a_closed_writer_is_not_an_ordinary_udp_drop() {
        let (io, peer) = tokio::io::duplex(8);
        let mut tunnel = Tunnel::stream(io);
        drop(peer);
        tunnel.send_datagram(Bytes::from_static(b"\0test")).unwrap();
        tokio::time::timeout(Duration::from_secs(2), tunnel.outbound.closed()).await.unwrap();
        assert!(matches!(tunnel.send_datagram(Bytes::from_static(b"\0test")), Err(TunnelError::Closed)));
        assert!(matches!(tunnel.next_event().await, Err(TunnelError::Closed)));
    }

    #[tokio::test]
    async fn dropping_a_flow_bounds_a_blocked_writer_and_abort_is_prompt() {
        for abort in [false, true] {
            let (io, _unread_peer) = tokio::io::duplex(1);
            let (tx, rx) = tokio::sync::oneshot::channel();
            let mut tunnel = Tunnel::stream_with_reset(
                io,
                Some(Box::new(|why| {
                    let _ = tx.send(why);
                })),
            );
            tunnel.send_datagram(Bytes::from(vec![0; 1024])).unwrap();
            if abort {
                tunnel.abort(Abort::Malformed);
            }
            drop(tunnel);
            let limit = if abort { Duration::from_millis(500) } else { Duration::from_secs(3) };
            let why = tokio::time::timeout(limit, rx).await.expect("blocked writer leaked").unwrap();
            assert_eq!(why, if abort { Abort::Malformed } else { Abort::Cancelled });
        }
    }

    #[tokio::test]
    async fn dropping_a_tunnel_releases_its_stream() {
        // A reader left behind, waiting for data that never comes, would keep
        // the stream (and the client's request) open after the flow ended.
        struct Marked(tokio::io::DuplexStream, #[allow(dead_code)] Arc<()>);
        impl tokio::io::AsyncRead for Marked {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
            }
        }
        impl tokio::io::AsyncWrite for Marked {
            fn poll_write(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                data: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                std::pin::Pin::new(&mut self.0).poll_write(cx, data)
            }
            fn poll_flush(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::pin::Pin::new(&mut self.0).poll_flush(cx)
            }
            fn poll_shutdown(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
            }
        }
        let (io, _peer) = tokio::io::duplex(1024);
        let marker = Arc::new(());
        drop(Tunnel::stream(Marked(io, marker.clone())));
        tokio::time::timeout(Duration::from_secs(2), async {
            while Arc::strong_count(&marker) > 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the tunnel's stream stayed open");
    }

    #[tokio::test]
    async fn queued_capsules_are_bounded_in_bytes() {
        // The peer never reads: everything stays queued.
        let (io, _unread_peer) = tokio::io::duplex(1);
        let mut tunnel = Tunnel::stream(io);
        let big = datagram_of(60_000);
        let sent = (0..10).filter(|_| tunnel.send_datagram(big.clone()).unwrap() == Sent::Sent).count();
        assert_eq!(sent, OUTBOUND_BYTES / 60_000, "large datagrams beyond the byte limit are dropped");
        assert!(tunnel.queued.load(Ordering::Relaxed) <= OUTBOUND_BYTES);
        // Ordinary packets still fit in what is left, up to the count limit.
        let small = datagram_of(100);
        let fitting = (0..OUTBOUND_QUEUE * 2).filter(|_| tunnel.send_datagram(small.clone()).unwrap() == Sent::Sent);
        assert!(fitting.count() >= OUTBOUND_QUEUE - sent);
        assert!(tunnel.queued.load(Ordering::Relaxed) <= OUTBOUND_BYTES);
    }

    #[tokio::test]
    async fn written_capsules_free_their_queue_space() {
        let (io, mut peer) = tokio::io::duplex(1 << 20);
        let mut tunnel = Tunnel::stream(io);
        let big = datagram_of(60_000);
        for _ in 0..20 {
            // Each fits again once the writer has passed the previous ones on.
            tokio::time::timeout(Duration::from_secs(2), async {
                while tunnel.send_datagram(big.clone()).unwrap() != Sent::Sent {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("queue space was never returned");
            let mut buf = vec![0; 70_000];
            let _ = peer.read(&mut buf).await.unwrap();
        }
    }

    fn datagram_of(len: usize) -> Bytes {
        let mut payload = vec![0u8; len + 1];
        payload[0] = 0;
        Bytes::from(payload)
    }

    #[tokio::test]
    async fn normal_close_drains_queued_capsules() {
        let (io, mut peer) = tokio::io::duplex(1);
        let mut tunnel = Tunnel::stream(io);
        tunnel.send_datagram(Bytes::from_static(b"\0answer")).unwrap();
        drop(tunnel);
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), peer.read_to_end(&mut received)).await.unwrap().unwrap();
        assert_eq!(received, b"\0\x07\0answer");
    }
}
