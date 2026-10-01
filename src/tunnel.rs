//! A CONNECT-UDP request stream, independent of the HTTP version beneath it.
//!
//! RFC 9298 runs over HTTP/1.1 (Upgrade), HTTP/2 and HTTP/3 (extended
//! CONNECT). In every case the request stream carries capsules; UDP payloads
//! travel as HTTP Datagrams, which HTTP/3 sends in QUIC DATAGRAM frames and
//! HTTP/1.1 and HTTP/2 send as DATAGRAM capsules on the stream (RFC 9297).
//! [`Tunnel`] hides those differences from the flow logic.

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

/// Stream chunks buffered in each direction.
const STREAM_QUEUE: usize = 256;
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
        let (in_tx, in_rx) = mpsc::channel(STREAM_QUEUE);
        let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(STREAM_QUEUE);
        let (abort_tx, mut abort_rx) = tokio::sync::watch::channel(false);
        let mut read_abort = abort_rx.clone();
        let reader = tokio::spawn(async move {
            let reading = async {
                loop {
                    match recv.recv_data().await {
                        Ok(Some(mut buf)) => {
                            if in_tx.send(buf.copy_to_bytes(buf.remaining())).await.is_err() {
                                break;
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            debug!("request stream read ended: {e}");
                            break;
                        }
                    }
                }
            };
            tokio::select! {
                biased;
                Ok(()) = read_abort.changed() => recv.stop_sending(Code::H3_MESSAGE_ERROR),
                _ = reading => {}
            }
        });
        tokio::spawn(async move {
            let aborted = {
                let writing = async {
                    while let Some(b) = out_rx.recv().await {
                        if send.send_data(b).await.is_err() {
                            return;
                        }
                    }
                    let _ = send.finish().await;
                };
                tokio::pin!(writing);
                tokio::select! {
                    biased;
                    changed = abort_rx.changed() => match changed {
                        Ok(()) => true,
                        Err(_) => tokio::time::timeout(CLOSE_TIMEOUT, &mut writing).await.is_err(),
                    },
                    _ = &mut writing => false,
                }
            };
            if aborted {
                send.stop_stream(Code::H3_MESSAGE_ERROR);
            }
        });
        Self::new(in_rx, out_tx, $datagrams, reader, abort_tx)
    }};
}

pub struct Tunnel {
    inbound: mpsc::Receiver<Bytes>,
    outbound: mpsc::Sender<Bytes>,
    decoder: CapsuleDecoder,
    datagrams: Datagrams,
    reader: tokio::task::JoinHandle<()>,
    abort: tokio::sync::watch::Sender<bool>,
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        // The writer ends on its own once `outbound` is dropped, after
        // finishing the stream gracefully.
        if !*self.abort.borrow() {
            self.reader.abort();
        }
    }
}

impl Tunnel {
    fn new(
        inbound: mpsc::Receiver<Bytes>,
        outbound: mpsc::Sender<Bytes>,
        datagrams: Datagrams,
        reader: tokio::task::JoinHandle<()>,
        abort: tokio::sync::watch::Sender<bool>,
    ) -> Self {
        Self { inbound, outbound, decoder: CapsuleDecoder::default(), datagrams, reader, abort }
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
                    Some(bytes) => decoder.push(bytes),
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
        let mut out = BytesMut::new();
        capsule::encode(types::DATAGRAM, &payload, &mut out);
        match self.outbound.try_send(out.freeze()) {
            Ok(()) => Ok(Sent::Sent),
            Err(mpsc::error::TrySendError::Full(_)) => Ok(Sent::Dropped),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(TunnelError::Closed),
        }
    }

    /// Largest HTTP Datagram payload that currently fits in one QUIC
    /// DATAGRAM frame, or `None` when datagrams travel as capsules and have
    /// no such limit.
    pub fn max_datagram_payload(&self) -> Option<usize> {
        match &self.datagrams {
            Datagrams::Quic(q) if q.sender.settings().enable_datagram() => {
                q.conn.max_datagram_size().map(|m| m.saturating_sub(q.qsid_len))
            }
            Datagrams::Quic(_) => None,
            Datagrams::Capsules => None,
        }
    }

    /// Aborts the request stream, as RFC 9297 §3.3 requires for a malformed
    /// message.
    pub fn abort(&self) {
        self.abort.send_replace(true);
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
        reset: Option<Box<dyn FnOnce() + Send>>,
    ) -> Self {
        let (mut rd, mut wr) = tokio::io::split(io);
        let (in_tx, in_rx) = mpsc::channel(STREAM_QUEUE);
        let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(STREAM_QUEUE);
        let (abort_tx, mut abort_rx) = tokio::sync::watch::channel(false);
        let mut read_abort = abort_rx.clone();
        let reader = tokio::spawn(async move {
            let reading = async {
                loop {
                    let mut buf = BytesMut::with_capacity(16 * 1024);
                    match rd.read_buf(&mut buf).await {
                        Ok(0) => break,
                        Ok(_) => {
                            if in_tx.send(buf.freeze()).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            debug!("tunnel stream read ended: {e}");
                            break;
                        }
                    }
                }
            };
            tokio::select! {
                biased;
                Ok(()) = read_abort.changed() => {}
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
                        Ok(()) => true,
                        Err(_) => tokio::time::timeout(CLOSE_TIMEOUT, &mut writing).await.is_err(),
                    },
                    _ = &mut writing => false,
                }
            };
            if aborted {
                if let Some(reset) = reset {
                    reset();
                }
            }
        });
        Self::new(in_rx, out_tx, Datagrams::Capsules, reader, abort_tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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
                Some(Box::new(|| {
                    let _ = tx.send(());
                })),
            );
            tunnel.send_datagram(Bytes::from(vec![0; 1024])).unwrap();
            if abort {
                tunnel.abort();
            }
            drop(tunnel);
            let limit = if abort { Duration::from_millis(500) } else { Duration::from_secs(3) };
            tokio::time::timeout(limit, rx).await.expect("blocked writer leaked").unwrap();
        }
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
