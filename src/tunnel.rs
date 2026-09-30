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
use h3_datagram::datagram_handler::{DatagramSender, SendDatagramError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::debug;

use crate::proto::capsule::{self, types};
use crate::proto::{varint, CapsuleDecoder};

pub type DgramSender = DatagramSender<h3_quinn::datagram::SendDatagramHandler, Bytes>;

/// Stream chunks buffered in each direction.
const STREAM_QUEUE: usize = 256;

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

enum Outbound {
    Data(Bytes),
    Abort,
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
        let (out_tx, mut out_rx) = mpsc::channel(STREAM_QUEUE);
        let reader = tokio::spawn(async move {
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
        });
        tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                match msg {
                    Outbound::Data(b) => {
                        if send.send_data(b).await.is_err() {
                            return;
                        }
                    }
                    Outbound::Abort => {
                        send.stop_stream(Code::H3_MESSAGE_ERROR);
                        return;
                    }
                }
            }
            let _ = send.finish().await;
        });
        Self::new(in_rx, out_tx, $datagrams, reader)
    }};
}

pub struct Tunnel {
    inbound: mpsc::Receiver<Bytes>,
    outbound: mpsc::Sender<Outbound>,
    decoder: CapsuleDecoder,
    datagrams: Datagrams,
    reader: tokio::task::JoinHandle<()>,
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        // The writer ends on its own once `outbound` is dropped, after
        // finishing the stream gracefully.
        self.reader.abort();
    }
}

impl Tunnel {
    fn new(
        inbound: mpsc::Receiver<Bytes>,
        outbound: mpsc::Sender<Outbound>,
        datagrams: Datagrams,
        reader: tokio::task::JoinHandle<()>,
    ) -> Self {
        Self { inbound, outbound, decoder: CapsuleDecoder::default(), datagrams, reader }
    }

    /// Waits for the next datagram from the peer. Capsules other than
    /// DATAGRAM are skipped, as RFC 9297 §3.2 requires for unknown types.
    pub async fn next_event(&mut self) -> Result<Event, TunnelError> {
        loop {
            if let Some(raw) = self.decoder.next_capsule().map_err(TunnelError::Malformed)? {
                if raw.capsule_type == types::DATAGRAM {
                    return Ok(Event::Datagram(raw.value));
                }
                debug!(capsule_type = raw.capsule_type, "ignoring capsule");
                continue;
            }
            let Tunnel { inbound, decoder, datagrams, .. } = self;
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
            Datagrams::Capsules => return Ok(self.send_datagram_capsule(payload)),
            Datagrams::Quic(q) => q,
        };
        let Some(max) = q.conn.max_datagram_size() else {
            // The peer does not accept QUIC DATAGRAM frames: RFC 9297 §3.5
            // lets us use DATAGRAM capsules instead.
            return Ok(self.send_datagram_capsule(payload));
        };
        if payload.len() > max.saturating_sub(q.qsid_len) {
            return Ok(Sent::TooBig);
        }
        match q.sender.send_datagram(payload.clone()) {
            Ok(()) => Ok(Sent::Sent),
            Err(SendDatagramError::TooLarge { .. }) => Ok(Sent::TooBig),
            Err(SendDatagramError::NotAvailable { .. }) => Ok(self.send_datagram_capsule(payload)),
            Err(e) => Err(TunnelError::Connection(e.to_string())),
        }
    }

    fn send_datagram_capsule(&self, payload: Bytes) -> Sent {
        let mut out = BytesMut::new();
        capsule::encode(types::DATAGRAM, &payload, &mut out);
        match self.outbound.try_send(Outbound::Data(out.freeze())) {
            Ok(()) => Sent::Sent,
            Err(_) => Sent::Dropped,
        }
    }

    /// Largest HTTP Datagram payload that currently fits in one QUIC
    /// DATAGRAM frame, or `None` when datagrams travel as capsules and have
    /// no such limit.
    pub fn max_datagram_payload(&self) -> Option<usize> {
        match &self.datagrams {
            Datagrams::Quic(q) => q.conn.max_datagram_size().map(|m| m.saturating_sub(q.qsid_len)),
            Datagrams::Capsules => None,
        }
    }

    /// Aborts the request stream, as RFC 9297 §3.3 requires for a malformed
    /// message.
    pub fn abort(&self) {
        let _ = self.outbound.try_send(Outbound::Abort);
    }

    /// Wraps an HTTP/3 request stream on the server.
    pub fn h3_server(
        stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
        datagrams: Datagrams,
    ) -> Self {
        let (send, recv) = stream.split();
        h3_pumps!(send, recv, datagrams)
    }

    /// Wraps an HTTP/3 request stream on the client.
    pub fn h3_client(
        stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
        datagrams: Datagrams,
    ) -> Self {
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
        let (mut rd, mut wr) = tokio::io::split(io);
        let (in_tx, in_rx) = mpsc::channel(STREAM_QUEUE);
        let (out_tx, mut out_rx) = mpsc::channel::<Outbound>(STREAM_QUEUE);
        let reader = tokio::spawn(async move {
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
        });
        tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                match msg {
                    Outbound::Data(b) => {
                        if wr.write_all(&b).await.is_err() {
                            return;
                        }
                        // Flush once the queue is drained, so bursts are
                        // batched but nothing waits in a buffer.
                        if out_rx.is_empty() && wr.flush().await.is_err() {
                            return;
                        }
                    }
                    // Dropping the stream resets it.
                    Outbound::Abort => return,
                }
            }
            let _ = wr.shutdown().await;
        });
        Self::new(in_rx, out_tx, Datagrams::Capsules, reader)
    }
}
