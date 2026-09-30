//! Moving data between a client's tunnel and the destination socket.

use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, BytesMut};
use h3::error::Code;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

use super::{ConnInfo, TunnelCtx};
use crate::proto::datagram::{self, CONTEXT_ID_UDP_PAYLOAD};
use crate::tunnel::{Event, Sent, Tunnel, TunnelError};

/// Bytes read from a destination at a time.
const CHUNK: usize = 64 * 1024;

type H3Stream = h3::server::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>;

/// Makes closing `tcp` send a TCP reset instead of an orderly close, so the
/// destination learns the connection failed (RFC 9114 §4.4, RFC 9113 §8.5).
fn reset_on_close(tcp: &TcpStream) {
    let _ = socket2::SockRef::from(tcp).set_linger(Some(Duration::ZERO));
}

/// The destination side of a tunnel, counting bytes as they pass, so the
/// connection's totals are right however the tunnel ends.
struct Counted<'a> {
    tcp: &'a mut TcpStream,
    conn: &'a ConnInfo,
}

impl AsyncRead for Counted<'_> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut *self.tcp).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        self.conn.down.fetch_add(n as u64, Ordering::Relaxed);
        r
    }
}

impl AsyncWrite for Counted<'_> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut *self.tcp).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = r {
            self.conn.up.fetch_add(n as u64, Ordering::Relaxed);
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.tcp).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.tcp).poll_shutdown(cx)
    }
}

/// Relays TCP over the byte stream of an HTTP/1.1 or HTTP/2 CONNECT. Each
/// side's end of data becomes an end of data on the other (half-close).
pub(super) async fn tcp_over_stream<S: AsyncRead + AsyncWrite + Unpin>(
    mut client: S,
    mut tcp: TcpStream,
    mut ctx: TunnelCtx,
) {
    let conn = ctx.conn.clone();
    let result = {
        let mut target = Counted { tcp: &mut tcp, conn: &conn };
        tokio::select! {
            r = tokio::io::copy_bidirectional_with_sizes(&mut client, &mut target, CHUNK, CHUNK) => r.map_err(|e| e.to_string()),
            _ = ctx.revoked() => Err("user removed or password changed".into()),
        }
    };
    match result {
        Ok((up, down)) => debug!(user = %ctx.user.name, target = %ctx.target, up, down, "TCP tunnel closed"),
        Err(e) => {
            reset_on_close(&tcp);
            debug!(user = %ctx.user.name, target = %ctx.target, "TCP tunnel aborted: {e}");
        }
    }
}

enum H3Outcome {
    Done,
    /// Tear both sides down: `code` resets the request stream, and the
    /// destination connection is reset.
    Abort(Code, String),
}

/// Relays TCP over an HTTP/3 CONNECT stream. A FIN on either side becomes a
/// FIN on the other; an error on either side resets both, with
/// H3_CONNECT_ERROR towards the client (RFC 9114 §4.4).
pub(super) async fn tcp_over_h3(stream: H3Stream, tcp: TcpStream, mut ctx: TunnelCtx) {
    let (mut send, mut recv) = stream.split();
    let (mut rd, mut wr) = tcp.into_split();
    let conn = ctx.conn.clone();
    let outcome = {
        let up = async {
            loop {
                match recv.recv_data().await {
                    Ok(Some(mut buf)) => {
                        while buf.has_remaining() {
                            let chunk = buf.chunk();
                            let n = chunk.len();
                            if let Err(e) = wr.write_all(chunk).await {
                                return Err(format!("writing to destination: {e}"));
                            }
                            conn.up.fetch_add(n as u64, Ordering::Relaxed);
                            buf.advance(n);
                        }
                    }
                    Ok(None) => {
                        let _ = wr.shutdown().await;
                        return Ok(());
                    }
                    Err(e) => return Err(format!("client stream: {e}")),
                }
            }
        };
        let down = async {
            let mut buf = BytesMut::with_capacity(CHUNK);
            loop {
                buf.reserve(CHUNK);
                match rd.read_buf(&mut buf).await {
                    Ok(0) => {
                        let _ = send.finish().await;
                        return Ok(());
                    }
                    Ok(n) => {
                        conn.down.fetch_add(n as u64, Ordering::Relaxed);
                        if let Err(e) = send.send_data(buf.split().freeze()).await {
                            return Err(format!("client stream: {e}"));
                        }
                    }
                    Err(e) => return Err(format!("reading from destination: {e}")),
                }
            }
        };
        tokio::pin!(up, down);
        let (mut up_done, mut down_done) = (false, false);
        loop {
            if up_done && down_done {
                break H3Outcome::Done;
            }
            tokio::select! {
                r = &mut up, if !up_done => match r {
                    Ok(()) => up_done = true,
                    Err(e) => break H3Outcome::Abort(Code::H3_CONNECT_ERROR, e),
                },
                r = &mut down, if !down_done => match r {
                    Ok(()) => down_done = true,
                    Err(e) => break H3Outcome::Abort(Code::H3_CONNECT_ERROR, e),
                },
                _ = ctx.revoked() => break H3Outcome::Abort(Code::H3_REQUEST_CANCELLED, "user removed or password changed".into()),
            }
        }
    };
    match outcome {
        H3Outcome::Done => debug!(user = %ctx.user.name, target = %ctx.target, "TCP tunnel closed"),
        H3Outcome::Abort(code, why) => {
            send.stop_stream(code);
            recv.stop_sending(code);
            reset_on_close(rd.as_ref());
            // Keep the write half from sending a FIN before the reset.
            wr.forget();
            debug!(user = %ctx.user.name, target = %ctx.target, "TCP tunnel aborted: {why}");
        }
    }
}

/// Relays UDP datagrams between a CONNECT-UDP tunnel and a connected UDP
/// socket until the client closes the stream, the flow is idle for
/// `udp_idle_timeout`, or the user is revoked.
pub(super) async fn udp(mut tunnel: Tunnel, sock: UdpSocket, mut ctx: TunnelCtx) {
    let idle = ctx.udp_idle_timeout;
    let deadline = tokio::time::sleep(idle);
    tokio::pin!(deadline);
    let (mut up, mut down, mut dropped) = (0u64, 0u64, 0u64);
    let why = loop {
        tokio::select! {
            event = tunnel.next_event() => match event {
                Ok(Event::Datagram(payload)) => {
                    deadline.as_mut().reset(tokio::time::Instant::now() + idle);
                    match datagram::split_context_id(&payload) {
                        // Awaited rather than tried: a new socket is not yet
                        // known to be writable, and `try_send` would drop the
                        // flow's first datagram, often a QUIC handshake.
                        Ok((CONTEXT_ID_UDP_PAYLOAD, data)) => match sock.send(data).await {
                            Ok(n) => {
                                up += 1;
                                ctx.conn.up.fetch_add(n as u64, Ordering::Relaxed);
                            }
                            // An ICMP error from an earlier datagram, for
                            // example: UDP tolerates the loss.
                            Err(_) => dropped += 1,
                        },
                        // Unknown context IDs are dropped (RFC 9298 §4).
                        _ => dropped += 1,
                    }
                }
                Ok(Event::Closed) => break "client closed the stream",
                Err(TunnelError::Malformed(e)) => {
                    tunnel.abort();
                    debug!("malformed capsule stream: {e}");
                    break "malformed capsule stream";
                }
                Err(_) => break "stream ended",
            },
            ready = sock.readable() => {
                if ready.is_err() {
                    break "socket error";
                }
                deadline.as_mut().reset(tokio::time::Instant::now() + idle);
                loop {
                    let mut buf = [0u8; 65_535];
                    match sock.try_recv(&mut buf) {
                        Ok(n) => {
                            ctx.conn.down.fetch_add(n as u64, Ordering::Relaxed);
                            match tunnel.send_datagram(datagram::udp_payload(&buf[..n])) {
                                Ok(Sent::Sent) => down += 1,
                                Ok(Sent::Dropped | Sent::TooBig) => dropped += 1,
                                Err(_) => break,
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        // ICMP errors such as port unreachable surface here;
                        // the flow stays open, as an unconnected socket would.
                        Err(_) => break,
                    }
                }
            }
            _ = &mut deadline => break "idle",
            _ = ctx.revoked() => {
                tunnel.abort();
                break "user removed or password changed";
            }
        }
    };
    debug!(user = %ctx.user.name, target = %ctx.target, up, down, dropped, "UDP flow closed: {why}");
}
