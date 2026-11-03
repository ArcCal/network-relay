//! Moving data between a client's tunnel and the destination socket.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, BytesMut};
use h3::error::Code;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::debug;

use super::{Cancellation, ConnInfo, TunnelCtx};
use crate::connect::{Tcp, Udp};
use crate::limits::Budget;
use crate::proto::datagram::{self, CONTEXT_ID_UDP_PAYLOAD};
use crate::tunnel::{Abort, Event, Sent, Tunnel, TunnelError};

/// Bytes read from a destination at a time.
const CHUNK: usize = 64 * 1024;

type H3Stream = h3::server::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>;
type H3Send = h3::server::RequestStream<h3_quinn::SendStream<bytes::Bytes>, bytes::Bytes>;
type H3Recv = h3::server::RequestStream<h3_quinn::RecvStream, bytes::Bytes>;

/// Makes closing `tcp` send a TCP reset instead of an orderly close, so the
/// destination learns the connection failed (RFC 9114 §4.4, RFC 9113 §8.5).
fn reset_on_close(tcp: &TcpStream) {
    let _ = socket2::SockRef::from(tcp).set_linger(Some(Duration::ZERO));
}

/// The destination side of a tunnel, counting bytes as they pass, so the
/// connection's totals are right however the tunnel ends, and holding each
/// direction back when the user's traffic budget is spent.
struct Counted<'a> {
    tcp: &'a mut Tcp,
    conn: &'a ConnInfo,
    budget: Option<&'a Budget>,
    read_pause: Option<Pin<Box<tokio::time::Sleep>>>,
    write_pause: Option<Pin<Box<tokio::time::Sleep>>>,
}

/// Charges `n` bytes to `budget` and returns the pause owed, if any.
fn charge(budget: Option<&Budget>, n: usize) -> Option<Pin<Box<tokio::time::Sleep>>> {
    let wait = budget?.charge_bytes(n);
    (!wait.is_zero()).then(|| Box::pin(tokio::time::sleep(wait)))
}

/// Waits out a pause, if one is pending.
fn poll_pause(pause: &mut Option<Pin<Box<tokio::time::Sleep>>>, cx: &mut Context<'_>) -> Poll<()> {
    if let Some(p) = pause {
        std::task::ready!(p.as_mut().poll(cx));
        *pause = None;
    }
    Poll::Ready(())
}

impl AsyncRead for Counted<'_> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        std::task::ready!(poll_pause(&mut self.read_pause, cx));
        let before = buf.filled().len();
        let r = Pin::new(&mut *self.tcp).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        self.conn.down.fetch_add(n as u64, Ordering::Relaxed);
        if n > 0 {
            self.read_pause = charge(self.budget, n);
        }
        r
    }
}

impl AsyncWrite for Counted<'_> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        std::task::ready!(poll_pause(&mut self.write_pause, cx));
        let r = Pin::new(&mut *self.tcp).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = r {
            self.conn.up.fetch_add(n as u64, Ordering::Relaxed);
            if n > 0 {
                self.write_pause = charge(self.budget, n);
            }
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
    mut tcp: Tcp,
    mut ctx: TunnelCtx,
) -> bool {
    let conn = ctx.conn.clone();
    let budget = ctx.budget.clone();
    let result = {
        let mut target =
            Counted { tcp: &mut tcp, conn: &conn, budget: budget.as_deref(), read_pause: None, write_pause: None };
        tokio::select! {
            r = tokio::io::copy_bidirectional_with_sizes(&mut client, &mut target, CHUNK, CHUNK) => r.map_err(|e| e.to_string()),
            why = ctx.cancelled() => Err(why.as_str().into()),
        }
    };
    let success = match result {
        Ok((up, down)) => {
            debug!(user = %ctx.user.name, target = %ctx.target, up, down, "TCP tunnel closed");
            true
        }
        Err(e) => {
            tcp.abort();
            debug!(user = %ctx.user.name, target = %ctx.target, "TCP tunnel aborted: {e}");
            false
        }
    };
    drop(tcp); // Close the foreground socket before releasing admission.
    drop(ctx);
    success
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
pub(super) async fn tcp_over_h3(
    mut stream: H3Stream,
    tcp: Tcp,
    mut ctx: TunnelCtx,
    mut bad_datagram: tokio::sync::oneshot::Receiver<()>,
) {
    stream.forbid_trailers();
    let (mut send, mut recv) = stream.split();
    let outcome = match tcp {
        Tcp::Host(tcp) => {
            let (mut rd, mut wr) = tcp.into_split();
            let outcome = h3_transfer(&mut send, &mut recv, &mut rd, &mut wr, &mut ctx, &mut bad_datagram).await;
            if let H3Outcome::Abort(code, _) = &outcome {
                stop(&mut send, &mut recv, *code);
                reset_on_close(rd.as_ref());
                // Keep the write half from sending a FIN before the reset.
                wr.forget();
            }
            outcome
        }
        Tcp::Egress(tcp) => {
            let abort = tcp.abort_handle();
            // Unlike a kernel socket's halves, dropping these sends no FIN.
            let (mut rd, mut wr) = tokio::io::split(tcp);
            let outcome = h3_transfer(&mut send, &mut recv, &mut rd, &mut wr, &mut ctx, &mut bad_datagram).await;
            if let H3Outcome::Abort(code, _) = &outcome {
                stop(&mut send, &mut recv, *code);
                abort();
            }
            outcome
        }
    };
    match outcome {
        H3Outcome::Done => debug!(user = %ctx.user.name, target = %ctx.target, "TCP tunnel closed"),
        H3Outcome::Abort(_, why) => debug!(user = %ctx.user.name, target = %ctx.target, "TCP tunnel aborted: {why}"),
    }
}

fn stop(send: &mut H3Send, recv: &mut H3Recv, code: Code) {
    send.stop_stream(code);
    recv.stop_sending(code);
}

/// Moves data both ways until both sides have finished or one fails.
async fn h3_transfer<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    send: &mut H3Send,
    recv: &mut H3Recv,
    rd: &mut R,
    wr: &mut W,
    ctx: &mut TunnelCtx,
    bad_datagram: &mut tokio::sync::oneshot::Receiver<()>,
) -> H3Outcome {
    let conn = ctx.conn.clone();
    let budget = ctx.budget.clone();
    {
        let up = async {
            loop {
                match recv.recv_data().await {
                    Ok(Some(mut buf)) => {
                        if let Some(b) = &budget {
                            b.spend_bytes(buf.remaining()).await;
                        }
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
                        wr.shutdown().await.map_err(|e| format!("closing destination write side: {e}"))?;
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
                        send.finish().await.map_err(|e| format!("finishing client stream: {e}"))?;
                        return Ok(());
                    }
                    Ok(n) => {
                        conn.down.fetch_add(n as u64, Ordering::Relaxed);
                        if let Err(e) = send.send_data(buf.split().freeze()).await {
                            return Err(format!("client stream: {e}"));
                        }
                        if let Some(b) = &budget {
                            b.spend_bytes(n).await;
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
                // Once the request's receive side is closed, RFC 9297 §2.1
                // asks for datagrams to be dropped silently instead.
                Ok(()) = &mut *bad_datagram, if !up_done => break H3Outcome::Abort(Code::H3_DATAGRAM_ERROR, "datagram on TCP request".into()),
                why = ctx.cancelled() => break match why {
                    Cancellation::Cancelled => H3Outcome::Abort(Code::H3_REQUEST_CANCELLED, why.as_str().into()),
                    // The destination connection failed (RFC 9114 section 4.4).
                    Cancellation::EgressFailed => H3Outcome::Abort(Code::H3_CONNECT_ERROR, why.as_str().into()),
                },
            }
        }
    }
}

/// Relays UDP datagrams between a CONNECT-UDP tunnel and a connected UDP
/// socket until the client closes the stream, the flow is idle for
/// `udp_idle_timeout`, or the user is revoked.
pub(super) async fn udp(mut tunnel: Tunnel, sock: Udp, mut ctx: TunnelCtx) {
    let idle = ctx.udp_idle_timeout;
    let budget = ctx.budget.clone();
    let allowed = |n: usize| budget.as_ref().is_none_or(|b| b.allow_packet(n));
    let activity = std::sync::Mutex::new(tokio::time::Instant::now());
    let conn = ctx.conn.clone();
    let (mut up, mut down, mut dropped) = (0u64, 0u64, 0u64);
    let (why, abort) = {
        let deadline = async {
            loop {
                let next = *activity.lock().unwrap() + idle;
                tokio::time::sleep_until(next).await;
                if tokio::time::Instant::now() >= *activity.lock().unwrap() + idle {
                    break;
                }
            }
        };
        let transferring = async {
            let mut buf = [0u8; 65_535];
            'flow: loop {
                tokio::select! {
                    event = tunnel.next_event() => match event {
                        Ok(Event::Datagram(payload)) => {
                            *activity.lock().unwrap() = tokio::time::Instant::now();
                            match datagram::split_context_id(&payload) {
                                // RFC 9298 §5: longer than a UDP packet can carry.
                                Ok((CONTEXT_ID_UDP_PAYLOAD, data)) if data.len() > datagram::MAX_UDP_PAYLOAD => {
                                    break ("oversized UDP payload", Some(Abort::Malformed));
                                }
                                // Awaited rather than tried: a new socket is not yet
                                // known to be writable, and `try_send` would drop the
                                // flow's first datagram, often a QUIC handshake.
                                // Over the user's budget: dropped, as UDP allows.
                                Ok((CONTEXT_ID_UDP_PAYLOAD, data)) if !allowed(data.len()) => dropped += 1,
                                // Too large for an egress's path: dropped, as
                                // UDP allows, never fragmented.
                                Ok((CONTEXT_ID_UDP_PAYLOAD, data)) if data.len() > sock.max_payload() => dropped += 1,
                                Ok((CONTEXT_ID_UDP_PAYLOAD, data)) => match sock.send(data).await {
                                    Ok(n) if n == data.len() => {
                                        up += 1;
                                        conn.up.fetch_add(n as u64, Ordering::Relaxed);
                                    }
                                    Ok(_) => break ("partial UDP send", Some(Abort::Failed)),
                                    // A datagram too large for the path, say:
                                    // dropped, as UDP allows (RFC 9298 §3.1).
                                    Err(e) if udp_error_is_transient(&e) => dropped += 1,
                                    // An egress path whose MTU shrank meanwhile.
                                    Err(_) if data.len() > sock.max_payload() => dropped += 1,
                                    Err(e) => break (unusable(&e), Some(Abort::Failed)),
                                },
                            // Unknown context IDs are dropped (RFC 9298 §4).
                            Ok(_) => dropped += 1,
                            Err(_) => break ("missing or truncated UDP context ID", Some(Abort::Malformed)),
                            }
                        }
                        Ok(Event::Closed) => break ("client closed the stream", None),
                        Err(TunnelError::Malformed(e)) => {
                            debug!("malformed capsule stream: {e}");
                            break ("malformed capsule stream", Some(Abort::Malformed));
                        }
                        Err(TunnelError::Closed) => break ("client stopped reading", Some(Abort::Cancelled)),
                        Err(TunnelError::Connection(_)) => break ("connection error", Some(Abort::Failed)),
                    },
                    received = sock.recv(&mut buf) => {
                        // Then what else has arrived, bounded per poll so an
                        // always-readable socket cannot starve cancellation,
                        // other flows, or the idle deadline. One buffer
                        // serves the whole batch.
                        let mut received = Some(received);
                        for _ in 0..32 {
                            let received = match received.take() {
                                Some(r) => r,
                                None => match sock.try_recv(&mut buf) {
                                    Some(r) => r,
                                    None => break,
                                },
                            };
                            match received {
                                Ok(n) if !allowed(n) => dropped += 1,
                                Ok(n) => {
                                    *activity.lock().unwrap() = tokio::time::Instant::now();
                                    conn.down.fetch_add(n as u64, Ordering::Relaxed);
                                    match tunnel.send_datagram(datagram::udp_payload(&buf[..n])) {
                                        Ok(Sent::Sent) => down += 1,
                                        Ok(Sent::Dropped | Sent::TooBig) => dropped += 1,
                                        Err(TunnelError::Closed) => break 'flow ("client stopped reading", Some(Abort::Cancelled)),
                                        Err(_) => break 'flow ("connection error", Some(Abort::Failed)),
                                    }
                                }
                                Err(e) if udp_error_is_transient(&e) => break,
                                // ICMP Destination Unreachable, for example.
                                Err(e) => break 'flow (unusable(&e), Some(Abort::Failed)),
                            }
                        }
                    }
                }
                tokio::task::yield_now().await;
            }
        };
        // Keep these outside the transfer loop, including any pending socket send.
        tokio::select! {
            biased;
            why = ctx.cancelled() => match why {
                Cancellation::Cancelled => (why.as_str(), Some(Abort::Cancelled)),
                Cancellation::EgressFailed => (why.as_str(), Some(Abort::Failed)),
            },
            _ = deadline => ("idle", None),
            result = transferring => result,
        }
    };
    if let Some(why) = abort {
        tunnel.abort(why);
    }
    debug!(user = %ctx.user.name, target = %ctx.target, up, down, dropped, "UDP flow closed: {why}");
    drop(sock);
    drop(ctx);
}

/// Errors that concern one datagram, after which the socket still works: a
/// datagram too large for the path, a full send queue, a local firewall rule.
///
/// Everything else ends the flow. RFC 9298 §3.1: "If a UDP proxy is notified
/// by its operating system that its socket is no longer usable, it MUST close
/// the request stream", with ICMP Destination Unreachable as the example. On
/// a connected socket Linux reports one as ECONNREFUSED (port unreachable),
/// EHOSTUNREACH or ENETUNREACH on the next send or receive; an egress
/// reports them with the same error kinds.
fn udp_error_is_transient(error: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted | ErrorKind::PermissionDenied)
        || matches!(error.raw_os_error(), Some(nix::libc::EMSGSIZE | nix::libc::ENOBUFS))
}

/// Why a flow ended on a socket error, for the log.
fn unusable(error: &std::io::Error) -> &'static str {
    use std::io::ErrorKind;
    match error.kind() {
        ErrorKind::ConnectionRefused => "destination port unreachable (ICMP)",
        ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable => "destination unreachable (ICMP)",
        _ => "unusable UDP socket",
    }
}
