//! A CONNECT stream with explicit HTTP/2 flow control and reset semantics.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct Send {
    stream: h2::SendStream<Bytes>,
    closed: bool,
    reset: bool,
}

#[derive(Clone)]
pub(super) struct Reset(Arc<Mutex<Send>>);

impl Reset {
    pub async fn cancelled(&self) {
        let _ = std::future::poll_fn(|cx| self.0.lock().unwrap().stream.poll_reset(cx)).await;
    }

    pub fn reset(&self, reason: h2::Reason) {
        let mut send = self.0.lock().unwrap();
        if !send.reset {
            send.stream.send_reset(reason);
            send.closed = true;
            send.reset = true;
        }
    }
}

pub(super) struct Stream {
    recv: h2::RecvStream,
    send: Arc<Mutex<Send>>,
    buffered: Bytes,
}

impl Stream {
    pub fn new(recv: h2::RecvStream, send: h2::SendStream<Bytes>) -> (Self, Reset) {
        let send = Arc::new(Mutex::new(Send { stream: send, closed: false, reset: false }));
        let reset = Reset(send.clone());
        (Self { recv, send, buffered: Bytes::new() }, reset)
    }
}

impl AsyncRead for Stream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, dst: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if dst.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        while self.buffered.is_empty() {
            match self.recv.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(io::Error::other(e))),
                Poll::Ready(None) => match std::task::ready!(self.recv.poll_trailers(cx)).map_err(io::Error::other)? {
                    Some(_) => {
                        Reset(self.send.clone()).reset(h2::Reason::PROTOCOL_ERROR);
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, "trailers on CONNECT")));
                    }
                    None => return Poll::Ready(Ok(())),
                },
                Poll::Ready(Some(Ok(bytes))) => self.buffered = bytes,
            }
        }
        let n = dst.remaining().min(self.buffered.len());
        dst.put_slice(&self.buffered[..n]);
        self.buffered.advance(n);
        self.recv.flow_control().release_capacity(n).map_err(io::Error::other)?;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut send = self.send.lock().unwrap();
        if send.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        match send.stream.poll_reset(cx) {
            Poll::Ready(Ok(reason)) => return Poll::Ready(Err(io::Error::other(h2::Error::from(reason)))),
            Poll::Ready(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
            Poll::Pending => {}
        }
        send.stream.reserve_capacity(bytes.len().min(64 * 1024));
        // Capacity can shrink again after h2 reported an increase (the client
        // may lower its window): wait for the next increase rather than
        // waking at once, which would spin.
        while send.stream.capacity() == 0 {
            match send.stream.poll_capacity(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(io::Error::other(e))),
                Poll::Ready(None) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                Poll::Ready(Some(Ok(_))) => {}
            }
        }
        let n = bytes.len().min(send.stream.capacity());
        send.stream.send_data(Bytes::copy_from_slice(&bytes[..n]), false).map_err(io::Error::other)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut send = self.send.lock().unwrap();
        if !send.closed {
            send.stream.send_data(Bytes::new(), true).map_err(io::Error::other)?;
            send.closed = true;
        }
        Poll::Ready(Ok(()))
    }
}
