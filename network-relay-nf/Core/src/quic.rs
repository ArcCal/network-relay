//! h3 transport traits over native streams, never QUIC packet construction.
use crate::native::{Bridge, Io, OPEN_STREAM, OpenFuture, Quic};
use bytes::{Buf, Bytes};
use h3::quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
fn stream_error(e: io::Error) -> StreamErrorIncoming {
    StreamErrorIncoming::Unknown(Box::new(e))
}
fn connection_error(e: io::Error) -> ConnectionErrorIncoming {
    ConnectionErrorIncoming::Undefined(Arc::new(e))
}
/// Created only when native bidirectional stream creation failed before it
/// returned a stream to h3. No request HEADERS can have been written yet.
#[derive(Debug, thiserror::Error)]
#[error("request stream was not created: {0}")]
pub(crate) struct RequestNotSubmitted(#[source] pub io::Error);
pub struct Stream {
    pub io: Io,
    pending: Bytes,
}
impl Stream {
    fn new(io: Io) -> Self {
        Self {
            io,
            pending: Bytes::new(),
        }
    }
    fn sid(&self) -> StreamId {
        self.io
            .ready
            .stream_id
            .try_into()
            .expect("native stream ID validated")
    }
}
impl quic::RecvStream for Stream {
    type Buf = Bytes;
    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        let mut bytes = [0; 32768];
        let mut rb = ReadBuf::new(&mut bytes);
        std::task::ready!(Pin::new(&mut self.io).poll_read(cx, &mut rb)).map_err(stream_error)?;
        Poll::Ready(Ok(
            (!rb.filled().is_empty()).then(|| Bytes::copy_from_slice(rb.filled()))
        ))
    }
    fn stop_sending(&mut self, code: u64) {
        if let Some(b) = self.io.lease.bridge() {
            b.control(crate::native::CLOSE, self.io.id(), code)
        }
    }
    fn recv_id(&self) -> StreamId {
        self.sid()
    }
}
impl quic::SendStream<Bytes> for Stream {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        while !self.pending.is_empty() {
            let n = std::task::ready!(Pin::new(&mut self.io).poll_write(cx, &self.pending))
                .map_err(stream_error)?;
            self.pending.advance(n)
        }
        Pin::new(&mut self.io)
            .poll_flush(cx)
            .map(|r| r.map_err(stream_error))
    }
    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        if !self.pending.is_empty() {
            return Err(stream_error(io::Error::new(
                io::ErrorKind::WouldBlock,
                "unflushed stream data",
            )));
        }
        let mut buf = data.into();
        self.pending = buf.copy_to_bytes(buf.remaining());
        Ok(())
    }
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        std::task::ready!(<Self as quic::SendStream<Bytes>>::poll_ready(self, cx))?;
        Pin::new(&mut self.io)
            .poll_shutdown(cx)
            .map(|r| r.map_err(stream_error))
    }
    fn reset(&mut self, code: u64) {
        if let Some(b) = self.io.lease.bridge() {
            b.control(crate::native::CLOSE, self.io.id(), code)
        }
    }
    fn send_id(&self) -> StreamId {
        self.sid()
    }
}
impl quic::SendStreamUnframed<Bytes> for Stream {
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        let n = std::task::ready!(Pin::new(&mut self.io).poll_write(cx, buf.chunk()))
            .map_err(stream_error)?;
        buf.advance(n);
        Poll::Ready(Ok(n))
    }
}
impl quic::BidiStream<Bytes> for Stream {
    type SendStream = Stream;
    type RecvStream = Stream;
    fn split(self) -> (Stream, Stream) {
        let read = Stream::new(self.io.read_half());
        (self, read)
    }
}
pub struct Connection {
    pub native: Quic,
    open: Opener,
}
impl Connection {
    pub fn new(native: Quic) -> Self {
        let open = Opener {
            bridge: native.bridge.clone(),
            parent: native.io.id(),
            bidi: None,
            uni: None,
        };
        Self { native, open }
    }
}
pub struct Opener {
    bridge: Arc<Bridge>,
    parent: u64,
    bidi: Option<OpenFuture>,
    uni: Option<OpenFuture>,
}
impl Opener {
    fn poll_open(
        &mut self,
        cx: &mut Context<'_>,
        uni: bool,
    ) -> Poll<Result<Stream, StreamErrorIncoming>> {
        let slot = if uni { &mut self.uni } else { &mut self.bidi };
        if slot.is_none() {
            let bridge = self.bridge.clone();
            let parent = self.parent;
            *slot = Some(Box::pin(async move {
                Ok(bridge
                    .open(OPEN_STREAM, parent, u64::from(uni), Vec::new())
                    .await?
                    .0)
            }))
        }
        let result = std::task::ready!(slot.as_mut().unwrap().as_mut().poll(cx));
        *slot = None;
        Poll::Ready(result.map(Stream::new).map_err(|error| {
            if !uni
                && matches!(
                    error.kind(),
                    io::ErrorKind::NotConnected | io::ErrorKind::ConnectionAborted
                )
            {
                StreamErrorIncoming::Unknown(Box::new(RequestNotSubmitted(error)))
            } else {
                stream_error(error)
            }
        }))
    }
}
impl quic::OpenStreams<Bytes> for Opener {
    type BidiStream = Stream;
    type SendStream = Stream;
    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Stream, StreamErrorIncoming>> {
        self.poll_open(cx, false)
    }
    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Stream, StreamErrorIncoming>> {
        self.poll_open(cx, true)
    }
    fn close(&mut self, code: h3::error::Code, _: &[u8]) {
        self.bridge
            .control(crate::native::CLOSE, self.parent, code.value());
    }
}
impl quic::OpenStreams<Bytes> for Connection {
    type BidiStream = Stream;
    type SendStream = Stream;
    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Stream, StreamErrorIncoming>> {
        self.open.poll_open(cx, false)
    }
    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Stream, StreamErrorIncoming>> {
        self.open.poll_open(cx, true)
    }
    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        self.open.close(code, reason)
    }
}
impl quic::Connection<Bytes> for Connection {
    type RecvStream = Stream;
    type OpenStreams = Opener;
    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Stream, ConnectionErrorIncoming>> {
        let (id, sid, ready) = std::task::ready!(self.native.accepted.poll_recv(cx))
            .ok_or(ConnectionErrorIncoming::ConnectionClosed { error_code: 0 })?;
        if sid & 2 == 0 {
            return Poll::Ready(Err(ConnectionErrorIncoming::InternalError(
                "server opened unexpected bidirectional stream".into(),
            )));
        }
        Poll::Ready(
            self.native
                .bridge
                .accepted_io(id, ready)
                .map(Stream::new)
                .map_err(connection_error),
        )
    }
    fn poll_accept_bidi(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<Result<Stream, ConnectionErrorIncoming>> {
        Poll::Pending
    }
    fn opener(&self) -> Opener {
        Opener {
            bridge: self.open.bridge.clone(),
            parent: self.open.parent,
            bidi: None,
            uni: None,
        }
    }
}
