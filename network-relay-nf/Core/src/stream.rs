//! Bounded HTTP byte streams. Half-closes remain independent; cancellation
//! resets an unfinished CONNECT stream rather than leaving detached pumps.
use bytes::{Buf, Bytes};
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

#[derive(Default)]
pub struct Keep {
    pub tasks: Vec<tokio::task::JoinHandle<()>>,
    // A flow owns only its pumps. Its shared connection survives until both
    // the client cache and every flow using it have been dropped.
    pub connection: Option<Arc<dyn Send + Sync>>,
}
#[derive(Default)]
pub struct ConnectionKeep {
    pub tasks: Vec<tokio::task::JoinHandle<()>>,
    pub lease: Option<Arc<crate::native::Lease>>,
    pub h3_driver: Option<Arc<H3Driver>>,
}
pub type H3Driver = Mutex<h3::client::Connection<crate::quic::Connection, Bytes>>;
impl Drop for Keep {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
impl Drop for ConnectionKeep {
    fn drop(&mut self) {
        if let Some(driver) = &self.h3_driver {
            send_h3_connection_error(driver);
        }
        for task in &self.tasks {
            task.abort();
        }
    }
}
/// h3 hands a connection error found on a request stream (a PUSH_PROMISE,
/// for example, is H3_ID_ERROR: RFC 9114 section 7.2.5) to the connection
/// driver, which closes the connection with that code when next polled. Poll
/// it once before the connection is given up, so the close carries the error
/// instead of code 0. Without a pending error this does nothing; it registers
/// no useful waker, so call it only when giving up.
pub fn send_h3_connection_error(driver: &H3Driver) {
    if let Ok(mut driver) = driver.lock() {
        let _ = driver.poll_close(&mut std::task::Context::from_waker(Waker::noop()));
    }
}

#[derive(Default)]
struct FailureState {
    message: Option<String>,
    reader: Option<Waker>,
    writer: Option<Waker>,
}
#[derive(Default)]
struct Failure(Mutex<FailureState>);
impl Failure {
    fn record(&self, message: String) {
        let (reader, writer) = {
            let mut state = self.0.lock().unwrap();
            if state.message.is_none() {
                state.message = Some(message);
            }
            (state.reader.take(), state.writer.take())
        };
        // Waking outside the lock allows either task to inspect the failure.
        for waker in [reader, writer].into_iter().flatten() {
            waker.wake();
        }
    }
    fn register(&self, cx: &Context<'_>, reading: bool) {
        let mut state = self.0.lock().unwrap();
        let slot = if reading {
            &mut state.reader
        } else {
            &mut state.writer
        };
        if slot.as_ref().is_none_or(|w| !w.will_wake(cx.waker())) {
            *slot = Some(cx.waker().clone());
        }
    }
    fn error(&self) -> Option<io::Error> {
        self.0
            .lock()
            .unwrap()
            .message
            .as_ref()
            .map(|s| io::Error::new(io::ErrorKind::ConnectionReset, s.clone()))
    }
}

pub struct Stream {
    io: Box<dyn Duplex>,
    error: Arc<Failure>,
    pub keep: Keep,
}
impl Stream {
    pub fn new(io: impl Duplex + 'static, keep: Keep) -> Self {
        Self {
            io: Box::new(io),
            error: Arc::default(),
            keep,
        }
    }
    fn pipes(
        keep: Keep,
    ) -> (
        Self,
        tokio::io::ReadHalf<DuplexStream>,
        tokio::io::WriteHalf<DuplexStream>,
    ) {
        let (local, remote) = tokio::io::duplex(64 << 10);
        let stream = Self::new(local, keep);
        let (read, write) = tokio::io::split(remote);
        (stream, read, write)
    }
    pub fn h2(send: h2::SendStream<Bytes>, mut recv: h2::RecvStream, keep: Keep) -> Self {
        let (mut stream, mut source, mut sink) = Self::pipes(keep);
        let error = stream.error.clone();
        stream.keep.tasks.push(tokio::spawn(async move {
            let result: anyhow::Result<()> = async {
                while let Some(bytes) = recv.data().await {
                    let bytes = bytes?;
                    let len = bytes.len();
                    sink.write_all(&bytes).await?;
                    recv.flow_control().release_capacity(len)?;
                }
                anyhow::ensure!(recv.trailers().await?.is_none(), "trailers on CONNECT");
                Ok(())
            }
            .await;
            if let Err(e) = result {
                error.record(e.to_string());
            }
            let _ = sink.shutdown().await;
        }));
        let error = stream.error.clone();
        stream.keep.tasks.push(tokio::spawn(async move {
            struct Reset(Option<h2::SendStream<Bytes>>);
            impl Drop for Reset {
                fn drop(&mut self) {
                    if let Some(s) = &mut self.0 {
                        s.send_reset(h2::Reason::CANCEL);
                    }
                }
            }
            let mut guard = Reset(Some(send));
            let result: anyhow::Result<()> = async {
                let send = guard.0.as_mut().unwrap();
                let mut buffer = [0; 16384];
                loop {
                    let n = source.read(&mut buffer).await?;
                    if n == 0 {
                        send.send_data(Bytes::new(), true)?;
                        break;
                    }
                    let mut bytes = Bytes::copy_from_slice(&buffer[..n]);
                    while !bytes.is_empty() {
                        send.reserve_capacity(bytes.len());
                        let cap = std::future::poll_fn(|cx| send.poll_capacity(cx))
                            .await
                            .ok_or_else(|| anyhow::anyhow!("HTTP/2 stream closed"))??;
                        if cap == 0 {
                            continue;
                        }
                        let count = cap.min(bytes.len());
                        send.send_data(bytes.split_to(count), false)?;
                    }
                }
                Ok(())
            }
            .await;
            match result {
                Ok(()) => {
                    guard.0.take();
                }
                Err(e) => {
                    error.record(e.to_string());
                }
            }
        }));
        stream
    }
    pub fn h3(
        mut request: h3::client::RequestStream<crate::quic::Stream, Bytes>,
        keep: Keep,
    ) -> Self {
        request.forbid_trailers();
        let (send, recv) = request.split();
        let (mut stream, mut source, mut sink) = Self::pipes(keep);
        let error = stream.error.clone();
        stream.keep.tasks.push(tokio::spawn(async move {
            struct Stop(Option<h3::client::RequestStream<crate::quic::Stream, Bytes>>);
            impl Drop for Stop {
                fn drop(&mut self) {
                    if let Some(s) = &mut self.0 {
                        s.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
                    }
                }
            }
            let mut guard = Stop(Some(recv));
            let result: anyhow::Result<()> = async {
                let recv = guard.0.as_mut().unwrap();
                while let Some(mut bytes) = recv.recv_data().await? {
                    while bytes.has_remaining() {
                        let count = bytes.remaining().min(16384);
                        sink.write_all(&bytes.copy_to_bytes(count)).await?;
                    }
                }
                Ok(())
            }
            .await;
            match result {
                Ok(()) => {
                    guard.0.take();
                }
                Err(e) => {
                    error.record(e.to_string());
                }
            }
            let _ = sink.shutdown().await;
        }));
        let error = stream.error.clone();
        stream.keep.tasks.push(tokio::spawn(async move {
            struct Reset(Option<h3::client::RequestStream<crate::quic::Stream, Bytes>>);
            impl Drop for Reset {
                fn drop(&mut self) {
                    if let Some(s) = &mut self.0 {
                        s.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                    }
                }
            }
            let mut guard = Reset(Some(send));
            let result: anyhow::Result<()> = async {
                let send = guard.0.as_mut().unwrap();
                let mut buffer = [0; 16384];
                loop {
                    let n = source.read(&mut buffer).await?;
                    if n == 0 {
                        send.finish().await?;
                        break;
                    }
                    send.send_data(Bytes::copy_from_slice(&buffer[..n])).await?;
                }
                Ok(())
            }
            .await;
            match result {
                Ok(()) => {
                    guard.0.take();
                }
                Err(e) => {
                    error.record(e.to_string());
                }
            }
        }));
        stream
    }
    fn failure(&self) -> Option<io::Error> {
        self.error.error()
    }
}
impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        self.error.register(cx, true);
        let before = buf.filled().len();
        let result = Pin::new(&mut self.io).poll_read(cx, buf);
        // Deliver already-buffered bytes first, including data received before
        // the opposite pump failed. A failure also completes an idle read.
        if buf.filled().len() == before
            && matches!(result, Poll::Pending | Poll::Ready(Ok(())))
            && let Some(e) = self.failure()
        {
            return Poll::Ready(Err(e));
        }
        result
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.error.register(cx, false);
        if let Some(e) = self.failure() {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.error.register(cx, false);
        if let Some(e) = self.failure() {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.error.register(cx, false);
        if let Some(e) = self.failure() {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn write_pump_failure_wakes_idle_reader_without_peer_fin() {
        let (mut stream, _source, _sink) = Stream::pipes(Keep::default());
        let failure = stream.error.clone();
        let waiting = tokio::spawn(async move { stream.read_u8().await });
        tokio::task::yield_now().await;
        failure.record("outbound pump failed".into());
        let error = timeout(Duration::from_secs(1), waiting)
            .await
            .expect("failed writer must wake idle reader")
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(error.to_string(), "outbound pump failed");
    }

    #[tokio::test]
    async fn read_pump_failure_wakes_backpressured_writer() {
        let (mut stream, _source, _sink) = Stream::pipes(Keep::default());
        stream.write_all(&vec![0; 64 << 10]).await.unwrap();
        let failure = stream.error.clone();
        let waiting = tokio::spawn(async move { stream.write_u8(1).await });
        tokio::task::yield_now().await;
        failure.record("inbound pump failed".into());
        let error = timeout(Duration::from_secs(1), waiting)
            .await
            .expect("failed reader must wake blocked writer")
            .unwrap()
            .unwrap_err();
        assert_eq!(error.to_string(), "inbound pump failed");
    }

    #[tokio::test]
    async fn buffered_bytes_precede_failure_and_first_error_is_retained() {
        let (mut stream, _source, mut sink) = Stream::pipes(Keep::default());
        sink.write_all(b"response").await.unwrap();
        stream.error.record("first failure".into());
        stream.error.record("cleanup failure".into());
        let mut bytes = [0; 8];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"response");
        assert_eq!(
            stream.read_u8().await.unwrap_err().to_string(),
            "first failure"
        );
        assert_eq!(
            stream.flush().await.unwrap_err().to_string(),
            "first failure"
        );
        assert_eq!(
            stream.shutdown().await.unwrap_err().to_string(),
            "first failure"
        );
        assert_eq!(stream.read(&mut []).await.unwrap(), 0);
    }
}
