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
    pub driver: Option<tokio::task::JoinHandle<()>>,
    pub sender: Option<Box<dyn Send>>,
    pub lease: Option<Arc<crate::native::Lease>>,
}
impl Drop for Keep {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        // Stream guards queue resets on cancellation, while successful upload
        // shutdown queues a final DATA frame. Let the existing connection driver
        // drain naturally after its public senders disappear: a cleanup deadline
        // could discard accepted bytes during temporary transport backpressure.
        // Application stop cancels the backend I/O and wakes blocked drivers.
        drop(self.sender.take());
        drop(self.lease.take());
        // Dropping a JoinHandle detaches its already-running task, including
        // when this value is dropped outside that task's Tokio context.
        drop(self.driver.take());
    }
}

#[derive(Default)]
struct FailureState {
    message: Option<String>,
    reader: Option<Waker>,
    writer: Option<Waker>,
    write_done: bool,
    malformed: bool,
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
    fn finish_write(&self) {
        let writer = {
            let mut state = self.0.lock().unwrap();
            state.write_done = true;
            state.writer.take()
        };
        if let Some(writer) = writer {
            writer.wake();
        }
    }
    fn write_result(&self) -> Option<io::Result<()>> {
        let state = self.0.lock().unwrap();
        if let Some(message) = &state.message {
            Some(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                message.clone(),
            )))
        } else if state.write_done {
            Some(Ok(()))
        } else {
            None
        }
    }
    fn mark_malformed(&self) {
        self.0.lock().unwrap().malformed = true;
    }
    fn malformed(&self) -> bool {
        self.0.lock().unwrap().malformed
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
    wait_for_write_pump: bool,
    malformed_abort: Option<Arc<dyn Fn() + Send + Sync>>,
}
impl Stream {
    pub fn new(io: impl Duplex + 'static, keep: Keep) -> Self {
        Self {
            io: Box::new(io),
            error: Arc::default(),
            keep,
            wait_for_write_pump: false,
            malformed_abort: None,
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
        let mut stream = Self::new(local, keep);
        stream.wait_for_write_pump = true;
        let (read, write) = tokio::io::split(remote);
        (stream, read, write)
    }
    pub fn h2(send: h2::SendStream<Bytes>, mut recv: h2::RecvStream, keep: Keep) -> Self {
        let (mut stream, mut source, mut sink) = Self::pipes(keep);
        let send = Arc::new(Mutex::new(send));
        let malformed_send = send.clone();
        stream.malformed_abort = Some(Arc::new(move || {
            malformed_send
                .lock()
                .unwrap()
                .send_reset(h2::Reason::PROTOCOL_ERROR);
        }));
        let receive_error_send = send.clone();
        let error = stream.error.clone();
        stream.keep.tasks.push(tokio::spawn(async move {
            let result: anyhow::Result<()> = async {
                while let Some(bytes) = recv.data().await {
                    let bytes = bytes?;
                    let len = bytes.len();
                    sink.write_all(&bytes).await?;
                    recv.flow_control().release_capacity(len)?;
                }
                if recv.trailers().await?.is_some() {
                    error.mark_malformed();
                    receive_error_send
                        .lock()
                        .unwrap()
                        .send_reset(h2::Reason::PROTOCOL_ERROR);
                    anyhow::bail!("trailers on CONNECT");
                }
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
            struct Reset(Option<Arc<Mutex<h2::SendStream<Bytes>>>>, Arc<Failure>);
            impl Drop for Reset {
                fn drop(&mut self) {
                    if let Some(s) = &mut self.0 {
                        s.lock().unwrap().send_reset(if self.1.malformed() {
                            h2::Reason::PROTOCOL_ERROR
                        } else {
                            h2::Reason::CANCEL
                        });
                    }
                }
            }
            let mut guard = Reset(Some(send), error.clone());
            let result: anyhow::Result<()> = async {
                let send = guard.0.as_ref().unwrap();
                let mut buffer = [0; 16384];
                loop {
                    let n = source.read(&mut buffer).await?;
                    if n == 0 {
                        send.lock().unwrap().send_data(Bytes::new(), true)?;
                        break;
                    }
                    let mut bytes = Bytes::copy_from_slice(&buffer[..n]);
                    while !bytes.is_empty() {
                        send.lock().unwrap().reserve_capacity(bytes.len());
                        let cap = std::future::poll_fn(|cx| send.lock().unwrap().poll_capacity(cx))
                            .await
                            .ok_or_else(|| anyhow::anyhow!("HTTP/2 stream closed"))??;
                        if cap == 0 {
                            continue;
                        }
                        let count = cap.min(bytes.len());
                        send.lock()
                            .unwrap()
                            .send_data(bytes.split_to(count), false)?;
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
            error.finish_write();
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
            struct Stop(
                Option<h3::client::RequestStream<crate::quic::Stream, Bytes>>,
                Arc<Failure>,
            );
            impl Drop for Stop {
                fn drop(&mut self) {
                    if let Some(s) = &mut self.0 {
                        s.stop_sending(if self.1.malformed() {
                            h3::error::Code::H3_MESSAGE_ERROR
                        } else {
                            h3::error::Code::H3_REQUEST_CANCELLED
                        });
                    }
                }
            }
            let mut guard = Stop(Some(recv), error.clone());
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
            struct Reset(
                Option<h3::client::RequestStream<crate::quic::Stream, Bytes>>,
                Arc<Failure>,
            );
            impl Drop for Reset {
                fn drop(&mut self) {
                    if let Some(s) = &mut self.0 {
                        s.stop_stream(if self.1.malformed() {
                            h3::error::Code::H3_MESSAGE_ERROR
                        } else {
                            h3::error::Code::H3_REQUEST_CANCELLED
                        });
                    }
                }
            }
            let mut guard = Reset(Some(send), error.clone());
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
            error.finish_write();
        }));
        stream
    }
    /// RFC 9297 section 3.3 maps Capsule decoding errors to HTTP message
    /// errors. HTTP/3 may promote a stream error to a connection error
    /// (RFC 9114 section 8); each RS connection carries one proxied flow, so
    /// this cannot cancel another user's request and preserves the wire code.
    pub fn abort_malformed(&mut self) {
        self.error.mark_malformed();
        self.error
            .record("malformed Capsule Protocol message".into());
        if let Some(abort) = &self.malformed_abort {
            abort();
        }
        if let Some(lease) = &self.keep.lease
            && let Some(bridge) = lease.bridge()
        {
            bridge.control(
                crate::native::CLOSE,
                lease.id,
                h3::error::Code::H3_MESSAGE_ERROR.value(),
            );
        }
        for task in &self.keep.tasks {
            task.abort();
        }
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
        std::task::ready!(Pin::new(&mut self.io).poll_shutdown(cx))?;
        if self.wait_for_write_pump {
            return self.error.write_result().map_or(Poll::Pending, Poll::Ready);
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn shutdown_waits_for_the_upload_pump_to_drain_buffered_bytes() {
        let (mut stream, mut source, _sink) = Stream::pipes(Keep::default());
        stream.write_all(b"queued upload").await.unwrap();
        let failure = stream.error.clone();
        let waiting = tokio::spawn(async move { stream.shutdown().await });
        tokio::task::yield_now().await;
        assert!(
            !waiting.is_finished(),
            "buffered upload must not be reported as drained"
        );
        let mut uploaded = Vec::new();
        source.read_to_end(&mut uploaded).await.unwrap();
        assert_eq!(uploaded, b"queued upload");
        failure.finish_write();
        timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn pump_error_during_shutdown_cannot_be_reported_as_success() {
        struct FailsDuringShutdown(Arc<Failure>);
        impl AsyncRead for FailsDuringShutdown {
            fn poll_read(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }
        impl AsyncWrite for FailsDuringShutdown {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(bytes.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.0
                    .record("upload pump failed while local shutdown completed".into());
                self.0.finish_write();
                Poll::Ready(Ok(()))
            }
        }
        let failure = Arc::new(Failure::default());
        let mut stream = Stream::new(FailsDuringShutdown(failure.clone()), Keep::default());
        stream.error = failure;
        stream.wait_for_write_pump = true;
        let error = stream.shutdown().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    }

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
