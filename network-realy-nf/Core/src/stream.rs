//! Bounded HTTP byte streams. Half-closes remain independent; cancellation
//! resets an unfinished CONNECT stream rather than leaving detached pumps.
use bytes::{Buf, Bytes};
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

#[derive(Default)]
pub struct Keep {
    pub tasks: Vec<tokio::task::JoinHandle<()>>,
    pub sender: Option<Box<dyn Send>>,
    pub lease: Option<Arc<crate::native::Lease>>,
}
impl Drop for Keep {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

pub struct Stream {
    io: Box<dyn Duplex>,
    error: Arc<Mutex<Option<String>>>,
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
                *error.lock().unwrap() = Some(e.to_string());
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
                    *error.lock().unwrap() = Some(e.to_string());
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
                    *error.lock().unwrap() = Some(e.to_string());
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
                    *error.lock().unwrap() = Some(e.to_string());
                }
            }
        }));
        stream
    }
    fn failure(&self) -> Option<io::Error> {
        self.error
            .lock()
            .unwrap()
            .as_ref()
            .map(|s| io::Error::new(io::ErrorKind::ConnectionReset, s.clone()))
    }
}
impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.io).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(())))
            && buf.filled().len() == before
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
        if let Some(e) = self.failure() {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
