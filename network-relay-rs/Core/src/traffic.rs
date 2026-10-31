//! Per-run SOCKS payload accepted for forwarding in each direction. Protocol
//! framing, readiness probes and bytes rejected before forwarding are excluded.
//! Native UDP sends and buffered stream writes retain their existing accepted
//! enqueue semantics; these are logical payload totals, not wire counters.
use std::{
    io,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
    time::Instant,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TrafficSnapshot {
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub elapsed_nanos: u64,
}

pub struct Traffic {
    upload: AtomicU64,
    download: AtomicU64,
    started: Instant,
}
impl Default for Traffic {
    fn default() -> Self {
        Self {
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
            started: Instant::now(),
        }
    }
}
impl Traffic {
    pub fn snapshot(&self) -> TrafficSnapshot {
        TrafficSnapshot {
            upload_bytes: self.upload.load(Ordering::Relaxed),
            download_bytes: self.download.load(Ordering::Relaxed),
            elapsed_nanos: self.started.elapsed().as_nanos().min(u64::MAX as u128) as u64,
        }
    }
    pub(crate) fn uploaded(&self, bytes: usize) {
        add(&self.upload, bytes);
    }
    pub(crate) fn downloaded(&self, bytes: usize) {
        add(&self.download, bytes);
    }
}
fn add(counter: &AtomicU64, bytes: usize) {
    if bytes != 0 {
        let mut total = counter.load(Ordering::Relaxed);
        loop {
            match counter.compare_exchange_weak(
                total,
                total.saturating_add(bytes as u64),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => total = current,
            }
        }
    }
}

/// Counts accepted writes rather than reads, so a failed forward does not
/// count bytes still buffered by the copying task. Reads and half-closes
/// retain the underlying stream's behavior.
struct CountedWriter<'a, S> {
    stream: S,
    counter: &'a AtomicU64,
}
impl<S: AsyncRead + Unpin> AsyncRead for CountedWriter<'_, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buffer)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for CountedWriter<'_, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let written = std::task::ready!(Pin::new(&mut self.stream).poll_write(cx, buffer))?;
        add(self.counter, written);
        Poll::Ready(Ok(written))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

pub(crate) async fn copy_bidirectional<L, R>(
    local: &mut L,
    relay: &mut R,
    traffic: &Traffic,
) -> io::Result<(u64, u64)>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    let mut local = CountedWriter {
        stream: local,
        counter: &traffic.download,
    };
    let mut relay = CountedWriter {
        stream: relay,
        counter: &traffic.upload,
    };
    tokio::io::copy_bidirectional(&mut local, &mut relay).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn payload_totals_are_live_exact_and_preserve_half_close() {
        let traffic = Arc::new(Traffic::default());
        let (mut local_peer, mut local) = tokio::io::duplex(1024);
        let (mut relay, mut relay_peer) = tokio::io::duplex(1024);
        let counters = traffic.clone();
        let copying =
            tokio::spawn(
                async move { copy_bidirectional(&mut local, &mut relay, &counters).await },
            );
        local_peer.write_all(b"initial upload").await.unwrap();
        let mut initial = [0; 14];
        relay_peer.read_exact(&mut initial).await.unwrap();
        assert_eq!(&initial, b"initial upload");
        assert_eq!(traffic.snapshot().upload_bytes, 14);
        assert_eq!(traffic.snapshot().download_bytes, 0);
        assert!(
            !copying.is_finished(),
            "traffic must be available before a flow ends"
        );

        let upload = vec![0x35; 40_003];
        let download = vec![0x71; 30_007];
        let expected_upload = upload.clone();
        let expected_download = download.clone();
        let remote = tokio::spawn(async move {
            let mut received = Vec::new();
            relay_peer.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, expected_upload);
            // A request FIN must still permit the response in the other direction.
            relay_peer.write_all(&download).await.unwrap();
            relay_peer.shutdown().await.unwrap();
        });
        local_peer.write_all(&upload).await.unwrap();
        local_peer.shutdown().await.unwrap();
        let mut received = Vec::new();
        local_peer.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, expected_download);
        remote.await.unwrap();
        assert_eq!(copying.await.unwrap().unwrap(), (40_017, 30_007));
        let snapshot = traffic.snapshot();
        assert_eq!(
            (snapshot.upload_bytes, snapshot.download_bytes),
            (40_017, 30_007)
        );
        assert!(snapshot.elapsed_nanos > 0);
        let fresh = Traffic::default().snapshot();
        assert_eq!((fresh.upload_bytes, fresh.download_bytes), (0, 0));
    }

    struct PartialFailure {
        pending: bool,
        written: usize,
    }
    impl AsyncWrite for PartialFailure {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if !self.pending {
                self.pending = true;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if self.written != 0 {
                return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
            }
            self.written = bytes.len().min(3);
            Poll::Ready(Ok(self.written))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    #[tokio::test]
    async fn pending_partial_and_failed_writes_count_only_accepted_bytes() {
        let traffic = Traffic::default();
        let mut output = CountedWriter {
            stream: PartialFailure {
                pending: false,
                written: 0,
            },
            counter: &traffic.upload,
        };
        let error = output.write_all(b"six123").await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        output.flush().await.unwrap();
        output.shutdown().await.unwrap();
        let snapshot = traffic.snapshot();
        assert_eq!((snapshot.upload_bytes, snapshot.download_bytes), (3, 0));
    }

    #[test]
    fn counters_aggregate_payloads_and_saturate_instead_of_wrapping() {
        let traffic = Traffic::default();
        traffic.uploaded(17);
        traffic.uploaded(0);
        traffic.uploaded(23);
        traffic.downloaded(11);
        assert_eq!(
            (
                traffic.snapshot().upload_bytes,
                traffic.snapshot().download_bytes
            ),
            (40, 11)
        );
        traffic.upload.store(u64::MAX - 1, Ordering::Relaxed);
        traffic.uploaded(3);
        assert_eq!(traffic.snapshot().upload_bytes, u64::MAX);
    }
}
