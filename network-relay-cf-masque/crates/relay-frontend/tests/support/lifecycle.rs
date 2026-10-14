//! A controllable terminal egress generation for integration tests.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;
use warp_masque_egress::egress::{DatagramIo, Egress, IoFuture, TcpStream, UdpSocket};

use super::support::LoopbackTestEgress;

#[derive(Clone, Copy, Debug, Default)]
pub struct Counters {
    pub tcp_read_bytes: usize,
    pub tcp_write_bytes: usize,
    pub tcp_aborts: usize,
    pub udp_drops: usize,
}

struct State {
    available: AtomicBool,
    failed: Notify,
    progress: Notify,
    tcp_read_bytes: AtomicUsize,
    tcp_write_bytes: AtomicUsize,
    tcp_aborts: AtomicUsize,
    udp_drops: AtomicUsize,
}

impl State {
    fn check(&self) -> io::Result<()> {
        if self.available.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(failure())
        }
    }

    async fn wait_failed(&self) -> io::Result<()> {
        loop {
            let notified = self.failed.notified();
            tokio::pin!(notified);
            // Registration precedes the terminal-state check so failure
            // between checking the flag and awaiting cannot be missed.
            notified.as_mut().enable();
            self.check()?;
            notified.await;
        }
    }

    async fn wait_counter(&self, counter: &AtomicUsize, minimum: usize, stop_on_failure: bool) -> io::Result<()> {
        loop {
            let notified = self.progress.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if counter.load(Ordering::Acquire) >= minimum {
                return Ok(());
            }
            if stop_on_failure {
                self.check()?;
            }
            notified.await;
        }
    }
}

fn failure() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "controlled egress generation failed")
}

fn owned_failure(state: Arc<State>) -> IoFuture<'static, ()> {
    Box::pin(async move { state.wait_failed().await })
}

pub struct ControlledEgress {
    inner: LoopbackTestEgress,
    state: Arc<State>,
}

impl Default for ControlledEgress {
    fn default() -> Self {
        Self {
            inner: LoopbackTestEgress,
            state: Arc::new(State {
                available: AtomicBool::new(true),
                failed: Notify::new(),
                progress: Notify::new(),
                tcp_read_bytes: AtomicUsize::new(0),
                tcp_write_bytes: AtomicUsize::new(0),
                tcp_aborts: AtomicUsize::new(0),
                udp_drops: AtomicUsize::new(0),
            }),
        }
    }
}

impl ControlledEgress {
    pub fn fail(&self) {
        if self.state.available.swap(false, Ordering::AcqRel) {
            self.state.failed.notify_waiters();
            self.state.progress.notify_waiters();
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            tcp_read_bytes: self.state.tcp_read_bytes.load(Ordering::Acquire),
            tcp_write_bytes: self.state.tcp_write_bytes.load(Ordering::Acquire),
            tcp_aborts: self.state.tcp_aborts.load(Ordering::Acquire),
            udp_drops: self.state.udp_drops.load(Ordering::Acquire),
        }
    }

    pub async fn wait_for_tcp_read_bytes(&self, minimum: usize) -> io::Result<()> {
        self.state.wait_counter(&self.state.tcp_read_bytes, minimum, true).await
    }

    pub async fn wait_for_udp_drops(&self, minimum: usize) -> io::Result<()> {
        self.state.wait_counter(&self.state.udp_drops, minimum, false).await
    }
}

impl Egress for ControlledEgress {
    fn resolve<'a>(&'a self, host: &'a str) -> IoFuture<'a, Vec<IpAddr>> {
        Box::pin(async move {
            tokio::select! {
                biased;
                result = self.failed() => { result?; Err(failure()) },
                result = self.inner.resolve(host) => { self.state.check()?; result },
            }
        })
    }

    fn connect_tcp(&self, peer: SocketAddr) -> IoFuture<'_, TcpStream> {
        Box::pin(async move {
            let stream = tokio::select! {
                biased;
                result = self.failed() => { result?; return Err(failure()); },
                result = self.inner.connect_tcp(peer) => result?,
            };
            if let Err(error) = self.state.check() {
                stream.abort();
                return Err(error);
            }
            let local = stream.local_addr()?;
            let peer = stream.peer_addr()?;
            let native_abort = stream.abort_handle();
            let state = self.state.clone();
            let abort = Arc::new(move || {
                state.tcp_aborts.fetch_add(1, Ordering::AcqRel);
                state.progress.notify_waiters();
                native_abort();
            });
            let wrapper = ControlledTcp {
                inner: stream,
                state: self.state.clone(),
                read_failed: owned_failure(self.state.clone()),
                write_failed: owned_failure(self.state.clone()),
            };
            Ok(TcpStream::new(wrapper, local, peer, abort))
        })
    }

    fn connect_udp(&self, peer: SocketAddr) -> IoFuture<'_, UdpSocket> {
        Box::pin(async move {
            let socket = tokio::select! {
                biased;
                result = self.failed() => { result?; return Err(failure()); },
                result = self.inner.connect_udp(peer) => result?,
            };
            self.state.check()?;
            Ok(UdpSocket(Arc::new(ControlledUdp { inner: socket, state: self.state.clone() })))
        })
    }

    fn available(&self) -> bool {
        self.state.available.load(Ordering::Acquire)
    }

    fn failed(&self) -> IoFuture<'_, ()> {
        Box::pin(self.state.wait_failed())
    }
}

struct ControlledTcp {
    inner: TcpStream,
    state: Arc<State>,
    // Separate subscriptions preserve both half-stream tasks' wakers.
    read_failed: IoFuture<'static, ()>,
    write_failed: IoFuture<'static, ()>,
}

impl ControlledTcp {
    fn check_failure(&mut self, cx: &mut Context<'_>, reading: bool) -> io::Result<()> {
        self.state.check()?;
        let failed = if reading { &mut self.read_failed } else { &mut self.write_failed };
        match std::future::Future::poll(failed.as_mut(), cx) {
            Poll::Ready(Err(error)) => Err(error),
            Poll::Ready(Ok(())) => Err(failure()),
            Poll::Pending => Ok(()),
        }
    }
}

impl AsyncRead for ControlledTcp {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.check_failure(cx, true) {
            return Poll::Ready(Err(error));
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Err(error) = this.state.check() {
            return Poll::Ready(Err(error));
        }
        if let Poll::Ready(Ok(())) = &result {
            let bytes = buf.filled().len() - before;
            if bytes != 0 {
                this.state.tcp_read_bytes.fetch_add(bytes, Ordering::AcqRel);
                this.state.progress.notify_waiters();
            }
        }
        result
    }
}

impl AsyncWrite for ControlledTcp {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Err(error) = this.check_failure(cx, false) {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Err(error) = this.state.check() {
            return Poll::Ready(Err(error));
        }
        if let Poll::Ready(Ok(bytes)) = &result {
            if *bytes != 0 {
                this.state.tcp_write_bytes.fetch_add(*bytes, Ordering::AcqRel);
                this.state.progress.notify_waiters();
            }
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.check_failure(cx, false) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.check_failure(cx, false) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

struct ControlledUdp {
    inner: UdpSocket,
    state: Arc<State>,
}

impl Drop for ControlledUdp {
    fn drop(&mut self) {
        self.state.udp_drops.fetch_add(1, Ordering::AcqRel);
        self.state.progress.notify_waiters();
    }
}

impl DatagramIo for ControlledUdp {
    fn send<'a>(&'a self, data: &'a [u8]) -> IoFuture<'a, usize> {
        Box::pin(async move {
            tokio::select! {
                biased;
                result = self.state.wait_failed() => { result?; Err(failure()) },
                result = self.inner.send(data) => { self.state.check()?; result },
            }
        })
    }

    fn recv<'a>(&'a self, data: &'a mut [u8]) -> IoFuture<'a, usize> {
        Box::pin(async move {
            tokio::select! {
                biased;
                result = self.state.wait_failed() => { result?; Err(failure()) },
                result = self.inner.recv(data) => { self.state.check()?; result },
            }
        })
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    fn max_payload(&self) -> usize {
        self.inner.max_payload()
    }
}
