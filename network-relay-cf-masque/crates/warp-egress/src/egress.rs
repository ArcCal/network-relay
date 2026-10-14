//! Application-independent TCP, connected UDP and resolver interfaces.
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub type IoFuture<'a, T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'a>>;

pub trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> IoStream for T {}

/// A stream with explicit abort and immutable endpoint metadata.
/// Implementations must fail pending reads/writes after their egress dies.
pub struct TcpStream {
    inner: Box<dyn IoStream>,
    local: SocketAddr,
    peer: SocketAddr,
    abort: Arc<dyn Fn() + Send + Sync>,
}

impl std::fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpStream").field("local", &self.local).field("peer", &self.peer).finish_non_exhaustive()
    }
}
impl TcpStream {
    pub fn new<S: IoStream + 'static>(
        inner: S,
        local: SocketAddr,
        peer: SocketAddr,
        abort: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self { inner: Box::new(inner), local, peer, abort }
    }
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer)
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
    pub fn abort(&self) {
        (self.abort)();
    }
    pub fn abort_handle(&self) -> Arc<dyn Fn() + Send + Sync> {
        self.abort.clone()
    }
}
impl AsyncRead for TcpStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for TcpStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

/// A connected UDP flow must only yield packets from its selected peer.
pub trait DatagramIo: Send + Sync {
    fn send<'a>(&'a self, data: &'a [u8]) -> IoFuture<'a, usize>;
    fn recv<'a>(&'a self, data: &'a mut [u8]) -> IoFuture<'a, usize>;
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn peer_addr(&self) -> io::Result<SocketAddr>;
    fn max_payload(&self) -> usize;
}

#[derive(Clone)]
pub struct UdpSocket(pub Arc<dyn DatagramIo>);
impl std::fmt::Debug for UdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpSocket").field("peer", &self.peer_addr()).finish_non_exhaustive()
    }
}
impl UdpSocket {
    pub async fn send(&self, data: &[u8]) -> io::Result<usize> {
        self.0.send(data).await
    }
    pub async fn recv(&self, data: &mut [u8]) -> io::Result<usize> {
        self.0.recv(data).await
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.0.peer_addr()
    }
    pub fn max_payload(&self) -> usize {
        self.0.max_payload()
    }
}

/// There is intentionally no default or host-network implementation.
pub trait Egress: Send + Sync {
    fn resolve<'a>(&'a self, host: &'a str) -> IoFuture<'a, Vec<IpAddr>>;
    fn connect_tcp(&self, peer: SocketAddr) -> IoFuture<'_, TcpStream>;
    fn connect_udp(&self, peer: SocketAddr) -> IoFuture<'_, UdpSocket>;
    fn available(&self) -> bool;
    /// Completes when the generation is permanently unavailable. Healthy
    /// providers keep it pending; callers must also select it while rate
    /// limits or idle flows prevent further socket operations.
    fn failed(&self) -> IoFuture<'_, ()>;
}
