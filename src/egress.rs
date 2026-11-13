//! Where tunnels lead when not to the relay's own network.
//!
//! By default the relay resolves names with the system resolver and opens
//! kernel sockets to destinations. A server built on this crate can instead
//! hand [`crate::server::Relay::with_egress`] an [`Egress`] that carries
//! every name lookup, TCP connection and UDP flow somewhere else (for
//! network-relay-cf-masque, through Cloudflare WARP). There is then no
//! fallback to the host network. Requests, authentication, destination
//! rules and limits stay the same either way.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub type IoFuture<'a, T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'a>>;

/// Admission and memory reservations retained until background I/O has ended.
pub type ResourceGuard = Arc<dyn Send + Sync>;
type ResourceRetainer = Arc<dyn Fn(ResourceGuard) + Send + Sync>;

/// What an egress TCP connection is underneath.
pub trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> IoStream for T {}

/// A TCP connection opened by an [`Egress`]. Its reads and writes must fail
/// once the egress is gone.
pub struct TcpStream {
    inner: Box<dyn IoStream>,
    local: SocketAddr,
    peer: SocketAddr,
    abort: Arc<dyn Fn() + Send + Sync>,
    retain: Option<ResourceRetainer>,
}

impl std::fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpStream").field("local", &self.local).field("peer", &self.peer).finish_non_exhaustive()
    }
}

impl TcpStream {
    /// `abort` resets the connection, as a kernel socket with a zero linger
    /// time does on close: the destination must learn that it failed
    /// (RFC 9113 section 8.5, RFC 9114 section 4.4). Dropping it closes it
    /// in order.
    pub fn new<S: IoStream + 'static>(
        inner: S,
        local: SocketAddr,
        peer: SocketAddr,
        abort: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self { inner: Box::new(inner), local, peer, abort, retain: None }
    }

    /// An egress with background cleanup must retain reservations until its
    /// socket and buffers are released, including after this stream is dropped.
    pub fn with_resource_retainer(mut self, retain: impl Fn(ResourceGuard) + Send + Sync + 'static) -> Self {
        self.retain = Some(Arc::new(retain));
        self
    }

    pub(crate) fn retain_resources(&self, guard: ResourceGuard) {
        if let Some(retain) = &self.retain {
            retain(guard);
        }
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    /// Resets the connection.
    pub fn abort(&self) {
        (self.abort)();
    }

    /// [`Self::abort`], for after the stream has been split.
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

/// A UDP flow opened by an [`Egress`]: like a connected UDP socket, it
/// sends to and receives from its peer only.
pub trait DatagramIo: Send + Sync {
    /// Retain reservations if the socket can outlive its foreground flow.
    /// Sockets closed synchronously on drop need no additional ownership.
    fn retain_resources(&self, _guard: ResourceGuard) {}

    /// Sends one datagram.
    fn send<'a>(&'a self, data: &'a [u8]) -> IoFuture<'a, usize>;
    /// Receives one whole datagram. Dropping the future loses none.
    fn recv<'a>(&'a self, data: &'a mut [u8]) -> IoFuture<'a, usize>;
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn peer_addr(&self) -> io::Result<SocketAddr>;
    /// The largest payload the flow can carry without IP fragmentation;
    /// larger datagrams are dropped, as UDP allows (RFC 9298 section 5).
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

/// Name lookups and connections for every tunnel, instead of the host's.
pub trait Egress: Send + Sync + 'static {
    /// Looks up the addresses of `host`, a name (never an IP literal).
    fn resolve<'a>(&'a self, host: &'a str) -> IoFuture<'a, Vec<IpAddr>>;
    /// Resolves within the caller's existing deadline, including time already
    /// spent waiting for admission. An egress can use this to cache completed
    /// timeout failures without treating caller cancellation as a DNS failure.
    /// The caller still enforces the deadline if the egress does not use it.
    fn resolve_until<'a>(&'a self, host: &'a str, _deadline: tokio::time::Instant) -> IoFuture<'a, Vec<IpAddr>> {
        self.resolve(host)
    }
    /// Opens a TCP connection to `peer`, an address the destination rules
    /// allow. The connection's peer address must be `peer`.
    fn connect_tcp(&self, peer: SocketAddr) -> IoFuture<'_, TcpStream>;
    /// Opens a UDP flow to `peer`, likewise.
    fn connect_udp(&self, peer: SocketAddr) -> IoFuture<'_, UdpSocket>;
    /// Whether the egress can carry traffic right now.
    fn available(&self) -> bool;
    /// Resolves once the egress is gone for good; pending while it works.
    /// Open tunnels then end as failed, even while paused by a traffic
    /// budget or idle, and the server stops.
    fn failed(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}
