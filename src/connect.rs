//! Opening connections to destinations.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::task::JoinSet;

use crate::egress::{self, Egress};
use crate::policy::Refusal;
use crate::sys;

/// Delay before trying the next address while an attempt is pending
/// (RFC 8305 §5 recommends 250 ms).
const ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// Receive buffer for relayed UDP flows, which often carry QUIC.
const UDP_BUFFER: usize = 1 << 20;

/// Orders addresses for connection attempts (RFC 8305 §4): the resolver's
/// first choice first, then alternating between address families.
fn interleave(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let Some(first) = addrs.first() else { return Vec::new() };
    let (mut same, mut other): (Vec<SocketAddr>, Vec<SocketAddr>) =
        addrs.iter().partition(|a| a.is_ipv6() == first.is_ipv6());
    same.reverse();
    other.reverse();
    let mut out = Vec::with_capacity(addrs.len());
    while !same.is_empty() || !other.is_empty() {
        out.extend(same.pop());
        out.extend(other.pop());
    }
    out
}

fn refusal(e: &io::Error) -> Refusal {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => Refusal::ConnectionRefused,
        io::ErrorKind::TimedOut => Refusal::ConnectionTimeout,
        // No socket for it, here or in an egress: a limit, not the route.
        io::ErrorKind::OutOfMemory => Refusal::TooManyTunnels,
        _ => Refusal::Unreachable(e.to_string()),
    }
}

/// Fix buffer sizes before the handshake, including data arriving before
/// the connection future returns.
async fn bounded_tcp_connect(addr: SocketAddr) -> io::Result<TcpStream> {
    let socket = if addr.is_ipv6() { TcpSocket::new_v6()? } else { TcpSocket::new_v4()? };
    sys::limit_tcp_buffers(socket2::SockRef::from(&socket), sys::TARGET_TCP_BUFFER)?;
    socket.connect(addr).await
}

/// Connects to the first address that answers, racing them as Happy
/// Eyeballs does (RFC 8305), within `timeout` overall.
pub async fn tcp(addrs: &[SocketAddr], timeout: Duration) -> Result<TcpStream, Refusal> {
    let stream = race(addrs, timeout, bounded_tcp_connect).await?;
    if let Err(e) = sys::tune_target_tcp(socket2::SockRef::from(&stream)) {
        tracing::debug!("could not set TCP options: {e}");
    }
    Ok(stream)
}

/// Runs `attempt` for the addresses as Happy Eyeballs does (RFC 8305) and
/// returns the first connection made, within `timeout` overall.
async fn race<T, F, A>(addrs: &[SocketAddr], timeout: Duration, attempt: A) -> Result<T, Refusal>
where
    T: Send + 'static,
    F: Future<Output = io::Result<T>> + Send + 'static,
    A: Fn(SocketAddr) -> F,
{
    let mut pending = interleave(addrs).into_iter().peekable();
    let deadline = tokio::time::Instant::now() + timeout;
    let mut attempts = JoinSet::new();
    let mut last_error = None;
    loop {
        if attempts.is_empty() {
            match pending.next() {
                Some(addr) => {
                    attempts.spawn(attempt(addr));
                }
                None => return Err(last_error.map_or(Refusal::NoAddresses, |e| refusal(&e))),
            }
        }
        let more = pending.peek().is_some();
        tokio::select! {
            joined = attempts.join_next() => match joined {
                Some(Ok(Ok(stream))) => return Ok(stream),
                Some(Ok(Err(e))) => {
                    last_error = Some(e);
                    // A failed attempt starts the next one at once (§5).
                    if let Some(addr) = pending.next() {
                        attempts.spawn(attempt(addr));
                    }
                }
                Some(Err(e)) => last_error = Some(io::Error::other(e)),
                None => {}
            },
            _ = tokio::time::sleep(ATTEMPT_DELAY), if more => {
                if let Some(addr) = pending.next() {
                    attempts.spawn(attempt(addr));
                }
            }
            _ = tokio::time::sleep_until(deadline) => return Err(Refusal::ConnectionTimeout),
        }
    }
}

/// A UDP socket connected to the first address the host has a route to,
/// so it only receives datagrams from that address.
pub async fn udp(addrs: &[SocketAddr]) -> Result<UdpSocket, Refusal> {
    let mut last_error = None;
    for addr in addrs {
        let local: IpAddr = if addr.is_ipv6() { Ipv6Addr::UNSPECIFIED.into() } else { Ipv4Addr::UNSPECIFIED.into() };
        let sock = match UdpSocket::bind(SocketAddr::new(local, 0)).await {
            Ok(s) => s,
            Err(e) => {
                last_error = Some(e);
                continue;
            }
        };
        // Connecting a UDP socket only picks a route; it fails at once when
        // there is none, for example for IPv6 on a host without it.
        match sock.connect(addr).await {
            Ok(()) => {
                if let Err(e) = sys::no_udp_fragmentation(socket2::SockRef::from(&sock), addr.is_ipv6()) {
                    last_error = Some(e);
                    continue;
                }
                sys::grow_buffers(socket2::SockRef::from(&sock), UDP_BUFFER);
                return Ok(sock);
            }
            Err(e) => last_error = Some(e),
        }
    }
    Err(last_error.map_or(Refusal::NoAddresses, |e| refusal(&e)))
}

/// A tunnel's TCP connection to its destination.
#[derive(Debug)]
pub enum Tcp {
    Host(TcpStream),
    Egress(egress::TcpStream),
}

impl Tcp {
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Host(tcp) => tcp.peer_addr(),
            Self::Egress(tcp) => tcp.peer_addr(),
        }
    }

    /// Makes the connection end with a reset instead of an orderly close,
    /// so the destination learns it failed (RFC 9114 section 4.4, RFC 9113 section 8.5):
    /// a kernel socket resets when closed, an egress connection at once.
    pub fn abort(&self) {
        match self {
            Self::Host(tcp) => {
                let _ = socket2::SockRef::from(tcp).set_linger(Some(Duration::ZERO));
            }
            Self::Egress(tcp) => tcp.abort(),
        }
    }
}

impl AsyncRead for Tcp {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Host(tcp) => Pin::new(tcp).poll_read(cx, buf),
            Self::Egress(tcp) => Pin::new(tcp).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Tcp {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Host(tcp) => Pin::new(tcp).poll_write(cx, data),
            Self::Egress(tcp) => Pin::new(tcp).poll_write(cx, data),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Host(tcp) => Pin::new(tcp).poll_flush(cx),
            Self::Egress(tcp) => Pin::new(tcp).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Host(tcp) => Pin::new(tcp).poll_shutdown(cx),
            Self::Egress(tcp) => Pin::new(tcp).poll_shutdown(cx),
        }
    }
}

/// A tunnel's UDP flow to its destination.
#[derive(Debug)]
pub enum Udp {
    Host(UdpSocket),
    Egress(egress::UdpSocket),
}

impl Udp {
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Host(sock) => sock.peer_addr(),
            Self::Egress(sock) => sock.peer_addr(),
        }
    }

    pub async fn send(&self, data: &[u8]) -> io::Result<usize> {
        match self {
            Self::Host(sock) => sock.send(data).await,
            Self::Egress(sock) => sock.send(data).await,
        }
    }

    /// Waits for one datagram; dropping the future loses none.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Host(sock) => sock.recv(buf).await,
            Self::Egress(sock) => sock.recv(buf).await,
        }
    }

    /// Another datagram that has already arrived, if the flow can tell
    /// without waiting.
    pub fn try_recv(&self, buf: &mut [u8]) -> Option<io::Result<usize>> {
        match self {
            Self::Host(sock) => match sock.try_recv(buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => None,
                result => Some(result),
            },
            Self::Egress(_) => None,
        }
    }

    /// The largest payload sent as is. A kernel socket reports larger ones
    /// as errors itself (see `sys::no_udp_fragmentation`).
    pub fn max_payload(&self) -> usize {
        match self {
            Self::Host(_) => usize::MAX,
            Self::Egress(sock) => sock.max_payload(),
        }
    }
}

/// Connects as [`tcp`] does, through `egress` if there is one.
pub async fn open_tcp(
    egress: Option<&Arc<dyn Egress>>,
    addrs: &[SocketAddr],
    timeout: Duration,
) -> Result<Tcp, Refusal> {
    match egress {
        None => tcp(addrs, timeout).await.map(Tcp::Host),
        Some(egress) => egress_tcp(egress, addrs, timeout).await.map(Tcp::Egress),
    }
}

/// Opens a flow as [`udp`] does, through `egress` if there is one.
pub async fn open_udp(
    egress: Option<&Arc<dyn Egress>>,
    addrs: &[SocketAddr],
    timeout: Duration,
) -> Result<Udp, Refusal> {
    match egress {
        None => udp(addrs).await.map(Udp::Host),
        Some(egress) => egress_udp(egress, addrs, timeout).await.map(Udp::Egress),
    }
}

fn unavailable() -> Refusal {
    Refusal::Unreachable("egress unavailable".into())
}

fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// An egress connection made during a race. Connections that lose the race
/// are reset, as they are dropped without ever carrying data.
struct Attempt(Option<egress::TcpStream>);

impl Drop for Attempt {
    fn drop(&mut self) {
        if let Some(stream) = &self.0 {
            stream.abort();
        }
    }
}

async fn egress_attempt(egress: Arc<dyn Egress>, addr: SocketAddr) -> io::Result<Attempt> {
    let attempt = Attempt(Some(egress.connect_tcp(addr).await?));
    if !egress.available() {
        return Err(io::Error::new(io::ErrorKind::NotConnected, "egress unavailable"));
    }
    // The egress must connect to the address the rules allowed, not another.
    if canonical(attempt.0.as_ref().expect("connected").peer_addr()?) != canonical(addr) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "egress connected to another address"));
    }
    Ok(attempt)
}

/// [`tcp`] through an egress.
async fn egress_tcp(
    egress: &Arc<dyn Egress>,
    addrs: &[SocketAddr],
    timeout: Duration,
) -> Result<egress::TcpStream, Refusal> {
    if !egress.available() {
        return Err(unavailable());
    }
    let mut attempt = race(addrs, timeout, |addr| egress_attempt(egress.clone(), addr)).await?;
    if !egress.available() {
        return Err(unavailable());
    }
    Ok(attempt.0.take().expect("connected"))
}

/// [`udp`] through an egress: the first address it opens a flow to, within
/// `timeout` overall. Opening only picks a route; the destination need not
/// answer.
async fn egress_udp(
    egress: &Arc<dyn Egress>,
    addrs: &[SocketAddr],
    timeout: Duration,
) -> Result<egress::UdpSocket, Refusal> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last_error = None;
    for addr in addrs {
        if !egress.available() {
            return Err(unavailable());
        }
        match tokio::time::timeout_at(deadline, egress.connect_udp(*addr)).await {
            Ok(Ok(sock)) => {
                if !egress.available() {
                    return Err(unavailable());
                }
                if canonical(sock.peer_addr().map_err(|e| refusal(&e))?) != canonical(*addr) {
                    return Err(Refusal::Unreachable("egress connected to another address".into()));
                }
                return Ok(sock);
            }
            Ok(Err(e)) => last_error = Some(e),
            Err(_) => return Err(Refusal::ConnectionTimeout),
        }
    }
    Err(last_error.map_or(Refusal::NoAddresses, |e| refusal(&e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn errors_map_to_refusals() {
        assert_eq!(refusal(&io::ErrorKind::ConnectionRefused.into()), Refusal::ConnectionRefused);
        assert_eq!(refusal(&io::ErrorKind::TimedOut.into()), Refusal::ConnectionTimeout);
        // Out of sockets (an egress's socket limit, say): connection_limit_reached.
        assert_eq!(refusal(&io::ErrorKind::OutOfMemory.into()), Refusal::TooManyTunnels);
        assert!(matches!(refusal(&io::ErrorKind::HostUnreachable.into()), Refusal::Unreachable(_)));
    }

    #[test]
    fn families_alternate_starting_with_the_first() {
        let v6 = [a("[2001:db8::1]:1"), a("[2001:db8::2]:1")];
        let v4 = [a("192.0.2.1:1"), a("192.0.2.2:1"), a("192.0.2.3:1")];
        assert_eq!(interleave(&[v6[0], v6[1], v4[0], v4[1], v4[2]]), [v6[0], v4[0], v6[1], v4[1], v4[2]]);
        assert_eq!(interleave(&[v4[0], v6[0], v6[1]]), [v4[0], v6[0], v6[1]]);
        assert!(interleave(&[]).is_empty());
    }

    #[tokio::test]
    async fn connects_to_the_address_that_answers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good = listener.local_addr().unwrap();
        // A closed port on loopback refuses at once; the next one is tried.
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let s = tcp(&[closed, good], Duration::from_secs(5)).await.unwrap();
        assert_eq!(s.peer_addr().unwrap(), good);
        assert_eq!(tcp(&[closed], Duration::from_secs(5)).await.unwrap_err(), Refusal::ConnectionRefused);
    }

    #[tokio::test]
    async fn gives_up_at_the_deadline() {
        // A documentation address never answers (or some sandboxes refuse
        // it at once); either way the attempt ends by the deadline.
        let started = std::time::Instant::now();
        let r = tcp(&[a("192.0.2.1:9"), a("192.0.2.2:9")], Duration::from_millis(300)).await;
        assert!(r.is_err());
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    }

    #[tokio::test]
    async fn udp_sockets_are_connected() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock = udp(&[peer.local_addr().unwrap()]).await.unwrap();
        assert_eq!(sock.peer_addr().unwrap(), peer.local_addr().unwrap());
        sock.send(b"ping").await.unwrap();
        let mut buf = [0u8; 8];
        let (n, from) = peer.recv_from(&mut buf).await.unwrap();
        assert_eq!((&buf[..n], from), (&b"ping"[..], sock.local_addr().unwrap()));
    }

    mod through_egress {
        use super::*;
        use crate::egress::IoFuture;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Mutex;

        /// Answers TCP at `good` only; every other attempt is refused, or
        /// with `pending`, never completes.
        struct FakeEgress {
            calls: Mutex<Vec<SocketAddr>>,
            unavailable: AtomicBool,
            good: SocketAddr,
            returned_peer: SocketAddr,
            pending: bool,
            aborted: Arc<AtomicUsize>,
            cancelled: AtomicUsize,
            held: Mutex<Vec<tokio::io::DuplexStream>>,
        }

        fn fake(good: SocketAddr) -> FakeEgress {
            FakeEgress {
                calls: Mutex::default(),
                unavailable: AtomicBool::new(false),
                good,
                returned_peer: good,
                pending: false,
                aborted: Arc::default(),
                cancelled: AtomicUsize::new(0),
                held: Mutex::default(),
            }
        }

        struct Cancelled<'a>(&'a AtomicUsize);

        impl Drop for Cancelled<'_> {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        impl Egress for FakeEgress {
            fn resolve<'a>(&'a self, _: &'a str) -> IoFuture<'a, Vec<IpAddr>> {
                panic!("connecting to addresses needs no lookup")
            }

            fn connect_tcp(&self, peer: SocketAddr) -> IoFuture<'_, egress::TcpStream> {
                self.calls.lock().unwrap().push(peer);
                Box::pin(async move {
                    if self.pending {
                        let _cancelled = Cancelled(&self.cancelled);
                        return std::future::pending().await;
                    }
                    if peer != self.good {
                        return Err(io::ErrorKind::ConnectionRefused.into());
                    }
                    let (client, held) = tokio::io::duplex(64);
                    self.held.lock().unwrap().push(held);
                    let aborted = self.aborted.clone();
                    let abort = Arc::new(move || {
                        aborted.fetch_add(1, Ordering::Relaxed);
                    });
                    Ok(egress::TcpStream::new(client, a("192.0.2.2:12345"), self.returned_peer, abort))
                })
            }

            fn connect_udp(&self, peer: SocketAddr) -> IoFuture<'_, egress::UdpSocket> {
                self.calls.lock().unwrap().push(peer);
                Box::pin(async move {
                    if self.pending {
                        let _cancelled = Cancelled(&self.cancelled);
                        std::future::pending().await
                    } else {
                        Err(io::ErrorKind::ConnectionRefused.into())
                    }
                })
            }

            fn available(&self) -> bool {
                !self.unavailable.load(Ordering::Relaxed)
            }

            fn failed(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                Box::pin(std::future::pending())
            }
        }

        fn shared(egress: FakeEgress) -> (Arc<FakeEgress>, Arc<dyn Egress>) {
            let egress = Arc::new(egress);
            (egress.clone(), egress)
        }

        #[tokio::test]
        async fn connects_to_the_address_that_answers() {
            let (bad, good) = (a("192.0.2.1:9"), a("192.0.2.2:9"));
            let (fake, egress) = shared(fake(good));
            let t = open_tcp(Some(&egress), &[bad, good], Duration::from_secs(5)).await.unwrap();
            assert!(matches!(t, Tcp::Egress(_)));
            assert_eq!(t.peer_addr().unwrap(), good);
            assert_eq!(*fake.calls.lock().unwrap(), [bad, good]);
            let refused = open_tcp(Some(&egress), &[bad], Duration::from_secs(5)).await.unwrap_err();
            assert_eq!(refused, Refusal::ConnectionRefused);
            assert_eq!(fake.aborted.load(Ordering::Relaxed), 0, "the winner is not reset");
            t.abort();
            assert_eq!(fake.aborted.load(Ordering::Relaxed), 1);
        }

        #[tokio::test(start_paused = true)]
        async fn both_protocols_give_up_at_the_deadline() {
            let mut f = fake(a("192.0.2.2:9"));
            f.pending = true;
            let (fake, egress) = shared(f);
            let addrs = [a("192.0.2.1:9")];
            let timeout = Duration::from_millis(300);
            assert_eq!(open_tcp(Some(&egress), &addrs, timeout).await.unwrap_err(), Refusal::ConnectionTimeout);
            assert_eq!(open_udp(Some(&egress), &addrs, timeout).await.unwrap_err(), Refusal::ConnectionTimeout);
            tokio::task::yield_now().await;
            assert_eq!(fake.cancelled.load(Ordering::Relaxed), 2, "both pending attempts are dropped");
        }

        #[tokio::test]
        async fn a_connection_to_another_address_is_reset_and_refused() {
            let requested = a("192.0.2.2:9");
            let mut f = fake(requested);
            f.returned_peer = a("127.0.0.1:9");
            let (fake, egress) = shared(f);
            let r = open_tcp(Some(&egress), &[requested], Duration::from_secs(1)).await;
            assert!(matches!(r, Err(Refusal::Unreachable(_))), "{r:?}");
            assert_eq!(fake.aborted.load(Ordering::Relaxed), 1);
        }

        #[tokio::test]
        async fn an_unavailable_egress_is_not_tried() {
            let f = fake(a("192.0.2.2:9"));
            f.unavailable.store(true, Ordering::Relaxed);
            let (fake, egress) = shared(f);
            let addrs = [fake.good];
            let r = open_tcp(Some(&egress), &addrs, Duration::from_secs(1)).await;
            assert!(matches!(r, Err(Refusal::Unreachable(_))), "{r:?}");
            let r = open_udp(Some(&egress), &addrs, Duration::from_secs(1)).await;
            assert!(matches!(r, Err(Refusal::Unreachable(_))), "{r:?}");
            assert!(fake.calls.lock().unwrap().is_empty());
        }

        #[tokio::test]
        async fn without_an_egress_the_host_network_is_used() {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let t = open_tcp(None, &[listener.local_addr().unwrap()], Duration::from_secs(5)).await.unwrap();
            assert!(matches!(t, Tcp::Host(_)));
            let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let u = open_udp(None, &[peer.local_addr().unwrap()], Duration::from_secs(5)).await.unwrap();
            assert!(matches!(u, Udp::Host(_)));
            assert_eq!(u.max_payload(), usize::MAX);
        }
    }
}
