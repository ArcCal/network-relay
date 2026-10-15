//! A user-space TCP/IP stack (smoltcp) on top of the tunnel's IP packets.
//!
//! SOCKS mode uses it to open TCP connections and send UDP datagrams from
//! the addresses the proxy assigned, as a kernel would through a TUN device,
//! but without a TUN device or any change to the host's routing or DNS.
//! [`TcpStream`] implements tokio's `AsyncRead` and `AsyncWrite`, so it can
//! be relayed with `tokio::io::copy_bidirectional`.
//!
//! One mutex guards the whole stack. [`NetStack::run`] moves packets between
//! the stack and the tunnel and runs the stack's timers; sockets wake their
//! tasks through smoltcp's waker registrations.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use ring::rand::{SecureRandom, SystemRandom};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp, Socket};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpCidr, IpEndpoint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, watch, Notify};
use tokio::time::Instant;

/// The stack sends packets of at most this size: the IPv6 minimum MTU, which
/// a tunnel carrying IPv6 must carry (RFC 9484 §7.2). The stack has no path
/// MTU discovery, so it stays at a size every tunnel carries, or lower while
/// the tunnel's own path MTU discovery has not found room for it yet
/// ([`NetStack::set_mtu`]).
pub const MTU: usize = 1280;
/// The least the stack goes down to (the IPv4 minimum, RFC 791).
const MIN_MTU: usize = 576;
/// Receive window per TCP connection: with window scaling, enough for about
/// 80 Mbit/s at 200 ms round-trip time. Memory is touched only as it fills.
const TCP_RX_BUFFER: usize = 256 << 10;
const TCP_TX_BUFFER: usize = 128 << 10;
const UDP_PACKETS: usize = 128;
const UDP_BUFFER: usize = 128 << 10;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// A connection with unacknowledged data and no word from the peer for
/// this long is reset.
const TCP_TIMEOUT: Duration = Duration::from_secs(120);
/// A dropped stream's connection gets this long to close before it is reset.
const LINGER: Duration = Duration::from_secs(30);
/// Upper bound on the wait between runs of the stack's timers.
const MAX_IDLE: Duration = Duration::from_secs(1);
/// Includes connections still being raced or closed, plus UDP and DNS.
/// The frontend session limit alone does not bound these socket buffers.
const MAX_SOCKETS: usize = 64;
const EPHEMERAL_FIRST: u16 = 49152;
const EPHEMERAL_PORTS: u16 = 16384;

/// The largest UDP payload that fits in one packet of `mtu` bytes.
pub fn max_udp_payload(mtu: usize, ipv4: bool) -> usize {
    mtu - if ipv4 { 20 } else { 40 } - 8
}

/// A user-space TCP/IP stack; cheap to clone.
#[derive(Clone)]
pub struct NetStack(Arc<Shared>);

struct Shared {
    state: Mutex<State>,
    /// Wakes [`NetStack::run`] after a socket changed.
    wake: Notify,
    ended: watch::Sender<Option<String>>,
    queue_drops: AtomicU64,
}

struct State {
    iface: Interface,
    device: Queues,
    sockets: SocketSet<'static>,
    addresses: Vec<IpAddr>,
    /// Sockets of dropped streams, with the time to give up on them.
    lingering: Vec<(SocketHandle, Instant)>,
    failure: Option<String>,
    // Lifecycle wakeups are separate from smoltcp readiness: stopping the
    // packet runner must wake pending operations even without another poll.
    waiters: HashMap<SocketHandle, Waiters>,
}

#[derive(Default)]
struct Waiters {
    read: Option<Waker>,
    write: Option<Waker>,
    token: Arc<()>,
}

impl NetStack {
    /// A stack without addresses. Each packet it sends is preceded by
    /// `headroom` zero bytes (the client's context ID 0).
    pub fn new(headroom: usize) -> Self {
        let mut device = Queues { headroom, ..Queues::default() };
        let iface = new_interface(&mut device);
        let state = State {
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            addresses: Vec::new(),
            lingering: Vec::new(),
            failure: None,
            waiters: HashMap::new(),
        };
        let (ended, _) = watch::channel(None);
        Self(Arc::new(Shared { state: Mutex::new(state), wake: Notify::new(), ended, queue_drops: AtomicU64::new(0) }))
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.0.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn wake(&self) {
        self.0.wake.notify_one();
    }

    /// Terminal failure is monotonic. Existing sockets retain valid handles
    /// until their owners release them, but all operations fail immediately.
    pub fn fail(&self, reason: impl Into<String>) {
        let reason = reason.into();
        let waiters = {
            let mut st = self.lock();
            if st.failure.is_some() {
                return;
            }
            st.failure = Some(reason.clone());
            st.device.rx.clear();
            st.device.tx.clear();
            for (_, socket) in st.sockets.iter_mut() {
                if let Socket::Tcp(socket) = socket {
                    socket.abort();
                }
            }
            // These handles no longer have stream owners and are safe to
            // remove immediately; no dead session runner will reap them.
            let lingering: Vec<_> = st.lingering.drain(..).map(|(handle, _)| handle).collect();
            for handle in lingering {
                st.sockets.remove(handle);
                st.waiters.remove(&handle);
            }
            st.waiters.values().flat_map(|w| [w.read.clone(), w.write.clone()]).flatten().collect::<Vec<_>>()
        };
        self.0.ended.send_replace(Some(reason));
        for waiter in waiters {
            waiter.wake();
        }
        self.wake();
    }

    pub fn check_available(&self) -> io::Result<()> {
        self.lock().check_available()
    }

    pub async fn closed(&self) -> String {
        let mut ended = self.0.ended.subscribe();
        let why = match ended.wait_for(|why| why.is_some()).await {
            Ok(why) => why.clone().unwrap_or_else(|| "egress stopped".into()),
            Err(_) => "egress stopped".into(),
        };
        why
    }

    pub fn socket_count(&self) -> usize {
        self.lock().sockets.iter().count()
    }

    pub fn socket_limit(&self) -> usize {
        MAX_SOCKETS
    }

    pub fn tcp_buffer_bytes(&self) -> usize {
        TCP_RX_BUFFER + TCP_TX_BUFFER
    }

    pub fn queue_drops(&self) -> u64 {
        self.0.queue_drops.load(Ordering::Relaxed)
    }

    pub fn failure_reason(&self) -> Option<String> {
        self.lock().failure.clone()
    }

    pub fn local_address(&self, peer: IpAddr) -> io::Result<IpAddr> {
        let st = self.lock();
        st.check_family(peer)?;
        st.addresses
            .iter()
            .copied()
            .find(|ip| ip.is_ipv4() == peer.is_ipv4())
            .ok_or_else(|| io::ErrorKind::AddrNotAvailable.into())
    }

    /// Sets the stack's own addresses (at most one per family). Connections
    /// from addresses it no longer has are reset.
    pub fn set_addresses(&self, addresses: &[IpAddr]) {
        let mut st = self.lock();
        if st.addresses == addresses {
            return;
        }
        st.addresses = addresses.to_vec();
        st.configure_interface();
        for (_, socket) in st.sockets.iter_mut() {
            if let Socket::Tcp(s) = socket {
                if s.local_endpoint().is_some_and(|e| !addresses.contains(&e.addr.into())) {
                    s.abort();
                }
            }
        }
        drop(st);
        self.wake();
    }

    /// Limits the packets the stack sends to `mtu` bytes (within 576 and
    /// [`MTU`]), for a tunnel that carries no more for now. Connections
    /// shrink their segments to fit; new ones also announce a smaller MSS.
    /// True if the limit changed.
    pub fn set_mtu(&self, mtu: usize) -> bool {
        let mtu = mtu.clamp(MIN_MTU, MTU);
        let mut st = self.lock();
        if st.device.mtu == mtu {
            return false;
        }
        st.device.mtu = mtu;
        let mut wake = Vec::new();
        if mtu < MTU {
            let mut affected = Vec::new();
            for (handle, socket) in st.sockets.iter_mut() {
                if let Socket::Tcp(socket) = socket {
                    if socket.local_endpoint().is_some_and(|peer| IpAddr::from(peer.addr).is_ipv6()) {
                        socket.abort();
                        affected.push(handle);
                    }
                }
            }
            for handle in affected {
                if let Some(waiters) = st.waiters.get(&handle) {
                    wake.extend([waiters.read.clone(), waiters.write.clone()].into_iter().flatten());
                }
            }
        }
        // UDP sockets may have a connected facade waiting on a family or
        // payload capability. Wake them to recheck it after an MTU change.
        for waiters in st.waiters.values() {
            wake.extend([waiters.read.clone(), waiters.write.clone()].into_iter().flatten());
        }
        // smoltcp reads the device's MTU when the interface is made; the
        // sockets are kept apart from it and carry on.
        st.iface = new_interface(&mut st.device);
        st.configure_interface();
        drop(st);
        for waiter in wake {
            waiter.wake();
        }
        self.wake();
        true
    }

    /// The largest packet the stack sends now.
    pub fn mtu(&self) -> usize {
        self.lock().device.mtu
    }

    /// The stack's current addresses.
    pub fn addresses(&self) -> Vec<IpAddr> {
        let st = self.lock();
        st.addresses.iter().copied().filter(|ip| ip.is_ipv4() || st.device.mtu >= MTU).collect()
    }

    /// A consistent diagnostics snapshot retains assigned addresses even
    /// when the current path cannot carry one of their families.
    pub(crate) fn address_snapshot(&self) -> (bool, usize, Vec<IpAddr>) {
        let st = self.lock();
        (st.failure.is_none(), st.device.mtu, st.addresses.clone())
    }

    /// Feeds `incoming` packets into the stack and sends what it produces to
    /// `outgoing`, until `incoming` closes. Packets are dropped when
    /// `outgoing` is full, as a network would; TCP sends them again.
    pub async fn run(&self, mut incoming: mpsc::Receiver<Bytes>, outgoing: mpsc::Sender<Bytes>) {
        loop {
            if outgoing.is_closed() {
                self.fail("the packet output channel closed");
                return;
            }
            let (out, delay) = {
                let mut st = self.lock();
                if st.failure.is_some() {
                    return;
                }
                let now = SmolInstant::now();
                let State { iface, device, sockets, .. } = &mut *st;
                iface.poll(now, device, sockets);
                st.reap();
                let out: Vec<Bytes> = st.device.tx.drain(..).collect();
                let State { iface, sockets, .. } = &mut *st;
                let delay = iface.poll_delay(now, sockets).map_or(MAX_IDLE, |d| d.into()).min(MAX_IDLE);
                (out, delay)
            };
            for p in out {
                match outgoing.try_send(p) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        self.0.queue_drops.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        self.fail("the packet output channel closed");
                        return;
                    }
                }
            }
            tokio::select! {
                _ = outgoing.closed() => {
                    self.fail("the packet output channel closed");
                    return;
                }
                p = incoming.recv() => {
                    let Some(p) = p else {
                        self.fail("the packet input channel closed");
                        return;
                    };
                    let mut st = self.lock();
                    st.device.rx.push_back(p);
                    for _ in 0..255 {
                        match incoming.try_recv() {
                            Ok(p) => st.device.rx.push_back(p),
                            Err(_) => break,
                        }
                    }
                }
                _ = self.0.wake.notified() => {}
                _ = tokio::time::sleep(delay) => {}
            }
        }
    }

    /// Opens a TCP connection from the stack's address of `remote`'s family.
    pub async fn connect(&self, remote: SocketAddr) -> io::Result<TcpStream> {
        let handle = {
            let mut st = self.lock();
            st.check_available()?;
            st.check_family(remote.ip())?;
            st.check_socket_capacity(1)?;
            let port = st.ephemeral_port()?;
            let mut socket = new_tcp_socket();
            let State { iface, .. } = &mut *st;
            socket.connect(iface.context(), remote, port).map_err(|e| {
                io::Error::new(io::ErrorKind::AddrNotAvailable, format!("cannot connect to {remote}: {e}"))
            })?;
            let handle = st.sockets.add(socket);
            st.waiters.insert(handle, Waiters::default());
            handle
        };
        self.wake();
        let stream = TcpStream { stack: self.clone(), handle };
        match tokio::time::timeout(CONNECT_TIMEOUT, poll_fn(|cx| stream.poll_connected(cx))).await {
            Ok(Ok(())) => Ok(stream),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, format!("connecting to {remote} timed out"))),
        }
    }

    #[allow(dead_code)] // used by the tests
    /// Accepts TCP connections to `port` on the stack's addresses. Up to
    /// `backlog` handshakes can be in progress or waiting for `accept`; more
    /// are refused.
    pub fn listen(&self, port: u16, backlog: usize) -> io::Result<TcpListener> {
        let mut st = self.lock();
        st.check_available()?;
        st.check_socket_capacity(backlog)?;
        let mut slots = Vec::with_capacity(backlog);
        for _ in 0..backlog {
            let mut socket = new_tcp_socket();
            socket.listen(port).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
            slots.push(st.sockets.add(socket));
        }
        Ok(TcpListener { stack: self.clone(), port, backlog: slots })
    }

    /// A UDP socket on `port`, or on a free ephemeral port if it is 0.
    pub fn bind_udp(&self, port: u16) -> io::Result<UdpSocket> {
        let mut st = self.lock();
        st.check_available()?;
        st.check_socket_capacity(1)?;
        let port = if port == 0 { st.ephemeral_port()? } else { port };
        let mut socket = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; UDP_PACKETS], vec![0; UDP_BUFFER]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; UDP_PACKETS], vec![0; UDP_BUFFER]),
        );
        socket.bind(port).map_err(|e| io::Error::new(io::ErrorKind::AddrInUse, e.to_string()))?;
        let handle = st.sockets.add(socket);
        st.waiters.insert(handle, Waiters::default());
        Ok(UdpSocket { stack: self.clone(), handle })
    }
}

fn new_interface(device: &mut Queues) -> Interface {
    let mut config = Config::new(HardwareAddress::Ip);
    let mut seed = [0u8; 8];
    SystemRandom::new().fill(&mut seed).expect("system RNG");
    config.random_seed = u64::from_le_bytes(seed);
    Interface::new(config, device, SmolInstant::now())
}

fn new_tcp_socket() -> tcp::Socket<'static> {
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; TCP_RX_BUFFER]),
        tcp::SocketBuffer::new(vec![0; TCP_TX_BUFFER]),
    );
    // A proxy passes on whatever it gets at once; batching is the
    // application's business.
    socket.set_nagle_enabled(false);
    socket.set_congestion_control(tcp::CongestionControl::Cubic);
    socket.set_timeout(Some(TCP_TIMEOUT.into()));
    socket
}

impl State {
    fn check_available(&self) -> io::Result<()> {
        match &self.failure {
            Some(why) => Err(io::Error::new(io::ErrorKind::ConnectionAborted, why.clone())),
            None => Ok(()),
        }
    }
    fn check_socket_capacity(&self, additional: usize) -> io::Result<()> {
        if self.sockets.iter().count().saturating_add(additional) > MAX_SOCKETS {
            return Err(io::Error::new(io::ErrorKind::OutOfMemory, "the user-space socket limit was reached"));
        }
        Ok(())
    }

    /// Gives the interface the stack's addresses, and routes everything to
    /// the tunnel.
    fn configure_interface(&mut self) {
        let addresses = &self.addresses;
        self.iface.update_ip_addrs(|a| {
            a.clear();
            for &ip in addresses {
                let _ = a.push(IpCidr::new(ip.into(), if ip.is_ipv4() { 32 } else { 128 }));
            }
        });
        // The gateway only has to exist; an IP-medium interface never
        // resolves it.
        self.iface.routes_mut().update(|r| r.clear());
        for &ip in addresses {
            let _ = match ip {
                IpAddr::V4(a) => self.iface.routes_mut().add_default_ipv4_route(a),
                IpAddr::V6(a) => self.iface.routes_mut().add_default_ipv6_route(a),
            };
        }
    }

    /// Fails unless the stack has an address of `dst`'s family.
    fn check_family(&self, dst: IpAddr) -> io::Result<()> {
        self.check_available()?;
        if dst.is_ipv6() && self.device.mtu < MTU {
            return Err(io::Error::new(
                io::ErrorKind::NetworkUnreachable,
                "the tunnel cannot carry the IPv6 minimum MTU",
            ));
        }
        if self.addresses.iter().any(|a| a.is_ipv4() == dst.is_ipv4()) {
            Ok(())
        } else {
            let family = if dst.is_ipv4() { "IPv4" } else { "IPv6" };
            Err(io::Error::new(io::ErrorKind::AddrNotAvailable, format!("the tunnel has no {family} address")))
        }
    }

    /// A random local port no socket uses, from the IANA dynamic range.
    /// Random, so that answers to DNS queries are harder to forge.
    fn ephemeral_port(&self) -> io::Result<u16> {
        let used: HashSet<u16> = self
            .sockets
            .iter()
            .map(|(_, s)| match s {
                Socket::Tcp(t) => t.local_endpoint().map_or(t.listen_endpoint().port, |e| e.port),
                Socket::Udp(u) => u.endpoint().port,
                #[allow(unreachable_patterns)]
                _ => 0,
            })
            .collect();
        choose_ephemeral_port(&used)
    }

    /// Removes the sockets of dropped streams once their connection is over,
    /// or has taken too long to close.
    fn reap(&mut self) {
        let now = Instant::now();
        let sockets = &mut self.sockets;
        self.lingering.retain(|&(handle, give_up)| {
            let s = sockets.get_mut::<tcp::Socket>(handle);
            match s.state() {
                tcp::State::Closed | tcp::State::TimeWait => {
                    sockets.remove(handle);
                    self.waiters.remove(&handle);
                    false
                }
                _ if now >= give_up => {
                    s.abort();
                    // Removed next time, after the reset has been sent.
                    true
                }
                _ => true,
            }
        });
    }
}

fn choose_ephemeral_port(used: &HashSet<u16>) -> io::Result<u16> {
    let rng = SystemRandom::new();
    let mut start = 0;
    // Preserve uniform random selection under ordinary load, especially
    // for DNS. Bound retries when almost all ports are occupied.
    for _ in 0..64 {
        let mut b = [0u8; 2];
        rng.fill(&mut b).expect("system RNG");
        start = u16::from_le_bytes(b) % EPHEMERAL_PORTS;
        let port = EPHEMERAL_FIRST + start;
        if !used.contains(&port) {
            return Ok(port);
        }
    }
    for offset in 0..EPHEMERAL_PORTS {
        let port = EPHEMERAL_FIRST + (start + offset) % EPHEMERAL_PORTS;
        if !used.contains(&port) {
            return Ok(port);
        }
    }
    Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "the user-space stack has no free ephemeral port"))
}

/// A TCP connection through the stack.
pub struct TcpStream {
    stack: NetStack,
    handle: SocketHandle,
}

impl TcpStream {
    fn poll_connected(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut st = self.stack.lock();
        st.check_available()?;
        st.waiters.entry(self.handle).or_default().write = Some(cx.waker().clone());
        let s = st.sockets.get_mut::<tcp::Socket>(self.handle);
        match s.state() {
            tcp::State::SynSent | tcp::State::SynReceived => {
                s.register_send_waker(cx.waker());
                Poll::Pending
            }
            tcp::State::Closed => Poll::Ready(Err(io::ErrorKind::ConnectionRefused.into())),
            _ => Poll::Ready(Ok(())),
        }
    }

    /// The stack's address and port of this connection.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.stack.lock().sockets.get::<tcp::Socket>(self.handle).local_endpoint().map(Into::into)
    }

    /// The remote address and port.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.stack.lock().sockets.get::<tcp::Socket>(self.handle).remote_endpoint().map(Into::into)
    }

    /// Reset this socket independently of the stream wrapper's ownership.
    pub fn abort_handle(&self) -> Arc<dyn Fn() + Send + Sync> {
        let shared = Arc::downgrade(&self.stack.0);
        let handle = self.handle;
        let token = Arc::downgrade(&self.stack.lock().waiters[&handle].token);
        Arc::new(move || {
            let Some(shared) = shared.upgrade() else { return };
            let Some(token) = token.upgrade() else { return };
            let stack = NetStack(shared);
            let waiters = {
                let mut st = stack.lock();
                // An abort control can outlive a dropped/reaped stream.
                let Some(waiters) = st.waiters.get(&handle) else { return };
                if !Arc::ptr_eq(&waiters.token, &token) {
                    return;
                }
                let waiters = [waiters.read.clone(), waiters.write.clone()];
                st.sockets.get_mut::<tcp::Socket>(handle).abort();
                waiters
            };
            for waiter in waiters.into_iter().flatten() {
                waiter.wake();
            }
            stack.wake();
        })
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut st = self.stack.lock();
        st.check_available()?;
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        st.waiters.entry(self.handle).or_default().read = Some(cx.waker().clone());
        let s = st.sockets.get_mut::<tcp::Socket>(self.handle);
        match s.recv_slice(buf.initialize_unfilled()) {
            Ok(0) => {
                s.register_recv_waker(cx.waker());
                Poll::Pending
            }
            Ok(n) => {
                buf.advance(n);
                drop(st);
                // The window opened; the stack may need to say so.
                self.stack.wake();
                Poll::Ready(Ok(()))
            }
            Err(tcp::RecvError::Finished) => Poll::Ready(Ok(())),
            Err(tcp::RecvError::InvalidState) => Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let mut st = self.stack.lock();
        st.check_available()?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        st.waiters.entry(self.handle).or_default().write = Some(cx.waker().clone());
        let s = st.sockets.get_mut::<tcp::Socket>(self.handle);
        if !s.may_send() {
            let kind = if s.state() == tcp::State::Closed {
                io::ErrorKind::ConnectionReset
            } else {
                io::ErrorKind::BrokenPipe
            };
            return Poll::Ready(Err(kind.into()));
        }
        match s.send_slice(data) {
            Ok(0) => {
                s.register_send_waker(cx.waker());
                Poll::Pending
            }
            Ok(n) => {
                drop(st);
                self.stack.wake();
                Poll::Ready(Ok(n))
            }
            Err(_) => Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.stack.check_available())
    }

    /// Sends FIN after the queued data.
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut st = self.stack.lock();
        st.check_available()?;
        st.sockets.get_mut::<tcp::Socket>(self.handle).close();
        drop(st);
        self.stack.wake();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let mut st = self.stack.lock();
        if st.failure.is_some() {
            st.sockets.remove(self.handle);
            st.waiters.remove(&self.handle);
            return;
        }
        let s = st.sockets.get_mut::<tcp::Socket>(self.handle);
        // Unread data means the application gave up on the connection: reset
        // it, as a kernel does. Otherwise let it close in order.
        if s.can_recv() || matches!(s.state(), tcp::State::SynSent | tcp::State::SynReceived) {
            s.abort();
        } else {
            s.close();
        }
        st.lingering.push((self.handle, Instant::now() + LINGER));
        drop(st);
        self.stack.wake();
    }
}

/// Accepts TCP connections through the stack.
#[allow(dead_code)] // used by the tests
pub struct TcpListener {
    stack: NetStack,
    port: u16,
    backlog: Vec<SocketHandle>,
}

impl TcpListener {
    #[allow(dead_code)] // used by the tests
    pub async fn accept(&mut self) -> io::Result<TcpStream> {
        poll_fn(|cx| {
            let mut st = self.stack.lock();
            st.check_available()?;
            for slot in &mut self.backlog {
                st.waiters.entry(*slot).or_default().write = Some(cx.waker().clone());
                let s = st.sockets.get_mut::<tcp::Socket>(*slot);
                match s.state() {
                    tcp::State::Listen | tcp::State::SynReceived => s.register_send_waker(cx.waker()),
                    tcp::State::Closed => {
                        // A handshake that failed: listen again.
                        let _ = s.listen(self.port);
                        s.register_send_waker(cx.waker());
                    }
                    _ => {
                        st.check_socket_capacity(1)?;
                        let mut fresh = new_tcp_socket();
                        if let Err(e) = fresh.listen(self.port) {
                            return Poll::Ready(Err(io::Error::other(e.to_string())));
                        }
                        let accepted = std::mem::replace(slot, st.sockets.add(fresh));
                        st.waiters.insert(accepted, Waiters::default());
                        drop(st);
                        self.stack.wake();
                        return Poll::Ready(Ok(TcpStream { stack: self.stack.clone(), handle: accepted }));
                    }
                }
            }
            Poll::Pending
        })
        .await
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut st = self.stack.lock();
        for &handle in &self.backlog {
            st.sockets.remove(handle);
            st.waiters.remove(&handle);
        }
    }
}

/// A UDP socket in the stack.
pub struct UdpSocket {
    stack: NetStack,
    handle: SocketHandle,
}

impl UdpSocket {
    /// Queues one datagram; waits while the socket's send buffer is full.
    pub async fn send_to(&self, data: &[u8], dst: SocketAddr) -> io::Result<()> {
        if data.len() > max_udp_payload(self.stack.mtu(), dst.is_ipv4()) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "datagram too large for the tunnel"));
        }
        self.stack.lock().check_family(dst.ip())?;
        poll_fn(|cx| {
            let mut st = self.stack.lock();
            st.check_family(dst.ip())?;
            if data.len() > max_udp_payload(st.device.mtu, dst.is_ipv4()) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "datagram too large for the tunnel",
                )));
            }
            st.waiters.entry(self.handle).or_default().write = Some(cx.waker().clone());
            let s = st.sockets.get_mut::<udp::Socket>(self.handle);
            match s.send_slice(data, IpEndpoint::from(dst)) {
                Ok(()) => {
                    drop(st);
                    self.stack.wake();
                    Poll::Ready(Ok(()))
                }
                Err(udp::SendError::BufferFull) => {
                    s.register_send_waker(cx.waker());
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::AddrNotAvailable, e.to_string()))),
            }
        })
        .await
    }

    /// The next datagram and its sender.
    pub async fn recv_from(&self) -> io::Result<(Bytes, SocketAddr)> {
        self.recv_from_family(None).await
    }

    pub async fn recv_from_family(&self, peer: Option<IpAddr>) -> io::Result<(Bytes, SocketAddr)> {
        poll_fn(|cx| {
            let mut st = self.stack.lock();
            st.check_available()?;
            if let Some(peer) = peer {
                st.check_family(peer)?;
            }
            st.waiters.entry(self.handle).or_default().read = Some(cx.waker().clone());
            let s = st.sockets.get_mut::<udp::Socket>(self.handle);
            match s.recv() {
                Ok((data, meta)) => Poll::Ready(Ok((Bytes::copy_from_slice(data), meta.endpoint.into()))),
                Err(_) => {
                    s.register_recv_waker(cx.waker());
                    Poll::Pending
                }
            }
        })
        .await
    }

    /// The local port.
    #[allow(dead_code)] // used by the tests
    pub fn port(&self) -> u16 {
        self.stack.lock().sockets.get::<udp::Socket>(self.handle).endpoint().port
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        let mut st = self.stack.lock();
        st.sockets.remove(self.handle);
        st.waiters.remove(&self.handle);
    }
}

/// Packet queues standing in for a network device.
struct Queues {
    rx: VecDeque<Bytes>,
    tx: VecDeque<Bytes>,
    headroom: usize,
    mtu: usize,
}

impl Default for Queues {
    fn default() -> Self {
        Self { rx: VecDeque::new(), tx: VecDeque::new(), headroom: 0, mtu: MTU }
    }
}

impl Device for Queues {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn receive(&mut self, _: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let p = self.rx.pop_front()?;
        Some((RxToken(p), TxToken { queue: &mut self.tx, headroom: self.headroom }))
    }

    fn transmit(&mut self, _: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TxToken { queue: &mut self.tx, headroom: self.headroom })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

struct RxToken(Bytes);

impl phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

struct TxToken<'a> {
    queue: &'a mut VecDeque<Bytes>,
    headroom: usize,
}

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = BytesMut::zeroed(self.headroom + len);
        let r = f(&mut buf[self.headroom..]);
        self.queue.push_back(buf.freeze());
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn signal_pending<F: Future>(future: F, ready: tokio::sync::oneshot::Sender<()>) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut ready = Some(ready);
        poll_fn(|cx| {
            let result = future.as_mut().poll(cx);
            if result.is_pending() {
                if let Some(ready) = ready.take() {
                    let _ = ready.send(());
                }
            }
            result
        })
        .await
    }

    const A4: &str = "10.0.0.1";
    const B4: &str = "10.0.0.2";
    const A6: &str = "fd00::1";
    const B6: &str = "fd00::2";

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Two stacks joined by a wire; the wire can drop packets.
    fn pair(loss_every: Option<usize>) -> (NetStack, NetStack, Vec<tokio::task::JoinHandle<()>>) {
        pair_with_limit(loss_every, usize::MAX)
    }

    /// Two stacks joined by a wire that drops every `loss_every`th packet
    /// from the first, and those over `max_len` bytes.
    fn pair_with_limit(
        loss_every: Option<usize>,
        max_len: usize,
    ) -> (NetStack, NetStack, Vec<tokio::task::JoinHandle<()>>) {
        let a = NetStack::new(0);
        let b = NetStack::new(0);
        a.set_addresses(&[ip(A4), ip(A6)]);
        b.set_addresses(&[ip(B4), ip(B6)]);
        let (a_out, mut a_wire) = mpsc::channel::<Bytes>(1024);
        let (b_out, mut b_wire) = mpsc::channel::<Bytes>(1024);
        let (to_a, a_in) = mpsc::channel(1024);
        let (to_b, b_in) = mpsc::channel(1024);
        let mut tasks = Vec::new();
        let (sa, sb) = (a.clone(), b.clone());
        tasks.push(tokio::spawn(async move { sa.run(a_in, a_out).await }));
        tasks.push(tokio::spawn(async move { sb.run(b_in, b_out).await }));
        tasks.push(tokio::spawn(async move {
            let mut n = 0;
            while let Some(p) = a_wire.recv().await {
                n += 1;
                if loss_every.is_some_and(|k| n % k == 0) || p.len() > max_len {
                    continue;
                }
                let _ = to_b.send(p).await;
            }
        }));
        tasks.push(tokio::spawn(async move {
            while let Some(p) = b_wire.recv().await {
                let _ = to_a.send(p).await;
            }
        }));
        (a, b, tasks)
    }

    /// Echoes every TCP connection on `port` and every UDP datagram to it.
    fn echo(stack: &NetStack, port: u16) -> Vec<tokio::task::JoinHandle<()>> {
        let mut listener = stack.listen(port, 32).unwrap();
        let udp = stack.bind_udp(port).unwrap();
        vec![
            tokio::spawn(async move {
                loop {
                    let mut s = listener.accept().await.unwrap();
                    tokio::spawn(async move {
                        let mut buf = vec![0; 65536];
                        loop {
                            match s.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => s.write_all(&buf[..n]).await.unwrap(),
                            }
                        }
                        s.shutdown().await.unwrap();
                    });
                }
            }),
            tokio::spawn(async move {
                loop {
                    let (data, from) = udp.recv_from().await.unwrap();
                    udp.send_to(&data, from).await.unwrap();
                }
            }),
        ]
    }

    async fn round_trip(a: &NetStack, dst: &str, len: usize) {
        let s = a.connect(SocketAddr::new(ip(dst), 7)).await.unwrap();
        assert_eq!(s.peer_addr(), Some(SocketAddr::new(ip(dst), 7)));
        assert!(a.addresses().contains(&s.local_addr().unwrap().ip()));
        let data: Vec<u8> = (0..len).map(|i| (i * 7 % 251) as u8).collect();
        let (mut r, mut w) = tokio::io::split(s);
        let sent = data.clone();
        let writer = tokio::spawn(async move {
            w.write_all(&sent).await.unwrap();
            w.shutdown().await.unwrap();
        });
        let mut back = Vec::new();
        r.read_to_end(&mut back).await.unwrap();
        writer.await.unwrap();
        assert!(back == data, "echo differs ({} of {} bytes back)", back.len(), data.len());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tcp_over_ipv4_and_ipv6() {
        let (a, b, _tasks) = pair(None);
        let _echo = echo(&b, 7);
        round_trip(&a, B4, 3 << 20).await;
        round_trip(&a, B6, 100_000).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tcp_recovers_from_packet_loss() {
        let (a, b, _tasks) = pair(Some(100));
        let _echo = echo(&b, 7);
        round_trip(&a, B4, 1 << 20).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lower_mtu_shrinks_the_segments_of_open_connections() {
        let (a, b, _tasks) = pair_with_limit(None, 1100);
        let _echo = echo(&b, 7);
        // Opened at the full MTU (the handshake's packets are small)...
        let s = a.connect(SocketAddr::new(ip(B4), 7)).await.unwrap();
        // ...then the path turns out to carry less.
        assert!(a.set_mtu(1100));
        assert!(!a.set_mtu(1100));
        assert_eq!(a.mtu(), 1100);
        let data: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect();
        let (mut r, mut w) = tokio::io::split(s);
        let sent = data.clone();
        let writer = tokio::spawn(async move {
            w.write_all(&sent).await.unwrap();
            w.shutdown().await.unwrap();
        });
        let mut back = Vec::new();
        tokio::time::timeout(Duration::from_secs(20), r.read_to_end(&mut back))
            .await
            .expect("full-size segments would be lost")
            .unwrap();
        writer.await.unwrap();
        assert!(back == data);
        // New connections work too, and the limit is kept within bounds.
        round_trip(&a, B4, 100_000).await;
        a.set_mtu(100);
        assert_eq!(a.mtu(), MIN_MTU);
        a.set_mtu(9000);
        assert_eq!(a.mtu(), MTU);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn many_connections_at_once() {
        let (a, b, _tasks) = pair(None);
        let _echo = echo(&b, 7);
        let runs: Vec<_> = (0..20)
            .map(|i| {
                let a = a.clone();
                tokio::spawn(async move { round_trip(&a, if i % 2 == 0 { B4 } else { B6 }, 50_000).await })
            })
            .collect();
        for r in runs {
            r.await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_closed_port_refuses_the_connection() {
        let (a, _b, _tasks) = pair(None);
        let e = a.connect(SocketAddr::new(ip(B4), 9)).await.err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_family_without_an_address_cannot_connect() {
        let (a, _b, _tasks) = pair(None);
        a.set_addresses(&[ip(A4)]);
        let e = a.connect(SocketAddr::new(ip(B6), 7)).await.err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::AddrNotAvailable);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn udp_over_ipv4_and_ipv6() {
        let (a, b, _tasks) = pair(None);
        let _echo = echo(&b, 7);
        let udp = a.bind_udp(0).unwrap();
        assert!(udp.port() >= 49152);
        for dst in [B4, B6] {
            let dst = SocketAddr::new(ip(dst), 7);
            udp.send_to(b"ping", dst).await.unwrap();
            let (data, from) = udp.recv_from().await.unwrap();
            assert_eq!((&data[..], from), (&b"ping"[..], dst));
        }
        let big = vec![0u8; max_udp_payload(MTU, true) + 1];
        assert_eq!(
            udp.send_to(&big, SocketAddr::new(ip(B4), 7)).await.unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let fits = vec![1u8; max_udp_payload(MTU, true)];
        udp.send_to(&fits, SocketAddr::new(ip(B4), 7)).await.unwrap();
        assert_eq!(udp.recv_from().await.unwrap().0.len(), fits.len());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn losing_the_address_resets_its_connections() {
        let (a, b, _tasks) = pair(None);
        let _echo = echo(&b, 7);
        let mut s = a.connect(SocketAddr::new(ip(B4), 7)).await.unwrap();
        a.set_addresses(&[ip("10.0.0.3"), ip(A6)]);
        let mut buf = [0u8; 8];
        let e = s.read(&mut buf).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::ConnectionReset);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropped_streams_are_cleaned_up() {
        let (a, b, _tasks) = pair(None);
        let _echo = echo(&b, 7);
        for _ in 0..5 {
            round_trip(&a, B4, 1000).await;
        }
        let sockets = |s: &NetStack| s.lock().sockets.iter().count();
        // Ours close and leave; the echo side keeps its listeners and UDP socket.
        for _ in 0..50 {
            if sockets(&a) == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(sockets(&a), 0);
    }

    #[test]
    fn packets_carry_the_headroom() {
        let mut q = Queues { headroom: 1, ..Queues::default() };
        let tx = q.transmit(SmolInstant::now()).unwrap();
        phy::TxToken::consume(tx, 3, |b| b.copy_from_slice(&[7, 8, 9]));
        assert_eq!(&q.tx.pop_front().unwrap()[..], &[0, 7, 8, 9]);
    }

    #[tokio::test]
    async fn socket_churn_has_a_budget_and_recovers_capacity() {
        let stack = NetStack::new(0);
        stack.set_addresses(&[ip(A4)]);
        let mut handles = Vec::new();
        {
            let mut state = stack.lock();
            // Small buffers keep this resource-limit test inexpensive.
            // These stand in for sockets still connecting or closing.
            for port in 49152..49152 + MAX_SOCKETS as u16 {
                let mut socket = udp::Socket::new(
                    udp::PacketBuffer::new(Vec::new(), Vec::new()),
                    udp::PacketBuffer::new(Vec::new(), Vec::new()),
                );
                socket.bind(port).unwrap();
                handles.push(state.sockets.add(socket));
            }
        }
        let error = stack.bind_udp(0).err().expect("socket churn has no resource limit");
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        let error = stack.connect(SocketAddr::new(ip(B4), 7)).await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        stack.lock().sockets.remove(handles.pop().unwrap());
        let replacement = stack.bind_udp(0).expect("released capacity was not reusable");
        assert_eq!(stack.lock().sockets.iter().count(), MAX_SOCKETS);
        drop(replacement);
        assert_eq!(stack.lock().sockets.iter().count(), MAX_SOCKETS - 1);
    }

    #[test]
    fn ephemeral_port_exhaustion_fails_and_a_last_free_port_is_found() {
        let mut used: HashSet<u16> = (49152..=65535).collect();
        assert_eq!(choose_ephemeral_port(&used).unwrap_err().kind(), io::ErrorKind::AddrNotAvailable);
        used.remove(&55555);
        assert_eq!(choose_ephemeral_port(&used).unwrap(), 55555);
        used.insert(7); // Non-ephemeral listener ports do not reduce this range.
        assert_eq!(choose_ephemeral_port(&used).unwrap(), 55555);
    }

    #[tokio::test]
    async fn terminal_failure_wakes_pending_connect_udp_read_and_full_send() {
        let stack = NetStack::new(0);
        stack.set_addresses(&[ip(A4)]);
        let udp = Arc::new(stack.bind_udp(0).unwrap());
        let (send_ready, sending) = tokio::sync::oneshot::channel();
        let sender = udp.clone();
        let send = tokio::spawn(async move {
            // No packet runner: fill the actual bounded smoltcp UDP queue.
            signal_pending(
                async {
                    for _ in 0..=UDP_PACKETS {
                        sender.send_to(&[0; 1252], sa(B4, 7)).await?;
                    }
                    Ok::<(), io::Error>(())
                },
                send_ready,
            )
            .await
        });
        let (read_ready, reading) = tokio::sync::oneshot::channel();
        let receiver = udp.clone();
        let read = tokio::spawn(async move { signal_pending(receiver.recv_from(), read_ready).await });
        let (connect_ready, connecting) = tokio::sync::oneshot::channel();
        let dial_stack = stack.clone();
        let dial = tokio::spawn(async move { signal_pending(dial_stack.connect(sa(B4, 7)), connect_ready).await });
        sending.await.unwrap();
        reading.await.unwrap();
        connecting.await.unwrap();
        stack.fail("fixture tunnel died");
        stack.fail("secondary cleanup error");
        assert_eq!(stack.closed().await, "fixture tunnel died");
        for task in [
            send,
            tokio::spawn(async move { read.await.unwrap().map(|_| ()) }),
            tokio::spawn(async move { dial.await.unwrap().map(|_| ()) }),
        ] {
            let result = tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .expect("failure did not wake the blocked task")
                .unwrap();
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
        }
        assert_eq!(udp.send_to(b"zombie", sa(B4, 7)).await.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
        assert!(stack.bind_udp(0).is_err());
        drop(udp);
        assert_eq!(stack.socket_count(), 0);
    }

    fn sa(ip: &str, port: u16) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), port)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn terminal_failure_wakes_established_tcp_read_and_backpressured_write() {
        let (a, b, tasks) = pair(None);
        let mut listener = b.listen(7, 1).unwrap();
        let dial = a.connect(sa(B4, 7));
        let (client, peer) = tokio::join!(dial, listener.accept());
        let peer = peer.unwrap(); // intentionally does not consume incoming data
        let stream = client.unwrap();
        let abort = stream.abort_handle();
        let (mut read_half, mut write_half) = tokio::io::split(stream);
        let (read_ready, reading) = tokio::sync::oneshot::channel();
        let read = tokio::spawn(async move {
            let mut data = [0u8; 1];
            signal_pending(read_half.read(&mut data), read_ready).await
        });
        let (write_ready, writing) = tokio::sync::oneshot::channel();
        let write = tokio::spawn(async move {
            let data = vec![0xa5; 8 << 20];
            signal_pending(write_half.write_all(&data), write_ready).await
        });
        reading.await.unwrap();
        writing.await.unwrap();
        a.fail("fixture transport reset");
        let read_error = tokio::time::timeout(Duration::from_secs(1), read).await.unwrap().unwrap().unwrap_err();
        let write_error = tokio::time::timeout(Duration::from_secs(1), write).await.unwrap().unwrap().unwrap_err();
        assert_eq!(read_error.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(write_error.kind(), io::ErrorKind::ConnectionAborted);
        abort(); // safe after both halves dropped and the socket was removed
        assert_eq!(a.socket_count(), 0);
        drop(peer);
        for task in tasks {
            task.abort();
        }
    }

    #[tokio::test]
    async fn packet_channel_closure_is_terminal() {
        let stack = NetStack::new(0);
        stack.set_addresses(&[ip(A4)]);
        let (incoming, received) = mpsc::channel(1);
        let (outgoing, _output) = mpsc::channel(1);
        drop(incoming);
        stack.run(received, outgoing).await;
        assert!(stack.check_available().is_err());
        assert!(stack.bind_udp(0).is_err());
        let stack = NetStack::new(0);
        stack.set_addresses(&[ip(A4)]);
        let (_input, received) = mpsc::channel(1);
        let (outgoing, output) = mpsc::channel(1);
        let worker = {
            let stack = stack.clone();
            tokio::spawn(async move { stack.run(received, outgoing).await })
        };
        tokio::task::yield_now().await;
        drop(output);
        tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .expect("closed output did not wake the runner")
            .unwrap();
        assert!(stack.check_available().is_err());
        assert!(stack.bind_udp(0).is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ipv6_minimum_mtu_and_abort_control_do_not_revive_old_flows() {
        let (a, b, tasks) = pair(None);
        let _echo = echo(&b, 7);
        let mut stream = a.connect(sa(B6, 7)).await.unwrap();
        a.set_mtu(1200);
        assert!(!a.addresses().iter().any(IpAddr::is_ipv6));
        assert!(a.connect(sa(B6, 7)).await.is_err());
        assert!(stream.read(&mut [0u8; 1]).await.is_err());
        drop(stream);
        // Force reaping and handle reuse, then invoke an old reset control.
        let first = a.connect(sa(B4, 7)).await.unwrap();
        let old_abort = first.abort_handle();
        drop(first);
        {
            let mut st = a.lock();
            let expired: Vec<_> = st.lingering.drain(..).map(|(handle, _)| handle).collect();
            for handle in expired {
                st.sockets.remove(handle);
                st.waiters.remove(&handle);
            }
        }
        let mut fresh = a.connect(sa(B4, 7)).await.unwrap();
        old_abort();
        fresh.write_all(b"fresh").await.unwrap();
        let mut data = [0u8; 5];
        tokio::time::timeout(Duration::from_secs(1), fresh.read_exact(&mut data)).await.unwrap().unwrap();
        assert_eq!(&data, b"fresh");
        for task in tasks {
            task.abort();
        }
        for task in _echo {
            task.abort();
        }
    }
}
