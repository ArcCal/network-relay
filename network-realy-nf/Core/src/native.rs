//! Bounded, socket-free transport boundary. Only Swift opens real connections.
use bytes::{Buf, Bytes};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, oneshot},
};
use tokio_util::sync::{CancellationToken, PollSender};

pub const OPEN_TCP: u32 = 1;
pub const OPEN_QUIC: u32 = 2;
pub const OPEN_STREAM: u32 = 3;
pub const WRITE: u32 = 4;
pub const READ: u32 = 5;
pub const DATAGRAM: u32 = 6;
pub const CLOSE: u32 = 7;
pub const LISTEN: u32 = 8;
pub const OPEN_UDP: u32 = 9;
pub const SEND_UDP: u32 = 10;
pub const LOG: u32 = 20;
pub const STATUS: u32 = 21;
pub const EXIT: u32 = 99;
pub const READY: u32 = 101;
pub const DATA: u32 = 102;
pub const ACK: u32 = 103;
pub const ERROR: u32 = 104;
pub const IN_DATAGRAM: u32 = 105;
pub const IN_UDP: u32 = 106;
pub const MAX_CHUNK: usize = 65536;

#[derive(Debug)]
pub struct Event {
    pub kind: u32,
    pub id: u64,
    pub token: u64,
    pub flags: u64,
    pub data: Bytes,
}
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Ready {
    #[serde(default)]
    pub alpn: String,
    #[serde(default)]
    pub local: String,
    #[serde(default)]
    pub peer: String,
    #[serde(default)]
    pub stream_id: u64,
    #[serde(default)]
    pub max_datagram: usize,
}
type SharedFailure = Arc<Mutex<Option<(u64, Vec<u8>)>>>;
type Accepted = (u64, u64, Ready);
type Opened = (
    Io,
    mpsc::Receiver<Accepted>,
    mpsc::Receiver<Bytes>,
    mpsc::Receiver<(Bytes, SocketAddr)>,
);
type PendingOpen = (
    Io,
    oneshot::Receiver<io::Result<Ready>>,
    mpsc::Receiver<Accepted>,
    mpsc::Receiver<Bytes>,
    mpsc::Receiver<(Bytes, SocketAddr)>,
);
pub struct Resource {
    pub ready: Option<oneshot::Sender<io::Result<Ready>>>,
    pub rx: mpsc::Sender<io::Result<Option<Bytes>>>,
    pub writes: HashMap<u64, oneshot::Sender<io::Result<()>>>,
    pub accepted: mpsc::Sender<(u64, u64, Ready)>,
    pub datagrams: mpsc::Sender<Bytes>,
    pub udp: mpsc::Sender<(Bytes, SocketAddr)>,
    pub parent: u64,
    failure: SharedFailure,
}
pub struct Bridge {
    pub events: mpsc::Sender<Event>,
    pub resources: Mutex<HashMap<u64, Resource>>,
    ids: AtomicU64,
    pub stop: CancellationToken,
    held: Mutex<HashMap<u64, Io>>,
}
impl Bridge {
    pub fn new(events: mpsc::Sender<Event>) -> Arc<Self> {
        Arc::new(Self {
            events,
            resources: Mutex::new(HashMap::new()),
            ids: AtomicU64::new(1),
            stop: CancellationToken::new(),
            held: Mutex::new(HashMap::new()),
        })
    }
    pub fn id(&self) -> u64 {
        self.ids.fetch_add(1, Ordering::Relaxed)
    }
    fn resource(self: &Arc<Self>, parent: u64) -> PendingOpen {
        let id = self.id();
        let (rt, rr) = oneshot::channel();
        let (tx, rx) = mpsc::channel(1);
        let (at, ar) = mpsc::channel(32);
        let (dt, dr) = mpsc::channel(128);
        let (ut, ur) = mpsc::channel(128);
        let failure = Arc::new(Mutex::new(None));
        self.resources.lock().unwrap().insert(
            id,
            Resource {
                ready: Some(rt),
                rx: tx,
                writes: HashMap::new(),
                accepted: at,
                datagrams: dt,
                udp: ut,
                parent,
                failure: failure.clone(),
            },
        );
        (
            Io {
                lease: Arc::new(Lease {
                    id,
                    bridge: Arc::downgrade(self),
                }),
                read: Arc::new(Mutex::new(ReadState {
                    rx,
                    bytes: Bytes::new(),
                    requested: false,
                    eof: false,
                })),
                sender: PollSender::new(self.events.clone()),
                pending: None,
                shutdown: false,
                ready: Ready::default(),
                failure,
            },
            rr,
            ar,
            dr,
            ur,
        )
    }
    pub async fn emit(
        &self,
        kind: u32,
        id: u64,
        token: u64,
        flags: u64,
        data: impl Into<Bytes>,
    ) -> io::Result<()> {
        tokio::select! {_ = self.stop.cancelled()=>Err(io::ErrorKind::Interrupted.into()), r=self.events.send(Event{kind,id,token,flags,data:data.into()})=>r.map_err(|_|io::ErrorKind::BrokenPipe.into())}
    }
    pub fn control(&self, kind: u32, id: u64, flags: u64) {
        // A protocol reset/close must also wake pending Rust operations;
        // native cancellation callbacks are intentionally suppressed on close.
        if kind == CLOSE && self.fail_with_code(id, 4, b"native resource closed by protocol", flags)
        {
            return;
        }
        self.send_control(kind, id, flags);
    }
    fn send_control(&self, kind: u32, id: u64, flags: u64) {
        let event = Event {
            kind,
            id,
            token: 0,
            flags,
            data: Bytes::new(),
        };
        if let Err(mpsc::error::TrySendError::Full(event)) = self.events.try_send(event) {
            let tx = self.events.clone();
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(async move {
                    let _ = tx.send(event).await;
                });
            }
        }
    }
    pub async fn open(
        self: &Arc<Self>,
        kind: u32,
        parent: u64,
        flags: u64,
        data: Vec<u8>,
    ) -> io::Result<Opened> {
        if parent != 0 && !self.resources.lock().unwrap().contains_key(&parent) {
            return Err(io::ErrorKind::NotConnected.into());
        }
        let (mut io, rr, ar, dr, ur) = self.resource(parent);
        self.emit(kind, io.id(), parent, flags, data).await?;
        io.ready = tokio::time::timeout(std::time::Duration::from_secs(10), rr)
            .await
            .map_err(|_| io::ErrorKind::TimedOut)?
            .map_err(|_| io::ErrorKind::BrokenPipe)??;
        Ok((io, ar, dr, ur))
    }
    pub async fn tcp(self: &Arc<Self>, data: Vec<u8>) -> io::Result<Io> {
        Ok(self.open(OPEN_TCP, 0, 0, data).await?.0)
    }
    pub async fn listen(self: &Arc<Self>, address: SocketAddr) -> io::Result<TcpListener> {
        let (io, accepted, _, _) = self
            .open(LISTEN, 0, 0, address.to_string().into_bytes())
            .await?;
        Ok(TcpListener {
            _io: io,
            accepted: tokio::sync::Mutex::new(accepted),
            bridge: self.clone(),
        })
    }
    pub async fn udp(self: &Arc<Self>, address: SocketAddr) -> io::Result<UdpSocket> {
        let (io, _, _, rx) = self
            .open(OPEN_UDP, 0, 0, address.to_string().into_bytes())
            .await?;
        Ok(UdpSocket {
            io,
            rx: tokio::sync::Mutex::new(rx),
            bridge: self.clone(),
        })
    }
    pub fn input(&self, kind: u32, id: u64, token: u64, flags: u64, data: &[u8]) -> bool {
        if kind == ERROR {
            return self.fail(id, flags, data);
        }
        let mut map = self.resources.lock().unwrap();
        let Some(r) = map.get_mut(&id) else {
            return false;
        };
        match kind {
            READY => {
                let parsed = serde_json::from_slice::<Ready>(data)
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid native ready metadata")
                    })
                    .and_then(|r| {
                        if r.stream_id < (1 << 62) {
                            Ok(r)
                        } else {
                            Err(io::ErrorKind::InvalidData.into())
                        }
                    });
                r.ready.take().is_some_and(|tx| tx.send(parsed).is_ok())
            }
            DATA if flags == 1 || !data.is_empty() => {
                r.rx.try_send(Ok(if flags == 1 {
                    None
                } else {
                    Some(Bytes::copy_from_slice(data))
                }))
                .is_ok()
            }
            ACK => r.writes.remove(&token).is_some_and(|tx| {
                tx.send(if flags == 0 {
                    Ok(())
                } else {
                    Err(native_error(flags, data))
                })
                .is_ok()
            }),
            IN_DATAGRAM => r.datagrams.try_send(Bytes::copy_from_slice(data)).is_ok(),
            IN_UDP => {
                let Some((addr, body)) = unpack_udp(data) else {
                    return false;
                };
                r.udp.try_send((body, addr)).is_ok()
            }
            _ => false,
        }
    }
    pub fn accept(self: &Arc<Self>, parent: u64, stream_id: u64, mut ready: Ready) -> u64 {
        if stream_id >= (1 << 62) {
            return 0;
        }
        ready.stream_id = stream_id;
        let (io, _, _, _, _) = self.resource(parent);
        let id = io.id();
        self.held.lock().unwrap().insert(id, io);
        let map = self.resources.lock().unwrap();
        if let Some(r) = map.get(&parent)
            && r.accepted.try_send((id, stream_id, ready)).is_ok()
        {
            return id;
        }
        drop(map);
        self.release(id);
        0
    }
    pub fn accepted_io(self: &Arc<Self>, id: u64, ready: Ready) -> io::Result<Io> {
        let mut io = self
            .held
            .lock()
            .unwrap()
            .remove(&id)
            .ok_or(io::ErrorKind::NotConnected)?;
        io.ready = ready;
        Ok(io)
    }
    pub fn release(&self, id: u64) {
        let children = {
            let mut map = self.resources.lock().unwrap();
            if map.remove(&id).is_none() {
                return;
            }
            map.iter()
                .filter_map(|(child, r)| (r.parent == id).then_some(*child))
                .collect::<Vec<_>>()
        };
        let held = self.held.lock().unwrap().remove(&id);
        drop(held);
        for child in children {
            self.release(child)
        }
        self.control(CLOSE, id, 0);
    }
    /// Closing all channels wakes every pending operation, including group accept.
    pub fn fail(&self, id: u64, flags: u64, data: &[u8]) -> bool {
        self.fail_with_code(id, flags, data, 0)
    }
    fn fail_with_code(&self, id: u64, flags: u64, data: &[u8], code: u64) -> bool {
        let (mut resource, children) = {
            let mut map = self.resources.lock().unwrap();
            let Some(r) = map.remove(&id) else {
                return false;
            };
            let children = map
                .iter()
                .filter_map(|(child, r)| (r.parent == id).then_some(*child))
                .collect::<Vec<_>>();
            (r, children)
        };
        *resource.failure.lock().unwrap() = Some((flags, data.to_vec()));
        if let Some(tx) = resource.ready.take() {
            let _ = tx.send(Err(native_error(flags, data)));
        }
        for (_, tx) in resource.writes.drain() {
            let _ = tx.send(Err(native_error(flags, data)));
        }
        drop(resource);
        drop(self.held.lock().unwrap().remove(&id));
        for child in children {
            self.fail_with_code(child, flags, data, code);
        }
        self.send_control(CLOSE, id, code);
        true
    }
}
fn native_error(flags: u64, data: &[u8]) -> io::Error {
    let kind = match flags {
        1 => io::ErrorKind::PermissionDenied,
        2 => io::ErrorKind::AddrInUse,
        3 => io::ErrorKind::TimedOut,
        _ => io::ErrorKind::ConnectionAborted,
    };
    io::Error::new(kind, String::from_utf8_lossy(data).into_owned())
}
pub struct Lease {
    pub id: u64,
    bridge: Weak<Bridge>,
}
impl Lease {
    pub fn bridge(&self) -> Option<Arc<Bridge>> {
        self.bridge.upgrade()
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(b) = self.bridge.upgrade() {
            b.release(self.id)
        }
    }
}
struct ReadState {
    rx: mpsc::Receiver<io::Result<Option<Bytes>>>,
    bytes: Bytes,
    requested: bool,
    eof: bool,
}
pub struct Io {
    pub lease: Arc<Lease>,
    read: Arc<Mutex<ReadState>>,
    sender: PollSender<Event>,
    pending: Option<(usize, oneshot::Receiver<io::Result<()>>)>,
    shutdown: bool,
    pub ready: Ready,
    failure: SharedFailure,
}
impl Io {
    pub fn id(&self) -> u64 {
        self.lease.id
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.ready
            .local
            .parse()
            .map_err(|_| io::ErrorKind::AddrNotAvailable.into())
    }
    pub fn set_nodelay(&self, _: bool) -> io::Result<()> {
        Ok(())
    }
    pub fn read_half(&self) -> Self {
        Self {
            lease: self.lease.clone(),
            read: self.read.clone(),
            sender: self.sender.clone(),
            pending: None,
            shutdown: false,
            ready: self.ready.clone(),
            failure: self.failure.clone(),
        }
    }
    fn bridge(&self) -> io::Result<Arc<Bridge>> {
        self.lease
            .bridge
            .upgrade()
            .ok_or_else(|| io::ErrorKind::BrokenPipe.into())
    }
    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
        fin: bool,
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() && !fin && self.pending.is_none() {
            return Poll::Ready(Ok(0));
        }
        if let Some((flags, data)) = &*self.failure.lock().unwrap() {
            return Poll::Ready(Err(native_error(*flags, data)));
        }
        if let Some((n, rx)) = &mut self.pending {
            let n = *n;
            let result = std::task::ready!(Pin::new(rx).poll(cx))
                .map_err(|_| io::ErrorKind::BrokenPipe.into())
                .and_then(|r| r);
            self.pending = None;
            return Poll::Ready(result.map(|_| n));
        }
        let n = buf.len().min(MAX_CHUNK);
        std::task::ready!(self.sender.poll_reserve(cx)).map_err(|_| io::ErrorKind::BrokenPipe)?;
        let bridge = self.bridge()?;
        let token = bridge.id();
        let (tx, rx) = oneshot::channel();
        {
            let mut resources = bridge.resources.lock().unwrap();
            let Some(resource) = resources.get_mut(&self.id()) else {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            };
            resource.writes.insert(token, tx);
        }
        self.sender
            .send_item(Event {
                kind: WRITE,
                id: self.id(),
                token,
                flags: u64::from(fin),
                data: Bytes::copy_from_slice(&buf[..n]),
            })
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        if fin {
            self.shutdown = true;
        }
        self.pending = Some((n, rx));
        self.poll_send(cx, buf, fin)
    }
}
impl AsyncRead for Io {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some((1, data)) = &*self.failure.lock().unwrap() {
            // A security rejection must never release purported payload.
            return Poll::Ready(Err(native_error(1, data)));
        }
        let mut r = self.read.lock().unwrap();
        if !r.bytes.is_empty() {
            let n = r.bytes.len().min(buf.remaining());
            buf.put_slice(&r.bytes[..n]);
            r.bytes.advance(n);
            return Poll::Ready(Ok(()));
        }
        if !r.eof {
            match r.rx.poll_recv(cx) {
                Poll::Ready(Some(Ok(Some(bytes)))) => {
                    r.requested = false;
                    r.bytes = bytes;
                    drop(r);
                    return self.poll_read(cx, buf);
                }
                Poll::Ready(Some(Ok(None))) | Poll::Ready(None) => r.eof = true,
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
        }
        // Drain received bytes before reporting a transport error. Failure
        // closes the sender too, so channel closure alone is not clean EOF.
        if let Some((flags, data)) = &*self.failure.lock().unwrap() {
            return Poll::Ready(Err(native_error(*flags, data)));
        }
        if r.eof {
            return Poll::Ready(Ok(()));
        }
        if !r.requested {
            drop(r);
            std::task::ready!(self.sender.poll_reserve(cx))
                .map_err(|_| io::ErrorKind::BrokenPipe)?;
            if let Some((flags, data)) = &*self.failure.lock().unwrap() {
                return Poll::Ready(Err(native_error(*flags, data)));
            }
            let id = self.id();
            self.sender
                .send_item(Event {
                    kind: READ,
                    id,
                    token: 0,
                    flags: MAX_CHUNK as u64,
                    data: Bytes::new(),
                })
                .map_err(|_| io::ErrorKind::BrokenPipe)?;
            self.read.lock().unwrap().requested = true;
        }
        Poll::Pending
    }
}
impl AsyncWrite for Io {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.shutdown {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        self.poll_send(cx, buf, false)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending.is_some() {
            self.poll_send(cx, &[], false).map(|r| r.map(|_| ()))
        } else {
            Poll::Ready(Ok(()))
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.shutdown {
            return self.as_mut().poll_flush(cx);
        }
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        std::task::ready!(self.poll_send(cx, &[], true))?;
        Poll::Ready(Ok(()))
    }
}
pub type TcpStream = Io;
pub struct TcpListener {
    _io: Io,
    accepted: tokio::sync::Mutex<mpsc::Receiver<(u64, u64, Ready)>>,
    bridge: Arc<Bridge>,
}
impl TcpListener {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self._io.local_addr()
    }
    pub async fn accept(&self) -> io::Result<(Io, SocketAddr)> {
        let (id, _, ready) = self
            .accepted
            .lock()
            .await
            .recv()
            .await
            .ok_or(io::ErrorKind::BrokenPipe)?;
        let peer = ready
            .peer
            .parse()
            .map_err(|_| io::ErrorKind::AddrNotAvailable)?;
        Ok((self.bridge.accepted_io(id, ready)?, peer))
    }
}
pub struct UdpSocket {
    io: Io,
    rx: tokio::sync::Mutex<mpsc::Receiver<(Bytes, SocketAddr)>>,
    bridge: Arc<Bridge>,
}
impl UdpSocket {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (bytes, addr) = self
            .rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(io::ErrorKind::BrokenPipe)?;
        if bytes.len() > buf.len() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        buf[..bytes.len()].copy_from_slice(&bytes);
        Ok((bytes.len(), addr))
    }
    pub async fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.bridge
            .emit(SEND_UDP, self.io.id(), 0, 0, pack_udp(addr, data))
            .await?;
        Ok(data.len())
    }
}
pub fn pack_udp(addr: SocketAddr, data: &[u8]) -> Bytes {
    let a = addr.to_string();
    let mut out = Vec::with_capacity(2 + a.len() + data.len());
    out.extend_from_slice(&(a.len() as u16).to_be_bytes());
    out.extend_from_slice(a.as_bytes());
    out.extend_from_slice(data);
    out.into()
}
pub fn unpack_udp(data: &[u8]) -> Option<(SocketAddr, Bytes)> {
    let n = u16::from_be_bytes(data.get(..2)?.try_into().ok()?) as usize;
    let addr = std::str::from_utf8(data.get(2..2 + n)?)
        .ok()?
        .parse()
        .ok()?;
    Some((addr, Bytes::copy_from_slice(data.get(2 + n..)?)))
}

use std::future::Future;
pub type OpenFuture = Pin<Box<dyn Future<Output = io::Result<Io>> + Send>>;
pub struct Quic {
    pub bridge: Arc<Bridge>,
    pub io: Io,
    pub accepted: mpsc::Receiver<(u64, u64, Ready)>,
    pub datagrams: mpsc::Receiver<Bytes>,
    pub max_datagram: Arc<AtomicUsize>,
}
impl Quic {
    pub async fn open(bridge: Arc<Bridge>, data: Vec<u8>) -> io::Result<Self> {
        let (io, accepted, datagrams, _) = bridge.open(OPEN_QUIC, 0, 0, data).await?;
        if io.ready.alpn != "h3" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native QUIC did not negotiate h3",
            ));
        }
        let max = io.ready.max_datagram;
        Ok(Self {
            bridge,
            io,
            accepted,
            datagrams,
            max_datagram: Arc::new(AtomicUsize::new(max)),
        })
    }
}
