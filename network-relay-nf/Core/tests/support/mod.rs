//! Test-only native bridge emulator. Quinn and rustls are not production dependencies.
#![allow(dead_code)]
use network_relay_nf_core::native::*;
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener as HostListener, TcpStream as HostStream, UdpSocket as HostUdp},
    sync::{mpsc, watch},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
const WAIT: Duration = Duration::from_secs(35);
async fn within<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, future)
        .await
        .expect("test operation timed out")
}
fn tls_config(ca: &std::path::Path, alpn: &[&[u8]]) -> io::Result<rustls::ClientConfig> {
    use rustls_pki_types::{CertificateDer, pem::PemObject};
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(ca).map_err(io::Error::other)? {
        roots
            .add(cert.map_err(io::Error::other)?)
            .map_err(io::Error::other)?;
    }
    let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(io::Error::other)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    crypto.alpn_protocols = alpn.iter().map(|s| s.to_vec()).collect();
    Ok(crypto)
}
type Reader = Box<dyn AsyncRead + Send + Unpin>;
type Writer = Box<dyn AsyncWrite + Send + Unpin>;
struct Stream {
    read: tokio::sync::Mutex<Reader>,
    write: tokio::sync::Mutex<Writer>,
    stop: CancellationToken,
    parent: u64,
    /// A second handle on a host TCP socket, to reset it on an aborting
    /// CLOSE as Network.framework's forceCancel does.
    socket: Mutex<Option<std::net::TcpStream>>,
}
impl Stream {
    fn halves(read: Reader, write: Writer, parent: u64) -> Arc<Self> {
        Arc::new(Self {
            read: tokio::sync::Mutex::new(read),
            write: tokio::sync::Mutex::new(write),
            stop: CancellationToken::new(),
            parent,
            socket: Mutex::new(None),
        })
    }
    fn tcp(tcp: HostStream, parent: u64) -> Arc<Self> {
        tcp.set_nodelay(true).unwrap();
        let socket = tcp.into_std().unwrap();
        let handle = socket.try_clone().unwrap();
        let stream = Self::split(HostStream::from_std(socket).unwrap(), parent);
        *stream.socket.lock().unwrap() = Some(handle);
        stream
    }
    fn split<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(io: T, parent: u64) -> Arc<Self> {
        let (r, w) = tokio::io::split(io);
        Self::halves(Box::new(r), Box::new(w), parent)
    }
}
#[derive(Default)]
struct State {
    streams: HashMap<u64, Arc<Stream>>,
    groups: HashMap<u64, (quinn::Endpoint, quinn::Connection)>,
    stops: HashMap<u64, CancellationToken>,
    udp: HashMap<u64, Arc<HostUdp>>,
}
#[derive(serde::Deserialize)]
struct Options {
    host: String,
    port: u16,
    server_name: String,
    alpn: Vec<String>,
}
pub struct Backend {
    pub bridge: Arc<Bridge>,
    pub status: watch::Receiver<(u64, String)>,
    pub opened: Arc<Mutex<Vec<(u32, String)>>>,
    sent_datagrams: Arc<AtomicUsize>,
    /// Peer actions on the emulated group-owned bidirectional stream 0, with
    /// the time elapsed since that QUIC connection became ready.
    pub stream_zero: Arc<Mutex<Vec<(Duration, String)>>>,
    state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
}
impl Drop for Backend {
    fn drop(&mut self) {
        self.task.abort();
        self.bridge.stop.cancel();
        let s = self.state.lock().unwrap();
        for io in s.streams.values() {
            io.stop.cancel()
        }
        for stop in s.stops.values() {
            stop.cancel()
        }
        for (_, conn) in s.groups.values() {
            conn.close(0u32.into(), b"test finished")
        }
    }
}
impl Backend {
    pub fn start(ca: PathBuf) -> Self {
        Self::start_with(ca, false)
    }
    /// `idle_stream_zero` emulates the documented NWConnectionGroup property
    /// that the group object owns client bidirectional stream 0 and exposes
    /// no I/O on it: stream 0 is allocated before any request, never written
    /// and never finished, so the first production request uses stream 4.
    pub fn start_with(ca: PathBuf, idle_stream_zero: bool) -> Self {
        let stream_zero = Arc::new(Mutex::new(Vec::new()));
        let zero_events = stream_zero.clone();
        let limit: Option<usize> = Some(0);
        let (tx, mut events) = mpsc::channel::<Event>(512);
        let bridge = Bridge::new(tx);
        let (status_tx, status) = watch::channel((0, String::new()));
        let opened = Arc::new(Mutex::new(Vec::new()));
        let sent_datagrams = Arc::new(AtomicUsize::new(0));
        let state = Arc::new(Mutex::new(State::default()));
        let owner = bridge.clone();
        let native = state.clone();
        let records = opened.clone();
        let datagrams = sent_datagrams.clone();
        let task = tokio::spawn(async move {
            let mut workers = tokio::task::JoinSet::new();
            while let Some(event) = events.recv().await {
                match event.kind {
                    OPEN_TCP | OPEN_QUIC => {
                        let options: Options = serde_json::from_slice(&event.data).unwrap();
                        records
                            .lock()
                            .unwrap()
                            .push((event.kind, options.host.clone()));
                        assert_eq!(
                            options.host, "127.0.0.1",
                            "test backend must never resolve a target or contact a remote host"
                        );
                        let bridge = owner.clone();
                        let state = native.clone();
                        let ca = ca.clone();
                        let zero_events = zero_events.clone();
                        workers.spawn(async move {
                            let result: io::Result<()> = async {
                                let alpn = options
                                    .alpn
                                    .iter()
                                    .map(|s| s.as_bytes())
                                    .collect::<Vec<_>>();
                                let crypto = tls_config(&ca, &alpn)?;
                                let address =
                                    SocketAddr::new(options.host.parse().unwrap(), options.port);
                                if event.kind == OPEN_TCP {
                                    let tcp = HostStream::connect(address).await?;
                                    tcp.set_nodelay(true)?;
                                    let local = tcp.local_addr()?;
                                    let name =
                                        rustls_pki_types::ServerName::try_from(options.server_name)
                                            .map_err(io::Error::other)?;
                                    let stream = tokio_rustls::TlsConnector::from(Arc::new(crypto))
                                        .connect(name, tcp)
                                        .await?;
                                    let selected = String::from_utf8(
                                        stream.get_ref().1.alpn_protocol().unwrap().to_vec(),
                                    )
                                    .unwrap();
                                    state
                                        .lock()
                                        .unwrap()
                                        .streams
                                        .insert(event.id, Stream::split(stream, 0));
                                    bridge.input(
                                        READY,
                                        event.id,
                                        0,
                                        0,
                                        &serde_json::to_vec(&Ready {
                                            alpn: selected,
                                            local: local.to_string(),
                                            peer: address.to_string(),
                                            ..Ready::default()
                                        })
                                        .unwrap(),
                                    );
                                } else {
                                    let quic =
                                        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                                            .map_err(io::Error::other)?;
                                    let mut config = quinn::ClientConfig::new(Arc::new(quic));
                                    config.transport_config(Arc::new(
                                        quinn::TransportConfig::default(),
                                    ));
                                    let mut endpoint =
                                        quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?;
                                    endpoint.set_default_client_config(config);
                                    let connection = endpoint
                                        .connect(address, &options.server_name)
                                        .map_err(io::Error::other)?
                                        .await
                                        .map_err(io::Error::other)?;
                                    if idle_stream_zero {
                                        let ready = std::time::Instant::now();
                                        let (send, mut recv) =
                                            connection.open_bi().await.map_err(io::Error::other)?;
                                        assert_eq!(u64::from(send.id()), 0);
                                        let events = zero_events.clone();
                                        // Keep both halves alive: dropping them would
                                        // send FIN or STOP_SENDING, which the group
                                        // does not do.
                                        tokio::spawn(async move {
                                            let stopped = send.stopped().await;
                                            events.lock().unwrap().push((
                                                ready.elapsed(),
                                                format!("peer STOP_SENDING result: {stopped:?}"),
                                            ));
                                            std::future::pending::<()>().await;
                                            drop(send);
                                        });
                                        let events = zero_events.clone();
                                        tokio::spawn(async move {
                                            let received = recv.read_to_end(1024).await;
                                            events.lock().unwrap().push((
                                                ready.elapsed(),
                                                format!("peer stream end result: {received:?}"),
                                            ));
                                            std::future::pending::<()>().await;
                                            drop(recv);
                                        });
                                    }
                                    let maximum = connection.max_datagram_size().unwrap_or(0);
                                    let maximum = limit.map_or(maximum, |limit| maximum.min(limit));
                                    state
                                        .lock()
                                        .unwrap()
                                        .groups
                                        .insert(event.id, (endpoint, connection.clone()));
                                    bridge.input(
                                        READY,
                                        event.id,
                                        0,
                                        0,
                                        &serde_json::to_vec(&Ready {
                                            alpn: "h3".into(),
                                            max_datagram: maximum,
                                            ..Ready::default()
                                        })
                                        .unwrap(),
                                    );
                                    let (b, s, c) =
                                        (bridge.clone(), state.clone(), connection.clone());
                                    tokio::spawn(async move {
                                        while let Ok(read) = c.accept_uni().await {
                                            let sid: u64 = read.id().into();
                                            let mut state = s.lock().unwrap();
                                            let id = b.accept(
                                                event.id,
                                                sid,
                                                Ready {
                                                    stream_id: sid,
                                                    ..Ready::default()
                                                },
                                            );
                                            if id != 0 {
                                                state.streams.insert(
                                                    id,
                                                    Stream::halves(
                                                        Box::new(read),
                                                        Box::new(tokio::io::sink()),
                                                        event.id,
                                                    ),
                                                );
                                            }
                                        }
                                    });
                                    let b = bridge.clone();
                                    let c = connection.clone();
                                    tokio::spawn(async move {
                                        while let Ok(data) = c.read_datagram().await {
                                            b.input(IN_DATAGRAM, event.id, 0, 0, &data);
                                        }
                                    });
                                }
                                Ok(())
                            }
                            .await;
                            if let Err(error) = result {
                                bridge.input(
                                    ERROR,
                                    event.id,
                                    0,
                                    if error.kind() == io::ErrorKind::InvalidData {
                                        1
                                    } else {
                                        4
                                    },
                                    error.to_string().as_bytes(),
                                );
                            }
                        });
                    }
                    OPEN_STREAM => {
                        let connection = native
                            .lock()
                            .unwrap()
                            .groups
                            .get(&event.token)
                            .map(|(_, c)| c.clone());
                        let bridge = owner.clone();
                        let state = native.clone();
                        workers.spawn(async move {
                            let Some(connection) = connection else {
                                bridge.input(ERROR, event.id, 0, 4, b"group closed");
                                return;
                            };
                            let opened = if event.flags == 1 {
                                connection.open_uni().await.map(|send| {
                                    let sid: u64 = send.id().into();
                                    (
                                        sid,
                                        Stream::halves(
                                            Box::new(tokio::io::empty()),
                                            Box::new(send),
                                            event.token,
                                        ),
                                    )
                                })
                            } else {
                                connection.open_bi().await.map(|(send, recv)| {
                                    let sid: u64 = send.id().into();
                                    (
                                        sid,
                                        Stream::halves(Box::new(recv), Box::new(send), event.token),
                                    )
                                })
                            };
                            match opened {
                                Ok((sid, io)) => {
                                    state.lock().unwrap().streams.insert(event.id, io);
                                    bridge.input(
                                        READY,
                                        event.id,
                                        0,
                                        0,
                                        &serde_json::to_vec(&Ready {
                                            stream_id: sid,
                                            ..Ready::default()
                                        })
                                        .unwrap(),
                                    );
                                }
                                Err(e) => {
                                    bridge.input(ERROR, event.id, 0, 4, e.to_string().as_bytes());
                                }
                            }
                        });
                    }
                    READ | WRITE => {
                        let stream = native.lock().unwrap().streams.get(&event.id).cloned();
                        let bridge = owner.clone();
                        workers.spawn(async move {
                            let Some(stream)=stream else{bridge.input(ERROR,event.id,0,4,b"native test stream absent");return};
                            tokio::select! { _=stream.stop.cancelled()=>{}, result=async {
                                if event.kind==READ { let mut data=vec![0;event.flags.min(65536) as usize];let n=stream.read.lock().await.read(&mut data).await?;bridge.input(DATA,event.id,0,u64::from(n==0),&data[..n]); }
                                else { let mut writer=stream.write.lock().await;writer.write_all(&event.data).await?;if event.flags==1{writer.shutdown().await?;}bridge.input(ACK,event.id,event.token,0,b""); }
                                io::Result::Ok(())
                            } => { if let Err(error)=result{bridge.input(ERROR,event.id,0,4,error.to_string().as_bytes());} } }
                        });
                    }
                    DATAGRAM => {
                        datagrams.fetch_add(1, Ordering::Relaxed);
                        let conn = native
                            .lock()
                            .unwrap()
                            .groups
                            .get(&event.id)
                            .map(|(_, c)| c.clone());
                        if let Some(conn) = conn
                            && let Err(e) = conn.send_datagram(event.data)
                        {
                            owner.input(ERROR, event.id, 0, 4, e.to_string().as_bytes());
                        }
                    }
                    LISTEN => {
                        let listener =
                            HostListener::bind(std::str::from_utf8(&event.data).unwrap())
                                .await
                                .unwrap();
                        let local = listener.local_addr().unwrap();
                        let stop = CancellationToken::new();
                        native.lock().unwrap().stops.insert(event.id, stop.clone());
                        owner.input(
                            READY,
                            event.id,
                            0,
                            0,
                            &serde_json::to_vec(&Ready {
                                local: local.to_string(),
                                ..Ready::default()
                            })
                            .unwrap(),
                        );
                        let bridge = owner.clone();
                        let state = native.clone();
                        workers.spawn(async move {loop{tokio::select!{_=stop.cancelled()=>break,accepted=listener.accept()=>{let(tcp,peer)=accepted.unwrap();let mut state=state.lock().unwrap();let id=bridge.accept(event.id,0,Ready{local:local.to_string(),peer:peer.to_string(),..Ready::default()});if id!=0{state.streams.insert(id,Stream::tcp(tcp,event.id));}}}}});
                    }
                    OPEN_UDP => {
                        let udp = Arc::new(
                            HostUdp::bind(std::str::from_utf8(&event.data).unwrap())
                                .await
                                .unwrap(),
                        );
                        let local = udp.local_addr().unwrap();
                        let stop = CancellationToken::new();
                        {
                            let mut state = native.lock().unwrap();
                            state.udp.insert(event.id, udp.clone());
                            state.stops.insert(event.id, stop.clone());
                        }
                        owner.input(
                            READY,
                            event.id,
                            0,
                            0,
                            &serde_json::to_vec(&Ready {
                                local: local.to_string(),
                                ..Ready::default()
                            })
                            .unwrap(),
                        );
                        let bridge = owner.clone();
                        workers.spawn(async move {let mut buffer=vec![0;65536];loop{tokio::select!{_=stop.cancelled()=>break,r=udp.recv_from(&mut buffer)=>{if let Ok((n,peer))=r{bridge.input(IN_UDP,event.id,0,0,&pack_udp(peer,&buffer[..n]));}else{break}}}}});
                    }
                    SEND_UDP => {
                        let udp = native.lock().unwrap().udp.get(&event.id).cloned();
                        if let (Some(udp), Some((peer, data))) = (udp, unpack_udp(&event.data)) {
                            udp.send_to(&data, peer).await.unwrap();
                        }
                    }
                    CLOSE => {
                        let mut state = native.lock().unwrap();
                        if let Some(stream) = state.streams.remove(&event.id) {
                            if event.flags == ABORT
                                && let Some(socket) = stream.socket.lock().unwrap().take()
                                && let Ok(socket) = HostStream::from_std(socket)
                            {
                                socket.set_zero_linger().unwrap();
                            }
                            stream.stop.cancel();
                        }
                        let children = state
                            .streams
                            .iter()
                            .filter_map(|(id, s)| (s.parent == event.id).then_some(*id))
                            .collect::<Vec<_>>();
                        for id in children {
                            if let Some(s) = state.streams.remove(&id) {
                                s.stop.cancel();
                            }
                        }
                        if let Some((_, connection)) = state.groups.remove(&event.id) {
                            connection.close(quinn::VarInt::from_u64(event.flags).unwrap(), b"");
                        }
                        if let Some(stop) = state.stops.remove(&event.id) {
                            stop.cancel();
                        }
                        state.udp.remove(&event.id);
                    }
                    STATUS => {
                        status_tx.send_replace((
                            event.flags,
                            String::from_utf8_lossy(&event.data).into_owned(),
                        ));
                    }
                    _ => {}
                }
                while workers.try_join_next().is_some() {}
            }
        });
        Self {
            bridge,
            status,
            opened,
            sent_datagrams,
            stream_zero,
            state,
            task,
        }
    }
    pub fn datagrams_sent(&self) -> usize {
        self.sent_datagrams.load(Ordering::Relaxed)
    }
    pub async fn connected(&mut self) {
        within(async {
            loop {
                if self.status.borrow().0 == 1 {
                    break;
                }
                self.status.changed().await.unwrap();
            }
        })
        .await;
    }
}
