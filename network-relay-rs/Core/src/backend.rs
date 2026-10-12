//! Production Rust networking: Tokio TCP/UDP, rustls TLS and Quinn QUIC.
//! No networking operation is delegated to an Apple networking framework.
use crate::native::*;
use anyhow::{Context, Result, ensure};
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, watch},
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
pub struct BackendOptions {
    /// Add a PEM certificate authority to the operating system's trusted roots.
    /// Certificate identity validation is always enabled.
    pub ca_file: Option<PathBuf>,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub resources: usize,
}
#[derive(Default)]
struct Counters {
    read: AtomicU64,
    written: AtomicU64,
}
type Reader = Box<dyn AsyncRead + Send + Unpin>;
type Writer = Box<dyn AsyncWrite + Send + Unpin>;
enum ReadHalf {
    Socket(Reader),
    Quic(quinn::RecvStream),
    Empty,
}
enum WriteHalf {
    Socket(Writer),
    Quic(quinn::SendStream),
    Empty,
}
impl ReadHalf {
    async fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Socket(read) => read.read(data).await,
            Self::Quic(read) => AsyncReadExt::read(read, data).await,
            Self::Empty => Ok(0),
        }
    }
}
impl WriteHalf {
    async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            Self::Socket(write) => write.write_all(data).await,
            Self::Quic(write) => AsyncWriteExt::write_all(write, data).await,
            Self::Empty if data.is_empty() => Ok(()),
            Self::Empty => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }
    async fn shutdown(&mut self) -> io::Result<()> {
        match self {
            Self::Socket(write) => write.shutdown().await,
            Self::Quic(write) => AsyncWriteExt::shutdown(write).await,
            Self::Empty => Ok(()),
        }
    }
}
struct Stream {
    read: tokio::sync::Mutex<ReadHalf>,
    write: tokio::sync::Mutex<WriteHalf>,
    stop: CancellationToken,
}
impl Stream {
    fn new(read: ReadHalf, write: WriteHalf, stop: CancellationToken) -> Arc<Self> {
        Arc::new(Self {
            read: tokio::sync::Mutex::new(read),
            write: tokio::sync::Mutex::new(write),
            stop,
        })
    }
    fn socket<T: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
        io: T,
        stop: CancellationToken,
    ) -> Arc<Self> {
        let (read, write) = tokio::io::split(io);
        Self::new(
            ReadHalf::Socket(Box::new(read)),
            WriteHalf::Socket(Box::new(write)),
            stop,
        )
    }
    async fn reset(&self, code: u64) {
        // Cancel blocked reads/writes first so their guards are released.
        self.stop.cancel();
        let code = quinn::VarInt::from_u64(code).unwrap_or(quinn::VarInt::from_u32(0x102));
        if let ReadHalf::Quic(read) = &mut *self.read.lock().await {
            let _ = read.stop(code);
        }
        if let WriteHalf::Quic(write) = &mut *self.write.lock().await {
            let _ = write.reset(code);
        }
    }
}
struct Group {
    // The endpoint must remain alive for the connection's entire lifetime.
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
}
enum Kind {
    Pending,
    Stream(Arc<Stream>),
    Group(Arc<Group>),
    Listener,
    Udp(Arc<UdpSocket>),
}
struct Resource {
    parent: u64,
    stop: CancellationToken,
    kind: Kind,
}
#[derive(Default)]
struct State {
    resources: HashMap<u64, Resource>,
}
fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
impl State {
    fn replace(&mut self, id: u64, kind: Kind) -> bool {
        if let Some(resource) = self.resources.get_mut(&id)
            && !resource.stop.is_cancelled()
        {
            resource.kind = kind;
            return true;
        }
        false
    }
    fn remove_tree(&mut self, id: u64) -> Vec<Resource> {
        let mut pending = vec![id];
        let mut removed = Vec::new();
        while let Some(id) = pending.pop() {
            pending.extend(
                self.resources
                    .iter()
                    .filter_map(|(child, resource)| (resource.parent == id).then_some(*child)),
            );
            if let Some(resource) = self.resources.remove(&id) {
                resource.stop.cancel();
                removed.push(resource);
            }
        }
        removed
    }
}
#[derive(serde::Deserialize)]
struct Options {
    host: String,
    port: u16,
    server_name: String,
    alpn: Vec<String>,
}
fn error_flag(error: &io::Error) -> u64 {
    match error.kind() {
        io::ErrorKind::PermissionDenied
        | io::ErrorKind::InvalidData
        | io::ErrorKind::InvalidInput => 1,
        io::ErrorKind::AddrInUse => 2,
        io::ErrorKind::TimedOut => 3,
        _ => 4,
    }
}
fn quic_error(error: quinn::ConnectionError) -> io::Error {
    if let quinn::ConnectionError::TransportError(transport) = &error
        && (0x100..0x200).contains(&u64::from(transport.code))
    {
        return io::Error::new(io::ErrorKind::PermissionDenied, error);
    }
    io::Error::from(error)
}
fn report(bridge: &Bridge, id: u64, error: io::Error) {
    tracing::debug!(resource=id, error=%error, "Rust transport operation failed");
    bridge.input(
        ERROR,
        id,
        0,
        error_flag(&error),
        error.to_string().as_bytes(),
    );
}
fn metadata(bridge: &Bridge, id: u64, ready: Ready) {
    match serde_json::to_vec(&ready) {
        Ok(data) => {
            bridge.input(READY, id, 0, 0, &data);
        }
        Err(error) => report(bridge, id, io::Error::other(error)),
    }
}
fn roots(options: &BackendOptions) -> Result<rustls::RootCertStore> {
    use rustls_pki_types::{CertificateDer, pem::PemObject};
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for certificate in native.certs {
        let _ = roots.add(certificate);
    }
    if let Some(path) = &options.ca_file {
        let mut added = 0;
        for certificate in CertificateDer::pem_file_iter(path)
            .with_context(|| format!("reading CA file {}", path.display()))?
        {
            roots
                .add(certificate.context("decoding CA certificate")?)
                .context("invalid CA certificate")?;
            added += 1;
        }
        ensure!(added != 0, "configured CA file contains no certificates");
    }
    ensure!(
        !roots.is_empty(),
        "no trusted root certificates are available"
    );
    Ok(roots)
}
fn tls_config(roots: &rustls::RootCertStore, alpn: &[String]) -> io::Result<rustls::ClientConfig> {
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(io::Error::other)?
    .with_root_certificates(roots.clone())
    .with_no_client_auth();
    config.alpn_protocols = alpn
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    Ok(config)
}
fn selected_alpn(selected: Option<&[u8]>, options: &Options) -> io::Result<String> {
    let selected = selected
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .filter(|protocol| options.alpn.iter().any(|offered| offered == protocol))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "server did not negotiate the requested ALPN",
            )
        })?;
    Ok(selected.to_owned())
}
async fn connect_tcp(options: &Options) -> io::Result<TcpStream> {
    let addresses: Vec<_> = tokio::net::lookup_host((options.host.as_str(), options.port))
        .await?
        .take(16)
        .collect();
    if addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "relay hostname resolved to no addresses",
        ));
    }
    // Staggered attempts prevent an unreachable IPv6 route from masking a
    // working IPv4 address. All losing attempts are owned and cancelled.
    let mut attempts = JoinSet::new();
    for (index, address) in addresses.into_iter().enumerate() {
        attempts.spawn(async move {
            tokio::time::sleep(Duration::from_millis(index as u64 * 200)).await;
            TcpStream::connect(address).await
        });
    }
    let mut last = io::Error::new(io::ErrorKind::ConnectionRefused, "relay connection failed");
    while let Some(attempt) = attempts.join_next().await {
        match attempt {
            Ok(Ok(stream)) => {
                attempts.shutdown().await;
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Ok(Err(error)) => last = error,
            Err(error) => last = io::Error::other(error),
        }
    }
    Err(last)
}
async fn open_tcp(
    options: &Options,
    roots: &rustls::RootCertStore,
) -> io::Result<(tokio_rustls::client::TlsStream<TcpStream>, Ready)> {
    let config = tls_config(roots, &options.alpn)?;
    let server_name = rustls_pki_types::ServerName::try_from(options.server_name.clone())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let tcp = connect_tcp(options).await?;
    let local = tcp.local_addr()?;
    let peer = tcp.peer_addr()?;
    let stream = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(server_name, tcp)
        .await?;
    let alpn = selected_alpn(stream.get_ref().1.alpn_protocol(), options)?;
    Ok((
        stream,
        Ready {
            alpn,
            local: local.to_string(),
            peer: peer.to_string(),
            ..Ready::default()
        },
    ))
}
async fn open_quic(
    options: &Options,
    roots: &rustls::RootCertStore,
) -> io::Result<(Arc<Group>, Ready)> {
    let crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config(roots, &options.alpn)?)
            .map_err(io::Error::other)?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_secs(120)
            .try_into()
            .map_err(io::Error::other)?,
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(20)));
    // This client negotiates reliable HTTP DATAGRAM Capsules. QUIC DATAGRAM
    // transport support is intentionally disabled instead of overstated.
    transport.datagram_receive_buffer_size(None);
    config.transport_config(Arc::new(transport));
    let mut addresses: Vec<_> = tokio::net::lookup_host((options.host.as_str(), options.port))
        .await?
        .take(16)
        .collect();
    addresses.sort_by_key(|address| !address.is_ipv4());
    let mut last = io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "relay hostname resolved to no usable addresses",
    );
    for address in addresses {
        let bind: SocketAddr = if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()
        .map_err(io::Error::other)?;
        let mut endpoint = quinn::Endpoint::client(bind)?;
        endpoint.set_default_client_config(config.clone());
        let connecting = endpoint
            .connect(address, &options.server_name)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let connection = match tokio::time::timeout(Duration::from_secs(3), connecting).await {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => {
                last = quic_error(error);
                if last.kind() == io::ErrorKind::PermissionDenied {
                    return Err(last);
                }
                continue;
            }
            Err(_) => {
                last = io::ErrorKind::TimedOut.into();
                continue;
            }
        };
        let data = connection.handshake_data().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "QUIC TLS metadata is absent")
        })?;
        let data = data
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "unexpected QUIC TLS metadata")
            })?;
        let alpn = selected_alpn(data.protocol.as_deref(), options)?;
        let ready = Ready {
            alpn,
            local: endpoint.local_addr()?.to_string(),
            peer: connection.remote_address().to_string(),
            max_datagram: 0,
            ..Ready::default()
        };
        return Ok((
            Arc::new(Group {
                _endpoint: endpoint,
                connection,
            }),
            ready,
        ));
    }
    Err(last)
}

pub struct Backend {
    pub bridge: Arc<Bridge>,
    pub status: watch::Receiver<(u64, String)>,
    state: Arc<Mutex<State>>,
    counters: Arc<Counters>,
    task: Option<JoinHandle<()>>,
}
impl Backend {
    /// Start on an existing Tokio runtime. Trust is initialized before any
    /// listener or connection is opened.
    pub fn start(options: BackendOptions) -> Result<Self> {
        let runtime = tokio::runtime::Handle::try_current()
            .context("Rust transport requires a Tokio runtime")?;
        let roots = Arc::new(roots(&options)?);
        let (events_tx, events_rx) = mpsc::channel(512);
        let bridge = Bridge::new(events_tx);
        let (status_tx, status) = watch::channel((0, String::new()));
        let state = Arc::new(Mutex::new(State::default()));
        let counters = Arc::new(Counters::default());
        let task = runtime.spawn(run(
            bridge.clone(),
            state.clone(),
            counters.clone(),
            roots,
            events_rx,
            status_tx,
        ));
        Ok(Self {
            bridge,
            status,
            state,
            counters,
            task: Some(task),
        })
    }
    pub fn resource_count(&self) -> usize {
        locked(&self.state).resources.len()
    }
    pub fn datagrams_sent(&self) -> usize {
        0
    }
    pub fn stats(&self) -> Stats {
        Stats {
            bytes_read: self.counters.read.load(Ordering::Relaxed),
            bytes_written: self.counters.written.load(Ordering::Relaxed),
            resources: self.resource_count(),
        }
    }
    pub async fn shutdown(&mut self) {
        self.bridge.stop.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}
impl Drop for Backend {
    fn drop(&mut self) {
        self.bridge.stop.cancel();
        for resource in locked(&self.state).resources.values() {
            resource.stop.cancel();
        }
        // The runner owns its JoinSet; aborting it also aborts all I/O tasks.
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn run(
    bridge: Arc<Bridge>,
    state: Arc<Mutex<State>>,
    counters: Arc<Counters>,
    roots: Arc<rustls::RootCertStore>,
    mut events: mpsc::Receiver<Event>,
    status: watch::Sender<(u64, String)>,
) {
    let mut workers = JoinSet::new();
    loop {
        let event = tokio::select! {
            _ = bridge.stop.cancelled() => break,
            Some(result) = workers.join_next(), if !workers.is_empty() => {
                if let Err(error) = result { tracing::error!(%error, "Rust transport task failed"); }
                continue;
            }
            event = events.recv() => { let Some(event) = event else { break }; event }
        };
        tracing::trace!(
            kind = event.kind,
            resource = event.id,
            bytes = event.data.len(),
            "Rust I/O request"
        );
        match event.kind {
            OPEN_TCP | OPEN_QUIC | LISTEN | OPEN_UDP => {
                let stop = bridge.stop.child_token();
                locked(&state).resources.insert(
                    event.id,
                    Resource {
                        parent: 0,
                        stop: stop.clone(),
                        kind: Kind::Pending,
                    },
                );
                let (bridge, state, roots) = (bridge.clone(), state.clone(), roots.clone());
                workers.spawn(async move {
                    let operation = open_resource(&event, &bridge, &state, &roots, stop.clone());
                    let result =
                        tokio::select! { _=stop.cancelled()=>return, result=operation=>result };
                    if let Err(error) = result {
                        report(&bridge, event.id, error);
                    }
                });
            }
            OPEN_STREAM => {
                let group = {
                    let state = locked(&state);
                    state
                        .resources
                        .get(&event.token)
                        .and_then(|resource| match &resource.kind {
                            Kind::Group(group) => {
                                Some((group.clone(), resource.stop.child_token()))
                            }
                            _ => None,
                        })
                };
                let Some((group, stop)) = group else {
                    report(&bridge, event.id, io::ErrorKind::NotConnected.into());
                    continue;
                };
                locked(&state).resources.insert(
                    event.id,
                    Resource {
                        parent: event.token,
                        stop: stop.clone(),
                        kind: Kind::Pending,
                    },
                );
                let (bridge, state) = (bridge.clone(), state.clone());
                workers.spawn(async move {
                    let operation = async {
                        let (sid, stream) = if event.flags == 1 {
                            let write =
                                group.connection.open_uni().await.map_err(io::Error::from)?;
                            let sid = write.id().into();
                            (
                                sid,
                                Stream::new(ReadHalf::Empty, WriteHalf::Quic(write), stop.clone()),
                            )
                        } else {
                            let (write, read) =
                                group.connection.open_bi().await.map_err(io::Error::from)?;
                            let sid = write.id().into();
                            (
                                sid,
                                Stream::new(
                                    ReadHalf::Quic(read),
                                    WriteHalf::Quic(write),
                                    stop.clone(),
                                ),
                            )
                        };
                        if locked(&state).replace(event.id, Kind::Stream(stream)) {
                            metadata(
                                &bridge,
                                event.id,
                                Ready {
                                    stream_id: sid,
                                    ..Ready::default()
                                },
                            );
                            tracing::debug!(resource = event.id, sid, "Rust QUIC stream ready");
                        }
                        io::Result::Ok(())
                    };
                    let result =
                        tokio::select! { _=stop.cancelled()=>return, result=operation=>result };
                    if let Err(error) = result {
                        report(&bridge, event.id, error);
                    }
                });
            }
            READ | WRITE => {
                let stream = locked(&state)
                    .resources
                    .get(&event.id)
                    .and_then(|resource| match &resource.kind {
                        Kind::Stream(stream) => Some(stream.clone()),
                        _ => None,
                    });
                let Some(stream) = stream else {
                    report(&bridge, event.id, io::ErrorKind::NotConnected.into());
                    continue;
                };
                let (bridge, counters) = (bridge.clone(), counters.clone());
                workers.spawn(async move {
                    let operation = async {
                        if event.kind == READ {
                            let mut data = vec![0; event.flags.clamp(1, MAX_CHUNK as u64) as usize];
                            let count = stream.read.lock().await.read(&mut data).await?;
                            tracing::trace!(
                                resource = event.id,
                                bytes = count,
                                final_data = count == 0,
                                "Rust stream received"
                            );
                            counters.read.fetch_add(count as u64, Ordering::Relaxed);
                            bridge.input(DATA, event.id, 0, u64::from(count == 0), &data[..count]);
                        } else {
                            let mut write = stream.write.lock().await;
                            write.write_all(&event.data).await?;
                            if event.flags == 1 {
                                write.shutdown().await?;
                            }
                            counters
                                .written
                                .fetch_add(event.data.len() as u64, Ordering::Relaxed);
                            bridge.input(ACK, event.id, event.token, 0, b"");
                        }
                        io::Result::Ok(())
                    };
                    let result =
                        tokio::select! {_=stream.stop.cancelled()=>return,result=operation=>result};
                    if let Err(error) = result {
                        report(&bridge, event.id, error);
                    }
                });
            }
            SEND_UDP => {
                let udp = locked(&state)
                    .resources
                    .get(&event.id)
                    .and_then(|resource| match &resource.kind {
                        Kind::Udp(udp) => Some((udp.clone(), resource.stop.clone())),
                        _ => None,
                    });
                let Some((udp, stop)) = udp else { continue };
                let Some((peer, data)) = unpack_udp(&event.data) else {
                    report(
                        &bridge,
                        event.id,
                        io::Error::new(io::ErrorKind::InvalidData, "invalid UDP destination"),
                    );
                    continue;
                };
                let bridge = bridge.clone();
                workers.spawn(async move{let result=tokio::select!{_=stop.cancelled()=>return,result=udp.send_to(&data,peer)=>result};if let Err(error)=result{report(&bridge,event.id,error);}});
            }
            DATAGRAM => report(
                &bridge,
                event.id,
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "native QUIC DATAGRAM is disabled; use negotiated Capsules",
                ),
            ),
            CLOSE => {
                let removed = locked(&state).remove_tree(event.id);
                for resource in removed {
                    match resource.kind {
                        Kind::Group(group) => group.connection.close(
                            quinn::VarInt::from_u64(if event.flags == 0 {
                                0x100
                            } else {
                                event.flags
                            })
                            .unwrap_or(quinn::VarInt::from_u32(0x102)),
                            b"",
                        ),
                        Kind::Stream(stream) => {
                            let code = if event.flags == 0 { 0x10c } else { event.flags };
                            workers.spawn(async move {
                                stream.reset(code).await;
                            });
                        }
                        _ => {}
                    }
                }
            }
            STATUS => {
                status.send_replace((
                    event.flags,
                    String::from_utf8_lossy(&event.data).into_owned(),
                ));
            }
            _ => {}
        }
    }
    let resources = std::mem::take(&mut locked(&state).resources);
    for (_, resource) in resources {
        resource.stop.cancel();
        if let Kind::Group(group) = resource.kind {
            group.connection.close(0x100u32.into(), b"client stopped");
        }
    }
    workers.shutdown().await;
    let ids: Vec<_> = locked(&bridge.resources).keys().copied().collect();
    for id in ids {
        bridge.input(ERROR, id, 0, 4, b"Rust transport stopped");
    }
}

async fn open_resource(
    event: &Event,
    bridge: &Arc<Bridge>,
    state: &Arc<Mutex<State>>,
    roots: &rustls::RootCertStore,
    stop: CancellationToken,
) -> io::Result<()> {
    match event.kind {
        OPEN_TCP | OPEN_QUIC => {
            let options: Options = serde_json::from_slice(&event.data)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            if options.host.is_empty() || options.port == 0 || options.alpn.is_empty() {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            if event.kind == OPEN_TCP {
                tracing::debug!(resource=event.id,host=%options.host,port=options.port,certificate_name=%options.server_name,alpn=?options.alpn,"Rust TLS opening");
                let (stream, ready) = open_tcp(&options, roots).await?;
                let alpn = ready.alpn.clone();
                if locked(state).replace(event.id, Kind::Stream(Stream::socket(stream, stop))) {
                    metadata(bridge, event.id, ready);
                    tracing::debug!(resource=event.id,%alpn,"Rust TLS ready");
                }
            } else {
                tracing::debug!(resource=event.id,host=%options.host,port=options.port,certificate_name=%options.server_name,"Rust QUIC opening");
                let (group, ready) = open_quic(&options, roots).await?;
                if !locked(state).replace(event.id, Kind::Group(group.clone())) {
                    return Ok(());
                }
                metadata(bridge, event.id, ready);
                tracing::debug!(
                    resource = event.id,
                    "Rust QUIC ready; ALPN h3; HTTP DATAGRAM Capsules"
                );
                loop {
                    tokio::select! {
                        _=stop.cancelled()=>return Ok(()),
                        error=group.connection.closed()=>return Err(quic_error(error)),
                        accepted=group.connection.accept_uni()=>{
                            let read=accepted.map_err(io::Error::from)?;
                            let sid:u64=read.id().into();
                            let mut state=locked(state);
                            if stop.is_cancelled(){return Ok(());}
                            let id=bridge.accept(event.id,sid,Ready{stream_id:sid,..Ready::default()});
                            if id!=0 {
                                let child_stop=stop.child_token();
                                state.resources.insert(id,Resource{parent:event.id,stop:child_stop.clone(),kind:Kind::Stream(Stream::new(ReadHalf::Quic(read),WriteHalf::Empty,child_stop))});
                            }
                        }
                        accepted=group.connection.accept_bi()=>{
                            let _=accepted.map_err(io::Error::from)?;
                            group.connection.close(0x103u32.into(),b"unexpected server-initiated bidirectional HTTP/3 stream");
                            return Err(io::Error::new(io::ErrorKind::ConnectionAborted,"HTTP/3 server opened a forbidden bidirectional stream"));
                        }
                    }
                }
            }
        }
        LISTEN => {
            let address: SocketAddr = std::str::from_utf8(&event.data)
                .map_err(io::Error::other)?
                .parse()
                .map_err(io::Error::other)?;
            let listener = TcpListener::bind(address).await?;
            let local = listener.local_addr()?;
            if !locked(state).replace(event.id, Kind::Listener) {
                return Ok(());
            }
            metadata(
                bridge,
                event.id,
                Ready {
                    local: local.to_string(),
                    ..Ready::default()
                },
            );
            tracing::info!(%local,"SOCKS TCP listener ready");
            loop {
                let (tcp, peer) = tokio::select! {_=stop.cancelled()=>return Ok(()),accepted=listener.accept()=>accepted?};
                tcp.set_nodelay(true)?;
                let mut state = locked(state);
                if stop.is_cancelled() {
                    return Ok(());
                }
                let id = bridge.accept(
                    event.id,
                    0,
                    Ready {
                        local: local.to_string(),
                        peer: peer.to_string(),
                        ..Ready::default()
                    },
                );
                if id != 0 {
                    let child_stop = stop.child_token();
                    state.resources.insert(
                        id,
                        Resource {
                            parent: event.id,
                            stop: child_stop.clone(),
                            kind: Kind::Stream(Stream::socket(tcp, child_stop)),
                        },
                    );
                }
            }
        }
        OPEN_UDP => {
            let address: SocketAddr = std::str::from_utf8(&event.data)
                .map_err(io::Error::other)?
                .parse()
                .map_err(io::Error::other)?;
            let udp = Arc::new(UdpSocket::bind(address).await?);
            let local = udp.local_addr()?;
            if !locked(state).replace(event.id, Kind::Udp(udp.clone())) {
                return Ok(());
            }
            metadata(
                bridge,
                event.id,
                Ready {
                    local: local.to_string(),
                    ..Ready::default()
                },
            );
            let mut buffer = vec![0; MAX_CHUNK];
            loop {
                let (count, peer) = tokio::select! {_=stop.cancelled()=>return Ok(()),received=udp.recv_from(&mut buffer)=>received?};
                bridge.input(IN_UDP, event.id, 0, 0, &pack_udp(peer, &buffer[..count]));
            }
        }
        _ => return Err(io::ErrorKind::InvalidInput.into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn occupied_listener_returns_an_error_and_cleans_up() {
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut backend = Backend::start(BackendOptions::default()).unwrap();
        let error = backend
            .bridge
            .listen(occupied.local_addr().unwrap())
            .await
            .err()
            .expect("duplicate bind must fail");
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        backend.shutdown().await;
        assert_eq!(backend.resource_count(), 0);
        assert!(locked(&backend.bridge.resources).is_empty());
    }
    #[tokio::test]
    async fn shutdown_wakes_a_blocked_socket_read_and_releases_resources() {
        let mut backend = Backend::start(BackendOptions::default()).unwrap();
        let listener = backend
            .bridge
            .listen("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let _peer = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut accepted, _) = listener.accept().await.unwrap();
        let reader = tokio::spawn(async move {
            let mut byte = [0];
            accepted.read(&mut byte).await
        });
        tokio::task::yield_now().await;
        backend.shutdown().await;
        assert!(
            tokio::time::timeout(Duration::from_secs(2), reader)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert_eq!(backend.resource_count(), 0);
        assert!(locked(&backend.bridge.resources).is_empty());
    }

    #[tokio::test]
    async fn shutdown_cancels_a_pending_tls_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut backend = Backend::start(BackendOptions::default()).unwrap();
        let bridge = backend.bridge.clone();
        let port = listener.local_addr().unwrap().port();
        let opening = tokio::spawn(async move {
            bridge
                .tcp(
                    serde_json::to_vec(&serde_json::json!({
                        "host": "127.0.0.1", "port": port,
                        "server_name": "relay.test", "alpn": ["h2"]
                    }))
                    .unwrap(),
                )
                .await
        });
        let _silent_peer = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        backend.shutdown().await;
        assert!(
            tokio::time::timeout(Duration::from_secs(2), opening)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert_eq!(backend.resource_count(), 0);
        assert!(locked(&backend.bridge.resources).is_empty());
    }

    #[test]
    fn a_missing_ca_file_fails_before_networking() {
        assert!(
            roots(&BackendOptions {
                ca_file: Some(PathBuf::from("/definitely-missing-relay-ca.pem"))
            })
            .is_err()
        );
    }
}
