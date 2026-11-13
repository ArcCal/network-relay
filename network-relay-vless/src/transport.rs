//! One VLESS connection: TCP to the VLESS server, a WebSocket (RFC 6455)
//! upgrade without TLS, the VLESS request header, then the tunnel's bytes in
//! binary messages, as Xray-core's `ws` transport with `security = none`
//! expects.

use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};
use std::time::Duration;

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::task::AtomicWaker;
use futures_util::{SinkExt, Stream, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest, protocol::WebSocketConfig, Bytes, Message};
use tokio_tungstenite::WebSocketStream;
use tokio_util::sync::PollSender;

use crate::config::VlessConfig;
use crate::vless::{self, Command, ResponseHeader};

/// The largest WebSocket message or frame accepted from the VLESS server.
/// Xray-core writes at most one 8 KiB buffer per message; the limit bounds
/// what a faulty server can make one tunnel hold.
const MAX_MESSAGE: usize = 256 * 1024;
/// The most bytes put in one message by one write.
const MAX_WRITE: usize = 16 * 1024;

/// Completion and failure of the bounded background writer. The receiver
/// publishes a failure before closing its queue, so blocked writes also wake.
#[derive(Default)]
struct WriteState {
    pending: AtomicUsize,
    finished: AtomicBool,
    failure: Mutex<Option<io::Error>>,
    reader: AtomicWaker,
    flusher: AtomicWaker,
}

impl WriteState {
    fn result(&self) -> io::Result<()> {
        if !self.finished.load(Ordering::Acquire) {
            return Ok(());
        }
        match self.failure.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            Some(error) => Err(match error.raw_os_error() {
                Some(code) => io::Error::from_raw_os_error(code),
                None => io::Error::new(error.kind(), error.to_string()),
            }),
            None => Ok(()),
        }
    }

    fn finish(&self, error: Option<io::Error>) {
        let mut failure = self.failure.lock().unwrap_or_else(|e| e.into_inner());
        if failure.is_none() {
            *failure = error;
        }
        drop(failure);
        self.finished.store(true, Ordering::Release);
        self.reader.wake();
        self.flusher.wake();
    }
}

/// Resets the TCP connection to the VLESS server, once, while it is open.
#[derive(Default)]
struct Resetter {
    /// The socket, until the connection is dropped.
    fd: Mutex<Option<RawFd>>,
}

impl Resetter {
    fn reset(&self) {
        let fd = self.fd.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(fd) = *fd {
            // SAFETY: the descriptor stays open while it is recorded here:
            // `VlessStream::drop` clears it, under this lock, before the
            // socket closes.
            let socket = unsafe { BorrowedFd::borrow_raw(fd) };
            let socket = socket2::SockRef::from(&socket);
            let _ = socket.set_linger(Some(Duration::ZERO));
            let _ = socket.shutdown(std::net::Shutdown::Both);
        }
    }
}

/// A VLESS connection's byte stream: the payload after the response header.
///
/// Writes go to a task that owns the WebSocket's sending half and flushes
/// whatever it is given, so data reaches the socket without the caller
/// flushing: network-relay writes to an egress stream as to a kernel socket.
pub struct VlessStream {
    incoming: SplitStream<WebSocketStream<TcpStream>>,
    outgoing: PollSender<Bytes>,
    writing: Arc<WriteState>,
    response: ResponseHeader,
    /// Payload received but not yet read.
    pending: Bytes,
    eof: bool,
    close_received: bool,
    close_error: Option<u16>,
    resetter: Arc<Resetter>,
    local: SocketAddr,
    closing: Option<oneshot::Sender<()>>,
    resources: Arc<Mutex<Option<network_relay::egress::ResourceGuard>>>,
}

/// Messages queued for the writer task. With [`MAX_WRITE`] this bounds what
/// one tunnel holds before the socket takes it.
const QUEUED_MESSAGES: usize = 8;
/// How long the writer task may take to drain data and close once the
/// tunnel is gone.
const CLOSE_WAIT: Duration = Duration::from_secs(5);

impl VlessStream {
    /// Opens a VLESS connection for `command` to `peer` through the server
    /// in `config`. The request goes out at once, so the server connects to
    /// the destination even before the client sends anything.
    pub async fn open(config: &VlessConfig, command: Command, peer: SocketAddr) -> io::Result<Self> {
        let tcp = connect_server(config).await?;
        let local = tcp.local_addr()?;
        let resetter = Arc::new(Resetter { fd: Mutex::new(Some(tcp.as_raw_fd())) });
        let request = config.websocket_url().into_client_request().map_err(ws_error)?;
        let ws_config =
            WebSocketConfig::default().max_message_size(Some(MAX_MESSAGE)).max_frame_size(Some(MAX_MESSAGE));
        let (mut ws, response) =
            tokio_tungstenite::client_async_with_config(request, tcp, Some(ws_config)).await.map_err(|e| match e {
                tungstenite::Error::Http(response) => io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("the VLESS server refused the WebSocket upgrade with HTTP {}", response.status()),
                ),
                other => ws_error(other),
            })?;
        tracing::trace!(status = %response.status(), "VLESS WebSocket open");
        let header = vless::request(&config.user_id, command, peer);
        ws.send(Message::Binary(header.into())).await.map_err(ws_error)?;
        let (sink, incoming) = ws.split();
        let (outgoing, queued) = mpsc::channel(QUEUED_MESSAGES);
        let (closing, closed) = oneshot::channel();
        let resources = Arc::new(Mutex::new(None));
        let writing = Arc::new(WriteState::default());
        let progress = writing.clone();
        let completion = writing.clone();
        let held = resources.clone();
        tokio::spawn(async move {
            {
                let writer = write_messages(sink, queued, progress);
                tokio::pin!(writer);
                tokio::select! {
                    _ = &mut writer => {}
                    _ = closed => { let _ = tokio::time::timeout(CLOSE_WAIT, writer).await; }
                }
            } // Drop the sink before releasing its reservations.
            if !completion.finished.load(Ordering::Acquire) {
                completion
                    .finish(Some(io::Error::new(io::ErrorKind::TimedOut, "closing the VLESS WebSocket timed out")));
            }
            drop(held);
        });
        Ok(Self {
            incoming,
            outgoing: PollSender::new(outgoing),
            writing,
            response: ResponseHeader::default(),
            pending: Bytes::new(),
            eof: false,
            close_received: false,
            close_error: None,
            resetter,
            local,
            closing: Some(closing),
            resources,
        })
    }

    pub fn resource_retainer(&self) -> impl Fn(network_relay::egress::ResourceGuard) + Send + Sync + 'static {
        let resources = self.resources.clone();
        move |guard| {
            *resources.lock().unwrap_or_else(|e| e.into_inner()) = Some(guard);
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Resets the connection to the VLESS server (the server, not this
    /// relay, decides how the destination learns of it).
    pub fn reset_handle(&self) -> Arc<dyn Fn() + Send + Sync> {
        let resetter = self.resetter.clone();
        Arc::new(move || resetter.reset())
    }
}

/// Sends queued payload as binary messages, flushing after each batch. When
/// the stream is dropped it closes the WebSocket, which ends the VLESS
/// connection in both directions.
async fn write_messages(
    mut sink: SplitSink<WebSocketStream<TcpStream>, Message>,
    mut queued: mpsc::Receiver<Bytes>,
    writing: Arc<WriteState>,
) {
    let result: Result<(), tungstenite::Error> = async {
        while let Some(data) = queued.recv().await {
            let mut bytes = data.len();
            sink.feed(Message::Binary(data)).await?;
            while let Ok(data) = queued.try_recv() {
                bytes += data.len();
                sink.feed(Message::Binary(data)).await?;
            }
            sink.flush().await?;
            writing.pending.fetch_sub(bytes, Ordering::AcqRel);
            writing.flusher.wake();
        }
        Ok(())
    }
    .await;
    // A received Close queues an automatic reply. Drive it even when a
    // queued application write was rejected because the peer was closing.
    // Publish termination only afterwards, so the relay cannot reset the
    // socket before that reply is flushed (RFC 6455 section 5.5.1).
    // Retain the first write error even if the close deadline cancels this
    // future; its notification waits until the Close reply attempt ends.
    let write_error = result.err().map(ws_error);
    if let Some(error) = &write_error {
        tracing::debug!("VLESS connection write failed: {error}");
    }
    *writing.failure.lock().unwrap_or_else(|e| e.into_inner()) = write_error;
    let error = match tokio::time::timeout(CLOSE_WAIT, sink.close()).await {
        Ok(result) => result.err().map(ws_error),
        Err(_) => Some(io::Error::new(io::ErrorKind::TimedOut, "closing the VLESS WebSocket timed out")),
    };
    if let Some(error) = &error {
        tracing::debug!("VLESS connection write failed: {error}");
    }
    writing.finish(error);
}

impl Drop for VlessStream {
    fn drop(&mut self) {
        // The socket can outlive this stream while the writer task finishes;
        // a reset is meant for the tunnel's lifetime only.
        *self.resetter.fd.lock().unwrap_or_else(|e| e.into_inner()) = None;
        if let Some(closing) = self.closing.take() {
            let _ = closing.send(());
        }
    }
}

/// The TCP connection to the VLESS server: each of its addresses in turn.
async fn connect_server(config: &VlessConfig) -> io::Result<TcpStream> {
    let addrs: Vec<SocketAddr> =
        tokio::net::lookup_host((config.server_host.as_str(), config.server_port)).await?.collect();
    let mut last = io::Error::new(io::ErrorKind::NotFound, "the VLESS server's name has no addresses");
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(tcp) => {
                let _ = tcp.set_nodelay(true);
                return Ok(tcp);
            }
            Err(e) => last = e,
        }
    }
    Err(io::Error::new(last.kind(), format!("connecting to the VLESS server: {last}")))
}

fn ws_error(e: tungstenite::Error) -> io::Error {
    match e {
        tungstenite::Error::Io(e) => e,
        tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed => {
            io::Error::new(io::ErrorKind::BrokenPipe, "the VLESS connection is closed")
        }
        other => io::Error::new(io::ErrorKind::InvalidData, format!("VLESS WebSocket: {other}")),
    }
}

/// The server closed before its response header: it refused the request
/// (an unknown user ID) or could not reach the destination.
fn closed_before_response() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionReset,
        "the VLESS server closed the connection without answering (rejected user ID or destination unreachable)",
    )
}

impl AsyncRead for VlessStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = &mut *self;
        this.writing.reader.register(cx.waker());
        loop {
            if !this.pending.is_empty() {
                let used = this.response.feed(&this.pending)?;
                let _ = this.pending.split_to(used);
                if !this.pending.is_empty() {
                    let n = this.pending.len().min(buf.remaining());
                    buf.put_slice(&this.pending.split_to(n));
                    return Poll::Ready(Ok(()));
                }
                continue;
            }
            if this.eof {
                if this.close_received && !this.writing.finished.load(Ordering::Acquire) {
                    return Poll::Pending;
                }
                return Poll::Ready(if this.response.done() {
                    match this.close_error {
                        // The peer's reason may contain credentials or other
                        // private data, so report only its numeric code.
                        Some(code) => Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            format!("the VLESS server closed the WebSocket with code {code}"),
                        )),
                        None => this.writing.result(),
                    }
                } else {
                    Err(closed_before_response())
                });
            }
            let next = match Pin::new(&mut this.incoming).poll_next(cx) {
                Poll::Ready(next) => next,
                Poll::Pending => {
                    this.writing.result()?;
                    return Poll::Pending;
                }
            };
            match next {
                Some(Ok(Message::Binary(data))) => this.pending = data,
                // tungstenite answers pings itself.
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => {}
                Some(Ok(Message::Text(_))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "the VLESS server sent a text WebSocket message",
                    )))
                }
                Some(Ok(Message::Close(frame))) => {
                    this.close_error = frame
                        .filter(|frame| frame.code != tungstenite::protocol::frame::coding::CloseCode::Normal)
                        .map(|frame| frame.code.into());
                    this.close_received = true;
                    this.outgoing.close();
                    this.outgoing.abort_send();
                    // Reuse the existing whole-writer teardown budget: a
                    // peer that stops reading must not hold EOF indefinitely.
                    if let Some(closing) = this.closing.take() {
                        let _ = closing.send(());
                    }
                    this.eof = true;
                }
                None => this.eof = true,
                Some(Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed)) => this.eof = true,
                Some(Err(e)) => {
                    let e = ws_error(e);
                    return Poll::Ready(Err(if this.response.done() { e } else { closed_before_response() }));
                }
            }
        }
    }
}

impl AsyncWrite for VlessStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.close_received {
            self.writing.flusher.register(cx.waker());
            if !self.writing.finished.load(Ordering::Acquire) {
                return Poll::Pending;
            }
        }
        self.writing.result()?;
        let closed = || io::Error::new(io::ErrorKind::BrokenPipe, "the VLESS connection is closed");
        if ready!(self.outgoing.poll_reserve(cx)).is_err() {
            return Poll::Ready(Err(self.writing.result().err().unwrap_or_else(closed)));
        }
        let n = buf.len().min(MAX_WRITE);
        self.writing.pending.fetch_add(n, Ordering::AcqRel);
        if self.outgoing.send_item(Bytes::copy_from_slice(&buf[..n])).is_err() {
            self.writing.pending.fetch_sub(n, Ordering::AcqRel);
            return Poll::Ready(Err(self.writing.result().err().unwrap_or_else(closed)));
        }
        Poll::Ready(Ok(n))
    }

    /// Wait until the writer has flushed all accepted payload to its socket.
    /// This is local completion, not acknowledgment by the remote application.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.writing.flusher.register(cx.waker());
        if self.close_received && !self.writing.finished.load(Ordering::Acquire) {
            return Poll::Pending;
        }
        self.writing.result()?;
        if self.writing.pending.load(Ordering::Acquire) == 0 {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    /// VLESS over WebSocket has no half-close: a WebSocket close ends both
    /// directions, and Xray-core then stops relaying the answer. So the end
    /// of the client's data is not passed on.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IpPreference;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn config(port: u16) -> VlessConfig {
        VlessConfig {
            server_host: "127.0.0.1".into(),
            server_port: port,
            user_id: vless::UserId::parse("b4e4fad1-c320-428e-92dc-f8f6944a7dec").unwrap(),
            path: "/ws".into(),
            host_header: "vless.test".into(),
            dns_servers: vec!["127.0.0.1:53".parse().unwrap()],
            ip_preference: IpPreference::Ipv4First,
        }
    }

    /// A VLESS server that checks the request, then reads nothing for a
    /// while, then answers and echoes.
    async fn slow_echo_server() -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let Some(Ok(Message::Binary(request))) = ws.next().await else { panic!("no request") };
            tokio::time::sleep(Duration::from_millis(300)).await;
            ws.send(Message::Binary(Bytes::from_static(&[0, 0]))).await.unwrap();
            while let Some(Ok(message)) = ws.next().await {
                match message {
                    Message::Binary(data) => ws.send(Message::Binary(data)).await.unwrap(),
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            request.to_vec()
        });
        (port, task)
    }

    /// network-relay writes to an egress stream without flushing; a write
    /// that the socket cannot take at once must still go out.
    #[tokio::test]
    async fn written_data_is_sent_without_a_flush() {
        let (port, server) = slow_echo_server().await;
        let peer: SocketAddr = "192.0.2.7:443".parse().unwrap();
        let mut stream = VlessStream::open(&config(port), Command::Tcp, peer).await.unwrap();
        let payload: Vec<u8> = (0..2 << 20).map(|i: u32| (i % 253) as u8).collect();
        let (mut rd, mut wr) = tokio::io::split(&mut stream);
        let sent = payload.clone();
        let write = async move {
            for chunk in sent.chunks(16 * 1024) {
                wr.write_all(chunk).await.unwrap();
            }
        };
        let read = async {
            let mut got = vec![0u8; payload.len()];
            tokio::time::timeout(Duration::from_secs(20), rd.read_exact(&mut got)).await.expect("stalled").unwrap();
            got
        };
        let ((), got) = tokio::join!(write, read);
        assert!(got == payload, "echoed bytes differ");
        drop(stream);
        let request = server.await.unwrap();
        assert_eq!(request, vless::request(&config(port).user_id, Command::Tcp, peer));
    }

    #[tokio::test]
    async fn an_empty_read_completes_without_waiting_for_a_peer_response() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            assert!(matches!(ws.next().await, Some(Ok(Message::Binary(_)))));
            assert!(matches!(ws.next().await, Some(Ok(Message::Close(_)))));
            let _ = ws.flush().await;
        });
        let mut stream =
            VlessStream::open(&config(port), Command::Tcp, "192.0.2.7:443".parse().unwrap()).await.unwrap();
        let result = tokio::time::timeout(Duration::from_millis(100), stream.read(&mut [])).await;
        drop(stream);
        tokio::time::timeout(Duration::from_secs(2), server).await.unwrap().unwrap();
        assert_eq!(result.expect("an empty read must not depend on peer data").unwrap(), 0);
    }

    #[tokio::test]
    async fn a_server_that_closes_without_answering_is_an_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let _ = ws.next().await;
            let _ = ws.close(None).await;
        });
        let mut stream =
            VlessStream::open(&config(port), Command::Tcp, "192.0.2.7:443".parse().unwrap()).await.unwrap();
        let mut buf = [0u8; 16];
        let error = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset, "{error}");
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_stalled_writer_releases_its_socket_after_the_stream_is_dropped() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            socket2::SockRef::from(&tcp).set_recv_buffer_size(4096).unwrap();
            let _ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            std::future::pending::<()>().await;
        });
        let mut stream =
            VlessStream::open(&config(port), Command::Tcp, "192.0.2.7:443".parse().unwrap()).await.unwrap();
        let admission = Arc::new(tokio::sync::Semaphore::new(1));
        stream.resource_retainer()(Arc::new(admission.clone().try_acquire_owned().unwrap()));
        let fd = stream.resetter.fd.lock().unwrap().unwrap();
        let path = format!("/proc/self/fd/{fd}");
        let socket = std::fs::read_link(&path).unwrap();
        let payload = [42; 16384];
        assert!(
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    stream.write_all(&payload).await.unwrap();
                }
            })
            .await
            .is_err(),
            "the peer should block the writer"
        );
        {
            let flushing = stream.flush();
            tokio::pin!(flushing);
            std::future::poll_fn(|cx| {
                use std::future::Future;
                assert!(flushing.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        } // Cancelling a flush waiter must not extend the drop deadline.
        drop(stream);
        assert_eq!(admission.available_permits(), 0, "closing sockets must remain charged");
        tokio::time::sleep(CLOSE_WAIT + Duration::from_millis(500)).await;
        assert_ne!(std::fs::read_link(path).ok(), Some(socket), "the detached writer retained its socket");
        assert_eq!(admission.available_permits(), 1, "closed sockets must return admission");
        server.abort();
        let _ = server.await;
    }

    /// Keep the peer alive after its response, so a local write-only fault
    /// cannot be mistaken for the peer closing its read direction too.
    async fn idle_peer() -> (u16, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            assert!(matches!(ws.next().await, Some(Ok(Message::Binary(_)))));
            ws.send(Message::Binary(Bytes::from_static(b"\0\0buffered reply"))).await.unwrap();
            let _ = stopped.await;
        });
        (port, stop, task)
    }

    /// Deliberate local fault injection, not a claim that every network loss
    /// is write-only: subsequent socket writes fail while reads remain open.
    fn fail_socket_writes(stream: &VlessStream) {
        let fd = stream.resetter.fd.lock().unwrap().unwrap();
        // SAFETY: this test owns the stream throughout the borrowed operation.
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
        socket2::SockRef::from(&borrowed).shutdown(std::net::Shutdown::Write).unwrap();
    }

    async fn wait_for_write_failure<W: AsyncWrite + Unpin>(writer: &mut W) -> io::Error {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match writer.write_all(b"trigger writer failure").await {
                    Err(error) => break error,
                    Ok(()) => tokio::task::yield_now().await,
                }
            }
        })
        .await
        .expect("injected write-only fault was not observed")
    }

    #[tokio::test]
    async fn writer_failure_wakes_read_after_buffered_data() {
        let (port, stop, peer) = idle_peer().await;
        let mut stream =
            VlessStream::open(&config(port), Command::Tcp, "192.0.2.7:443".parse().unwrap()).await.unwrap();
        let mut first = [0];
        stream.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"b");
        fail_socket_writes(&stream);
        let (mut reader, mut writer) = tokio::io::split(stream);
        let (ready, waiting) = oneshot::channel();
        let mut read = tokio::spawn(async move {
            let mut buffered = [0; 13];
            reader.read_exact(&mut buffered).await.unwrap();
            let mut byte = [0];
            let read = reader.read(&mut byte);
            tokio::pin!(read);
            std::future::poll_fn(|cx| {
                use std::future::Future;
                assert!(read.as_mut().poll(cx).is_pending(), "peer should leave the reader pending");
                Poll::Ready(())
            })
            .await;
            ready.send(()).unwrap();
            (buffered, read.await)
        });
        waiting.await.unwrap();
        assert_eq!(wait_for_write_failure(&mut writer).await.kind(), io::ErrorKind::BrokenPipe);
        let result = tokio::time::timeout(Duration::from_secs(2), &mut read).await;
        if result.is_err() {
            read.abort();
            let _ = read.await;
        }
        drop(writer);
        let _ = stop.send(());
        peer.await.unwrap();
        let (buffered, result) = result.expect("writer failed but did not wake the reader").unwrap();
        assert_eq!(&buffered, b"uffered reply");
        let error = result.expect_err("write failure must not become a clean EOF");
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(error.raw_os_error(), Some(32), "the original socket error was not preserved");
    }

    #[tokio::test]
    async fn writer_failure_preserves_buffered_reply_and_reaches_flush() {
        let (port, stop, peer) = idle_peer().await;
        let mut stream =
            VlessStream::open(&config(port), Command::Tcp, "192.0.2.7:443".parse().unwrap()).await.unwrap();
        let mut first = [0];
        stream.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"b");
        fail_socket_writes(&stream);
        assert_eq!(wait_for_write_failure(&mut stream).await.kind(), io::ErrorKind::BrokenPipe);
        let flushed = stream.flush().await;
        let mut buffered = [0; 13];
        stream.read_exact(&mut buffered).await.expect("write failure discarded an already buffered reply");
        drop(stream);
        let _ = stop.send(());
        peer.await.unwrap();
        assert_eq!(&buffered, b"uffered reply");
        let error = flushed.expect_err("flush succeeded after the writer permanently failed");
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(error.raw_os_error(), Some(32));
    }

    #[tokio::test]
    async fn flush_drains_payload_before_a_later_socket_write_shutdown() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let peer = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            assert!(matches!(ws.next().await, Some(Ok(Message::Binary(_)))));
            let mut received = Vec::new();
            while let Some(Ok(message)) = ws.next().await {
                if let Message::Binary(data) = message {
                    received.extend_from_slice(&data);
                }
            }
            received
        });
        let mut stream =
            VlessStream::open(&config(port), Command::Tcp, "192.0.2.7:443".parse().unwrap()).await.unwrap();
        let payload = b"data accepted before flush";
        stream.write_all(payload).await.unwrap();
        stream.flush().await.unwrap();
        // SHUT_WR preserves bytes already accepted by the kernel and puts FIN
        // after them. This is not a remote ACK or WebSocket half-close test.
        fail_socket_writes(&stream);
        drop(stream);
        let received = tokio::time::timeout(Duration::from_secs(2), peer).await.unwrap().unwrap();
        assert_eq!(received, payload, "flush returned with payload still only in the local writer queue");
    }

    #[tokio::test]
    async fn close_codes_preserve_payload_and_error_semantics() {
        use tokio_tungstenite::tungstenite::protocol::{frame::coding::CloseCode, CloseFrame};
        for code in [None, Some(1000), Some(1002), Some(1008), Some(1011), Some(4000)] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let peer = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
                assert!(matches!(ws.next().await, Some(Ok(Message::Binary(_)))));
                ws.send(Message::Binary(Bytes::from_static(b"\0\0complete reply"))).await.unwrap();
                let frame = code.map(|code| CloseFrame {
                    code: CloseCode::from(code),
                    reason: "private-peer-text-must-not-enter-errors".into(),
                });
                let _ = ws.close(frame).await;
            });
            let mut stream =
                VlessStream::open(&config(port), Command::Tcp, "192.0.2.7:443".parse().unwrap()).await.unwrap();
            let mut payload = Vec::new();
            let result = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut payload)).await.unwrap();
            drop(stream);
            peer.await.unwrap();
            assert_eq!(payload, b"complete reply", "payload before close {code:?} was lost");
            if let Some(code) = code.filter(|code| *code != 1000) {
                let error = result.expect_err("abnormal WebSocket close became a clean EOF");
                assert!(error.to_string().contains(&code.to_string()), "{error}");
                assert!(!error.to_string().contains("private-peer-text"), "peer text reached the error");
            } else {
                result.expect("normal close became an error");
            }
        }
    }

    #[tokio::test]
    async fn received_close_is_acknowledged_before_the_stream_is_dropped() {
        use tokio_tungstenite::tungstenite::protocol::{frame::coding::CloseCode, CloseFrame};
        for (code, upload) in [(1000, false), (1002, false), (1000, true), (1002, true)] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let (close, start_closing) = oneshot::channel();
            let (acknowledged, acknowledgment) = oneshot::channel();
            let peer = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                socket2::SockRef::from(&tcp).set_recv_buffer_size(4096).unwrap();
                let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
                assert!(matches!(ws.next().await, Some(Ok(Message::Binary(_)))));
                start_closing.await.unwrap();
                ws.send(Message::Binary(Bytes::from_static(b"\0\0complete reply"))).await.unwrap();
                ws.close(Some(CloseFrame { code: CloseCode::from(code), reason: "private reason".into() }))
                    .await
                    .unwrap();
                loop {
                    match ws.next().await {
                        Some(Ok(Message::Binary(_))) => assert!(upload),
                        Some(Ok(Message::Close(frame))) => {
                            assert_eq!(frame.unwrap().code, CloseCode::from(code));
                            acknowledged.send(()).unwrap();
                            break;
                        }
                        other => panic!("missing Close acknowledgment for {code}/{upload}: {other:?}"),
                    }
                }
            });
            let mut stream =
                VlessStream::open(&config(port), Command::Tcp, "192.0.2.7:443".parse().unwrap()).await.unwrap();
            if upload {
                let fd = stream.resetter.fd.lock().unwrap().unwrap();
                // SAFETY: this fixture owns the stream and its descriptor.
                let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
                socket2::SockRef::from(&borrowed).set_send_buffer_size(4096).unwrap();
                assert!(tokio::time::timeout(Duration::from_millis(250), async {
                    loop {
                        stream.write_all(&[42; MAX_WRITE]).await.unwrap();
                    }
                })
                .await
                .is_err());
            }
            close.send(()).unwrap();
            let mut payload = Vec::new();
            let result = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut payload)).await.unwrap();
            assert_eq!(payload, b"complete reply");
            // Keep the foreground owner alive: Drop must not be what drives
            // the automatic reply required by RFC 6455 section 5.5.1.
            tokio::time::timeout(Duration::from_secs(2), acknowledgment)
                .await
                .expect("valid peer Close was not acknowledged while its stream stayed alive")
                .unwrap();
            if code != 1000 {
                let error = result.expect_err("an error Close must remain an error");
                assert!(error.to_string().contains(&code.to_string()), "{error}");
                assert!(!error.to_string().contains("private reason"));
            } else if upload {
                result.expect_err("unflushed upload must not become a clean EOF");
                stream.flush().await.expect_err("unflushed upload must not become a successful flush");
            } else {
                result.unwrap();
            }
            drop(stream);
            tokio::time::timeout(Duration::from_secs(2), peer).await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn peer_close_cannot_leave_a_blocked_upload_waiting_forever() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (close, start_closing) = oneshot::channel();
        let peer = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            socket2::SockRef::from(&tcp).set_recv_buffer_size(4096).unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            assert!(matches!(ws.next().await, Some(Ok(Message::Binary(_)))));
            start_closing.await.unwrap();
            ws.send(Message::Binary(Bytes::from_static(b"\0\0complete reply"))).await.unwrap();
            ws.close(None).await.unwrap();
            // Keep the read half alive without accepting the queued upload
            // or the Close reply; teardown must remain bounded nonetheless.
            std::future::pending::<()>().await;
        });
        let mut stream =
            VlessStream::open(&config(port), Command::Tcp, "192.0.2.7:443".parse().unwrap()).await.unwrap();
        let fd = stream.resetter.fd.lock().unwrap().unwrap();
        // SAFETY: this fixture owns the stream throughout this operation.
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
        socket2::SockRef::from(&borrowed).set_send_buffer_size(4096).unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(250), async {
            loop {
                stream.write_all(&[42; MAX_WRITE]).await.unwrap();
            }
        })
        .await
        .is_err());
        close.send(()).unwrap();
        let mut payload = Vec::new();
        let result =
            tokio::time::timeout(CLOSE_WAIT + Duration::from_millis(500), stream.read_to_end(&mut payload)).await;
        assert_eq!(payload, b"complete reply");
        let error = result.expect("peer Close left the blocked writer alive without a deadline").unwrap_err();
        // Depending on kernel buffering, the writer either stays blocked
        // until its deadline or observes Close before its next queued feed.
        // RFC 6455 forbids that later data write. Its original error must
        // remain visible rather than being replaced by a close timeout.
        let after_close = ws_error(tungstenite::Error::Protocol(tungstenite::error::ProtocolError::SendAfterClosing));
        assert!(
            error.kind() == io::ErrorKind::TimedOut
                || (error.kind() == after_close.kind() && error.to_string() == after_close.to_string()),
            "unexpected blocked-upload close error: {error}"
        );
        eprintln!("blocked-upload close result: {error}");
        tokio::time::timeout(Duration::from_millis(500), async {
            stream.flush().await.expect_err("a failed pending upload must not flush successfully");
            stream.write_all(b"late").await.expect_err("writes must fail after peer Close");
        })
        .await
        .expect("closed writer still waits for peer progress");
        peer.abort();
        let _ = peer.await;
    }

    #[tokio::test]
    async fn full_writer_queue_preserves_reverse_progress_and_neighbor_streams() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (reverse, send_reverse) = oneshot::channel();
        let (drain, start_draining) = oneshot::channel::<usize>();
        let peer = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let receive_buffer = socket2::SockRef::from(&tcp).recv_buffer_size().unwrap();
            socket2::SockRef::from(&tcp).set_recv_buffer_size(4096).unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            assert!(matches!(ws.next().await, Some(Ok(Message::Binary(_)))));
            send_reverse.await.unwrap();
            ws.send(Message::Binary(Bytes::from_static(b"\0\0reverse progress"))).await.unwrap();
            let expected = start_draining.await.unwrap();
            // Restore the fixture's ordinary receive buffer after provoking
            // backpressure; its tiny advertised window is not a drain-rate
            // requirement on the production transport.
            socket2::SockRef::from(ws.get_ref()).set_recv_buffer_size(receive_buffer).unwrap();
            let mut received = 0;
            while received < expected {
                let Some(Ok(Message::Binary(data))) = ws.next().await else { panic!("missing queued payload") };
                assert!(data.iter().all(|byte| *byte == 42));
                received += data.len();
            }
            assert_eq!(received, expected);
            ws.send(Message::Binary(Bytes::from_static(b"drained"))).await.unwrap();
        });
        let stream = VlessStream::open(&config(port), Command::Tcp, "192.0.2.7:443".parse().unwrap()).await.unwrap();
        let fd = stream.resetter.fd.lock().unwrap().unwrap();
        // SAFETY: the stream remains owned below while setting its fixture's
        // small send buffer; production buffer settings are unchanged.
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
        socket2::SockRef::from(&borrowed).set_send_buffer_size(4096).unwrap();
        let (mut reader, mut writer) = tokio::io::split(stream);
        let payload = [42; MAX_WRITE];
        let mut accepted = 0;
        assert!(
            tokio::time::timeout(Duration::from_millis(250), async {
                loop {
                    writer.write_all(&payload).await.unwrap();
                    accepted += payload.len();
                }
            })
            .await
            .is_err(),
            "the non-reading fixture should exert backpressure"
        );
        assert!(accepted > 0);
        {
            let flushing = writer.flush();
            tokio::pin!(flushing);
            std::future::poll_fn(|cx| {
                use std::future::Future;
                assert!(flushing.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        } // Retry below after cancelling this pending flush future.
        reverse.send(()).unwrap();
        let mut received = [0; 16];
        tokio::time::timeout(Duration::from_secs(2), reader.read_exact(&mut received)).await.unwrap().unwrap();
        assert_eq!(&received, b"reverse progress");

        let (neighbor_port, neighbor_peer) = slow_echo_server().await;
        let mut neighbor =
            VlessStream::open(&config(neighbor_port), Command::Tcp, "192.0.2.7:443".parse().unwrap()).await.unwrap();
        neighbor.write_all(b"neighbor").await.unwrap();
        let mut reply = [0; 8];
        tokio::time::timeout(Duration::from_secs(2), neighbor.read_exact(&mut reply)).await.unwrap().unwrap();
        assert_eq!(&reply, b"neighbor");
        drop(neighbor);
        tokio::time::timeout(Duration::from_secs(2), neighbor_peer).await.unwrap().unwrap();

        drain.send(accepted).unwrap();
        tokio::time::timeout(Duration::from_secs(2), writer.flush()).await.unwrap().unwrap();
        let mut complete = [0; 7];
        tokio::time::timeout(Duration::from_secs(2), reader.read_exact(&mut complete)).await.unwrap().unwrap();
        assert_eq!(&complete, b"drained");
        drop(reader);
        drop(writer);
        tokio::time::timeout(Duration::from_secs(2), peer).await.unwrap().unwrap();
    }
}
