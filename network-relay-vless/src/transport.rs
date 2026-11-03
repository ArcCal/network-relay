//! One VLESS connection: TCP to the VLESS server, a WebSocket (RFC 6455)
//! upgrade without TLS, the VLESS request header, then the tunnel's bytes in
//! binary messages, as Xray-core's `ws` transport with `security = none`
//! expects.

use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};
use std::time::Duration;

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, Stream, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
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
    response: ResponseHeader,
    /// Payload received but not yet read.
    pending: Bytes,
    eof: bool,
    resetter: Arc<Resetter>,
    local: SocketAddr,
}

/// Messages queued for the writer task. With [`MAX_WRITE`] this bounds what
/// one tunnel holds before the socket takes it.
const QUEUED_MESSAGES: usize = 8;
/// How long the writer task may take to finish the close handshake once the
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
        tokio::spawn(write_messages(sink, queued));
        Ok(Self {
            incoming,
            outgoing: PollSender::new(outgoing),
            response: ResponseHeader::default(),
            pending: Bytes::new(),
            eof: false,
            resetter,
            local,
        })
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
async fn write_messages(mut sink: SplitSink<WebSocketStream<TcpStream>, Message>, mut queued: mpsc::Receiver<Bytes>) {
    let result: Result<(), tungstenite::Error> = async {
        while let Some(data) = queued.recv().await {
            sink.feed(Message::Binary(data)).await?;
            while let Ok(data) = queued.try_recv() {
                sink.feed(Message::Binary(data)).await?;
            }
            sink.flush().await?;
        }
        Ok(())
    }
    .await;
    match result {
        Ok(()) => {
            let _ = tokio::time::timeout(CLOSE_WAIT, sink.close()).await;
        }
        Err(e) => tracing::debug!("VLESS connection write failed: {e}"),
    }
}

impl Drop for VlessStream {
    fn drop(&mut self) {
        // The socket can outlive this stream while the writer task finishes;
        // a reset is meant for the tunnel's lifetime only.
        *self.resetter.fd.lock().unwrap_or_else(|e| e.into_inner()) = None;
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
        let this = &mut *self;
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
                return Poll::Ready(if this.response.done() { Ok(()) } else { Err(closed_before_response()) });
            }
            match ready!(Pin::new(&mut this.incoming).poll_next(cx)) {
                Some(Ok(Message::Binary(data))) => this.pending = data,
                // tungstenite answers pings itself.
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => {}
                Some(Ok(Message::Text(_))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "the VLESS server sent a text WebSocket message",
                    )))
                }
                Some(Ok(Message::Close(_))) | None => this.eof = true,
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
        let closed = || io::Error::new(io::ErrorKind::BrokenPipe, "the VLESS connection is closed");
        ready!(self.outgoing.poll_reserve(cx)).map_err(|_| closed())?;
        let n = buf.len().min(MAX_WRITE);
        self.outgoing.send_item(Bytes::copy_from_slice(&buf[..n])).map_err(|_| closed())?;
        Poll::Ready(Ok(n))
    }

    /// The writer task flushes on its own; nothing waits here.
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// VLESS over WebSocket has no half-close: a WebSocket close ends both
    /// directions, and Xray-core then stops relaying the answer. So the end
    /// of the client's data is not passed on.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
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
}
