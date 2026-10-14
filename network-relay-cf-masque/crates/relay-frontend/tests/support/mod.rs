//! Native sockets for integration tests, restricted to loopback destinations.
//!
//! Production egress has no host-network implementation. This fixture resolves
//! only IP literals and the in-memory `localhost` entry, without host DNS.

#![cfg(test)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use relay_frontend::sys;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpSocket, TcpStream as NativeTcpStream, UdpSocket as NativeUdpSocket};
use warp_masque_egress::egress::{DatagramIo, Egress, IoFuture, TcpStream, UdpSocket};

const UDP_BUFFER: usize = 1 << 20;
const UDP_MAX_PAYLOAD: usize = 65_507;

#[derive(Default)]
pub struct LoopbackTestEgress;

fn loopback_peer(peer: SocketAddr) -> io::Result<SocketAddr> {
    let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
    if peer.ip().is_loopback() {
        Ok(peer)
    } else {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "test egress permits only loopback destinations"))
    }
}

impl Egress for LoopbackTestEgress {
    fn resolve<'a>(&'a self, host: &'a str) -> IoFuture<'a, Vec<IpAddr>> {
        Box::pin(async move {
            if let Ok(ip) = host.parse::<IpAddr>() {
                return Ok(vec![ip.to_canonical()]);
            }
            if host.trim_end_matches('.').eq_ignore_ascii_case("localhost") {
                return Ok(vec![Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()]);
            }
            Err(io::Error::new(io::ErrorKind::NotFound, "name is not in the test resolver"))
        })
    }

    fn connect_tcp(&self, peer: SocketAddr) -> IoFuture<'_, TcpStream> {
        Box::pin(async move {
            let peer = loopback_peer(peer)?;
            let socket = if peer.is_ipv6() { TcpSocket::new_v6()? } else { TcpSocket::new_v4()? };
            // Reserve target buffers before the handshake, as native upstream
            // does; preserve its optional post-connect socket tuning as well.
            sys::limit_tcp_buffers(socket2::SockRef::from(&socket), sys::TARGET_TCP_BUFFER)?;
            let stream = socket.connect(peer).await?;
            if let Err(error) = sys::tune_target_tcp(socket2::SockRef::from(&stream)) {
                tracing::debug!("could not set test TCP options: {error}");
            }
            let local = stream.local_addr()?;
            let peer = stream.peer_addr()?;
            let native = stream.into_std()?;
            let abort_socket = native.try_clone()?;
            let stream = NativeTcpStream::from_std(native)?;
            let state = Arc::new(Mutex::new(TcpState {
                stream: Some(stream),
                abort_socket: Some(abort_socket),
                read_waker: None,
                write_waker: None,
            }));
            let abort_state = state.clone();
            let abort = Arc::new(move || {
                let (stream, abort_socket, read_waker, write_waker) = {
                    let mut state = abort_state.lock().unwrap();
                    if let Some(socket) = &state.abort_socket {
                        // SockRef borrows an owned clone. Closing both owners
                        // below makes zero-linger reset the actual connection.
                        if let Err(error) = socket2::SockRef::from(socket).set_linger(Some(Duration::ZERO)) {
                            tracing::debug!("could not set test TCP abort linger: {error}");
                        }
                    }
                    (state.stream.take(), state.abort_socket.take(), state.read_waker.take(), state.write_waker.take())
                };
                drop(stream);
                drop(abort_socket);
                if let Some(waker) = read_waker {
                    waker.wake();
                }
                if let Some(waker) = write_waker {
                    waker.wake();
                }
            });
            Ok(TcpStream::new(TestTcpStream(state), local, peer, abort))
        })
    }

    fn connect_udp(&self, peer: SocketAddr) -> IoFuture<'_, UdpSocket> {
        Box::pin(async move { Ok(UdpSocket(Arc::new(ConnectedUdp(connected_udp_native(peer).await?)))) })
    }

    fn available(&self) -> bool {
        true
    }

    fn failed(&self) -> IoFuture<'_, ()> {
        Box::pin(std::future::pending())
    }
}

struct TcpState {
    stream: Option<NativeTcpStream>,
    abort_socket: Option<std::net::TcpStream>,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

struct TestTcpStream(Arc<Mutex<TcpState>>);

impl Drop for TestTcpStream {
    fn drop(&mut self) {
        let (stream, abort_socket) = {
            let mut state = self.0.lock().unwrap();
            state.read_waker = None;
            state.write_waker = None;
            (state.stream.take(), state.abort_socket.take())
        };
        // A retained abort handle must not keep a normally dropped stream open.
        drop(stream);
        drop(abort_socket);
    }
}

impl TestTcpStream {
    fn poll_io<T>(
        &self,
        cx: &mut Context<'_>,
        reading: bool,
        poll: impl FnOnce(&mut NativeTcpStream, &mut Context<'_>) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        let mut state = self.0.lock().unwrap();
        let Some(stream) = state.stream.as_mut() else {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionAborted, "test TCP connection aborted")));
        };
        let result = poll(stream, cx);
        let waker = if reading { &mut state.read_waker } else { &mut state.write_waker };
        *waker = result.is_pending().then(|| cx.waker().clone());
        result
    }
}

impl AsyncRead for TestTcpStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.poll_io(cx, true, |stream, cx| Pin::new(stream).poll_read(cx, buf))
    }
}

impl AsyncWrite for TestTcpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.poll_io(cx, false, |stream, cx| Pin::new(stream).poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_io(cx, false, |stream, cx| Pin::new(stream).poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_io(cx, false, |stream, cx| Pin::new(stream).poll_shutdown(cx))
    }
}

/// The same native socket used by the fixture, exposed for option assertions.
pub async fn connected_udp_native(peer: SocketAddr) -> io::Result<NativeUdpSocket> {
    let peer = loopback_peer(peer)?;
    let local: IpAddr = if peer.is_ipv6() { Ipv6Addr::UNSPECIFIED.into() } else { Ipv4Addr::UNSPECIFIED.into() };
    let socket = NativeUdpSocket::bind(SocketAddr::new(local, 0)).await?;
    socket.connect(peer).await?;
    sys::no_udp_fragmentation(socket2::SockRef::from(&socket), peer.is_ipv6())?;
    sys::grow_buffers(socket2::SockRef::from(&socket), UDP_BUFFER);
    Ok(socket)
}

struct ConnectedUdp(NativeUdpSocket);

impl DatagramIo for ConnectedUdp {
    fn send<'a>(&'a self, data: &'a [u8]) -> IoFuture<'a, usize> {
        Box::pin(self.0.send(data))
    }

    fn recv<'a>(&'a self, data: &'a mut [u8]) -> IoFuture<'a, usize> {
        Box::pin(self.0.recv(data))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.0.peer_addr()
    }

    fn max_payload(&self) -> usize {
        UDP_MAX_PAYLOAD
    }
}
