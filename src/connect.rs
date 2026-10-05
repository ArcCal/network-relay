//! Opening connections to destinations.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinSet;

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
        _ => Refusal::Unreachable(e.to_string()),
    }
}

/// Connects to the first address that answers, racing them as Happy
/// Eyeballs does (RFC 8305), within `timeout` overall.
pub async fn tcp(addrs: &[SocketAddr], timeout: Duration) -> Result<TcpStream, Refusal> {
    let mut pending = interleave(addrs).into_iter().peekable();
    let deadline = tokio::time::Instant::now() + timeout;
    let mut attempts = JoinSet::new();
    let mut last_error = None;
    loop {
        if attempts.is_empty() {
            match pending.next() {
                Some(addr) => {
                    attempts.spawn(TcpStream::connect(addr));
                }
                None => return Err(last_error.map_or(Refusal::NoAddresses, |e| refusal(&e))),
            }
        }
        let more = pending.peek().is_some();
        tokio::select! {
            joined = attempts.join_next() => match joined {
                Some(Ok(Ok(stream))) => {
                    if let Err(e) = sys::tune_target_tcp(socket2::SockRef::from(&stream)) {
                        tracing::debug!("could not set TCP options: {e}");
                    }
                    return Ok(stream);
                }
                Some(Ok(Err(e))) => {
                    last_error = Some(e);
                    // A failed attempt starts the next one at once (§5).
                    if let Some(addr) = pending.next() {
                        attempts.spawn(TcpStream::connect(addr));
                    }
                }
                Some(Err(e)) => last_error = Some(io::Error::other(e)),
                None => {}
            },
            _ = tokio::time::sleep(ATTEMPT_DELAY), if more => {
                if let Some(addr) = pending.next() {
                    attempts.spawn(TcpStream::connect(addr));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
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
}
