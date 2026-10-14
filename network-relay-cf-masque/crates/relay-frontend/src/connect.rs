//! Opening policy-approved numeric destinations through the required egress.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinSet;
use warp_masque_egress::egress::{Egress, TcpStream, UdpSocket};

use crate::policy::Refusal;

/// Delay before trying the next address while an attempt is pending
/// (RFC 8305 §5 recommends 250 ms).
const ATTEMPT_DELAY: Duration = Duration::from_millis(250);

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

fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

fn unavailable() -> Refusal {
    Refusal::Unreachable("egress unavailable".into())
}

/// A successful racing attempt still belongs to the race until selected.
/// Discarding a completed loser must reset its connection.
struct Attempt(Option<TcpStream>);

impl Drop for Attempt {
    fn drop(&mut self) {
        if let Some(stream) = &self.0 {
            stream.abort();
        }
    }
}

async fn tcp_attempt(egress: Arc<dyn Egress>, addr: SocketAddr) -> io::Result<Attempt> {
    let stream = egress.connect_tcp(addr).await?;
    let attempt = Attempt(Some(stream));
    if !egress.available() {
        return Err(io::Error::new(io::ErrorKind::NotConnected, "egress unavailable"));
    }
    if canonical(attempt.0.as_ref().expect("owned stream").peer_addr()?) != canonical(addr) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "egress selected an unapproved destination"));
    }
    Ok(attempt)
}

/// Connects to the first address that answers, racing them as Happy
/// Eyeballs does (RFC 8305), within `timeout` overall. Every attempt belongs to
/// the injected egress; there is no host-network or resolver fallback.
pub async fn tcp(egress: Arc<dyn Egress>, addrs: &[SocketAddr], timeout: Duration) -> Result<TcpStream, Refusal> {
    if !egress.available() {
        return Err(unavailable());
    }
    let mut pending = interleave(addrs).into_iter().peekable();
    let deadline = tokio::time::Instant::now() + timeout;
    let mut attempts = JoinSet::new();
    let mut last_error = None;
    loop {
        if !egress.available() {
            return Err(unavailable());
        }
        if attempts.is_empty() {
            match pending.next() {
                Some(addr) => {
                    attempts.spawn(tcp_attempt(egress.clone(), addr));
                }
                None => return Err(last_error.map_or(Refusal::NoAddresses, |e| refusal(&e))),
            }
        }
        let more = pending.peek().is_some();
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(deadline) => return Err(Refusal::ConnectionTimeout),
            joined = attempts.join_next() => match joined {
                Some(Ok(Ok(mut attempt))) => {
                    if !egress.available() {
                        return Err(unavailable());
                    }
                    return Ok(attempt.0.take().expect("winning stream"));
                }
                Some(Ok(Err(e))) => {
                    last_error = Some(e);
                    // A failed attempt starts the next one at once (§5).
                    if let Some(addr) = pending.next() {
                        attempts.spawn(tcp_attempt(egress.clone(), addr));
                    }
                }
                Some(Err(e)) => last_error = Some(io::Error::other(e)),
                None => {}
            },
            _ = tokio::time::sleep(ATTEMPT_DELAY), if more => {
                if let Some(addr) = pending.next() {
                    attempts.spawn(tcp_attempt(egress.clone(), addr));
                }
            }
        }
    }
}

/// Opens a peer-pinned UDP flow to the first supported numeric address.
/// Opening selects a tunnel route; it does not establish destination liveness.
/// An asynchronous backend must finish opening within the overall deadline.
pub async fn udp(egress: Arc<dyn Egress>, addrs: &[SocketAddr], timeout: Duration) -> Result<UdpSocket, Refusal> {
    if !egress.available() {
        return Err(unavailable());
    }
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
                    return Err(Refusal::Unreachable("egress selected an unapproved destination".into()));
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
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;
    use warp_masque_egress::egress::IoFuture;

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

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

    impl FakeEgress {
        fn new(good: SocketAddr) -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::default(),
                unavailable: AtomicBool::new(false),
                good,
                returned_peer: good,
                pending: false,
                aborted: Arc::default(),
                cancelled: AtomicUsize::new(0),
                held: Mutex::default(),
            })
        }
    }

    struct PendingGuard<'a>(&'a AtomicUsize);

    impl Drop for PendingGuard<'_> {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl Egress for FakeEgress {
        fn resolve<'a>(&'a self, _: &'a str) -> IoFuture<'a, Vec<IpAddr>> {
            Box::pin(async { panic!("numeric dialing must never resolve") })
        }
        fn connect_tcp(&self, peer: SocketAddr) -> IoFuture<'_, TcpStream> {
            self.calls.lock().unwrap().push(peer);
            Box::pin(async move {
                if self.pending {
                    let _cancelled = PendingGuard(&self.cancelled);
                    return std::future::pending().await;
                }
                if peer != self.good {
                    return Err(io::ErrorKind::ConnectionRefused.into());
                }
                let (client, held) = tokio::io::duplex(64);
                self.held.lock().unwrap().push(held);
                let aborted = self.aborted.clone();
                Ok(TcpStream::new(
                    client,
                    a("192.0.2.2:12345"),
                    self.returned_peer,
                    Arc::new(move || {
                        aborted.fetch_add(1, Ordering::Relaxed);
                    }),
                ))
            })
        }
        fn connect_udp(&self, peer: SocketAddr) -> IoFuture<'_, UdpSocket> {
            self.calls.lock().unwrap().push(peer);
            Box::pin(async move {
                if self.pending {
                    let _cancelled = PendingGuard(&self.cancelled);
                    std::future::pending().await
                } else {
                    Err(io::ErrorKind::ConnectionRefused.into())
                }
            })
        }
        fn available(&self) -> bool {
            !self.unavailable.load(Ordering::Relaxed)
        }
        fn failed(&self) -> IoFuture<'_, ()> {
            Box::pin(std::future::pending())
        }
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
    async fn connects_to_the_injected_address_that_answers() {
        let bad = a("192.0.2.1:9");
        let good = a("192.0.2.2:9");
        let egress = FakeEgress::new(good);
        let stream = tcp(egress.clone(), &[bad, good], Duration::from_secs(5)).await.unwrap();
        assert_eq!(stream.peer_addr().unwrap(), good);
        assert_eq!(*egress.calls.lock().unwrap(), [bad, good]);
        assert_eq!(tcp(egress.clone(), &[bad], Duration::from_secs(5)).await.unwrap_err(), Refusal::ConnectionRefused);
        assert_eq!(egress.aborted.load(Ordering::Relaxed), 0, "winner must not be aborted");
    }

    #[tokio::test(start_paused = true)]
    async fn both_protocols_give_up_at_the_deadline() {
        let mut egress = FakeEgress::new(a("192.0.2.2:9"));
        Arc::get_mut(&mut egress).unwrap().pending = true;
        assert_eq!(
            tcp(egress.clone(), &[a("192.0.2.1:9")], Duration::from_millis(300)).await.unwrap_err(),
            Refusal::ConnectionTimeout
        );
        assert_eq!(
            udp(egress.clone(), &[a("192.0.2.1:9")], Duration::from_millis(300)).await.unwrap_err(),
            Refusal::ConnectionTimeout
        );
        tokio::task::yield_now().await;
        assert_eq!(egress.cancelled.load(Ordering::Relaxed), 2, "both pending backend opens are dropped");
    }

    #[tokio::test]
    async fn an_unapproved_peer_is_aborted_and_refused() {
        let requested = a("192.0.2.2:9");
        let mut egress = FakeEgress::new(requested);
        Arc::get_mut(&mut egress).unwrap().returned_peer = a("127.0.0.1:9");
        assert!(matches!(
            tcp(egress.clone(), &[requested], Duration::from_secs(1)).await,
            Err(Refusal::Unreachable(_))
        ));
        assert_eq!(egress.aborted.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn unavailable_egress_never_starts_an_attempt() {
        let egress = FakeEgress::new(a("192.0.2.2:9"));
        egress.unavailable.store(true, Ordering::Relaxed);
        assert!(matches!(
            tcp(egress.clone(), &[egress.good], Duration::from_secs(1)).await,
            Err(Refusal::Unreachable(_))
        ));
        assert!(matches!(
            udp(egress.clone(), &[egress.good], Duration::from_secs(1)).await,
            Err(Refusal::Unreachable(_))
        ));
        assert!(egress.calls.lock().unwrap().is_empty());
    }
}
