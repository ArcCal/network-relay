//! One fixed-transport WARP session. Only this module's tunnel opens host
//! sockets; business traffic and DNS exclusively use the userspace stack.
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use serde::Serialize;
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tokio::task::{JoinHandle, JoinSet};

use crate::config::WarpConfig;
use crate::dns::Resolver;
use crate::egress::{DatagramIo, Egress, IoFuture, TcpStream, UdpSocket};
use crate::masque::{Sent, Tunnel};
use crate::netstack::{self, NetStack};

const PACKET_QUEUE: usize = 256;

#[derive(Default)]
struct Counters {
    sent_bytes: AtomicU64,
    received_bytes: AtomicU64,
    inbound_queue_drops: AtomicU64,
    workers: AtomicUsize,
}

struct Owner {
    stack: NetStack,
    resolver: Resolver,
    tunnel: Arc<Tunnel>,
    workers: Mutex<Vec<JoinHandle<()>>>,
    counters: Arc<Counters>,
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.stack.fail("the final egress controller was dropped");
        for worker in self.workers.get_mut().unwrap_or_else(|e| e.into_inner()) {
            worker.abort();
        }
    }
}

/// Cloneable controller for one session generation. Streams retain socket
/// state but do not retain this owner, so controller drop always fails them.
#[derive(Clone)]
pub struct WarpEgress(Arc<Owner>);

/// Safe to serialize: no enrollment token, device key, pin or peer headers.
#[derive(Debug, Serialize)]
pub struct WarpStatus {
    pub available: bool,
    pub transport: String,
    pub generation: u64,
    pub mtu: usize,
    pub ipv4: bool,
    pub ipv6: bool,
    pub tunnel_addresses: Vec<IpAddr>,
    pub sockets: usize,
    pub lingering_sockets: usize,
    pub socket_limit: usize,
    pub tcp_buffer_bytes_per_socket: usize,
    pub workers: usize,
    pub sent_packets: u64,
    pub received_packets: u64,
    pub dropped_packets: u64,
    pub sent_ip_bytes: u64,
    pub received_ip_bytes: u64,
    pub stack_queue_drops: u64,
    pub inbound_queue_drops: u64,
    pub failure: Option<String>,
}

impl WarpEgress {
    #[cfg(feature = "test-support")]
    pub fn tcp_snapshot(&self) -> Vec<netstack::TcpSnapshot> {
        self.0.stack.tcp_snapshot()
    }

    pub async fn connect(config: &WarpConfig) -> Result<Self> {
        config.validate()?;
        let options = config.options()?;
        let tunnel = Arc::new(Tunnel::connect(&options).await?);
        let stack = NetStack::new(0);
        stack.set_addresses(&config.addresses()?);
        fit_mtu(&stack, &tunnel)?;
        let resolver = Resolver::new(stack.clone(), config.dns_servers().to_vec());
        let counters = Arc::new(Counters::default());
        let (to_stack, incoming) = mpsc::channel(PACKET_QUEUE);
        let (outgoing, from_stack) = mpsc::channel(PACKET_QUEUE);
        let worker_stack = stack.clone();
        let worker_tunnel = tunnel.clone();
        let worker_counters = counters.clone();
        let worker = tokio::spawn(async move {
            let _worker_count = WorkerCount::new(worker_counters.clone());
            let mut tasks = JoinSet::new();
            let runner = worker_stack.clone();
            let runner_counters = worker_counters.clone();
            tasks.spawn(async move {
                let _worker_count = WorkerCount::new(runner_counters);
                runner.run(incoming, outgoing).await
            });
            // Declared after the task set: reverse drop order publishes
            // terminal state before nested tasks/channels are destroyed.
            let _guard = FailureGuard(worker_stack.clone());
            let why = tokio::select! {
                why = pump(&worker_stack, &worker_tunnel, to_stack, from_stack, &worker_counters) => why,
                result = tasks.join_next() => match result {
                    Some(Ok(())) => "the userspace packet runner stopped".into(),
                    Some(Err(_)) => "the userspace packet runner failed".into(),
                    None => "the userspace packet runner disappeared".into(),
                },
                why = worker_stack.closed() => why,
            };
            worker_stack.fail(why);
            tasks.shutdown().await; // abort and observe the owned runner
            worker_tunnel.shutdown().await;
        });
        Ok(Self(Arc::new(Owner { stack, resolver, tunnel, workers: Mutex::new(vec![worker]), counters })))
    }

    pub fn status(&self) -> WarpStatus {
        let owner = &self.0;
        let capabilities = address_capabilities(&owner.stack);
        let workers = owner.counters.workers.load(Ordering::Relaxed);
        let (sockets, lingering_sockets) = owner.stack.socket_counts();
        WarpStatus {
            available: capabilities.available,
            transport: owner.tunnel.transport().into(),
            generation: 1,
            mtu: capabilities.mtu,
            ipv4: capabilities.ipv4,
            ipv6: capabilities.ipv6,
            tunnel_addresses: capabilities.addresses,
            sockets,
            lingering_sockets,
            socket_limit: owner.stack.socket_limit(),
            tcp_buffer_bytes_per_socket: owner.stack.tcp_buffer_bytes(),
            workers,
            sent_packets: owner.tunnel.sent.load(Ordering::Relaxed),
            received_packets: owner.tunnel.received.load(Ordering::Relaxed),
            dropped_packets: owner.tunnel.dropped.load(Ordering::Relaxed),
            sent_ip_bytes: owner.counters.sent_bytes.load(Ordering::Relaxed),
            received_ip_bytes: owner.counters.received_bytes.load(Ordering::Relaxed),
            stack_queue_drops: owner.stack.queue_drops(),
            inbound_queue_drops: owner.counters.inbound_queue_drops.load(Ordering::Relaxed),
            failure: owner.stack.failure_reason(),
        }
    }

    pub async fn closed(&self) -> String {
        self.0.stack.closed().await
    }

    /// Idempotent shutdown; nested workers are observed or aborted within a
    /// bound. This invalidates existing operations before waiting for close.
    pub async fn shutdown(&self) {
        self.0.stack.fail("egress was shut down");
        let workers = std::mem::take(&mut *self.0.workers.lock().unwrap_or_else(|e| e.into_inner()));
        for mut worker in workers {
            if tokio::time::timeout(Duration::from_secs(5), &mut worker).await.is_err() {
                worker.abort();
                let _ = worker.await;
            }
        }
        self.0.tunnel.shutdown().await;
    }
}

struct AddressCapabilities {
    available: bool,
    mtu: usize,
    ipv4: bool,
    ipv6: bool,
    addresses: Vec<IpAddr>,
}

fn address_capabilities(stack: &NetStack) -> AddressCapabilities {
    let (available, mtu, addresses) = stack.address_snapshot();
    AddressCapabilities {
        available,
        mtu,
        ipv4: available && addresses.iter().any(IpAddr::is_ipv4),
        ipv6: available && mtu >= netstack::MTU && addresses.iter().any(IpAddr::is_ipv6),
        addresses,
    }
}

impl Egress for WarpEgress {
    fn resolve<'a>(&'a self, host: &'a str) -> IoFuture<'a, Vec<IpAddr>> {
        Box::pin(async move {
            self.0.stack.check_available()?;
            self.0.resolver.lookup(host).await.map_err(|error| {
                let kind = match error {
                    crate::dns::LookupError::InvalidName => io::ErrorKind::InvalidInput,
                    crate::dns::LookupError::NotFound => io::ErrorKind::NotFound,
                    crate::dns::LookupError::NoAnswer => io::ErrorKind::TimedOut,
                    crate::dns::LookupError::Unavailable => io::ErrorKind::ConnectionAborted,
                };
                io::Error::new(kind, error.to_string())
            })
        })
    }

    fn connect_tcp(&self, peer: SocketAddr) -> IoFuture<'_, TcpStream> {
        Box::pin(async move {
            let peer = canonical(peer);
            self.0.stack.check_available()?;
            let stream = self.0.stack.connect(peer).await?;
            let local = stream.local_addr().ok_or(io::ErrorKind::AddrNotAvailable)?;
            let actual_peer = stream.peer_addr().ok_or(io::ErrorKind::AddrNotAvailable)?;
            let abort = stream.abort_handle();
            Ok(TcpStream::new(stream, local, actual_peer, abort))
        })
    }

    fn connect_udp(&self, peer: SocketAddr) -> IoFuture<'_, UdpSocket> {
        Box::pin(async move {
            let peer = canonical(peer);
            let source = self.0.stack.local_address(peer.ip())?;
            let socket = self.0.stack.bind_udp(0)?;
            let local = SocketAddr::new(source, socket.port());
            Ok(UdpSocket(Arc::new(ConnectedUdp {
                socket,
                stack: self.0.stack.clone(),
                peer,
                local,
                read: AsyncMutex::new(()),
                write: AsyncMutex::new(()),
            })))
        })
    }

    fn available(&self) -> bool {
        self.0.stack.check_available().is_ok()
    }

    fn failed(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            self.0.stack.closed().await;
        })
    }
}

fn canonical(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}

struct ConnectedUdp {
    socket: netstack::UdpSocket,
    stack: NetStack,
    peer: SocketAddr,
    local: SocketAddr,
    read: AsyncMutex<()>,
    write: AsyncMutex<()>,
}

impl DatagramIo for ConnectedUdp {
    fn send<'a>(&'a self, data: &'a [u8]) -> IoFuture<'a, usize> {
        Box::pin(async move {
            // Only one task may own smoltcp's send waker at a time.
            let _write = tokio::select! {
                lock = self.write.lock() => lock,
                _ = self.stack.closed() => return Err(self.stack.check_available().err().unwrap_or_else(|| io::ErrorKind::NotConnected.into())),
            };
            self.stack.check_available()?;
            self.socket.send_to(data, self.peer).await?;
            Ok(data.len())
        })
    }

    fn recv<'a>(&'a self, data: &'a mut [u8]) -> IoFuture<'a, usize> {
        Box::pin(async move {
            let _read = tokio::select! {
                lock = self.read.lock() => lock,
                _ = self.stack.closed() => return Err(self.stack.check_available().err().unwrap_or_else(|| io::ErrorKind::NotConnected.into())),
            };
            let mut ignored = 0;
            loop {
                let (packet, source) = self.socket.recv_from_family(Some(self.peer.ip())).await?;
                if canonical(source) != self.peer {
                    ignored += 1;
                    if ignored % 32 == 0 {
                        tokio::task::yield_now().await;
                    }
                    continue;
                }
                if packet.len() > data.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "the UDP receive buffer is smaller than the datagram",
                    ));
                }
                data[..packet.len()].copy_from_slice(&packet);
                return Ok(packet.len());
            }
        })
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer)
    }
    fn max_payload(&self) -> usize {
        netstack::max_udp_payload(self.stack.mtu(), self.peer.is_ipv4())
    }
}

struct FailureGuard(NetStack);
impl Drop for FailureGuard {
    fn drop(&mut self) {
        self.0.fail("the egress worker stopped");
    }
}

struct WorkerCount(Arc<Counters>);
impl WorkerCount {
    fn new(counters: Arc<Counters>) -> Self {
        counters.workers.fetch_add(1, Ordering::Relaxed);
        Self(counters)
    }
}
impl Drop for WorkerCount {
    fn drop(&mut self) {
        self.0.workers.fetch_sub(1, Ordering::Relaxed);
    }
}

fn fit_mtu(stack: &NetStack, tunnel: &Tunnel) -> Result<()> {
    let mtu = tunnel.max_packet().unwrap_or(netstack::MTU);
    anyhow::ensure!(mtu >= 576, "the tunnel path cannot carry the IPv4 minimum MTU");
    stack.set_mtu(mtu);
    Ok(())
}

async fn pump(
    stack: &NetStack,
    tunnel: &Tunnel,
    to_stack: mpsc::Sender<Bytes>,
    mut from_stack: mpsc::Receiver<Bytes>,
    counters: &Counters,
) -> String {
    let outbound = async {
        let mut mtu_tick = tokio::time::interval(Duration::from_millis(500));
        loop {
            tokio::select! {
                packet = from_stack.recv() => {
                    let Some(packet) = packet else { return "the stack output ended".into() };
                    match tunnel.send_packet(&packet) {
                        Ok(Sent::Yes) => { counters.sent_bytes.fetch_add(packet.len() as u64, Ordering::Relaxed); },
                        Ok(Sent::TooLarge(_)) => if let Err(error) = fit_mtu(stack, tunnel) { return error.to_string(); },
                        Ok(Sent::QueueFull) => {},
                        Err(error) => return error.to_string(),
                    }
                },
                _ = mtu_tick.tick() => if let Err(error) = fit_mtu(stack, tunnel) { return error.to_string(); },
            }
        }
    };
    let inbound = async {
        loop {
            match tunnel.recv_packet().await {
                Ok(packet) => {
                    counters.received_bytes.fetch_add(packet.len() as u64, Ordering::Relaxed);
                    match to_stack.try_send(packet) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            counters.inbound_queue_drops.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => return "the stack input ended".into(),
                    }
                }
                Err(error) => return error.to_string(),
            }
        }
    };
    tokio::select! {
        why = outbound => why,
        why = inbound => why,
        why = tunnel.closed() => why,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_retains_assigned_addresses_across_mtu_loss_and_restoration() {
        let stack = NetStack::new(0);
        let assigned = ["192.0.2.1".parse().unwrap(), "fd00::1".parse().unwrap()];
        stack.set_addresses(&assigned);
        let initial = address_capabilities(&stack);
        assert!(initial.available && initial.ipv4 && initial.ipv6);
        assert_eq!(initial.addresses, assigned);

        assert!(stack.set_mtu(1200));
        let reduced = address_capabilities(&stack);
        assert_eq!(reduced.mtu, 1200);
        assert!(reduced.available && reduced.ipv4);
        assert!(!reduced.ipv6);
        assert_eq!(reduced.addresses, assigned);
        assert!(stack.local_address(assigned[1]).is_err());

        assert!(stack.set_mtu(netstack::MTU));
        let restored = address_capabilities(&stack);
        assert!(restored.available && restored.ipv4 && restored.ipv6);
        assert_eq!(restored.addresses, assigned);
        assert_eq!(stack.local_address(assigned[1]).unwrap(), assigned[1]);

        stack.fail("status fixture ended");
        let stopped = address_capabilities(&stack);
        assert!(!stopped.available && !stopped.ipv4 && !stopped.ipv6);
        assert_eq!(stopped.addresses, assigned);
    }

    fn connected(stack: &NetStack, peer: SocketAddr) -> Arc<ConnectedUdp> {
        let socket = stack.bind_udp(0).unwrap();
        let local = SocketAddr::new(stack.local_address(peer.ip()).unwrap(), socket.port());
        Arc::new(ConnectedUdp {
            socket,
            stack: stack.clone(),
            peer,
            local,
            read: AsyncMutex::new(()),
            write: AsyncMutex::new(()),
        })
    }

    #[tokio::test]
    async fn ipv6_udp_receive_wakes_when_the_path_loses_minimum_mtu() {
        use std::future::{poll_fn, Future};
        let stack = NetStack::new(0);
        stack.set_addresses(&["fd00::1".parse().unwrap()]);
        let socket = connected(&stack, "[fd00::2]:7".parse().unwrap());
        let waiting = socket.clone();
        let (ready, registered) = tokio::sync::oneshot::channel();
        let receiver = tokio::spawn(async move {
            let mut data = [0u8; 1];
            let mut receive = std::pin::pin!(waiting.recv(&mut data));
            let mut ready = Some(ready);
            poll_fn(|cx| {
                let result = receive.as_mut().poll(cx);
                if result.is_pending() {
                    if let Some(ready) = ready.take() {
                        let _ = ready.send(());
                    }
                }
                result
            })
            .await
        });
        registered.await.unwrap();
        stack.set_mtu(1200);
        let error = tokio::time::timeout(Duration::from_secs(1), receiver)
            .await
            .expect("MTU change did not wake the IPv6 receive")
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NetworkUnreachable);
        assert_eq!(socket.send(b"x").await.unwrap_err().kind(), io::ErrorKind::NetworkUnreachable);
    }

    #[tokio::test]
    async fn connected_udp_pins_peer_preserves_empty_and_large_datagrams_and_fails_terminally() {
        let client = NetStack::new(0);
        let server = NetStack::new(0);
        client.set_addresses(&["192.0.2.1".parse().unwrap(), "fd00::1".parse().unwrap()]);
        server.set_addresses(&["192.0.2.2".parse().unwrap(), "fd00::2".parse().unwrap()]);
        let (to_server, from_client) = mpsc::channel(PACKET_QUEUE);
        let (to_client, from_server) = mpsc::channel(PACKET_QUEUE);
        let mut tasks = JoinSet::new();
        let (c, s) = (client.clone(), server.clone());
        tasks.spawn(async move { c.run(from_server, to_server).await });
        tasks.spawn(async move { s.run(from_client, to_client).await });
        let peer = server.bind_udp(7).unwrap();
        let stray = server.bind_udp(8).unwrap();
        for address in ["192.0.2.2:7", "[fd00::2]:7"] {
            let flow = connected(&client, address.parse().unwrap());
            flow.send(b"first").await.unwrap();
            let (packet, source) = peer.recv_from().await.unwrap();
            assert_eq!(packet.as_ref(), b"first");
            stray.send_to(b"forged", source).await.unwrap();
            peer.send_to(b"verified", source).await.unwrap();
            let mut buffer = vec![0; 1280];
            let length = tokio::time::timeout(Duration::from_secs(1), flow.recv(&mut buffer)).await.unwrap().unwrap();
            assert_eq!(&buffer[..length], b"verified");
            for size in [0, 1, flow.max_payload()] {
                let data = vec![0x6d; size];
                assert_eq!(flow.send(&data).await.unwrap(), size);
                let (packet, source) = peer.recv_from().await.unwrap();
                assert_eq!(packet.as_ref(), data);
                peer.send_to(&packet, source).await.unwrap();
                let length =
                    tokio::time::timeout(Duration::from_secs(1), flow.recv(&mut buffer)).await.unwrap().unwrap();
                assert_eq!(&buffer[..length], data);
            }
            assert_eq!(
                flow.send(&vec![0; flow.max_payload() + 1]).await.unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        let flow = connected(&client, "192.0.2.2:7".parse().unwrap());
        let waiting = flow.clone();
        let (pending_tx, pending_rx) = tokio::sync::oneshot::channel();
        let receive = tokio::spawn(async move {
            use std::future::{poll_fn, Future};
            let mut data = [0u8; 32];
            let mut future = std::pin::pin!(waiting.recv(&mut data));
            let mut pending_tx = Some(pending_tx);
            poll_fn(|cx| {
                let result = future.as_mut().poll(cx);
                if result.is_pending() {
                    if let Some(tx) = pending_tx.take() {
                        let _ = tx.send(());
                    }
                }
                result
            })
            .await
        });
        pending_rx.await.unwrap();
        client.fail("UDP fixture tunnel died");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), receive).await.unwrap().unwrap().unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(flow.send(b"").await.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
    }
}
