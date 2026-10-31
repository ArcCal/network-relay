//! Business flows intentionally remain open for the entire soak clock.
use super::relay::{TestRelay, PASSWORD, USER, WAIT};
use anyhow::{ensure, Context, Result};
use bytes::{Buf, Bytes};
use http::{Method, Request, StatusCode};
use http_body_util::Empty;
use hyper_util::rt::TokioIo;
use network_relay::{
    auth, check,
    tunnel::{Event, Tunnel},
};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

enum TcpMode {
    Upgraded { stream: Box<dyn warp_masque_egress::egress::IoStream>, _driver: check::AbortOnDrop },
    H3 { stream: Box<check::H3ClientStream>, _client: Box<check::H3> },
}
pub struct PersistentTcp {
    inbound: &'static str,
    mode: TcpMode,
    opened: Instant,
    pings: u64,
    hash: Sha256,
}
fn request() -> http::request::Builder {
    Request::builder()
        .method(Method::CONNECT)
        .uri("fixture.test:7")
        .header("host", "fixture.test:7")
        .header("proxy-authorization", auth::basic_authorization(USER, PASSWORD))
}
fn payload(sequence: u64, size: usize) -> Vec<u8> {
    let mut bytes = vec![0; size];
    for (offset, byte) in bytes.iter_mut().enumerate() {
        *byte = (sequence.wrapping_mul(71) ^ (offset as u64).wrapping_mul(53) ^ ((offset as u64) >> 5)) as u8;
    }
    bytes[..8].copy_from_slice(&sequence.to_be_bytes());
    bytes
}
impl PersistentTcp {
    pub async fn open(relay: &TestRelay, inbound: &'static str) -> Result<Self> {
        let opts = relay.options();
        let mode = match inbound {
            "h1" => {
                let (mut sender, driver) = check::h1_sender(&opts, &opts.addresses).await?;
                let mut response = sender.send_request(request().body(Empty::<Bytes>::new())?).await?;
                ensure!(response.status() == StatusCode::OK, "persistent H1 CONNECT refused");
                TcpMode::Upgraded {
                    stream: Box::new(TokioIo::new(hyper::upgrade::on(&mut response).await?)),
                    _driver: driver,
                }
            }
            "h2" => {
                let (mut sender, driver) = check::h2_sender(&opts, &opts.addresses).await?;
                let mut response = sender.send_request(request().body(Empty::<Bytes>::new())?).await?;
                ensure!(response.status() == StatusCode::OK, "persistent H2 CONNECT refused");
                TcpMode::Upgraded {
                    stream: Box::new(TokioIo::new(hyper::upgrade::on(&mut response).await?)),
                    _driver: driver,
                }
            }
            "h3" => {
                let mut client = check::H3::connect(&opts, &opts.addresses).await?;
                let mut stream = client.request(request().body(())?).await?;
                ensure!(stream.recv_response().await?.status() == StatusCode::OK, "persistent H3 CONNECT refused");
                TcpMode::H3 { stream: Box::new(stream), _client: Box::new(client) }
            }
            _ => unreachable!(),
        };
        Ok(Self { inbound, mode, opened: Instant::now(), pings: 0, hash: Sha256::new() })
    }
    pub async fn ping(&mut self, sequence: u64) -> Result<()> {
        let bytes = payload(sequence, 4096);
        let expected = bytes.clone();
        let echoed = tokio::time::timeout(WAIT, async {
            match &mut self.mode {
                TcpMode::Upgraded { stream, .. } => {
                    stream.write_all(&bytes).await?;
                    stream.flush().await?;
                    let mut echo = vec![0; bytes.len()];
                    stream.read_exact(&mut echo).await?;
                    Ok::<_, anyhow::Error>(echo)
                }
                TcpMode::H3 { stream, .. } => {
                    stream.send_data(Bytes::from(bytes)).await?;
                    let mut echo = Vec::with_capacity(expected.len());
                    while echo.len() < expected.len() {
                        let mut chunk = stream.recv_data().await?.context("persistent H3 stream ended")?;
                        while chunk.has_remaining() {
                            let count = chunk.chunk().len();
                            echo.extend_from_slice(chunk.chunk());
                            chunk.advance(count);
                        }
                        ensure!(echo.len() <= expected.len(), "persistent H3 echoed extra bytes");
                    }
                    Ok(echo)
                }
            }
        })
        .await
        .context("persistent TCP sequence echo timed out")??;
        ensure!(echoed == expected, "persistent {} TCP sequence/hash corrupted", self.inbound);
        self.hash.update(&echoed);
        self.pings += 1;
        Ok(())
    }
    pub fn metrics(&self) -> serde_json::Value {
        serde_json::json!({"inbound": self.inbound, "age_seconds": self.opened.elapsed().as_secs_f64(), "pings": self.pings, "echo_bytes": self.pings * 4096, "sha256": format!("{:x}", self.hash.clone().finalize())})
    }
}

#[allow(dead_code)] // Fields retain the real connection and datagram task.
enum UdpOwner {
    Upgraded(check::AbortOnDrop),
    H3 { client: check::H3, filter: check::AbortOnDrop },
}
pub struct PersistentUdp {
    inbound: &'static str,
    tunnel: Tunnel,
    _owner: UdpOwner,
    opened: Instant,
    pings: u64,
}
impl PersistentUdp {
    pub async fn open(relay: &TestRelay, inbound: &'static str) -> Result<Self> {
        let opts = relay.options();
        let path = "/.well-known/masque/udp/fixture.test/7/";
        let uri = format!("https://relay.test:{}{path}", opts.port);
        let credentials = auth::basic_authorization(USER, PASSWORD);
        let (tunnel, owner) = match inbound {
            "h1" => {
                let (mut sender, driver) = check::h1_sender(&opts, &opts.addresses).await?;
                let req = Request::builder()
                    .method(Method::GET)
                    .uri(path)
                    .header("host", format!("relay.test:{}", opts.port))
                    .header("connection", "Upgrade")
                    .header("upgrade", "connect-udp")
                    .header("capsule-protocol", "?1")
                    .header("authorization", credentials)
                    .body(Empty::<Bytes>::new())?;
                let mut response = sender.send_request(req).await?;
                ensure!(response.status() == StatusCode::SWITCHING_PROTOCOLS, "persistent H1 UDP upgrade refused");
                (Tunnel::upgraded(hyper::upgrade::on(&mut response).await?), UdpOwner::Upgraded(driver))
            }
            "h2" => {
                let (mut sender, driver) = check::h2_sender(&opts, &opts.addresses).await?;
                let req = Request::builder()
                    .method(Method::CONNECT)
                    .uri(uri)
                    .header("capsule-protocol", "?1")
                    .header("authorization", credentials)
                    .extension(hyper::ext::Protocol::from_static("connect-udp"))
                    .body(Empty::<Bytes>::new())?;
                let mut response = sender.send_request(req).await?;
                ensure!(response.status() == StatusCode::OK, "persistent H2 UDP CONNECT refused");
                (Tunnel::upgraded(hyper::upgrade::on(&mut response).await?), UdpOwner::Upgraded(driver))
            }
            "h3" => {
                let mut client = check::H3::connect(&opts, &opts.addresses).await?;
                let req = Request::builder()
                    .method(Method::CONNECT)
                    .uri(uri)
                    .header("capsule-protocol", "?1")
                    .header("authorization", credentials)
                    .extension(h3::ext::Protocol::CONNECT_UDP)
                    .body(())?;
                let mut stream = client.request(req).await?;
                ensure!(stream.recv_response().await?.status() == StatusCode::OK, "persistent H3 UDP CONNECT refused");
                let (tunnel, filter) = client.udp_tunnel(stream);
                (tunnel, UdpOwner::H3 { client, filter })
            }
            _ => unreachable!(),
        };
        Ok(Self { inbound, tunnel, _owner: owner, opened: Instant::now(), pings: 0 })
    }
    pub async fn ping(&mut self, sequence: u64) -> Result<()> {
        let bytes = payload(sequence, 512);
        let wire = network_relay::proto::datagram::udp_payload(&bytes);
        tokio::time::timeout(WAIT, async {
            for _ in 0..3 {
                self.tunnel.send_datagram(wire.clone())?;
                let deadline = tokio::time::sleep(Duration::from_secs(1));
                tokio::pin!(deadline);
                loop {
                    tokio::select! {
                        event = self.tunnel.next_event() => match event? {
                            Event::Closed => anyhow::bail!("persistent UDP tunnel closed"),
                            Event::Datagram(data) => { let (context, got) = network_relay::proto::datagram::split_context_id(&data)?; if context == 0 && got == bytes { return Ok::<_, anyhow::Error>(()); } }
                        },
                        _ = &mut deadline => break,
                    }
                }
            }
            anyhow::bail!("persistent UDP sequence echo missing")
        }).await.context("persistent UDP deadline")??;
        self.pings += 1;
        Ok(())
    }
    pub fn metrics(&self) -> serde_json::Value {
        serde_json::json!({"inbound": self.inbound, "age_seconds": self.opened.elapsed().as_secs_f64(), "pings": self.pings, "echo_bytes": self.pings * 512})
    }
}

/// The business flows run on their own cadence so a bulk transfer or metric
/// sample cannot let a standard client's 30-second QUIC idle timer expire.
pub struct PersistentFlows {
    tasks: tokio::task::JoinSet<Result<()>>,
    tcp: Vec<tokio::sync::watch::Receiver<serde_json::Value>>,
    udp: Vec<tokio::sync::watch::Receiver<serde_json::Value>>,
    stop: tokio::sync::watch::Sender<bool>,
}
impl PersistentFlows {
    pub async fn start(relay: &TestRelay) -> Result<Self> {
        let (stop, _) = tokio::sync::watch::channel(false);
        let mut owner = Self { tasks: tokio::task::JoinSet::new(), tcp: Vec::new(), udp: Vec::new(), stop };
        for inbound in ["h1", "h2", "h3"] {
            let mut stream = PersistentTcp::open(relay, inbound).await?;
            stream.ping(0).await?;
            let (metrics, receive) = tokio::sync::watch::channel(stream.metrics());
            owner.tcp.push(receive);
            let mut stopped = owner.stop.subscribe();
            owner.tasks.spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(10));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                let mut sequence = 1;
                loop {
                    tokio::select! {
                        _ = stopped.changed() => return Ok(()),
                        _ = tick.tick() => {
                            stream.ping(sequence).await.with_context(|| format!("persistent {inbound} TCP"))?;
                            metrics.send_replace(stream.metrics());
                            sequence += 1;
                        }
                    }
                }
            });
            let mut flow = PersistentUdp::open(relay, inbound).await?;
            flow.ping(0).await?;
            let (metrics, receive) = tokio::sync::watch::channel(flow.metrics());
            owner.udp.push(receive);
            let mut stopped = owner.stop.subscribe();
            owner.tasks.spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(10));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                let mut sequence = 1;
                loop {
                    tokio::select! {
                        _ = stopped.changed() => return Ok(()),
                        _ = tick.tick() => {
                            flow.ping(sequence).await.with_context(|| format!("persistent {inbound} UDP"))?;
                            metrics.send_replace(flow.metrics());
                            sequence += 1;
                        }
                    }
                }
            });
        }
        Ok(owner)
    }
    pub fn check(&mut self) -> Result<()> {
        if let Some(result) = self.tasks.try_join_next() {
            result??;
            anyhow::bail!("a persistent flow worker ended before the soak clock");
        }
        Ok(())
    }
    pub fn tcp_metrics(&self) -> Vec<serde_json::Value> {
        self.tcp.iter().map(|value| value.borrow().clone()).collect()
    }
    pub fn udp_metrics(&self) -> Vec<serde_json::Value> {
        self.udp.iter().map(|value| value.borrow().clone()).collect()
    }
    pub async fn shutdown(mut self) -> Result<()> {
        self.stop.send_replace(true);
        let joined = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(result) = self.tasks.join_next().await {
                result??;
            }
            Ok::<(), anyhow::Error>(())
        })
        .await;
        match joined {
            Ok(result) => result,
            Err(_) => {
                self.tasks.shutdown().await;
                Ok(())
            }
        }
    }
}
