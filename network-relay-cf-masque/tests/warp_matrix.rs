//! End-to-end local protocol evidence. This fake WARP peer is not Cloudflare.
//! Every business connection crosses WarpEgress's real userspace packet pump.
mod support;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{ensure, Context, Result};
use bytes::{Buf, Bytes};
use http::{Method, Request, StatusCode};
use http_body_util::Empty;
use hyper_util::rt::TokioIo;
use network_relay::{auth, check};
use sha2::{Digest, Sha256};
use support::persistent::{PersistentFlows, PersistentTcp, PersistentUdp};
use support::relay::{TestEnv, TestRelay, PASSWORD, USER, WAIT};
use support::warp_peer::{peer_addr, WarpPeer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use warp_masque_egress::{Egress, Transport, WarpEgress};

const BULK_BYTES: usize = 64 << 20;
const CHUNK: usize = 64 << 10;

struct Fixture {
    _env: TestEnv,
    peer: WarpPeer,
    warp: Arc<WarpEgress>,
    relay: TestRelay,
}
impl Fixture {
    async fn start(transport: Transport) -> Result<Self> {
        let label = match transport {
            Transport::H2 => "h2",
            Transport::H3 => "h3",
        };
        let env = TestEnv::new(label)?;
        let peer = WarpPeer::start(transport).await?;
        let config = peer.config(&env.path)?;
        let warp = Arc::new(
            tokio::time::timeout(WAIT, WarpEgress::connect(&config)).await.context("WARP handshake deadline")??,
        );
        let relay = TestRelay::start(&env, warp.clone()).await?;
        Ok(Self { _env: env, peer, warp, relay })
    }
    async fn finish(mut self) -> Result<()> {
        self.relay.shutdown().await?;
        self.warp.shutdown().await;
        ensure!(!self.warp.available(), "shutdown left egress available");
        ensure!(self.warp.status().workers == 0, "egress workers survived shutdown");
        let _ = self.peer.shutdown().await;
        Ok(())
    }
}

fn transport_name(transport: Transport) -> &'static str {
    match transport {
        Transport::H2 => "h2",
        Transport::H3 => "h3",
    }
}

async fn standard_check(fixture: &Fixture) -> Result<Vec<serde_json::Value>> {
    let outcomes = check::run(&fixture.relay.options()).await;
    ensure!(outcomes.len() == 7, "standard check did not execute its seven checks");
    let mut rows = Vec::new();
    for outcome in outcomes {
        let detail = outcome.result.with_context(|| outcome.name)?;
        if outcome.name.contains("TCP") {
            ensure!(detail.contains("204 No Content"), "invalid HTTP origin response: {detail}");
        }
        if outcome.name.contains("UDP") {
            ensure!(
                detail.contains("rcode 0") && detail.contains("1 records"),
                "invalid tunneled DNS response: {detail}"
            );
        }
        rows.push(
            serde_json::json!({"check": outcome.name, "result": detail, "elapsed_ms": outcome.elapsed.as_millis()}),
        );
    }
    Ok(rows)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn six_inbound_warp_transport_pairings_use_real_packet_egress() -> Result<()> {
    let mut evidence = Vec::new();
    for transport in [Transport::H2, Transport::H3] {
        let fixture = Fixture::start(transport).await?;
        let before = fixture.peer.snapshot();
        let outcomes = standard_check(&fixture).await?;
        let after = fixture.peer.snapshot();
        ensure!(
            after.authenticated_clients == 1 && after.tunnels == 1,
            "peer did not authenticate exactly one pinned session"
        );
        ensure!(
            after.ip_packets_from_client > before.ip_packets_from_client
                && after.ip_packets_to_client > before.ip_packets_to_client,
            "checks bypassed IP packet tunnel"
        );
        ensure!(after.http_requests >= 3, "not every inbound TCP check reached peer HTTP server");
        ensure!(after.dns_queries >= 4, "business and CONNECT-UDP DNS did not cross peer stack");
        ensure!(
            fixture.peer.dns_queries().iter().any(|query| query.name == "fixture.test"),
            "no fixture DNS name observed inside tunnel"
        );
        ensure!(fixture.peer.errors().is_empty(), "peer errors: {:?}", fixture.peer.errors());
        let expected = match transport {
            Transport::H2 => "HTTP/2",
            Transport::H3 => "HTTP/3",
        };
        ensure!(fixture.warp.status().transport == expected, "transport silently changed");
        evidence.push(serde_json::json!({"warp_transport": transport_name(transport), "service": "local fake WARP protocol peer", "checks": outcomes, "peer": after, "egress": fixture.warp.status(), "process": process_metrics()}));
        fixture.finish().await?;
    }
    save_evidence(
        "functional-matrix",
        serde_json::json!({"pairings": 6, "live_cloudflare": false, "cases": evidence}),
    )?;
    Ok(())
}

fn connect_request(target: &str) -> http::request::Builder {
    Request::builder()
        .method(Method::CONNECT)
        .uri(target)
        .header("host", target)
        .header("proxy-authorization", auth::basic_authorization(USER, PASSWORD))
}

fn fill_pattern(buf: &mut [u8], offset: usize) {
    for (i, byte) in buf.iter_mut().enumerate() {
        let position = offset + i;
        *byte = ((position.wrapping_mul(73) ^ (position >> 7) ^ (position >> 19)) & 255) as u8;
    }
}
fn expected_hash(bytes: usize) -> String {
    let mut hash = Sha256::new();
    let mut buf = vec![0; CHUNK];
    for offset in (0..bytes).step_by(CHUNK) {
        let count = CHUNK.min(bytes - offset);
        fill_pattern(&mut buf[..count], offset);
        hash.update(&buf[..count]);
    }
    format!("{:x}", hash.finalize())
}

async fn echo_stream<S: AsyncRead + AsyncWrite + Unpin>(stream: S, bytes: usize) -> Result<String> {
    let (mut read, mut write) = tokio::io::split(stream);
    let sending = async {
        let mut buf = vec![0; CHUNK];
        for offset in (0..bytes).step_by(CHUNK) {
            let count = CHUNK.min(bytes - offset);
            fill_pattern(&mut buf[..count], offset);
            write.write_all(&buf[..count]).await?;
        }
        write.shutdown().await?; // The peer waits for this FIN before closing its half.
        Ok::<(), anyhow::Error>(())
    };
    let receiving = async {
        let mut hash = Sha256::new();
        let mut count = 0usize;
        let mut buf = vec![0; CHUNK];
        loop {
            let n = read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            count += n;
            ensure!(count <= bytes, "echo produced extra bytes");
            hash.update(&buf[..n]);
        }
        ensure!(count == bytes, "echo/half-close lost data: received {count}, expected {bytes}");
        Ok::<String, anyhow::Error>(format!("{:x}", hash.finalize()))
    };
    let (_, hash) = tokio::try_join!(sending, receiving)?;
    Ok(hash)
}

async fn bulk(fixture: &Fixture, inbound: &str, bytes: usize) -> Result<serde_json::Value> {
    let opts = fixture.relay.options();
    let target = "fixture.test:7";
    let started = Instant::now();
    let expected = expected_hash(bytes);
    let actual = match inbound {
        "h1" | "h2" => {
            // These are exactly the standard client's transport helpers.
            let mut response;
            let stream;
            if inbound == "h1" {
                let (mut sender, _driver) = check::h1_sender(&opts, &opts.addresses).await?;
                response = sender.send_request(connect_request(target).body(Empty::<Bytes>::new())?).await?;
                ensure!(response.status() == StatusCode::OK, "TCP CONNECT failed: {}", response.status());
                stream = TokioIo::new(hyper::upgrade::on(&mut response).await?);
                tokio::time::timeout(Duration::from_secs(240), echo_stream(stream, bytes))
                    .await
                    .context("H1 bulk deadline")??
            } else {
                let (mut sender, _driver) = check::h2_sender(&opts, &opts.addresses).await?;
                response = sender.send_request(connect_request(target).body(Empty::<Bytes>::new())?).await?;
                ensure!(response.status() == StatusCode::OK, "TCP CONNECT failed: {}", response.status());
                stream = TokioIo::new(hyper::upgrade::on(&mut response).await?);
                tokio::time::timeout(Duration::from_secs(240), echo_stream(stream, bytes))
                    .await
                    .context("H2 bulk deadline")??
            }
        }
        "h3" => {
            let mut client = check::H3::connect(&opts, &opts.addresses).await.context("H3 bulk connect client")?;
            let mut stream =
                client.request(connect_request(target).body(())?).await.context("H3 bulk request CONNECT")?;
            ensure!(
                stream.recv_response().await.context("H3 bulk receive CONNECT response")?.status() == StatusCode::OK,
                "H3 CONNECT failed"
            );
            let (mut send, mut recv) = stream.split();
            let sent = AtomicUsize::new(0);
            let received = AtomicUsize::new(0);
            let finished = AtomicBool::new(false);
            let received_eof = AtomicBool::new(false);
            let last_sent_ms = AtomicUsize::new(0);
            let last_received_ms = AtomicUsize::new(0);
            let writing = async {
                let mut buf = vec![0; CHUNK];
                for offset in (0..bytes).step_by(CHUNK) {
                    let count = CHUNK.min(bytes - offset);
                    fill_pattern(&mut buf[..count], offset);
                    send.send_data(Bytes::copy_from_slice(&buf[..count]))
                        .await
                        .with_context(|| format!("H3 bulk send DATA at {offset}"))?;
                    sent.fetch_add(count, Ordering::Relaxed);
                    last_sent_ms.store(started.elapsed().as_millis() as usize, Ordering::Relaxed);
                }
                send.finish().await.context("H3 bulk send FIN")?;
                finished.store(true, Ordering::Relaxed);
                Ok::<(), anyhow::Error>(())
            };
            let reading = async {
                let mut hash = Sha256::new();
                let mut count = 0usize;
                while let Some(mut chunk) = recv.recv_data().await.context("H3 bulk receive DATA/FIN")? {
                    count += chunk.remaining();
                    received.store(count, Ordering::Relaxed);
                    last_received_ms.store(started.elapsed().as_millis() as usize, Ordering::Relaxed);
                    ensure!(count <= bytes, "H3 echoed extra data");
                    while chunk.has_remaining() {
                        let len = chunk.chunk().len();
                        hash.update(chunk.chunk());
                        chunk.advance(len);
                    }
                }
                received_eof.store(true, Ordering::Relaxed);
                ensure!(count == bytes, "H3 half-close lost bytes: {count}/{bytes}");
                Ok::<String, anyhow::Error>(format!("{:x}", hash.finalize()))
            };
            let result = tokio::time::timeout(Duration::from_secs(240), async { tokio::try_join!(writing, reading) })
                .await
                .context("H3 bulk deadline")
                .and_then(|result| result);
            match result {
                Ok((_, hash)) => hash,
                Err(error) => {
                    let diagnostic = serde_json::json!({"error_chain": format!("{error:#}"), "warp_transport": fixture.warp.status().transport, "inbound": inbound, "elapsed_ms": started.elapsed().as_millis(), "expected_bytes": bytes, "sent_data_bytes": sent.load(Ordering::Relaxed), "received_data_bytes": received.load(Ordering::Relaxed), "last_sent_ms": last_sent_ms.load(Ordering::Relaxed), "last_received_ms": last_received_ms.load(Ordering::Relaxed), "send_fin_completed": finished.load(Ordering::Relaxed), "received_eof": received_eof.load(Ordering::Relaxed), "quinn_close_reason": format!("{:?}", client.connection().close_reason()), "quinn_stats": format!("{:?}", client.connection().stats()), "egress": fixture.warp.status(), "peer": fixture.peer.snapshot(), "peer_stack": fixture.peer.stack_diagnostics(), "peer_errors": fixture.peer.errors(), "live_cloudflare": false});
                    save_evidence("h3-bulk-failure", diagnostic.clone())?;
                    return Err(error.context(format!("H3 bulk diagnostic: {diagnostic}")));
                }
            }
        }
        _ => unreachable!(),
    };
    ensure!(actual == expected, "bulk byte integrity failure over {inbound}");
    Ok(
        serde_json::json!({"inbound": inbound, "bytes_each_direction": bytes, "sha256": actual, "half_close": true, "elapsed_ms": started.elapsed().as_millis()}),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repeated_64mib_bulk_hash_and_half_close_across_six_pairings() -> Result<()> {
    let mut evidence = Vec::new();
    for transport in [Transport::H2, Transport::H3] {
        let fixture = Fixture::start(transport).await?;
        standard_check(&fixture).await?;
        let before = process_metrics();
        let (before_rss, _) = required_resource_metrics(&before)?;
        let counters = fixture.peer.snapshot();
        let mut rounds = Vec::new();
        for inbound in ["h1", "h2", "h3"] {
            for round in 0..2 {
                let mut result = bulk(&fixture, inbound, BULK_BYTES).await?;
                result["round"] = round.into();
                rounds.push(result);
            }
        }
        let after = fixture.peer.snapshot();
        ensure!(
            after.tcp_bytes_received - counters.tcp_bytes_received == 6 * BULK_BYTES as u64,
            "bulk bytes bypassed peer TCP stack"
        );
        ensure!(
            after.tcp_bytes_sent - counters.tcp_bytes_sent == 6 * BULK_BYTES as u64,
            "peer TCP byte counters disagree with client"
        );
        let process = process_metrics();
        let (rss, _) = required_resource_metrics(&process)?;
        let rss_growth = rss.saturating_sub(before_rss);
        ensure!(rss_growth < 192 * 1024, "repeated streaming grew RSS by {rss_growth} KiB");
        ensure!(fixture.warp.status().sockets <= fixture.warp.status().socket_limit, "socket bound exceeded");
        evidence.push(serde_json::json!({"warp_transport": transport_name(transport), "rounds": rounds, "peer": after, "egress": fixture.warp.status(), "rss_growth_kib": rss_growth, "process": process}));
        fixture.finish().await?;
    }
    save_evidence("bulk-matrix", serde_json::json!({"live_cloudflare": false, "cases": evidence}))?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnel_dns_udp_peer_pinning_oversize_auth_and_terminal_failure() -> Result<()> {
    for transport in [Transport::H2, Transport::H3] {
        let fixture = Fixture::start(transport).await?;
        standard_check(&fixture).await?;
        // A name impossible to resolve on the host succeeds only via peer DNS.
        let addresses = fixture.warp.resolve("fixture.test").await?;
        ensure!(addresses.contains(&peer_addr(7).ip()), "fixture address not returned by tunneled DNS");
        ensure!(fixture.warp.resolve("missing.test").await.is_err(), "negative DNS answer escaped to another resolver");
        fixture.peer.dns_truncate_udp(true);
        let truncated = fixture.warp.resolve("tcp-fallback.test").await?;
        ensure!(truncated.contains(&peer_addr(7).ip()), "DNS TCP fallback failed");
        ensure!(fixture.peer.snapshot().dns_tcp_queries > 0, "truncated query did not use tunneled TCP DNS");
        fixture.peer.dns_truncate_udp(false);

        let socket = fixture.warp.connect_udp(peer_addr(7)).await?;
        let local = socket.local_addr()?;
        fixture.peer.send_udp(8, b"spoof", local).await?;
        let payload = b"authenticated-source-pinned-udp";
        socket.send(payload).await?;
        let mut buf = vec![0; 65_535];
        let n = tokio::time::timeout(WAIT, socket.recv(&mut buf)).await??;
        ensure!(&buf[..n] == payload, "connected UDP accepted an unselected source");
        let oversized = vec![0x5a; socket.max_payload() + 1];
        ensure!(socket.send(&oversized).await.is_err(), "oversize UDP was fragmented/split");
        socket.send(b"after-oversize").await?;
        let n = tokio::time::timeout(WAIT, socket.recv(&mut buf)).await??;
        ensure!(&buf[..n] == b"after-oversize", "oversize rejection poisoned valid UDP");

        let before = fixture.peer.snapshot();
        let mut wrong = fixture.relay.options();
        wrong.password = "wrong-ephemeral-password".into();
        for outcome in check::run(&wrong).await {
            if outcome.name.contains("TCP") || outcome.name.contains("UDP") {
                ensure!(outcome.result.is_err(), "wrong password succeeded: {}", outcome.name);
            }
        }
        ensure!(
            fixture.peer.snapshot().tcp_connections == before.tcp_connections,
            "wrong password opened an inner TCP socket"
        );
        fixture.relay.revoke_user()?;
        for outcome in check::run(&fixture.relay.options()).await {
            if outcome.name.contains("TCP") || outcome.name.contains("UDP") {
                ensure!(outcome.result.is_err(), "revoked user succeeded: {}", outcome.name);
            }
        }
        fixture.relay.restore_user()?;

        fixture.peer.dns_pause(true);
        let dns_before = fixture.peer.snapshot().dns_queries;
        let dns_egress = fixture.warp.clone();
        let pending_dns = tokio::spawn(async move { dns_egress.resolve("pending-failure.test").await });
        tokio::time::timeout(WAIT, async {
            while fixture.peer.snapshot().dns_queries == dns_before {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .context("pending DNS did not cross the tunnel")?;
        let mut pending = fixture.warp.connect_tcp(peer_addr(7)).await?;
        fixture.peer.terminate_transport();
        tokio::time::timeout(WAIT, fixture.warp.closed()).await.context("egress failed to detect dead tunnel")?;
        ensure!(!fixture.warp.available(), "closed tunnel remained ready");
        ensure!(fixture.warp.resolve("fixture.test").await.is_err(), "cached DNS remained callable after tunnel death");
        ensure!(fixture.warp.connect_tcp(peer_addr(7)).await.is_err(), "failed TCP dial used fallback");
        ensure!(fixture.warp.connect_udp(peer_addr(7)).await.is_err(), "failed UDP flow used fallback");
        ensure!(socket.send(b"dead").await.is_err(), "retained UDP socket survived dead tunnel");
        let dns_error = tokio::time::timeout(Duration::from_secs(3), pending_dns)
            .await
            .context("pending DNS did not wake on tunnel death")??;
        ensure!(dns_error.is_err(), "pending DNS survived terminal WARP failure");
        let mut byte = [0; 1];
        let read = tokio::time::timeout(Duration::from_secs(3), pending.read(&mut byte))
            .await
            .context("pending TCP read did not wake")?;
        ensure!(read.is_err(), "pending TCP read turned terminal egress failure into clean EOF");
        fixture.finish().await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_pairings_relay_inner_resets_and_active_revocation() -> Result<()> {
    for transport in [Transport::H2, Transport::H3] {
        let fixture = Fixture::start(transport).await?;
        let mut tcp = Vec::new();
        let mut udp = Vec::new();
        for inbound in ["h1", "h2", "h3"] {
            let mut stream = PersistentTcp::open(&fixture.relay, inbound).await?;
            stream.ping(0).await?;
            tcp.push(stream);
            let mut flow = PersistentUdp::open(&fixture.relay, inbound).await?;
            flow.ping(0).await?;
            udp.push(flow);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        for stream in &mut tcp {
            stream.ping(1).await?;
        }
        for flow in &mut udp {
            flow.ping(1).await?;
        }
        let mut resetting = fixture.warp.connect_tcp(peer_addr(9)).await?;
        resetting.write_all(b"reset").await?;
        let mut buf = [0; 1];
        let error =
            tokio::time::timeout(WAIT, resetting.read(&mut buf)).await?.expect_err("inner RST became clean EOF");
        ensure!(error.kind() == std::io::ErrorKind::ConnectionReset, "inner RST did not remain a reset: {error}");
        drop(resetting);
        fixture.relay.revoke_user()?;
        for stream in &mut tcp {
            ensure!(stream.ping(2).await.is_err(), "revoked persistent TCP survived");
        }
        for flow in &mut udp {
            ensure!(flow.ping(2).await.is_err(), "revoked persistent UDP survived");
        }
        drop(tcp);
        drop(udp);
        fixture.relay.restore_user()?;
        standard_check(&fixture).await?;
        fixture.finish().await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn idle_outer_keepalive_and_active_inner_flows_survive_two_idle_windows() -> Result<()> {
    let mut idle = Vec::new();
    let mut active = Vec::new();
    let mut idle_clients = Vec::new();
    for mode in [Transport::H2, Transport::H3] {
        idle.push(Fixture::start(mode).await?);
        let fixture = Fixture::start(mode).await?;
        let flows = PersistentFlows::start(&fixture.relay).await?;
        let opts = fixture.relay.options();
        let mut client = check::H3::connect(&opts, &opts.addresses).await?;
        let mut stream = client.request(connect_request("fixture.test:7").body(())?).await?;
        ensure!(stream.recv_response().await?.status() == StatusCode::OK, "idle diagnosis CONNECT refused");
        idle_clients.push((client, stream));
        active.push((fixture, flows));
    }
    // Both WARP transports have idle_timeout=30, keepalive=1, and these
    // first two cases send no business packets during the entire interval.
    tokio::time::sleep(Duration::from_secs(65)).await;
    let mut evidence = Vec::new();
    for fixture in &idle {
        let status = fixture.warp.status();
        ensure!(
            status.available && status.sent_packets == 0 && status.received_packets == 0,
            "idle outer tunnel lost liveness or carried unexpected business packets"
        );
        evidence.push(serde_json::json!({"case": "outer_idle_with_keepalive", "seconds": 65, "egress": status, "peer": fixture.peer.snapshot()}));
    }
    for (client, _) in &idle_clients {
        ensure!(
            matches!(client.connection().close_reason(), Some(quinn::ConnectionError::TimedOut)),
            "standard H3 client did not expose its exact default QUIC idle timeout: {:?}",
            client.connection().close_reason()
        );
    }
    drop(idle_clients);
    for (fixture, mut flows) in active {
        flows.check()?;
        ensure!(fixture.warp.available(), "client idle timeout was confused with outer WARP death");
        for metrics in flows.tcp_metrics().into_iter().chain(flows.udp_metrics()) {
            ensure!(metrics["pings"].as_u64().unwrap_or(0) >= 7, "independent persistent cadence stalled");
        }
        evidence.push(serde_json::json!({"case": "active_business_with_10s_ping", "tcp": flows.tcp_metrics(), "udp": flows.udp_metrics(), "egress": fixture.warp.status()}));
        flows.shutdown().await?;
        fixture.finish().await?;
    }
    for fixture in idle {
        fixture.finish().await?;
    }
    save_evidence("idle-liveness", serde_json::json!({"live_cloudflare": false, "cases": evidence}))?;
    Ok(())
}

fn process_metrics() -> serde_json::Value {
    let rss = std::fs::read_to_string("/proc/self/status").ok().and_then(|status| {
        status.lines().find_map(|line| {
            line.strip_prefix("VmRSS:")
                .and_then(|s| s.split_whitespace().next()?.parse::<u64>().ok())
                .filter(|rss| *rss > 0)
        })
    });
    let fds = std::fs::read_dir("/proc/self/fd").ok().map(|entries| entries.count()).filter(|fds| *fds > 0);
    serde_json::json!({"metrics_available": rss.is_some() && fds.is_some(), "metrics_source": "linux_proc", "rss_kib": rss.unwrap_or(0), "fd_count": fds.unwrap_or(0)})
}
fn required_resource_metrics(metrics: &serde_json::Value) -> Result<(u64, u64)> {
    ensure!(
        metrics["metrics_available"].as_bool() == Some(true),
        "resource checks require readable Linux /proc RSS and FD metrics; observations are unavailable"
    );
    let rss = metrics["rss_kib"].as_u64().filter(|value| *value > 0).context("RSS metric is absent or nonpositive")?;
    let fds = metrics["fd_count"].as_u64().filter(|value| *value > 0).context("FD metric is absent or nonpositive")?;
    Ok((rss, fds))
}
#[test]
fn resource_gates_reject_unavailable_and_nonpositive_observations() -> Result<()> {
    for invalid in [
        serde_json::json!({}),
        serde_json::json!({"metrics_available": false, "rss_kib": 1024, "fd_count": 8}),
        serde_json::json!({"metrics_available": true, "rss_kib": 0, "fd_count": 8}),
        serde_json::json!({"metrics_available": true, "rss_kib": 1024, "fd_count": 0}),
        serde_json::json!({"metrics_available": true, "rss_kib": 1024}),
    ] {
        ensure!(required_resource_metrics(&invalid).is_err(), "missing metrics falsely passed a resource gate");
    }
    ensure!(
        required_resource_metrics(&serde_json::json!({"metrics_available": true, "rss_kib": 1024, "fd_count": 8}))?
            == (1024, 8),
        "positive measurements were rejected"
    );
    Ok(())
}
fn save_evidence(label: &str, value: serde_json::Value) -> Result<()> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/evidence");
    std::fs::create_dir_all(&path)?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let file = path.join(format!("{label}-{stamp}-{}.json", std::process::id()));
    let mut out = std::fs::OpenOptions::new().write(true).create_new(true).open(file)?;
    serde_json::to_writer_pretty(&mut out, &value)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore = "requires SOAK_SECONDS >= 3600 after functional tests pass"]
async fn one_hour_forced_h2_and_h3_soak_with_resource_metrics() -> Result<()> {
    let seconds: u64 = std::env::var("SOAK_SECONDS").context("set SOAK_SECONDS >= 3600")?.parse()?;
    ensure!(seconds >= 3600, "a shorter run cannot satisfy the one-hour soak");
    let mut fixtures = Vec::new();
    for transport in [Transport::H2, Transport::H3] {
        let fixture = Fixture::start(transport).await?;
        standard_check(&fixture).await?;
        // Both endpoints must carry a large file before starting the soak clock.
        bulk(&fixture, "h3", BULK_BYTES).await?;
        let flows = PersistentFlows::start(&fixture.relay).await?;
        fixtures.push((transport, fixture, flows));
    }
    let started = Instant::now();
    let baseline = process_metrics();
    let (base_rss, base_fds) = required_resource_metrics(&baseline)?;
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/evidence");
    std::fs::create_dir_all(&directory)?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let mut log = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join(format!("soak-{stamp}-{}.jsonl", std::process::id())))?;
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut cycles = 0u64;
    while started.elapsed() < Duration::from_secs(seconds) {
        tick.tick().await;
        for (_, fixture, flows) in &mut fixtures {
            flows.check()?;
            standard_check(fixture).await?;
        }
        if cycles > 0 && cycles.is_multiple_of(10) {
            let inbound = ["h1", "h2", "h3"][(cycles as usize / 10) % 3];
            for (transport, fixture, _) in &fixtures {
                bulk(fixture, inbound, BULK_BYTES).await.with_context(|| {
                    format!("soak periodic bulk cycle {cycles}, inbound {inbound}, WARP {}", transport_name(*transport))
                })?;
            }
        }
        let process = process_metrics();
        let (rss, fds) = required_resource_metrics(&process)?;
        ensure!(rss <= base_rss + 192 * 1024, "soak RSS exceeded bounded growth");
        ensure!(fds <= base_fds + 48, "soak leaked descriptors");
        let modes: Vec<_> = fixtures.iter().map(|(transport, fixture, flows)| serde_json::json!({"warp_transport": transport_name(*transport), "egress": fixture.warp.status(), "peer": fixture.peer.snapshot(), "peer_stack": fixture.peer.stack_diagnostics(), "persistent_tcp": flows.tcp_metrics(), "persistent_udp": flows.udp_metrics(), "relay_tunnels": fixture.relay.relay.active_tunnels(), "relay_connections": fixture.relay.relay.open_connections()})).collect();
        let row = serde_json::json!({"elapsed_seconds": started.elapsed().as_secs_f64(), "cycle": cycles, "process": process, "modes": modes, "live_cloudflare": false});
        use std::io::Write;
        serde_json::to_writer(&mut log, &row)?;
        writeln!(&mut log)?;
        log.flush()?;
        cycles += 1;
    }
    ensure!(cycles >= 120, "less than 120 thirty-second probe samples completed");
    for (_, fixture, mut flows) in fixtures {
        flows.check()?;
        for stream in flows.tcp_metrics() {
            ensure!(stream["age_seconds"].as_f64().unwrap_or(0.0) >= 3600.0, "persistent TCP lived less than an hour");
        }
        for flow in flows.udp_metrics() {
            ensure!(flow["age_seconds"].as_f64().unwrap_or(0.0) >= 3600.0, "persistent UDP lived less than an hour");
        }
        ensure!(
            fixture.peer.snapshot().tunnels == 1 && fixture.peer.snapshot().authenticated_clients == 1,
            "soak restarted its outer WARP session"
        );
        flows.shutdown().await?;
        fixture.finish().await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore = "diagnoses repeated H3 bulk with unchanged client idle limits; not a one-hour soak"]
async fn diagnose_h3_bulk_with_persistent_pairings() -> Result<()> {
    let rounds: usize = std::env::var("DIAG_BULK_ROUNDS").unwrap_or_else(|_| "16".into()).parse()?;
    let mut fixtures = Vec::new();
    for transport in [Transport::H2, Transport::H3] {
        let fixture = Fixture::start(transport).await?;
        standard_check(&fixture).await?;
        let flows = PersistentFlows::start(&fixture.relay).await?;
        fixtures.push((transport, fixture, flows));
    }
    let mut results = Vec::new();
    for round in 0..rounds {
        for (transport, fixture, flows) in &mut fixtures {
            flows.check()?;
            standard_check(fixture).await?;
            eprintln!("H3 bulk diagnostic round {round}, WARP {}", transport_name(*transport));
            let before = fixture.peer.snapshot();
            match bulk(fixture, "h3", BULK_BYTES).await {
                Ok(result) => results.push(serde_json::json!({"round": round, "warp_transport": transport_name(*transport), "bulk": result, "peer_before": before, "peer_after": fixture.peer.snapshot(), "egress": fixture.warp.status(), "persistent_tcp": flows.tcp_metrics(), "persistent_udp": flows.udp_metrics()})),
                Err(error) => {
                    save_evidence("h3-bulk-diagnostic", serde_json::json!({"result": "failed", "one_hour_soak": false, "live_cloudflare": false, "round": round, "warp_transport": transport_name(*transport), "error_chain": format!("{error:#}"), "prior_results": results, "peer_before": before, "peer_after": fixture.peer.snapshot(), "egress": fixture.warp.status(), "persistent_tcp": flows.tcp_metrics(), "persistent_udp": flows.udp_metrics()}))?;
                    return Err(error.context(format!("diagnostic H3 bulk round {round}, WARP {}", transport_name(*transport))));
                }
            }
        }
    }
    for (_, fixture, flows) in fixtures {
        flows.shutdown().await?;
        fixture.finish().await?;
    }
    save_evidence(
        "h3-bulk-diagnostic",
        serde_json::json!({"result": "passed", "one_hour_soak": false, "live_cloudflare": false, "rounds": rounds, "results": results}),
    )?;
    Ok(())
}
