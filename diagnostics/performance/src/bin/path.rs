#![allow(dead_code)]

#[path = "../netstack.rs"]
mod netstack;

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use netstack::{NetStack, TcpStream};
use ring::digest::{Context, SHA256};
use serde::Serialize;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::Instant;

const PACKET_CAP: usize = 4096;
const PAYLOAD_LEN: usize = 8 << 20;
const PROBE: &[u8; 16] = b"delay-link-probe";

#[derive(Default, Serialize)]
struct LinkStats {
    received_packets: u64,
    received_ip_bytes: u64,
    delivered_packets: u64,
    delivered_ip_bytes: u64,
    scheduler_capacity_drops: u64,
    delivery_channel_drops: u64,
    source_channel_peak_packets: usize,
    scheduled_peak_packets: usize,
    scheduled_peak_bytes: usize,
    delivery_channel_peak_packets: usize,
    residence_us_sum: u64,
    residence_us_min: Option<u64>,
    residence_us_max: u64,
    fin_packets: u64,
    rst_packets: u64,
}

// Every packet receives its own deadline at link admission. The task keeps
// admitting new packets while old packets wait, and emits all due packets.
// No per-packet sleep is awaited, and there is no configured link rate.
async fn link(
    mut input: mpsc::Receiver<Bytes>,
    output: mpsc::Sender<Bytes>,
    one_way_delay: Duration,
    shared: Arc<Mutex<LinkStats>>,
) {
    let mut pending: VecDeque<(Instant, Instant, Bytes)> = VecDeque::new();
    let mut queued_bytes = 0;
    loop {
        let now = Instant::now();
        while pending.front().is_some_and(|(due, _, _)| *due <= now) {
            let (_, admitted, packet) = pending.pop_front().unwrap();
            queued_bytes -= packet.len();
            let len = packet.len();
            let residence_us = admitted.elapsed().as_micros() as u64;
            let sent = output.try_send(packet);
            let mut stats = shared.lock().unwrap();
            match sent {
                Ok(()) => {
                    stats.delivered_packets += 1;
                    stats.delivered_ip_bytes += len as u64;
                    stats.residence_us_sum += residence_us;
                    stats.residence_us_min =
                        Some(stats.residence_us_min.map_or(residence_us, |old| old.min(residence_us)));
                    stats.residence_us_max = stats.residence_us_max.max(residence_us);
                    stats.delivery_channel_peak_packets =
                        stats.delivery_channel_peak_packets.max(output.max_capacity() - output.capacity());
                }
                Err(mpsc::error::TrySendError::Full(_)) => stats.delivery_channel_drops += 1,
                Err(mpsc::error::TrySendError::Closed(_)) => return,
            }
        }
        let deadline = pending.front().map(|(due, _, _)| *due);
        tokio::select! {
            packet = input.recv() => {
                let Some(packet) = packet else { return };
                let admitted = Instant::now();
                let mut stats = shared.lock().unwrap();
                stats.received_packets += 1;
                stats.received_ip_bytes += packet.len() as u64;
                stats.source_channel_peak_packets = stats.source_channel_peak_packets.max(input.len() + 1);
                if packet.first().is_some_and(|byte| byte >> 4 == 4) && packet.get(9) == Some(&6) {
                    let tcp = usize::from(packet[0] & 15) * 4;
                    let flags = packet.get(tcp + 13).copied().unwrap_or(0);
                    stats.fin_packets += u64::from(flags & 1 != 0);
                    stats.rst_packets += u64::from(flags & 4 != 0);
                }
                if pending.len() == PACKET_CAP {
                    stats.scheduler_capacity_drops += 1;
                } else {
                    queued_bytes += packet.len();
                    pending.push_back((admitted + one_way_delay, admitted, packet));
                    stats.scheduled_peak_packets = stats.scheduled_peak_packets.max(pending.len());
                    stats.scheduled_peak_bytes = stats.scheduled_peak_bytes.max(queued_bytes);
                }
            }
            _ = async {
                match deadline {
                    Some(due) => tokio::time::sleep_until(due).await,
                    None => std::future::pending::<()>().await,
                }
            } => {}
        }
    }
}

#[derive(Default, Serialize)]
struct ResourceStats {
    samples: u64,
    a_peak_sockets: usize,
    b_peak_sockets: usize,
    a_peak_lingering: usize,
    b_peak_lingering: usize,
    a_peak_received_bytes: usize,
    b_peak_received_bytes: usize,
    a_peak_queued_bytes: usize,
    b_peak_queued_bytes: usize,
    rss_peak_kib_sampled: u64,
}

fn rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("VmRSS:"))
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|value| value.parse().ok())
        })
        .unwrap_or(0)
}

fn sample(a: &NetStack, b: &NetStack, stats: &mut ResourceStats) {
    stats.samples += 1;
    let (an, al) = a.socket_counts();
    let (bn, bl) = b.socket_counts();
    stats.a_peak_sockets = stats.a_peak_sockets.max(an);
    stats.b_peak_sockets = stats.b_peak_sockets.max(bn);
    stats.a_peak_lingering = stats.a_peak_lingering.max(al);
    stats.b_peak_lingering = stats.b_peak_lingering.max(bl);
    let sums = |stack: &NetStack| {
        stack
            .tcp_snapshot()
            .iter()
            .fold((0, 0), |(rx, tx), socket| (rx + socket.received_bytes, tx + socket.queued_bytes))
    };
    let (ar, aw) = sums(a);
    let (br, bw) = sums(b);
    stats.a_peak_received_bytes = stats.a_peak_received_bytes.max(ar);
    stats.b_peak_received_bytes = stats.b_peak_received_bytes.max(br);
    stats.a_peak_queued_bytes = stats.a_peak_queued_bytes.max(aw);
    stats.b_peak_queued_bytes = stats.b_peak_queued_bytes.max(bw);
    stats.rss_peak_kib_sampled = stats.rss_peak_kib_sampled.max(rss_kib());
}

fn digest_hex(data: &[u8]) -> String {
    ring::digest::digest(&SHA256, data).as_ref().iter().map(|byte| format!("{byte:02x}")).collect()
}

struct ReceiveResult {
    bytes: usize,
    sha256: String,
    last_byte_at: Instant,
    eof_at: Instant,
}

async fn receive_eof(stream: &mut TcpStream) -> io::Result<ReceiveResult> {
    let mut hash = Context::new(&SHA256);
    let mut bytes = 0;
    let mut last_byte_at = Instant::now();
    let mut chunk = vec![0u8; 64 << 10];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            if bytes != PAYLOAD_LEN {
                return Err(io::Error::other(format!("wrong payload length {bytes}")));
            }
            return Ok(ReceiveResult {
                bytes,
                sha256: hash.finish().as_ref().iter().map(|byte| format!("{byte:02x}")).collect(),
                last_byte_at,
                eof_at: Instant::now(),
            });
        }
        bytes += n;
        if bytes > PAYLOAD_LEN {
            return Err(io::Error::other("payload exceeded 8 MiB bound"));
        }
        hash.update(&chunk[..n]);
        last_byte_at = Instant::now();
    }
}

async fn trial(rtt_ms: u64, repeat: u64) -> io::Result<serde_json::Value> {
    let trial_start = Instant::now();
    let before_rss = rss_kib();
    let upload: Arc<Vec<u8>> = Arc::new((0..PAYLOAD_LEN).map(|i| ((i * 7 + 3) % 251) as u8).collect());
    let download: Arc<Vec<u8>> = Arc::new((0..PAYLOAD_LEN).map(|i| ((i * 11 + 17) % 251) as u8).collect());
    let upload_hash = digest_hex(&upload);
    let download_hash = digest_hex(&download);
    let a = NetStack::new(0);
    let b = NetStack::new(0);
    a.set_addresses(&["10.0.0.1".parse::<IpAddr>().unwrap()]);
    b.set_addresses(&["10.0.0.2".parse::<IpAddr>().unwrap()]);
    let (a_out, a_wire) = mpsc::channel(PACKET_CAP);
    let (b_out, b_wire) = mpsc::channel(PACKET_CAP);
    let (to_a, a_in) = mpsc::channel(PACKET_CAP);
    let (to_b, b_in) = mpsc::channel(PACKET_CAP);
    let ab = Arc::new(Mutex::new(LinkStats::default()));
    let ba = Arc::new(Mutex::new(LinkStats::default()));
    let mut tasks = Vec::new();
    let one_way = Duration::from_micros(rtt_ms * 500);
    if rtt_ms == 0 {
        // No tracing task or per-packet mutex between the two production stacks.
        for (stack, incoming, outgoing) in [(a.clone(), b_wire, a_out), (b.clone(), a_wire, b_out)] {
            tasks.push(tokio::spawn(async move { stack.run(incoming, outgoing).await }));
        }
    } else {
        for (stack, incoming, outgoing) in [(a.clone(), a_in, a_out), (b.clone(), b_in, b_out)] {
            tasks.push(tokio::spawn(async move { stack.run(incoming, outgoing).await }));
        }
        tasks.push(tokio::spawn(link(a_wire, to_b, one_way, ab.clone())));
        tasks.push(tokio::spawn(link(b_wire, to_a, one_way, ba.clone())));
    }
    let mut listener = b.listen(7, 1)?;
    let handshake_start = Instant::now();
    let (client, peer) = tokio::join!(a.connect("10.0.0.2:7".parse::<SocketAddr>().unwrap()), listener.accept());
    let mut client = client?;
    let mut peer = peer?;
    let handshake_ms = handshake_start.elapsed().as_secs_f64() * 1000.0;
    drop(listener);
    let resources = Arc::new(Mutex::new(ResourceStats::default()));
    sample(&a, &b, &mut resources.lock().unwrap());
    let sampler = {
        let (a, b, resources) = (a.clone(), b.clone(), resources.clone());
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(10)).await;
                sample(&a, &b, &mut resources.lock().unwrap());
            }
        })
    };
    let expected_upload = upload_hash.clone();
    let server = tokio::spawn(async move {
        let mut probe = [0u8; 16];
        peer.read_exact(&mut probe).await?;
        if probe != *PROBE {
            return Err(io::Error::other("wrong probe"));
        }
        peer.write_all(&probe).await?;
        let up = receive_eof(&mut peer).await?;
        if up.sha256 != expected_upload {
            return Err(io::Error::other("upload hash mismatch"));
        }
        let download_start = Instant::now();
        peer.write_all(&download).await?;
        let download_write_ms = download_start.elapsed().as_secs_f64() * 1000.0;
        peer.shutdown().await?;
        drop(peer);
        Ok::<_, io::Error>((up, download_start, download_write_ms))
    });
    let probe_start = Instant::now();
    client.write_all(PROBE).await?;
    let mut echoed = [0u8; 16];
    client.read_exact(&mut echoed).await?;
    if echoed != *PROBE {
        return Err(io::Error::other("probe echo mismatch"));
    }
    let observed_probe_rtt_ms = probe_start.elapsed().as_secs_f64() * 1000.0;
    let upload_start = Instant::now();
    client.write_all(&upload).await?;
    let upload_write_ms = upload_start.elapsed().as_secs_f64() * 1000.0;
    client.shutdown().await?;
    let down = receive_eof(&mut client).await?;
    if down.sha256 != download_hash {
        return Err(io::Error::other("download hash mismatch"));
    }
    drop(client);
    let (up, download_start, download_write_ms) = server.await.map_err(io::Error::other)??;
    let transfer_end = Instant::now();
    let sockets_after_app_drop = [a.socket_counts(), b.socket_counts()];
    let snapshots_after_app_drop = [a.tcp_snapshot(), b.tcp_snapshot()];
    let cleanup_start = Instant::now();
    while a.socket_counts().0 + b.socket_counts().0 != 0 && cleanup_start.elapsed() < Duration::from_secs(15) {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let cleanup_ms = cleanup_start.elapsed().as_secs_f64() * 1000.0;
    let sockets_after_cleanup = [a.socket_counts(), b.socket_counts()];
    sampler.abort();
    let _ = sampler.await;
    sample(&a, &b, &mut resources.lock().unwrap());
    for task in &tasks {
        task.abort();
    }
    for task in tasks {
        let _ = task.await;
    }
    let duration = |end: Instant, start: Instant| end.duration_since(start).as_secs_f64();
    let upstream_s = duration(up.last_byte_at, upload_start);
    let downstream_s = duration(down.last_byte_at, download_start);
    let upstream_eof_s = duration(up.eof_at, upload_start);
    let downstream_eof_s = duration(down.eof_at, download_start);
    let complete_cleanup = sockets_after_cleanup.iter().all(|pair| pair.0 == 0 && pair.1 == 0);
    let stack_drops = [a.queue_drops(), b.queue_drops()];
    let link_drop_total = [ab.clone(), ba.clone()]
        .iter()
        .map(|stats| {
            let stats = stats.lock().unwrap();
            stats.scheduler_capacity_drops + stats.delivery_channel_drops
        })
        .sum::<u64>();
    let success = complete_cleanup && stack_drops == [0, 0] && link_drop_total == 0;
    Ok(json!({
        "variant": std::env::var("RELAY_STACK_STUDY").unwrap(),
        "rtt_ms_configured": rtt_ms, "repeat": repeat, "success": success,
        "payload_bytes_each_direction": PAYLOAD_LEN,
        "workload": "sequential upload then reply after upload EOF, one IPv4 TCP connection",
        "handshake_both_ends_ms": handshake_ms, "observed_probe_rtt_ms": observed_probe_rtt_ms,
        "upstream": { "received_bytes": up.bytes, "sha256": up.sha256, "expected_sha256": upload_hash,
            "receive_payload_s": upstream_s, "receive_eof_s": upstream_eof_s,
            "sender_write_ms": upload_write_ms, "payload_mbit_s": PAYLOAD_LEN as f64 * 8.0 / upstream_s / 1e6 },
        "downstream": { "received_bytes": down.bytes, "sha256": down.sha256, "expected_sha256": download_hash,
            "receive_payload_s": downstream_s, "receive_eof_s": downstream_eof_s,
            "sender_write_ms": download_write_ms, "payload_mbit_s": PAYLOAD_LEN as f64 * 8.0 / downstream_s / 1e6 },
        "transfer_wall_s": transfer_end.duration_since(upload_start).as_secs_f64(),
        "trial_wall_s": trial_start.elapsed().as_secs_f64(),
        "one_way_delay_us_configured": one_way.as_micros(),
        "packet_cap_each_channel_and_scheduler": PACKET_CAP,
        "mtu": a.mtu(), "tcp_buffer_bytes_per_socket": a.tcp_buffer_bytes(),
        "default_socket_limit_at_1gib": netstack::default_socket_limit(Some(1 << 30)),
        "socket_buffer_budget_two_established_sockets_bytes": a.tcp_buffer_bytes() * 2,
        "stack_queue_drops": stack_drops,
        "sockets_after_app_drop": sockets_after_app_drop,
        "snapshots_after_app_drop": snapshots_after_app_drop,
        "sockets_after_cleanup": sockets_after_cleanup, "cleanup_ms": cleanup_ms,
        "sample_interval_ms": 10, "resources": *resources.lock().unwrap(),
        "rss_before_payload_kib": before_rss, "rss_after_cleanup_kib": rss_kib(),
        "link_a_to_b": *ab.lock().unwrap(), "link_b_to_a": *ba.lock().unwrap(),
    }))
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rtt_ms = args.get(1).unwrap().parse::<u64>().unwrap();
    let repeat = args.get(2).unwrap().parse::<u64>().unwrap();
    match tokio::time::timeout(Duration::from_secs(120), trial(rtt_ms, repeat)).await {
        Ok(Ok(value)) => {
            println!("{}", value);
            if value["success"] != true {
                std::process::exit(1);
            }
        }
        result => {
            eprintln!("trial failed: {result:?}");
            std::process::exit(1);
        }
    }
}
