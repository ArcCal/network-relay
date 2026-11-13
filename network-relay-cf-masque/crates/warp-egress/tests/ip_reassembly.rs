// Real production NetStack controls and deterministic malformed-packet mutations.
// Run with: cargo test -p warp-masque-egress --features test-support --test ip_reassembly
// Private vendor modules are compiled directly only to test their bounded state.
#![cfg(feature = "test-support")]

extern crate alloc;
use warp_masque_egress::test_support as netstack;

use bytes::Bytes;
use netstack::{NetStack, UdpSocket};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_time().build().unwrap()
}
fn ip6(s: &str) -> [u8; 16] {
    s.parse::<std::net::Ipv6Addr>().unwrap().octets()
}
fn udp_packet(payload: &[u8]) -> Bytes {
    let (src, dst) = (ip6("fd00::2"), ip6("fd00::1"));
    let len = 8 + payload.len();
    let mut p = vec![0u8; 40 + len];
    p[0] = 0x60;
    p[6] = 17;
    p[7] = 64;
    p[4..6].copy_from_slice(&(len as u16).to_be_bytes());
    p[8..24].copy_from_slice(&src);
    p[24..40].copy_from_slice(&dst);
    p[40..42].copy_from_slice(&4321u16.to_be_bytes());
    p[42..44].copy_from_slice(&1234u16.to_be_bytes());
    p[44..46].copy_from_slice(&(len as u16).to_be_bytes());
    p[48..].copy_from_slice(payload);
    let mut pseudo = Vec::from(src);
    pseudo.extend_from_slice(&dst);
    pseudo.extend_from_slice(&(len as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]);
    let sum = checksum(&[&pseudo, &p[40..]]);
    p[46..48].copy_from_slice(&(if sum == 0 { 0xffff } else { sum }).to_be_bytes());
    Bytes::from(p)
}
fn fragment(p: &[u8], id: u32, offset: usize, len: usize, more: bool) -> Bytes {
    assert_eq!(offset % 8, 0);
    let mut out = Vec::from(&p[..40]);
    out[6] = 44;
    out[4..6].copy_from_slice(&((len + 8) as u16).to_be_bytes());
    out.extend_from_slice(&[p[6], 0]);
    out.extend_from_slice(&((offset as u16) | u16::from(more)).to_be_bytes());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&p[40 + offset..40 + offset + len]);
    Bytes::from(out)
}
struct UdpPeer {
    tx: mpsc::Sender<Bytes>,
    socket: UdpSocket,
    wire: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    workers: Vec<tokio::task::JoinHandle<()>>,
}
impl UdpPeer {
    fn new() -> Self {
        let stack = NetStack::new(0);
        stack.set_addresses(&["fd00::1".parse().unwrap()]);
        let socket = stack.bind_udp(1234).unwrap();
        let (tx, input) = mpsc::channel(128);
        let (out, wire) = mpsc::channel(128);
        let workers = vec![tokio::spawn(async move { stack.run(input, out).await })];
        Self { tx, socket, wire: tokio::sync::Mutex::new(wire), workers }
    }
    async fn inject(&self, r: &mut (), p: Bytes, now: u64) {
        let _ = (r, now);
        self.tx.send(p).await.unwrap();
    }
    async fn receive(&self) -> Vec<u8> {
        tokio::time::timeout(Duration::from_millis(350), self.socket.recv_from())
            .await
            .expect("actual NetStack did not deliver UDP payload")
            .unwrap()
            .0
            .to_vec()
    }
    async fn reply(&self) -> Bytes {
        tokio::time::timeout(Duration::from_millis(350), self.wire.lock().await.recv())
            .await
            .expect("no wire error response")
            .unwrap()
    }
    async fn wire_quiet(&self) {
        assert!(tokio::time::timeout(Duration::from_millis(60), self.wire.lock().await.recv()).await.is_err());
    }
    async fn quiet(&self) {
        assert!(tokio::time::timeout(Duration::from_millis(60), self.socket.recv_from()).await.is_err());
    }
}
impl Drop for UdpPeer {
    fn drop(&mut self) {
        for w in &self.workers {
            w.abort();
        }
    }
}

#[test]
fn valid_fragmented_udp_1500_out_of_order() {
    rt().block_on(async {
        let peer = UdpPeer::new();
        let mut r = ();
        let payload: Vec<u8> = (0..1452).map(|n| (n % 251) as u8).collect();
        let p = udp_packet(&payload);
        assert_eq!(p.len(), 1500);
        peer.inject(&mut r, fragment(&p, 7, 1232, 228, false), 0).await;
        peer.inject(&mut r, fragment(&p, 7, 0, 1232, true), 10).await;
        assert_eq!(peer.receive().await, payload);
    });
}

#[test]
fn valid_atomic_udp() {
    rt().block_on(async {
        let peer = UdpPeer::new();
        let mut r = ();
        let p = udp_packet(b"atomic");
        peer.inject(&mut r, fragment(&p, 7, 0, p.len() - 40, false), 0).await;
        assert_eq!(peer.receive().await, b"atomic");
    });
}

#[test]
fn actual_repeated_atomic_headers_deliver_udp() {
    rt().block_on(async {
        let peer = UdpPeer::new();
        let p = udp_packet(b"repeated fragment headers");
        let inner = fragment(&p, 81, 0, p.len() - 40, false);
        let outer = fragment(&inner, 82, 0, inner.len() - 40, false);
        peer.inject(&mut (), outer, 0).await;
        assert_eq!(peer.receive().await, b"repeated fragment headers");
        peer.wire_quiet().await;
    });
}

#[test]
fn actual_deep_atomic_and_nested_fragmented_udp_remain_bounded() {
    rt().block_on(async {
        let peer = UdpPeer::new();
        let p = udp_packet(b"deep atomic chain");
        let mut nested = p.clone();
        for id in 0..170 {
            nested = fragment(&nested, id, 0, nested.len() - 40, false);
        }
        assert!(nested.len() <= 1500);
        peer.inject(&mut (), nested, 0).await;
        assert_eq!(peer.receive().await, b"deep atomic chain");
        let payload = vec![0x37; 1000];
        let p = udp_packet(&payload);
        // Both an atomic wrapper around real fragments and real fragments
        // around an atomic packet must pass through the same ingress path.
        for inner in [fragment(&p, 301, 512, p.len() - 40 - 512, false), fragment(&p, 301, 0, 512, true)] {
            let outer = fragment(&inner, 302, 0, inner.len() - 40, false);
            peer.inject(&mut (), outer, 1).await;
        }
        assert_eq!(peer.receive().await, payload);
        let inner = fragment(&p, 303, 0, p.len() - 40, false);
        for outer in [fragment(&inner, 304, 512, inner.len() - 40 - 512, false), fragment(&inner, 304, 0, 512, true)] {
            peer.inject(&mut (), outer, 2).await;
        }
        assert_eq!(peer.receive().await, payload);
        peer.wire_quiet().await;
    });
}

#[test]
fn actual_nested_first_fragment_requires_complete_upper_header() {
    rt().block_on(async {
        let peer = UdpPeer::new();
        let p = udp_packet(b"nested incomplete header");
        let inner = fragment(&p, 401, 0, p.len() - 40, false);
        // Eight bytes contain only the inner Fragment header, without UDP.
        let incomplete = fragment(&inner, 402, 0, 8, true);
        peer.inject(&mut (), incomplete.clone(), 0).await;
        let error = peer.reply().await;
        assert_eq!(&error[40..42], &[4, 3]);
        assert_eq!(&error[48..], &incomplete[..]);
        peer.quiet().await;
    });
}

#[test]
fn actual_hbh_after_atomic_fragment_is_rejected_with_original_pointer() {
    rt().block_on(async {
        let peer = UdpPeer::new();
        let p = add_extension(&udp_packet(b"late hop-by-hop"), 0, [0; 8]);
        let original = fragment(&p, 83, 0, p.len() - 40, false);
        peer.inject(&mut (), original.clone(), 0).await;
        let error = peer.reply().await;
        assert_eq!(&error[40..42], &[4, 1]);
        assert_eq!(u32::from_be_bytes(error[44..48].try_into().unwrap()), 40);
        assert_eq!(&error[48..], &original[..]);
        peer.quiet().await;
    });
}

#[test]
fn actual_tcp_payload_and_half_close_over_fragmented_wire() {
    rt().block_on(async {
        let a = NetStack::new(0);
        let b = NetStack::new(0);
        a.set_addresses(&["fd00::a".parse().unwrap()]);
        b.set_addresses(&["fd00::b".parse().unwrap()]);
        let mut listener = b.listen(7000, 4).unwrap();
        let (atx, arx) = mpsc::channel(512);
        let (btx, brx) = mpsc::channel(512);
        let (ao, mut aw) = mpsc::channel::<Bytes>(512);
        let (bo, mut bw) = mpsc::channel::<Bytes>(512);
        let (arun, brun) = (a.clone(), b.clone());
        let mut workers = vec![
            tokio::spawn(async move { arun.run(arx, ao).await }),
            tokio::spawn(async move { brun.run(brx, bo).await }),
        ];
        async fn link(input: &mut mpsc::Receiver<Bytes>, output: mpsc::Sender<Bytes>) {
            let mut r = ();
            let mut id = 100u32;
            let start = std::time::Instant::now();
            while let Some(p) = input.recv().await {
                if p.len() > 80 && p[0] >> 4 == 6 && p[6] == 6 {
                    id += 1;
                    let len = p.len() - 40;
                    let cut = ((len / 2) / 8) * 8;
                    let pieces = [fragment(&p, id, cut, len - cut, false), fragment(&p, id, 0, cut, true)];
                    for f in pieces {
                        let _ = (&mut r, &start);
                        let normalized = Some(f);
                        if let Some(f) = normalized {
                            if output.send(f).await.is_err() {
                                return;
                            }
                        }
                    }
                } else if output.send(p).await.is_err() {
                    return;
                }
            }
        }
        workers.push(tokio::spawn(async move { link(&mut aw, btx).await }));
        workers.push(tokio::spawn(async move { link(&mut bw, atx).await }));
        workers.push(tokio::spawn(async move {
            let mut server = listener.accept().await.unwrap();
            let mut data = Vec::new();
            server.read_to_end(&mut data).await.unwrap();
            server.write_all(&data).await.unwrap();
            server.shutdown().await.unwrap();
        }));
        let result = tokio::time::timeout(Duration::from_secs(3), async {
            let mut stream = a.connect("[fd00::b]:7000".parse::<SocketAddr>().unwrap()).await.unwrap();
            let payload: Vec<u8> = (0..65536).map(|n| (n % 251) as u8).collect();
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, payload);
        })
        .await;
        for worker in workers {
            worker.abort();
        }
        result.expect("actual NetStack TCP payload/halfclose failed on fragment wire");
    });
}
pub fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    for part in parts {
        for word in part.chunks(2) {
            sum += u32::from(u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)]));
        }
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// Compile the actual candidate modules as component tests, with the same wire/time
// definitions. No duplicate reassembly implementation or public production API.
mod wire {
    pub use smoltcp::wire::*;
}
mod time {
    pub use smoltcp::time::*;
}
// Inspect the unchanged vendor internals without imposing workspace style rewrites.
#[allow(
    dead_code,
    unexpected_cfgs,
    clippy::needless_lifetimes,
    clippy::manual_div_ceil,
    clippy::manual_range_contains,
    clippy::manual_is_multiple_of
)]
#[rustfmt::skip]
#[path = "../../../vendor/smoltcp/src/iface/ipv6_input.rs"]
mod ipv6_input;
// Inspect the unchanged vendor internals without imposing workspace style rewrites.
#[allow(
    dead_code,
    unexpected_cfgs,
    clippy::needless_lifetimes,
    clippy::manual_div_ceil,
    clippy::manual_range_contains,
    clippy::manual_is_multiple_of
)]
#[rustfmt::skip]
#[path = "../../../vendor/smoltcp/src/iface/ipv6_reassembly.rs"]
mod ipv6_reassembly;
#[test]
fn fixed_reassembly_memory_bound() {
    assert!(std::mem::size_of::<ipv6_input::Ipv6Ingress>() < 60 * 1024);
    println!("fixed IPv6 ingress reservation bytes={}", std::mem::size_of::<ipv6_input::Ipv6Ingress>());
}
fn add_extension(packet: &[u8], kind: u8, mut header: [u8; 8]) -> Bytes {
    let mut p = packet[..40].to_vec();
    header[0] = packet[6];
    p[6] = kind;
    p[4..6].copy_from_slice(&((packet.len() - 40 + 8) as u16).to_be_bytes());
    p.extend_from_slice(&header);
    p.extend_from_slice(&packet[40..]);
    Bytes::from(p)
}
#[test]
fn actual_udp_overlap_late_and_simultaneous_atomic() {
    rt().block_on(async {
        let peer = UdpPeer::new();
        let mut dummy = ();
        let payload = vec![0x5a; 1200];
        let p = udp_packet(&payload);
        let total = p.len() - 40;
        for f in
            [fragment(&p, 7, 0, 512, true), fragment(&p, 7, 256, 512, true), fragment(&p, 7, 512, total - 512, false)]
        {
            peer.inject(&mut dummy, f, 0).await;
        }
        peer.quiet().await;
        let atomic = udp_packet(b"atomic crosses poisoned tuple");
        peer.inject(&mut dummy, fragment(&atomic, 7, 0, atomic.len() - 40, false), 1).await;
        assert_eq!(peer.receive().await, b"atomic crosses poisoned tuple");
        for f in [fragment(&p, 7, 0, 512, true), fragment(&p, 7, 512, total - 512, false)] {
            peer.inject(&mut dummy, f, 2).await;
        }
        peer.quiet().await;
        let control = udp_packet(b"runner remains healthy");
        peer.inject(&mut dummy, control, 3).await;
        assert_eq!(peer.receive().await, b"runner remains healthy");
    });
}
#[test]
fn actual_udp_context_cap_old_progress_and_new_tuple() {
    rt().block_on(async {
        let peer = UdpPeer::new();
        let mut dummy = ();
        let payload = vec![0x4a; 1200];
        let p = udp_packet(&payload);
        let total = p.len() - 40;
        for id in 0..16 {
            peer.inject(&mut dummy, fragment(&p, id, 0, 512, true), 0).await;
        }
        peer.inject(&mut dummy, fragment(&p, 99, 0, 512, true), 1).await;
        peer.inject(&mut dummy, fragment(&p, 0, 512, total - 512, false), 2).await;
        assert_eq!(peer.receive().await, payload);
        peer.inject(&mut dummy, fragment(&p, 99, 512, total - 512, false), 3).await;
        peer.quiet().await;
        peer.inject(&mut dummy, fragment(&p, 99, 0, 512, true), 4).await;
        assert_eq!(peer.receive().await, payload);
    });
}
#[test]
fn actual_udp_reserved_bits_and_different_nonfirst_header() {
    rt().block_on(async {
        let peer = UdpPeer::new();
        let mut dummy = ();
        let payload = vec![0x2a; 1200];
        let p = udp_packet(&payload);
        let total = p.len() - 40;
        let mut first = fragment(&p, 1, 0, 512, true).to_vec();
        first[41] = 255;
        first[43] |= 6;
        let mut last = fragment(&p, 1, 512, total - 512, false).to_vec();
        last[40] = 253;
        last[41] = 255;
        last[43] |= 6;
        for f in [Bytes::from(last), Bytes::from(first)] {
            peer.inject(&mut dummy, f, 0).await;
        }
        assert_eq!(peer.receive().await, payload);
    });
}
#[test]
fn actual_per_fragment_hbh_and_first_prefix_origin() {
    rt().block_on(async {
        let peer = UdpPeer::new();
        let mut dummy = ();
        let payload = vec![0x3a; 1200];
        let p = udp_packet(&payload);
        let total = p.len() - 40;
        let first = add_extension(&fragment(&p, 1, 0, 512, true), 0, [0, 0, 0, 0, 0, 0, 0, 0]);
        peer.inject(&mut dummy, first, 0).await;
        let bad_last = add_extension(&fragment(&p, 1, 512, total - 512, false), 0, [0, 0, 0, 0, 0, 0, 0x40, 0]);
        peer.inject(&mut dummy, bad_last, 1).await;
        peer.quiet().await;
        peer.inject(&mut dummy, fragment(&p, 1, 512, total - 512, false), 2).await;
        assert_eq!(peer.receive().await, payload);
    });
}
#[test]
fn actual_destination_routing_and_post_fragment_headers() {
    rt().block_on(async {
        let peer = UdpPeer::new();
        let mut dummy = ();
        for (kind, header) in
            [(60, [0, 0, 5, 1, 0, 0, 0, 0]), (43, [0, 0, 253, 0, 0, 0, 0, 0]), (43, [0, 0, 0, 0, 0, 0, 0, 0])]
        {
            let packet = add_extension(&udp_packet(b"extension payload"), kind, header);
            peer.inject(&mut dummy, packet, 0).await;
            assert_eq!(peer.receive().await, b"extension payload");
        }
        let payload = vec![0x6a; 1444];
        let original = add_extension(&udp_packet(&payload), 60, [0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(original.len(), 1500);
        for f in [fragment(&original, 1, 1232, 228, false), fragment(&original, 1, 0, 1232, true)] {
            peer.inject(&mut dummy, f, 1).await;
        }
        assert_eq!(peer.receive().await, payload);
    });
}
#[test]
fn actual_error_pointers_and_quotes_use_original_or_normalized_packet() {
    rt().block_on(async {
        let peer = UdpPeer::new();
        let mut dummy = ();
        let mut original = add_extension(&udp_packet(b"unknown upper protocol"), 60, [0, 0, 0, 0, 0, 0, 0, 0]).to_vec();
        original[40] = 253;
        original[0] = 0x6f;
        original[1] = 0xab;
        original[2] = 0x12;
        original[3] = 0x34;
        peer.inject(&mut dummy, Bytes::from(original.clone()), 0).await;
        let error = peer.reply().await;
        assert_eq!(&error[40..42], &[4, 1]);
        assert_eq!(u32::from_be_bytes(error[44..48].try_into().unwrap()), 40);
        assert_eq!(&error[48..], original);
        let mut full = add_extension(&udp_packet(&vec![0x7a; 1444]), 60, [0, 0, 0, 0, 0, 0, 0, 0]).to_vec();
        full[40] = 253;
        full[0] = 0x6a;
        full[1] = 0xb5;
        for f in [fragment(&full, 2, 1232, 228, false), fragment(&full, 2, 0, 1232, true)] {
            peer.inject(&mut dummy, f, 1).await;
        }
        let error = peer.reply().await;
        assert_eq!(&error[40..42], &[4, 1]);
        assert_eq!(u32::from_be_bytes(error[44..48].try_into().unwrap()), 40);
        assert_eq!(&error[48..], &full[..1232]);
        assert_eq!(error.len(), 1280);
        let mut none = udp_packet(b"ignored trailing octets").to_vec();
        none[6] = 59;
        peer.inject(&mut dummy, Bytes::from(none), 2).await;
        peer.wire_quiet().await;
    });
}
#[test]
fn actual_multicast_option_error_uses_assigned_unicast_source() {
    rt().block_on(async {
        let peer = UdpPeer::new();
        let mut packet = add_extension(&udp_packet(b"multicast option"), 60, [0, 0, 0x80, 0, 0, 0, 0, 0]).to_vec();
        packet[24..40].copy_from_slice(&ip6("ff02::1"));
        peer.inject(&mut (), Bytes::from(packet.clone()), 0).await;
        let error = peer.reply().await;
        assert_eq!(&error[8..24], &ip6("fd00::1"), "RFC4443 section2.2 requires an assigned unicast source");
        assert_eq!(&error[24..40], &ip6("fd00::2"));
        assert_eq!(&error[40..42], &[4, 2]);
        assert_eq!(&error[48..], packet);
        let body = smoltcp::wire::Icmpv6Packet::new_checked(&error[40..]).unwrap();
        assert!(body.verify_checksum(&"fd00::1".parse().unwrap(), &"fd00::2".parse().unwrap()));
    });
}
#[test]
fn actual_first_fragment_requires_complete_upper_header() {
    rt().block_on(async {
        let peer = UdpPeer::new();
        let mut dummy = ();
        let mut packet = udp_packet(&vec![0; 1200]).to_vec();
        packet[6] = 6;
        packet[52] = 0x50;
        peer.inject(&mut dummy, fragment(&packet, 1, 0, 16, true), 0).await;
        let error = peer.reply().await;
        assert_eq!(&error[40..42], &[4, 3]);
        assert_eq!(&error[44..48], &[0, 0, 0, 0]);
        peer.quiet().await;
    });
}

fn udp4_packet(payload: &[u8]) -> Bytes {
    let len = 28 + payload.len();
    let mut p = vec![0u8; len];
    p[0] = 0x45;
    p[1] = 0xb8;
    p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&[10, 0, 0, 2]);
    p[16..20].copy_from_slice(&[10, 0, 0, 1]);
    p[20..22].copy_from_slice(&4321u16.to_be_bytes());
    p[22..24].copy_from_slice(&1234u16.to_be_bytes());
    p[24..26].copy_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
    p[28..].copy_from_slice(payload);
    let mut pseudo = Vec::from(&p[12..20]);
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
    let sum = checksum(&[&pseudo, &p[20..]]);
    p[26..28].copy_from_slice(&(if sum == 0 { 0xffff } else { sum }).to_be_bytes());
    let sum = checksum(&[&p[..20]]);
    p[10..12].copy_from_slice(&sum.to_be_bytes());
    Bytes::from(p)
}
fn fragment4(p: &[u8], id: u16, offset: usize, len: usize, more: bool) -> Bytes {
    let h = usize::from(p[0] & 15) * 4;
    let mut out = p[..h].to_vec();
    out[2..4].copy_from_slice(&((h + len) as u16).to_be_bytes());
    out[4..6].copy_from_slice(&id.to_be_bytes());
    out[6..8].copy_from_slice(&(((offset / 8) as u16) | (if more { 0x2000 } else { 0 })).to_be_bytes());
    out[10..12].fill(0);
    let sum = checksum(&[&out]);
    out[10..12].copy_from_slice(&sum.to_be_bytes());
    out.extend_from_slice(&p[h + offset..h + offset + len]);
    Bytes::from(out)
}
impl UdpPeer {
    fn new4() -> Self {
        let stack = NetStack::new(0);
        stack.set_addresses(&["10.0.0.1".parse().unwrap()]);
        let socket = stack.bind_udp(1234).unwrap();
        let (tx, input) = mpsc::channel(128);
        let (out, wire) = mpsc::channel(128);
        let workers = vec![tokio::spawn(async move { stack.run(input, out).await })];
        Self { tx, socket, wire: tokio::sync::Mutex::new(wire), workers }
    }
}
#[test]
fn actual_ipv4_fragmented_udp1500_reversed() {
    rt().block_on(async {
        let peer = UdpPeer::new4();
        let data: Vec<u8> = (0..1472).map(|n| (n % 251) as u8).collect();
        let p = udp4_packet(&data);
        assert_eq!(p.len(), 1500);
        peer.tx.send(fragment4(&p, 7, 1232, 248, false)).await.unwrap();
        peer.tx.send(fragment4(&p, 7, 0, 1232, true)).await.unwrap();
        assert_eq!(peer.receive().await, data);
    });
}
#[test]
fn actual_ipv4_identical_overlap_valid_conflicting_overlap_tombstone() {
    rt().block_on(async {
        let peer = UdpPeer::new4();
        let data = vec![0x5a; 1200];
        let p = udp4_packet(&data);
        for f in [
            fragment4(&p, 7, 0, 512, true),
            fragment4(&p, 7, 256, 512, true),
            fragment4(&p, 7, 512, p.len() - 20 - 512, false),
        ] {
            peer.tx.send(f).await.unwrap();
        }
        assert_eq!(peer.receive().await, data);
        let first = fragment4(&p, 8, 0, 512, true);
        let mut bad = fragment4(&p, 8, 256, 512, true).to_vec();
        bad[20] ^= 1;
        for f in
            [first, Bytes::from(bad), fragment4(&p, 8, 512, p.len() - 20 - 512, false), fragment4(&p, 8, 0, 512, true)]
        {
            peer.tx.send(f).await.unwrap();
        }
        peer.quiet().await;
        let control = udp4_packet(b"unfragmented survives");
        peer.tx.send(control).await.unwrap();
        assert_eq!(peer.receive().await, b"unfragmented survives");
    });
}
#[test]
fn actual_ipv4_tcp_split_first_header_and_halfclose() {
    rt().block_on(async {
        let a = NetStack::new(0);
        let b = NetStack::new(0);
        a.set_addresses(&["10.0.0.1".parse().unwrap()]);
        b.set_addresses(&["10.0.0.2".parse().unwrap()]);
        let mut listener = b.listen(7000, 4).unwrap();
        let (atx, arx) = mpsc::channel(512);
        let (btx, brx) = mpsc::channel(512);
        let (ao, mut aw) = mpsc::channel::<Bytes>(512);
        let (bo, mut bw) = mpsc::channel::<Bytes>(512);
        let (arun, brun) = (a.clone(), b.clone());
        let mut workers = vec![
            tokio::spawn(async move { arun.run(arx, ao).await }),
            tokio::spawn(async move { brun.run(brx, bo).await }),
        ];
        async fn link(input: &mut mpsc::Receiver<Bytes>, output: mpsc::Sender<Bytes>) {
            let mut id = 1u16;
            while let Some(p) = input.recv().await {
                let h = usize::from(p[0] & 15) * 4;
                if p[0] >> 4 == 4 && p[9] == 6 && p.len() > h + 8 {
                    id = id.wrapping_add(1);
                    let total = p.len() - h;
                    for f in [fragment4(&p, id, 8, total - 8, false), fragment4(&p, id, 0, 8, true)] {
                        if output.send(f).await.is_err() {
                            return;
                        }
                    }
                } else if output.send(p).await.is_err() {
                    return;
                }
            }
        }
        workers.push(tokio::spawn(async move { link(&mut aw, btx).await }));
        workers.push(tokio::spawn(async move { link(&mut bw, atx).await }));
        workers.push(tokio::spawn(async move {
            let mut s = listener.accept().await.unwrap();
            let mut data = Vec::new();
            s.read_to_end(&mut data).await.unwrap();
            s.write_all(&data).await.unwrap();
            s.shutdown().await.unwrap();
        }));
        let result = tokio::time::timeout(Duration::from_secs(3), async {
            let mut s = a.connect("10.0.0.2:7000".parse::<SocketAddr>().unwrap()).await.unwrap();
            let data: Vec<u8> = (0..65536).map(|n| (n % 251) as u8).collect();
            s.write_all(&data).await.unwrap();
            s.shutdown().await.unwrap();
            let mut reply = Vec::new();
            s.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, data);
        })
        .await;
        for w in workers {
            w.abort();
        }
        result.expect("actual IPv4 TCP fragmented first header/halfclose failed");
    });
}
// Inspect the unchanged vendor internals without imposing workspace style rewrites.
#[allow(
    dead_code,
    unexpected_cfgs,
    clippy::needless_lifetimes,
    clippy::manual_div_ceil,
    clippy::manual_range_contains,
    clippy::manual_is_multiple_of
)]
#[rustfmt::skip]
#[path = "../../../vendor/smoltcp/src/iface/ipv4_reassembly.rs"]
mod ipv4_reassembly;
#[test]
fn fixed_both_family_memory_bound() {
    let v4 = std::mem::size_of::<ipv4_reassembly::Ipv4Ingress>();
    let v6 = std::mem::size_of::<ipv6_input::Ipv6Ingress>();
    println!("fixed IPv4 ingress bytes={v4}, IPv6={v6}, total={}", v4 + v6);
    assert!(v4 + v6 < 120 * 1024);
}

#[test]
fn deterministic_mutations_preserve_parser_bounds_and_recovery() {
    use smoltcp::time::Instant;
    use smoltcp::wire::{Ipv4Packet, Ipv6Packet, Ipv6Repr};
    let original6 = udp_packet(&[0x5a; 1200]);
    let original4 = udp4_packet(&[0x5a; 1200]);
    let corpora = [
        original6.clone(),
        fragment(&original6, 1, 0, 1208, false),
        fragment(&original6, 2, 0, 512, true),
        fragment(&original6, 2, 512, 696, false),
        add_extension(&original6, 0, [17, 0, 0, 0, 0, 0, 0, 0]),
        add_extension(&original6, 60, [17, 0, 0, 0, 0, 0, 0, 0]),
        original4.clone(),
        fragment4(&original4, 3, 0, 512, true),
        fragment4(&original4, 3, 512, 696, false),
    ];
    let mut six = ipv6_input::Ipv6Ingress::new();
    let mut four = ipv4_reassembly::Ipv4Ingress::new();
    let mut random = 0x9e3779b97f4a7c15_u64;
    let mut next = || {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        random
    };
    let mut counts = [0_usize; 2];
    for n in 0..131_072 {
        let mut packet = corpora[n % corpora.len()].to_vec();
        for _ in 0..1 + next() % 8 {
            let offset = next() as usize % packet.len();
            packet[offset] ^= next() as u8;
        }
        if n % 3 == 0 {
            packet.truncate(next() as usize % (packet.len() + 1));
        }
        let now = Instant::from_millis(n as i64 * 100);
        while six.assembler.take_expired(now).is_some() {}
        while four.assembler.take_expired(now).is_some() {}
        match packet.first().map(|byte| byte >> 4) {
            Some(6) => {
                if let Ok(parsed) = Ipv6Packet::new_checked(&packet[..]) {
                    if Ipv6Repr::parse(&parsed).is_ok() {
                        counts[0] += 1;
                        let raw = &packet[..40 + usize::from(parsed.payload_len())];
                        let _ = six.resolve(now, raw);
                        let _ = six.error.make(now, raw, 4, 0, 6, false);
                    }
                }
            }
            Some(4) => {
                if let Ok(parsed) = Ipv4Packet::new_checked(&packet[..]) {
                    counts[1] += 1;
                    let _ = four.assembler.accept(now, &parsed);
                    let _ = four.error.make(now, &packet, 11, 1);
                }
            }
            _ => {}
        }
    }
    assert!(counts.into_iter().all(|n| n > 10_000), "insufficient validated parser inputs: {counts:?}");
    let now = Instant::from_millis(20_000_000);
    while six.assembler.take_expired(now).is_some() {}
    while four.assembler.take_expired(now).is_some() {}
    let first = fragment(&original6, 42, 0, 512, true);
    let last = fragment(&original6, 42, 512, 696, false);
    assert!(matches!(six.resolve(now, &first), Ok(None)));
    assert!(matches!(six.resolve(now, &last), Ok(Some(_))));
    let first = fragment4(&original4, 42, 0, 512, true);
    let last = fragment4(&original4, 42, 512, 696, false);
    assert!(four.assembler.accept(now, &Ipv4Packet::new_checked(&first[..]).unwrap()).is_none());
    assert!(four.assembler.accept(now, &Ipv4Packet::new_checked(&last[..]).unwrap()).is_some());
    println!("deterministic mutation corpus=131072, admitted IPv6={}, IPv4={}", counts[0], counts[1]);
}
