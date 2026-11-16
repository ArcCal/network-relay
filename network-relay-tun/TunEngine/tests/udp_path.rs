mod common;
use network_relay_tun_engine::{CancellationToken, run_with_mtu};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    time::{Duration, timeout},
};

fn packet(payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 28];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&[192, 0, 2, 1]);
    p[16..20].copy_from_slice(&[198, 51, 100, 2]);
    let mut sum: u32 = p[..20].chunks_exact(2).map(|w| u16::from_be_bytes([w[0], w[1]]) as u32).sum();
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    p[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    p[20..22].copy_from_slice(&12345u16.to_be_bytes());
    p[22..24].copy_from_slice(&443u16.to_be_bytes());
    p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(payload);
    p
}

async fn forwarded_payload(size: usize, fragmented: bool) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut control, _) = listener.accept().await.unwrap();
        let mut hello = [0u8; 2];
        control.read_exact(&mut hello).await.unwrap();
        let mut methods = vec![0; hello[1] as usize];
        control.read_exact(&mut methods).await.unwrap();
        control.write_all(&[5, 0]).await.unwrap();
        let mut request = [0u8; 10];
        control.read_exact(&mut request).await.unwrap();
        assert_eq!(&request[..4], &[5, 3, 0, 1]);
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut reply = vec![5, 0, 0, 1, 127, 0, 0, 1];
        reply.extend_from_slice(&udp.local_addr().unwrap().port().to_be_bytes());
        control.write_all(&reply).await.unwrap();
        let mut data = vec![0; 65536];
        let (len, _) = udp.recv_from(&mut data).await.unwrap();
        assert_eq!(&data[..10], &[0, 0, 0, 1, 198, 51, 100, 2, 1, 187]);
        data[10..len].to_vec()
    });
    let (device, kernel, mut replies) = common::device();
    let stop = CancellationToken::new();
    let engine = tokio::spawn(run_with_mtu(device, endpoint, if fragmented { 1500 } else { 9000 }, stop.clone()));
    let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let whole = packet(&payload);
    if fragmented {
        let chunks: Vec<_> = whole[20..].chunks(1280).collect();
        for index in (0..chunks.len()).rev() {
            let chunk = chunks[index];
            let mut fragment = whole[..20].to_vec();
            fragment[2..4].copy_from_slice(&((20 + chunk.len()) as u16).to_be_bytes());
            let flags = (index * 160) as u16 | if index + 1 < chunks.len() { 0x2000 } else { 0 };
            fragment[6..8].copy_from_slice(&flags.to_be_bytes());
            fragment[10..12].fill(0);
            let mut sum: u32 = fragment.chunks_exact(2).map(|w| u16::from_be_bytes([w[0], w[1]]) as u32).sum();
            while sum > 65535 {
                sum = (sum & 65535) + (sum >> 16);
            }
            fragment[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
            fragment.extend_from_slice(chunk);
            kernel.send(fragment).unwrap();
        }
    } else {
        kernel.send(whole).unwrap();
    }
    // Keep the receive half alive until the worker stops.
    let _ = &mut replies;
    let received = timeout(Duration::from_secs(3), server).await;
    stop.cancel();
    let _ = timeout(Duration::from_secs(3), engine).await.unwrap();
    received.unwrap().unwrap()
}
#[tokio::test]
async fn udp_packet_reaches_local_nf_socks_boundary() {
    assert_eq!(forwarded_payload(100, false).await, (0..100).map(|i| (i % 251) as u8).collect::<Vec<_>>());
}
#[tokio::test]
async fn udp_large_payload_is_not_silently_truncated() {
    assert_eq!(forwarded_payload(8192, false).await.len(), 8192);
}

#[tokio::test]
async fn zero_length_datagram_is_forwarded_instead_of_being_treated_as_eof() {
    assert!(forwarded_payload(0, false).await.is_empty());
}

async fn echoed_payload(size: usize, ipv6: bool, port: u16) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut control, _) = listener.accept().await.unwrap();
        let mut hello = [0u8; 2];
        control.read_exact(&mut hello).await.unwrap();
        let mut methods = vec![0; hello[1] as usize];
        control.read_exact(&mut methods).await.unwrap();
        control.write_all(&[5, 0]).await.unwrap();
        let mut request = [0u8; 10];
        control.read_exact(&mut request).await.unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut reply = vec![5, 0, 0, 1, 127, 0, 0, 1];
        reply.extend_from_slice(&udp.local_addr().unwrap().port().to_be_bytes());
        control.write_all(&reply).await.unwrap();
        let mut data = vec![0; 65536];
        let (len, peer) = udp.recv_from(&mut data).await.unwrap();
        // A response claiming another target must not be injected into this flow.
        let mut wrong = data[..len].to_vec();
        wrong[9] ^= 1;
        udp.send_to(&wrong, peer).await.unwrap();
        udp.send_to(&data[..len], peer).await.unwrap();
        data[if ipv6 { 22 } else { 10 }..len].to_vec()
    });
    let (device, kernel, mut replies) = common::device();
    let stop = CancellationToken::new();
    let engine = tokio::spawn(run_with_mtu(device, endpoint, 9000, stop.clone()));
    let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    kernel.send(ip_packet(&payload, ipv6, port)).unwrap();
    let response = timeout(Duration::from_secs(3), replies.recv()).await.unwrap().unwrap();
    let count = response.len();
    let header = if ipv6 { 48 } else { 28 };
    assert_eq!(count, header + size);
    if ipv6 {
        assert_eq!(&response[8..24], &ip_packet(&payload, true, port)[24..40]);
        assert_eq!(&response[24..40], &ip_packet(&payload, true, port)[8..24]);
    } else {
        assert_eq!(&response[12..20], &[198, 51, 100, 2, 192, 0, 2, 1]);
    }
    assert_eq!(&response[header..count], payload);
    assert_eq!(server.await.unwrap(), payload);
    stop.cancel();
    timeout(Duration::from_secs(3), engine).await.unwrap().unwrap().unwrap();
}
#[tokio::test]
async fn empty_and_jumbo_replies_preserve_datagram_boundaries() {
    echoed_payload(0, false, 443).await;
    echoed_payload(8192, false, 443).await;
}

fn ip_packet(payload: &[u8], ipv6: bool, port: u16) -> Vec<u8> {
    if !ipv6 {
        let mut p = packet(payload);
        p[22..24].copy_from_slice(&port.to_be_bytes());
        return p;
    }
    let source: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
    let target: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
    let length = (8 + payload.len()) as u16;
    let mut p = vec![0; 48];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&length.to_be_bytes());
    p[6] = 17;
    p[7] = 64;
    p[8..24].copy_from_slice(&source.octets());
    p[24..40].copy_from_slice(&target.octets());
    p[40..42].copy_from_slice(&12345u16.to_be_bytes());
    p[42..44].copy_from_slice(&port.to_be_bytes());
    p[44..46].copy_from_slice(&length.to_be_bytes());
    p.extend_from_slice(payload);
    let mut sum: u32 =
        p[8..40].chunks_exact(2).chain(p[40..].chunks_exact(2)).map(|w| u16::from_be_bytes([w[0], w[1]]) as u32).sum();
    if payload.len() % 2 != 0 {
        sum += (*payload.last().unwrap() as u32) << 8;
    }
    sum += length as u32 + 17;
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    p[46..48].copy_from_slice(&if checksum == 0 { 65535u16 } else { checksum }.to_be_bytes());
    p
}
#[tokio::test]
async fn ipv6_empty_odd_and_large_datagrams_round_trip() {
    for size in [0, 99, 8192] {
        echoed_payload(size, true, 443).await;
    }
}
#[tokio::test]
async fn dns_udp_uses_the_same_relay_boundary() {
    echoed_payload(37, false, 53).await;
    echoed_payload(37, true, 53).await;
}

#[tokio::test]
async fn out_of_order_ip_fragments_reach_socks_as_one_complete_datagram() {
    assert_eq!(forwarded_payload(8192, true).await, (0..8192).map(|i| (i % 251) as u8).collect::<Vec<_>>());
}
