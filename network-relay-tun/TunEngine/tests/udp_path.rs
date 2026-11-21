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
    let mut sum: u32 = p[..20].as_chunks::<2>().0.iter().map(|w| u32::from(u16::from_be_bytes(*w))).sum();
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
        let (_control, udp) = accept_association(&listener).await;
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
            let mut sum: u32 = fragment.as_chunks::<2>().0.iter().map(|w| u32::from(u16::from_be_bytes(*w))).sum();
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

async fn accept_association(listener: &TcpListener) -> (tokio::net::TcpStream, UdpSocket) {
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
    (control, udp)
}

async fn echoed_payload(size: usize, ipv6: bool, port: u16) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (_control, udp) = accept_association(&listener).await;
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
    // The two 16-byte addresses and UDP header/payload are contiguous.
    let (words, tail) = p[8..].as_chunks::<2>();
    let mut sum: u32 = words.iter().map(|w| u32::from(u16::from_be_bytes(*w))).sum();
    if let [last] = tail {
        sum += u32::from(*last) << 8;
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

fn dns_query(id: u16) -> Vec<u8> {
    let mut bytes = id.to_be_bytes().to_vec();
    bytes.extend_from_slice(b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x00\x00\x01\x00\x01");
    bytes
}

fn client_packet(source_port: u16, port: u16, data: &[u8]) -> Vec<u8> {
    let mut p = ip_packet(data, false, port);
    p[20..22].copy_from_slice(&source_port.to_be_bytes());
    p
}

async fn answer_dns(udp: &UdpSocket, replies: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>, query: &[u8]) {
    let mut buf = [0; 512];
    let (len, peer) = udp.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[10..len], query);
    buf[12] |= 0x80; // QR: this fixture returns NOERROR with no answer records.
    udp.send_to(&buf[..len], peer).await.unwrap();
    let reply = replies.recv().await.unwrap();
    assert_eq!(&reply[28..], &buf[10..len]);
}

#[tokio::test]
async fn dns_retry_on_the_same_port_after_socks_control_closes() {
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (device, kernel, mut replies) = common::device();
        let stop = CancellationToken::new();
        let engine = tokio::spawn(run_with_mtu(device, listener.local_addr().unwrap(), 1500, stop.clone()));

        let question = dns_query(1);
        kernel.send(client_packet(12345, 53, &question)).unwrap();
        let (mut old_control, old_udp) = accept_association(&listener).await;
        let mut buf = [0; 512];
        old_udp.recv_from(&mut buf).await.unwrap();
        // Keep the old UDP port bound: only the control FIN signals the end
        // of the SOCKS association. The client has not received a DNS answer.
        old_control.shutdown().await.unwrap();
        let retired = timeout(Duration::from_secs(1), old_control.read(&mut buf)).await;

        kernel.send(client_packet(12345, 53, &question)).unwrap();
        let (_control, udp) = timeout(Duration::from_secs(2), accept_association(&listener))
            .await
            .expect("the same-port DNS retry could not open a fresh association");
        assert_eq!(retired.unwrap().unwrap(), 0);
        answer_dns(&udp, &mut replies, &question).await;
        stop.cancel();
        engine.await.unwrap().unwrap();
    })
    .await
    .expect("the worker kept sending queries to a retired SOCKS association");
}

#[tokio::test]
async fn completed_dns_can_yield_capacity_without_interrupting_pending_queries() {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        // Three slots model the production budget using just three ordinary
        // DNS clients. Completed queries can keep their association while
        // there is spare capacity; unanswered queries must keep theirs.
        let args = tun2proxy::Args {
            proxy: format!("socks5://{}", listener.local_addr().unwrap()).parse().unwrap(),
            max_sessions: 3,
            udp_timeout: 120,
            ..Default::default()
        };
        let (device, kernel, mut replies) = common::device();
        let stop = CancellationToken::new();
        let engine = tokio::spawn(tun2proxy::run(device, 1500, args, stop.clone()));

        let question = dns_query(1);
        kernel.send(client_packet(12001, 53, &question)).unwrap();
        let (mut first, udp1) = accept_association(&listener).await;
        answer_dns(&udp1, &mut replies, &question).await;
        let mut eof = [0];
        assert!(timeout(Duration::from_millis(1200), first.read(&mut eof)).await.is_err());

        let second = dns_query(2);
        kernel.send(client_packet(12002, 53, &second)).unwrap();
        let (_c2, udp2) = accept_association(&listener).await;
        let third = dns_query(3);
        kernel.send(client_packet(12003, 53, &third)).unwrap();
        let (_c3, udp3) = accept_association(&listener).await;
        let retired = timeout(Duration::from_secs(3), first.read(&mut eof)).await;

        let fourth = dns_query(4);
        kernel.send(client_packet(12004, 53, &fourth)).unwrap();
        let (_c4, udp4) = timeout(Duration::from_secs(2), accept_association(&listener))
            .await
            .expect("a new lookup could not open while an answered DNS mapping occupied the budget");
        assert_eq!(retired.unwrap().unwrap(), 0);
        answer_dns(&udp4, &mut replies, &fourth).await;
        answer_dns(&udp3, &mut replies, &third).await;
        answer_dns(&udp2, &mut replies, &second).await;
        stop.cancel();
        engine.await.unwrap().unwrap();
    })
    .await
    .expect("new DNS lookup stalled while active queries were pending");
}
