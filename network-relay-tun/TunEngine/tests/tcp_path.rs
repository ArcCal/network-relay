mod common;
use network_relay_tun_engine::{CancellationToken, run};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::{Duration, timeout},
};
fn checksum(data: &[u8]) -> u16 {
    let mut n: u32 = data.chunks(2).map(|v| (v[0] as u32) * 256 + v.get(1).copied().unwrap_or(0) as u32).sum();
    while n > 65535 {
        n = (n & 65535) + (n >> 16);
    }
    !(n as u16)
}
fn packet(seq: u32, ack: u32, flags: u8, payload: &[u8], port: u16) -> Vec<u8> {
    let mut p = vec![0; 40];
    p[0] = 0x45;
    p[8] = 64;
    p[9] = 6;
    p[2..4].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
    p[12..20].copy_from_slice(&[192, 0, 2, 1, 198, 51, 100, 2]);
    let c = checksum(&p[..20]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p[20..22].copy_from_slice(&12345u16.to_be_bytes());
    p[22..24].copy_from_slice(&port.to_be_bytes());
    p[24..28].copy_from_slice(&seq.to_be_bytes());
    p[28..32].copy_from_slice(&ack.to_be_bytes());
    p[32] = 0x50;
    p[33] = flags;
    p[34..36].copy_from_slice(&65535u16.to_be_bytes());
    p.extend_from_slice(payload);
    let mut pseudo = p[12..20].to_vec();
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    pseudo.extend_from_slice(&p[20..]);
    let c = checksum(&pseudo);
    p[36..38].copy_from_slice(&c.to_be_bytes());
    p
}
async fn round_trip(port: u16, combined_fin: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut peer, _) = listener.accept().await.unwrap();
        let mut hello = [0; 2];
        peer.read_exact(&mut hello).await.unwrap();
        let mut methods = vec![0; hello[1] as usize];
        peer.read_exact(&mut methods).await.unwrap();
        peer.write_all(&[5, 0]).await.unwrap();
        let mut request = [0; 10];
        peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request[..8], &[5, 1, 0, 1, 198, 51, 100, 2]);
        assert_eq!(&request[8..], port.to_be_bytes());
        peer.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await.unwrap();
        let mut upload = Vec::new();
        peer.read_to_end(&mut upload).await.unwrap();
        assert_eq!(upload, b"request");
        // A peer must still be able to reply after receiving the client's FIN.
        peer.write_all(b"response after FIN").await.unwrap();
        peer.shutdown().await.unwrap();
    });
    let (device, tx, mut rx) = common::device();
    let stop = CancellationToken::new();
    let engine = tokio::spawn(run(device, endpoint, stop.clone()));
    tx.send(packet(100, 0, 2, &[], port)).unwrap();
    let syn = rx.recv().await.unwrap();
    assert_eq!(syn[33] & 0x12, 0x12);
    let mut remote = u32::from_be_bytes(syn[24..28].try_into().unwrap()) + 1;
    tx.send(packet(101, remote, 16, &[], port)).unwrap();
    if combined_fin {
        tx.send(packet(101, remote, 25, b"request", port)).unwrap();
    } else {
        tx.send(packet(101, remote, 24, b"request", port)).unwrap();
        tx.send(packet(108, remote, 17, &[], port)).unwrap();
    }
    let mut received = Vec::new();
    loop {
        let p = rx.recv().await.unwrap();
        let header = 20 + (p[32] >> 4) as usize * 4;
        let seq = u32::from_be_bytes(p[24..28].try_into().unwrap());
        if !p[header..].is_empty() && seq == remote {
            received.extend_from_slice(&p[header..]);
            remote += p[header..].len() as u32;
        }
        let fin = p[33] & 1 != 0;
        if fin {
            remote += 1;
        }
        tx.send(packet(109, remote, 16, &[], port)).unwrap();
        if fin {
            break;
        }
    }
    assert_eq!(received, b"response after FIN");
    server.await.unwrap();
    stop.cancel();
    engine.await.unwrap().unwrap();
}
#[tokio::test]
async fn tcp_and_dns_tcp_preserve_half_close() {
    timeout(Duration::from_secs(10), async {
        round_trip(443, false).await;
        round_trip(53, false).await;
        round_trip(443, true).await;
    })
    .await
    .unwrap();
}
