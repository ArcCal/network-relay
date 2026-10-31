//! HTTP/1.1 close boundaries through the production NF core and its test-only
//! TLS bridge. A TLS close_notify is orderly EOF; a reset without it is an
//! error. A later raw TCP reset cannot retroactively invalidate delivered EOF.
mod support;

use network_relay_nf_core::{Config, client::Client, stream::Duplex};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};

const PAYLOAD: &[u8] = b"complete TLS tunnel payload";
const UPLOAD: &[u8] = b"upload after the receive half closes";

#[derive(Clone, Copy, Debug)]
enum Ending {
    HalfClose,
    ResetWithoutNotify,
    NotifyThenReset,
}

struct Certificate(PathBuf);
impl Drop for Certificate {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn exercise(ending: Ending, socks: bool) {
    let key = rcgen::KeyPair::generate().unwrap();
    let certificate = rcgen::CertificateParams::new(vec!["relay.test".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let ca = Certificate(std::env::temp_dir().join(format!(
        "relay-nf-h1-close-{}-{ending:?}-{socks}.pem",
        std::process::id()
    )));
    std::fs::write(&ca.0, certificate.pem()).unwrap();
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate.der().clone()],
        rustls_pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    )
    .unwrap();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (send_payload_tx, send_payload) = oneshot::channel();
    let (payload_read_tx, payload_read) = oneshot::channel();
    let (eof_read_tx, eof_read) = oneshot::channel();
    let server = tokio::spawn(async move {
        let mut probes = tokio::task::JoinSet::new();
        let mut tls = loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                headers.push(tls.read_u8().await.unwrap());
                assert!(headers.len() < 8192);
            }
            // The real SOCKS runner concurrently performs its admission
            // probe. Keep that separate from the CONNECT close fixture.
            if headers.starts_with(b"GET ") {
                probes.spawn(async move {
                    tls.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n")
                        .await
                        .unwrap();
                    let _ = tls.read_u8().await;
                });
                continue;
            }
            assert!(headers.starts_with(b"CONNECT "));
            break tls;
        };
        tls.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        tls.flush().await.unwrap();
        // Wait until the local handshake is complete so its bytes and the
        // concurrent admission probe can be checked before any payload flows.
        send_payload.await.unwrap();
        tls.write_all(PAYLOAD).await.unwrap();
        tls.flush().await.unwrap();
        // The reset test concerns terminal semantics, not whether a kernel
        // discards payload that has not yet reached the peer when RST is sent.
        payload_read.await.unwrap();
        match ending {
            Ending::HalfClose => {
                tls.shutdown().await.unwrap();
                let mut upload = Vec::new();
                tls.read_to_end(&mut upload).await.unwrap();
                assert_eq!(upload, UPLOAD);
            }
            Ending::ResetWithoutNotify => {
                let (tcp, _) = tls.into_inner();
                tcp.set_zero_linger().unwrap();
                drop(tcp);
            }
            Ending::NotifyThenReset => {
                // Flush only the TLS alert, preserving the TCP write side.
                // Wait until the client observes that authenticated TLS EOF
                // before sending a later TCP reset. Do not invent an error
                // merely because an otherwise orderly tunnel ends.
                tls.get_mut().1.send_close_notify();
                tls.flush().await.unwrap();
                eof_read.await.unwrap();
                let (tcp, _) = tls.into_inner();
                tcp.set_zero_linger().unwrap();
                drop(tcp);
            }
        }
    });
    let backend = support::Backend::start(ca.0.clone());
    let config = Config {
        uri_template: format!(
            "https://{address}/.well-known/masque/udp/{{target_host}}/{{target_port}}/"
        ),
        username: "alice".into(),
        password: "disposable-close-fixture-password".into(),
        server_name: Some("relay.test".into()),
        transport: "http/1.1".into(),
        probe_target: "127.0.0.1:9".parse().unwrap(),
        mode: "socks".into(),
        socks: network_relay_nf_core::Socks {
            listen: vec!["127.0.0.1:0".parse().unwrap()],
        },
    };
    let client = Arc::new(Client::new(&config, backend.bridge.clone()).unwrap());
    let mut worker = None;
    let mut io: Box<dyn Duplex> = if socks {
        let listener = backend
            .bridge
            .listen("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        worker = Some(tokio::spawn(network_relay_nf_core::socks::run(
            client.clone(),
            vec![listener],
        )));
        let mut local = TcpStream::connect(address).await.unwrap();
        local.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0; 2];
        local.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0]);
        local
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 7])
            .await
            .unwrap();
        let mut reply = [0; 10];
        local.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0);
        Box::new(local)
    } else {
        Box::new(client.open("127.0.0.1", 7, false).await.unwrap().stream)
    };
    let before_payload = client.bridge.traffic.snapshot();
    assert_eq!(
        (before_payload.upload_bytes, before_payload.download_bytes),
        (0, 0),
        "SOCKS, CONNECT and admission-probe handshakes are not payload"
    );
    send_payload_tx.send(()).unwrap();
    let mut payload = vec![0; PAYLOAD.len()];
    io.read_exact(&mut payload).await.unwrap();
    assert_eq!(payload, PAYLOAD);
    payload_read_tx.send(()).unwrap();
    let mut tail = Vec::new();
    let outcome = io.read_to_end(&mut tail).await;
    assert!(tail.is_empty());
    match ending {
        Ending::ResetWithoutNotify => {
            let error = outcome.expect_err("abrupt TLS failure became clean EOF");
            if socks {
                assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
            }
        }
        Ending::HalfClose => {
            outcome.unwrap();
            io.write_all(UPLOAD).await.unwrap();
            io.shutdown().await.unwrap();
        }
        Ending::NotifyThenReset => {
            outcome.expect("authenticated TLS close_notify must remain orderly EOF");
            eof_read_tx.send(()).unwrap();
        }
    }
    server.await.unwrap();
    let expected_upload = if socks && matches!(ending, Ending::HalfClose) {
        UPLOAD.len() as u64
    } else {
        0
    };
    let expected_download = if socks { PAYLOAD.len() as u64 } else { 0 };
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let snapshot = client.bridge.traffic.snapshot();
            if (snapshot.upload_bytes, snapshot.download_bytes)
                == (expected_upload, expected_download)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{ending:?}, SOCKS={socks}: payload totals {:?}, expected ({expected_upload}, {expected_download})",
            client.bridge.traffic.snapshot()
        )
    });
    drop(io);
    if let Some(worker) = worker {
        worker.abort();
        let _ = worker.await;
    }
    let ended = client.bridge.traffic.snapshot();
    assert_eq!(
        (ended.upload_bytes, ended.download_bytes),
        (expected_upload, expected_download),
        "closing or aborting a flow must preserve its payload totals"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h1_tls_close_notify_reset_and_half_close_remain_distinct() {
    for socks in [false, true] {
        for ending in [
            Ending::HalfClose,
            Ending::ResetWithoutNotify,
            Ending::NotifyThenReset,
        ] {
            tokio::time::timeout(Duration::from_secs(15), exercise(ending, socks))
                .await
                .unwrap_or_else(|_| panic!("{ending:?}, SOCKS={socks}: close fixture stalled"));
        }
    }
}
