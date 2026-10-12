//! Production HTTP/3 client against a raw HTTP/3 server on loopback, through
//! the transport emulator (not Network.framework), which applies the client's
//! close code to the QUIC connection as the app does natively.
//!
//! The client never sends MAX_PUSH_ID, so its maximum push ID is unset (RFC
//! 9114 section 7.2.7): a server's CANCEL_PUSH (section 7.2.3) or PUSH_PROMISE
//! (section 7.2.5) names a push ID beyond it, H3_ID_ERROR. A MAX_PUSH_ID from a
//! server is H3_FRAME_UNEXPECTED (section 7.2.7), and a malformed payload
//! H3_FRAME_ERROR (section 7.1). The raw server observes the client's close.
mod support;
use network_realy_nf_core::{Config, client::Client};
use std::{sync::Arc, time::Duration};
use tokio::io::AsyncReadExt;

const ID_ERROR: u64 = 0x108;
const FRAME_UNEXPECTED: u64 = 0x105;
const FRAME_ERROR: u64 = 0x106;
/// HEADERS (QPACK, no dynamic table): `:status: 200` (static index 25).
const OK: [u8; 5] = [0x01, 0x03, 0x00, 0x00, 0xd9];
const PUSH_PROMISE: [u8; 6] = [0x05, 0x04, 0x00, 0x00, 0x00, 0xd9];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http3_client_checks_push_frames() {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["relay.test".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let ca = std::env::temp_dir().join(format!("realy-nf-push-frames-{}.pem", std::process::id()));
    std::fs::write(&ca, cert.pem()).unwrap();
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls_pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    )
    .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let address = endpoint.local_addr().unwrap();
    let settings = Config {
        uri_template: format!(
            "https://{address}/.well-known/masque/udp/{{target_host}}/{{target_port}}/"
        ),
        username: "alice".into(),
        password: "disposable-fixture-password".into(),
        server_name: Some("relay.test".into()),
        transport: "h3".into(),
        probe_target: "127.0.0.1:9".parse().unwrap(),
        mode: "socks".into(),
        socks: network_realy_nf_core::Socks {
            listen: vec!["127.0.0.1:0".parse().unwrap()],
        },
    };
    let established = [&OK[..], &PUSH_PROMISE[..]].concat();
    for (control, response, want) in [
        (&[0x03, 0x01, 0x00][..], None, ID_ERROR),
        (&[][..], Some(&PUSH_PROMISE[..]), ID_ERROR),
        // A PUSH_PROMISE after the 200 response that established the tunnel.
        (&[][..], Some(&established[..]), ID_ERROR),
        (&[0x0d, 0x01, 0x00][..], None, FRAME_UNEXPECTED),
        (&[0x03, 0x02, 0x00, 0x00][..], None, FRAME_ERROR),
        (&[0x0d, 0x01, 0x40, 0x07, 0x01, 0x00][..], None, FRAME_ERROR),
    ] {
        let backend = support::Backend::start(ca.clone());
        let client = Client::new(&settings, backend.bridge.clone()).unwrap();
        let opening = tokio::spawn(async move {
            // An established tunnel is read until the client fails it.
            if let Ok(mut opened) = client.open("127.0.0.1", 7, false).await {
                let mut buf = [0; 64];
                let _ = tokio::time::timeout(Duration::from_secs(5), opened.stream.read(&mut buf))
                    .await;
            }
        });
        let conn = tokio::time::timeout(Duration::from_secs(10), endpoint.accept())
            .await
            .unwrap()
            .unwrap()
            .await
            .unwrap();
        let mut ctrl = conn.open_uni().await.unwrap();
        // Control stream: SETTINGS with SETTINGS_ENABLE_CONNECT_PROTOCOL,
        // then the frames under test.
        let mut bytes = vec![0x00, 0x04, 0x02, 0x08, 0x01];
        bytes.extend_from_slice(control);
        ctrl.write_all(&bytes).await.unwrap();
        if let Some(response) = response {
            let (mut send, _recv) = tokio::time::timeout(Duration::from_secs(10), conn.accept_bi())
                .await
                .unwrap()
                .unwrap();
            send.write_all(response).await.unwrap();
        }
        let closed = tokio::time::timeout(Duration::from_secs(10), conn.closed())
            .await
            .unwrap();
        assert!(
            matches!(closed, quinn::ConnectionError::ApplicationClosed(ref c) if c.error_code.into_inner() == want),
            "{control:02x?} {response:02x?}: {closed:?}, want {want:#x}"
        );
        opening.abort();
    }
    let _ = std::fs::remove_file(&ca);
}
