//! Production HTTP/3 client against a raw HTTP/3 server on loopback, through
//! the transport emulator (not Network.framework), which applies the client's
//! close code to the QUIC connection as the app does natively.
//!
//! No frame payload but DATA is buffered beyond 64 KiB (RFC 9114 section
//! 10.5): a longer HEADERS is H3_EXCESSIVE_LOAD from its header, a GOAWAY
//! longer than one varint H3_FRAME_ERROR (section 7.1), an HTTP/2 frame type
//! H3_FRAME_UNEXPECTED (section 7.2.8), and frames of unknown types are
//! discarded as they arrive (section 9). The allocator below records the
//! test's peak heap use, so an unknown frame that was buffered would show.
mod support;
use network_relay_nf_core::{Config, client::Client};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

struct Counting;
static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let now = CURRENT.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

const EXCESSIVE_LOAD: u64 = 0x107;
const FRAME_UNEXPECTED: u64 = 0x105;
const FRAME_ERROR: u64 = 0x106;
/// HEADERS (QPACK, no dynamic table): `:status: 200` (static index 25).
const OK: [u8; 5] = [0x01, 0x03, 0x00, 0x00, 0xd9];
/// A reserved frame type (RFC 9114 section 7.2.8), which must be ignored.
const RESERVED: u64 = 0x21;
/// Unknown-frame payload streamed to the client, and the most the client's
/// heap may grow while it arrives.
const UNKNOWN_PAYLOAD: usize = 128 << 20;
const MAX_GROWTH: usize = 64 << 20;

fn varint(value: u64) -> Vec<u8> {
    match value {
        0..=0x3f => vec![value as u8],
        0x40..=0x3fff => (value as u16 | 0x4000).to_be_bytes().to_vec(),
        0x4000..=0x3fff_ffff => (value as u32 | 0x8000_0000).to_be_bytes().to_vec(),
        _ => (value | 0xc000_0000_0000_0000).to_be_bytes().to_vec(),
    }
}

fn frame_header(ty: u64, len: u64) -> Vec<u8> {
    [varint(ty), varint(len)].concat()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http3_client_bounds_frame_payloads() {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["relay.test".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let ca = std::env::temp_dir().join(format!("relay-nf-frame-limits-{}.pem", std::process::id()));
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
        socks: network_relay_nf_core::Socks {
            listen: vec!["127.0.0.1:0".parse().unwrap()],
        },
    };
    let accept = || async {
        tokio::time::timeout(Duration::from_secs(10), endpoint.accept())
            .await
            .unwrap()
            .unwrap()
            .await
            .unwrap()
    };
    // Control stream: SETTINGS with SETTINGS_ENABLE_CONNECT_PROTOCOL.
    let settings_frame = [0x00, 0x04, 0x02, 0x08, 0x01];

    let huge: u64 = 1 << 40;
    let oversized: u64 = (64 << 10) + 1;
    for (control, response, want, finish) in [
        (
            vec![],
            Some(frame_header(0x01, huge)),
            EXCESSIVE_LOAD,
            false,
        ),
        (
            vec![],
            Some(frame_header(0x01, oversized)),
            EXCESSIVE_LOAD,
            false,
        ),
        (frame_header(0x07, huge), None, FRAME_ERROR, false),
        (frame_header(0x06, huge), None, FRAME_UNEXPECTED, false),
        // A clean FIN cannot hide a truncated ignored response frame.
        (
            vec![],
            Some([frame_header(RESERVED, 2), b"x".to_vec()].concat()),
            FRAME_ERROR,
            true,
        ),
    ] {
        let backend = support::Backend::start(ca.clone());
        let client = Client::new(&settings, backend.bridge.clone()).unwrap();
        let opening = tokio::spawn(async move {
            let _ = client.open("127.0.0.1", 7, false).await;
        });
        let conn = accept().await;
        let mut ctrl = conn.open_uni().await.unwrap();
        ctrl.write_all(&[&settings_frame[..], &control].concat())
            .await
            .unwrap();
        // The streams stay open: a FIN inside a frame would be a truncated
        // frame whatever its length.
        let mut _request = None;
        if let Some(response) = &response {
            let (mut send, recv) = tokio::time::timeout(Duration::from_secs(10), conn.accept_bi())
                .await
                .unwrap()
                .unwrap();
            send.write_all(response).await.unwrap();
            if finish {
                send.finish().unwrap();
            }
            _request = Some((send, recv));
        }
        let closed = tokio::time::timeout(Duration::from_secs(10), conn.closed())
            .await
            .unwrap_or_else(|_| panic!("{control:02x?} {response:02x?}: the client kept waiting"));
        assert!(
            matches!(closed, quinn::ConnectionError::ApplicationClosed(ref c) if c.error_code.into_inner() == want),
            "{control:02x?} {response:02x?}: {closed:?}, want {want:#x}"
        );
        opening.abort();
    }

    // An unknown frame on the control stream is read and discarded, an
    // unknown frame on the request stream skipped, and the tunnel opens.
    let backend = support::Backend::start(ca.clone());
    let client = Client::new(&settings, backend.bridge.clone()).unwrap();
    let opening = tokio::spawn(async move {
        let opened = client.open("127.0.0.1", 7, false).await;
        (client, opened)
    });
    let conn = accept().await;
    let baseline = CURRENT.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let mut ctrl = conn.open_uni().await.unwrap();
    ctrl.write_all(&settings_frame).await.unwrap();
    let flood = tokio::spawn(async move {
        ctrl.write_all(&frame_header(RESERVED, UNKNOWN_PAYLOAD as u64))
            .await
            .unwrap();
        let chunk = vec![0u8; 1 << 20];
        for _ in 0..UNKNOWN_PAYLOAD / chunk.len() {
            ctrl.write_all(&chunk).await.unwrap();
        }
        ctrl
    });
    let (mut send, _recv) = tokio::time::timeout(Duration::from_secs(10), conn.accept_bi())
        .await
        .unwrap()
        .unwrap();
    send.write_all(&[&frame_header(RESERVED, 3)[..], b"abc", &OK[..]].concat())
        .await
        .unwrap();
    let (_client, opened) = tokio::time::timeout(Duration::from_secs(10), opening)
        .await
        .unwrap()
        .unwrap();
    let _opened = opened.expect("a response after an unknown frame did not open the tunnel");
    let _ctrl = tokio::time::timeout(Duration::from_secs(120), flood)
        .await
        .expect("the client stopped reading its control stream")
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(conn.close_reason().is_none(), "{:?}", conn.close_reason());
    let growth = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
    assert!(
        growth < MAX_GROWTH,
        "heap grew by {growth} bytes while a {UNKNOWN_PAYLOAD}-byte unknown frame arrived"
    );
    let _ = std::fs::remove_file(&ca);
}
