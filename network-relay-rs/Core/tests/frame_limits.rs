//! Production HTTP/3 client against a raw HTTP/3 server on loopback, through
//! the production Rust backend.
//!
//! No frame payload but DATA is buffered beyond 64 KiB (RFC 9114 section
//! 10.5): a longer HEADERS is H3_EXCESSIVE_LOAD from its header, a GOAWAY
//! longer than one varint H3_FRAME_ERROR (section 7.1), an HTTP/2 frame type
//! H3_FRAME_UNEXPECTED (section 7.2.8), and frames of unknown types are
//! discarded as they arrive (section 9). The allocator below records the
//! test's peak heap use, so an unknown frame that was buffered would show.
use network_relay_rs_core::{
    Config, Socks,
    backend::{Backend, BackendOptions},
    client::Client,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    process::Command,
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
    let directory =
        std::env::temp_dir().join(format!("relay-rs-frame-limits-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).unwrap();
    let openssl = |arguments: &[&str]| {
        let output = Command::new("openssl")
            .args(arguments)
            .current_dir(&directory)
            .output()
            .expect("OpenSSL is required by the relay interoperability tests");
        assert!(
            output.status.success(),
            "OpenSSL fixture setup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    std::fs::write(
        directory.join("ca.cnf"),
        "[req]\nprompt=no\ndistinguished_name=subject\nx509_extensions=ca\n\
         [subject]\nCN=Disposable relay test CA\n\
         [ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n",
    )
    .unwrap();
    openssl(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-sha256",
        "-days",
        "2",
        "-config",
        "ca.cnf",
        "-keyout",
        "ca-key.pem",
        "-out",
        "ca.pem",
    ]);
    openssl(&[
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=relay.test",
        "-keyout",
        "key.pem",
        "-out",
        "request.pem",
    ]);
    std::fs::write(
        directory.join("leaf.cnf"),
        "basicConstraints=critical,CA:FALSE\n\
         keyUsage=critical,digitalSignature,keyEncipherment\n\
         extendedKeyUsage=serverAuth\nsubjectAltName=DNS:relay.test\n",
    )
    .unwrap();
    openssl(&[
        "x509",
        "-req",
        "-in",
        "request.pem",
        "-CA",
        "ca.pem",
        "-CAkey",
        "ca-key.pem",
        "-set_serial",
        "2",
        "-days",
        "2",
        "-sha256",
        "-extfile",
        "leaf.cnf",
        "-out",
        "cert.pem",
    ]);
    let certificates = CertificateDer::pem_file_iter(directory.join("cert.pem"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_file(directory.join("key.pem")).unwrap();
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certificates, key)
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
        password: "disposable-test-password".into(),
        server_name: Some("relay.test".into()),
        transport: "h3".into(),
        probe_target: "127.0.0.1:9".parse().unwrap(),
        mode: "socks".into(),
        socks: Socks {
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
    for (control, response, want) in [
        (vec![], Some(frame_header(0x01, huge)), EXCESSIVE_LOAD),
        (vec![], Some(frame_header(0x01, oversized)), EXCESSIVE_LOAD),
        (frame_header(0x07, huge), None, FRAME_ERROR),
        (frame_header(0x06, huge), None, FRAME_UNEXPECTED),
    ] {
        let backend = Backend::start(BackendOptions {
            ca_file: Some(directory.join("ca.pem")),
        })
        .unwrap();
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
    let backend = Backend::start(BackendOptions {
        ca_file: Some(directory.join("ca.pem")),
    })
    .unwrap();
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
    let _ = std::fs::remove_dir_all(&directory);
}
