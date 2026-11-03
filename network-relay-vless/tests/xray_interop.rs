//! network-relay-vless against a real Xray-core VLESS server, configured as
//! the documented inbound (VLESS, WebSocket, `security: none`, sniffing for
//! http, quic and tls), with a freedom outbound.
//!
//! Every destination is a loopback fixture: 127.0.0.2 is allowed; the relay
//! blocks 127.0.0.1 and 127.0.0.3. Names resolve through the VLESS server
//! with a fixture DNS server. The tests need an Xray-core binary in
//! `XRAY_BIN` and are ignored otherwise; `scripts/test-xray.sh` runs them.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use bytes::{Buf, Bytes};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{rdata, RData, Record, RecordType};
use http::{header::AUTHORIZATION, Method, Request, StatusCode};
use network_relay::check::{self, H3};
use network_relay::tunnel::Event;
use network_relay::{auth, certs::CertStore, config::Config, server};
use network_relay_vless::{FileConfig, VlessEgress};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

const UUID: &str = "b4e4fad1-c320-428e-92dc-f8f6944a7dec";
const WS_PATH: &str = "/J2kV4jxviMDXceRQYVXiv6YwCc462T6P0Dayx5JYR8R";
const USER: &str = "vless-user";
const PASSWORD: &str = "ephemeral-vless-test-password-2026";
const WAIT: Duration = Duration::from_secs(20);
const NEEDS_XRAY: &str = "needs an Xray-core binary in XRAY_BIN; run scripts/test-xray.sh";

const ALLOWED: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const BLOCKED: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);
const LOCALHOST: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

// ------------------------------------------------------------ environment

struct Dir(PathBuf);

impl Dir {
    fn new(label: &str) -> Result<Self> {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-runtime").join(format!(
            "{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path)?;
        Ok(Self(path))
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A free TCP port on `ip` whose UDP side is free too.
fn free_port(ip: Ipv4Addr) -> u16 {
    loop {
        let tcp = std::net::TcpListener::bind((ip, 0)).unwrap();
        let port = tcp.local_addr().unwrap().port();
        if std::net::UdpSocket::bind((ip, port)).is_ok() {
            return port;
        }
    }
}

struct Xray {
    child: tokio::process::Child,
    port: u16,
    _dir: Dir,
}

impl Xray {
    /// The documented inbound on 127.0.0.1 and a free port, and a freedom
    /// outbound. `route_only` sets `sniffing.routeOnly`. Xray-core 26 blocks
    /// private destinations of VLESS inbounds by default; the fixtures are
    /// on loopback, so this test server allows 127.0.0.0/8. Sniffing makes
    /// Xray-core resolve the HTTP Host itself, so it knows fixture.test too.
    async fn start(route_only: bool) -> Result<Self> {
        let binary = std::env::var_os("XRAY_BIN").context(NEEDS_XRAY)?;
        let dir = Dir::new("xray")?;
        let port = free_port(LOCALHOST);
        let config = format!(
            r#"{{
  "log": {{ "loglevel": "{}" }},
  "inbounds": [{{
    "listen": "127.0.0.1", "port": {port}, "protocol": "vless",
    "settings": {{ "clients": [{{ "id": "{UUID}" }}], "decryption": "none" }},
    "streamSettings": {{ "network": "ws", "security": "none", "wsSettings": {{ "path": "{WS_PATH}" }} }},
    "sniffing": {{ "enabled": true, "destOverride": ["http", "quic", "tls"], "routeOnly": {route_only} }}
  }}],
  "dns": {{ "hosts": {{ "fixture.test": "127.0.0.2" }} }},
  "outbounds": [{{ "protocol": "freedom",
    "settings": {{ "domainStrategy": "UseIP", "finalRules": [{{ "action": "allow", "ip": ["127.0.0.0/8"] }}] }} }}]
}}"#,
            std::env::var("XRAY_LOG").unwrap_or_else(|_| "warning".into())
        );
        let path = dir.0.join("xray.json");
        std::fs::write(&path, config)?;
        let child = tokio::process::Command::new(binary)
            .arg("run")
            .arg("-c")
            .arg(&path)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .context("starting Xray-core")?;
        let deadline = tokio::time::Instant::now() + WAIT;
        while tokio::net::TcpStream::connect((LOCALHOST, port)).await.is_err() {
            ensure!(tokio::time::Instant::now() < deadline, "Xray-core did not start listening");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok(Self { child, port, _dir: dir })
    }
}

impl Drop for Xray {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

// --------------------------------------------------------------- fixtures

struct Fixture {
    port: u16,
    accepted: Arc<AtomicUsize>,
    _task: JoinHandle<()>,
}

/// A web server that answers every request with `body`.
async fn web(ip: Ipv4Addr, port: u16, body: &'static str) -> Fixture {
    let listener = TcpListener::bind((ip, port)).await.unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    let task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                let answer =
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                let _ = socket.write_all(answer.as_bytes()).await;
            });
        }
    });
    Fixture { port, accepted, _task: task }
}

async fn tcp_echo(ip: Ipv4Addr) -> Fixture {
    let listener = TcpListener::bind((ip, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    let task = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let (mut r, mut w) = socket.into_split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    Fixture { port, accepted, _task: task }
}

async fn udp_echo(ip: Ipv4Addr) -> Fixture {
    let socket = UdpSocket::bind((ip, 0)).await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            count.fetch_add(1, Ordering::SeqCst);
            let _ = socket.send_to(&buf[..n], from).await;
        }
    });
    Fixture { port, accepted, _task: task }
}

/// The answer to a DNS query: fixture.test is 127.0.0.2, blocked.test
/// 127.0.0.3, other names do not exist; there are no AAAA records.
fn dns_answer(query: &[u8]) -> Option<Vec<u8>> {
    let query = Message::from_vec(query).ok()?;
    let question = query.queries().first()?.clone();
    let mut answer = Message::new();
    answer.set_id(query.id()).set_message_type(MessageType::Response).set_recursion_available(true);
    answer.add_query(question.clone());
    let name = question.name().to_ascii().to_ascii_lowercase();
    let address = match name.as_str() {
        "fixture.test." => Some(ALLOWED),
        "blocked.test." => Some(BLOCKED),
        "." => None,
        _ => {
            answer.set_response_code(ResponseCode::NXDomain);
            None
        }
    };
    if let (Some(ip), RecordType::A) = (address, question.query_type()) {
        answer.add_answer(Record::from_rdata(question.name().clone(), 60, RData::A(rdata::A(ip))));
    }
    answer.to_vec().ok()
}

/// A DNS server on UDP and TCP, on the same port.
async fn dns(ip: Ipv4Addr) -> Fixture {
    let port = free_port(ip);
    let udp = UdpSocket::bind((ip, port)).await.unwrap();
    let tcp = TcpListener::bind((ip, port)).await.unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    let task = tokio::spawn(async move {
        let udp_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, from)) = udp.recv_from(&mut buf).await {
                if let Some(answer) = dns_answer(&buf[..n]) {
                    let _ = udp.send_to(&answer, from).await;
                }
            }
        });
        while let Ok((mut socket, _)) = tcp.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                loop {
                    let Ok(length) = socket.read_u16().await else { return };
                    let mut query = vec![0; length as usize];
                    if socket.read_exact(&mut query).await.is_err() {
                        return;
                    }
                    let Some(answer) = dns_answer(&query) else { return };
                    let mut wire = (answer.len() as u16).to_be_bytes().to_vec();
                    wire.extend_from_slice(&answer);
                    if socket.write_all(&wire).await.is_err() {
                        return;
                    }
                }
            });
        }
        udp_task.abort();
    });
    Fixture { port, accepted, _task: task }
}

// ------------------------------------------------------------------ relay

struct Relay {
    addr: SocketAddr,
    ca: PathBuf,
    tasks: Vec<JoinHandle<()>>,
    _dir: Dir,
}

impl Drop for Relay {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn write_certificates(path: &Path) -> Result<()> {
    let ca_key = rcgen::KeyPair::generate()?;
    let mut ca_params = rcgen::CertificateParams::new(Vec::new())?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(rcgen::DnType::CommonName, "Ephemeral VLESS test CA");
    let ca = ca_params.self_signed(&ca_key)?;
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let key = rcgen::KeyPair::generate()?;
    let cert = rcgen::CertificateParams::new(vec!["relay.test".into()])?.signed_by(&key, &issuer)?;
    std::fs::write(path.join("ca.pem"), ca.pem())?;
    std::fs::write(path.join("fullchain.pem"), cert.pem() + &ca.pem())?;
    std::fs::write(path.join("privkey.pem"), key.serialize_pem())?;
    Ok(())
}

/// The relay, configured from one network-relay-vless file, with tunnels
/// through the VLESS server at `vless_port` with user ID `uuid`.
async fn relay(vless_port: u16, uuid: &str, dns_port: u16) -> Result<Relay> {
    let dir = Dir::new("relay")?;
    write_certificates(&dir.0)?;
    let (udp, tcp) = loop {
        let udp = std::net::UdpSocket::bind((LOCALHOST, 0))?;
        if let Ok(tcp) = TcpListener::bind(udp.local_addr()?).await {
            break (udp, tcp);
        }
    };
    let addr = udp.local_addr()?;
    static HASH: OnceLock<String> = OnceLock::new();
    let hash = HASH.get_or_init(|| auth::hash_password(PASSWORD).expect("hashing the fixture password"));
    let text = format!(
        "listen = \"{addr}\"\n[tls]\ncert = {:?}\nkey = {:?}\n[relay]\n\
         blocked_destinations = [\"127.0.0.1/32\", \"127.0.0.3/32\"]\nblocked_ports = []\n\
         block_own_addresses = false\nconnect_timeout_secs = 5\n\
         [[user]]\nname = \"{USER}\"\npassword_hash = \"{hash}\"\n\
         [vless]\nserver = \"127.0.0.1:{vless_port}\"\nuuid = \"{uuid}\"\ntransport = \"ws\"\nsecurity = \"none\"\n\
         path = \"{WS_PATH}\"\nhost = \"vless.example.test\"\ndns_servers = [\"{ALLOWED}:{dns_port}\"]\n",
        dir.0.join("fullchain.pem"),
        dir.0.join("privkey.pem"),
    );
    let FileConfig { relay: config, vless, .. } = FileConfig::from_toml(&text)?;
    let config: Config = config;
    let certs = CertStore::open(&config.tls.cert, &config.tls.key)?;
    let relay = server::Relay::with_egress(&config, Arc::new(VlessEgress::new(vless)))?;
    let endpoint = server::quic_endpoint(certs.clone(), udp, false)?;
    let tasks = vec![
        tokio::spawn(relay.clone().serve_quic(endpoint)),
        tokio::spawn(relay.clone().serve_tcp(tcp, server::tcp_tls_config(certs, false)?)),
    ];
    Ok(Relay { addr, ca: dir.0.join("ca.pem"), tasks, _dir: dir })
}

impl Relay {
    fn options(&self, tcp_target: String, udp_target: (String, u16)) -> check::Options {
        check::Options {
            host: "relay.test".into(),
            port: self.addr.port(),
            addresses: vec![self.addr],
            user: USER.into(),
            password: PASSWORD.into(),
            udp_template: network_relay::proto::DEFAULT_UDP_PATH_TEMPLATE.into(),
            tcp_target,
            udp_target,
            dns_name: "fixture.test".into(),
            ca: Some(self.ca.clone()),
            client_cert: None,
            timeout: WAIT,
        }
    }

    async fn h3(&self) -> Result<H3> {
        let opts = self.options(String::new(), (String::new(), 0));
        H3::connect(&opts, &[self.addr]).await
    }
}

fn connect_request(target: &str) -> Request<()> {
    Request::builder()
        .method(Method::CONNECT)
        .uri(target)
        .header(AUTHORIZATION, auth::basic_authorization(USER, PASSWORD))
        .body(())
        .unwrap()
}

/// Sends `request` through a CONNECT tunnel to `target` and returns what
/// comes back until the destination closes, or the status if refused.
async fn fetch(h3: &mut H3, target: &str, request: &[u8]) -> Result<std::result::Result<Vec<u8>, Refused>> {
    let mut stream = h3.request(connect_request(target)).await?;
    let response = tokio::time::timeout(WAIT, stream.recv_response()).await??;
    if response.status() != StatusCode::OK {
        let proxy_status = response.headers().get("proxy-status").and_then(|v| v.to_str().ok()).unwrap_or("");
        return Ok(Err(Refused(response.status(), proxy_status.to_string())));
    }
    let (mut send, mut recv) = stream.split();
    send.send_data(Bytes::copy_from_slice(request)).await?;
    let mut got = Vec::new();
    loop {
        match tokio::time::timeout(WAIT, recv.recv_data()).await? {
            Ok(Some(mut data)) => got.extend_from_slice(&data.copy_to_bytes(data.remaining())),
            Ok(None) => return Ok(Ok(got)),
            Err(e) => bail!("tunnel failed after {} bytes: {e}", got.len()),
        }
    }
}

/// A refusal: the status and the Proxy-Status field.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Refused(StatusCode, String);

fn refused(status: StatusCode, error: &str) -> Refused {
    Refused(status, format!("network-relay; error={error}"))
}

fn body(response: &[u8]) -> &str {
    let text = std::str::from_utf8(response).unwrap_or("");
    text.split("\r\n\r\n").nth(1).unwrap_or("")
}

// ------------------------------------------------------------------ tests

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs an Xray-core binary in XRAY_BIN; run scripts/test-xray.sh"]
async fn network_relay_check_passes_over_every_http_version() -> Result<()> {
    let xray = Xray::start(false).await?;
    let dns = dns(ALLOWED).await;
    let site = web(ALLOWED, free_port(ALLOWED), "fixture site").await;
    let relay = relay(xray.port, UUID, dns.port).await?;
    let opts = relay.options(format!("fixture.test:{}", site.port), ("fixture.test".into(), dns.port));
    let outcomes = check::run(&opts).await;
    for outcome in &outcomes {
        println!("{}: {:?}", outcome.name, outcome.result);
    }
    ensure!(outcomes.len() >= 7, "{} checks ran", outcomes.len());
    for outcome in outcomes {
        outcome.result.with_context(|| outcome.name)?;
    }
    ensure!(site.accepted.load(Ordering::SeqCst) >= 3, "the site was reached over each HTTP version");
    ensure!(dns.accepted.load(Ordering::SeqCst) >= 1, "names were resolved through the VLESS server");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs an Xray-core binary in XRAY_BIN; run scripts/test-xray.sh"]
async fn tcp_bulk_data_and_udp_datagrams_round_trip() -> Result<()> {
    let xray = Xray::start(false).await?;
    let dns = dns(ALLOWED).await;
    let echo = tcp_echo(ALLOWED).await;
    let udp = udp_echo(ALLOWED).await;
    let relay = relay(xray.port, UUID, dns.port).await?;
    let mut h3 = relay.h3().await?;

    // 4 MiB each way, written and read at once.
    let mut stream = h3.request(connect_request(&format!("{ALLOWED}:{}", echo.port))).await?;
    let response = tokio::time::timeout(WAIT, stream.recv_response()).await??;
    ensure!(response.status() == StatusCode::OK, "CONNECT answered {}", response.status());
    let (mut send, mut recv) = stream.split();
    let payload: Vec<u8> = (0..4 << 20).map(|i: u32| (i % 251) as u8).collect();
    let sent = payload.clone();
    let writer = tokio::spawn(async move {
        for chunk in sent.chunks(16 * 1024) {
            send.send_data(Bytes::copy_from_slice(chunk)).await?;
        }
        anyhow::Ok(send)
    });
    let mut got = Vec::with_capacity(payload.len());
    while got.len() < payload.len() {
        let mut data = tokio::time::timeout(WAIT, recv.recv_data()).await??.context("tunnel ended early")?;
        got.extend_from_slice(&data.copy_to_bytes(data.remaining()));
    }
    ensure!(got == payload, "echoed bytes differ");
    let _send = writer.await??;

    // CONNECT-UDP: datagrams of many sizes, each echoed exactly.
    let uri = format!("https://relay.test:{}/.well-known/masque/udp/{ALLOWED}/{}/", relay.addr.port(), udp.port);
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .header("capsule-protocol", "?1")
        .header(AUTHORIZATION, auth::basic_authorization(USER, PASSWORD))
        .extension(h3::ext::Protocol::CONNECT_UDP)
        .body(())?;
    let mut stream = h3.request(request).await?;
    let response = tokio::time::timeout(WAIT, stream.recv_response()).await??;
    ensure!(response.status() == StatusCode::OK, "CONNECT-UDP answered {}", response.status());
    let (mut tunnel, _filter) = h3.udp_tunnel(stream);
    let sizes: Vec<usize> = (0..120).map(|i| 1 + (i * 37) % 1150).collect();
    for (i, size) in sizes.iter().enumerate() {
        let mut datagram = vec![0u8]; // context ID 0: UDP payload
        datagram.extend((0..*size).map(|j| (i + j) as u8));
        tunnel.send_datagram(Bytes::from(datagram.clone()))?;
        let event = tokio::time::timeout(WAIT, tunnel.next_event()).await??;
        match event {
            Event::Datagram(echoed) => ensure!(echoed == datagram, "datagram {i} ({size} bytes) differs"),
            Event::Closed => bail!("the UDP tunnel closed"),
        }
    }
    ensure!(udp.accepted.load(Ordering::SeqCst) == sizes.len(), "every datagram reached the destination once");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs an Xray-core binary in XRAY_BIN; run scripts/test-xray.sh"]
async fn destination_rules_and_name_errors_apply_before_the_vless_server() -> Result<()> {
    let xray = Xray::start(false).await?;
    let dns = dns(ALLOWED).await;
    let port = free_port(BLOCKED);
    let blocked = web(BLOCKED, port, "blocked site").await;
    let relay = relay(xray.port, UUID, dns.port).await?;
    let mut h3 = relay.h3().await?;
    let get = b"GET / HTTP/1.1\r\nHost: example\r\n\r\n";
    // A blocked address is 502 destination_ip_prohibited (RFC 9209), as in
    // network-relay; names are resolved through the VLESS server first.
    let prohibited = refused(StatusCode::BAD_GATEWAY, "destination_ip_prohibited");
    for target in [format!("{BLOCKED}:{port}"), format!("blocked.test:{port}"), format!("{LOCALHOST}:{}", xray.port)] {
        let outcome = fetch(&mut h3, &target, get).await?;
        ensure!(outcome == Err(prohibited.clone()), "{target}: {outcome:?}");
    }
    let outcome = fetch(&mut h3, &format!("missing.test:{port}"), get).await?;
    ensure!(
        matches!(&outcome, Err(Refused(StatusCode::BAD_GATEWAY, status)) if status.contains("error=dns_error")),
        "{outcome:?}"
    );
    ensure!(blocked.accepted.load(Ordering::SeqCst) == 0, "a blocked destination was reached");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs an Xray-core binary in XRAY_BIN; run scripts/test-xray.sh"]
async fn a_rejected_user_id_or_a_missing_server_fails_closed() -> Result<()> {
    let xray = Xray::start(false).await?;
    let dns = dns(ALLOWED).await;
    let site = web(ALLOWED, free_port(ALLOWED), "fixture site").await;
    let get = b"GET / HTTP/1.1\r\nHost: example\r\n\r\n";

    // Xray-core closes a connection with an unknown user ID. VLESS has no
    // refusal message, so the tunnel is answered 200, then fails.
    let wrong = relay(xray.port, "00000000-0000-4000-8000-000000000000", dns.port).await?;
    let mut h3 = wrong.h3().await?;
    let outcome = fetch(&mut h3, &format!("{ALLOWED}:{}", site.port), get).await;
    ensure!(outcome.is_err(), "a rejected user ID must fail the tunnel, got {outcome:?}");
    let name = fetch(&mut h3, &format!("fixture.test:{}", site.port), get).await?;
    ensure!(
        matches!(&name, Err(Refused(StatusCode::BAD_GATEWAY | StatusCode::GATEWAY_TIMEOUT, _))),
        "a name cannot be resolved through it either: {name:?}"
    );

    // Nothing listens: refused at once, never connected directly.
    let down = relay(free_port(LOCALHOST), UUID, dns.port).await?;
    let mut h3 = down.h3().await?;
    let outcome = fetch(&mut h3, &format!("{ALLOWED}:{}", site.port), get).await?;
    ensure!(matches!(&outcome, Err(Refused(StatusCode::BAD_GATEWAY, _))), "{outcome:?}");
    ensure!(site.accepted.load(Ordering::SeqCst) == 0, "the destination was reached without the VLESS server");
    Ok(())
}

/// Not a feature: the documented limit. With sniffing and the default
/// `routeOnly: false`, Xray-core replaces the address the relay checked
/// with the HTTP Host (or TLS/QUIC server name) it sniffs, and connects
/// there itself, so the relay's destination rules do not hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs an Xray-core binary in XRAY_BIN; run scripts/test-xray.sh"]
async fn sniffing_can_override_the_checked_destination_unless_route_only() -> Result<()> {
    let dns = dns(ALLOWED).await;
    let port = free_port(ALLOWED);
    let _allowed = web(ALLOWED, port, "allowed").await;
    // `localhost` resolves to 127.0.0.1 on the VLESS server's host, which
    // the relay blocks.
    let forbidden = web(LOCALHOST, port, "forbidden").await;
    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let target = format!("{ALLOWED}:{port}");

    let xray = Xray::start(false).await?;
    let relay_default = relay(xray.port, UUID, dns.port).await?;
    let mut h3 = relay_default.h3().await?;
    let response = fetch(&mut h3, &target, request).await?.map_err(|r| anyhow::anyhow!("{r:?}"))?;
    ensure!(body(&response) == "forbidden", "sniffing default: {:?}", String::from_utf8_lossy(&response));
    ensure!(forbidden.accepted.load(Ordering::SeqCst) == 1);
    drop(xray);

    let xray = Xray::start(true).await?;
    let relay_route_only = relay(xray.port, UUID, dns.port).await?;
    let mut h3 = relay_route_only.h3().await?;
    let response = fetch(&mut h3, &target, request).await?.map_err(|r| anyhow::anyhow!("{r:?}"))?;
    ensure!(body(&response) == "allowed", "routeOnly: {:?}", String::from_utf8_lossy(&response));
    ensure!(forbidden.accepted.load(Ordering::SeqCst) == 1, "routeOnly kept the checked address");
    Ok(())
}

/// Established TCP connections to the VLESS server, from /proc/net/tcp.
fn connections_to(port: u16) -> usize {
    let table = std::fs::read_to_string("/proc/net/tcp").unwrap_or_default();
    table
        .lines()
        .skip(1)
        .filter(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            fields.len() > 3
                && fields[3] == "01"
                && fields[2].rsplit(':').next().and_then(|p| u16::from_str_radix(p, 16).ok()) == Some(port)
        })
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs an Xray-core binary in XRAY_BIN; run scripts/test-xray.sh"]
async fn ended_and_reset_tunnels_close_their_vless_connections() -> Result<()> {
    let xray = Xray::start(false).await?;
    let dns = dns(ALLOWED).await;
    let echo = tcp_echo(ALLOWED).await;
    let udp = udp_echo(ALLOWED).await;
    let relay = relay(xray.port, UUID, dns.port).await?;
    let mut h3 = relay.h3().await?;
    let before = connections_to(xray.port);
    let mut open = Vec::new();
    for i in 0..24 {
        let mut stream = h3.request(connect_request(&format!("{ALLOWED}:{}", echo.port))).await?;
        let response = tokio::time::timeout(WAIT, stream.recv_response()).await??;
        ensure!(response.status() == StatusCode::OK);
        stream.send_data(Bytes::from_static(b"ping")).await?;
        let data = tokio::time::timeout(WAIT, stream.recv_data()).await??.context("no echo")?;
        ensure!(data.chunk() == b"ping");
        if i % 2 == 0 {
            // A client that gives up: the relay aborts the tunnel.
            stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
            stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
        } else {
            stream.finish().await?;
        }
        open.push(stream);
    }
    for _ in 0..8 {
        let uri = format!("https://relay.test:{}/.well-known/masque/udp/{ALLOWED}/{}/", relay.addr.port(), udp.port);
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .header("capsule-protocol", "?1")
            .header(AUTHORIZATION, auth::basic_authorization(USER, PASSWORD))
            .extension(h3::ext::Protocol::CONNECT_UDP)
            .body(())?;
        let mut stream = h3.request(request).await?;
        let response = tokio::time::timeout(WAIT, stream.recv_response()).await??;
        ensure!(response.status() == StatusCode::OK);
        let (mut tunnel, filter) = h3.udp_tunnel(stream);
        tunnel.send_datagram(Bytes::from_static(b"\0ping"))?;
        ensure!(matches!(tokio::time::timeout(WAIT, tunnel.next_event()).await??, Event::Datagram(_)));
        drop((tunnel, filter));
    }
    ensure!(connections_to(xray.port) > before, "tunnels opened VLESS connections");
    drop(open);
    drop(h3);
    let deadline = tokio::time::Instant::now() + WAIT;
    while connections_to(xray.port) > before {
        ensure!(
            tokio::time::Instant::now() < deadline,
            "{} VLESS connections still open",
            connections_to(xray.port) - before
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

/// The program as an operator runs it: `serve` with one configuration file
/// holding the relay settings and `[vless]`, tested with its own `check`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs an Xray-core binary in XRAY_BIN; run scripts/test-xray.sh"]
async fn the_program_serves_from_one_file_and_passes_its_own_check() -> Result<()> {
    let program = env!("CARGO_BIN_EXE_network-relay-vless");
    let xray = Xray::start(false).await?;
    let dns = dns(ALLOWED).await;
    let site = web(ALLOWED, free_port(ALLOWED), "fixture site").await;
    let dir = Dir::new("program")?;
    write_certificates(&dir.0)?;
    let account = std::process::Command::new(program)
        .args(["passwd", "--name", USER, "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(format!("{PASSWORD}\n").as_bytes())?;
            child.wait_with_output()
        })?;
    ensure!(account.status.success(), "passwd failed");
    let account = String::from_utf8(account.stdout)?;
    let user_lines: String =
        account.lines().skip_while(|l| !l.starts_with("[[user]]")).map(|l| format!("{l}\n")).collect();
    ensure!(user_lines.contains("password_hash"), "passwd printed no account: {account}");
    let port = free_port(LOCALHOST);
    let config = dir.0.join("relay.toml");
    std::fs::write(
        &config,
        format!(
            "listen = \"127.0.0.1:{port}\"\n[tls]\ncert = {:?}\nkey = {:?}\n[relay]\n\
             blocked_destinations = [\"127.0.0.1/32\", \"127.0.0.3/32\"]\nblock_own_addresses = false\n\
             {user_lines}\n[vless]\nserver = \"127.0.0.1:{}\"\nuuid = \"{UUID}\"\ntransport = \"ws\"\n\
             security = \"none\"\npath = \"{WS_PATH}\"\ndns_servers = [\"{ALLOWED}:{}\"]\n",
            dir.0.join("fullchain.pem"),
            dir.0.join("privkey.pem"),
            xray.port,
            dns.port,
        ),
    )?;
    let checked =
        std::process::Command::new(program).arg("serve").arg("--check").arg("--config").arg(&config).output()?;
    ensure!(checked.status.success(), "serve --check: {}", String::from_utf8_lossy(&checked.stderr));
    let mut server = tokio::process::Command::new(program)
        .arg("serve")
        .arg("--config")
        .arg(&config)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let deadline = tokio::time::Instant::now() + WAIT;
    while tokio::net::TcpStream::connect((LOCALHOST, port)).await.is_err() {
        ensure!(tokio::time::Instant::now() < deadline, "the relay did not start listening");
        ensure!(server.try_wait()?.is_none(), "the relay exited");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let check = tokio::process::Command::new(program)
        .args(["check", "--server", "relay.test", "--address", "127.0.0.1", "--port", &port.to_string()])
        .args(["--user", USER, "--password", PASSWORD])
        .args(["--tcp-target", &format!("fixture.test:{}", site.port)])
        .args(["--udp-target", &format!("fixture.test:{}", dns.port), "--dns-name", "fixture.test"])
        .arg("--ca")
        .arg(dir.0.join("ca.pem"))
        .output()
        .await?;
    let report = String::from_utf8_lossy(&check.stdout).to_string() + &String::from_utf8_lossy(&check.stderr);
    println!("{report}");
    ensure!(check.status.success(), "check failed:\n{report}");
    server.start_kill()?;
    let output = server.wait_with_output().await?;
    let log = String::from_utf8_lossy(&output.stdout).to_string() + &String::from_utf8_lossy(&output.stderr);
    ensure!(log.contains("plaintext WebSocket"), "the plaintext warning is missing:\n{log}");
    ensure!(log.contains("VLESS egress ready"), "the start-up check did not pass:\n{log}");
    ensure!(!log.contains(UUID) && !log.contains(WS_PATH), "the log shows the user ID or path:\n{log}");
    Ok(())
}
