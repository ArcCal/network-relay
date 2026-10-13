//! SOCKS GSS-API authentication (RFC 1961) through the production SOCKS
//! code, over the transport emulator (not Network.framework): a stand-in
//! mechanism without a relay server, and, ignored, real Kerberos against
//! both real relay servers (scripts/test-socks-gssapi.sh).
mod support;
use network_relay_nf_core::{Config, client::Client, gssapi, socks};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinHandle;

const WAIT: Duration = Duration::from_secs(10);

struct ProxyRun {
    address: SocketAddr,
    task: JoinHandle<anyhow::Result<()>>,
    _backend: support::Backend,
}
impl Drop for ProxyRun {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn proxy(
    settings: &Config,
    ca: std::path::PathBuf,
    gssapi: Option<Arc<dyn gssapi::Acceptor>>,
) -> ProxyRun {
    let backend = support::Backend::start(ca);
    let client = Arc::new(Client::new(settings, backend.bridge.clone()).unwrap());
    let listener = backend
        .bridge
        .listen("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(socks::run(client, vec![listener], gssapi));
    ProxyRun {
        address,
        task,
        _backend: backend,
    }
}
fn settings(server: &str) -> Config {
    Config {
        uri_template: format!(
            "https://{server}/.well-known/masque/udp/{{target_host}}/{{target_port}}/"
        ),
        username: "alice".into(),
        password: "disposable-fixture-password".into(),
        server_name: Some("relay.test".into()),
        transport: "h2".into(),
        probe_target: "127.0.0.1:9".parse().unwrap(),
        mode: "socks".into(),
        socks: network_relay_nf_core::Socks {
            listen: vec!["127.0.0.1:0".parse().unwrap()],
            gssapi_keytab: None,
            gssapi_principals: Vec::new(),
        },
    }
}
/// A trust anchor for a relay that is not there.
fn unused_ca() -> std::path::PathBuf {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["relay.test".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let ca = std::env::temp_dir().join(format!("relay-nf-gssapi-{}.pem", std::process::id()));
    std::fs::write(&ca, cert.pem()).unwrap();
    ca
}

/// A stand-in mechanism: the token "hello" completes the context and
/// "again" asks for another round; a wrapped token is a byte saying whether
/// the data is "encrypted" (inverted), then the data.
struct Toy {
    live: Arc<AtomicUsize>,
}
struct ToyContext {
    live: Arc<AtomicUsize>,
}
impl gssapi::Acceptor for Toy {
    fn context(&self) -> Result<Box<dyn gssapi::Context>, String> {
        self.live.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(ToyContext {
            live: self.live.clone(),
        }))
    }
    fn allows(&self, peer: &str) -> bool {
        peer == "alice@TEST"
    }
}
impl Drop for ToyContext {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}
impl gssapi::Context for ToyContext {
    fn accept(&mut self, token: &[u8]) -> Result<(Vec<u8>, bool), String> {
        match token {
            b"again" => Ok((b"more".to_vec(), false)),
            b"hello" => Ok((b"welcome".to_vec(), true)),
            _ => Err("bad token".into()),
        }
    }
    fn peer(&self) -> String {
        "alice@TEST".into()
    }
    fn flags(&self) -> u32 {
        gssapi::INTEG_FLAG | gssapi::CONF_FLAG
    }
    fn wrap(&mut self, confidential: bool, data: &[u8]) -> Result<Vec<u8>, String> {
        Ok(seal(confidential, data))
    }
    fn unwrap(&mut self, token: &[u8]) -> Result<(Vec<u8>, bool, u32), String> {
        let (data, confidential) = open(token)?;
        Ok((data, confidential, 0))
    }
    fn max_input(&mut self, _: bool, max_token: usize) -> Result<usize, String> {
        Ok(max_token - 1)
    }
}
fn seal(confidential: bool, data: &[u8]) -> Vec<u8> {
    let mut token = vec![u8::from(confidential)];
    token.extend(data.iter().map(|b| if confidential { !b } else { *b }));
    token
}
fn open(token: &[u8]) -> Result<(Vec<u8>, bool), String> {
    let [flag, data @ ..] = token else {
        return Err("short token".into());
    };
    let confidential = *flag == 1;
    Ok((
        data.iter()
            .map(|b| if confidential { !b } else { *b })
            .collect(),
        confidential,
    ))
}

fn message(mtyp: u8, token: &[u8]) -> Vec<u8> {
    let mut m = vec![1, mtyp];
    m.extend_from_slice(&(token.len() as u16).to_be_bytes());
    m.extend_from_slice(token);
    m
}
/// A message's type and token; an abort message has none.
async fn read_message(stream: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut head = [0; 2];
    tokio::time::timeout(WAIT, stream.read_exact(&mut head))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head[0], 1);
    if head[1] == 0xff {
        return (0xff, Vec::new());
    }
    let mut token = vec![0; stream.read_u16().await.unwrap().into()];
    stream.read_exact(&mut token).await.unwrap();
    (head[1], token)
}
async fn method(address: SocketAddr, offered: &[u8]) -> (TcpStream, u8) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let mut greeting = vec![5, offered.len() as u8];
    greeting.extend_from_slice(offered);
    stream.write_all(&greeting).await.unwrap();
    let mut chosen = [0; 2];
    tokio::time::timeout(WAIT, stream.read_exact(&mut chosen))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(chosen[0], 5);
    (stream, chosen[1])
}
/// The stand-in context established, and confidentiality agreed.
async fn authenticated(address: SocketAddr) -> TcpStream {
    let (mut stream, chosen) = method(address, &[0, 1]).await;
    assert_eq!(chosen, 1);
    stream.write_all(&message(1, b"hello")).await.unwrap();
    assert_eq!(read_message(&mut stream).await, (1, b"welcome".to_vec()));
    stream
        .write_all(&message(2, &seal(false, &[2])))
        .await
        .unwrap();
    let (mtyp, token) = read_message(&mut stream).await;
    assert_eq!(
        (mtyp, open(&token).unwrap()),
        (2, (vec![2], false)),
        "agreed without confidentiality"
    );
    stream
}
async fn send(stream: &mut TcpStream, data: &[u8]) {
    stream
        .write_all(&message(3, &seal(true, data)))
        .await
        .unwrap();
}
async fn recv(stream: &mut TcpStream) -> Vec<u8> {
    let (mtyp, token) = read_message(stream).await;
    assert_eq!(mtyp, 3);
    let (data, confidential) = open(&token).unwrap();
    assert!(confidential);
    data
}
fn relay_address(reply: &[u8]) -> SocketAddr {
    assert_eq!((reply.len(), &reply[..4]), (10, &[5, 0, 0, 1][..]));
    SocketAddr::new(
        IpAddr::from([reply[4], reply[5], reply[6], reply[7]]),
        u16::from_be_bytes([reply[8], reply[9]]),
    )
}
async fn closed(stream: &mut TcpStream) -> bool {
    matches!(
        tokio::time::timeout(WAIT, stream.read(&mut [0])).await,
        Ok(Ok(0) | Err(_))
    )
}
async fn contexts_drop_to(live: &AtomicUsize, n: usize) {
    tokio::time::timeout(WAIT, async {
        while live.load(Ordering::SeqCst) != n {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{} contexts alive, not {n}", live.load(Ordering::SeqCst)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gssapi_negotiation_encapsulation_and_cleanup() {
    let ca = unused_ca();
    let config = settings("127.0.0.1:9");
    // Without a keytab: no authentication, as before; GSS-API is not offered.
    let plain = proxy(&config, ca.clone(), None).await;
    assert_eq!(method(plain.address, &[1]).await.1, 0xff);
    assert_eq!(method(plain.address, &[1, 0]).await.1, 0);
    drop(plain);

    let live = Arc::new(AtomicUsize::new(0));
    let run = proxy(&config, ca, Some(Arc::new(Toy { live: live.clone() }))).await;
    assert_eq!(
        method(run.address, &[0, 2]).await.1,
        0xff,
        "GSS-API is required once configured"
    );
    // The request and the reply are encapsulated: CONNECT is refused (the
    // relay is not there), UDP ASSOCIATE answered.
    let mut stream = authenticated(run.address).await;
    send(&mut stream, &[5, 1, 0, 1, 192, 0, 2, 80, 0, 7]).await;
    assert_eq!(&recv(&mut stream).await[..2], &[5, 1]);
    drop(stream);
    let mut stream = authenticated(run.address).await;
    send(&mut stream, &[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await;
    relay_address(&recv(&mut stream).await);
    drop(stream);

    // Malformed: a plain request after authentication; a token the
    // mechanism rejects (an abort message).
    let mut stream = authenticated(run.address).await;
    stream
        .write_all(&[5, 1, 0, 1, 192, 0, 2, 80, 0, 7])
        .await
        .unwrap();
    assert!(closed(&mut stream).await);
    let (mut stream, _) = method(run.address, &[1]).await;
    stream.write_all(&message(1, b"forged")).await.unwrap();
    assert_eq!(read_message(&mut stream).await.0, 0xff);
    assert!(closed(&mut stream).await);
    drop(stream);

    // Cancellation: a client that leaves between rounds releases its
    // context, and the proxy still serves.
    contexts_drop_to(&live, 0).await;
    let (mut stream, _) = method(run.address, &[1]).await;
    stream.write_all(&message(1, b"again")).await.unwrap();
    assert_eq!(read_message(&mut stream).await, (1, b"more".to_vec()));
    assert_eq!(live.load(Ordering::SeqCst), 1);
    drop(stream);
    contexts_drop_to(&live, 0).await;
    let mut stream = authenticated(run.address).await;
    send(&mut stream, &[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await;
    relay_address(&recv(&mut stream).await);
}

/// The client side with the system library and the default credentials.
struct Kerberos {
    stream: TcpStream,
    initiator: gssapi::Initiator,
    confidential: bool,
}
impl Kerberos {
    /// Method, context establishment with rcmd@localhost, and `level`; or the
    /// message type when the proxy refuses.
    async fn open(address: SocketAddr, level: u8) -> Result<Self, u8> {
        let (mut stream, chosen) = method(address, &[1]).await;
        assert_eq!(chosen, 1);
        let mut initiator = gssapi::Initiator::new("rcmd@localhost").unwrap();
        let (mut token, mut complete) = initiator.step(None).unwrap();
        loop {
            stream.write_all(&message(1, &token)).await.unwrap();
            let (mtyp, reply) = read_message(&mut stream).await;
            if mtyp != 1 {
                return Err(mtyp);
            }
            if complete {
                break;
            }
            (token, complete) = initiator.step(Some(&reply)).unwrap();
            if complete && token.is_empty() {
                break;
            }
        }
        stream
            .write_all(&message(2, &initiator.wrap(false, &[level]).unwrap()))
            .await
            .unwrap();
        let (mtyp, reply) = read_message(&mut stream).await;
        if mtyp != 2 {
            return Err(mtyp);
        }
        let (agreed, confidential, _) = initiator.unwrap(&reply).unwrap();
        assert!(!confidential);
        Ok(Self {
            stream,
            initiator,
            confidential: agreed == [2],
        })
    }
    async fn send(&mut self, data: &[u8]) {
        let token = self.initiator.wrap(self.confidential, data).unwrap();
        self.stream.write_all(&message(3, &token)).await.unwrap();
    }
    async fn recv(&mut self) -> Vec<u8> {
        let (mtyp, token) = read_message(&mut self.stream).await;
        assert_eq!(mtyp, 3);
        let (data, confidential, _) = self.initiator.unwrap(&token).unwrap();
        assert_eq!(confidential, self.confidential);
        data
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a relay server and a Kerberos realm: run scripts/test-socks-gssapi.sh"]
async fn socks_gssapi_with_kerberos() {
    let var = |name: &str| {
        std::env::var(name)
            .unwrap_or_else(|_| panic!("{name} is unset: run scripts/test-socks-gssapi.sh"))
    };
    let fixture: serde_json::Value =
        serde_json::from_slice(&std::fs::read(var("RELAY_NF_FIXTURE")).unwrap()).unwrap();
    let ccaches = std::path::PathBuf::from(var("RELAY_NF_GSSAPI_CCACHE_DIR"));
    // SAFETY: set before any thread of this test reads the environment.
    unsafe {
        std::env::set_var(
            "KRB5CCNAME",
            format!("FILE:{}", ccaches.join("alice.ccache").display()),
        )
    };
    let mut config = settings(fixture["server"].as_str().unwrap());
    config.password = fixture["password"].as_str().unwrap().into();
    // As the app configures it.
    config.socks = toml::from_str(&format!(
        "listen = [\"127.0.0.1:1080\"]\ngssapi_keytab = \"{}\"\ngssapi_principals = [\"alice@{}\"]\n",
        var("RELAY_NF_GSSAPI_KEYTAB"),
        var("RELAY_NF_GSSAPI_REALM")
    ))
    .unwrap();
    let tcp: SocketAddr = fixture["tcp"].as_str().unwrap().parse().unwrap();
    let udp: SocketAddr = fixture["udp"].as_str().unwrap().parse().unwrap();
    let run = proxy(
        &config,
        fixture["ca"].as_str().unwrap().into(),
        config.socks.gssapi().unwrap(),
    )
    .await;
    let mut request = vec![5, 1, 0, 3, 9];
    request.extend_from_slice(b"localhost");
    request.extend_from_slice(&tcp.port().to_be_bytes());
    for level in [1, 2] {
        let mut session = Kerberos::open(run.address, level).await.unwrap();
        assert_eq!(session.confidential, level == 2);
        session.send(&request).await;
        assert_eq!(&session.recv().await[..2], &[5, 0]);
        let data = (0..100_013).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        session.send(&data[..60_000]).await;
        session.send(&data[60_000..]).await;
        let mut echoed = Vec::new();
        while echoed.len() < data.len() {
            echoed.extend(session.recv().await);
        }
        assert_eq!(echoed, data, "level {level}");
    }
    let mut session = Kerberos::open(run.address, 2).await.unwrap();
    session.send(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await;
    let relay = relay_address(&session.recv().await);
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut packet = vec![0, 0, 0, 3, 9];
    packet.extend_from_slice(b"localhost");
    packet.extend_from_slice(&udp.port().to_be_bytes());
    packet.extend_from_slice(b"kerberos datagram");
    let token = session.initiator.wrap(true, &packet).unwrap();
    socket.send_to(&message(3, &token), relay).await.unwrap();
    let mut buf = vec![0; 4096];
    let (n, _) = tokio::time::timeout(WAIT, socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..2], &[1, 3]);
    let (reply, confidential, _) = session.initiator.unwrap(&buf[4..n]).unwrap();
    assert!(confidential && reply.ends_with(b"kerberos datagram"));
    // A plain datagram on the encapsulated association is dropped.
    socket.send_to(&packet, relay).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut buf))
            .await
            .is_err()
    );
    drop(session);
    // Bob authenticates, but is not admitted: an abort message.
    unsafe {
        std::env::set_var(
            "KRB5CCNAME",
            format!("FILE:{}", ccaches.join("bob.ccache").display()),
        )
    };
    assert_eq!(Kerberos::open(run.address, 2).await.err(), Some(0xff));
}
