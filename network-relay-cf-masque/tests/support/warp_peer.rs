//! Local Cloudflare-shaped WARP peer. Only the outer tunnel uses host sockets;
//! TCP, UDP, HTTP and DNS fixtures all run on the peer's userspace IP stack.
#![allow(dead_code)]

use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use base64::prelude::*;
use bytes::{Buf, Bytes, BytesMut};
use http::Method;
use rcgen::PublicKeyData;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};
use warp_masque_egress::test_support::{NetStack, TcpStream, UdpSocket};
use warp_masque_egress::{Transport, WarpConfig};

pub const CLIENT_IPV4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
pub const PEER_IPV4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
pub const CLIENT_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
pub const PEER_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
pub const HTTP_FILE_BYTES: usize = 64 << 20;
const QUEUE: usize = 1024;

/// Fill a slice of `/large.bin` at an absolute file offset. Byte `n` is
/// `((n * 73 + 19) ^ (n >> 8)) & 0xff`, repeating every 65,536 bytes.
pub fn http_file_pattern(buf: &mut [u8], offset: usize) {
    for (index, byte) in buf.iter_mut().enumerate() {
        let position = offset.wrapping_add(index);
        *byte = (position.wrapping_mul(73).wrapping_add(19) ^ (position >> 8)) as u8;
    }
}

pub fn peer_addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(PEER_IPV4), port)
}

macro_rules! counters {
    ($($field:ident),+ $(,)?) => {
        #[derive(Default)]
        struct Counters { $( $field: AtomicU64, )+ }
        #[derive(Clone, Debug, Default, Serialize)]
        pub struct PeerSnapshot { $( pub $field: u64, )+ }
        impl Counters {
            fn snapshot(&self) -> PeerSnapshot {
                PeerSnapshot { $( $field: self.$field.load(Ordering::SeqCst), )+ }
            }
        }
    };
}
counters!(
    authenticated_clients,
    tunnels,
    ip_packets_from_client,
    ip_packets_to_client,
    ip_bytes_from_client,
    ip_bytes_to_client,
    tcp_connections,
    tcp_bytes_received,
    tcp_bytes_sent,
    udp_datagrams_received,
    udp_datagrams_sent,
    udp_bytes_received,
    udp_bytes_sent,
    dns_queries,
    dns_tcp_queries,
    http_requests,
    http_file_requests,
    http_file_bytes_sent,
    h2_capsules,
    h3_datagrams,
    h3_route_advertisements
);

#[derive(Clone, Debug, Serialize)]
pub struct DnsQuery {
    pub name: String,
    pub qtype: u16,
    pub source: SocketAddr,
    pub tcp: bool,
    pub wire: Vec<u8>,
}

#[derive(Default)]
struct Observations {
    counters: Counters,
    errors: Mutex<Vec<String>>,
    dns: Mutex<Vec<DnsQuery>>,
    udp_sources: Mutex<Vec<SocketAddr>>,
    dns_paused: AtomicBool,
    dns_truncated: AtomicBool,
}

/// Each instance accepts one authenticated tunnel. Termination closes that
/// generation and its listening endpoint, making failure tests deterministic.
pub struct WarpPeer {
    pub endpoint: SocketAddr,
    pub transport: Transport,
    pub server_spki: Vec<u8>,
    pub device_pkcs8: Vec<u8>,
    pub device_spki: Vec<u8>,
    stack: NetStack,
    observations: Arc<Observations>,
    stop_transport: watch::Sender<bool>,
    transport_task: Option<JoinHandle<()>>,
    services_task: Option<JoinHandle<()>>,
    stack_task: Option<JoinHandle<()>>,
    spoof_udp: Arc<UdpSocket>,
}

impl WarpPeer {
    pub async fn start(transport: Transport) -> Result<Self> {
        let device = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let server = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let certificate = rcgen::CertificateParams::new(vec!["localhost".into()])?.self_signed(&server)?;
        let device_spki = device.subject_public_key_info();
        let observations = Arc::new(Observations::default());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(Arc::new(EnrolledClient {
                provider,
                spki: device_spki.clone(),
                observations: observations.clone(),
            }))
            .with_single_cert(
                vec![certificate.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server.serialize_der())),
            )?;
        tls.alpn_protocols = vec![match transport {
            Transport::H2 => b"h2".to_vec(),
            Transport::H3 => b"h3".to_vec(),
        }];

        let stack = NetStack::new(0);
        stack.set_addresses(&[PEER_IPV4.into(), PEER_IPV6.into()]);
        let tcp_echo = stack.listen(7, 8)?;
        let tcp_reset = stack.listen(9, 4)?;
        let http = stack.listen(80, 8)?;
        let dns_tcp = stack.listen(53, 4)?;
        let udp_echo = Arc::new(stack.bind_udp(7)?);
        let udp_dns = stack.bind_udp(53)?;
        let spoof_udp = Arc::new(stack.bind_udp(8)?);
        let (incoming, stack_input) = mpsc::channel(QUEUE);
        let (stack_output, outgoing) = mpsc::channel(QUEUE);
        let (stop_transport, stopped) = watch::channel(false);

        // Bind before spawning services so setup failures leave no worker tasks.
        enum Listener {
            H2(tokio::net::TcpListener, tokio_rustls::TlsAcceptor),
            H3(quinn::Endpoint),
        }
        let (listener, endpoint) = match transport {
            Transport::H2 => {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                let addr = listener.local_addr()?;
                (Listener::H2(listener, tokio_rustls::TlsAcceptor::from(Arc::new(tls))), addr)
            }
            Transport::H3 => {
                let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
                let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
                let mut settings = quinn::TransportConfig::default();
                settings.initial_mtu(1400);
                settings.datagram_receive_buffer_size(Some(4 << 20));
                settings.datagram_send_buffer_size(4 << 20);
                settings.max_idle_timeout(Some(Duration::from_secs(30).try_into()?));
                config.transport_config(Arc::new(settings));
                let listener = quinn::Endpoint::server(config, "127.0.0.1:0".parse()?)?;
                let addr = listener.local_addr()?;
                (Listener::H3(listener), addr)
            }
        };

        let runner = stack.clone();
        let stack_task = tokio::spawn(async move { runner.run(stack_input, stack_output).await });
        let observation = observations.clone();
        let service_stack = stack.clone();
        let services_task = tokio::spawn(async move {
            let mut workers = JoinSet::new();
            let obs = observation.clone();
            workers.spawn(async move { serve_tcp(tcp_echo, Service::Echo, obs).await });
            let obs = observation.clone();
            workers.spawn(async move { serve_tcp(tcp_reset, Service::Reset, obs).await });
            let obs = observation.clone();
            workers.spawn(async move { serve_tcp(http, Service::Http, obs).await });
            let obs = observation.clone();
            workers.spawn(async move { serve_tcp(dns_tcp, Service::Dns, obs).await });
            let obs = observation.clone();
            workers.spawn(async move { serve_udp_echo(udp_echo, obs).await });
            let obs = observation.clone();
            workers.spawn(async move { serve_udp_dns(udp_dns, obs).await });
            // Stack failure wakes every listener/socket. Drain their owners so
            // shutdown joins accepted child sessions as well as listeners.
            while let Some(result) = workers.join_next().await {
                let error = match result {
                    Ok(Err(e)) => Some(e),
                    Err(e) => Some(anyhow!("fixture service task: {e}")),
                    Ok(Ok(())) => None,
                };
                if let Some(error) = error {
                    if service_stack.failure_reason().is_none() {
                        record_error(&observation, error);
                        service_stack.fail("local fixture service failed");
                    }
                }
            }
        });
        let observation = observations.clone();
        let transport_task = tokio::spawn(async move {
            let mut stopped = stopped;
            let session = async {
                match listener {
                    Listener::H2(listener, acceptor) => {
                        let (socket, _) = listener.accept().await?;
                        let socket = acceptor.accept(socket).await?;
                        serve_h2(socket, incoming, outgoing, observation.clone()).await
                    }
                    Listener::H3(endpoint) => {
                        let incoming_conn = endpoint.accept().await.context("QUIC listener ended")?;
                        let conn = incoming_conn.await?;
                        let result = serve_h3(conn.clone(), incoming, outgoing, observation.clone()).await;
                        conn.close(0u32.into(), b"fixture session ended");
                        endpoint.close(0u32.into(), b"fixture session ended");
                        result
                    }
                }
            };
            tokio::select! {
                result = session => {
                    if let Err(e) = result { record_error(&observation, e); }
                }
                _ = stopped.changed() => {}
            }
        });
        Ok(Self {
            endpoint,
            transport,
            server_spki: server.subject_public_key_info(),
            device_pkcs8: device.serialize_der(),
            device_spki,
            stack,
            observations,
            stop_transport,
            transport_task: Some(transport_task),
            services_task: Some(services_task),
            stack_task: Some(stack_task),
            spoof_udp,
        })
    }

    /// Write synthetic registration material in the caller's project-owned
    /// fixture directory. Loading these files never enrolls a real device.
    pub fn config(&self, directory: &Path) -> Result<WarpConfig> {
        std::fs::create_dir_all(directory)?;
        let registration = serde_json::json!({
            "device_id": "local-warp-fixture", "access_token": "synthetic-fixture-token",
            "license": "", "private_key": BASE64_STANDARD.encode(&self.device_pkcs8),
            "endpoint_v4": self.endpoint.to_string(), "endpoint_v6": "[::1]:0",
            "endpoint_h2_v4": self.endpoint.to_string(),
            "endpoint_public_key": format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", BASE64_STANDARD.encode(&self.server_spki)),
            "tunnel_ipv4": CLIENT_IPV4.to_string(), "tunnel_ipv6": CLIENT_IPV6.to_string()
        });
        let registration_path = directory.join("registration.json");
        std::fs::write(&registration_path, serde_json::to_vec_pretty(&registration)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&registration_path, std::fs::Permissions::from_mode(0o600))?;
        }
        let transport = match self.transport {
            Transport::H2 => "h2",
            Transport::H3 => "h3",
        };
        let settings = format!(
            "[warp]\nregistration = \"registration.json\"\ntransport = \"{transport}\"\nendpoint = \"{}\"\nsni = \"localhost\"\nuri = \"https://cloudflareaccess.com/\"\ndns = [\"{}\"]\nkeepalive_secs = 1\nidle_timeout_secs = 30\n",
            self.endpoint,
            peer_addr(53)
        );
        let settings_path = directory.join("warp.toml");
        std::fs::write(&settings_path, settings)?;
        WarpConfig::load(&settings_path)
    }

    pub fn snapshot(&self) -> PeerSnapshot {
        self.observations.counters.snapshot()
    }

    pub fn stack_diagnostics(&self) -> serde_json::Value {
        serde_json::json!({"queue_drops": self.stack.queue_drops(), "sockets": self.stack.socket_count(), "socket_limit": self.stack.socket_limit(), "mtu": self.stack.mtu(), "tcp_buffer_bytes_per_socket": self.stack.tcp_buffer_bytes(), "failure": self.stack.failure_reason()})
    }
    pub fn errors(&self) -> Vec<String> {
        self.observations.errors.lock().unwrap().clone()
    }
    pub fn dns_queries(&self) -> Vec<DnsQuery> {
        self.observations.dns.lock().unwrap().clone()
    }
    pub fn udp_sources(&self) -> Vec<SocketAddr> {
        self.observations.udp_sources.lock().unwrap().clone()
    }
    pub fn dns_pause(&self, paused: bool) {
        self.observations.dns_paused.store(paused, Ordering::SeqCst);
    }
    pub fn dns_truncate_udp(&self, truncated: bool) {
        self.observations.dns_truncated.store(truncated, Ordering::SeqCst);
    }
    pub fn terminate_transport(&self) {
        self.stop_transport.send_replace(true);
    }

    pub async fn wait_connected(&self) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                ensure!(self.errors().is_empty(), "local WARP peer: {:?}", self.errors());
                if self.snapshot().tunnels != 0 {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .context("local WARP tunnel did not open")?
    }

    /// Inject a datagram from an unrelated inner source port to test source
    /// filtering. Port 8 is bound before the tunnel opens.
    pub async fn send_udp(&self, source_port: u16, payload: &[u8], destination: SocketAddr) -> Result<()> {
        ensure!(source_port == 8, "spoof fixture owns only source port 8");
        self.spoof_udp.send_to(payload, destination).await?;
        Ok(())
    }

    pub async fn shutdown(&mut self) {
        self.terminate_transport();
        if let Some(task) = self.transport_task.take() {
            let _ = task.await;
        }
        self.stack.fail("local WARP peer stopped");
        if let Some(task) = self.services_task.take() {
            let _ = task.await;
        }
        if let Some(task) = self.stack_task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for WarpPeer {
    fn drop(&mut self) {
        self.terminate_transport();
        self.stack.fail("local WARP peer dropped");
        for task in [&self.transport_task, &self.services_task, &self.stack_task].into_iter().flatten() {
            task.abort();
        }
    }
}

#[derive(Debug)]
struct EnrolledClient {
    provider: Arc<rustls::crypto::CryptoProvider>,
    spki: Vec<u8>,
    observations: Arc<Observations>,
}

impl std::fmt::Debug for Observations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PeerObservations")
    }
}

impl ClientCertVerifier for EnrolledClient {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        certificate: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        let (rest, parsed) = x509_parser::parse_x509_certificate(certificate.as_ref())
            .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        if !rest.is_empty()
            || !intermediates.is_empty()
            || parsed.tbs_certificate.subject_pki.raw != self.spki.as_slice()
        {
            return Err(rustls::CertificateError::ApplicationVerificationFailure.into());
        }
        // TLS CertificateVerify independently proves possession of the pinned
        // enrolled private key through the signature methods below.
        self.observations.counters.authenticated_clients.fetch_add(1, Ordering::SeqCst);
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

async fn serve_h2(
    socket: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    incoming: mpsc::Sender<Bytes>,
    mut outgoing: mpsc::Receiver<Bytes>,
    observations: Arc<Observations>,
) -> Result<()> {
    let mut connection = h2::server::handshake(socket).await?;
    let (request, mut response) = connection.accept().await.context("no H2 CONNECT request")??;
    ensure!(request.method() == Method::CONNECT, "H2 WARP requires CONNECT");
    ensure!(request.uri().authority().map(|a| a.as_str()) == Some("cloudflareaccess.com:443"), "H2 WARP authority");
    ensure!(request.extensions().get::<h2::ext::Protocol>().is_none(), "H2 WARP must use plain CONNECT");
    ensure!(
        request.headers().get("cf-connect-proto").and_then(|v| v.to_str().ok()) == Some("cf-connect-ip"),
        "H2 WARP cf-connect-proto"
    );
    ensure!(request.headers().get("pq-enabled").and_then(|v| v.to_str().ok()) == Some("false"), "H2 WARP pq-enabled");
    ensure!(
        !request.headers().contains_key("capsule-protocol") && !request.headers().contains_key("user-agent"),
        "H2 WARP unexpected headers"
    );
    let mut receive = request.into_body();
    let mut send = response.send_response(http::Response::new(()), false)?;
    observations.counters.tunnels.fetch_add(1, Ordering::SeqCst);
    let mut buffer = BytesMut::new();
    let mut workers = JoinSet::new();
    workers.spawn(async move {
        if let Some(request) = connection.accept().await {
            request?;
            bail!("fixture received a second H2 request");
        }
        Ok::<(), anyhow::Error>(())
    });
    loop {
        tokio::select! {
            data = receive.data() => {
                let Some(data) = data else {
                    ensure!(buffer.is_empty(), "H2 WARP ended within a capsule");
                    return Ok(());
                };
                let data = data?;
                receive.flow_control().release_capacity(data.len())?;
                buffer.extend_from_slice(&data);
                while let Some((kind, value)) = take_capsule(&mut buffer)? {
                    ensure!(kind == 0, "H2 WARP carries only bare-IP type-0 capsules");
                    observations.counters.h2_capsules.fetch_add(1, Ordering::SeqCst);
                    record_packet(&observations, &value, true)?;
                    incoming.send(value).await.context("peer IP input closed")?;
                }
            }
            packet = outgoing.recv() => {
                let Some(packet) = packet else { return Ok(()); };
                record_packet(&observations, &packet, false)?;
                send_h2_capsule(&mut send, capsule(0, &packet)).await?;
            }
            ended = workers.join_next() => {
                if let Some(result) = ended { result??; }
                return Ok(());
            }
        }
    }
}

async fn serve_h3(
    connection: quinn::Connection,
    incoming: mpsc::Sender<Bytes>,
    mut outgoing: mpsc::Receiver<Bytes>,
    observations: Arc<Observations>,
) -> Result<()> {
    // Cloudflare does not advertise SETTINGS_ENABLE_CONNECT_PROTOCOL.
    let mut h3 = h3::server::builder()
        .enable_extended_connect(false)
        .enable_datagram(true)
        .build::<_, Bytes>(h3_quinn::Connection::new(connection.clone()))
        .await?;
    let (request, mut stream) = h3.accept().await?.context("no H3 CONNECT request")?.resolve_request().await?;
    ensure!(
        request.method() == Method::CONNECT && request.uri() == "https://cloudflareaccess.com/",
        "H3 WARP request URI/method"
    );
    let protocol = request
        .extensions()
        .get::<h3::ext::Protocol>()
        .map(|p| p.as_str())
        .or_else(|| request.extensions().get::<h3::ext::OtherProtocol>().map(|p| p.as_str()));
    ensure!(protocol == Some("cf-connect-ip"), "H3 WARP requires cf-connect-ip, got {protocol:?}");
    ensure!(
        request.headers().get("capsule-protocol").and_then(|v| v.to_str().ok()) == Some("?1"),
        "H3 WARP capsule-protocol"
    );
    ensure!(!request.headers().contains_key("user-agent"), "H3 WARP must omit User-Agent");
    let quarter_stream = stream.id().into_inner() / 4;
    stream.send_response(http::Response::new(())).await?;
    observations.counters.tunnels.fetch_add(1, Ordering::SeqCst);
    let mut buffer = BytesMut::new();
    let mut workers = JoinSet::new();
    workers.spawn(async move {
        if let Some(request) = h3.accept().await? {
            let _ = request.resolve_request().await?;
            bail!("fixture received a second H3 request");
        }
        Ok::<(), anyhow::Error>(())
    });
    loop {
        tokio::select! {
            data = stream.recv_data() => {
                let Some(mut data) = data? else {
                    ensure!(buffer.is_empty(), "H3 WARP ended within a capsule");
                    return Ok(());
                };
                while data.has_remaining() {
                    buffer.extend_from_slice(data.chunk());
                    let len = data.chunk().len(); data.advance(len);
                }
                while let Some((kind, value)) = take_capsule(&mut buffer)? {
                    ensure!(kind == 3 && value.as_ref() == default_routes().as_slice(), "H3 WARP default route advertisement");
                    observations.counters.h3_route_advertisements.fetch_add(1, Ordering::SeqCst);
                }
            }
            datagram = connection.read_datagram() => {
                let datagram = datagram?;
                let (flow, used) = decode_varint(&datagram).context("H3 datagram quarter stream ID")?;
                ensure!(flow == quarter_stream, "H3 datagram quarter stream ID mismatch");
                let (context, context_len) = decode_varint(&datagram[used..]).context("H3 datagram context ID")?;
                ensure!(context == 0, "H3 WARP uses context ID zero");
                let packet = datagram.slice(used + context_len..);
                observations.counters.h3_datagrams.fetch_add(1, Ordering::SeqCst);
                record_packet(&observations, &packet, true)?;
                incoming.send(packet).await.context("peer IP input closed")?;
            }
            packet = outgoing.recv() => {
                let Some(packet) = packet else { return Ok(()); };
                record_packet(&observations, &packet, false)?;
                let mut datagram = Vec::with_capacity(packet.len() + 9);
                encode_varint(&mut datagram, quarter_stream); encode_varint(&mut datagram, 0);
                datagram.extend_from_slice(&packet);
                connection.send_datagram_wait(Bytes::from(datagram)).await?;
            }
            ended = workers.join_next() => {
                if let Some(result) = ended { result??; }
                return Ok(());
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Service {
    Echo,
    Http,
    Dns,
    Reset,
}

async fn serve_tcp(
    mut listener: warp_masque_egress::test_support::TcpListener,
    service: Service,
    observations: Arc<Observations>,
) -> Result<()> {
    let mut sessions = JoinSet::new();
    loop {
        tokio::select! {
            stream = listener.accept() => {
                let stream = match stream {
                    Ok(stream) => stream,
                    Err(error) => {
                        sessions.shutdown().await;
                        return Err(error.into());
                    }
                };
                observations.counters.tcp_connections.fetch_add(1, Ordering::SeqCst);
                let obs = observations.clone();
                sessions.spawn(async move {
                    match service {
                        Service::Echo => tcp_echo(stream, obs).await,
                        Service::Http => http_fixture(stream, obs).await,
                        Service::Dns => dns_tcp_fixture(stream, obs).await,
                        Service::Reset => tcp_reset_fixture(stream).await,
                    }
                });
            }
            result = sessions.join_next(), if !sessions.is_empty() => {
                if let Some(result) = result {
                    let result = result.map_err(anyhow::Error::from).and_then(|result| result);
                    if let Err(error) = result {
                        // A relay/client reset ends only this business flow.
                        // It must not destroy unrelated fixture DNS/listeners.
                        let reset = error.chain().filter_map(|cause| cause.downcast_ref::<std::io::Error>()).any(|error| {
                            matches!(error.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::BrokenPipe)
                        });
                        if reset { continue; }
                        sessions.shutdown().await;
                        return Err(error);
                    }
                }
            }
        }
    }
}

async fn tcp_echo(mut stream: TcpStream, observations: Arc<Observations>) -> Result<()> {
    let mut buffer = vec![0; 32 << 10];
    loop {
        let len = stream.read(&mut buffer).await?;
        if len == 0 {
            stream.shutdown().await?;
            return Ok(());
        }
        observations.counters.tcp_bytes_received.fetch_add(len as u64, Ordering::SeqCst);
        stream.write_all(&buffer[..len]).await?;
        observations.counters.tcp_bytes_sent.fetch_add(len as u64, Ordering::SeqCst);
    }
}

async fn tcp_reset_fixture(mut stream: TcpStream) -> Result<()> {
    let mut byte = [0];
    let _ = stream.read(&mut byte).await?;
    (stream.abort_handle())();
    Ok(())
}

async fn http_fixture(mut stream: TcpStream, observations: Arc<Observations>) -> Result<()> {
    let mut request = Vec::new();
    let mut chunk = [0; 1024];
    while !request.windows(4).any(|v| v == b"\r\n\r\n") {
        let len = stream.read(&mut chunk).await?;
        if len == 0 {
            return Ok(());
        }
        request.extend_from_slice(&chunk[..len]);
        ensure!(request.len() <= 16 << 10, "HTTP fixture request too large");
    }
    ensure!(request.starts_with(b"GET ") || request.starts_with(b"HEAD "), "HTTP fixture method");
    observations.counters.http_requests.fetch_add(1, Ordering::SeqCst);
    if request.starts_with(b"GET /large.bin ") {
        observations.counters.http_file_requests.fetch_add(1, Ordering::SeqCst);
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {HTTP_FILE_BYTES}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(header.as_bytes()).await?;
        let mut body = vec![0; 64 << 10];
        let mut offset = 0;
        while offset < HTTP_FILE_BYTES {
            let len = body.len().min(HTTP_FILE_BYTES - offset);
            http_file_pattern(&mut body[..len], offset);
            stream.write_all(&body[..len]).await?;
            observations.counters.http_file_bytes_sent.fetch_add(len as u64, Ordering::SeqCst);
            offset += len;
        }
    } else {
        stream.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await?;
    }
    stream.shutdown().await?;
    Ok(())
}

async fn serve_udp_echo(socket: Arc<UdpSocket>, observations: Arc<Observations>) -> Result<()> {
    loop {
        let (payload, source) = socket.recv_from().await?;
        observations.udp_sources.lock().unwrap().push(source);
        observations.counters.udp_datagrams_received.fetch_add(1, Ordering::SeqCst);
        observations.counters.udp_bytes_received.fetch_add(payload.len() as u64, Ordering::SeqCst);
        socket.send_to(&payload, source).await?;
        observations.counters.udp_datagrams_sent.fetch_add(1, Ordering::SeqCst);
        observations.counters.udp_bytes_sent.fetch_add(payload.len() as u64, Ordering::SeqCst);
    }
}

async fn serve_udp_dns(socket: UdpSocket, observations: Arc<Observations>) -> Result<()> {
    loop {
        let (payload, source) = socket.recv_from().await?;
        let response = dns_response(&payload, source, false, &observations)?;
        if !observations.dns_paused.load(Ordering::SeqCst) {
            socket.send_to(&response, source).await?;
        }
    }
}

async fn dns_tcp_fixture(mut stream: TcpStream, observations: Arc<Observations>) -> Result<()> {
    let source = stream.peer_addr().context("DNS TCP peer address")?;
    loop {
        let len = match stream.read_u16().await {
            Ok(len) => len,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                stream.shutdown().await?;
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };
        ensure!(len >= 12, "DNS TCP query length");
        let mut query = vec![0; usize::from(len)];
        stream.read_exact(&mut query).await?;
        let response = dns_response(&query, source, true, &observations)?;
        if !observations.dns_paused.load(Ordering::SeqCst) {
            stream.write_u16(response.len().try_into()?).await?;
            stream.write_all(&response).await?;
        }
    }
}

fn dns_response(query: &[u8], source: SocketAddr, tcp: bool, observations: &Observations) -> Result<Vec<u8>> {
    ensure!(query.len() >= 12 && u16::from_be_bytes([query[4], query[5]]) == 1, "DNS fixture requires one question");
    ensure!(query[2] & 0xf8 == 0, "DNS fixture requires a standard query");
    let mut offset = 12;
    let mut labels = Vec::new();
    loop {
        let len = usize::from(*query.get(offset).context("DNS query label length")?);
        offset += 1;
        if len == 0 {
            break;
        }
        ensure!(len <= 63 && offset + len <= query.len(), "invalid DNS query label");
        labels.push(std::str::from_utf8(&query[offset..offset + len])?.to_ascii_lowercase());
        offset += len;
    }
    ensure!(offset + 4 <= query.len(), "short DNS query question");
    let qtype = u16::from_be_bytes([query[offset], query[offset + 1]]);
    ensure!(query[offset + 2..offset + 4] == [0, 1], "DNS query class must be IN");
    offset += 4;
    let name = labels.join(".");
    observations.dns.lock().unwrap().push(DnsQuery { name: name.clone(), qtype, source, tcp, wire: query.to_vec() });
    observations.counters.dns_queries.fetch_add(1, Ordering::SeqCst);
    if tcp {
        observations.counters.dns_tcp_queries.fetch_add(1, Ordering::SeqCst);
    }
    let truncated = !tcp && observations.dns_truncated.load(Ordering::SeqCst);
    let found = matches!(name.as_str(), "fixture.test" | "tcp-fallback.test");
    let has_answer = found && qtype == 1 && !truncated;
    let flags =
        0x8080u16 | (u16::from(query[2] & 1) << 8) | if truncated { 0x0200 } else { 0 } | if found { 0 } else { 3 };
    let mut response = Vec::new();
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&u16::from(has_answer).to_be_bytes());
    response.extend_from_slice(&[0, 0, 0, 0]);
    response.extend_from_slice(&query[12..offset]);
    if has_answer {
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        response.extend_from_slice(&60u32.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&PEER_IPV4.octets());
    }
    Ok(response)
}

fn record_error(observations: &Observations, error: anyhow::Error) {
    observations.errors.lock().unwrap().push(format!("{error:#}"));
}

fn record_packet(observations: &Observations, packet: &[u8], from_client: bool) -> Result<()> {
    let version = packet.first().context("empty tunneled IP packet")? >> 4;
    match version {
        4 => {
            let header_length = usize::from(packet[0] & 15) * 4;
            ensure!(
                packet.len() >= 20 && header_length >= 20 && header_length <= packet.len(),
                "short tunneled IPv4 packet"
            );
            ensure!(
                usize::from(u16::from_be_bytes([packet[2], packet[3]])) == packet.len(),
                "IPv4 packet length mismatch"
            );
            let source = &packet[12..16];
            let destination = &packet[16..20];
            let (expected_src, expected_dst) = if from_client {
                (CLIENT_IPV4.octets(), PEER_IPV4.octets())
            } else {
                (PEER_IPV4.octets(), CLIENT_IPV4.octets())
            };
            ensure!(source == expected_src && destination == expected_dst, "tunneled IPv4 source/destination mismatch");
        }
        6 => {
            ensure!(
                packet.len() >= 40 && usize::from(u16::from_be_bytes([packet[4], packet[5]])) + 40 == packet.len(),
                "IPv6 packet length mismatch"
            );
            let (expected_src, expected_dst) = if from_client {
                (CLIENT_IPV6.octets(), PEER_IPV6.octets())
            } else {
                (PEER_IPV6.octets(), CLIENT_IPV6.octets())
            };
            ensure!(
                packet[8..24] == expected_src && packet[24..40] == expected_dst,
                "tunneled IPv6 source/destination mismatch"
            );
        }
        _ => bail!("tunneled value must start with bare IPv4/IPv6; got version {version}"),
    }
    let counters = &observations.counters;
    let (packets, bytes) = if from_client {
        (&counters.ip_packets_from_client, &counters.ip_bytes_from_client)
    } else {
        (&counters.ip_packets_to_client, &counters.ip_bytes_to_client)
    };
    packets.fetch_add(1, Ordering::SeqCst);
    bytes.fetch_add(packet.len() as u64, Ordering::SeqCst);
    Ok(())
}

fn decode_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    let len = 1usize << (first >> 6);
    let bytes = bytes.get(..len)?;
    let mut value = u64::from(first & 63);
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, len))
}

fn encode_varint(bytes: &mut Vec<u8>, value: u64) {
    let (len, tag) = match value {
        0..=63 => (1, 0),
        64..=16383 => (2, 0x40),
        16384..=1073741823 => (4, 0x80),
        _ => (8, 0xc0),
    };
    let encoded = value.to_be_bytes();
    let start = bytes.len();
    bytes.extend_from_slice(&encoded[8 - len..]);
    bytes[start] |= tag;
}

fn capsule(kind: u64, value: &[u8]) -> Bytes {
    let mut bytes = Vec::with_capacity(value.len() + 16);
    encode_varint(&mut bytes, kind);
    encode_varint(&mut bytes, value.len() as u64);
    bytes.extend_from_slice(value);
    Bytes::from(bytes)
}

fn take_capsule(buffer: &mut BytesMut) -> Result<Option<(u64, Bytes)>> {
    let Some((kind, type_len)) = decode_varint(buffer) else {
        return Ok(None);
    };
    let Some((length, length_len)) = decode_varint(&buffer[type_len..]) else {
        return Ok(None);
    };
    ensure!(length <= 65536, "fixture capsule too large");
    let header = type_len + length_len;
    let total = header + length as usize;
    if buffer.len() < total {
        return Ok(None);
    }
    let capsule = buffer.split_to(total).freeze();
    Ok(Some((kind, capsule.slice(header..))))
}

async fn send_h2_capsule(stream: &mut h2::SendStream<Bytes>, mut bytes: Bytes) -> Result<()> {
    while !bytes.is_empty() {
        stream.reserve_capacity(bytes.len());
        let capacity = poll_fn(|cx| stream.poll_capacity(cx)).await.context("H2 fixture stream closed")??;
        if capacity == 0 {
            continue;
        }
        let len = capacity.min(bytes.len());
        stream.send_data(bytes.split_to(len), false)?;
    }
    Ok(())
}

fn default_routes() -> Vec<u8> {
    let mut routes = vec![4];
    routes.extend_from_slice(&[0; 4]);
    routes.extend_from_slice(&[255; 4]);
    routes.push(0);
    routes.push(6);
    routes.extend_from_slice(&[0; 16]);
    routes.extend_from_slice(&[255; 16]);
    routes.push(0);
    routes
}
