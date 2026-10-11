//! Relay protocols over native byte streams. Production network operations
//! are requested through the bridge; rustls/Quinn are test-only backends.
use crate::{
    native, proto,
    stream::{Keep, Stream},
};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use http::{
    Method, Request, StatusCode,
    header::{AUTHORIZATION, CONNECTION, HOST, UPGRADE},
};
use http_body_util::Empty;
use hyper_util::rt::TokioIo;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::watch,
};

const WAIT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
#[error(
    "relay rejected request with HTTP {0}; check credentials, destination policy and server template"
)]
pub struct Rejected(pub StatusCode);

pub struct Client {
    pub bridge: Arc<native::Bridge>,
    template: proto::UriTemplate,
    authority: http::uri::Authority,
    certificate_name: String,
    authorization: http::HeaderValue,
    transport: String,
    selected: watch::Sender<Option<String>>,
    pub probe_target: SocketAddr,
}
pub struct Opened {
    pub stream: Stream,
    pub transport: &'static str,
}
impl Client {
    pub fn new(config: &crate::Config, bridge: Arc<native::Bridge>) -> Result<Self> {
        use base64::Engine;
        let template = proto::UriTemplate::parse(&config.uri_template)?;
        ensure!(
            template.has_variable("target_host") && template.has_variable("target_port"),
            "CONNECT-UDP template needs target_host and target_port"
        );
        template.check_round_trip()?;
        let rest = config
            .uri_template
            .strip_prefix("https://")
            .context("relay must use HTTPS")?;
        let authority: http::uri::Authority = rest
            .split('/')
            .next()
            .context("missing relay authority")?
            .parse()?;
        ensure!(
            !config.username.is_empty() && !config.password.is_empty(),
            "relay account is incomplete"
        );
        ensure!(
            config.username.len() <= 64
                && !config.username.starts_with('.')
                && config
                    .username
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_ .".contains(&c) && c != b' '),
            "invalid relay username"
        );
        ensure!(
            config.password.len() <= 1024 && !config.password.chars().any(char::is_control),
            "invalid relay password"
        );
        let mut authorization = http::HeaderValue::from_str(&format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", config.username, config.password))
        ))?;
        authorization.set_sensitive(true);
        let certificate_name = config
            .server_name
            .clone()
            .unwrap_or_else(|| authority.host().trim_matches(['[', ']']).into());
        let (selected, _) = watch::channel(None);
        Ok(Self {
            bridge,
            template,
            authority,
            certificate_name,
            authorization,
            transport: config.transport.clone(),
            selected,
            probe_target: config.probe_target,
        })
    }
    fn options(&self, alpn: &[&str]) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"host":self.authority.host().trim_matches(['[', ']']),"port":self.authority.port_u16().unwrap_or(443),"server_name":self.certificate_name,"alpn":alpn})).unwrap()
    }
    fn request(&self, host: &str, port: u16, udp: bool) -> Result<Request<()>> {
        let uri = if udp {
            let path = self
                .template
                .expand(&[("target_host", host), ("target_port", &port.to_string())]);
            format!("https://{}{path}", self.authority)
        } else if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let mut builder = Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .header(AUTHORIZATION, &self.authorization);
        if udp {
            builder = builder.header(proto::CAPSULE_PROTOCOL_HEADER, "?1");
        }
        Ok(builder.body(())?)
    }
    pub async fn open(&self, host: &str, port: u16, udp: bool) -> Result<Opened> {
        ensure!(
            port != 0
                && !host.is_empty()
                && host.len() <= 253
                && host
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-._:".contains(&c)),
            "invalid target host or port"
        );
        let selected = self.selected.borrow().clone();
        let mode = selected.as_deref().unwrap_or(&self.transport);
        if mode == "h3" {
            return tokio::time::timeout(WAIT * 3, self.open_h3(host, port, udp))
                .await
                .context("HTTP/3 connect timed out")?;
        }
        if mode == "auto" {
            match tokio::time::timeout(Duration::from_secs(5), self.open_h3(host, port, udp)).await
            {
                Ok(Ok(open)) => return Ok(open),
                Ok(Err(e)) if terminal(&e) => return Err(e),
                _ => tracing::warn!("HTTP/3 unavailable; trying native TCP"),
            }
        }
        tokio::time::timeout(WAIT * 3, self.open_tcp(host, port, udp, mode))
            .await
            .context("TCP connect timed out")?
    }
    async fn open_tcp(&self, host: &str, port: u16, udp: bool, mode: &str) -> Result<Opened> {
        let alpn = match mode {
            "h2" => vec!["h2"],
            "http/1.1" => vec!["http/1.1"],
            _ => vec!["h2", "http/1.1"],
        };
        let io = tokio::time::timeout(WAIT, self.bridge.tcp(self.options(&alpn))).await??;
        let chosen = io.ready.alpn.clone();
        match chosen.as_str() {
            "h2" if mode != "http/1.1" => self.open_h2(io, host, port, udp).await,
            "http/1.1" if mode != "h2" => self.open_h1(io, host, port, udp).await,
            _ => anyhow::bail!("server did not negotiate the requested ALPN"),
        }
    }
    async fn open_h2(&self, io: native::Io, host: &str, port: u16, udp: bool) -> Result<Opened> {
        let mut builder = h2::client::Builder::new();
        builder
            .initial_window_size(2 << 20)
            .initial_connection_window_size(5 << 20)
            .max_header_list_size(16384);
        let (mut sender, connection) =
            tokio::time::timeout(WAIT, builder.handshake::<_, Bytes>(io)).await??;
        let mut keep = Keep::default();
        keep.tasks.push(tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::debug!("HTTP/2 connection ended: {e}");
            }
        }));
        if udp {
            tokio::time::timeout(WAIT, async {
                while !sender.is_extended_connect_protocol_enabled() {
                    ensure!(
                        !keep.tasks[0].is_finished(),
                        "HTTP/2 closed before Extended CONNECT settings"
                    );
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Ok::<_, anyhow::Error>(())
            })
            .await
            .context("server did not enable HTTP/2 Extended CONNECT")??;
        }
        sender = sender.ready().await?;
        let mut request = self.request(host, port, udp)?;
        if udp {
            request
                .extensions_mut()
                .insert(h2::ext::Protocol::from_static(proto::CONNECT_UDP_PROTOCOL));
        }
        let (response, send) = sender.send_request(request, false)?;
        let response = tokio::time::timeout(WAIT, response).await??;
        check(response.status(), response.headers(), udp, StatusCode::OK)?;
        keep.sender = Some(Box::new(sender));
        Ok(Opened {
            stream: Stream::h2(send, response.into_body(), keep),
            transport: "HTTP/2",
        })
    }
    async fn open_h1(&self, io: native::Io, host: &str, port: u16, udp: bool) -> Result<Opened> {
        let (mut sender, connection) = tokio::time::timeout(
            WAIT,
            hyper::client::conn::http1::handshake(TokioIo::new(io)),
        )
        .await??;
        let mut keep = Keep::default();
        keep.tasks.push(tokio::spawn(async move {
            if let Err(e) = connection.with_upgrades().await {
                tracing::debug!("HTTP/1.1 connection ended: {e}");
            }
        }));
        let request = if udp {
            Request::builder()
                .method(Method::GET)
                .uri(
                    self.template
                        .expand(&[("target_host", host), ("target_port", &port.to_string())]),
                )
                .header(HOST, self.authority.as_str())
                .header(AUTHORIZATION, &self.authorization)
                .header(CONNECTION, "Upgrade")
                .header(UPGRADE, proto::CONNECT_UDP_PROTOCOL)
                .header(proto::CAPSULE_PROTOCOL_HEADER, "?1")
                .body(Empty::<Bytes>::new())?
        } else {
            let request = self.request(host, port, false)?;
            let (parts, _) = request.into_parts();
            let mut request = Request::from_parts(parts, Empty::<Bytes>::new());
            let host_header = request.uri().authority().unwrap().as_str().parse()?;
            request.headers_mut().insert(HOST, host_header);
            request
        };
        let mut response = tokio::time::timeout(WAIT, sender.send_request(request)).await??;
        let expected = if udp {
            StatusCode::SWITCHING_PROTOCOLS
        } else {
            StatusCode::OK
        };
        check(response.status(), response.headers(), udp, expected)?;
        if udp {
            ensure!(
                response
                    .headers()
                    .get(UPGRADE)
                    .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"connect-udp")),
                "missing CONNECT-UDP Upgrade response"
            );
            ensure!(
                response
                    .headers()
                    .get(CONNECTION)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v
                        .split(',')
                        .any(|x| x.trim().eq_ignore_ascii_case("upgrade"))),
                "missing Connection: Upgrade response"
            );
        }
        let io = tokio::time::timeout(WAIT, hyper::upgrade::on(&mut response)).await??;
        keep.sender = Some(Box::new(sender));
        Ok(Opened {
            stream: Stream::new(TokioIo::new(io), keep),
            transport: "HTTP/1.1",
        })
    }
    async fn open_h3(&self, host: &str, port: u16, udp: bool) -> Result<Opened> {
        let native = tokio::time::timeout(
            WAIT,
            native::Quic::open(self.bridge.clone(), self.options(&["h3"])),
        )
        .await??;
        let lease = native.io.lease.clone();
        let mut builder = h3::client::builder();
        builder
            .enable_extended_connect(true)
            .enable_datagram(false)
            .send_grease(false)
            .max_field_section_size(16384);
        let (mut driver, mut sender) = tokio::time::timeout(
            WAIT,
            builder.build::<_, _, Bytes>(crate::quic::Connection::new(native)),
        )
        .await??;
        let mut keep = Keep::default();
        keep.lease = Some(lease);
        keep.tasks.push(tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        }));
        if udp {
            use h3::ConnectionState;
            let waiter = &mut sender;
            let driver_task = &keep.tasks[0];
            tokio::time::timeout(WAIT, async move {
                while !waiter.settings().enable_extended_connect() {
                    ensure!(
                        !driver_task.is_finished(),
                        "HTTP/3 closed before Extended CONNECT settings"
                    );
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Ok::<_, anyhow::Error>(())
            })
            .await
            .context("server did not enable HTTP/3 Extended CONNECT")??;
        }
        let mut request = self.request(host, port, udp)?;
        if udp {
            request
                .extensions_mut()
                .insert(h3::ext::Protocol::CONNECT_UDP);
        }
        let mut stream = tokio::time::timeout(WAIT, sender.send_request(request)).await??;
        tracing::debug!(
            sid = stream.id().into_inner(),
            "HTTP/3 request HEADERS sent; waiting for response"
        );
        let response = tokio::time::timeout(WAIT, stream.recv_response())
            .await
            .context("no HTTP/3 response")??;
        check(response.status(), response.headers(), udp, StatusCode::OK)?;
        keep.sender = Some(Box::new(sender));
        Ok(Opened {
            stream: Stream::h3(stream, keep),
            transport: "HTTP/3",
        })
    }
    /// An authenticated idle UDP flow verifies server-side CONNECT-UDP
    /// admission. This is not an Internet reachability or continuous DNS test.
    pub async fn monitor(&self) -> Result<()> {
        let mut backoff = Duration::from_secs(1);
        loop {
            self.selected.send_replace(None);
            let result: Result<()> = async {
                let Opened { stream, transport } = self.open(&self.probe_target.ip().to_string(), self.probe_target.port(), true).await?;
                let mode = match transport { "HTTP/3" => "h3", "HTTP/2" => "h2", _ => "http/1.1" };
                self.selected.send_replace(Some(mode.into()));
                self.bridge.emit(native::STATUS, 0, 0, 1, format!("Relay ready; {transport}; authenticated CONNECT-UDP")).await?;
                tracing::info!("Relay ready; {transport}; authenticated CONNECT-UDP (destination reachability is not implied)");
                let mut flow = UdpFlow::new(stream);
                while flow.recv().await?.is_some() {}
                anyhow::bail!("relay control flow ended")
            }.await;
            self.selected.send_replace(None);
            if let Err(e) = result {
                if terminal(&e) {
                    return Err(e);
                }
                tracing::warn!("Relay session failed: {e:#}");
                self.bridge
                    .emit(native::STATUS, 0, 0, 2, format!("{e:#}"))
                    .await?;
            }
            tracing::info!("Reconnecting in {:.1}s", backoff.as_secs_f64());
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    }
}
pub fn terminal(error: &anyhow::Error) -> bool {
    error.downcast_ref::<Rejected>().is_some()
        || error.chain().any(|e| {
            e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
        })
}
fn check(
    status: StatusCode,
    headers: &http::HeaderMap,
    udp: bool,
    expected: StatusCode,
) -> Result<()> {
    if status != expected {
        return Err(Rejected(status).into());
    }
    if udp {
        ensure!(
            headers
                .get(proto::CAPSULE_PROTOCOL_HEADER)
                .is_some_and(|v| v.as_bytes() == b"?1"),
            "relay did not negotiate Capsule Protocol"
        );
        ensure!(
            proto::valid_capsule_headers(headers),
            "content headers on CONNECT-UDP response"
        );
    }
    Ok(())
}
pub struct UdpFlow {
    pub stream: Stream,
    decoder: proto::CapsuleDecoder,
}
impl UdpFlow {
    pub fn new(stream: Stream) -> Self {
        Self {
            stream,
            decoder: proto::CapsuleDecoder::default(),
        }
    }
    pub async fn send(&mut self, payload: &[u8]) -> Result<()> {
        ensure!(payload.len() <= 65507, "UDP payload exceeds IPv4 maximum");
        let mut value = bytes::BytesMut::with_capacity(payload.len() + 1);
        value.extend_from_slice(&[0]);
        value.extend_from_slice(payload);
        let mut wire = bytes::BytesMut::new();
        proto::capsule::encode(0, &value, &mut wire);
        self.stream.write_all(&wire).await?;
        Ok(())
    }
    pub async fn recv(&mut self) -> Result<Option<Bytes>> {
        loop {
            if let Some(capsule) = self.decoder.next_udp_capsule()? {
                let mut payload = &capsule.value[..];
                if proto::varint::decode(&mut payload)? == 0 {
                    return Ok(Some(Bytes::copy_from_slice(payload)));
                }
                continue;
            }
            let mut bytes = [0; 16384];
            let count = self.stream.read(&mut bytes).await?;
            if count == 0 {
                self.decoder.finish()?;
                return Ok(None);
            }
            self.decoder.push(&bytes[..count]);
        }
    }
}
