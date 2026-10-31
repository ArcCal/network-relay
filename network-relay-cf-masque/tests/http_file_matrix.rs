//! A known HTTP file crosses CONNECT and the real WARP IP transport.
mod support;
use anyhow::{ensure, Context, Result};
use bytes::{Buf, Bytes};
use http::{Method, Request, StatusCode};
use http_body_util::Empty;
use hyper_util::rt::TokioIo;
use network_relay::{auth, check};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant};
use support::relay::{TestEnv, TestRelay, PASSWORD, USER};
use support::warp_peer::{WarpPeer, HTTP_FILE_BYTES};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use warp_masque_egress::{Transport, WarpEgress};

// Independently computed in Python, then verified by executing only the
// fixture's Rust pattern helper as a standalone streamed producer.
const FILE_SHA256: &str = "6e337e4992fc84fc2744a38b784928aaaf460757861b749fcb01c066fbb80780";
const GET: &[u8] = b"GET /large.bin HTTP/1.1\r\nHost: fixture.test\r\nConnection: close\r\n\r\n";
struct HttpFile {
    header: Vec<u8>,
    ready: bool,
    bytes: usize,
    hash: Sha256,
}
impl HttpFile {
    fn new() -> Self {
        Self { header: Vec::new(), ready: false, bytes: 0, hash: Sha256::new() }
    }
    fn feed(&mut self, data: &[u8]) -> Result<()> {
        let mut offset = 0;
        if !self.ready {
            while offset < data.len() {
                self.header.push(data[offset]);
                offset += 1;
                ensure!(self.header.len() <= 4096, "HTTP file header grew without bound");
                if self.header.ends_with(b"\r\n\r\n") {
                    let text = std::str::from_utf8(&self.header)?;
                    ensure!(text.starts_with("HTTP/1.1 200 OK\r\n"), "file origin returned the wrong status");
                    let length = text
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>())
                                .transpose()
                                .ok()
                                .flatten()
                        })
                        .context("file response has no numeric Content-Length")?;
                    ensure!(length == HTTP_FILE_BYTES, "file origin did not advertise64MiB");
                    ensure!(
                        !text.lines().any(|line| line.to_ascii_lowercase().starts_with("transfer-encoding:")),
                        "test file unexpectedly used transfer encoding"
                    );
                    self.ready = true;
                    break;
                }
            }
        }
        if self.ready {
            self.bytes += data.len() - offset;
            ensure!(self.bytes <= HTTP_FILE_BYTES, "origin sent more than Content-Length");
            self.hash.update(&data[offset..]);
        }
        Ok(())
    }
    fn finish(self) -> Result<String> {
        ensure!(
            self.ready && self.bytes == HTTP_FILE_BYTES,
            "file/EOF truncated: {}/{} bytes",
            self.bytes,
            HTTP_FILE_BYTES
        );
        let actual = format!("{:x}", self.hash.finalize());
        ensure!(actual == FILE_SHA256, "known HTTP file SHA256 mismatch");
        Ok(actual)
    }
}
fn connect() -> http::request::Builder {
    Request::builder()
        .method(Method::CONNECT)
        .uri("fixture.test:80")
        .header("host", "fixture.test:80")
        .header("proxy-authorization", auth::basic_authorization(USER, PASSWORD))
}
async fn read_file<S: AsyncRead + Unpin>(stream: &mut S) -> Result<String> {
    let mut file = HttpFile::new();
    let mut buffer = vec![0; 64 << 10];
    loop {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        file.feed(&buffer[..count])?;
    }
    file.finish()
}
async fn fetch(relay: &TestRelay, inbound: &str) -> Result<serde_json::Value> {
    let started = Instant::now();
    let opts = relay.options();
    let hash = match inbound {
        "h1" => {
            let (mut sender, _driver) = check::h1_sender(&opts, &opts.addresses).await?;
            let mut response = sender.send_request(connect().body(Empty::<Bytes>::new())?).await?;
            ensure!(response.status() == StatusCode::OK, "file H1 CONNECT refused");
            let mut stream = TokioIo::new(hyper::upgrade::on(&mut response).await?);
            stream.write_all(GET).await?;
            stream.shutdown().await?;
            read_file(&mut stream).await?
        }
        "h2" => {
            let (mut sender, _driver) = check::h2_sender(&opts, &opts.addresses).await?;
            let mut response = sender.send_request(connect().body(Empty::<Bytes>::new())?).await?;
            ensure!(response.status() == StatusCode::OK, "file H2 CONNECT refused");
            let mut stream = TokioIo::new(hyper::upgrade::on(&mut response).await?);
            stream.write_all(GET).await?;
            stream.shutdown().await?;
            read_file(&mut stream).await?
        }
        "h3" => {
            let mut client = check::H3::connect(&opts, &opts.addresses).await?;
            let mut stream = client.request(connect().body(())?).await?;
            ensure!(stream.recv_response().await?.status() == StatusCode::OK, "file H3 CONNECT refused");
            stream.send_data(Bytes::from_static(GET)).await?;
            stream.finish().await?;
            let mut file = HttpFile::new();
            while let Some(mut chunk) = stream.recv_data().await? {
                while chunk.has_remaining() {
                    let count = chunk.chunk().len();
                    file.feed(chunk.chunk())?;
                    chunk.advance(count);
                }
            }
            file.finish()?
        }
        _ => unreachable!(),
    };
    Ok(
        serde_json::json!({"inbound": inbound, "http": "GET /large.bin", "body_bytes": HTTP_FILE_BYTES, "sha256": hash, "elapsed_ms": started.elapsed().as_millis()}),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn known_64mib_http_file_streams_across_all_six_pairings() -> Result<()> {
    let mut cases = Vec::new();
    for mode in [Transport::H2, Transport::H3] {
        let env = TestEnv::new("http-file")?;
        let mut peer = WarpPeer::start(mode).await?;
        let warp = Arc::new(WarpEgress::connect(&peer.config(&env.path)?).await?);
        let mut relay = TestRelay::start(&env, warp.clone()).await?;
        let mut results = Vec::new();
        for inbound in ["h1", "h2", "h3"] {
            results.push(
                tokio::time::timeout(Duration::from_secs(180), fetch(&relay, inbound))
                    .await
                    .context("HTTP file deadline")??,
            );
        }
        let snapshot = peer.snapshot();
        ensure!(
            snapshot.http_file_requests == 3 && snapshot.http_file_bytes_sent == 3 * HTTP_FILE_BYTES as u64,
            "HTTP file bytes bypassed peer userspace origin"
        );
        cases.push(serde_json::json!({"warp_transport": format!("{mode:?}"), "checks": results, "peer": snapshot, "egress": warp.status(), "live_cloudflare": false}));
        relay.shutdown().await?;
        warp.shutdown().await;
        peer.shutdown().await;
    }
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/evidence");
    std::fs::create_dir_all(&dir)?;
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis();
    std::fs::write(
        dir.join(format!("http-file-{stamp}-{}.json", std::process::id())),
        serde_json::to_vec_pretty(&cases)?,
    )?;
    Ok(())
}
