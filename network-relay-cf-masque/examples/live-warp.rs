//! Live validation utility. Every origin lookup and socket uses WARP egress.
//! It never substitutes host sockets or an automatic transport downgrade.
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use http::{header, Request, Uri};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;
use warp_masque_egress::{Egress, WarpConfig, WarpEgress};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    warp_config: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Confirm tunneled DNS/UDP and Cloudflare trace's WARP exit marker.
    Probe,
    /// Stream a known artifact and compare its independently obtained SHA-256.
    Download {
        #[arg(long)]
        url: String,
        #[arg(long)]
        sha256: String,
        #[arg(long, default_value_t = 67_108_864)]
        min_bytes: u64,
    },
    /// Repeated live probes; this does not replace a held-connection soak.
    Soak {
        #[arg(long, default_value_t = 3900)]
        seconds: u64,
    },
}

struct Driver(JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn get(warp: &WarpEgress, url: &str) -> Result<(hyper::Response<hyper::body::Incoming>, Driver)> {
    let uri: Uri = url.parse().context("invalid URL")?;
    let target = origin_target(&uri)?;
    let host = target.host.as_str();
    let port = target.port;
    let addresses = warp.resolve(host).await.context("tunneled origin DNS")?;
    let mut stream = None;
    for address in addresses {
        match tokio::time::timeout(Duration::from_secs(15), warp.connect_tcp(SocketAddr::new(address, port))).await {
            Ok(Ok(tcp)) => {
                stream = Some(tcp);
                break;
            }
            _ => continue,
        }
    }
    let tcp = stream.context("no origin address reachable through WARP")?;
    let tls = network_relay::tls::client_config(None, &[b"http/1.1"])?;
    let tls = tokio::time::timeout(
        Duration::from_secs(20),
        tokio_rustls::TlsConnector::from(Arc::new(tls)).connect(host.to_string().try_into()?, tcp),
    )
    .await
    .context("origin TLS deadline")??;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
    let driver = Driver(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let request = Request::builder()
        .uri(uri.path_and_query().map_or("/", |p| p.as_str()))
        .header(header::HOST, uri.authority().unwrap().as_str())
        .header(header::ACCEPT_ENCODING, "identity")
        .header(header::CONNECTION, "close")
        .body(Empty::<Bytes>::new())?;
    let response = tokio::time::timeout(Duration::from_secs(30), sender.send_request(request))
        .await
        .context("origin response deadline")??;
    ensure!(response.status().is_success(), "origin returned HTTP {} (redirects are not followed)", response.status());
    Ok((response, driver))
}

fn origin_target(uri: &Uri) -> Result<network_relay::policy::Target> {
    ensure!(uri.scheme_str() == Some("https"), "only HTTPS validation URLs are accepted");
    let authority = uri.authority().context("URL needs a host")?;
    ensure!(!authority.as_str().contains('@'), "URL credentials are not accepted");
    let authority = if authority.port().is_some() { authority.as_str().to_owned() } else { format!("{authority}:443") };
    network_relay::policy::Target::from_authority(&authority).context("invalid origin host or port")
}

#[test]
fn validation_urls_use_the_parent_target_parser_for_each_address_family() {
    for (url, host, port) in [
        ("https://example.com/path", "example.com", 443),
        ("https://192.0.2.1:8443/", "192.0.2.1", 8443),
        ("https://[2001:db8::1]/", "2001:db8::1", 443),
        ("https://[2001:db8::1]:8443/", "2001:db8::1", 8443),
    ] {
        let target = origin_target(&url.parse().unwrap()).unwrap();
        assert_eq!((target.host.as_str(), target.port), (host, port));
    }
    for url in ["http://example.com/", "https://user:password@example.com/", "https://example.com:0/"] {
        assert!(origin_target(&url.parse().unwrap()).is_err());
    }
}

async fn trace(warp: &WarpEgress) -> Result<serde_json::Value> {
    tokio::time::timeout(Duration::from_secs(90), trace_inner(warp))
        .await
        .context("complete trace/DNS/UDP probe deadline")?
}

async fn trace_inner(warp: &WarpEgress) -> Result<serde_json::Value> {
    // The DNS result is observable evidence, not a host resolver lookup.
    let dns = warp.resolve("www.cloudflare.com").await?;
    ensure!(!dns.is_empty(), "empty tunneled DNS result");
    // Separate UDP DNS through the same tunnel, with an explicit transaction ID.
    let udp = warp.connect_udp("1.1.1.1:53".parse()?).await?;
    let mut query = vec![0x63, 0x66, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["www", "cloudflare", "com"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    udp.send(&query).await?;
    let mut answer = vec![0; udp.max_payload()];
    let n = tokio::time::timeout(Duration::from_secs(15), udp.recv(&mut answer)).await??;
    ensure!(
        n >= 12 && answer[..2] == query[..2] && answer[2] & 0x80 != 0 && answer[3] & 0x0f == 0,
        "UDP DNS transaction failed"
    );
    let (mut response, _driver) = get(warp, "https://www.cloudflare.com/cdn-cgi/trace").await?;
    let mut text = Vec::new();
    while let Some(frame) = tokio::time::timeout(Duration::from_secs(30), response.body_mut().frame()).await? {
        if let Ok(data) = frame?.into_data() {
            ensure!(text.len() + data.len() <= 65_536, "trace exceeded the bounded response size");
            text.extend_from_slice(&data);
        }
    }
    let text = std::str::from_utf8(&text)?;
    let value = |key: &str| text.lines().find_map(|line| line.strip_prefix(key)).map(str::to_owned);
    let exit = value("ip=").context("trace has no exit IP")?;
    exit.parse::<std::net::IpAddr>().context("trace exit IP invalid")?;
    let marker = value("warp=").context("trace has no WARP marker")?;
    ensure!(marker == "on" || marker == "plus", "trace does not confirm WARP egress");
    Ok(serde_json::json!({"live_cloudflare":true,"exit_ip":exit,"warp":marker,"tunneled_dns":dns,
        "udp_dns_reply_bytes":n,"status":warp.status()}))
}

async fn download(warp: &WarpEgress, url: &str, expected: &str, min: u64) -> Result<serde_json::Value> {
    tokio::time::timeout(Duration::from_secs(1800), download_inner(warp, url, expected, min))
        .await
        .context("complete download deadline")?
}

async fn download_inner(warp: &WarpEgress, url: &str, expected: &str, min: u64) -> Result<serde_json::Value> {
    ensure!(
        expected.len() == 64 && expected.bytes().all(|b| b.is_ascii_hexdigit()),
        "expected SHA-256 must be 64 hex digits"
    );
    let (mut response, _driver) = get(warp, url).await?;
    let length = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .map(|v| v.to_str()?.parse::<u64>().map_err(anyhow::Error::from))
        .transpose()?;
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let started = std::time::Instant::now();
    while let Some(frame) = tokio::time::timeout(Duration::from_secs(45), response.body_mut().frame()).await? {
        if let Ok(data) = frame?.into_data() {
            bytes += data.len() as u64;
            hash.update(&data);
        }
        ensure!(started.elapsed() < Duration::from_secs(1800), "download exceeded the total deadline");
    }
    ensure!(bytes >= min, "download too small: {bytes} < {min}");
    if let Some(length) = length {
        ensure!(bytes == length, "download truncated: {bytes}/{length}");
    }
    let actual = format!("{:x}", hash.finalize());
    ensure!(actual.eq_ignore_ascii_case(expected), "download SHA-256 mismatch");
    Ok(serde_json::json!({"live_cloudflare":true,"downloaded_bytes":bytes,"sha256":actual,
        "elapsed_seconds":started.elapsed().as_secs_f64(),"status":warp.status()}))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = WarpConfig::load(&args.warp_config)?;
    let warp = tokio::time::timeout(Duration::from_secs(25), WarpEgress::connect(&config))
        .await
        .context("WARP setup deadline; no transport fallback attempted")??;
    let result = async {
        match args.command {
            Command::Probe => println!("{}", trace(&warp).await?),
            Command::Download { url, sha256, min_bytes } => {
                println!("{}", download(&warp, &url, &sha256, min_bytes).await?)
            }
            Command::Soak { seconds } => {
                ensure!(seconds >= 3600, "live soak requires at least 3600 actual seconds");
                let start = std::time::Instant::now();
                let mut tick = tokio::time::interval(Duration::from_secs(30));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                while start.elapsed().as_secs() < seconds {
                    tick.tick().await;
                    let mut row = trace(&warp).await?;
                    row["elapsed_seconds"] = start.elapsed().as_secs_f64().into();
                    println!("{row}");
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    warp.shutdown().await;
    result
}
