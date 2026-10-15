//! Actual unchanged client protocol cores against real userspace WARP egress.
//! The local synthetic WARP peer is not Cloudflare. NF's native bridge is
//! emulated on Linux; RS uses its unchanged production Rust transport backend.
mod support;

use anyhow::{ensure, Context, Result};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use support::relay::{TestEnv, TestRelay, PASSWORD, USER, WAIT};
use support::warp_peer::WarpPeer;
use warp_masque_egress::{Egress, Transport, WarpEgress};

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn project() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

async fn client_harness(client: &str, fixture: &Path) -> Result<serde_json::Value> {
    let variable = match client {
        "nf" => "NF_INTEROP_BIN",
        "rs" => "RS_INTEROP_BIN",
        "nf-current" => "NF_CURRENT_INTEROP_BIN",
        "rs-current" => "RS_CURRENT_INTEROP_BIN",
        _ => unreachable!(),
    };
    let binary = std::env::var_os(variable).map(PathBuf::from).unwrap_or_else(|| {
        let family = client.split('-').next().expect("client family");
        project().join(format!("target/client-interop-{family}/debug/client-interop-{client}"))
    });
    ensure!(
        binary.is_file(),
        "build unchanged client harness first: python3 scripts/prepare-client-tests.py ({})",
        binary.display()
    );
    let child = Command::new(&binary)
        .arg(fixture)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting {client} protocol-core harness"))?;
    let mut child = ChildGuard(child);
    let mut stdout = child.0.stdout.take().expect("stdout pipe");
    let mut stderr = child.0.stderr.take().expect("stderr pipe");
    let status = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            if let Some(status) = child.0.try_wait()? {
                return Ok::<_, std::io::Error>(status);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("unchanged client process deadline")??;
    let mut output = Vec::new();
    let mut error = Vec::new();
    stdout.read_to_end(&mut output)?;
    stderr.read_to_end(&mut error)?;
    ensure!(status.success(), "{client} harness failed: {}", String::from_utf8_lossy(&error));
    let row: serde_json::Value = serde_json::from_slice(&output).context("client evidence JSON")?;
    ensure!(
        row["rows"].as_array().is_some_and(|rows| rows.len() == 8),
        "client did not execute all IPv4/domain and IPv6 TCP/UDP cases"
    );
    ensure!(
        row["wrong_password_rejected"] == true && row["certificate_name_rejected"] == true,
        "client authentication/TLS negative checks missing"
    );
    Ok(row)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unchanged_nf_rs_cores_use_each_ingress_and_warp_transport() -> Result<()> {
    let started = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut evidence = Vec::new();
    for transport in [Transport::H2, Transport::H3] {
        let env = TestEnv::new("unchanged-client-interop")?;
        let mut peer = WarpPeer::start(transport).await?;
        let config = peer.config(&env.path)?;
        let warp = Arc::new(tokio::time::timeout(WAIT, WarpEgress::connect(&config)).await??);
        let mut relay = TestRelay::start(&env, warp.clone()).await?;
        for client in ["nf", "rs", "nf-current", "rs-current"] {
            for ingress in ["http/1.1", "h2", "h3"] {
                let fixture = env.path.join(format!("{client}-{}.json", ingress.replace('/', "_")));
                let settings = serde_json::json!({"server":relay.addr.to_string(),"ca":env.path.join("ca.pem"),
                    "user":USER,"password":PASSWORD,"transport":ingress});
                relay_frontend::private_file::write(&fixture, &serde_json::to_vec(&settings)?)?;
                let before = peer.snapshot();
                let row = client_harness(client, &fixture).await?;
                let after = peer.snapshot();
                ensure!(
                    after.ip_packets_from_client > before.ip_packets_from_client
                        && after.ip_packets_to_client > before.ip_packets_to_client,
                    "unchanged {client}/{ingress} bypassed the WARP IP packet path"
                );
                ensure!(
                    after.dns_queries > before.dns_queries,
                    "unchanged {client}/{ingress} target name did not resolve through WARP"
                );
                ensure!(peer.errors().is_empty(), "synthetic WARP peer errors: {:?}", peer.errors());
                tokio::time::timeout(WAIT, async {
                    while relay.relay.active_tunnels() != 0 {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                })
                .await
                .context("unchanged client server tunnel release")?;
                evidence.push(serde_json::json!({"client":client,"ingress":ingress,
                    "egress":match transport{Transport::H2=>"h2",Transport::H3=>"h3"},
                    "packet_delta_uploaded":after.ip_packets_from_client-before.ip_packets_from_client,
                    "packet_delta_downloaded":after.ip_packets_to_client-before.ip_packets_to_client,
                    "dns_queries_delta":after.dns_queries-before.dns_queries,
                    "client_evidence":row}));
            }
        }
        relay.shutdown().await?;
        warp.shutdown().await;
        ensure!(!warp.available() && warp.status().workers == 0, "WARP owner failed to release workers");
        peer.shutdown().await;
    }
    ensure!(evidence.len() == 24, "unchanged client transport matrix incomplete");
    let mut source_ids = serde_json::Map::new();
    for client in ["nf", "rs", "nf-current", "rs-current"] {
        let pin: serde_json::Value = serde_json::from_slice(&std::fs::read(
            project().join(format!("tests/client-fixtures/{client}/PIN.json")),
        )?)?;
        source_ids.insert(
            client.to_string(),
            serde_json::json!({"aggregate_sha256":pin["aggregate_sha256"],
            "source_revision":pin["source_revision"],"version":pin["version"]}),
        );
    }
    let result = serde_json::json!({"started_unix":started,"ended_unix":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "client_sources":source_ids,
        "client_sources_modified":false,"native_nf_transport":"unchanged Linux test bridge emulator",
        "rs_transport":"unchanged production Tokio/rustls/Quinn backend",
        "live_cloudflare":false,"native_macos_or_gui_tested":false,"matrix":evidence});
    let path = project().join("docs/evidence/client-interop.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&result)?)?;
    println!("Unchanged parent and current NF/RS cores: 24 ingress/egress pairs, 192 IPv4/domain+IPv6 TCP/UDP checks, authentication and TLS negatives; evidence {}", path.display());
    Ok(())
}
