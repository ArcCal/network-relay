//! The actual root binary must wire the mandatory backend before listening.
mod support;
use anyhow::{ensure, Result};
use relay_frontend::{auth, check};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use support::relay::{TestEnv, PASSWORD, USER, WAIT};
use support::warp_peer::WarpPeer;
use warp_masque_egress::Transport;

const BIN: &str = env!("CARGO_BIN_EXE_network-relay-cf-masque");
struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}
fn unused_ingress() -> Result<std::net::SocketAddr> {
    for _ in 0..30 {
        let udp = std::net::UdpSocket::bind("127.0.0.1:0")?;
        if let Ok(_tcp) = std::net::TcpListener::bind(udp.local_addr()?) {
            return Ok(udp.local_addr()?);
        }
    }
    anyhow::bail!("could not reserve paired CLI ingress port")
}
fn serve_command(env: &TestEnv) -> Command {
    let mut command = Command::new(BIN);
    command
        .arg("serve")
        .arg("--config")
        .arg(env.path.join("relay.toml"))
        .arg("--warp-config")
        .arg(env.path.join("warp.toml"));
    command
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn root_cli_offline_check_real_serve_and_tunnel_death_are_fail_closed() -> Result<()> {
    let mut rows = Vec::new();
    for mode in [Transport::H2, Transport::H3] {
        let env = TestEnv::new("root-cli")?;
        let mut peer = WarpPeer::start(mode).await?;
        peer.config(&env.path)?;
        let addr = unused_ingress()?;
        static HASH: OnceLock<String> = OnceLock::new();
        let hash = HASH.get_or_init(|| auth::hash_password(PASSWORD).unwrap());
        let config = format!("listen = \"{addr}\"\n[tls]\ncert = {:?}\nkey = {:?}\n[web]\nroot = {:?}\n[relay]\nblocked_destinations = []\nblocked_ports = []\nblock_own_addresses = false\n[[user]]\nname = \"{USER}\"\npassword_hash = \"{hash}\"\n", env.path.join("fullchain.pem"), env.path.join("privkey.pem"), env.path.join("site"));
        std::fs::write(env.path.join("relay.toml"), config)?;
        let offline = serve_command(&env).arg("--check").output()?;
        ensure!(
            offline.status.success(),
            "offline configuration check failed: {}",
            String::from_utf8_lossy(&offline.stderr)
        );
        ensure!(
            peer.snapshot().authenticated_clients == 0 && peer.snapshot().tunnels == 0,
            "offline --check opened a tunnel"
        );

        let original = std::fs::read_to_string(env.path.join("warp.toml"))?;
        let invalid = original
            .replace("transport = \"h2\"", "transport = \"automatic\"")
            .replace("transport = \"h3\"", "transport = \"automatic\"");
        std::fs::write(env.path.join("warp.toml"), invalid)?;
        let invalid = serve_command(&env).arg("--check").output()?;
        ensure!(!invalid.status.success(), "invalid/implicit transport was accepted");
        ensure!(
            peer.snapshot().authenticated_clients == 0 && peer.snapshot().tunnels == 0,
            "bad transport opened underlay"
        );
        std::fs::write(env.path.join("warp.toml"), original)?;

        let logfile = std::fs::File::create(env.path.join("server.log"))?;
        let stderr = logfile.try_clone()?;
        let mut server = Server(serve_command(&env).stdout(Stdio::from(logfile)).stderr(Stdio::from(stderr)).spawn()?);
        let ready = Instant::now();
        loop {
            ensure!(
                server.0.try_wait()?.is_none(),
                "CLI exited during startup: {}",
                std::fs::read_to_string(env.path.join("server.log"))?
            );
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            ensure!(ready.elapsed() < WAIT, "root CLI did not start ingress");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let options = check::Options {
            host: "relay.test".into(),
            port: addr.port(),
            addresses: vec![addr],
            user: USER.into(),
            password: PASSWORD.into(),
            udp_template: relay_frontend::proto::DEFAULT_UDP_PATH_TEMPLATE.into(),
            tcp_target: "fixture.test:80".into(),
            udp_target: ("fixture.test".into(), 53),
            dns_name: "fixture.test".into(),
            ca: Some(env.path.join("ca.pem")),
            client_cert: None,
            timeout: WAIT,
        };
        let results = check::run(&options).await;
        ensure!(results.len() == 7, "CLI client did not run all checks");
        for result in &results {
            result.result.as_ref().map_err(|error| anyhow::anyhow!("{}: {error:#}", result.name))?;
        }
        let snapshot = peer.snapshot();
        ensure!(
            snapshot.http_requests >= 3 && snapshot.dns_queries >= 4 && snapshot.ip_packets_from_client > 0,
            "actual serve bypassed packet backend"
        );

        peer.terminate_transport();
        let ended = Instant::now();
        let status = loop {
            if let Some(status) = server.0.try_wait()? {
                break status;
            }
            ensure!(ended.elapsed() < Duration::from_secs(10), "CLI remained alive after terminal WARP failure");
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        ensure!(!status.success(), "root serve treated mandatory WARP failure as success");
        ensure!(
            tokio::net::TcpStream::connect(addr).await.is_err(),
            "failed root serve still listens for business traffic"
        );
        rows.push(serde_json::json!({"warp_transport": format!("{mode:?}"), "offline_check": "passed_without_tunnel", "bad_transport": "rejected_without_tunnel", "actual_serve_checks": 7, "peer": snapshot, "terminal_exit": status.code(), "listener_closed": true, "live_cloudflare": false}));
        drop(server);
        peer.shutdown().await;
    }
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/evidence");
    std::fs::create_dir_all(&dir)?;
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis();
    std::fs::write(
        dir.join(format!("root-cli-warp-{stamp}-{}.json", std::process::id())),
        serde_json::to_vec_pretty(&rows)?,
    )?;
    Ok(())
}
