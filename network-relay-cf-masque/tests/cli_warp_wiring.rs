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
    command.env("RUST_LOG", "info").arg("serve").arg("--config").arg(env.path.join("relay.toml"));
    command
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn root_cli_offline_check_real_serve_and_tunnel_death_are_fail_closed() -> Result<()> {
    let mut rows = Vec::new();
    for mode in [Transport::H2, Transport::H3] {
        let env = TestEnv::new("root-cli")?;
        let mut peer = WarpPeer::start(mode).await?;
        peer.config(&env.path)?;
        let registration_path = env.path.join("registration.json");
        let mut old_registration: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&registration_path)?)?;
        let ipv6 = old_registration.as_object_mut().unwrap().remove("tunnel_ipv6").unwrap();
        old_registration["ipv6"] = ipv6; // Also exercise the supported usque alias.
        std::fs::write(&registration_path, serde_json::to_vec(&old_registration)?)?;
        let addr = unused_ingress()?;
        static HASH: OnceLock<String> = OnceLock::new();
        let hash = HASH.get_or_init(|| auth::hash_password(PASSWORD).unwrap());
        let config = format!("listen = \"{addr}\"\n[tls]\ncert = {:?}\nkey = {:?}\n[web]\nroot = {:?}\n[relay]\nblocked_destinations = []\nblocked_ports = []\nblock_own_addresses = false\n[[user]]\nname = \"{USER}\"\npassword_hash = \"{hash}\"\n", env.path.join("fullchain.pem"), env.path.join("privkey.pem"), env.path.join("site"));
        std::fs::write(env.path.join("relay.toml"), config)?;
        let offline =
            serve_command(&env).arg("--warp-config").arg(env.path.join("warp.toml")).arg("--check").output()?;
        ensure!(
            offline.status.success(),
            "offline configuration check failed: {}",
            String::from_utf8_lossy(&offline.stderr)
        );
        ensure!(
            peer.snapshot().authenticated_clients == 0 && peer.snapshot().tunnels == 0,
            "offline --check opened a tunnel"
        );

        // Migrate the actual legacy fixture, then remove both extra files. All
        // following checks and the real server must work with this one TOML.
        let combined = env.path.join("combined.toml");
        let migration = Command::new(BIN)
            .arg("migrate-config")
            .arg("--config")
            .arg(env.path.join("relay.toml"))
            .arg("--warp-config")
            .arg(env.path.join("warp.toml"))
            .arg("--out")
            .arg(&combined)
            .arg("--ipv4-only")
            .output()?;
        ensure!(migration.status.success(), "migration failed: {}", String::from_utf8_lossy(&migration.stderr));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(std::fs::metadata(&combined)?.permissions().mode() & 0o777 == 0o600, "migration permissions");
        }
        let original = std::fs::read_to_string(&combined)?;
        let parsed: toml::Value = toml::from_str(&original)?;
        let registration = &parsed["warp"]["registration"];
        ensure!(
            registration.get("tunnel_ipv6").is_none() && registration.get("ipv6").is_none(),
            "IPv4 migration retained IPv6"
        );
        let secret = registration["private_key"].as_str().unwrap();
        ensure!(!String::from_utf8_lossy(&migration.stdout).contains(secret), "migration printed a key");
        // Refusing an existing output must leave its contents intact.
        let duplicate = Command::new(BIN)
            .arg("migrate-config")
            .arg("--config")
            .arg(env.path.join("relay.toml"))
            .arg("--warp-config")
            .arg(env.path.join("warp.toml"))
            .arg("--out")
            .arg(&combined)
            .output()?;
        ensure!(
            !duplicate.status.success() && std::fs::read_to_string(&combined)? == original,
            "migration overwrote output"
        );
        std::fs::write(env.path.join("relay.toml"), &original)?;
        std::fs::remove_file(env.path.join("warp.toml"))?;
        std::fs::remove_file(env.path.join("registration.json"))?;
        let offline = serve_command(&env).arg("--check").output()?;
        ensure!(
            offline.status.success(),
            "single-file offline check failed: {}",
            String::from_utf8_lossy(&offline.stderr)
        );
        let invalid = original
            .replace("transport = \"h2\"", "transport = \"automatic\"")
            .replace("transport = \"h3\"", "transport = \"automatic\"");
        std::fs::write(env.path.join("relay.toml"), invalid)?;
        let invalid = serve_command(&env).arg("--check").output()?;
        ensure!(!invalid.status.success(), "invalid/implicit transport was accepted");
        ensure!(
            peer.snapshot().authenticated_clients == 0 && peer.snapshot().tunnels == 0,
            "bad transport opened underlay"
        );
        ensure!(!String::from_utf8_lossy(&invalid.stderr).contains(secret), "configuration error printed a key");
        std::fs::write(env.path.join("relay.toml"), &original)?;

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
        // SIGHUP validates the combined file, reloads ordinary relay settings,
        // and keeps the existing WARP session until a requested restart.
        let mut changed: toml::Value = toml::from_str(&original)?;
        changed["warp"]["keepalive_secs"] = toml::Value::Integer(2);
        let reloaded_password = "new-ephemeral-matrix-password-2026";
        changed["user"][0]["password_hash"] = toml::Value::String(auth::hash_password(reloaded_password)?);
        std::fs::write(env.path.join("relay.toml"), toml::to_string(&changed)?)?;
        hup(&server)?;
        wait_log(&env, "[warp] changes require a restart").await?;
        ensure!(peer.snapshot().authenticated_clients == 1, "SIGHUP replaced the WARP session");
        let mut reloaded_options = options.clone();
        reloaded_options.password = reloaded_password.into();
        changed["warp"]["transport"] = toml::Value::String("invalid-transport".into());
        std::fs::write(env.path.join("relay.toml"), toml::to_string(&changed)?)?;
        hup(&server)?;
        wait_log(&env, "not reloading, configuration is invalid").await?;
        ensure!(server.0.try_wait()?.is_none(), "bad reload stopped the active server");
        for result in check::run(&reloaded_options).await {
            result.result.map_err(|error| anyhow::anyhow!("after reload {}: {error:#}", result.name))?;
        }
        ensure!(!std::fs::read_to_string(env.path.join("server.log"))?.contains(secret), "reload logged a private key");
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

fn hup(server: &Server) -> Result<()> {
    ensure!(Command::new("kill").arg("-HUP").arg(server.0.id().to_string()).status()?.success(), "SIGHUP failed");
    Ok(())
}

async fn wait_log(env: &TestEnv, needle: &str) -> Result<()> {
    let started = Instant::now();
    while !std::fs::read_to_string(env.path.join("server.log"))?.contains(needle) {
        ensure!(started.elapsed() < WAIT, "expected server log missing: {needle}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Ok(())
}

#[tokio::test]
async fn ipv4_migration_converts_wildcard_listeners_and_rejects_specific_ipv6() -> Result<()> {
    let mut peer = WarpPeer::start(Transport::H2).await?;
    for (listen, expected) in
        [(None, Some("0.0.0.0:443")), (Some("[::]:8443"), Some("0.0.0.0:8443")), (Some("[::1]:8443"), None)]
    {
        let env = TestEnv::new("ipv4-migration")?;
        peer.config(&env.path)?;
        let prefix = listen.map(|listen| format!("listen = \"{listen}\"\n")).unwrap_or_default();
        let input = format!("{prefix}[tls]\ncert = \"fullchain.pem\"\nkey = \"privkey.pem\"\n");
        std::fs::write(env.path.join("relay.toml"), &input)?;
        let out = env.path.join("single.toml");
        let result = Command::new(BIN)
            .arg("migrate-config")
            .arg("--config")
            .arg(env.path.join("relay.toml"))
            .arg("--warp-config")
            .arg(env.path.join("warp.toml"))
            .arg("--out")
            .arg(&out)
            .arg("--ipv4-only")
            .output()?;
        if let Some(expected) = expected {
            ensure!(result.status.success(), "listener migration failed: {}", String::from_utf8_lossy(&result.stderr));
            let output: toml::Value = toml::from_str(&std::fs::read_to_string(out)?)?;
            ensure!(output["listen"].as_str() == Some(expected), "wrong IPv4 listener");
        } else {
            ensure!(!result.status.success() && !out.exists(), "specific IPv6 listener accepted");
        }
        ensure!(std::fs::read_to_string(env.path.join("relay.toml"))? == input, "migration modified input");
    }
    peer.shutdown().await;
    Ok(())
}
