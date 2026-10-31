//! Real, unchanged relay transports; all target I/O is supplied by WarpEgress.
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use network_relay::{
    auth,
    certs::CertStore,
    check,
    config::Config,
    server::{self, Relay},
};
use tokio::{net::TcpListener, task::JoinHandle};
use warp_masque_egress::WarpEgress;

pub const USER: &str = "matrix-user";
pub const PASSWORD: &str = "ephemeral-matrix-password-2026";
pub const WAIT: Duration = Duration::from_secs(30);

pub struct TestEnv {
    pub path: PathBuf,
}
impl TestEnv {
    pub fn new(label: &str) -> Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-runtime");
        std::fs::create_dir_all(&parent)?;
        let path =
            parent.join(format!("warp-matrix-{label}-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        }
        std::fs::create_dir(path.join("site"))?;
        std::fs::write(path.join("site/index.html"), "<!doctype html><title>matrix cover</title>")?;
        write_certificates(&path)?;
        Ok(Self { path })
    }
}
impl Drop for TestEnv {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn write_certificates(path: &Path) -> Result<()> {
    let ca_key = rcgen::KeyPair::generate()?;
    let mut ca_params = rcgen::CertificateParams::new(Vec::new())?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(rcgen::DnType::CommonName, "Ephemeral matrix CA");
    let ca = ca_params.self_signed(&ca_key)?;
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let key = rcgen::KeyPair::generate()?;
    let cert = rcgen::CertificateParams::new(vec!["relay.test".into()])?.signed_by(&key, &issuer)?;
    std::fs::write(path.join("ca.pem"), ca.pem())?;
    std::fs::write(path.join("fullchain.pem"), cert.pem() + &ca.pem())?;
    std::fs::write(path.join("privkey.pem"), key.serialize_pem())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path.join("privkey.pem"), std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub struct TestRelay {
    pub relay: Relay,
    pub addr: SocketAddr,
    config: Config,
    ca: PathBuf,
    tasks: Vec<JoinHandle<()>>,
}
impl TestRelay {
    pub async fn start(env: &TestEnv, egress: Arc<WarpEgress>) -> Result<Self> {
        let (udp, tcp) = bind_pair().await?;
        let addr = udp.local_addr()?;
        static HASH: OnceLock<String> = OnceLock::new();
        let hash = HASH.get_or_init(|| auth::hash_password(PASSWORD).expect("hashing fixture password"));
        let text = format!(
            "listen = \"{addr}\"\n[tls]\ncert = {:?}\nkey = {:?}\n[web]\nroot = {:?}\n[relay]\nblocked_destinations = []\nblocked_ports = []\nblock_own_addresses = false\nmax_tunnels = 64\nmax_tunnels_per_user = 64\n[[user]]\nname = \"{USER}\"\npassword_hash = \"{hash}\"\n",
            env.path.join("fullchain.pem"),
            env.path.join("privkey.pem"),
            env.path.join("site")
        );
        let config: Config = toml::from_str(&text)?;
        config.validate()?;
        let certs = CertStore::open(&config.tls.cert, &config.tls.key)?;
        let relay = Relay::with_egress(&config, egress)?;
        let endpoint = server::quic_endpoint(certs.clone(), udp, false)?;
        let tasks = vec![
            tokio::spawn(relay.clone().serve_quic(endpoint)),
            tokio::spawn(relay.clone().serve_tcp(tcp, server::tcp_tls_config(certs, false)?)),
        ];
        Ok(Self { relay, addr, config, ca: env.path.join("ca.pem"), tasks })
    }
    pub fn options(&self) -> check::Options {
        check::Options {
            host: "relay.test".into(),
            port: self.addr.port(),
            addresses: vec![self.addr],
            user: USER.into(),
            password: PASSWORD.into(),
            udp_template: network_relay::proto::DEFAULT_UDP_PATH_TEMPLATE.into(),
            tcp_target: "fixture.test:80".into(),
            udp_target: ("fixture.test".into(), 53),
            dns_name: "fixture.test".into(),
            ca: Some(self.ca.clone()),
            client_cert: None,
            timeout: WAIT,
        }
    }
    pub fn revoke_user(&self) -> Result<()> {
        let mut config = self.config.clone();
        config.users.clear();
        self.relay.reload(&config).context("revoking matrix user")
    }
    pub fn restore_user(&self) -> Result<()> {
        self.relay.reload(&self.config)
    }
    pub async fn shutdown(&mut self) -> Result<()> {
        self.relay.begin_shutdown();
        anyhow::ensure!(self.relay.drain(WAIT).await, "relay did not drain");
        for task in self.tasks.drain(..) {
            task.abort();
            let _ = task.await;
        }
        Ok(())
    }
}
impl Drop for TestRelay {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn bind_pair() -> Result<(std::net::UdpSocket, TcpListener)> {
    for _ in 0..30 {
        let udp = std::net::UdpSocket::bind("127.0.0.1:0")?;
        if let Ok(tcp) = TcpListener::bind(udp.local_addr()?).await {
            return Ok((udp, tcp));
        }
    }
    anyhow::bail!("could not reserve paired ingress TCP/UDP port")
}
