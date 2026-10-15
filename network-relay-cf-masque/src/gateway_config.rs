//! Application configuration. The reusable frontend and WARP crates stay independent.

use std::io::Write;
use std::path::Path;

use anyhow::{ensure, Context, Result};
use relay_frontend::config::Config;
use warp_masque_egress::WarpConfig;

pub struct GatewayConfig {
    pub relay: Config,
    pub warp: WarpConfig,
    pub warp_settings: toml::Value,
}

fn read(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("reading configuration {}", path.display()))
}

fn table(text: &str) -> Result<toml::Table> {
    // Never retain a TOML/serde error: its Display can echo a private key.
    toml::from_str(text).map_err(|_| anyhow::anyhow!("invalid configuration TOML; check syntax and field types"))
}

fn warp_table(value: &toml::Table) -> Result<toml::Table> {
    match value.get("warp") {
        Some(toml::Value::Table(warp)) => Ok(warp.clone()),
        Some(_) => anyhow::bail!("[warp] must be a TOML table"),
        None => Ok(value.clone()), // Legacy plain WARP settings.
    }
}

fn inline_registration(warp: &mut toml::Table, settings_path: &Path) -> Result<()> {
    if let Some(toml::Value::String(name)) = warp.get("registration") {
        let parent = settings_path.parent().unwrap_or_else(|| Path::new("."));
        let path = parent.join(name);
        let text = read(&path)?;
        let value: serde_json::Value =
            serde_json::from_str(&text).map_err(|_| anyhow::anyhow!("invalid WARP registration JSON"))?;
        let value = toml::Value::try_from(value)
            .map_err(|_| anyhow::anyhow!("WARP registration cannot be represented as TOML"))?;
        ensure!(value.is_table(), "WARP registration must be an object");
        warp.insert("registration".into(), value);
    }
    Ok(())
}

impl GatewayConfig {
    pub fn load(path: &Path, legacy_warp_path: Option<&Path>) -> Result<Self> {
        let text = read(path)?;
        let relay = Config::from_toml(&text).with_context(|| format!("loading configuration {}", path.display()))?;
        let root = table(&text)?;
        let (warp_text, warp_path) = match legacy_warp_path {
            Some(warp_path) => {
                ensure!(!root.contains_key("warp"), "choose [warp] in --config or legacy --warp-config, not both");
                (read(warp_path)?, warp_path)
            }
            None => {
                ensure!(
                    root.contains_key("warp"),
                    "missing [warp] in --config; add inline WARP settings and registration"
                );
                (text, path)
            }
        };
        let warp = WarpConfig::from_toml(&warp_text, warp_path)?;
        let mut warp_settings = warp_table(&table(&warp_text)?)?;
        // Compare enrollment changes as well as settings on SIGHUP, without logging either.
        inline_registration(&mut warp_settings, warp_path)?;
        Ok(Self { relay, warp, warp_settings: toml::Value::Table(warp_settings) })
    }
}

/// Read the old files, validate the combined snapshot, and create one private file.
/// No input is overwritten or deleted and no credential contents are printed.
pub fn migrate(relay_path: &Path, warp_path: &Path, out: &Path, ipv4_only: bool) -> Result<()> {
    let mut root = table(&read(relay_path)?)?;
    ensure!(!root.contains_key("warp"), "relay input already contains [warp]; use that file directly");
    let warp_text = read(warp_path)?;
    WarpConfig::from_toml(&warp_text, warp_path)?;
    let mut warp = warp_table(&table(&warp_text)?)?;
    inline_registration(&mut warp, warp_path)?;
    if ipv4_only {
        let relay = Config::from_toml(&read(relay_path)?)?;
        if let std::net::IpAddr::V6(ip) = relay.listen.ip() {
            ensure!(ip.is_unspecified(), "--ipv4-only requires an IPv4 listen address; update the relay input first");
            root.insert("listen".into(), toml::Value::String(format!("0.0.0.0:{}", relay.listen.port())));
        }
        warp.insert("ipv6_endpoint".into(), toml::Value::Boolean(false));
        let registration = warp
            .get_mut("registration")
            .and_then(toml::Value::as_table_mut)
            .context("missing inline WARP registration")?;
        for key in ["tunnel_ipv6", "ipv6", "endpoint_v6", "endpoint_h2_v6"] {
            registration.remove(key);
        }
        // Explicit endpoint/DNS overrides are validated below, never silently replaced.
    }
    root.insert("warp".into(), toml::Value::Table(warp));
    let text = toml::to_string_pretty(&root).map_err(|_| anyhow::anyhow!("cannot encode combined TOML"))?;
    Config::from_toml(&text)?;
    let validated = WarpConfig::from_toml(&text, out)?;
    if ipv4_only {
        ensure!(
            validated.endpoint.is_none_or(|endpoint| endpoint.is_ipv4())
                && validated.dns_servers().iter().all(std::net::SocketAddr::is_ipv4),
            "--ipv4-only requires IPv4 endpoint and DNS overrides; update the old WARP settings first"
        );
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(out).with_context(|| format!("creating new configuration {}", out.display()))?;
    if let Err(error) = file.write_all(text.as_bytes()).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(out);
        return Err(error).context("writing combined configuration");
    }
    println!("Created {}; keep this file private (mode 0600).", out.display());
    println!("Validate with: network-relay-cf-masque serve --config {} --check", out.display());
    Ok(())
}
