//! The server's configuration file.

use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use ipnet::IpNet;
use serde::Deserialize;

use crate::auth;
use crate::proto::{UriTemplate, DEFAULT_UDP_PATH_TEMPLATE};

/// Default location of the configuration file.
pub const DEFAULT_PATH: &str = "/etc/network-relay/relay.toml";

/// Destinations clients may not reach unless the configuration says
/// otherwise: this host, private and shared address space, link-local,
/// multicast, reserved and documentation ranges. A relay on the public
/// internet should only reach the public internet (RFC 9298 §7).
pub const DEFAULT_BLOCKED: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/127",
    "::ffff:0:0/96",
    "64:ff9b:1::/48",
    "100::/64",
    "2001:db8::/32",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address for UDP (HTTP/3) and TCP (HTTP/2 and HTTP/1.1).
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Directory for plain-text log files, in addition to stdout.
    pub log_dir: Option<PathBuf>,
    pub tls: Tls,
    /// The website unauthenticated visitors see. Without it they get 404.
    pub web: Option<Web>,
    #[serde(default)]
    pub relay: Relay,
    #[serde(default)]
    pub debug: Debug,
    #[serde(default, rename = "user")]
    pub users: Vec<UserEntry>,
}

/// The server certificate, for example from Let's Encrypt.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    /// Certificate chain, leaf first (`fullchain.pem`).
    pub cert: PathBuf,
    /// Private key (`privkey.pem`).
    pub key: PathBuf,
    /// Reload the files every this many days (1-7). Without it, reload
    /// every day at 03:00 in the system time zone.
    pub reload_interval_days: Option<u32>,
}

/// Longest allowed certificate reload interval.
pub const MAX_RELOAD_INTERVAL_DAYS: u32 = 7;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web {
    /// Directory with the site; must contain `index.html`.
    pub root: PathBuf,
    /// Extra response headers, such as a Content-Security-Policy.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

/// What clients may reach, and resource limits.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relay {
    /// Path and query of the CONNECT-UDP URI template (RFC 9298 §2); must
    /// contain `{target_host}` and `{target_port}`. Clients are configured
    /// with `https://<host><this>`.
    #[serde(default = "default_udp_template")]
    pub udp_template: String,
    /// Destinations clients may not reach, checked against every address a
    /// name resolves to.
    #[serde(default = "default_blocked")]
    pub blocked_destinations: Vec<IpNet>,
    /// Destination ports clients may not reach, for TCP and UDP. Port 25
    /// (SMTP) is blocked by default so the relay cannot send spam.
    #[serde(default = "default_blocked_ports")]
    pub blocked_ports: Vec<u16>,
    /// Give up connecting to a TCP destination after this many seconds.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
    /// Close a UDP flow after this many seconds without a datagram in
    /// either direction.
    #[serde(default = "default_udp_idle_timeout")]
    pub udp_idle_timeout_secs: u64,
    /// Most TCP connections and UDP flows relayed at once, over all users.
    #[serde(default = "default_max_tunnels")]
    pub max_tunnels: usize,
}

impl Default for Relay {
    fn default() -> Self {
        Self {
            udp_template: default_udp_template(),
            blocked_destinations: default_blocked(),
            blocked_ports: default_blocked_ports(),
            connect_timeout_secs: default_connect_timeout(),
            udp_idle_timeout_secs: default_udp_idle_timeout(),
            max_tunnels: default_max_tunnels(),
        }
    }
}

impl Relay {
    pub fn udp_template(&self) -> Result<UriTemplate> {
        let t = UriTemplate::parse_path(&self.udp_template).context("relay.udp_template")?;
        for var in ["target_host", "target_port"] {
            ensure!(t.has_variable(var), "relay.udp_template must contain {{{var}}} (RFC 9298 §2)");
        }
        Ok(t)
    }

    pub fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.connect_timeout_secs)
    }

    pub fn udp_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.udp_idle_timeout_secs)
    }
}

/// Settings for finding out what clients send.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Debug {
    /// Log every proxy request (CONNECT or Upgrade) with its headers, with
    /// credentials masked.
    #[serde(default)]
    pub log_requests: bool,
}

/// A user allowed to use the relay.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserEntry {
    pub name: String,
    /// Argon2id hash in PHC format, as printed by `network-relay passwd`.
    pub password_hash: String,
}

fn default_listen() -> SocketAddr {
    "[::]:443".parse().unwrap()
}

fn default_udp_template() -> String {
    DEFAULT_UDP_PATH_TEMPLATE.into()
}

fn default_blocked() -> Vec<IpNet> {
    DEFAULT_BLOCKED.iter().map(|s| s.parse().unwrap()).collect()
}

fn default_blocked_ports() -> Vec<u16> {
    vec![25]
}

fn default_connect_timeout() -> u64 {
    10
}

fn default_udp_idle_timeout() -> u64 {
    300
}

fn default_max_tunnels() -> usize {
    20_000
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let config: Self = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        config.validate().with_context(|| format!("checking {}", path.display()))?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(dir) = &self.log_dir {
            ensure!(dir.is_absolute(), "log_dir must be an absolute path, got {}", dir.display());
        }
        if let Some(days) = self.tls.reload_interval_days {
            ensure!(
                (1..=MAX_RELOAD_INTERVAL_DAYS).contains(&days),
                "tls.reload_interval_days must be between 1 and {MAX_RELOAD_INTERVAL_DAYS}, got {days}"
            );
        }
        let r = &self.relay;
        r.udp_template()?;
        ensure!(!r.blocked_ports.contains(&0), "relay.blocked_ports: 0 is not a port");
        ensure!(
            (1..=120).contains(&r.connect_timeout_secs),
            "relay.connect_timeout_secs must be between 1 and 120, got {}",
            r.connect_timeout_secs
        );
        // RFC 4787 REQ-5: UDP mappings live at least 2 minutes.
        ensure!(
            (120..=3600).contains(&r.udp_idle_timeout_secs),
            "relay.udp_idle_timeout_secs must be between 120 and 3600, got {}",
            r.udp_idle_timeout_secs
        );
        ensure!(
            (1..=tokio::sync::Semaphore::MAX_PERMITS).contains(&r.max_tunnels),
            "relay.max_tunnels is outside the supported range"
        );
        let mut names = HashSet::new();
        for u in &self.users {
            auth::validate_user_name(&u.name).with_context(|| format!("user name {:?}", u.name))?;
            auth::validate_hash(&u.password_hash).with_context(|| format!("user {}", u.name))?;
            if !names.insert(u.name.clone()) {
                bail!("user {} appears twice", u.name);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY";

    fn parse(extra: &str) -> Result<Config> {
        let text = format!("[tls]\ncert = \"/fullchain.pem\"\nkey = \"/privkey.pem\"\n{extra}\n");
        let c: Config = toml::from_str(&text)?;
        c.validate()?;
        Ok(c)
    }

    #[test]
    fn minimal_config_uses_defaults() {
        let c = parse("").unwrap();
        assert_eq!(c.listen, "[::]:443".parse().unwrap());
        assert!(c.web.is_none() && c.log_dir.is_none() && c.users.is_empty());
        assert!(!c.debug.log_requests);
        assert_eq!(c.relay.udp_template, DEFAULT_UDP_PATH_TEMPLATE);
        assert_eq!(c.relay.blocked_destinations.len(), DEFAULT_BLOCKED.len());
        assert_eq!(c.relay.blocked_ports, [25]);
        assert_eq!(c.relay.connect_timeout(), Duration::from_secs(10));
        assert_eq!(c.relay.udp_idle_timeout(), Duration::from_secs(300));
    }

    #[test]
    fn relay_settings_are_checked() {
        assert!(parse("[relay]\nudp_template = \"/udp?h={target_host}&p={target_port}\"").is_ok());
        assert!(parse("[relay]\nudp_template = \"/udp/{target_host}/\"").is_err(), "needs the port");
        assert!(parse("[relay]\nudp_template = \"udp/{target_host}/{target_port}\"").is_err(), "not a path");
        assert!(parse("[relay]\nblocked_ports = [0]").is_err());
        assert!(parse("[relay]\nblocked_ports = []\nblocked_destinations = []").is_ok());
        assert!(parse("[relay]\nconnect_timeout_secs = 0").is_err());
        assert!(parse("[relay]\nudp_idle_timeout_secs = 30").is_err(), "RFC 4787 minimum");
        assert!(parse("[relay]\nmax_tunnels = 0").is_err());
        assert!(parse(&format!("[relay]\nmax_tunnels = {}", tokio::sync::Semaphore::MAX_PERMITS + 1)).is_err());
        assert!(parse("[relay]\nunknown = 1").is_err());
        assert!(parse("log_dir = \"logs\"").is_err(), "relative log_dir");
    }

    #[test]
    fn reload_interval_is_one_to_seven_days() {
        for ok in ["1", "7"] {
            let c = format!("[tls]\ncert = \"/c\"\nkey = \"/k\"\nreload_interval_days = {ok}");
            assert!(toml::from_str::<Config>(&c).unwrap().validate().is_ok(), "{ok}");
        }
        for bad in ["0", "8"] {
            let c = format!("[tls]\ncert = \"/c\"\nkey = \"/k\"\nreload_interval_days = {bad}");
            assert!(toml::from_str::<Config>(&c).unwrap().validate().is_err(), "{bad}");
        }
    }

    #[test]
    fn users_are_validated() {
        let ok = format!("[[user]]\nname = \"iphone\"\npassword_hash = \"{HASH}\"");
        assert_eq!(parse(&ok).unwrap().users.len(), 1);
        assert!(parse(&ok.replace(HASH, "secret")).is_err(), "plain text is not a hash");
        assert!(parse(&format!("{ok}\n{ok}")).is_err(), "same name twice");
        assert!(parse(&ok.replace("iphone", "a:b")).is_err());
    }

    #[test]
    fn web_section_is_optional() {
        let c =
            parse("[web]\nroot = \"/var/www/site\"\n[web.headers]\nContent-Security-Policy = \"default-src 'self'\"")
                .unwrap();
        let web = c.web.unwrap();
        assert_eq!(web.root, PathBuf::from("/var/www/site"));
        assert_eq!(web.headers.len(), 1);
    }

    #[test]
    fn deploy_example_is_valid() {
        let text = include_str!("../deploy/relay.example.toml");
        let c: Config = toml::from_str(text).unwrap();
        c.validate().unwrap();
        assert!(c.web.is_some());
    }
}
