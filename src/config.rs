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
/// multicast, reserved, benchmarking, documentation and other ranges that
/// the IANA special-purpose registries mark as not globally reachable. A
/// relay on the public internet should only reach the public internet
/// (RFC 9298 §7). IPv6 forms that carry an IPv4 address (NAT64, 6to4,
/// Teredo) are checked by the IPv4 address they carry; the relay's own
/// addresses are blocked separately (`relay.block_own_addresses`).
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
    "192.88.99.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/127",
    "::ffff:0:0/96",
    "64:ff9b:1::/48",
    "100::/64",
    "100:0:0:1::/64",
    "2001:2::/48",
    "2001:10::/28",
    "2001:20::/28",
    "2001:db8::/32",
    "3fff::/20",
    "5f00::/16",
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
    /// Ask TLS clients for a certificate (optional for them), so users can
    /// authenticate with `certificate_sha256` instead of a password. Off by
    /// default: a website that asks for client certificates is unusual and
    /// can make browsers offer the user a certificate to choose.
    #[serde(default)]
    pub client_certificates: bool,
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
    /// Without it, sized from this machine's memory (1-20000).
    pub max_tunnels: Option<usize>,
    /// Most TCP connections and UDP flows relayed at once for one user.
    #[serde(default = "default_max_tunnels_per_user")]
    pub max_tunnels_per_user: usize,
    /// Payload bytes per second one user may move, both directions and all
    /// tunnels together; 0 is unlimited. TCP waits, UDP drops the excess.
    #[serde(default)]
    pub max_bytes_per_second_per_user: u64,
    /// UDP packets per second one user may relay, both directions together;
    /// 0 is unlimited.
    #[serde(default)]
    pub max_udp_packets_per_second_per_user: u64,
    /// Most client connections (TCP and QUIC) open at once. Without it,
    /// sized from this machine's memory (256-16384).
    pub max_connections: Option<usize>,
    /// Most client connections open at once from one IPv4 address or IPv6
    /// /64.
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: usize,
    /// Close a client connection after this many seconds without an open
    /// request. Connections that never authenticated get at most 30.
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    /// Also block every address of this machine's network interfaces, which
    /// the default list cannot know (a connection to the host's own public
    /// address stays on the host, past cloud firewalls).
    #[serde(default = "default_true")]
    pub block_own_addresses: bool,
}

impl Default for Relay {
    fn default() -> Self {
        Self {
            udp_template: default_udp_template(),
            blocked_destinations: default_blocked(),
            blocked_ports: default_blocked_ports(),
            connect_timeout_secs: default_connect_timeout(),
            udp_idle_timeout_secs: default_udp_idle_timeout(),
            max_tunnels: None,
            max_tunnels_per_user: default_max_tunnels_per_user(),
            max_bytes_per_second_per_user: 0,
            max_udp_packets_per_second_per_user: 0,
            max_connections: None,
            max_connections_per_ip: default_max_connections_per_ip(),
            idle_timeout_secs: default_idle_timeout(),
            block_own_addresses: true,
        }
    }
}

impl Relay {
    pub fn udp_template(&self) -> Result<UriTemplate> {
        let t = UriTemplate::parse_path(&self.udp_template).context("relay.udp_template")?;
        for var in ["target_host", "target_port"] {
            ensure!(t.has_variable(var), "relay.udp_template must contain {{{var}}} (RFC 9298 §2)");
        }
        t.check_round_trip().context("relay.udp_template")?;
        Ok(t)
    }

    pub fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.connect_timeout_secs)
    }

    pub fn udp_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.udp_idle_timeout_secs)
    }

    /// `max_tunnels`, or the default for this machine's memory.
    pub fn max_tunnels(&self) -> usize {
        self.max_tunnels.unwrap_or_else(|| crate::limits::default_max_tunnels(crate::limits::total_memory()))
    }

    /// `max_connections`, or the default for this machine's memory.
    pub fn max_connections(&self) -> usize {
        self.max_connections.unwrap_or_else(|| crate::limits::default_max_connections(crate::limits::total_memory()))
    }

    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs)
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
    /// Password hash in PHC format, as printed by `network-relay passwd`.
    #[serde(default)]
    pub password_hash: Option<String>,
    /// SHA-256 fingerprint of the user's client certificate, as printed by
    /// `network-relay identity`. Needs `[tls] client_certificates = true`.
    #[serde(default)]
    pub certificate_sha256: Option<String>,
    /// The account stops working at this time (RFC 3339, for example
    /// `2027-01-31T00:00:00Z`); open tunnels are closed then.
    #[serde(default, deserialize_with = "time_or_string")]
    pub expires: Option<String>,
}

impl UserEntry {
    /// A user with a password hash only.
    pub fn with_password(name: &str, password_hash: &str) -> Self {
        Self { name: name.into(), password_hash: Some(password_hash.into()), certificate_sha256: None, expires: None }
    }
}

/// Accepts a TOML date-time as well as a string.
fn time_or_string<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Option<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Time {
        Text(String),
        Toml(toml::value::Datetime),
    }
    Ok(Option::<Time>::deserialize(d)?.map(|t| match t {
        Time::Text(s) => s,
        Time::Toml(t) => t.to_string(),
    }))
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

fn default_max_tunnels_per_user() -> usize {
    512
}

fn default_max_connections_per_ip() -> usize {
    64
}

fn default_idle_timeout() -> u64 {
    300
}

fn default_true() -> bool {
    true
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
        if let Some(n) = r.max_tunnels {
            ensure!(
                (1..=tokio::sync::Semaphore::MAX_PERMITS).contains(&n),
                "relay.max_tunnels is outside the supported range"
            );
        }
        ensure!(r.max_tunnels_per_user >= 1, "relay.max_tunnels_per_user must be at least 1");
        ensure!(
            r.max_bytes_per_second_per_user <= 1 << 40 && r.max_udp_packets_per_second_per_user <= 1 << 30,
            "relay per-user traffic limits are outside the supported range"
        );
        ensure!(
            r.max_connections != Some(0) && r.max_connections_per_ip >= 1,
            "relay.max_connections and relay.max_connections_per_ip must be at least 1"
        );
        ensure!(
            (30..=3600).contains(&r.idle_timeout_secs),
            "relay.idle_timeout_secs must be between 30 and 3600, got {}",
            r.idle_timeout_secs
        );
        let mut names = HashSet::new();
        let mut certificates = HashSet::new();
        for u in &self.users {
            auth::validate_user_name(&u.name).with_context(|| format!("user name {:?}", u.name))?;
            auth::validate_entry(u).with_context(|| format!("user {}", u.name))?;
            if !names.insert(u.name.clone()) {
                bail!("user {} appears twice", u.name);
            }
            if let Some(c) = &u.certificate_sha256 {
                ensure!(
                    self.tls.client_certificates,
                    "user {} has a certificate_sha256, which needs [tls] client_certificates = true",
                    u.name
                );
                ensure!(certificates.insert(auth::parse_fingerprint(c)?), "user {}: certificate used twice", u.name);
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
        assert!(c.relay.max_tunnels.is_none() && (1..=20_000).contains(&c.relay.max_tunnels()));
        assert_eq!(c.relay.max_tunnels_per_user, 512);
        assert_eq!((c.relay.max_bytes_per_second_per_user, c.relay.max_udp_packets_per_second_per_user), (0, 0));
        assert!(c.relay.max_connections.is_none() && (256..=16_384).contains(&c.relay.max_connections()));
        assert_eq!(c.relay.max_connections_per_ip, 64);
        assert_eq!(c.relay.idle_timeout(), Duration::from_secs(300));
        assert!(c.relay.block_own_addresses && !c.tls.client_certificates);
    }

    #[test]
    fn limits_are_checked() {
        assert_eq!(parse("[relay]\nmax_tunnels = 7").unwrap().relay.max_tunnels(), 7);
        assert!(parse("[relay]\nmax_tunnels_per_user = 0").is_err());
        assert!(parse("[relay]\nmax_connections_per_ip = 0").is_err());
        assert!(parse("[relay]\nmax_connections = 0").is_err());
        assert_eq!(parse("[relay]\nmax_connections = 100000").unwrap().relay.max_connections(), 100_000);
        assert!(parse("[relay]\nidle_timeout_secs = 5").is_err());
        assert!(
            parse("[relay]\nmax_bytes_per_second_per_user = 10000\nmax_udp_packets_per_second_per_user = 100").is_ok()
        );
    }

    #[test]
    fn relay_settings_are_checked() {
        assert!(parse("[relay]\nudp_template = \"/udp?h={target_host}&p={target_port}\"").is_ok());
        assert!(parse("[relay]\nudp_template = \"/udp/{target_host}/\"").is_err(), "needs the port");
        assert!(parse("[relay]\nudp_template = \"/udp?{target_host}&p={target_port}\"").is_err(), "unmatchable");
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
        let expiring = format!("{ok}\nexpires = 2027-01-31T00:00:00Z");
        assert_eq!(parse(&expiring).unwrap().users[0].expires.as_deref(), Some("2027-01-31T00:00:00Z"));
        assert!(parse(&format!("{ok}\nexpires = \"2027-01-31T00:00:00+08:00\"")).is_ok());
        assert!(parse(&format!("{ok}\nexpires = \"soon\"")).is_err());
        let fp = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let cert = format!("[[user]]\nname = \"ipad\"\ncertificate_sha256 = \"{fp}\"");
        assert!(parse(&cert).is_err(), "needs client_certificates");
        let tls = "[tls]\ncert = \"/c\"\nkey = \"/k\"\nclient_certificates = true\n";
        let c: Config = toml::from_str(&format!("{tls}{cert}")).unwrap();
        c.validate().unwrap();
        assert!(c.users[0].password_hash.is_none());
        let twice = format!("{tls}{cert}\n{}", cert.replace("ipad", "ipad2"));
        assert!(toml::from_str::<Config>(&twice).unwrap().validate().is_err(), "one certificate, two users");
        assert!(parse("[[user]]\nname = \"none\"").is_err(), "a user needs a credential");
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
        let mut listed = c.relay.blocked_destinations.clone();
        let mut defaults = default_blocked();
        listed.sort();
        defaults.sort();
        assert_eq!(listed, defaults, "the example shows the defaults");
    }
}
