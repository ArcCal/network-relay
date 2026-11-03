//! The one configuration file: network-relay's settings, as network-relay
//! reads them, plus a `[vless]` table for the downstream VLESS server.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use network_relay::config::Config;
use serde::Deserialize;

use crate::vless::UserId;

/// Resolvers asked through the VLESS server when `[vless] dns_servers` is
/// not set.
pub const DEFAULT_DNS_SERVERS: [&str; 2] = ["1.1.1.1:53", "8.8.8.8:53"];

pub struct FileConfig {
    pub relay: Config,
    pub vless: VlessConfig,
    /// The `[vless]` table as written, to notice changes on SIGHUP.
    pub vless_settings: toml::Value,
}

impl FileConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading configuration {}", path.display()))?;
        Self::from_toml(&text).with_context(|| format!("loading configuration {}", path.display()))
    }

    pub fn from_toml(text: &str) -> Result<Self> {
        let relay = relay_settings(text)?;
        let mut document = parse(text)?;
        let table = document.as_table_mut().context("the configuration must be a TOML table")?;
        let vless_settings = table.remove("vless").context("missing [vless]")?;
        let raw: RawVless = vless_settings
            .clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid [vless]: an unknown field or a value of the wrong type"))?;
        Ok(Self { relay, vless: VlessConfig::from_raw(raw)?, vless_settings })
    }
}

/// Parses TOML without ever quoting the file, which holds the VLESS user ID.
fn parse(text: &str) -> Result<toml::Value> {
    toml::from_str(text).map_err(|error: toml::de::Error| match error.span() {
        Some(span) => {
            let mut offset = span.start.min(text.len());
            while !text.is_char_boundary(offset) {
                offset -= 1;
            }
            let before = &text[..offset];
            let line = before.bytes().filter(|byte| *byte == b'\n').count() + 1;
            let column = before.rsplit('\n').next().unwrap_or("").chars().count() + 1;
            anyhow::anyhow!("invalid TOML at line {line}, column {column}")
        }
        None => anyhow::anyhow!("invalid TOML"),
    })
}

/// network-relay's settings: every table but `[vless]`, as strictly checked
/// as network-relay checks them.
pub fn relay_settings(text: &str) -> Result<Config> {
    let mut document = parse(text)?;
    let table = document.as_table_mut().context("the configuration must be a TOML table")?;
    ensure!(table.remove("vless").is_none_or(|vless| vless.is_table()), "[vless] must be a table");
    let config: Config = document.try_into().map_err(|_| {
        anyhow::anyhow!("invalid relay settings: an unknown field or a value of the wrong type outside [vless]")
    })?;
    config.validate()?;
    Ok(config)
}

/// `[vless]` as written.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVless {
    server: String,
    uuid: String,
    transport: String,
    security: String,
    path: String,
    host: Option<String>,
    encryption: Option<String>,
    flow: Option<String>,
    dns_servers: Option<Vec<String>>,
    ip_preference: Option<String>,
}

/// Which address families of a name are used, and in which order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpPreference {
    Ipv4First,
    Ipv6First,
    Ipv4Only,
    Ipv6Only,
}

impl IpPreference {
    /// Orders (and filters) looked-up addresses.
    pub fn apply(self, addrs: &mut Vec<IpAddr>) {
        match self {
            Self::Ipv4Only => addrs.retain(IpAddr::is_ipv4),
            Self::Ipv6Only => addrs.retain(IpAddr::is_ipv6),
            Self::Ipv4First => addrs.sort_by_key(|a| a.is_ipv6()),
            Self::Ipv6First => addrs.sort_by_key(|a| a.is_ipv4()),
        }
    }

    pub fn wants_ipv4(self) -> bool {
        self != Self::Ipv6Only
    }

    pub fn wants_ipv6(self) -> bool {
        self != Self::Ipv4Only
    }
}

/// The checked downstream VLESS settings.
#[derive(Clone)]
pub struct VlessConfig {
    /// The VLESS server: a host name or IP address, and a port.
    pub server_host: String,
    pub server_port: u16,
    pub user_id: UserId,
    /// The WebSocket request path, including any query.
    pub path: String,
    /// The WebSocket request's Host header (an authority).
    pub host_header: String,
    pub dns_servers: Vec<SocketAddr>,
    pub ip_preference: IpPreference,
}

impl std::fmt::Debug for VlessConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessConfig")
            .field("server", &format_args!("{}:{}", self.server_host, self.server_port))
            .field("host_header", &self.host_header)
            .field("dns_servers", &self.dns_servers)
            .field("ip_preference", &self.ip_preference)
            .finish_non_exhaustive()
    }
}

impl VlessConfig {
    fn from_raw(raw: RawVless) -> Result<Self> {
        ensure!(
            raw.transport == "ws",
            "vless.transport: only \"ws\" (WebSocket) is supported; TCP, gRPC, HTTP/2, HTTPUpgrade, XHTTP and mKCP are not"
        );
        ensure!(
            raw.security == "none",
            "vless.security: only \"none\" (a plaintext WebSocket) is supported; TLS and REALITY are not"
        );
        if let Some(encryption) = &raw.encryption {
            ensure!(encryption == "none", "vless.encryption: only \"none\" is supported (VLESS encryption is not)");
        }
        if let Some(flow) = &raw.flow {
            ensure!(flow.is_empty(), "vless.flow: no flow is supported (XTLS Vision needs TLS); remove it or set \"\"");
        }
        let user_id = UserId::parse(&raw.uuid).context(
            "vless.uuid: not a UUID, nor a string of 1 to 30 bytes (which Xray-core maps to a UUID the same way)",
        )?;
        let (server_host, server_port) = split_authority(&raw.server).context("vless.server: expected host:port")?;
        ensure!(server_port != 0, "vless.server: the port must not be 0");
        ensure!(valid_path(&raw.path), "vless.path: must start with \"/\" and hold only visible ASCII characters");
        let host_header = match raw.host {
            Some(host) => {
                ensure!(
                    split_authority(&host).is_some() || valid_host(&host),
                    "vless.host: expected a host name or IP address, optionally with :port"
                );
                host
            }
            // As a browser would send it: the port only when not 80.
            None => {
                let host = if server_host.contains(':') { format!("[{server_host}]") } else { server_host.clone() };
                if server_port == 80 {
                    host
                } else {
                    format!("{host}:{server_port}")
                }
            }
        };
        let dns_servers = raw
            .dns_servers
            .unwrap_or_else(|| DEFAULT_DNS_SERVERS.iter().map(|s| s.to_string()).collect())
            .iter()
            .map(|s| {
                s.parse::<SocketAddr>()
                    .ok()
                    .filter(|a| a.port() != 0 && !a.ip().is_unspecified())
                    .with_context(|| format!("vless.dns_servers: {s:?} is not an IP address and port"))
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(!dns_servers.is_empty(), "vless.dns_servers: needs at least one server");
        ensure!(dns_servers.len() <= 8, "vless.dns_servers: at most 8 servers");
        let ip_preference = match raw.ip_preference.as_deref().unwrap_or("ipv4_first") {
            "ipv4_first" => IpPreference::Ipv4First,
            "ipv6_first" => IpPreference::Ipv6First,
            "ipv4_only" => IpPreference::Ipv4Only,
            "ipv6_only" => IpPreference::Ipv6Only,
            _ => bail!("vless.ip_preference: expected ipv4_first, ipv6_first, ipv4_only or ipv6_only"),
        };
        Ok(Self { server_host, server_port, user_id, path: raw.path, host_header, dns_servers, ip_preference })
    }

    /// The URL tungstenite builds the upgrade request from: its authority is
    /// the Host header, its path and query the request target.
    pub fn websocket_url(&self) -> String {
        format!("ws://{}{}", self.host_header, self.path)
    }
}

/// `host:port`, with an IPv6 address in brackets.
fn split_authority(text: &str) -> Option<(String, u16)> {
    let (host, port) = text.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    let host = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(v6) => v6.parse::<std::net::Ipv6Addr>().ok()?.to_string(),
        None => host.to_string(),
    };
    (host.parse::<std::net::Ipv6Addr>().is_ok() || valid_host(&host)).then_some((host, port))
}

/// A DNS name of letters, digits, hyphens, underscores and dots, or an IPv4
/// address.
fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

fn valid_path(path: &str) -> bool {
    path.starts_with('/') && path.len() <= 2048 && path.bytes().all(|b| b.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TLS: &str = "[tls]\ncert = '/fullchain.pem'\nkey = '/privkey.pem'\n";
    const UUID: &str = "b4e4fad1-c320-428e-92dc-f8f6944a7dec";

    fn file(vless: &str) -> String {
        format!(
            "listen = '0.0.0.0:443'\n{TLS}[vless]\nserver = 'vless.example.net:80'\nuuid = '{UUID}'\n\
             transport = 'ws'\nsecurity = 'none'\npath = '/J2kV4jxviMDXceRQYVXiv6YwCc462T6P0Dayx5JYR8R'\n{vless}"
        )
    }

    #[test]
    fn the_documented_combination_is_accepted() {
        let config = FileConfig::from_toml(&file("")).unwrap();
        let vless = &config.vless;
        assert_eq!((vless.server_host.as_str(), vless.server_port), ("vless.example.net", 80));
        assert_eq!(vless.host_header, "vless.example.net");
        assert_eq!(vless.websocket_url(), "ws://vless.example.net/J2kV4jxviMDXceRQYVXiv6YwCc462T6P0Dayx5JYR8R");
        assert_eq!(vless.user_id, UserId::parse(UUID).unwrap());
        assert_eq!(vless.dns_servers, ["1.1.1.1:53".parse().unwrap(), "8.8.8.8:53".parse().unwrap()]);
        assert_eq!(vless.ip_preference, IpPreference::Ipv4First);
        let with_host =
            FileConfig::from_toml(&file("host = 'cdn.example.org'\nencryption = 'none'\nflow = ''\n")).unwrap();
        assert_eq!(with_host.vless.host_header, "cdn.example.org");
        let v6 = FileConfig::from_toml(&file("").replace("vless.example.net:80", "[2001:db8::5]:8080")).unwrap();
        assert_eq!(v6.vless.server_host, "2001:db8::5");
        assert_eq!(v6.vless.host_header, "[2001:db8::5]:8080");
    }

    #[test]
    fn unsupported_settings_are_refused_not_reinterpreted() {
        for (change, field) in [
            ("transport = 'ws'", "transport = 'tcp'"),
            ("transport = 'ws'", "transport = 'grpc'"),
            ("security = 'none'", "security = 'tls'"),
            ("security = 'none'", "security = 'reality'"),
        ] {
            let error = FileConfig::from_toml(&file("").replace(change, field)).err().expect(field);
            assert!(format!("{error:#}").contains(field.split(' ').next().unwrap()), "{error:#}");
        }
        for extra in [
            "flow = 'xtls-rprx-vision'",
            "encryption = 'mlkem768x25519plus'",
            "ip_preference = 'both'",
            "dns_servers = []",
            "dns_servers = ['dns.google:53']",
            "dns_servers = ['0.0.0.0:53']",
            "host = 'bad host'",
            "fingerprint = 'chrome'",
            "sni = 'example.com'",
        ] {
            assert!(FileConfig::from_toml(&file(extra)).is_err(), "{extra}");
        }
        assert!(FileConfig::from_toml(&file("").replace("path = '/", "path = '")).is_err(), "path without /");
        assert!(FileConfig::from_toml(&file("").replace(":80'", "'")).is_err(), "server without port");
        assert!(FileConfig::from_toml(TLS).is_err(), "[vless] is required");
        assert!(relay_settings(&format!("unexpected = 1\n{}", file(""))).is_err(), "relay fields stay strict");
    }

    #[test]
    fn errors_do_not_quote_the_file() {
        let secret = "DO-NOT-PRINT-a1b2c3d4e5f6";
        for text in [
            file("").replace(UUID, &format!("{secret}' trailing '")),
            file("").replace(&format!("'{UUID}'"), &format!("['{secret}']")),
            file(&format!("'{secret}' = 1\n")),
            file("").replace(UUID, &"x".repeat(40)).replace("xxxx", secret),
        ] {
            let error = FileConfig::from_toml(&text).err().expect("invalid");
            for shown in [format!("{error:#}"), format!("{error:?}")] {
                assert!(!shown.contains(secret), "{shown}");
            }
        }
        let shown = format!("{:?}", FileConfig::from_toml(&file("")).unwrap().vless);
        assert!(!shown.contains("b4e4fad1") && !shown.contains("J2kV4"), "{shown}");
    }
}
