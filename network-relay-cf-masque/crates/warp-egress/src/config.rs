//! Explicit, numeric transport settings and an existing device registration.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Deserializer};
use x509_parser::prelude::FromDer;

use crate::api;
use crate::masque::{self, Auth, Options, Transport, Verify};

/// Settings are loaded from `[warp]` in a separate TOML file. Relative
/// registration paths are relative to that configuration file's directory.
#[derive(Clone)]
pub struct WarpConfig {
    pub registration: PathBuf,
    pub transport: Transport,
    pub endpoint: Option<SocketAddr>,
    pub port: u16,
    pub ipv6_endpoint: bool,
    pub sni: String,
    pub uri: String,
    pub dns: Vec<SocketAddr>,
    pub keepalive_secs: u64,
    pub idle_timeout_secs: u64,
    pub fwmark: Option<u32>,
    credentials: Arc<api::Config>,
}

impl fmt::Debug for WarpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WarpConfig")
            .field("registration", &self.registration)
            .field("transport", &self.transport)
            .field("endpoint", &self.endpoint)
            .field("port", &self.port)
            .field("ipv6_endpoint", &self.ipv6_endpoint)
            .field("sni", &self.sni)
            .field("uri", &self.uri)
            .field("dns", &self.dns)
            .field("keepalive_secs", &self.keepalive_secs)
            .field("idle_timeout_secs", &self.idle_timeout_secs)
            .field("fwmark", &self.fwmark)
            .field("credentials", &"[REDACTED]")
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    registration: PathBuf,
    transport: Transport,
    endpoint: Option<String>,
    port: Option<u16>,
    #[serde(default)]
    ipv6_endpoint: bool,
    #[serde(default = "default_sni")]
    sni: String,
    #[serde(default = "default_uri")]
    uri: String,
    #[serde(default = "default_dns")]
    dns: Vec<SocketAddr>,
    #[serde(default = "default_keepalive")]
    keepalive_secs: u64,
    #[serde(default = "default_idle_timeout")]
    idle_timeout_secs: u64,
    fwmark: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WrappedConfig {
    warp: RawConfig,
}

impl<'de> Deserialize<'de> for Transport {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match String::deserialize(deserializer)?.as_str() {
            "h2" => Ok(Self::H2),
            "h3" => Ok(Self::H3),
            _ => Err(serde::de::Error::custom("warp.transport must be h2 or h3")),
        }
    }
}

impl WarpConfig {
    /// Load and validate settings and credentials without opening a socket.
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading WARP settings {}", path.display()))?;
        let raw = parse_settings(&text).with_context(|| format!("loading WARP settings {}", path.display()))?;
        ensure!(!raw.registration.as_os_str().is_empty(), "warp.registration is required");
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let registration =
            if raw.registration.is_absolute() { raw.registration } else { parent.join(raw.registration) };
        ensure!(!registration.as_os_str().is_empty(), "warp.registration is required");
        let endpoint = raw.endpoint.as_deref().map(|value| parse_override(value, raw.port)).transpose()?;
        let port = raw.port.or_else(|| endpoint.map(|addr| addr.port())).unwrap_or(443);
        let config = Self {
            credentials: Arc::new(api::Config::load(&registration)?),
            registration,
            transport: raw.transport,
            endpoint,
            port,
            ipv6_endpoint: raw.ipv6_endpoint,
            sni: raw.sni,
            uri: raw.uri,
            dns: raw.dns.into_iter().map(|server| SocketAddr::new(server.ip().to_canonical(), server.port())).collect(),
            keepalive_secs: raw.keepalive_secs,
            idle_timeout_secs: raw.idle_timeout_secs,
            fwmark: raw.fwmark,
        };
        config.validate()?;
        Ok(config)
    }

    /// Validate mTLS credentials, the endpoint pin, assigned addresses and
    /// numeric transport settings. Validation never registers a device.
    pub fn validate(&self) -> Result<()> {
        ensure!(self.port != 0, "warp.port must be nonzero");
        ensure!(self.keepalive_secs > 0, "warp.keepalive_secs must be nonzero");
        ensure!(self.idle_timeout_secs > self.keepalive_secs, "warp.idle_timeout_secs must exceed warp.keepalive_secs");
        ensure!(self.idle_timeout_secs <= 86_400, "warp.idle_timeout_secs must be at most 86400");
        ensure!(!self.dns.is_empty(), "warp.dns must contain a numeric DNS socket address");
        ensure!(
            self.dns.iter().all(|addr| addr.port() != 0 && !addr.ip().is_unspecified() && !addr.ip().is_multicast()),
            "warp.dns must contain nonzero ports and unicast addresses"
        );
        rustls::pki_types::ServerName::try_from(self.sni.clone()).context("invalid warp.sni")?;
        let uri = self.uri.parse::<http::Uri>().context("invalid warp.uri")?;
        ensure!(
            uri.scheme_str() == Some("https") && uri.authority().is_some(),
            "warp.uri must be an absolute HTTPS URI"
        );
        self.selected_endpoint()?;
        self.addresses()?;
        let pkcs8 = self.credentials.private_key_der()?;
        rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
            &rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8.as_slice()),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        )
        .context("registration private_key is not a valid P-256 private key")?;
        let spki = self.credentials.endpoint_spki()?;
        let (remaining, _) = x509_parser::x509::SubjectPublicKeyInfo::from_der(&spki)
            .map_err(|_| anyhow::anyhow!("registration endpoint_public_key is not valid SPKI DER"))?;
        ensure!(remaining.is_empty(), "registration endpoint_public_key has trailing DER bytes");
        Ok(())
    }

    fn selected_endpoint(&self) -> Result<SocketAddr> {
        let endpoint = match self.endpoint {
            Some(addr) => SocketAddr::new(addr.ip(), self.port),
            None => self.credentials.endpoint(self.transport == Transport::H2, self.ipv6_endpoint, self.port)?,
        };
        ensure!(
            !endpoint.ip().is_unspecified() && !endpoint.ip().is_multicast(),
            "warp endpoint must be a unicast IP address"
        );
        Ok(SocketAddr::new(endpoint.ip().to_canonical(), endpoint.port()))
    }

    pub(crate) fn options(&self) -> Result<Options> {
        Ok(Options {
            endpoint: self.selected_endpoint()?,
            sni: self.sni.clone(),
            uri: self.uri.clone(),
            protocol: masque::DEFAULT_PROTOCOL,
            verify: Verify::PinnedKey(self.credentials.endpoint_spki()?),
            auth: Auth::DeviceKey { pkcs8_der: self.credentials.private_key_der()? },
            fwmark: self.fwmark,
            keepalive: Duration::from_secs(self.keepalive_secs),
            idle_timeout: Duration::from_secs(self.idle_timeout_secs),
            transport: self.transport,
            rfc: false,
        })
    }

    pub fn addresses(&self) -> Result<Vec<IpAddr>> {
        self.credentials.addresses()
    }

    pub fn dns_servers(&self) -> &[SocketAddr] {
        &self.dns
    }
}

fn parse_settings(text: &str) -> Result<RawConfig> {
    // Support a dedicated plain settings file as well as the documented
    // `[warp]` wrapper. No deserializer diagnostics include the input text.
    let value: toml::Value = toml::from_str(text).map_err(|_| anyhow::anyhow!("invalid WARP settings TOML"))?;
    if value.get("warp").is_some() {
        value.try_into::<WrappedConfig>().map(|wrapped| wrapped.warp).map_err(|_| {
            anyhow::anyhow!("invalid [warp] settings; registration and explicit h2/h3 transport are required")
        })
    } else {
        value.try_into::<RawConfig>().map_err(|_| {
            anyhow::anyhow!("invalid WARP settings; registration and explicit h2/h3 transport are required")
        })
    }
}

fn parse_override(value: &str, port: Option<u16>) -> Result<SocketAddr> {
    if let Ok(endpoint) = value.parse::<SocketAddr>() {
        let selected_port = port.unwrap_or(endpoint.port());
        ensure!(selected_port != 0, "warp.endpoint port must be nonzero");
        return Ok(SocketAddr::new(endpoint.ip(), selected_port));
    }
    let ip = value.parse::<IpAddr>().context("warp.endpoint must be a numeric IP address or socket address")?;
    Ok(SocketAddr::new(ip, port.unwrap_or(443)))
}

fn default_sni() -> String {
    masque::DEFAULT_SNI.to_owned()
}
fn default_uri() -> String {
    masque::DEFAULT_URI.to_owned()
}
fn default_dns() -> Vec<SocketAddr> {
    vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)]
}
fn default_keepalive() -> u64 {
    15
}
fn default_idle_timeout() -> u64 {
    30
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::*;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.build/test-fixtures");
            std::fs::create_dir_all(&base).unwrap();
            let path = base.join(format!("warp-settings-{}-{}", std::process::id(), rand::random::<u64>()));
            std::fs::create_dir(&path).unwrap();
            let keys = api::generate_keys().unwrap();
            let json = serde_json::json!({
                "device_id":"fixture-device", "access_token":"fixture-token", "license":"fixture-license",
                "private_key":BASE64_STANDARD.encode(&keys.pkcs8_der),
                "endpoint_v4":"162.159.198.1:0", "endpoint_v6":"[2606:4700:103::1]:0",
                "endpoint_public_key":format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", BASE64_STANDARD.encode(&keys.spki_der)),
                "tunnel_ipv4":"172.16.0.2", "tunnel_ipv6":"2606:4700:110:8000::1"
            });
            std::fs::write(path.join("registration.json"), serde_json::to_vec(&json).unwrap()).unwrap();
            Self(path)
        }
        fn load(&self, settings: &str) -> Result<WarpConfig> {
            let path = self.0.join("warp.toml");
            std::fs::write(&path, settings).unwrap();
            WarpConfig::load(&path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn transport_and_registration_are_required_and_dns_is_numeric() {
        for settings in [
            "[warp]\nregistration='registration.json'",
            "[warp]\ntransport='h3'",
            "[warp]\nregistration='registration.json'\ntransport='auto'",
            "[warp]\nregistration='registration.json'\ntransport='h3'\ndns=['dns.example:53']",
        ] {
            assert!(parse_settings(settings).is_err());
        }
        assert!(parse_override("endpoint.example:443", None).is_err());
        assert!(parse_override("162.159.198.1:0", None).is_err());
        assert_eq!(parse_override("162.159.198.1", None).unwrap().port(), 443);
    }

    #[test]
    fn config_relative_registration_port_zero_and_pinned_defaults() {
        let fixture = Fixture::new();
        let config = fixture.load("[warp]\nregistration='registration.json'\ntransport='h3'").unwrap();
        assert_eq!(config.registration, fixture.0.join("registration.json"));
        assert_eq!(config.options().unwrap().endpoint, "162.159.198.1:443".parse().unwrap());
        assert_eq!(config.dns_servers(), ["1.1.1.1:53".parse().unwrap()]);
        assert_eq!((config.keepalive_secs, config.idle_timeout_secs), (15, 30));
        config.validate().unwrap();
        let rendered = format!("{config:?}");
        for secret in ["fixture-device", "fixture-token", "fixture-license", "BEGIN PUBLIC KEY"] {
            assert!(!rendered.contains(secret));
        }
        let h2 = fixture.load("registration='registration.json'\ntransport='h2'").unwrap();
        assert_eq!(h2.options().unwrap().endpoint, "162.159.198.2:443".parse().unwrap());
        let overridden = fixture
            .load("[warp]\nregistration='registration.json'\ntransport='h3'\nendpoint='[::1]:8443'\ndns=['[::1]:5353']")
            .unwrap();
        assert_eq!(overridden.options().unwrap().endpoint, "[::1]:8443".parse().unwrap());
        assert_eq!(overridden.dns_servers(), ["[::1]:5353".parse().unwrap()]);
    }

    #[test]
    fn validation_rejects_invalid_keys_pins_and_runtime_settings() {
        let fixture = Fixture::new();
        for fields in [
            "port=0",
            "keepalive_secs=0",
            "idle_timeout_secs=15",
            "dns=[]",
            "uri='http://cloudflareaccess.com/'",
            "endpoint='relay.invalid:443'",
        ] {
            assert!(fixture
                .load(&format!("[warp]\nregistration='registration.json'\ntransport='h3'\n{fields}"))
                .is_err());
        }
        let path = fixture.0.join("registration.json");
        let original = std::fs::read_to_string(&path).unwrap();
        for (field, invalid) in [
            ("private_key", "AQID"),
            ("endpoint_public_key", "-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----"),
            ("tunnel_ipv4", "not-an-address"),
        ] {
            let mut registration: serde_json::Value = serde_json::from_str(&original).unwrap();
            registration[field] = invalid.into();
            std::fs::write(&path, serde_json::to_string(&registration).unwrap()).unwrap();
            assert!(fixture.load("[warp]\nregistration='registration.json'\ntransport='h3'").is_err());
        }
    }
}
