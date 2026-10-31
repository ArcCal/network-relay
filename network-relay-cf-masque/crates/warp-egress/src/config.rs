//! Explicit, numeric transport settings and an existing device registration.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Deserializer};
use x509_parser::prelude::FromDer;

use crate::api;
use crate::masque::{self, Auth, Options, Transport, Verify};

/// Settings are loaded from the `[warp]` table of the relay's one TOML
/// configuration file, with the registration inline in `[warp.registration]`.
#[derive(Clone)]
pub struct WarpConfig {
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
    registration: Box<api::Config>,
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
        Self::from_toml(&text).with_context(|| format!("loading WARP settings {}", path.display()))
    }

    /// Parse the `[warp]` table of a configuration file's text. Errors never
    /// include input excerpts or credential values.
    pub fn from_toml(text: &str) -> Result<Self> {
        let raw = parse_settings(text)?;
        let credentials = *raw.registration;
        let endpoint = raw.endpoint.as_deref().map(|value| parse_override(value, raw.port)).transpose()?;
        let port = raw.port.or_else(|| endpoint.map(|addr| addr.port())).unwrap_or(443);
        let config = Self {
            credentials: Arc::new(credentials),
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
        let addresses = self.addresses()?;
        ensure!(
            self.dns.iter().all(|server| addresses.iter().any(|own| own.is_ipv4() == server.is_ipv4())),
            "warp.dns contains a server whose address family has no configured tunnel address"
        );
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

    /// What the settings leave out that the operator should know about. None
    /// of it stops the egress from working.
    pub fn warnings(&self) -> Vec<String> {
        let missing: Vec<&str> = [
            ("tunnel_ipv6", self.credentials.tunnel_ipv6.trim().is_empty()),
            ("endpoint_v6", self.credentials.endpoint_v6.trim().is_empty()),
        ]
        .into_iter()
        .filter_map(|(name, missing)| missing.then_some(name))
        .collect();
        if missing.is_empty() {
            return Vec::new();
        }
        let mut warning = format!(
            "[warp.registration] has no {}; copy it from the WARP enrollment for IPv6 (for example \
             tunnel_ipv6 = \"2606:4700:110:88ca:7332:13e4:5a18:e3d9\" and endpoint_v6 = \"[2606:4700:103::2]:0\")",
            missing.join(" or ")
        );
        if missing.contains(&"tunnel_ipv6") {
            warning.push_str("; until then IPv6 destinations cannot be reached through WARP, only IPv4 ones");
        }
        if missing.contains(&"endpoint_v6") {
            warning.push_str("; until then the HTTP/3 tunnel cannot use an IPv6 WARP endpoint");
        }
        vec![warning]
    }
}

fn parse_settings(text: &str) -> Result<RawConfig> {
    // No deserializer diagnostics include the input text.
    let mut value: toml::Value = toml::from_str(text).map_err(|_| anyhow::anyhow!("invalid WARP settings TOML"))?;
    let warp = value
        .as_table_mut()
        .and_then(|table| table.remove("warp"))
        .context("missing [warp]; add the WARP settings and [warp.registration] to the configuration file")?;
    warp.try_into::<RawConfig>().map_err(|_| {
        anyhow::anyhow!(
            "invalid [warp] settings; check field names, explicit h2/h3 transport and the inline \
             [warp.registration] credentials"
        )
    })
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

    /// A complete inline registration, as in the configuration file.
    fn registration() -> toml::Table {
        let keys = api::generate_keys().unwrap();
        let spki = BASE64_STANDARD.encode(&keys.spki_der);
        let mut registration = toml::Table::new();
        for (name, value) in [
            ("device_id", "fixture-device".to_string()),
            ("access_token", "fixture-token".into()),
            ("license", "fixture-license".into()),
            ("private_key", BASE64_STANDARD.encode(&keys.pkcs8_der)),
            ("endpoint_v4", "162.159.198.1:0".into()),
            ("endpoint_v6", "[2606:4700:103::1]:0".into()),
            ("endpoint_public_key", format!("-----BEGIN PUBLIC KEY-----\n{spki}\n-----END PUBLIC KEY-----\n")),
            ("tunnel_ipv4", "172.16.0.2".into()),
            ("tunnel_ipv6", "2606:4700:110:8000::1".into()),
        ] {
            registration.insert(name.into(), value.into());
        }
        registration
    }

    /// A configuration file with `[warp]`: `transport`, the registration
    /// fields `keep`, and then `extra` (TOML lines in `[warp]`).
    fn settings(transport: &str, registration: &toml::Table, keep: &[&str], extra: &str) -> toml::Value {
        let mut kept = toml::Table::new();
        for name in keep {
            kept.insert((*name).into(), registration[*name].clone());
        }
        let mut warp: toml::Table = toml::from_str(extra).unwrap();
        warp.insert("transport".into(), transport.into());
        warp.insert("registration".into(), kept.into());
        let mut root: toml::Table =
            toml::from_str("listen='[::]:443'\n[tls]\ncert='certificate.pem'\nkey='key.pem'\n").unwrap();
        root.insert("warp".into(), warp.into());
        root.into()
    }

    const REQUIRED: [&str; 3] = ["private_key", "endpoint_public_key", "tunnel_ipv4"];
    const ALL: [&str; 9] = [
        "device_id",
        "access_token",
        "license",
        "private_key",
        "endpoint_v4",
        "endpoint_v6",
        "endpoint_public_key",
        "tunnel_ipv4",
        "tunnel_ipv6",
    ];

    fn load(settings: &toml::Value) -> Result<WarpConfig> {
        WarpConfig::from_toml(&toml::to_string(settings).unwrap())
    }

    #[test]
    fn transport_and_registration_are_required_and_dns_is_numeric() {
        let r = registration();
        for settings in [
            "[warp]\ntransport='h3'",
            "[warp]\nregistration='registration.json'\ntransport='h3'",
            "[warp]\nregistration={}\ntransport='h3'",
            "transport='h3'\n[registration]\ntunnel_ipv4='172.16.0.2'",
        ] {
            assert!(parse_settings(settings).is_err(), "{settings}");
        }
        assert!(load(&settings("auto", &r, &ALL, "")).is_err());
        assert!(load(&settings("h3", &r, &ALL, "dns=['dns.example:53']")).is_err());
        assert!(parse_override("endpoint.example:443", None).is_err());
        assert!(parse_override("162.159.198.1:0", None).is_err());
        assert_eq!(parse_override("162.159.198.1", None).unwrap().port(), 443);
    }

    #[test]
    fn registration_port_zero_and_pinned_defaults() {
        let r = registration();
        let config = load(&settings("h3", &r, &ALL, "")).unwrap();
        assert_eq!(config.options().unwrap().endpoint, "162.159.198.1:443".parse().unwrap());
        assert_eq!(config.dns_servers(), ["1.1.1.1:53".parse().unwrap()]);
        assert_eq!((config.keepalive_secs, config.idle_timeout_secs), (15, 30));
        assert!(config.warnings().is_empty());
        let rendered = format!("{config:?}");
        for secret in ["fixture-device", "fixture-token", "fixture-license", "BEGIN PUBLIC KEY"] {
            assert!(!rendered.contains(secret));
        }
        let h2 = load(&settings("h2", &r, &ALL, "")).unwrap();
        assert_eq!(h2.options().unwrap().endpoint, "162.159.198.2:443".parse().unwrap());
        let overridden = load(&settings("h3", &r, &ALL, "endpoint='[::1]:8443'\ndns=['[::1]:5353']")).unwrap();
        assert_eq!(overridden.options().unwrap().endpoint, "[::1]:8443".parse().unwrap());
        assert_eq!(overridden.dns_servers(), ["[::1]:5353".parse().unwrap()]);
    }

    #[test]
    fn validation_rejects_invalid_keys_pins_and_runtime_settings() {
        let r = registration();
        for fields in [
            "port=0",
            "keepalive_secs=0",
            "idle_timeout_secs=15",
            "dns=[]",
            "uri='http://cloudflareaccess.com/'",
            "endpoint='relay.invalid:443'",
        ] {
            assert!(load(&settings("h3", &r, &ALL, fields)).is_err(), "{fields}");
        }
        for (field, invalid) in [
            ("private_key", "AQID"),
            ("endpoint_public_key", "-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----"),
            ("tunnel_ipv4", "not-an-address"),
        ] {
            let mut r = r.clone();
            r.insert(field.into(), invalid.into());
            assert!(load(&settings("h3", &r, &ALL, "")).is_err(), "{field}");
        }
    }

    #[test]
    fn ipv4_only_registrations_work_for_h2_and_h3_with_a_warning() {
        let r = registration();
        for transport in ["h2", "h3"] {
            let config = load(&settings(transport, &r, &[&REQUIRED[..], &["endpoint_v4"]].concat(), "")).unwrap();
            assert_eq!(config.addresses().unwrap(), ["172.16.0.2".parse::<IpAddr>().unwrap()]);
            assert!(!config.ipv6_endpoint);
            assert_eq!(
                config.options().unwrap().transport,
                if transport == "h2" { Transport::H2 } else { Transport::H3 }
            );
            assert_eq!(
                config.options().unwrap().endpoint,
                if transport == "h2" { "162.159.198.2:443" } else { "162.159.198.1:443" }.parse().unwrap()
            );
            let warnings = config.warnings();
            assert_eq!(warnings.len(), 1);
            assert!(warnings[0].contains("tunnel_ipv6 or endpoint_v6"), "{}", warnings[0]);
            assert!(warnings[0].contains("IPv6 destinations cannot be reached"));
        }
        let only_tunnel = load(&settings("h2", &r, &[&REQUIRED[..], &["tunnel_ipv6"]].concat(), "")).unwrap();
        let warnings = only_tunnel.warnings();
        assert!(warnings[0].contains("no endpoint_v6") && !warnings[0].contains("destinations cannot"));
        let only_endpoint = load(&settings("h2", &r, &[&REQUIRED[..], &["endpoint_v6"]].concat(), "")).unwrap();
        assert!(only_endpoint.warnings()[0].contains("no tunnel_ipv6;"));
        assert!(!format!("{:?}", only_endpoint.warnings()).contains("fixture"));
    }

    #[test]
    fn endpoint_requirements_are_explicit_and_do_not_fall_back() {
        let r = registration();
        // H3 needs endpoint_v4 or an explicit endpoint.
        assert!(load(&settings("h3", &r, &REQUIRED, "")).is_err());
        let explicit = load(&settings("h3", &r, &REQUIRED, "endpoint='192.0.2.1:8443'")).unwrap();
        assert_eq!(explicit.options().unwrap().endpoint, "192.0.2.1:8443".parse().unwrap());
        for transport in ["h2", "h3"] {
            assert!(load(&settings(transport, &r, &REQUIRED, "ipv6_endpoint=true")).is_err());
            let field = if transport == "h2" { "endpoint_h2_v6" } else { "endpoint_v6" };
            let mut r = r.clone();
            r.insert("endpoint_h2_v6".into(), "[2001:db8::1]:0".into());
            r.insert("endpoint_v6".into(), "[2001:db8::1]:0".into());
            let config =
                load(&settings(transport, &r, &[&REQUIRED[..], &[field]].concat(), "ipv6_endpoint=true")).unwrap();
            assert!(config.options().unwrap().endpoint.is_ipv6());
            assert!(config.addresses().unwrap().iter().all(IpAddr::is_ipv4));
        }
    }

    #[test]
    fn settings_reject_missing_credentials_unknown_fields_and_secret_type_errors() {
        let r = registration();
        for field in REQUIRED {
            let keep: Vec<&str> = ALL.iter().copied().filter(|f| *f != field).collect();
            assert!(load(&settings("h2", &r, &keep, "")).is_err(), "missing {field} was accepted");
        }
        let mut with_secret = r.clone();
        with_secret.insert("private_keey".into(), "never-echo-this-secret".into());
        let error = load(&settings("h2", &with_secret, &[&ALL[..], &["private_keey"]].concat(), "")).unwrap_err();
        assert!(!format!("{error:#}").contains("never-echo-this-secret"));
        let error = load(&settings("h2", &r, &ALL, "tranpsort='never-echo-this-secret'")).unwrap_err();
        assert!(!format!("{error:#}").contains("never-echo-this-secret"));
        for field in ["private_key", "endpoint_public_key", "tunnel_ipv4", "tunnel_ipv6", "access_token", "device_id"] {
            let mut r = r.clone();
            r.insert(field.into(), toml::Value::Array(vec!["never-echo-this-secret".into()]));
            let error = load(&settings("h2", &r, &ALL, "")).unwrap_err();
            assert!(!format!("{error:#}").contains("never-echo-this-secret"));
        }
        let error = WarpConfig::from_toml("[warp]\nprivate_key = 'never-echo-this-secret\n").unwrap_err();
        assert!(!format!("{error:#}").contains("never-echo-this-secret"));
    }

    #[test]
    fn ipv6_and_metadata_are_optional_but_validated_when_present() {
        let r = registration();
        let config = load(&settings("h2", &r, &ALL, "")).unwrap();
        assert_eq!(config.addresses().unwrap().len(), 2);
        assert!(!format!("{config:?}").contains("fixture"));
        for invalid in ["not-an-address", "::", "ff02::1", "::ffff:192.0.2.1"] {
            let mut r = r.clone();
            r.insert("tunnel_ipv6".into(), invalid.into());
            assert!(load(&settings("h2", &r, &ALL, "")).is_err(), "{invalid}");
        }
    }

    #[test]
    fn dns_servers_require_a_configured_tunnel_address_of_their_family() {
        let r = registration();
        for servers in ["dns=['[2606:4700:4700::1111]:53']", "dns=['1.1.1.1:53', '[2606:4700:4700::1111]:53']"] {
            let error = load(&settings("h2", &r, &REQUIRED, servers)).unwrap_err();
            assert!(format!("{error:#}").contains("address family has no configured tunnel address"));
            assert!(load(&settings("h2", &r, &[&REQUIRED[..], &["tunnel_ipv6"]].concat(), servers)).is_ok());
        }
    }
}
