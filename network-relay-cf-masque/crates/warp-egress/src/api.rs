//! Reading existing WARP device registrations. Enrollment is deliberately
//! outside this crate: loading credentials never makes a control-plane request.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::prelude::*;
use serde::Deserialize;

/// Cloudflare's separate TCP endpoint, preserved from the pinned client.
pub const DEFAULT_H2_ENDPOINT_V4: &str = "162.159.198.2";

/// The pinned cf-masque registration format and usque's compatible aliases.
/// Access tokens and licenses are accepted for compatibility, but are never
/// used by the data plane.
#[derive(Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, alias = "id")]
    #[allow(dead_code)] // accepted registration metadata; never used by data plane
    pub device_id: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub access_token: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub license: String,
    pub private_key: String,
    #[serde(default)]
    pub endpoint_v4: String,
    #[serde(default)]
    pub endpoint_v6: String,
    #[serde(default)]
    pub endpoint_h2_v4: String,
    #[serde(default)]
    pub endpoint_h2_v6: String,
    #[serde(alias = "endpoint_pub_key")]
    pub endpoint_public_key: String,
    #[serde(alias = "ipv4")]
    pub tunnel_ipv4: String,
    #[serde(default, alias = "ipv6")]
    pub tunnel_ipv6: String,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registration").field("credentials", &"[REDACTED]").finish_non_exhaustive()
    }
}

impl Config {
    /// Load the named file only; no stdin, discovery, enrollment, or fallback.
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading WARP registration {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("loading WARP registration {}", path.display()))
    }

    fn parse(text: &str) -> Result<Self> {
        // serde's type errors may contain the rejected string. Retain location
        // information without exposing registration contents in an error chain.
        serde_json::from_str(text)
            .map_err(|e| anyhow::anyhow!("invalid WARP registration JSON at line {}, column {}", e.line(), e.column()))
    }

    /// The enrolled P-256 private key, with SEC1 converted to PKCS#8.
    pub fn private_key_der(&self) -> Result<Vec<u8>> {
        let der = BASE64_STANDARD
            .decode(self.private_key.trim())
            .map_err(|_| anyhow::anyhow!("private_key is not base64"))?;
        Ok(match der.get(..5) {
            Some([0x30, _, 0x02, 0x01, 0x01]) => sec1_to_pkcs8(&der),
            _ => der,
        })
    }

    /// The server's pinned SubjectPublicKeyInfo, DER.
    pub fn endpoint_spki(&self) -> Result<Vec<u8>> {
        pem_body(&self.endpoint_public_key).context("endpoint_public_key is not a PEM public key")
    }

    /// Select a numeric outer address without consulting the host resolver.
    pub fn endpoint(&self, h2: bool, ipv6: bool, port: u16) -> Result<SocketAddr> {
        let endpoint = match (h2, ipv6) {
            (false, false) => self.endpoint_v4.as_str(),
            (false, true) => self.endpoint_v6.as_str(),
            (true, false) if self.endpoint_h2_v4.is_empty() => DEFAULT_H2_ENDPOINT_V4,
            (true, false) => self.endpoint_h2_v4.as_str(),
            (true, true) if self.endpoint_h2_v6.is_empty() => {
                bail!("no HTTP/2 IPv6 endpoint is registered; set warp.endpoint or endpoint_h2_v6")
            }
            (true, true) => self.endpoint_h2_v6.as_str(),
        };
        if endpoint.trim().is_empty() {
            bail!("no endpoint is configured for the selected WARP transport and address family; set warp.endpoint or the matching registration endpoint");
        }
        let ip = parse_endpoint(endpoint)?;
        if ip.is_ipv6() != ipv6 {
            bail!("the selected registration endpoint has the wrong address family");
        }
        Ok(SocketAddr::new(ip, port))
    }

    pub fn addresses(&self) -> Result<Vec<IpAddr>> {
        let ipv4 = self.tunnel_ipv4.parse::<Ipv4Addr>().context("invalid tunnel_ipv4")?;
        anyhow::ensure!(
            !ipv4.is_unspecified() && !ipv4.is_multicast() && !ipv4.is_broadcast(),
            "tunnel_ipv4 must be a unicast source address"
        );
        let mut addresses = vec![IpAddr::V4(ipv4)];
        if !self.tunnel_ipv6.is_empty() {
            let ipv6 = self.tunnel_ipv6.parse::<Ipv6Addr>().context("invalid tunnel_ipv6")?;
            anyhow::ensure!(
                !ipv6.is_unspecified() && !ipv6.is_multicast() && ipv6.to_ipv4_mapped().is_none(),
                "tunnel_ipv6 must be an IPv6 unicast source address"
            );
            addresses.push(IpAddr::V6(ipv6));
        }
        Ok(addresses)
    }
}

/// Wrap the same SEC1 ECPrivateKey as the pinned client in PKCS#8, declaring
/// id-ecPublicKey and prime256v1 (RFC 5208 and RFC 5915).
fn sec1_to_pkcs8(sec1: &[u8]) -> Vec<u8> {
    fn tlv(tag: u8, value: &[u8], out: &mut Vec<u8>) {
        out.push(tag);
        match value.len() {
            n @ 0..=0x7f => out.push(n as u8),
            n @ 0x80..=0xff => out.extend_from_slice(&[0x81, n as u8]),
            n => out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
        }
        out.extend_from_slice(value);
    }
    const ALGORITHM: &[u8] = &[
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x03, 0x01, 0x07,
    ];
    let mut body = vec![0x02, 0x01, 0x00];
    body.extend_from_slice(ALGORITHM);
    tlv(0x04, sec1, &mut body);
    let mut out = Vec::with_capacity(body.len() + 4);
    tlv(0x30, &body, &mut out);
    out
}

fn pem_body(pem: &str) -> Result<Vec<u8>> {
    let body: String =
        pem.lines().map(str::trim).filter(|line| !line.is_empty() && !line.starts_with("-----")).collect();
    if body.is_empty() {
        bail!("no PEM body");
    }
    BASE64_STANDARD.decode(body).map_err(|_| anyhow::anyhow!("invalid PEM base64"))
}

fn parse_endpoint(endpoint: &str) -> Result<IpAddr> {
    if let Ok(addr) = endpoint.parse::<SocketAddr>() {
        return Ok(addr.ip());
    }
    endpoint
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .context("registration endpoint is not a numeric IP address")
}

/// Synthetic credentials for deterministic local transport fixtures only.
#[cfg(test)]
pub struct Keys {
    pub pkcs8_der: Vec<u8>,
    pub spki_der: Vec<u8>,
}

#[cfg(test)]
pub fn generate_keys() -> Result<Keys> {
    use rcgen::PublicKeyData;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    Ok(Keys { pkcs8_der: key.serialize_der(), spki_der: key.subject_public_key_info() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_endpoint_forms_and_h2_selection_stay_numeric() {
        for text in ["162.159.198.1", "162.159.198.1:0"] {
            assert_eq!(parse_endpoint(text).unwrap(), "162.159.198.1".parse::<IpAddr>().unwrap());
        }
        for text in ["2606:4700:103::1", "[2606:4700:103::1]", "[2606:4700:103::1]:0"] {
            assert_eq!(parse_endpoint(text).unwrap(), "2606:4700:103::1".parse::<IpAddr>().unwrap());
        }
        assert!(parse_endpoint("example.com").is_err());
        assert_eq!(Config::default().endpoint(true, false, 443).unwrap(), "162.159.198.2:443".parse().unwrap());
        assert!(Config::default().endpoint(true, true, 443).is_err());
    }

    #[test]
    fn usque_aliases_and_sec1_key_load() {
        let cfg = Config::parse(r#"{
            "id":"fixture-device", "access_token":"fixture-token", "license":"fixture-license",
            "private_key":"MHcCAQEEIN4aGJ6xCSDw3WLBic0tVEpJLQD72jyn9zgF4VmNUoukoAoGCCqGSM49AwEHoUQDQgAE4E4fTzjKFVHBH+T9TFDwkt7aBCXTzVg1WMLwwHL8XbYNilvjkFE6DgjBlMDuqsKOimEvTANZYVtTTiN+I07oOQ==",
            "endpoint_v4":"162.159.198.1", "endpoint_v6":"2606:4700:103::1",
            "endpoint_pub_key":"-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----\n",
            "ipv4":"172.16.0.2", "ipv6":"2606:4700:110:8000::1"
        }"#).unwrap();
        assert_eq!(cfg.device_id, "fixture-device");
        assert_eq!(cfg.access_token, "fixture-token");
        assert_eq!(cfg.license, "fixture-license");
        assert_eq!(cfg.addresses().unwrap().len(), 2);
        let pkcs8 = cfg.private_key_der().unwrap();
        rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
            &rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8.as_slice()),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        )
        .unwrap();
        assert_eq!(cfg.endpoint_spki().unwrap(), [1, 2, 3]);
        let rendered = format!("{cfg:?}");
        for secret in [&cfg.device_id, &cfg.access_token, &cfg.license, &cfg.private_key, &cfg.endpoint_public_key] {
            assert!(!rendered.contains(secret));
        }
        assert!(rendered.contains("REDACTED"));
    }

    #[test]
    fn pkcs8_is_preserved_and_parse_errors_do_not_expose_values() {
        let key = generate_keys().unwrap();
        let cfg = Config { private_key: BASE64_STANDARD.encode(&key.pkcs8_der), ..Config::default() };
        assert_eq!(cfg.private_key_der().unwrap(), key.pkcs8_der);
        let error = Config::parse(r#"{"access_token":["do-not-log-me"]}"#).unwrap_err();
        assert!(!format!("{error:#}").contains("do-not-log-me"));
    }

    #[test]
    fn ipv4_only_registration_omits_control_plane_metadata_and_ipv6_fields() {
        let cfg = Config::parse(
            r#"{
            "private_key":"AQID", "endpoint_public_key":"AQID", "tunnel_ipv4":"172.16.0.2"
        }"#,
        )
        .unwrap();
        assert!(cfg.device_id.is_empty() && cfg.access_token.is_empty() && cfg.license.is_empty());
        assert_eq!(cfg.addresses().unwrap(), ["172.16.0.2".parse::<IpAddr>().unwrap()]);
        assert_eq!(cfg.endpoint(true, false, 443).unwrap(), "162.159.198.2:443".parse().unwrap());
        assert!(cfg.endpoint(false, false, 443).is_err());
        assert!(cfg.endpoint(false, true, 443).is_err());
        assert!(cfg.endpoint(true, true, 443).is_err());
        let error = Config::parse(
            r#"{
            "private_key":"AQID", "endpoint_public_key":"AQID", "tunnel_ipv4":"172.16.0.2",
            "private_keey":"never-echo-this-secret"
        }"#,
        )
        .unwrap_err();
        assert!(!format!("{error:#}").contains("never-echo-this-secret"));
    }
}
