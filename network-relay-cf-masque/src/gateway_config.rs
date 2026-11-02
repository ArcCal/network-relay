//! The one configuration file: network-relay's settings, as network-relay
//! reads them, plus a `[warp]` table with the WARP settings and the inline
//! registration.

use std::path::Path;

use anyhow::{ensure, Context, Result};
use network_relay::config::Config;
use warp_masque_egress::WarpConfig;

pub struct GatewayConfig {
    pub relay: Config,
    pub warp: WarpConfig,
    /// The `[warp]` table as written, to notice changes on SIGHUP.
    pub warp_settings: toml::Value,
}

impl GatewayConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading configuration {}", path.display()))?;
        Self::from_toml(&text).with_context(|| format!("loading configuration {}", path.display()))
    }

    pub fn from_toml(text: &str) -> Result<Self> {
        let mut relay = relay_settings(text)?;
        let warp = WarpConfig::from_toml(text)?;
        // Every tunnel also takes a socket of the WARP stack. Unless the file
        // sets relay.max_tunnels, its memory-based default is kept to seven
        // eighths of the stack's socket limit, which leaves the rest for DNS
        // and for connections still opening or closing.
        if relay.relay.max_tunnels.is_none() {
            let sockets = warp.socket_limit();
            relay.relay.max_tunnels = Some(relay.relay.max_tunnels().min(sockets - sockets / 8));
        }
        let mut document: toml::Table = toml::from_str(text).map_err(|_| anyhow::anyhow!("invalid TOML"))?;
        let warp_settings = document.remove("warp").context("missing [warp]")?;
        Ok(Self { relay, warp, warp_settings })
    }
}

/// network-relay's settings: every table but `[warp]`, as strictly checked
/// as network-relay checks them. Errors never quote the file, which holds
/// the WARP private key.
pub fn relay_settings(text: &str) -> Result<Config> {
    let mut document: toml::Value = toml::from_str(text).map_err(|error: toml::de::Error| match error.span() {
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
    })?;
    let table = document.as_table_mut().context("the configuration must be a TOML table")?;
    ensure!(table.remove("warp").is_none_or(|warp| warp.is_table()), "[warp] must be a table");
    let config: Config = document.try_into().map_err(|_| {
        anyhow::anyhow!("invalid relay settings: an unknown field or a value of the wrong type outside [warp]")
    })?;
    config.validate()?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TLS: &str = "[tls]\ncert = '/fullchain.pem'\nkey = '/privkey.pem'\n";

    #[test]
    fn relay_settings_are_network_relays_without_the_warp_table() {
        let text =
            format!("listen = '0.0.0.0:8443'\n{TLS}[warp]\ntransport = 'h2'\n[warp.registration]\nprivate_key = 'x'\n");
        let config = relay_settings(&text).unwrap();
        assert_eq!(config.listen, "0.0.0.0:8443".parse().unwrap());
        assert_eq!(config.tls.cert, std::path::PathBuf::from("/fullchain.pem"));
        // Unknown fields are still refused outside [warp].
        assert!(relay_settings(&format!("unexpected = 1\n{text}")).is_err());
        assert!(relay_settings(&format!("{text}\n[relay]\nunexpected = 1\n")).is_err());
        assert!(relay_settings(&format!("warp = 1\n{TLS}")).is_err(), "[warp] must be a table");
        assert!(relay_settings(TLS).is_ok());
        let error = GatewayConfig::from_toml(TLS).err().expect("[warp] is required: one file holds everything");
        assert!(format!("{error:#}").contains("missing [warp]"), "{error:#}");
    }

    /// A configuration file with a valid inline registration and `relay`
    /// and `warp` lines added to those tables.
    fn with_registration(relay: &str, warp: &str) -> String {
        use base64::prelude::*;
        use rcgen::PublicKeyData;
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let spki = BASE64_STANDARD.encode(key.subject_public_key_info());
        format!(
            "listen = '0.0.0.0:8443'\n{TLS}[relay]\n{relay}\n[warp]\ntransport = 'h2'\n{warp}\n[warp.registration]\n\
             private_key = '{}'\nendpoint_public_key = '''-----BEGIN PUBLIC KEY-----\n{spki}\n-----END PUBLIC KEY-----\n'''\n\
             tunnel_ipv4 = '172.16.0.2'\n",
            BASE64_STANDARD.encode(key.serialize_der()),
        )
    }

    #[test]
    fn the_default_tunnel_limit_leaves_sockets_for_dns_and_closing_connections() {
        let config = GatewayConfig::from_toml(&with_registration("", "max_sockets = 128")).unwrap();
        assert_eq!(config.warp.socket_limit(), 128);
        let expected = network_relay::limits::default_max_tunnels(network_relay::limits::total_memory()).min(112);
        assert_eq!(config.relay.relay.max_tunnels, Some(expected), "seven eighths of 128 sockets at most");
        let explicit = GatewayConfig::from_toml(&with_registration("max_tunnels = 500", "max_sockets = 128")).unwrap();
        assert_eq!(explicit.relay.relay.max_tunnels, Some(500), "an explicit setting is used as given");
        let derived = GatewayConfig::from_toml(&with_registration("", "")).unwrap();
        let sockets = derived.warp.socket_limit();
        assert!(derived.relay.relay.max_tunnels.unwrap() <= sockets - sockets / 8);
        for out_of_range in ["max_sockets = 63", "max_sockets = 4097"] {
            let error = GatewayConfig::from_toml(&with_registration("", out_of_range)).err().expect(out_of_range);
            assert!(format!("{error:#}").contains("warp.max_sockets"), "{error:#}");
        }
    }

    #[test]
    fn errors_do_not_quote_the_file() {
        let secret = "DO_NOT_PRINT_THIS_PRIVATE_KEY";
        let samples = [
            // Syntax errors normally quote the offending line.
            format!("{TLS}[warp]\nprivate_key = '{secret}' trailing\n"),
            // Type errors normally quote the value.
            format!("listen = '{secret}'\n{TLS}[warp]\nprivate_key='{secret}'\n"),
            // Unknown field names can themselves be a secret.
            format!("'{secret}' = 1\n{TLS}[warp]\nprivate_key='{secret}'\n"),
        ];
        for text in samples {
            let error = GatewayConfig::from_toml(&text).err().expect("invalid");
            for shown in [format!("{error:#}"), format!("{error:?}")] {
                assert!(!shown.contains(secret), "{shown}");
            }
        }
        let error = relay_settings(&format!("{TLS}[warp]\nprivate_key = '{secret}' trailing\n")).unwrap_err();
        assert!(error.to_string().contains("line 5, column"), "{error}");
    }
}
