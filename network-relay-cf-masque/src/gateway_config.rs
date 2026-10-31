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
        let relay = relay_settings(text)?;
        let warp = WarpConfig::from_toml(text)?;
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
