//! Rust HTTP CONNECT / CONNECT-UDP client and SOCKS5 proxy.
//!
//! All production sockets, TLS and QUIC are implemented in [`backend`].
//! The bounded internal bridge joins the protocol tasks to the Rust I/O tasks;
//! it has no platform networking dependency.
pub mod backend;
pub mod client;
mod limits;
pub mod native;
pub mod proto;
pub mod quic;
pub mod socks;
pub mod stream;
pub mod traffic;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize)]
pub struct Config {
    pub uri_template: String,
    pub username: String,
    pub password: String,
    pub server_name: Option<String>,
    #[serde(default = "automatic")]
    pub transport: String,
    #[serde(default = "default_probe")]
    pub probe_target: std::net::SocketAddr,
    pub mode: String,
    pub socks: Socks,
}
impl Config {
    /// Validate settings shared by the graphical application and headless mode.
    /// Port zero remains valid for local listeners so callers may request an
    /// ephemeral SOCKS port; a relay probe must name an actual destination port.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.mode == "socks", "only SOCKS mode is supported");
        anyhow::ensure!(
            matches!(self.transport.as_str(), "auto" | "h3" | "h2" | "http/1.1"),
            "unsupported relay transport"
        );
        anyhow::ensure!(
            !self.socks.listen.is_empty(),
            "at least one SOCKS listener is required"
        );
        anyhow::ensure!(
            self.probe_target.port() != 0,
            "relay probe destination port must be nonzero"
        );
        Ok(())
    }
}

fn default_probe() -> std::net::SocketAddr {
    "1.1.1.1:53".parse().expect("constant probe address")
}
fn automatic() -> String {
    "auto".into()
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Socks {
    pub listen: Vec<std::net::SocketAddr>,
}

#[cfg(test)]
mod config_tests {
    use super::*;
    fn valid() -> Config {
        Config {
            uri_template: "https://relay.test/.well-known/masque/udp/{target_host}/{target_port}/"
                .into(),
            username: "alice".into(),
            password: "disposable-test-password".into(),
            server_name: None,
            transport: "h3".into(),
            probe_target: default_probe(),
            mode: "socks".into(),
            socks: Socks {
                listen: vec!["127.0.0.1:0".parse().unwrap()],
            },
        }
    }
    #[test]
    fn invalid_modes_transports_and_listener_sets_are_rejected() {
        let mut config = valid();
        assert!(config.validate().is_ok());
        config.mode = "tun".into();
        assert!(config.validate().is_err());
        config = valid();
        config.transport = "h4".into();
        assert!(config.validate().is_err());
        config = valid();
        config.socks.listen.clear();
        assert!(config.validate().is_err());
        config = valid();
        config.probe_target.set_port(0);
        assert!(config.validate().is_err());
    }
}
