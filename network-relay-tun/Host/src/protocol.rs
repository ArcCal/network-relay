//! Credential-free, bounded requests for the privileged network broker.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const MAX_REQUEST: usize = 4096;
pub const CONTROL_REVISION: u32 = 2;

#[derive(Debug, thiserror::Error)]
#[error("no usable physical path to the selected relay address")]
pub struct EndpointUnavailable;

#[derive(Debug, thiserror::Error)]
#[error("system capture changed")]
pub struct CaptureChanged;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub endpoints: Vec<IpAddr>,
    pub resolvers: Vec<IpAddr>,
    pub mtu: u16,
    #[serde(default = "default_port")]
    pub socks_port: u16,
}
fn default_port() -> u16 {
    1080
}
impl Plan {
    pub fn validate(&self) -> Result<()> {
        ensure!((1..=8).contains(&self.endpoints.len()), "expected 1 to 8 relay endpoints");
        ensure!((1..=4).contains(&self.resolvers.len()), "expected 1 to 4 DNS resolvers");
        ensure!(self.socks_port != 0, "invalid SOCKS port");
        ensure!((1280..=9000).contains(&self.mtu), "unsupported MTU");
        for ip in self.endpoints.iter().chain(&self.resolvers) {
            ensure!(!ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback(), "invalid network endpoint");
            match ip {
                IpAddr::V4(ip) => ensure!(!ip.is_broadcast() && !ip.is_link_local(), "unsupported scoped endpoint"),
                IpAddr::V6(ip) => {
                    ensure!(!ip.is_unicast_link_local(), "unsupported scoped endpoint");
                    ensure!(ip.to_ipv4_mapped().is_none(), "use canonical IPv4 address");
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Prepare { plan: Plan },
    Activate { lease: String },
    Stop { lease: String },
    Refresh { lease: String },
    Status,
    Recover,
}

pub fn decode(bytes: &[u8]) -> Result<Request> {
    ensure!(bytes.len() <= MAX_REQUEST, "request exceeds size limit");
    // Parser diagnostics can quote input. Never reflect untrusted fields.
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("invalid broker request"))?;
    let object = value.as_object().ok_or_else(|| anyhow::anyhow!("invalid broker request"))?;
    let valid_keys = match object.get("operation").and_then(|v| v.as_str()) {
        Some("status" | "recover") => object.len() == 1,
        Some("prepare") => object.len() == 2 && object.contains_key("plan"),
        Some("activate" | "stop" | "refresh") => object.len() == 2 && object.contains_key("lease"),
        _ => false,
    };
    ensure!(valid_keys, "invalid broker request");
    let request: Request = serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("invalid broker request"))?;
    if let Request::Prepare { plan } = &request {
        plan.validate()?;
    }
    match &request {
        Request::Activate { lease } | Request::Stop { lease } | Request::Refresh { lease } => {
            ensure!(lease.len() == 64 && lease.bytes().all(|b| b.is_ascii_hexdigit()), "invalid lease");
        }
        _ => {}
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_credentials_commands_paths_and_claimed_identity() {
        for value in [
            r#"{"operation":"status","password":"secret"}"#,
            r#"{"operation":"status","owner":501}"#,
            r#"{"operation":"recover","path":"/etc/resolv.conf"}"#,
            r#"{"operation":"exec","command":"id"}"#,
            r#"{"operation":"prepare","plan":{"endpoints":["192.0.2.1"],"resolvers":["1.1.1.1"],"mtu":1500,"password":"secret"}}"#,
        ] {
            let error = decode(value.as_bytes()).unwrap_err().to_string();
            assert!(!error.contains("secret"));
        }
        assert!(decode(&vec![b' '; MAX_REQUEST + 1]).is_err());
    }
    #[test]
    fn validates_dual_stack_plan_and_rejects_scoped_or_ambiguous_addresses() {
        let mut plan = Plan {
            endpoints: vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
            resolvers: vec!["1.1.1.1".parse().unwrap()],
            mtu: 1500,
            socks_port: 1080,
        };
        plan.validate().unwrap();
        for invalid in
            ["0.0.0.0", "127.0.0.1", "255.255.255.255", "224.0.0.1", "::", "::1", "fe80::1", "::ffff:127.0.0.1"]
        {
            plan.endpoints = vec![invalid.parse().unwrap()];
            assert!(plan.validate().is_err(), "{invalid}");
        }
    }
}
