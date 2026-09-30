//! `network-relay profile`: writes a configuration profile (`.mobileconfig`)
//! that sets up the relay on an iPhone, iPad or Mac.
//!
//! The profile holds one `com.apple.relay.managed` payload (iOS 17+,
//! macOS 14+; installable by hand, no supervision needed). Its relay entry
//! names the server by URI template (RFC 9298 §2) for HTTP/3 and HTTP/2, and
//! carries the user's credentials in `AdditionalHTTPHeaderFields`, which the
//! device sends with every CONNECT request.

use anyhow::{ensure, Result};

use crate::auth::basic_authorization;
use crate::proto::{UriTemplate, DEFAULT_UDP_PATH_TEMPLATE};

/// Reverse-DNS prefix of the payload identifiers.
const IDENTIFIER_PREFIX: &str = "com.github.arccal.network-relay";

#[derive(Debug, Clone)]
pub struct ProfileOptions {
    /// The relay's host name, as in its certificate.
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    /// Path and query of the CONNECT-UDP template.
    pub udp_template: String,
    /// Only these domains and their subdomains use the relay; empty means
    /// all traffic.
    pub match_domains: Vec<String>,
    /// These domains and their subdomains never use the relay.
    pub excluded_domains: Vec<String>,
    /// Name shown in Settings; defaults to the host.
    pub name: Option<String>,
    /// Offer HTTP/3 (QUIC) and HTTP/2; at least one.
    pub http3: bool,
    pub http2: bool,
}

impl ProfileOptions {
    pub fn new(host: &str, user: &str, password: &str) -> Self {
        Self {
            host: host.to_string(),
            port: 443,
            user: user.to_string(),
            password: password.to_string(),
            udp_template: DEFAULT_UDP_PATH_TEMPLATE.to_string(),
            match_domains: Vec::new(),
            excluded_domains: Vec::new(),
            name: None,
            http3: true,
            http2: true,
        }
    }

    /// The URI template the device is configured with.
    pub fn relay_url(&self) -> String {
        let port = if self.port == 443 { String::new() } else { format!(":{}", self.port) };
        format!("https://{}{port}{}", self.host, self.udp_template)
    }
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

/// A random (version 4) UUID in the upper-case form profiles use.
fn uuid() -> String {
    let mut b = [0u8; 16];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b).expect("system RNG");
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02X}")).collect();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

fn check_domain(d: &str) -> Result<()> {
    ensure!(
        !d.is_empty()
            && d.len() <= 253
            && d.split('.').all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
        "{d:?} is not a domain name"
    );
    Ok(())
}

fn string_array(key: &str, values: &[String], indent: &str) -> String {
    if values.is_empty() {
        return String::new();
    }
    let mut out = format!("{indent}<key>{key}</key>\n{indent}<array>\n");
    for v in values {
        out.push_str(&format!("{indent}  <string>{}</string>\n", escape(&v.to_ascii_lowercase())));
    }
    out.push_str(&format!("{indent}</array>\n"));
    out
}

/// Builds the profile. Installing a profile with the same host and user
/// again replaces the earlier one, since the identifiers are derived from
/// them.
pub fn generate(opts: &ProfileOptions) -> Result<String> {
    ensure!(opts.http3 || opts.http2, "the profile needs HTTP/3, HTTP/2 or both");
    crate::auth::validate_user_name(&opts.user)?;
    check_domain(&opts.host)?;
    for d in opts.match_domains.iter().chain(&opts.excluded_domains) {
        check_domain(d)?;
    }
    let template = UriTemplate::parse(&opts.relay_url())?;
    for var in ["target_host", "target_port"] {
        ensure!(template.has_variable(var), "the UDP template must contain {{{var}}}");
    }
    let url = escape(&opts.relay_url());
    let name = escape(opts.name.as_deref().unwrap_or(&opts.host));
    let id = format!("{IDENTIFIER_PREFIX}.{}.{}", opts.host.to_ascii_lowercase(), opts.user);
    let authorization = escape(&basic_authorization(&opts.user, &opts.password));
    let scope = if opts.match_domains.is_empty() {
        "all of this device's traffic".to_string()
    } else {
        format!("this device's traffic to {}", opts.match_domains.join(", "))
    };
    let description = escape(&format!("Sends {scope} through the relay {} as user {}.", opts.host, opts.user));
    let mut urls = String::new();
    if opts.http3 {
        urls.push_str(&format!("          <key>HTTP3RelayURL</key>\n          <string>{url}</string>\n"));
    }
    if opts.http2 {
        urls.push_str(&format!("          <key>HTTP2RelayURL</key>\n          <string>{url}</string>\n"));
    }
    let domains = string_array("MatchDomains", &opts.match_domains, "      ")
        + &string_array("ExcludedDomains", &opts.excluded_domains, "      ");
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.relay.managed</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadIdentifier</key>
      <string>{id}.relay</string>
      <key>PayloadUUID</key>
      <string>{relay_uuid}</string>
      <key>PayloadDisplayName</key>
      <string>{name}</string>
      <key>Relays</key>
      <array>
        <dict>
{urls}          <key>AdditionalHTTPHeaderFields</key>
          <dict>
            <key>Authorization</key>
            <string>{authorization}</string>
          </dict>
        </dict>
      </array>
{domains}    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>{name}</string>
  <key>PayloadDescription</key>
  <string>{description}</string>
  <key>PayloadIdentifier</key>
  <string>{id}</string>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>{profile_uuid}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
"#,
        relay_uuid = uuid(),
        profile_uuid = uuid(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuids_are_version_4() {
        let u = uuid();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
        assert!("89AB".contains(&u[19..20]));
        assert_ne!(u, uuid());
    }

    #[test]
    fn profile_carries_template_and_credentials() {
        let mut o = ProfileOptions::new("relay.example.com", "iphone", "p&ss<word>");
        o.match_domains = vec!["ifconfig.me".into()];
        let p = generate(&o).unwrap();
        assert!(p.contains("<string>com.apple.relay.managed</string>"));
        let url = "https://relay.example.com/.well-known/masque/udp/{target_host}/{target_port}/";
        assert!(p.contains(&format!("<key>HTTP3RelayURL</key>\n          <string>{url}</string>")));
        assert!(p.contains(&format!("<key>HTTP2RelayURL</key>\n          <string>{url}</string>")));
        let basic = basic_authorization("iphone", "p&ss<word>");
        assert!(p.contains(&format!("<string>{}</string>", escape(&basic))));
        assert!(p.contains("<key>MatchDomains</key>\n      <array>\n        <string>ifconfig.me</string>"));
        assert!(!p.contains("ExcludedDomains"));
        assert!(p.contains("<string>com.github.arccal.network-relay.relay.example.com.iphone</string>"));
        assert!(!p.contains("p&ss"), "special characters are escaped");
        // Balanced tags, as a plist parser needs.
        for tag in ["dict", "array", "plist"] {
            assert_eq!(p.matches(&format!("<{tag}")).count(), p.matches(&format!("</{tag}>")).count(), "{tag}");
        }
    }

    #[test]
    fn options_are_checked() {
        let mut o = ProfileOptions::new("relay.example.com", "iphone", "pw");
        o.port = 8443;
        o.http2 = false;
        let p = generate(&o).unwrap();
        assert!(p.contains("https://relay.example.com:8443/.well-known/masque/udp/"));
        assert!(!p.contains("HTTP2RelayURL"));
        o.http3 = false;
        assert!(generate(&o).is_err(), "no transport");
        let mut o = ProfileOptions::new("relay.example.com", "iphone", "pw");
        o.udp_template = "/udp/{target_host}/".into();
        assert!(generate(&o).is_err(), "no port variable");
        assert!(generate(&ProfileOptions::new("relay example", "iphone", "pw")).is_err());
        assert!(generate(&ProfileOptions::new("relay.example.com", "a:b", "pw")).is_err());
        let mut o = ProfileOptions::new("relay.example.com", "iphone", "pw");
        o.excluded_domains = vec!["bad domain".into()];
        assert!(generate(&o).is_err());
    }
}
