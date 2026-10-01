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
    /// These domains and their subdomains use the relay. If both this list
    /// and match_fqdns are empty, all traffic is matched, except exclusions.
    pub match_domains: Vec<String>,
    /// These domains and their subdomains never use the relay.
    pub excluded_domains: Vec<String>,
    /// Exact hostnames (iOS 18.4+, macOS 15.4+), without subdomain matching.
    pub match_fqdns: Vec<String>,
    pub excluded_fqdns: Vec<String>,
    /// Optional controls introduced in iOS/macOS 26.
    pub ui_toggle_enabled: Option<bool>,
    pub allow_dns_failover: Option<bool>,
    /// Relay configuration identity for managed-app/user-enrollment routing.
    pub relay_uuid: Option<String>,
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
            match_fqdns: Vec::new(),
            excluded_fqdns: Vec::new(),
            ui_toggle_enabled: None,
            allow_dns_failover: None,
            relay_uuid: None,
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
            && d.split('.').all(|l| !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
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
        out.push_str(&format!(
            "{indent}  <string>{}</string>\n",
            escape(&v.strip_suffix('.').unwrap_or(v).to_ascii_lowercase())
        ));
    }
    out.push_str(&format!("{indent}</array>\n"));
    out
}

/// Builds the profile. Installing a profile with the same host and user
/// again replaces the earlier one, since the identifiers are derived from
/// them.
pub fn generate(opts: &ProfileOptions) -> Result<String> {
    ensure!(opts.http3 || opts.http2, "the profile needs HTTP/3, HTTP/2 or both");
    ensure!(opts.port != 0, "the relay port must be between 1 and 65535");
    crate::auth::validate_user_name(&opts.user)?;
    check_domain(&opts.host)?;
    for d in
        opts.match_domains.iter().chain(&opts.excluded_domains).chain(&opts.match_fqdns).chain(&opts.excluded_fqdns)
    {
        check_domain(d.strip_suffix('.').unwrap_or(d))?;
    }
    if let Some(id) = &opts.relay_uuid {
        let groups: Vec<_> = id.split('-').collect();
        ensure!(
            groups.len() == 5
                && groups
                    .iter()
                    .zip([8, 4, 4, 4, 12])
                    .all(|(g, n)| g.len() == n && g.bytes().all(|b| b.is_ascii_hexdigit())),
            "--relay-uuid must be a UUID"
        );
    }
    ensure!(
        opts.name.as_deref().is_none_or(|name| name
            .chars()
            .all(|c| matches!(c, '\t' | '\n' | '\r') || (c >= ' ' && c != '\u{fffe}' && c != '\u{ffff}'))),
        "the profile name contains a character XML cannot represent"
    );
    let template = UriTemplate::parse_path(&opts.udp_template)?;
    for var in ["target_host", "target_port"] {
        ensure!(template.has_variable(var), "the UDP template must contain {{{var}}}");
    }
    template.check_round_trip()?;
    let url = escape(&opts.relay_url());
    let name = escape(opts.name.as_deref().unwrap_or(&opts.host));
    let id = format!("{IDENTIFIER_PREFIX}.{}.{}", opts.host.to_ascii_lowercase(), opts.user);
    let authorization = escape(&basic_authorization(&opts.user, &opts.password));
    let scope = if opts.match_domains.is_empty() && opts.match_fqdns.is_empty() {
        "all of this device's traffic".to_string()
    } else {
        format!(
            "this device's traffic to {}",
            opts.match_domains.iter().chain(&opts.match_fqdns).cloned().collect::<Vec<_>>().join(", ")
        )
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
        + &string_array("ExcludedDomains", &opts.excluded_domains, "      ")
        + &string_array("MatchFQDNs", &opts.match_fqdns, "      ")
        + &string_array("ExcludedFQDNs", &opts.excluded_fqdns, "      ");
    let mut controls = String::new();
    for (key, value) in [("UIToggleEnabled", opts.ui_toggle_enabled), ("AllowDNSFailover", opts.allow_dns_failover)] {
        if let Some(value) = value {
            controls.push_str(&format!("      <key>{key}</key>\n      <{value}/>\n"));
        }
    }
    if let Some(id) = &opts.relay_uuid {
        controls.push_str(&format!("      <key>RelayUUID</key>\n      <string>{}</string>\n", id.to_ascii_uppercase()));
    }
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
{domains}{controls}    </dict>
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
    fn precise_matching_and_device_controls_are_encoded() {
        let mut opts = ProfileOptions::new("relay.example.com", "alice", "fixture-password");
        opts.match_fqdns = vec!["API.Example.COM.".into()];
        opts.excluded_fqdns = vec!["private.example.com".into()];
        opts.ui_toggle_enabled = Some(false);
        opts.allow_dns_failover = Some(true);
        opts.relay_uuid = Some("00112233-4455-6677-8899-aabbccddeeff".into());
        let profile = generate(&opts).unwrap();
        assert!(profile.contains("<key>MatchFQDNs</key>"));
        assert!(profile.contains("<string>api.example.com</string>"));
        assert!(profile.contains("<key>ExcludedFQDNs</key>"));
        assert!(profile.contains("<key>UIToggleEnabled</key>\n      <false/>"));
        assert!(profile.contains("<key>AllowDNSFailover</key>\n      <true/>"));
        assert!(profile.contains("<string>00112233-4455-6677-8899-AABBCCDDEEFF</string>"));
        assert!(!profile.contains("all of this device"));
        opts.relay_uuid = Some("not-a-uuid".into());
        assert!(generate(&opts).is_err());
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

    #[test]
    fn invalid_xml_names_and_endpoint_authority_changes_are_rejected() {
        let mut opts = ProfileOptions::new("relay.example.com", "alice", "password");
        for name in ["name\0", "name\u{1f}", "name\u{fffe}"] {
            opts.name = Some(name.into());
            assert!(generate(&opts).is_err(), "{name:?}");
        }
        opts.name = Some("中继 & <名字>\n".into());
        assert!(generate(&opts).unwrap().contains("中继 &amp; &lt;名字&gt;"));
        opts.udp_template = "elsewhere/udp/{target_host}/{target_port}".into();
        assert!(generate(&opts).is_err(), "a missing slash must not change the relay host");
        opts.udp_template = DEFAULT_UDP_PATH_TEMPLATE.into();
        opts.match_domains = vec!["example.com..".into()];
        assert!(generate(&opts).is_err());
    }
}
