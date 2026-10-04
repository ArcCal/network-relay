//! `network-relay profile`: writes a configuration profile (`.mobileconfig`)
//! that sets up the relay on an iPhone, iPad or Mac, or the equivalent
//! declarative device management (DDM) configuration for an MDM server.
//!
//! The profile holds one `com.apple.relay.managed` payload (iOS 17+,
//! macOS 14+; installable by hand, no supervision needed; deprecated from
//! iOS/macOS 27 in favour of the DDM `com.apple.configuration.network.relay`
//! declaration). Its relay entry names the server by URI template (RFC 9298
//! §2) for HTTP/3 and HTTP/2, and carries the user's credentials: a password
//! in `AdditionalHTTPHeaderFields`, which the device sends with every CONNECT
//! request, and/or an identity certificate (`com.apple.security.pkcs12`
//! payload referenced by `PayloadCertificateUUID`).

use anyhow::{ensure, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::auth::basic_authorization;
use crate::proto::UriTemplate;

/// Reverse-DNS prefix of the payload identifiers.
const IDENTIFIER_PREFIX: &str = "com.github.arccal.network-relay";

/// A PKCS#12 identity to install with the profile.
#[derive(Debug, Clone)]
pub struct IdentityPayload {
    pub p12: Vec<u8>,
    /// Embedded in the profile when given; otherwise the device asks for it
    /// during installation, so the profile alone does not unlock the key.
    pub password: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProfileOptions {
    /// The relay's host name, as in its certificate.
    pub host: String,
    pub port: u16,
    pub user: String,
    /// Basic-auth password; optional when an identity is given.
    pub password: Option<String>,
    /// A client identity (PKCS#12) for certificate authentication.
    pub identity: Option<IdentityPayload>,
    /// DDM only: identifier of the identity asset declaration.
    pub identity_asset: Option<String>,
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
    #[cfg(test)]
    pub fn new(host: &str, user: &str, password: &str) -> Self {
        Self {
            host: host.to_string(),
            port: 443,
            user: user.to_string(),
            password: Some(password.to_string()),
            identity: None,
            identity_asset: None,
            udp_template: crate::proto::DEFAULT_UDP_PATH_TEMPLATE.to_string(),
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

/// The checks shared by both output formats.
fn check(opts: &ProfileOptions) -> Result<()> {
    ensure!(opts.http3 || opts.http2, "the profile needs HTTP/3, HTTP/2 or both");
    ensure!(
        opts.password.is_some() || opts.identity.is_some() || opts.identity_asset.is_some(),
        "the profile needs a password, an identity certificate, or both"
    );
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
    Ok(())
}

/// Builds the profile. Installing a profile with the same host and user
/// again replaces the earlier one, since the identifiers are derived from
/// them.
pub fn generate(opts: &ProfileOptions) -> Result<String> {
    check(opts)?;
    ensure!(opts.identity_asset.is_none(), "an identity asset reference is only for DDM declarations (--ddm)");
    let url = escape(&opts.relay_url());
    let name = escape(opts.name.as_deref().unwrap_or(&opts.host));
    let id = format!("{IDENTIFIER_PREFIX}.{}.{}", opts.host.to_ascii_lowercase(), opts.user);
    let cert_uuid = uuid();
    let mut credentials = String::new();
    if let Some(password) = &opts.password {
        credentials.push_str(&format!(
            "          <key>AdditionalHTTPHeaderFields</key>\n          <dict>\n            <key>Authorization</key>\n            \
             <string>{}</string>\n          </dict>\n",
            escape(&basic_authorization(&opts.user, password))
        ));
    }
    if opts.identity.is_some() {
        credentials.push_str(&format!(
            "          <key>PayloadCertificateUUID</key>\n          <string>{cert_uuid}</string>\n"
        ));
    }
    let identity_payload = match &opts.identity {
        None => String::new(),
        Some(identity) => {
            let password = identity
                .password
                .as_ref()
                .map(|p| format!("      <key>Password</key>\n      <string>{}</string>\n", escape(p)))
                .unwrap_or_default();
            format!(
                r#"    <dict>
      <key>PayloadType</key>
      <string>com.apple.security.pkcs12</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadIdentifier</key>
      <string>{id}.identity</string>
      <key>PayloadUUID</key>
      <string>{cert_uuid}</string>
      <key>PayloadDisplayName</key>
      <string>{name} identity</string>
      <key>PayloadCertificateFileName</key>
      <string>{user}.p12</string>
{password}      <key>PayloadContent</key>
      <data>{data}</data>
    </dict>
"#,
                user = escape(&opts.user),
                data = STANDARD.encode(&identity.p12),
            )
        }
    };
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
{identity_payload}    <dict>
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
{urls}{credentials}        </dict>
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

/// Builds the DDM declaration (`com.apple.configuration.network.relay`,
/// iOS/macOS/visionOS 27+) for an MDM server, as JSON. A client identity
/// is referenced as an asset declaration (`IdentityAssetReference`), which
/// the MDM server provides.
pub fn generate_ddm(opts: &ProfileOptions) -> Result<String> {
    check(opts)?;
    ensure!(
        opts.identity.is_none(),
        "a DDM declaration references the identity as an asset: use --identity-asset with the asset's identifier"
    );
    let url = opts.relay_url();
    let mut relay = serde_json::Map::new();
    if opts.http3 {
        relay.insert("HTTP3RelayURL".into(), url.clone().into());
    }
    if opts.http2 {
        relay.insert("HTTP2RelayURL".into(), url.into());
    }
    if let Some(password) = &opts.password {
        relay.insert(
            "AdditionalHTTPHeaderFields".into(),
            serde_json::json!({ "Authorization": basic_authorization(&opts.user, password) }),
        );
    }
    if let Some(asset) = &opts.identity_asset {
        relay.insert("IdentityAssetReference".into(), asset.clone().into());
    }
    let mut payload = serde_json::Map::new();
    payload.insert("VisibleName".into(), opts.name.clone().unwrap_or_else(|| opts.host.clone()).into());
    payload.insert("Relays".into(), serde_json::Value::Array(vec![relay.into()]));
    for (key, values) in [
        ("MatchDomains", &opts.match_domains),
        ("ExcludedDomains", &opts.excluded_domains),
        ("MatchFQDNs", &opts.match_fqdns),
        ("ExcludedFQDNs", &opts.excluded_fqdns),
    ] {
        if !values.is_empty() {
            let list: Vec<String> =
                values.iter().map(|v| v.strip_suffix('.').unwrap_or(v).to_ascii_lowercase()).collect();
            payload.insert(key.into(), list.into());
        }
    }
    if let Some(id) = &opts.relay_uuid {
        payload.insert("RelayUUID".into(), id.to_ascii_uppercase().into());
    }
    if let Some(v) = opts.ui_toggle_enabled {
        payload.insert("UIToggleEnabled".into(), v.into());
    }
    if let Some(v) = opts.allow_dns_failover {
        payload.insert("AllowDNSFailover".into(), v.into());
    }
    let declaration = serde_json::json!({
        "Type": "com.apple.configuration.network.relay",
        "Identifier": format!("{IDENTIFIER_PREFIX}.{}.{}", opts.host.to_ascii_lowercase(), opts.user),
        "ServerToken": uuid(),
        "Payload": payload,
    });
    Ok(serde_json::to_string_pretty(&declaration)? + "\n")
}

/// Warnings about settings that are valid but probably not what was meant.
pub fn warnings(opts: &ProfileOptions) -> Vec<String> {
    let mut out = Vec::new();
    if opts.match_domains.is_empty() && (!opts.match_fqdns.is_empty() || !opts.excluded_fqdns.is_empty()) {
        out.push(
            "MatchFQDNs/ExcludedFQDNs need iOS 18.4 / macOS 15.4; older systems ignore them, and a profile with no \
             MatchDomains then relays all traffic"
                .to_string(),
        );
    }
    if !opts.match_domains.is_empty() {
        let norm = |d: &String| d.strip_suffix('.').unwrap_or(d).to_ascii_lowercase();
        let matches: Vec<String> = opts.match_domains.iter().map(norm).collect();
        for fqdn in opts.excluded_fqdns.iter().map(norm) {
            if !matches.iter().any(|m| fqdn == *m || fqdn.ends_with(&format!(".{m}"))) {
                out.push(format!("excluded FQDN {fqdn} is not under any match domain, so it has no effect"));
            }
        }
    }
    if opts.ui_toggle_enabled == Some(false) {
        out.push(
            "UIToggleEnabled is false: the relay cannot be turned off in Settings; if it is unreachable, every \
             matching site stops working until the profile is removed"
                .to_string(),
        );
    }
    out
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
        assert!(!p.contains("PayloadCertificateUUID") && !p.contains("pkcs12"));
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
    fn identity_certificates_are_embedded_and_referenced() {
        let mut o = ProfileOptions::new("relay.example.com", "ipad", "unused");
        o.password = None;
        assert!(generate(&o).is_err(), "no credentials at all");
        o.identity = Some(IdentityPayload { p12: vec![1, 2, 3], password: None });
        let p = generate(&o).unwrap();
        assert!(p.contains("<string>com.apple.security.pkcs12</string>"));
        assert!(p.contains("<data>AQID</data>"));
        assert!(!p.contains("<key>Password</key>"), "the device asks for it");
        assert!(!p.contains("AdditionalHTTPHeaderFields"));
        let uuid_of = |key: &str, p: &str| {
            let start = p.find(&format!("<key>{key}</key>")).unwrap();
            let rest = &p[start..];
            let s = rest.find("<string>").unwrap() + 8;
            rest[s..s + 36].to_string()
        };
        let pkcs12 = &p[p.find("com.apple.security.pkcs12").unwrap()..];
        assert_eq!(uuid_of("PayloadCertificateUUID", &p), uuid_of("PayloadUUID", pkcs12));
        o.identity = Some(IdentityPayload { p12: vec![1], password: Some("p<w".into()) });
        o.password = Some("also".into());
        let p = generate(&o).unwrap();
        assert!(p.contains("<string>p&lt;w</string>") && p.contains("AdditionalHTTPHeaderFields"));
        for tag in ["dict", "array", "plist"] {
            assert_eq!(p.matches(&format!("<{tag}")).count(), p.matches(&format!("</{tag}>")).count(), "{tag}");
        }
    }

    #[test]
    fn ddm_declarations_follow_apples_schema() {
        let mut o = ProfileOptions::new("Relay.example.com", "iphone", "pw");
        o.host = "relay.example.com".into();
        o.match_domains = vec!["Example.COM.".into()];
        o.ui_toggle_enabled = Some(true);
        o.relay_uuid = Some("00112233-4455-6677-8899-aabbccddeeff".into());
        let v: serde_json::Value = serde_json::from_str(&generate_ddm(&o).unwrap()).unwrap();
        assert_eq!(v["Type"], "com.apple.configuration.network.relay");
        assert_eq!(v["Payload"]["VisibleName"], "relay.example.com");
        let relay = &v["Payload"]["Relays"][0];
        let url = "https://relay.example.com/.well-known/masque/udp/{target_host}/{target_port}/";
        assert_eq!((relay["HTTP3RelayURL"].as_str(), relay["HTTP2RelayURL"].as_str()), (Some(url), Some(url)));
        assert_eq!(relay["AdditionalHTTPHeaderFields"]["Authorization"], basic_authorization("iphone", "pw"));
        assert_eq!(v["Payload"]["MatchDomains"][0], "example.com");
        assert_eq!(v["Payload"]["UIToggleEnabled"], true);
        assert_eq!(v["Payload"]["RelayUUID"], "00112233-4455-6677-8899-AABBCCDDEEFF");
        assert!(v["Payload"].get("AllowDNSFailover").is_none());
        o.password = None;
        o.identity_asset = Some("identity.ipad".into());
        let v: serde_json::Value = serde_json::from_str(&generate_ddm(&o).unwrap()).unwrap();
        assert_eq!(v["Payload"]["Relays"][0]["IdentityAssetReference"], "identity.ipad");
        assert!(generate(&o).is_err(), "asset references are only for DDM");
        o.identity = Some(IdentityPayload { p12: vec![1], password: None });
        assert!(generate_ddm(&o).is_err());
    }

    #[test]
    fn risky_settings_are_warned_about() {
        let mut o = ProfileOptions::new("relay.example.com", "iphone", "pw");
        assert!(warnings(&o).is_empty());
        o.match_fqdns = vec!["api.example.com".into()];
        assert!(warnings(&o)[0].contains("18.4"));
        o.match_fqdns.clear();
        o.match_domains = vec!["example.com".into()];
        o.excluded_fqdns = vec!["a.example.com".into(), "b.example.org".into()];
        let w = warnings(&o);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("b.example.org"));
        o.excluded_fqdns.clear();
        o.ui_toggle_enabled = Some(false);
        assert!(warnings(&o)[0].contains("cannot be turned off"));
    }

    #[test]
    fn invalid_xml_names_and_endpoint_authority_changes_are_rejected() {
        let mut opts = ProfileOptions::new("relay.example.com", "alice", "password");
        for name in ["name\0", "name\u{1f}", "name\u{fffe}"] {
            opts.name = Some(name.into());
            assert!(generate(&opts).is_err(), "{name:?}");
        }
        opts.name = Some("Relé & <Näme>\n".into());
        assert!(generate(&opts).unwrap().contains("Relé &amp; &lt;Näme&gt;"));
        opts.udp_template = "elsewhere/udp/{target_host}/{target_port}".into();
        assert!(generate(&opts).is_err(), "a missing slash must not change the relay host");
        opts.udp_template = crate::proto::DEFAULT_UDP_PATH_TEMPLATE.into();
        opts.match_domains = vec!["example.com..".into()];
        assert!(generate(&opts).is_err());
    }
}
