//! URI Templates (RFC 6570) as restricted by RFC 9298 §2.
//!
//! CONNECT-UDP clients are configured with a URI Template such as
//! `https://example.org/.well-known/masque/udp/{target_host}/{target_port}/`.
//! The template must be level 3 or lower, absolute, ASCII, keep its
//! variables in the path or query, and must not use the `+`, `#`, `.`, `/`
//! or `;` operators. That leaves three expression types, all implemented
//! here: simple `{a,b}`, form-style query `{?a,b}` and query continuation
//! `{&a,b}`.
//!
//! Clients expand the template to build the request; the proxy matches the
//! request's path and query against the same template to recover the
//! variables.

use std::collections::HashMap;

/// Errors from parsing a template.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid URI template: {0}")]
pub struct TemplateError(&'static str);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    /// `{var}`: comma-separated values, reserved characters encoded.
    Simple,
    /// `{?var}`: `?name=value&name=value`.
    Query,
    /// `{&var}`: `&name=value&name=value`.
    QueryContinuation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    Literal(String),
    Expr { op: Op, vars: Vec<String> },
}

/// A parsed URI Template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UriTemplate {
    raw: String,
    scheme: String,
    authority: String,
    /// Path and query, starting with `/`.
    parts: Vec<Part>,
}

impl std::fmt::Display for UriTemplate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.raw)
    }
}

impl std::str::FromStr for UriTemplate {
    type Err = TemplateError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl UriTemplate {
    /// Parses an absolute template, enforcing RFC 9298 §2.
    pub fn parse(raw: &str) -> Result<Self, TemplateError> {
        if raw.is_empty() || !raw.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(TemplateError("only ASCII characters 0x21-0x7E are allowed"));
        }
        let (scheme, rest) =
            raw.split_once("://").ok_or(TemplateError("must be absolute (scheme://authority/path)"))?;
        if scheme.is_empty() || !scheme.bytes().all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b)) {
            return Err(TemplateError("missing or invalid scheme"));
        }
        let path_start = rest.find('/').ok_or(TemplateError("path must not be empty and must start with '/'"))?;
        let (authority, path) = rest.split_at(path_start);
        if authority.is_empty() {
            return Err(TemplateError("authority must not be empty"));
        }
        if authority.contains(['{', '}']) {
            return Err(TemplateError("variables are only allowed in the path or query"));
        }
        let parts = Self::parse_parts(path)?;
        Ok(Self { raw: raw.to_string(), scheme: scheme.to_ascii_lowercase(), authority: authority.to_string(), parts })
    }

    /// Parses a template for just the path and query, as a server
    /// configures its endpoint.
    pub fn parse_path(path: &str) -> Result<Self, TemplateError> {
        if !path.starts_with('/') {
            return Err(TemplateError("path must start with '/'"));
        }
        Self::parse(&format!("https://server{path}"))
    }

    fn parse_parts(mut s: &str) -> Result<Vec<Part>, TemplateError> {
        let mut parts = Vec::new();
        while !s.is_empty() {
            match s.find('{') {
                Some(0) => {
                    let end = s.find('}').ok_or(TemplateError("unterminated expression"))?;
                    let body = &s[1..end];
                    let (op, list) = match body.as_bytes().first() {
                        Some(b'?') => (Op::Query, &body[1..]),
                        Some(b'&') => (Op::QueryContinuation, &body[1..]),
                        Some(b'+' | b'#' | b'.' | b'/' | b';') => {
                            return Err(TemplateError("operators + # . / ; are not allowed"))
                        }
                        Some(b'=' | b',' | b'!' | b'@' | b'|') => return Err(TemplateError("reserved operator")),
                        _ => (Op::Simple, body),
                    };
                    let vars = list.split(',').map(str::to_string).collect::<Vec<_>>();
                    for v in &vars {
                        if v.contains([':', '*']) {
                            return Err(TemplateError("level 4 modifiers are not allowed"));
                        }
                        if v.is_empty() || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.') {
                            return Err(TemplateError("invalid variable name"));
                        }
                    }
                    parts.push(Part::Expr { op, vars });
                    s = &s[end + 1..];
                }
                Some(i) => {
                    parts.push(Part::Literal(s[..i].to_string()));
                    s = &s[i..];
                }
                None => {
                    if s.contains('}') {
                        return Err(TemplateError("unmatched '}'"));
                    }
                    parts.push(Part::Literal(s.to_string()));
                    s = "";
                }
            }
        }
        for p in &parts {
            if let Part::Literal(l) = p {
                if l.contains('}') {
                    return Err(TemplateError("unmatched '}'"));
                }
            }
        }
        Ok(parts)
    }

    /// Whether the template has an expression for variable `name`.
    pub fn has_variable(&self, name: &str) -> bool {
        self.parts.iter().any(|p| matches!(p, Part::Expr { vars, .. } if vars.iter().any(|v| v == name)))
    }

    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The authority (`host[:port]`) the request goes to.
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Host part of the authority, without brackets around IPv6 literals.
    pub fn host(&self) -> &str {
        let a = self.authority.rsplit_once('@').map_or(self.authority.as_str(), |(_, h)| h);
        if let Some(rest) = a.strip_prefix('[') {
            return rest.split(']').next().unwrap_or(rest);
        }
        a.rsplit_once(':').map_or(a, |(h, _)| h)
    }

    /// Port of the authority, or the scheme's default.
    pub fn port(&self) -> Option<u16> {
        let a = self.authority.rsplit_once('@').map_or(self.authority.as_str(), |(_, h)| h);
        let after_host = if a.starts_with('[') { a.split_once(']').map(|(_, r)| r)? } else { a };
        match after_host.rsplit_once(':') {
            Some((_, p)) => p.parse().ok(),
            None => match self.scheme.as_str() {
                "https" => Some(443),
                "http" => Some(80),
                _ => None,
            },
        }
    }

    /// Expands the template into a path and query (origin form). Variables
    /// not in `vars` are left out, as RFC 6570 specifies. Everything outside
    /// the unreserved set is percent-encoded, including the colons of IPv6
    /// addresses (RFC 9298 §2).
    pub fn expand(&self, vars: &[(&str, &str)]) -> String {
        let lookup = |name: &str| vars.iter().find(|(n, _)| *n == name).map(|(_, v)| *v);
        let mut out = String::new();
        for part in &self.parts {
            match part {
                Part::Literal(l) => out.push_str(l),
                Part::Expr { op, vars: names } => {
                    let defined: Vec<(&str, &str)> =
                        names.iter().filter_map(|n| lookup(n).map(|v| (n.as_str(), v))).collect();
                    if defined.is_empty() {
                        continue;
                    }
                    match op {
                        Op::Simple => {
                            let values: Vec<String> = defined.iter().map(|(_, v)| encode(v)).collect();
                            out.push_str(&values.join(","));
                        }
                        Op::Query | Op::QueryContinuation => {
                            out.push(if *op == Op::Query { '?' } else { '&' });
                            let pairs: Vec<String> =
                                defined.iter().map(|(n, v)| format!("{n}={}", encode(v))).collect();
                            out.push_str(&pairs.join("&"));
                        }
                    }
                }
            }
        }
        out
    }

    /// Matches a request's path and query against the template and returns
    /// the percent-decoded variables it carries. Returns `None` if the
    /// request does not match.
    pub fn matches(&self, path_and_query: &str) -> Option<HashMap<String, String>> {
        let (path, query) = match path_and_query.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (path_and_query, None),
        };
        // Split the template into its path part and its query part.
        let mut path_parts = Vec::new();
        let mut query_exprs = Vec::new();
        let mut query_literal = String::new();
        let mut in_query = false;
        for part in &self.parts {
            match part {
                Part::Literal(l) if !in_query => match l.split_once('?') {
                    Some((before, after)) => {
                        path_parts.push(Part::Literal(before.to_string()));
                        query_literal.push_str(after);
                        in_query = true;
                    }
                    None => path_parts.push(part.clone()),
                },
                Part::Literal(l) => query_literal.push_str(l),
                Part::Expr { op: Op::Simple, vars } if in_query => {
                    // A simple expression inside a literal query such as
                    // `?t={target}`: remember which parameter it fills.
                    let name = query_literal.rsplit(['&', '?']).next().unwrap_or("").trim_end_matches('=');
                    if vars.len() != 1 || name.is_empty() {
                        return None;
                    }
                    query_exprs.push((name.to_string(), vars[0].clone()));
                    query_literal.push('\u{0}'); // placeholder for the value
                }
                Part::Expr { op: Op::Simple, .. } => path_parts.push(part.clone()),
                Part::Expr { vars, .. } => {
                    in_query = true;
                    query_exprs.extend(vars.iter().map(|v| (v.clone(), v.clone())));
                }
            }
        }

        let mut out = HashMap::new();
        match_path(&path_parts, path, &mut out)?;

        let params: Vec<(String, String)> = query
            .unwrap_or("")
            .split('&')
            .filter(|kv| !kv.is_empty())
            .map(|kv| {
                let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                (decode(k).unwrap_or_default(), decode(v).unwrap_or_default())
            })
            .collect();
        // Fixed parameters written literally in the template must be present.
        for kv in query_literal.split('&').filter(|kv| !kv.is_empty() && !kv.contains('\u{0}')) {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            if !params.iter().any(|(pk, pv)| pk == k && pv == v) {
                return None;
            }
        }
        for (param, var) in query_exprs {
            if let Some((_, v)) = params.iter().find(|(k, _)| *k == param) {
                out.insert(var, v.clone());
            }
        }
        Some(out)
    }
}

/// Matches path parts left to right. A simple expression captures up to the
/// next literal; two expressions in a row cannot be matched unambiguously.
fn match_path(parts: &[Part], mut path: &str, out: &mut HashMap<String, String>) -> Option<()> {
    let mut i = 0;
    while i < parts.len() {
        match &parts[i] {
            Part::Literal(l) => path = path.strip_prefix(l.as_str())?,
            Part::Expr { vars, .. } => {
                let captured = match parts.get(i + 1) {
                    Some(Part::Literal(next)) if !next.is_empty() => {
                        let end = path.find(next.as_str())?;
                        let (c, rest) = path.split_at(end);
                        path = rest;
                        c
                    }
                    Some(_) => return None,
                    None => std::mem::take(&mut path),
                };
                if !captured.is_empty() {
                    let values: Vec<&str> = captured.split(',').collect();
                    if values.len() != vars.len() {
                        return None;
                    }
                    for (name, value) in vars.iter().zip(values) {
                        out.insert(name.clone(), decode(value)?);
                    }
                }
            }
        }
        i += 1;
    }
    path.is_empty().then_some(())
}

fn encode(value: &str) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Percent-decodes a URI component. Returns `None` for malformed escapes or
/// invalid UTF-8.
pub fn decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT: &str = "https://example.org/.well-known/masque/udp/{target_host}/{target_port}/";

    fn t(s: &str) -> UriTemplate {
        UriTemplate::parse(s).unwrap()
    }

    fn vars(m: &HashMap<String, String>) -> (&str, &str) {
        (m["target_host"].as_str(), m["target_port"].as_str())
    }

    #[test]
    fn rfc9298_example_templates_parse() {
        // RFC 9298 §2, Figure 1.
        for s in [
            DEFAULT,
            "https://proxy.example.org:4443/masque?h={target_host}&p={target_port}",
            "https://proxy.example.org:4443/masque{?target_host,target_port}",
        ] {
            let tpl = UriTemplate::parse(s).unwrap();
            assert!(tpl.has_variable("target_host") && tpl.has_variable("target_port"), "{s}");
        }
        assert!(!t("https://masque.example.org/?user=bob").has_variable("target_host"));
    }

    #[test]
    fn disallowed_templates_are_rejected() {
        for s in [
            "/relative/{target_host}",
            "https://{host}/udp/",
            "https://example.org",
            "https://example.org/{+target_host}",
            "https://example.org/{#target_host}",
            "https://example.org{/target_host}",
            "https://example.org/{.target_host}",
            "https://example.org/{;target_host}",
            "https://example.org/{target_host*}",
            "https://example.org/{target_host:3}",
            "https://example.org/{target_host",
            "https://example.org/udp /x",
            "https://example.org/udp/é",
        ] {
            assert!(UriTemplate::parse(s).is_err(), "{s} should be rejected");
        }
    }

    #[test]
    fn expands_like_the_rfc_example() {
        // RFC 9298 §3.4: ":path = /.well-known/masque/udp/192.0.2.6/443/"
        assert_eq!(
            t(DEFAULT).expand(&[("target_host", "192.0.2.6"), ("target_port", "443")]),
            "/.well-known/masque/udp/192.0.2.6/443/"
        );
        // RFC 9298 §2: the colons of IPv6 addresses are percent-encoded.
        assert_eq!(
            t(DEFAULT).expand(&[("target_host", "2001:db8::42"), ("target_port", "53")]),
            "/.well-known/masque/udp/2001%3Adb8%3A%3A42/53/"
        );
    }

    #[test]
    fn expands_query_forms() {
        let q = t("https://proxy.example.org:4443/masque{?target_host,target_port}");
        assert_eq!(
            q.expand(&[("target_host", "example.com"), ("target_port", "443")]),
            "/masque?target_host=example.com&target_port=443"
        );
        assert_eq!(q.expand(&[]), "/masque");
        let lit = t("https://proxy.example.org:4443/masque?h={target_host}&p={target_port}");
        assert_eq!(lit.expand(&[("target_host", "a.example"), ("target_port", "53")]), "/masque?h=a.example&p=53");
        assert_eq!(t("https://masque.example.org/?user=bob").expand(&[]), "/?user=bob");
    }

    #[test]
    fn authority_host_and_port() {
        let q = t("https://proxy.example.org:4443/masque{?target_host,target_port}");
        assert_eq!((q.authority(), q.host(), q.port()), ("proxy.example.org:4443", "proxy.example.org", Some(4443)));
        let d = t(DEFAULT);
        assert_eq!((d.host(), d.port()), ("example.org", Some(443)));
        let v6 = t("https://[2001:db8::1]:8443/udp/");
        assert_eq!((v6.host(), v6.port()), ("2001:db8::1", Some(8443)));
    }

    #[test]
    fn matching_recovers_variables() {
        let d = t(DEFAULT);
        assert_eq!(vars(&d.matches("/.well-known/masque/udp/192.0.2.6/443/").unwrap()), ("192.0.2.6", "443"));
        assert_eq!(vars(&d.matches("/.well-known/masque/udp/2001%3adb8%3A%3A42/53/").unwrap()), ("2001:db8::42", "53"));
        assert_eq!(vars(&d.matches("/.well-known/masque/udp/example.com/443/").unwrap()), ("example.com", "443"));
        assert!(d.matches("/.well-known/masque/ip/*/*/").is_none());
        assert!(d.matches("/.well-known/masque/udp/192.0.2.6/443/extra").is_none());
        assert!(d.matches("/.well-known/masque/udp/192.0.2.6/443").is_none());
        assert!(d.matches("/.well-known/masque/udp/%ff/443/").is_none(), "not UTF-8");
    }

    #[test]
    fn matching_query_templates() {
        let q = t("https://p.example/masque{?target_host,target_port}");
        let m = q.matches("/masque?target_port=53&target_host=192.0.2.1").unwrap();
        assert_eq!(vars(&m), ("192.0.2.1", "53"));
        assert!(q.matches("/masque").unwrap().is_empty(), "variables are optional to the matcher");
        let lit = t("https://p.example/masque?h={target_host}&p={target_port}");
        assert_eq!(vars(&lit.matches("/masque?h=a.example&p=443").unwrap()), ("a.example", "443"));
        let fixed = t("https://masque.example.org/?user=bob");
        assert!(fixed.matches("/?user=bob").is_some());
        assert!(fixed.matches("/?user=eve").is_none());
    }

    #[test]
    fn expand_then_match_roundtrip() {
        for tpl in [
            DEFAULT,
            "https://p.example/udp{?target_host,target_port}",
            "https://p.example/udp?h={target_host}&p={target_port}",
        ] {
            let tpl = t(tpl);
            for (host, port) in [("192.0.2.6", "443"), ("2001:db8::42", "53"), ("xn--bcher-kva.example", "8443")] {
                let path = tpl.expand(&[("target_host", host), ("target_port", port)]);
                let m = tpl.matches(&path).unwrap_or_else(|| panic!("{tpl} did not match {path}"));
                assert_eq!(vars(&m), (host, port), "{path}");
            }
        }
    }
}
