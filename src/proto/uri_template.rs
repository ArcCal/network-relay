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
        if !scheme.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            || !scheme.bytes().all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
        {
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
        if authority.parse::<http::uri::Authority>().is_err() || authority.contains(['@', '?', '#']) {
            return Err(TemplateError("invalid authority"));
        }
        if path.contains('#') {
            return Err(TemplateError("fragments are not allowed in a relay endpoint"));
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
                let escapes_valid = l.bytes().enumerate().all(|(i, b)| {
                    b != b'%' || l.as_bytes().get(i + 1..i + 3).is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
                });
                if !escapes_valid || l.bytes().any(|b| b"\"<>\\^`|".contains(&b)) {
                    return Err(TemplateError("invalid URI literal or percent escape"));
                }
            }
        }
        Ok(parts)
    }

    /// Checks that requests built from this template can be matched back to
    /// the targets they name. Some valid RFC 6570 forms, such as a query
    /// with an unnamed `{target_host}`, expand fine but cannot be matched,
    /// and would quietly turn every UDP request into a website request.
    pub fn check_round_trip(&self) -> Result<(), TemplateError> {
        for (host, port) in [("example.com", "443"), ("192.0.2.1", "53"), ("2001:db8::1", "8443")] {
            let path = self.expand(&[("target_host", host), ("target_port", port)]);
            let matched = self.matches(&path);
            let back = matched.as_ref().map(|m| (m.get("target_host"), m.get("target_port")));
            if back != Some((Some(&host.to_string()), Some(&port.to_string()))) {
                return Err(TemplateError("requests built from this template cannot be matched back to their target"));
            }
        }
        Ok(())
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
        let mut query_parts = Vec::new();
        let mut in_query = false;
        for part in &self.parts {
            match part {
                Part::Literal(l) if !in_query => match l.split_once('?') {
                    Some((before, after)) => {
                        path_parts.push(Part::Literal(before.to_string()));
                        query_parts.push(Part::Literal(after.to_string()));
                        in_query = true;
                    }
                    None => path_parts.push(part.clone()),
                },
                Part::Expr { op: Op::Query | Op::QueryContinuation, vars } => {
                    in_query = true;
                    for var in vars {
                        if !query_parts.is_empty() {
                            query_parts.push(Part::Literal("&".to_string()));
                        }
                        query_parts.push(Part::Literal(format!("{var}=")));
                        query_parts.push(Part::Expr { op: Op::Simple, vars: vec![var.clone()] });
                    }
                }
                _ if in_query => query_parts.push(part.clone()),
                _ => path_parts.push(part.clone()),
            }
        }

        let mut out = HashMap::new();
        match_path(&path_parts, path, &mut out)?;
        // Keep encoded values until matching: a variable's escaped '&' or ','
        // must not turn into a delimiter. Reject malformed percent escapes.
        let params: Vec<(String, &str)> = query
            .unwrap_or("")
            .split('&')
            .filter(|kv| !kv.is_empty())
            .map(|kv| {
                let (key, value) = kv.split_once('=').unwrap_or((kv, ""));
                decode(value)?;
                Some((decode(key)?, value))
            })
            .collect::<Option<_>>()?;
        let mut patterns: Vec<Vec<Part>> = vec![Vec::new()];
        for part in query_parts {
            match part {
                Part::Literal(l) => {
                    for (i, piece) in l.split('&').enumerate() {
                        if i != 0 {
                            patterns.push(Vec::new());
                        }
                        if !piece.is_empty() {
                            patterns.last_mut()?.push(Part::Literal(piece.to_string()));
                        }
                    }
                }
                other => patterns.last_mut()?.push(other),
            }
        }
        for mut pattern in patterns {
            if pattern.is_empty() {
                continue;
            }
            let Part::Literal(first) = pattern.first_mut()? else { return None };
            let (key, prefix) = first.split_once('=').unwrap_or((first, ""));
            let key = decode(key)?;
            *first = prefix.to_string();
            if let Some((_, value)) = params.iter().find(|(k, _)| k == &key) {
                match_path(&pattern, value, &mut out)?;
            } else if !pattern.iter().any(|p| matches!(p, Part::Expr { .. })) {
                return None;
            }
        }
        Some(out)
    }
}

/// Matches path parts left to right. A simple expression captures up to the
/// next literal; two expressions in a row cannot be matched unambiguously.
fn match_path(parts: &[Part], path: &str, out: &mut HashMap<String, String>) -> Option<()> {
    // Literals may also occur in a hostname, e.g. "{target_host}-{target_port}".
    // Try complete matches, with a fixed work budget for attacker-controlled paths.
    fn walk(
        parts: &[Part],
        path: &str,
        out: &HashMap<String, String>,
        budget: &mut usize,
        strict_port: bool,
    ) -> Option<HashMap<String, String>> {
        *budget = budget.checked_sub(1 + path.len() / 64)?;
        let Some((first, rest)) = parts.split_first() else { return path.is_empty().then(|| out.clone()) };
        match first {
            Part::Literal(l) => walk(rest, path.strip_prefix(l)?, out, budget, strict_port),
            Part::Expr { vars, .. } => {
                let mut ends: Vec<usize> = match rest.first() {
                    Some(Part::Literal(l)) if !l.is_empty() => {
                        let mut positions = Vec::new();
                        let mut offset = 0;
                        while let Some(i) = path[offset..].find(l.as_str()) {
                            positions.push(offset + i);
                            offset += i + 1;
                        }
                        positions
                    }
                    None => vec![path.len()],
                    _ => return None,
                };
                ends.reverse();
                for end in ends {
                    let mut next = out.clone();
                    let captured = &path[..end];
                    if !captured.is_empty() {
                        let values: Vec<_> = captured.split(',').collect();
                        if values.iter().any(|v| !v.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~%".contains(&b)))
                        {
                            continue;
                        }
                        if values.len() > vars.len() {
                            continue;
                        }
                        let mut values = values.into_iter().peekable();
                        let mut valid = true;
                        for (i, name) in vars.iter().enumerate() {
                            let required = |v: &String| v == "target_host" || v == "target_port";
                            let remaining_required = vars[i..].iter().filter(|v| required(v)).count();
                            if !required(name) && values.len() <= remaining_required {
                                continue;
                            }
                            let Some(value) = values.next().and_then(decode) else {
                                valid = false;
                                break;
                            };
                            if strict_port && name == "target_port" && value.parse::<u16>().map_or(true, |p| p == 0) {
                                valid = false;
                                break;
                            }
                            if next.get(name).is_some_and(|old| old != &value) {
                                valid = false;
                                break;
                            }
                            next.insert(name.clone(), value);
                        }
                        if !valid || values.next().is_some() {
                            continue;
                        }
                    }
                    if let Some(found) = walk(rest, &path[end..], &next, budget, strict_port) {
                        return Some(found);
                    }
                }
                None
            }
        }
    }
    // Still return structurally matching malformed targets for a 400 response.
    *out = walk(parts, path, out, &mut 4096, true).or_else(|| walk(parts, path, out, &mut 4096, false))?;
    Some(())
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
    fn query_literals_around_variables_round_trip() {
        for raw in [
            "/udp?h=prefix-{target_host}&p={target_port}",
            "/udp?h={target_host}-suffix&p={target_port}",
            "/udp?h=prefix-{target_host}-suffix&p={target_port}&tag=fixed",
            "/udp?pair={target_host,target_port}",
        ] {
            let tpl = UriTemplate::parse_path(raw).unwrap();
            let path = tpl.expand(&[("target_host", "example.com"), ("target_port", "443")]);
            let matched = tpl.matches(&path).unwrap();
            assert_eq!(vars(&matched), ("example.com", "443"), "{path}");
        }
        assert!(UriTemplate::parse_path("/udp{?target_host,target_port}")
            .unwrap()
            .matches("/udp?target_host=%zz&target_port=443")
            .is_none());
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

    #[test]
    fn separators_inside_hosts_and_optional_variables_round_trip() {
        for path in [
            "/udp/{target_host}-{target_port}/",
            "/udp/{target_port}-{target_host}/",
            "/udp/{target_host}aa{target_port}/",
            "/udp/{ignored,target_host,target_port}/",
            "/udp/{target_host,ignored,target_port}/",
            "/udp/{target_host}/{target_port}/{target_host}",
            "/udp?h={target_host}-{target_port}",
        ] {
            let tpl = UriTemplate::parse_path(path).unwrap();
            for host in ["some-host.example", "aaa", "a-123-456.example", "::1"] {
                let expanded = tpl.expand(&[("target_host", host), ("target_port", "53")]);
                assert_eq!(vars(&tpl.matches(&expanded).unwrap()), (host, "53"), "{path} => {expanded}");
            }
        }
        let tpl = UriTemplate::parse_path("/udp/{target_host}/{target_port}/{target_host}").unwrap();
        assert!(tpl.matches("/udp/first.example/53/second.example").is_none());
    }

    #[test]
    fn templates_that_cannot_be_matched_back_are_rejected() {
        for ok in [
            "/.well-known/masque/udp/{target_host}/{target_port}/",
            "/masque?h={target_host}&p={target_port}",
            "/masque{?target_host,target_port}",
            "/udp/{target_host}-{target_port}/",
            "/udp?h=prefix-{target_host}-suffix&p={target_port}&tag=fixed",
        ] {
            UriTemplate::parse_path(ok).unwrap().check_round_trip().unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in ["/udp?{target_host}&p={target_port}", "/udp/{target_host}{target_port}/"] {
            assert!(UriTemplate::parse_path(bad).unwrap().check_round_trip().is_err(), "{bad}");
        }
    }

    #[test]
    fn invalid_endpoints_are_rejected_but_escaped_literals_are_allowed() {
        for raw in [
            "1https://example.org/udp",
            "https://user@example.org/udp",
            "https://example.org/udp#fragment",
            "https://example.org/udp/%",
            "https://example.org/udp/%gg",
            "https://example.org/udp/<bad>",
        ] {
            assert!(UriTemplate::parse(raw).is_err(), "{raw}");
        }
        assert!(UriTemplate::parse("https://example.org/udp/%FF/%00").is_ok());
    }
}
