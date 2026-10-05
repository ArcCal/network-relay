//! The website that visitors without valid credentials see.
//!
//! Every request that is not an authenticated proxy request gets the same
//! answers as any other visitor of the site: files from the configured
//! directory, and the site's `index.html` for every path that has no file,
//! as single-page applications commonly do. A failed proxy request is
//! therefore indistinguishable from a request for any other missing page.
//! RFC 9110 §15.5.5 lets a server answer this way instead of revealing a
//! resource it wants to hide.
//!
//! Paths under `/.well-known/` are the exception: they have registered
//! meanings (RFC 8615), and clients such as Apple devices fetch
//! `/.well-known/pvd` from a relay to look for proxy configuration. Serving
//! the index page there would look like a malformed answer, so a missing
//! well-known file is a plain 404.
//!
//! The directory is read into memory when the server starts or reloads, so
//! requests can never reach files outside it.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use http::header::{
    HeaderName, HeaderValue, ALLOW, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, LAST_MODIFIED, REFERRER_POLICY,
    X_CONTENT_TYPE_OPTIONS,
};
use http::{Method, StatusCode};

const MAX_FILES: usize = 1000;
const MAX_TOTAL_BYTES: u64 = 64 << 20;

struct StaticFile {
    body: Bytes,
    content_type: &'static str,
    cache_control: &'static str,
    last_modified: HeaderValue,
}

/// A static website held in memory.
pub struct Website {
    files: HashMap<String, StaticFile>,
    headers: Vec<(HeaderName, HeaderValue)>,
}

/// A response that does not reveal the proxy.
#[derive(Debug)]
pub struct Cover {
    pub status: StatusCode,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body: Bytes,
}

impl Website {
    /// Reads every file under `root`, which must contain `index.html`.
    /// `extra_headers` are added to every response, for example a
    /// Content-Security-Policy.
    pub fn load(root: &Path, extra_headers: &BTreeMap<String, String>) -> Result<Self> {
        let root = root.canonicalize().with_context(|| format!("resolving website {}", root.display()))?;
        let mut files = HashMap::new();
        let mut total = 0u64;
        read_dir(&root, &root, &mut files, &mut total)
            .with_context(|| format!("reading website {}", root.display()))?;
        ensure!(files.contains_key("index.html"), "website {} has no index.html", root.display());
        let mut headers = vec![
            (X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")),
            (REFERRER_POLICY, HeaderValue::from_static("no-referrer")),
        ];
        for (name, value) in extra_headers {
            let name = HeaderName::try_from(name.as_str()).with_context(|| format!("invalid header name {name:?}"))?;
            ensure!(
                !matches!(
                    name.as_str(),
                    "content-length"
                        | "transfer-encoding"
                        | "connection"
                        | "upgrade"
                        | "keep-alive"
                        | "proxy-connection"
                        | "te"
                        | "trailer"
                ),
                "web.headers cannot override HTTP framing field {name}"
            );
            let value = HeaderValue::try_from(value.as_str()).with_context(|| format!("invalid value for {name}"))?;
            headers.retain(|(n, _)| *n != name);
            headers.push((name, value));
        }
        Ok(Self { files, headers })
    }

    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    fn index(&self) -> &StaticFile {
        &self.files["index.html"]
    }

    /// The file for a request path, `index.html` when there is none, or
    /// `None` for a missing well-known file.
    fn lookup(&self, path: &str) -> Option<&StaticFile> {
        let Some(key) = normalize(path) else { return Some(self.index()) };
        if let Some(f) = self.files.get(&key) {
            return Some(f);
        }
        let dir_index = if key.is_empty() { "index.html".to_string() } else { format!("{key}/index.html") };
        if let Some(f) = self.files.get(&dir_index) {
            return Some(f);
        }
        (key != ".well-known" && !key.starts_with(".well-known/")).then(|| self.index())
    }

    fn not_found(&self) -> Cover {
        let mut headers =
            vec![(CONTENT_LENGTH, HeaderValue::from(0)), (CACHE_CONTROL, HeaderValue::from_static("no-cache"))];
        self.add_headers(&mut headers);
        Cover { status: StatusCode::NOT_FOUND, headers, body: Bytes::new() }
    }

    fn respond(&self, status: StatusCode, file: &StaticFile, with_body: bool) -> Cover {
        let mut headers = vec![
            (CONTENT_TYPE, HeaderValue::from_static(file.content_type)),
            (CONTENT_LENGTH, HeaderValue::from(file.body.len())),
            (CACHE_CONTROL, HeaderValue::from_static(file.cache_control)),
            (LAST_MODIFIED, file.last_modified.clone()),
        ];
        self.add_headers(&mut headers);
        Cover { status, headers, body: if with_body { file.body.clone() } else { Bytes::new() } }
    }

    fn add_headers(&self, headers: &mut Vec<(HeaderName, HeaderValue)>) {
        for (name, value) in &self.headers {
            headers.retain(|(old, _)| old != name);
            headers.push((name.clone(), value.clone()));
        }
    }
}

/// The answer to a request that is not an authenticated proxy request.
/// `connect` marks CONNECT requests (including extended CONNECT):
/// a 2xx response to those would mean "tunnel established" (RFC 9110
/// §9.3.6), so they get the page with 404 instead.
pub fn cover(site: Option<&Website>, method: &Method, path: &str, connect: bool) -> Cover {
    let Some(site) = site else {
        return Cover {
            status: StatusCode::NOT_FOUND,
            headers: vec![(CONTENT_LENGTH, HeaderValue::from(0))],
            body: Bytes::new(),
        };
    };
    if connect || *method == Method::CONNECT {
        return site.respond(StatusCode::NOT_FOUND, site.index(), true);
    }
    match *method {
        Method::GET | Method::HEAD => match site.lookup(path) {
            Some(file) => site.respond(StatusCode::OK, file, *method == Method::GET),
            None => site.not_found(),
        },
        _ => {
            let mut c = site.respond(StatusCode::METHOD_NOT_ALLOWED, site.index(), true);
            c.headers.push((ALLOW, HeaderValue::from_static("GET, HEAD")));
            c
        }
    }
}

/// Turns a request path into a relative file name: percent-decoded, without
/// the query, `.` or empty segments. `None` for paths that try to leave the
/// directory or are not UTF-8.
fn normalize(path: &str) -> Option<String> {
    let path = path.split(['?', '#']).next().unwrap_or("");
    let decoded = percent_decode(path)?;
    let mut parts = Vec::new();
    for segment in decoded.split('/') {
        match segment {
            "" | "." => {}
            ".." => return None,
            s => parts.push(s),
        }
    }
    Some(parts.join("/"))
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok()?;
            if let Ok(b) = u8::from_str_radix(hex, 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).ok()
}

fn read_dir(root: &Path, dir: &Path, files: &mut HashMap<String, StaticFile>, total: &mut u64) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("listing {}", dir.display()))? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else { continue };
        // Dotfiles stay private, except the well-known directory (RFC 8615).
        if name.starts_with('.') && !(dir == root && name == ".well-known") {
            continue;
        }
        let path = entry.path();
        let meta = match std::fs::metadata(&path) {
            Ok(meta) => meta,
            // A dangling or looping symlink is not part of the site, and
            // must not keep the rest of it from loading.
            Err(_) if entry.file_type().is_ok_and(|t| t.is_symlink()) => continue,
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        if meta.is_dir() {
            // Following directory symlinks could loop.
            if !entry.file_type()?.is_symlink() {
                read_dir(root, &path, files, total)?;
            }
            continue;
        }
        if !meta.is_file() {
            continue;
        }
        let resolved = path.canonicalize()?;
        let Ok(relative) = resolved.strip_prefix(root) else { continue };
        if relative.components().enumerate().any(|(i, c)| {
            let name = c.as_os_str().to_string_lossy();
            name.starts_with('.') && !(i == 0 && name == ".well-known")
        }) {
            continue;
        }
        if files.len() >= MAX_FILES {
            bail!("more than {MAX_FILES} files");
        }
        if meta.len() > MAX_TOTAL_BYTES - *total {
            bail!("more than {} MiB of files", MAX_TOTAL_BYTES >> 20);
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&resolved)?;
        ensure!(file.metadata()?.is_file(), "{} is no longer a regular file", path.display());
        let mut body = Vec::new();
        file.take(MAX_TOTAL_BYTES - *total + 1)
            .read_to_end(&mut body)
            .with_context(|| format!("reading {}", path.display()))?;
        *total += body.len() as u64;
        ensure!(*total <= MAX_TOTAL_BYTES, "more than {} MiB of files", MAX_TOTAL_BYTES >> 20);
        let rel = path.strip_prefix(root).expect("under root");
        let key = rel.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/");
        let modified: DateTime<Utc> = meta.modified().map(DateTime::from).unwrap_or_else(|_| Utc::now());
        let last_modified = HeaderValue::try_from(modified.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
            .expect("date is a valid header value");
        let (content_type, cache_control) = file_type(&key);
        files.insert(key, StaticFile { body: body.into(), content_type, cache_control, last_modified });
    }
    Ok(())
}

/// Content type and caching by file extension. Pages and manifests are
/// revalidated on every visit so edits show up at once.
fn file_type(name: &str) -> (&'static str, &'static str) {
    const REVALIDATE: &str = "no-cache";
    const DAY: &str = "public, max-age=86400";
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "html" | "htm" => ("text/html; charset=utf-8", REVALIDATE),
        "json" => ("application/json", REVALIDATE),
        "webmanifest" => ("application/manifest+json", REVALIDATE),
        "css" => ("text/css; charset=utf-8", DAY),
        "js" | "mjs" => ("text/javascript; charset=utf-8", DAY),
        "txt" => ("text/plain; charset=utf-8", DAY),
        "xml" => ("application/xml", DAY),
        "svg" => ("image/svg+xml", DAY),
        "png" => ("image/png", DAY),
        "jpg" | "jpeg" => ("image/jpeg", DAY),
        "gif" => ("image/gif", DAY),
        "webp" => ("image/webp", DAY),
        "avif" => ("image/avif", DAY),
        "ico" => ("image/x-icon", DAY),
        "woff" => ("font/woff", DAY),
        "woff2" => ("font/woff2", DAY),
        "pdf" => ("application/pdf", DAY),
        // Configuration profiles: Safari offers to install them.
        "mobileconfig" => ("application/x-apple-aspen-config", "no-store"),
        "wasm" => ("application/wasm", DAY),
        _ => ("application/octet-stream", DAY),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Site(std::path::PathBuf);

    impl Site {
        fn new(tag: &str) -> Self {
            let d = std::env::temp_dir().join(format!("relay-web-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(d.join("docs")).unwrap();
            std::fs::write(d.join("index.html"), "<h1>home</h1>").unwrap();
            std::fs::write(d.join("icon.png"), [0x89, b'P', b'N', b'G']).unwrap();
            std::fs::write(d.join("docs/index.html"), "<h1>docs</h1>").unwrap();
            std::fs::write(d.join(".secret"), "hidden").unwrap();
            Self(d)
        }
    }

    impl Drop for Site {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn header(c: &Cover, name: HeaderName) -> Option<&str> {
        c.headers.iter().find(|(n, _)| *n == name).map(|(_, v)| v.to_str().unwrap())
    }

    #[test]
    fn serves_files_and_falls_back_to_the_index() {
        let s = Site::new("serve");
        let mut extra = BTreeMap::new();
        extra.insert("Content-Security-Policy".to_string(), "default-src 'self'".to_string());
        let site = Website::load(&s.0, &extra).unwrap();
        assert_eq!(site.file_count(), 3, "dotfiles are skipped");

        let get = |path: &str| cover(Some(&site), &Method::GET, path, false);
        let home = get("/");
        assert_eq!((home.status, &home.body[..]), (StatusCode::OK, &b"<h1>home</h1>"[..]));
        assert_eq!(header(&home, CONTENT_TYPE), Some("text/html; charset=utf-8"));
        assert_eq!(header(&home, CONTENT_LENGTH), Some("13"));
        assert_eq!(header(&home, HeaderName::from_static("content-security-policy")), Some("default-src 'self'"));
        assert_eq!(header(&get("/icon.png"), CONTENT_TYPE), Some("image/png"));
        assert_eq!(file_type("x.mobileconfig"), ("application/x-apple-aspen-config", "no-store"));
        assert_eq!(&get("/docs/").body[..], b"<h1>docs</h1>");
        assert_eq!(&get("/docs").body[..], b"<h1>docs</h1>");
        assert_eq!(&get("/%64ocs/index.html?x=1").body[..], b"<h1>docs</h1>");
        for missing in ["/nope", "/.secret", "/../etc/passwd", "/docs/../../x", "/.well-knownx"] {
            let c = get(missing);
            assert_eq!((c.status, &c.body[..]), (StatusCode::OK, &b"<h1>home</h1>"[..]), "{missing}");
        }
        for well_known in ["/.well-known/pvd", "/.well-known/", "/%2Ewell-known/masque/udp/192.0.2.4/53/"] {
            let c = get(well_known);
            assert_eq!((c.status, c.body.len()), (StatusCode::NOT_FOUND, 0), "{well_known}");
            assert_eq!(header(&c, HeaderName::from_static("content-security-policy")), Some("default-src 'self'"));
        }

        let head = cover(Some(&site), &Method::HEAD, "/icon.png", false);
        assert_eq!((head.status, head.body.len(), header(&head, CONTENT_LENGTH)), (StatusCode::OK, 0, Some("4")));

        let connect = cover(Some(&site), &Method::CONNECT, "/.well-known/masque/udp/192.0.2.1/443/", true);
        assert_eq!((connect.status, &connect.body[..]), (StatusCode::NOT_FOUND, &b"<h1>home</h1>"[..]));

        let post = cover(Some(&site), &Method::POST, "/", false);
        assert_eq!(post.status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(header(&post, ALLOW), Some("GET, HEAD"));
    }

    #[test]
    fn without_a_site_everything_is_not_found() {
        for (method, connect) in [(Method::GET, false), (Method::CONNECT, true), (Method::POST, false)] {
            let c = cover(None, &method, "/", connect);
            assert_eq!((c.status, c.body.len()), (StatusCode::NOT_FOUND, 0));
        }
    }

    #[test]
    fn a_site_needs_an_index() {
        let s = Site::new("noindex");
        std::fs::remove_file(s.0.join("index.html")).unwrap();
        assert!(Website::load(&s.0, &BTreeMap::new()).is_err());
        let mut bad = BTreeMap::new();
        bad.insert("bad header".to_string(), "x".to_string());
        std::fs::write(s.0.join("index.html"), "x").unwrap();
        assert!(Website::load(&s.0, &bad).is_err());
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(normalize("/a%20b/c").as_deref(), Some("a b/c"));
        assert_eq!(normalize("/%zz").as_deref(), Some("%zz"));
        assert_eq!(normalize("/%").as_deref(), Some("%"));
        assert_eq!(normalize("/%ff"), None, "not UTF-8");
        assert_eq!(normalize("//./a//b/"), Some("a/b".into()));
    }

    #[test]
    fn file_symlinks_cannot_expose_private_files() {
        use std::os::unix::fs::symlink;
        let site = Site::new("symlinks");
        let outside = Site::new("outside");
        std::fs::write(site.0.join(".secret"), "private").unwrap();
        std::fs::write(outside.0.join("secret"), "outside").unwrap();
        symlink(outside.0.join("secret"), site.0.join("external.txt")).unwrap();
        symlink(site.0.join(".secret"), site.0.join("private.txt")).unwrap();
        symlink(site.0.join("index.html"), site.0.join("public.html")).unwrap();
        symlink(site.0.join("missing"), site.0.join("dangling.html")).unwrap();
        symlink("loop-b", site.0.join("loop-a")).unwrap();
        symlink("loop-a", site.0.join("loop-b")).unwrap();
        let loaded = Website::load(&site.0, &BTreeMap::new()).unwrap();
        assert!(!loaded.files.contains_key("external.txt"));
        assert!(!loaded.files.contains_key("private.txt"));
        assert!(loaded.files.contains_key("public.html"));
        assert!(!loaded.files.contains_key("dangling.html"), "a broken link does not stop the site loading");
    }

    #[test]
    fn extra_headers_cannot_break_http_framing_and_override_once() {
        let site = Site::new("headers");
        for header in ["Content-Length", "Transfer-Encoding", "Connection", "Upgrade", "Keep-Alive", "TE", "Trailer"] {
            let headers = BTreeMap::from([(header.into(), "1".into())]);
            assert!(Website::load(&site.0, &headers).is_err(), "{header}");
        }
        let headers = BTreeMap::from([("Cache-Control".into(), "private".into())]);
        let loaded = Website::load(&site.0, &headers).unwrap();
        let response = cover(Some(&loaded), &Method::GET, "/", false);
        let values: Vec<_> = response.headers.iter().filter(|(k, _)| k == CACHE_CONTROL).collect();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].1, "private");
    }
}
