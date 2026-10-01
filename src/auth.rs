//! Username and password authentication.
//!
//! Apple devices send the header fields configured in the relay profile
//! (`AdditionalHTTPHeaderFields`) with every CONNECT request, so the profile
//! carries an `Authorization` header with HTTP Basic credentials (RFC 7617).
//! Classic HTTP proxy clients such as curl send the same credentials in
//! `Proxy-Authorization` (RFC 9110 §11.7.2); both are accepted. The TLS
//! connection protects the password. The server stores only Argon2id hashes
//! (RFC 9106) in PHC string format.
//!
//! A device opens a relayed connection for almost every connection an app
//! makes, each a new request with the same credentials, and verifying an
//! Argon2id hash takes tens of milliseconds. Results are therefore cached
//! for a while, keyed by a keyed hash of the header value so the cache holds
//! no passwords.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, ensure, Result};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::{watch, Semaphore};

use crate::config::UserEntry;

/// Shortest password `network-relay passwd` accepts from the user.
pub const MIN_PASSWORD_LEN: usize = 12;

/// How long a verified header is trusted without hashing again.
const CACHE_TTL: Duration = Duration::from_secs(600);
/// How long a rejected header is rejected without hashing again, so a device
/// with a wrong password cannot keep the server busy.
const NEGATIVE_TTL: Duration = Duration::from_secs(60);
/// Most cached headers; beyond that the cache starts over.
const CACHE_MAX: usize = 4096;

/// User names appear in logs and must not contain `:`, which separates the
/// name from the password in Basic credentials.
pub fn validate_user_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            && !name.starts_with('.'),
        "user name must be 1-64 characters of letters, digits, '-', '_' or '.', and not start with '.'"
    );
    Ok(())
}

/// The Authorization header value for Basic credentials.
pub fn basic_authorization(username: &str, password: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{username}:{password}")))
}

/// Parses a Basic Authorization header value into user name and password.
pub fn parse_basic(value: &[u8]) -> Option<(String, String)> {
    let value = std::str::from_utf8(value).ok()?.trim();
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = STANDARD.decode(token.trim()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (user, password) = decoded.split_once(':')?;
    Some((user.to_string(), password.to_string()))
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    SystemRandom::new().fill(&mut b).expect("system RNG");
    b
}

/// A random password with 144 bits of entropy: out of reach of online
/// guessing, so the server needs no lockout.
pub fn generate_password() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<18>())
}

/// Argon2id hash of `password` with the argon2 crate's default parameters
/// (19 MiB, 2 passes, 1 lane: the OWASP recommendation).
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::encode_b64(&random_bytes::<16>()).map_err(|e| anyhow!("salt: {e}"))?;
    let hash = Argon2::default().hash_password(password.as_bytes(), &salt).map_err(|e| anyhow!("hashing: {e}"))?;
    Ok(hash.to_string())
}

/// Checks that a configured hash is an Argon2id PHC string.
pub fn validate_hash(hash: &str) -> Result<()> {
    let parsed = PasswordHash::new(hash).map_err(|e| anyhow!("not a valid password hash ({e})"))?;
    ensure!(parsed.algorithm.as_str() == "argon2id", "password hash must use argon2id");
    ensure!(parsed.salt.is_some() && parsed.hash.is_some(), "password hash needs a salt and output");
    if let Some(version) = parsed.version {
        argon2::Version::try_from(version).map_err(|e| anyhow!("invalid Argon2 version: {e}"))?;
    }
    argon2::Params::try_from(&parsed).map_err(|e| anyhow!("invalid Argon2 parameters: {e}"))?;
    Ok(())
}

fn verify_hash(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|h| Argon2::default().verify_password(password.as_bytes(), &h).is_ok())
}

/// An authenticated user, as the tunnel records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub name: String,
    /// The hash the user authenticated against; a reload that changes it
    /// ends the user's tunnels.
    pub hash: String,
}

struct Cached {
    user: Option<User>,
    until: Instant,
}

type CacheTag = [u8; 32];

/// Verifies credentials against the configured users.
pub struct Authenticator {
    users: RwLock<HashMap<String, String>>,
    /// Hashing takes tens of milliseconds and megabytes of memory, so the
    /// number of concurrent verifications is capped. This limits resources,
    /// it does not lock anyone out.
    slots: Arc<Semaphore>,
    /// Verified instead of a real hash for unknown user names, so the
    /// response time does not reveal which names exist.
    dummy_hash: String,
    /// Keys the cache by HMAC of the header value; random per process.
    cache_key: ring::hmac::Key,
    cache: Mutex<HashMap<CacheTag, Cached>>,
    /// One verification per header at a time: a device's burst of requests
    /// with the same new credentials waits for the first to finish.
    inflight: Mutex<HashMap<CacheTag, Arc<tokio::sync::Mutex<()>>>>,
    /// Bumped whenever the user list changes, so tunnels can check whether
    /// their user is still current.
    generation: watch::Sender<u64>,
}

/// Removes a verification entry even if the request is cancelled while waiting.
struct InflightGuard {
    auth: Arc<Authenticator>,
    tag: CacheTag,
    lock: Arc<tokio::sync::Mutex<()>>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        let mut inflight = self.auth.inflight.lock().unwrap();
        if Arc::strong_count(&self.lock) == 2 {
            inflight.remove(&self.tag);
        }
    }
}

impl Authenticator {
    pub fn new(users: &[UserEntry]) -> Result<Self> {
        let slots = std::thread::available_parallelism().map_or(2, |n| n.get()) * 2;
        let auth = Self {
            users: RwLock::new(HashMap::new()),
            slots: Arc::new(Semaphore::new(slots)),
            dummy_hash: hash_password(&generate_password())?,
            cache_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &random_bytes::<32>()),
            cache: Mutex::default(),
            inflight: Mutex::default(),
            generation: watch::Sender::new(0),
        };
        auth.replace(users);
        Ok(auth)
    }

    /// Installs a new user list and forgets every cached verification.
    pub fn replace(&self, users: &[UserEntry]) {
        let mut current = self.users.write().unwrap();
        *current = users.iter().map(|u| (u.name.clone(), u.password_hash.clone())).collect();
        self.cache.lock().unwrap().clear();
        self.generation.send_modify(|g| *g += 1);
    }

    /// Changes whenever the user list is replaced.
    pub fn changes(&self) -> watch::Receiver<u64> {
        self.generation.subscribe()
    }

    pub fn user_count(&self) -> usize {
        self.users.read().unwrap().len()
    }

    /// Whether `user` is still configured with the same password hash.
    pub fn is_current(&self, user: &User) -> bool {
        self.users.read().unwrap().get(&user.name) == Some(&user.hash)
    }

    fn cached(&self, tag: &CacheTag) -> Option<Option<User>> {
        // Serialize lookup with replacement and cache invalidation.
        let _users = self.users.read().unwrap();
        let cache = self.cache.lock().unwrap();
        cache.get(tag).filter(|c| c.until > Instant::now()).map(|c| c.user.clone())
    }

    fn remember(&self, tag: CacheTag, user: Option<User>) {
        let ttl = if user.is_some() { CACHE_TTL } else { NEGATIVE_TTL };
        let mut cache = self.cache.lock().unwrap();
        if cache.len() >= CACHE_MAX {
            let now = Instant::now();
            cache.retain(|_, c| c.until > now);
            if cache.len() >= CACHE_MAX {
                cache.clear();
            }
        }
        cache.insert(tag, Cached { user, until: Instant::now() + ttl });
    }

    /// Checks an Authorization or Proxy-Authorization header value. Requests
    /// without one are answered at once, like on any web server; only
    /// requests that carry credentials pay for a hash verification, and only
    /// the first time within the cache lifetime.
    pub async fn verify(self: &Arc<Self>, authorization: Option<&[u8]>) -> Option<User> {
        let header = authorization?;
        let (name, password) = parse_basic(header)?;
        let tag: CacheTag = ring::hmac::sign(&self.cache_key, header).as_ref().try_into().expect("SHA-256 size");
        if let Some(result) = self.cached(&tag) {
            return result;
        }
        let lock = {
            let mut inflight = self.inflight.lock().unwrap();
            if !inflight.contains_key(&tag) && inflight.len() >= CACHE_MAX {
                return None;
            }
            inflight.entry(tag).or_default().clone()
        };
        let cleanup = InflightGuard { auth: self.clone(), tag, lock };
        let _guard = cleanup.lock.lock().await;
        if let Some(result) = self.cached(&tag) {
            return result;
        }
        let generation = *self.generation.borrow();
        let result = self.verify_uncached(name, password).await;
        // Hold the user lock through the generation check and cache insertion:
        // replacement must not clear the cache between these two operations.
        let users = self.users.read().unwrap();
        if *self.generation.borrow() != generation
            || result.as_ref().is_some_and(|u| users.get(&u.name) != Some(&u.hash))
        {
            return None;
        }
        self.remember(tag, result.clone());
        result
    }

    async fn verify_uncached(&self, name: String, password: String) -> Option<User> {
        let known = self.users.read().unwrap().get(&name).cloned();
        let hash = known.clone().unwrap_or_else(|| self.dummy_hash.clone());
        let permit = self.slots.clone().acquire_owned().await.ok()?;
        let ok = {
            let hash = hash.clone();
            tokio::task::spawn_blocking(move || {
                // Cancellation of the HTTP request must not release the slot
                // while this non-cancellable computation is still running.
                let _permit = permit;
                verify_hash(&password, &hash)
            })
            .await
            .unwrap_or(false)
        };
        (ok && known.is_some()).then_some(User { name, hash })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(name: &str, password: &str) -> UserEntry {
        UserEntry { name: name.into(), password_hash: hash_password(password).unwrap() }
    }

    #[test]
    fn basic_header_round_trip() {
        let header = basic_authorization("laptop", "p:a ss");
        assert!(header.starts_with("Basic "));
        assert_eq!(parse_basic(header.as_bytes()), Some(("laptop".into(), "p:a ss".into())));
        // RFC 7617 example.
        assert_eq!(parse_basic(b"Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="), Some(("Aladdin".into(), "open sesame".into())));
        assert_eq!(parse_basic(b"basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==").unwrap().0, "Aladdin");
        for bad in [&b"Bearer abc"[..], b"Basic", b"Basic !!!", b"Basic bm9jb2xvbg==", b"\xff\xfe"] {
            assert_eq!(parse_basic(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn hashes_are_argon2id_and_verify() {
        let hash = hash_password("correct horse").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        validate_hash(&hash).unwrap();
        assert!(verify_hash("correct horse", &hash));
        assert!(!verify_hash("wrong horse", &hash));
        assert!(validate_hash("plaintext").is_err());
        assert!(validate_hash("$argon2id$v=19$m=19456,t=2,p=1").is_err());
        assert!(validate_hash(&hash.replace("v=19", "v=99")).is_err());
        assert!(validate_hash(&hash.replace("p=1", "p=0")).is_err());
        assert!(validate_hash("$argon2i$v=19$m=16,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo").is_err());
    }

    #[test]
    fn generated_passwords_are_long_and_distinct() {
        let a = generate_password();
        assert_eq!(a.len(), 24);
        assert_ne!(a, generate_password());
        assert!(a.len() >= MIN_PASSWORD_LEN);
    }

    #[test]
    fn user_names_are_checked() {
        validate_user_name("laptop-1.home_x").unwrap();
        for bad in ["", "a:b", ".hidden", "with space", &"x".repeat(65)] {
            assert!(validate_user_name(bad).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn removal_during_verification_rejects_the_old_user() {
        use std::future::Future;
        use std::task::Poll;
        let auth = Arc::new(Authenticator::new(&[user("alice", "alice-password")]).unwrap());
        let header = basic_authorization("alice", "alice-password");
        let mut verification = Box::pin(auth.verify(Some(header.as_bytes())));
        std::future::poll_fn(|cx| {
            assert!(verification.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        auth.replace(&[]);
        assert!(verification.await.is_none());
        assert!(auth.cache.lock().unwrap().is_empty());
        assert!(auth.inflight.lock().unwrap().is_empty());
    }

    #[test]
    fn cancelled_verification_cleans_up_and_keeps_hash_slot() {
        use std::future::Future;
        use std::task::Poll;
        // Keep the sole blocking worker occupied so the assertion cannot race
        // with a fast hash computation completing on another thread.
        let runtime = tokio::runtime::Builder::new_current_thread().max_blocking_threads(1).build().unwrap();
        let (started, ready) = std::sync::mpsc::channel();
        let (release, waiting) = std::sync::mpsc::channel();
        let blocker = runtime.spawn_blocking(move || {
            started.send(()).unwrap();
            let _ = waiting.recv();
        });
        ready.recv().unwrap();
        runtime.block_on(async {
            let auth = Arc::new(Authenticator::new(&[user("alice", "alice-password")]).unwrap());
            let slots = auth.slots.available_permits();
            let header = basic_authorization("alice", "alice-password");
            let mut verification = Box::pin(auth.verify(Some(header.as_bytes())));
            std::future::poll_fn(|cx| {
                assert!(verification.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            drop(verification);
            assert!(auth.inflight.lock().unwrap().is_empty());
            assert_eq!(auth.slots.available_permits(), slots - 1);
            release.send(()).unwrap();
            blocker.await.unwrap();
            let _permit = auth.slots.clone().acquire_many_owned(slots as u32).await.unwrap();
        });
    }

    #[tokio::test]
    async fn authenticator_accepts_only_configured_credentials() {
        let auth = Arc::new(Authenticator::new(&[user("alice", "alice-password")]).unwrap());
        let ok = auth.verify(Some(basic_authorization("alice", "alice-password").as_bytes())).await.unwrap();
        assert_eq!(ok.name, "alice");
        assert!(auth.is_current(&ok));
        assert!(auth.verify(Some(basic_authorization("alice", "nope").as_bytes())).await.is_none());
        assert!(auth.verify(Some(basic_authorization("mallory", "alice-password").as_bytes())).await.is_none());
        assert!(auth.verify(None).await.is_none());
        // A new password hash makes old tunnels stale, and clears the cache.
        let changes = auth.changes();
        auth.replace(&[user("alice", "alice-password")]);
        assert!(changes.has_changed().unwrap());
        assert!(!auth.is_current(&ok));
        auth.replace(&[]);
        assert!(auth.verify(Some(basic_authorization("alice", "alice-password").as_bytes())).await.is_none());
        assert_eq!(auth.user_count(), 0);
    }

    #[tokio::test]
    async fn verifications_are_cached() {
        let auth = Arc::new(Authenticator::new(&[user("alice", "alice-password")]).unwrap());
        let good = basic_authorization("alice", "alice-password");
        let bad = basic_authorization("alice", "wrong");
        let first = std::time::Instant::now();
        assert!(auth.verify(Some(good.as_bytes())).await.is_some());
        let uncached = first.elapsed();
        let second = std::time::Instant::now();
        for _ in 0..20 {
            assert!(auth.verify(Some(good.as_bytes())).await.is_some());
        }
        assert!(second.elapsed() < uncached, "20 cached checks should beat one hash");
        assert!(auth.verify(Some(bad.as_bytes())).await.is_none());
        assert!(auth.verify(Some(bad.as_bytes())).await.is_none());
        assert_eq!(auth.cache.lock().unwrap().len(), 2);
        assert!(auth.inflight.lock().unwrap().is_empty());
        auth.replace(&[user("alice", "wrong")]);
        assert!(auth.cache.lock().unwrap().is_empty());
        assert!(auth.verify(Some(bad.as_bytes())).await.is_some(), "the new password works at once");
        assert!(auth.verify(Some(good.as_bytes())).await.is_none(), "the old one stops working at once");
    }

    #[tokio::test]
    async fn a_burst_of_requests_hashes_once() {
        let auth = Arc::new(Authenticator::new(&[user("alice", "alice-password")]).unwrap());
        let good = basic_authorization("alice", "alice-password");
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let (auth, good) = (auth.clone(), good.clone());
                tokio::spawn(async move { auth.verify(Some(good.as_bytes())).await.is_some() })
            })
            .collect();
        for t in tasks {
            assert!(t.await.unwrap());
        }
        assert_eq!(auth.cache.lock().unwrap().len(), 1);
    }
}
