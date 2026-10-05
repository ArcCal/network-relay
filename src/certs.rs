//! The server's TLS certificate, read from files such as those a Let's
//! Encrypt client writes, and reloaded on a schedule so that a renewed
//! certificate takes effect without a restart. Connections already
//! established keep the certificate they started with.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Days, Local, LocalResult, NaiveTime, TimeZone, Utc};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tracing::{error, info, warn};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::tls;

/// Retry interval after a failed reload.
const RETRY_AFTER: Duration = Duration::from_secs(3600);
/// Warn when the certificate in use expires sooner than this.
const EXPIRY_WARNING_DAYS: i64 = 14;

/// A certificate chain with its key, checked to belong together.
struct Loaded {
    key: Arc<CertifiedKey>,
    names: Vec<String>,
    not_before: i64,
    not_after: i64,
}

impl Loaded {
    fn read(cert: &Path, key: &Path) -> Result<Self> {
        let chain = tls::load_certs(cert)?;
        let (names, not_before, not_after) = describe(chain[0].as_ref())
            .with_context(|| format!("parsing the first certificate in {}", cert.display()))?;
        let key_der = tls::load_key(key)?;
        let certified = CertifiedKey::from_der(chain, key_der, &tls::provider()).with_context(|| {
            format!("{} does not hold the private key of the certificate in {}", key.display(), cert.display())
        })?;
        Ok(Self { key: Arc::new(certified), names, not_before, not_after })
    }

    fn check_validity(&self, now: i64) -> Result<()> {
        if now < self.not_before {
            bail!("the certificate is not valid until {}", format_time(self.not_before));
        }
        if now >= self.not_after {
            bail!("the certificate expired on {}", format_time(self.not_after));
        }
        Ok(())
    }

    fn summary(&self, now: i64) -> String {
        let days = (self.not_after - now).div_euclid(86_400);
        format!("{}, valid until {} ({days} days)", self.names.join(" "), format_time(self.not_after))
    }

    fn warn_if_expiring(&self, now: i64) {
        let days = (self.not_after - now).div_euclid(86_400);
        if (0..EXPIRY_WARNING_DAYS).contains(&days) {
            warn!("the TLS certificate expires in {days} days ({}); renew it", format_time(self.not_after));
        }
    }
}

/// Names (DNS and IP subject alternative names) and validity of a DER
/// certificate.
fn describe(der: &[u8]) -> Result<(Vec<String>, i64, i64)> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut names = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(n) => names.push(n.to_string()),
                GeneralName::IPAddress(ip) => match ip.len() {
                    4 => names.push(std::net::Ipv4Addr::from(<[u8; 4]>::try_from(*ip).unwrap()).to_string()),
                    16 => names.push(std::net::Ipv6Addr::from(<[u8; 16]>::try_from(*ip).unwrap()).to_string()),
                    _ => {}
                },
                _ => {}
            }
        }
    }
    if names.is_empty() {
        names.push(cert.subject().to_string());
    }
    let validity = cert.validity();
    Ok((names, validity.not_before.timestamp(), validity.not_after.timestamp()))
}

fn format_time(unix: i64) -> String {
    DateTime::<Utc>::from_timestamp(unix, 0)
        .map_or_else(|| unix.to_string(), |t| t.format("%Y-%m-%d %H:%M UTC").to_string())
}

fn now_unix() -> i64 {
    Utc::now().timestamp()
}

/// Serves the current certificate to every TLS handshake, over QUIC and TCP.
pub struct CertStore {
    cert: PathBuf,
    key: PathBuf,
    current: RwLock<Arc<CertifiedKey>>,
}

impl fmt::Debug for CertStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertStore").field("cert", &self.cert).field("key", &self.key).finish_non_exhaustive()
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.read().unwrap().clone())
    }
}

impl CertStore {
    /// Loads the certificate at start-up. An unreadable certificate is
    /// fatal; an expired one is only logged, so that a scheduled reload can
    /// pick up its renewal later.
    pub fn open(cert: &Path, key: &Path) -> Result<Arc<Self>> {
        let loaded = Loaded::read(cert, key)?;
        let now = now_unix();
        match loaded.check_validity(now) {
            Ok(()) => info!("TLS certificate: {}", loaded.summary(now)),
            Err(e) => error!("serving an unusable TLS certificate from {}: {e:#}", cert.display()),
        }
        loaded.warn_if_expiring(now);
        Ok(Arc::new(Self { cert: cert.to_path_buf(), key: key.to_path_buf(), current: RwLock::new(loaded.key) }))
    }

    /// Checks that the files hold a certificate and its key, valid now. For
    /// `serve --check`; starting the server only warns, so a scheduled
    /// reload can pick up a renewal.
    pub fn check_files(cert: &Path, key: &Path) -> Result<()> {
        let loaded = Loaded::read(cert, key)?;
        loaded.check_validity(now_unix()).with_context(|| cert.display().to_string())
    }

    /// Reads the files again and switches to them if they hold a valid
    /// certificate; otherwise keeps the current one.
    pub fn reload(&self) -> Result<()> {
        let loaded = Loaded::read(&self.cert, &self.key)?;
        let now = now_unix();
        loaded.check_validity(now)?;
        let unchanged = {
            let current = self.current.read().unwrap();
            current.cert == loaded.key.cert
        };
        *self.current.write().unwrap() = loaded.key.clone();
        if unchanged {
            info!("TLS certificate reloaded, unchanged: {}", loaded.summary(now));
        } else {
            info!("TLS certificate reloaded, now using: {}", loaded.summary(now));
        }
        loaded.warn_if_expiring(now);
        Ok(())
    }

    /// Reloads according to `schedule` forever.
    pub async fn run_schedule(self: Arc<Self>, schedule: Schedule) {
        let mut next = schedule.next_after(Local::now());
        info!("next TLS certificate reload: {}", next.format("%Y-%m-%d %H:%M %Z"));
        loop {
            sleep_until(next).await;
            match self.reload() {
                Ok(()) => next = schedule.next_after(Local::now()),
                Err(e) => {
                    warn!("TLS certificate reload failed, keeping the current certificate: {e:#}; retrying in 1 hour");
                    next = Local::now() + RETRY_AFTER;
                }
            }
        }
    }
}

/// Sleeps until a wall-clock time, checking the clock at least hourly so
/// that suspends and clock changes do not delay the wake-up.
async fn sleep_until(target: DateTime<Local>) {
    loop {
        let now = Local::now();
        if now >= target {
            return;
        }
        let wait = (target - now).to_std().unwrap_or_default().min(Duration::from_secs(3600));
        tokio::time::sleep(wait.max(Duration::from_millis(10))).await;
    }
}

/// When to reload the certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Schedule {
    /// Every N days after start-up (and after each reload).
    EveryDays(u32),
    /// Every day at 03:00 in the system time zone.
    DailyAt3,
}

impl Schedule {
    pub fn from_config(interval_days: Option<u32>) -> Self {
        interval_days.map_or(Schedule::DailyAt3, Schedule::EveryDays)
    }

    /// The first reload time after `now`.
    pub fn next_after<Tz: TimeZone>(&self, now: DateTime<Tz>) -> DateTime<Tz> {
        match *self {
            Schedule::EveryDays(n) => now + chrono::Duration::days(i64::from(n)),
            Schedule::DailyAt3 => {
                let three = NaiveTime::from_hms_opt(3, 0, 0).expect("valid time");
                let tz = now.timezone();
                let mut date = now.date_naive();
                loop {
                    let local = date.and_time(three);
                    let candidate = match tz.from_local_datetime(&local) {
                        LocalResult::Single(t) => Some(t),
                        LocalResult::Ambiguous(first, _) => Some(first),
                        // 03:00 does not exist on a daylight-saving change day
                        // in some zones; use the first valid time after it.
                        LocalResult::None => tz.from_local_datetime(&(local + chrono::Duration::hours(1))).earliest(),
                    };
                    if let Some(t) = candidate.filter(|t| *t > now) {
                        return t;
                    }
                    date = date.checked_add_days(Days::new(1)).expect("date in range");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::FixedOffset;

    use super::*;

    fn at(tz: &FixedOffset, y: i32, mo: u32, d: u32, h: u32, mi: u32) -> DateTime<FixedOffset> {
        tz.with_ymd_and_hms(y, mo, d, h, mi, 0).unwrap()
    }

    #[test]
    fn daily_reload_is_the_next_3am() {
        let tz = FixedOffset::east_opt(8 * 3600).unwrap();
        let s = Schedule::DailyAt3;
        assert_eq!(s.next_after(at(&tz, 2026, 9, 30, 1, 0)), at(&tz, 2026, 9, 30, 3, 0));
        assert_eq!(s.next_after(at(&tz, 2026, 9, 30, 3, 0)), at(&tz, 2026, 10, 1, 3, 0));
        assert_eq!(s.next_after(at(&tz, 2026, 9, 30, 23, 59)), at(&tz, 2026, 10, 1, 3, 0));
        assert_eq!(s.next_after(at(&tz, 2026, 12, 31, 4, 0)), at(&tz, 2027, 1, 1, 3, 0));
    }

    #[test]
    fn interval_reload_counts_days() {
        let tz = FixedOffset::east_opt(0).unwrap();
        assert_eq!(Schedule::EveryDays(7).next_after(at(&tz, 2026, 9, 30, 10, 15)), at(&tz, 2026, 10, 7, 10, 15));
        assert_eq!(Schedule::from_config(None), Schedule::DailyAt3);
        assert_eq!(Schedule::from_config(Some(3)), Schedule::EveryDays(3));
    }

    struct Dir(PathBuf);

    impl Dir {
        fn new(tag: &str) -> Self {
            let d = std::env::temp_dir().join(format!("relay-certs-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Self(d)
        }

        /// Writes a self-signed certificate for `name`, valid until the given
        /// year, to `cert.pem`/`key.pem` and returns its DER encoding.
        fn write(&self, name: &str, until_year: i32) -> Vec<u8> {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(vec![format!("{name}.test")]).unwrap();
            params.not_before = rcgen::date_time_ymd(2000, 1, 1);
            params.not_after = rcgen::date_time_ymd(until_year, 1, 1);
            let cert = params.self_signed(&key).unwrap();
            std::fs::write(self.0.join("cert.pem"), cert.pem()).unwrap();
            std::fs::write(self.0.join("key.pem"), key.serialize_pem()).unwrap();
            cert.der().to_vec()
        }

        fn open(&self) -> Arc<CertStore> {
            CertStore::open(&self.0.join("cert.pem"), &self.0.join("key.pem")).unwrap()
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn serving(store: &CertStore) -> Vec<u8> {
        store.current.read().unwrap().cert[0].to_vec()
    }

    #[test]
    fn reload_switches_to_a_renewed_certificate() {
        let d = Dir::new("renew");
        let first = d.write("a", 2099);
        let store = d.open();
        assert_eq!(serving(&store), first);
        let second = d.write("b", 2099);
        store.reload().unwrap();
        assert_eq!(serving(&store), second);
        store.reload().unwrap(); // unchanged files are fine too
        assert_eq!(serving(&store), second);
    }

    #[test]
    fn reload_keeps_the_current_certificate_when_the_new_one_is_unusable() {
        let d = Dir::new("bad");
        let good = d.write("a", 2099);
        let store = d.open();

        // Expired.
        d.write("old", 2001);
        assert!(store.reload().unwrap_err().to_string().contains("expired"));
        assert_eq!(serving(&store), good);

        // Key of another certificate.
        let other_key = rcgen::KeyPair::generate().unwrap().serialize_pem();
        d.write("b", 2099);
        std::fs::write(d.0.join("key.pem"), other_key).unwrap();
        assert!(store.reload().is_err());
        assert_eq!(serving(&store), good);

        // Missing file.
        std::fs::remove_file(d.0.join("cert.pem")).unwrap();
        assert!(store.reload().is_err());
        assert_eq!(serving(&store), good);
    }

    #[test]
    fn the_configuration_check_rejects_an_expired_certificate() {
        let d = Dir::new("check");
        d.write("ok", 2099);
        CertStore::check_files(&d.0.join("cert.pem"), &d.0.join("key.pem")).unwrap();
        d.write("old", 2001);
        let e = CertStore::check_files(&d.0.join("cert.pem"), &d.0.join("key.pem")).unwrap_err();
        assert!(format!("{e:#}").contains("expired"), "{e:#}");
    }

    #[test]
    fn start_up_accepts_an_expired_certificate_so_a_later_reload_can_fix_it() {
        let d = Dir::new("expired");
        d.write("old", 2001);
        let store = d.open();
        let renewed = d.write("new", 2099);
        store.reload().unwrap();
        assert_eq!(serving(&store), renewed);
    }

    #[test]
    fn names_and_validity_are_read_from_the_certificate() {
        let d = Dir::new("describe");
        let der = d.write("relay", 2099);
        let (names, not_before, not_after) = describe(&der).unwrap();
        assert_eq!(names, ["relay.test"]);
        assert!(not_before < now_unix() && now_unix() < not_after);
    }
}
