//! Logging: to stdout (the terminal or the systemd journal) and, when the
//! configuration names a log directory, also to plain-text files there.
//!
//! The current file is `<program>.log`. When a clock hour of the system
//! time zone ends, it is renamed to `<program>.<YYYY-MM-DD-HH>.log` after
//! the hour it covers and a new one is started. Renamed files are deleted
//! before any line in them is 24 hours old. Timestamps are in the system
//! time zone.
//!
//! Lines are handed to background threads for writing, so a slow journal or
//! disk never holds up request handling; if they fall far behind (a flood),
//! lines are dropped rather than queued without bound.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use chrono::{DateTime, Local, TimeDelta, Timelike};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// No line stays in the log directory longer than this.
pub const RETENTION: Duration = Duration::from_secs(24 * 3600);
/// Lines beyond this many bytes in one hour go only to stdout, so a flood
/// of requests cannot fill the disk: at most 24 × 16 MiB per program.
pub const MAX_BYTES_PER_HOUR: u64 = 16 << 20;
/// How often the files are checked while nothing is logged.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60);
/// A renamed file holds lines from at most one hour before its last write,
/// and is noticed up to one maintenance interval late.
const DELETE_AFTER: Duration = Duration::from_secs(RETENTION.as_secs() - 3600 - MAINTENANCE_INTERVAL.as_secs());
const TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S%.3f %:z";

/// Keeps the background log writers running; dropping it writes out what
/// is still buffered.
#[must_use]
pub struct LogGuard(#[allow(dead_code)] Vec<tracing_appender::non_blocking::WorkerGuard>);

/// Lines buffered per writer before new ones are dropped.
const BUFFERED_LINES: usize = 64 * 1024;

/// Sets up logging for `program` (`network-relay` or `other-program`): to
/// stdout, and with `dir` also to files there. `RUST_LOG` overrides the
/// default `info` level for both.
pub fn init(program: &'static str, dir: Option<&Path>) -> Result<LogGuard> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    // Colour only on a terminal, not in the journal or files.
    let ansi = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let mut guards = Vec::new();
    let (stdout_writer, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .buffered_lines_limit(BUFFERED_LINES)
        .lossy(true)
        .thread_name("log-stdout")
        .finish(std::io::stdout());
    guards.push(guard);
    let stdout = tracing_subscriber::fmt::layer()
        .with_timer(LocalTime)
        .with_target(false)
        .with_ansi(ansi)
        .with_writer(stdout_writer);
    let files = match dir {
        Some(dir) => {
            let log = LogFile::open(dir, program, Local::now())
                .with_context(|| format!("opening log file {}", dir.join(format!("{program}.log")).display()))?;
            let files = Files(Arc::new(Mutex::new(log)));
            let maintained = files.clone();
            std::thread::Builder::new()
                .name("log-files".into())
                .spawn(move || loop {
                    std::thread::sleep(MAINTENANCE_INTERVAL);
                    maintained.lock().maintain(Local::now());
                })
                .context("starting the log file thread")?;
            log_panics(files.clone());
            let (file_writer, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
                .buffered_lines_limit(BUFFERED_LINES)
                .lossy(true)
                .thread_name("log-files-writer")
                .finish(FileSink(files));
            guards.push(guard);
            Some(
                tracing_subscriber::fmt::layer()
                    .with_timer(LocalTime)
                    .with_target(false)
                    .with_ansi(false)
                    .with_writer(file_writer),
            )
        }
        None => None,
    };
    tracing_subscriber::registry().with(filter).with(stdout).with(files).init();
    if let Some(dir) = dir {
        tracing::info!("log files in {}, kept for at most 24 hours", dir.display());
    }
    Ok(LogGuard(guards))
}

/// Timestamps in the system time zone, with its offset.
struct LocalTime;

impl FormatTime for LocalTime {
    fn format_time(&self, w: &mut Writer<'_>) -> std::fmt::Result {
        write!(w, "{}", Local::now().format(TIME_FORMAT))
    }
}

/// Also writes panics to the log file; stdout still gets the usual message.
fn log_panics(files: Files) {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let now = Local::now();
        let thread = std::thread::current().name().unwrap_or("unnamed").to_string();
        let message = info.to_string().replace('\n', " ");
        let line = format!("{} ERROR panic in thread {thread}: {message}\n", now.format(TIME_FORMAT));
        // The panicking thread may itself hold the lock; give up rather
        // than wait forever.
        for _ in 0..100 {
            match files.0.try_lock() {
                Ok(mut log) => {
                    let _ = log.write_line(line.as_bytes(), now);
                    break;
                }
                Err(TryLockError::Poisoned(e)) => {
                    let _ = e.into_inner().write_line(line.as_bytes(), now);
                    break;
                }
                Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(1)),
            }
        }
        default(info);
    }));
}

/// The log file, shared by the tracing layer, the maintenance thread and
/// the panic hook.
#[derive(Clone)]
struct Files(Arc<Mutex<LogFile>>);

impl Files {
    fn lock(&self) -> MutexGuard<'_, LogFile> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Receives one formatted line per event from the background writer.
struct FileSink(Files);

impl Write for FileSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().write_line(buf, Local::now())?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct LogFile {
    dir: PathBuf,
    program: &'static str,
    file: File,
    /// Start of the clock hour the current file covers.
    hour: DateTime<Local>,
    /// Bytes in the current file.
    written: u64,
    /// Lines were dropped this hour because of `MAX_BYTES_PER_HOUR`.
    capped: bool,
}

impl LogFile {
    fn open(dir: &Path, program: &'static str, now: DateTime<Local>) -> io::Result<Self> {
        fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        let current = dir.join(format!("{program}.log"));
        // A file left by an earlier run is continued within the same hour
        // and renamed otherwise.
        if let Ok(meta) = fs::metadata(&current) {
            let modified = hour_start(meta.modified()?.into());
            if meta.len() > 0 && modified != hour_start(now) {
                archive(dir, program, &current, modified)?;
            }
        }
        let file = open_append(&current)?;
        let written = file.metadata()?.len();
        let log = Self { dir: dir.to_owned(), program, file, hour: hour_start(now), written, capped: false };
        log.prune(now.into());
        Ok(log)
    }

    fn current(&self) -> PathBuf {
        self.dir.join(format!("{}.log", self.program))
    }

    fn write_line(&mut self, line: &[u8], now: DateTime<Local>) -> io::Result<()> {
        // A failed rename is retried with the next line; until then lines
        // stay in the current file.
        let _ = self.rotate_if_due(now);
        if self.written + line.len() as u64 > MAX_BYTES_PER_HOUR {
            if !self.capped {
                self.capped = true;
                let note = format!(
                    "{}  WARN log file reached {} MiB this hour; until the next hour, lines go only to stdout\n",
                    now.format(TIME_FORMAT),
                    MAX_BYTES_PER_HOUR >> 20
                );
                self.file.write_all(note.as_bytes())?;
            }
            return Ok(());
        }
        self.file.write_all(line)?;
        self.written += line.len() as u64;
        Ok(())
    }

    /// Starts a new file when the clock hour of the current one is over.
    fn rotate_if_due(&mut self, now: DateTime<Local>) -> io::Result<()> {
        let hour = hour_start(now);
        if hour == self.hour {
            return Ok(());
        }
        if self.file.metadata()?.len() > 0 {
            let current = self.current();
            archive(&self.dir, self.program, &current, self.hour)?;
            self.file = open_append(&current)?;
        }
        self.hour = hour;
        self.written = 0;
        self.capped = false;
        Ok(())
    }

    /// Runs every minute, so files are renamed and deleted on time even
    /// when nothing is logged.
    fn maintain(&mut self, now: DateTime<Local>) {
        let current = self.current();
        if fs::symlink_metadata(&current).is_err() {
            // Deleted by hand: start a new one.
            if let Ok(file) = open_append(&current) {
                self.file = file;
                self.written = 0;
            }
        }
        let _ = self.rotate_if_due(now);
        self.prune(now.into());
    }

    /// Deletes renamed files before any line in them is `RETENTION` old.
    fn prune(&self, now: SystemTime) {
        let Ok(entries) = fs::read_dir(&self.dir) else { return };
        for entry in entries.flatten() {
            let name = entry.file_name();
            if !name.to_str().is_some_and(|n| is_archive_name(self.program, n)) {
                continue;
            }
            let modified = entry.metadata().and_then(|m| m.modified());
            if modified.is_ok_and(|t| now.duration_since(t).is_ok_and(|age| age >= DELETE_AFTER)) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).mode(0o600).open(path)
}

/// Start of the clock hour `t` is in.
fn hour_start(t: DateTime<Local>) -> DateTime<Local> {
    t - TimeDelta::seconds(i64::from(t.minute() * 60 + t.second())) - TimeDelta::nanoseconds(i64::from(t.nanosecond()))
}

/// Renames `current` to `<program>.<hour>.log`, or to `<program>.<hour>.<n>.log`
/// if that exists (the repeated hour when daylight saving time ends).
fn archive(dir: &Path, program: &str, current: &Path, hour: DateTime<Local>) -> io::Result<()> {
    let stamp = hour.format("%Y-%m-%d-%H");
    let mut target = dir.join(format!("{program}.{stamp}.log"));
    let mut n = 1;
    while fs::symlink_metadata(&target).is_ok() {
        target = dir.join(format!("{program}.{stamp}.{n}.log"));
        n += 1;
    }
    fs::rename(current, target)
}

/// Whether `name` is one of the renamed files `archive` makes for `program`.
fn is_archive_name(program: &str, name: &str) -> bool {
    let Some(middle) =
        name.strip_prefix(program).and_then(|s| s.strip_prefix('.')).and_then(|s| s.strip_suffix(".log"))
    else {
        return false;
    };
    let (stamp, n) = middle.split_once('.').unwrap_or((middle, "0"));
    stamp.len() == 13
        && stamp.bytes().enumerate().all(|(i, b)| if matches!(i, 4 | 7 | 10) { b == b'-' } else { b.is_ascii_digit() })
        && !n.is_empty()
        && n.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::os::unix::fs::PermissionsExt;

    const P: &str = "network-relay";

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("relay-log-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn at(h: u32, m: u32) -> DateTime<Local> {
        // In the past, so files the tests write are newer than their clock.
        Local.with_ymd_and_hms(2025, 1, 15, h, m, 0).unwrap()
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> =
            fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    }

    fn read(dir: &Path, name: &str) -> String {
        fs::read_to_string(dir.join(name)).unwrap()
    }

    fn set_modified(path: &Path, t: impl Into<SystemTime>) {
        File::options().write(true).open(path).unwrap().set_modified(t.into()).unwrap();
    }

    #[test]
    fn creates_a_private_directory_and_file() {
        let dir = temp_dir("private").join("logs");
        let mut log = LogFile::open(&dir, P, at(13, 30)).unwrap();
        log.write_line(b"hello\n", at(13, 31)).unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(dir.join("network-relay.log")).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(read(&dir, "network-relay.log"), "hello\n");
        fs::remove_dir_all(dir.parent().unwrap()).unwrap();
    }

    #[test]
    fn a_new_file_every_clock_hour() {
        let dir = temp_dir("hourly");
        let mut log = LogFile::open(&dir, P, at(13, 30)).unwrap();
        log.write_line(b"a\n", at(13, 59)).unwrap();
        log.write_line(b"b\n", at(14, 0)).unwrap();
        log.write_line(b"c\n", at(14, 59)).unwrap();
        assert_eq!(names(&dir), ["network-relay.2025-01-15-13.log", "network-relay.log"]);
        assert_eq!(read(&dir, "network-relay.2025-01-15-13.log"), "a\n");
        assert_eq!(read(&dir, "network-relay.log"), "b\nc\n");

        // Idle hours leave no empty files behind.
        log.maintain(at(15, 1));
        log.maintain(at(16, 1));
        log.write_line(b"d\n", at(16, 2)).unwrap();
        assert_eq!(
            names(&dir),
            ["network-relay.2025-01-15-13.log", "network-relay.2025-01-15-14.log", "network-relay.log"]
        );
        log.maintain(at(17, 0));
        assert_eq!(read(&dir, "network-relay.2025-01-15-16.log"), "d\n");
        assert_eq!(read(&dir, "network-relay.log"), "");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_restart_continues_the_file_of_the_same_hour_only() {
        let dir = temp_dir("restart");
        let mut log = LogFile::open(&dir, P, at(13, 10)).unwrap();
        log.write_line(b"first run\n", at(13, 10)).unwrap();
        drop(log);
        set_modified(&dir.join("network-relay.log"), at(13, 10));

        let mut log = LogFile::open(&dir, P, at(13, 40)).unwrap();
        log.write_line(b"second run\n", at(13, 40)).unwrap();
        assert_eq!(names(&dir), ["network-relay.log"]);
        assert_eq!(read(&dir, "network-relay.log"), "first run\nsecond run\n");
        drop(log);
        set_modified(&dir.join("network-relay.log"), at(13, 40));

        LogFile::open(&dir, P, at(15, 5)).unwrap();
        assert_eq!(names(&dir), ["network-relay.2025-01-15-13.log", "network-relay.log"]);
        assert_eq!(read(&dir, "network-relay.2025-01-15-13.log"), "first run\nsecond run\n");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_taken_name_gets_a_number() {
        let dir = temp_dir("taken");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("network-relay.2025-01-15-13.log"), "earlier\n").unwrap();
        let mut log = LogFile::open(&dir, P, at(13, 30)).unwrap();
        log.write_line(b"later\n", at(13, 31)).unwrap();
        log.maintain(at(14, 0));
        assert_eq!(read(&dir, "network-relay.2025-01-15-13.log"), "earlier\n");
        assert_eq!(read(&dir, "network-relay.2025-01-15-13.1.log"), "later\n");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn no_line_is_kept_for_24_hours() {
        let dir = temp_dir("prune");
        fs::create_dir_all(&dir).unwrap();
        let now = at(14, 30);
        let file = |name: &str, age_minutes: i64| {
            let path = dir.join(name);
            fs::write(&path, "x\n").unwrap();
            set_modified(&path, now - TimeDelta::minutes(age_minutes));
        };
        // Its last line is 22 h 59 min old, so its first may be 23 h 59 min.
        file("network-relay.2025-01-14-15.log", 22 * 60 + 59);
        file("network-relay.2025-01-14-15.1.log", 23 * 60);
        file("network-relay.2025-01-14-16.log", 22 * 60 + 58);
        // Not ours.
        file("other-program.2025-01-13-10.log", 50 * 60);
        file("network-relay.notes.log", 50 * 60);
        file("network-relay.2025-01-13-10.log.bak", 50 * 60);

        let log = LogFile::open(&dir, P, now).unwrap();
        assert_eq!(
            names(&dir),
            [
                "network-relay.2025-01-13-10.log.bak",
                "network-relay.2025-01-14-16.log",
                "network-relay.log",
                "network-relay.notes.log",
                "other-program.2025-01-13-10.log",
            ]
        );
        set_modified(&dir.join("network-relay.2025-01-14-16.log"), now - TimeDelta::hours(23));
        log.prune(now.into());
        assert!(!dir.join("network-relay.2025-01-14-16.log").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn at_most_16_mib_per_hour() {
        let dir = temp_dir("cap");
        let mut log = LogFile::open(&dir, P, at(13, 0)).unwrap();
        let line = vec![b'x'; 1 << 20];
        for _ in 0..20 {
            log.write_line(&line, at(13, 10)).unwrap();
        }
        let text = read(&dir, "network-relay.log");
        assert_eq!(text.matches("reached 16 MiB").count(), 1);
        assert!(text.len() < (16 << 20) + 200);
        log.write_line(b"next hour\n", at(14, 0)).unwrap();
        assert_eq!(read(&dir, "network-relay.log"), "next hour\n");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn archive_names() {
        assert!(is_archive_name(P, "network-relay.2025-01-15-13.log"));
        assert!(is_archive_name(P, "network-relay.2025-01-15-13.2.log"));
        assert!(!is_archive_name(P, "network-relay.log"));
        assert!(!is_archive_name(P, "other-program.2025-01-15-13.log"));
        assert!(!is_archive_name(P, "network-relay.2026-09-30.log"));
        assert!(!is_archive_name(P, "network-relay.2025-01-15-13..log"));
        assert!(!is_archive_name(P, "network-relay.2025-01-15-13.x.log"));
    }

    #[test]
    fn hour_starts() {
        assert_eq!(hour_start(at(13, 59)), at(13, 0));
        assert_eq!(hour_start(at(13, 0)), at(13, 0));
        assert_eq!(hour_start(at(13, 0) + TimeDelta::milliseconds(1500)), at(13, 0));
    }
}
