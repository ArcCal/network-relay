//! The GUI owns settings; a cancellable Rust runtime owns this instance's sockets.
use crate::model::{Configuration, LogLevel};
use anyhow::{Context, Result};
use network_relay_rs_core::{
    backend::{Backend, BackendOptions},
    client::Client,
    socks,
};
use std::{
    collections::VecDeque,
    io::Write,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
        mpsc,
    },
    thread,
};
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Stopped,
    Connecting,
    Connected,
    Reconnecting,
    Failed(String),
}
impl Status {
    pub fn title(&self) -> &str {
        match self {
            Self::Stopped => "Not Connected",
            Self::Connecting => "Connecting…",
            Self::Connected => "Connected",
            Self::Reconnecting => "Connection Lost, Reconnecting…",
            Self::Failed(_) => "Connection Failed",
        }
    }
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Connecting | Self::Connected | Self::Reconnecting)
    }
}
#[derive(Clone, Debug)]
pub struct LogEntry {
    pub text: String,
    pub level: u8,
    pub sequence: u64,
}
impl LogEntry {
    fn parse(text: String) -> Self {
        let level = if text.contains(" ERROR ") {
            0
        } else if text.contains(" WARN ") {
            1
        } else if text.contains(" DEBUG ") {
            3
        } else if text.contains(" TRACE ") {
            4
        } else {
            2
        };
        Self { text, level, sequence: 0 }
    }
}
pub fn level_number(level: LogLevel) -> u8 {
    match level {
        LogLevel::Errors => 0,
        LogLevel::Warnings => 1,
        LogLevel::Normal => 2,
        LogLevel::Detailed => 3,
        LogLevel::Everything => 4,
    }
}
fn runtime_filter<S: tracing::Subscriber>(level: Arc<AtomicU8>) -> impl tracing_subscriber::layer::Filter<S> {
    // The level changes while this subscriber remains installed. A static
    // filter_fn would cache always/never interest at each tracing callsite.
    tracing_subscriber::filter::dynamic_filter_fn(move |meta, _context| {
        let n = match *meta.level() {
            tracing::Level::ERROR => 0,
            tracing::Level::WARN => 1,
            tracing::Level::INFO => 2,
            tracing::Level::DEBUG => 3,
            tracing::Level::TRACE => 4,
        };
        n <= level.load(Ordering::Relaxed) && (n <= 2 || meta.target().starts_with("network_relay_rs"))
    })
}
enum Message {
    Log(LogEntry),
    Status(u64, String),
    Exit(Result<(), String>),
}
struct Worker {
    stop: tokio_util::sync::CancellationToken,
    thread: thread::JoinHandle<()>,
    level: Arc<AtomicU8>,
}
pub struct Controller {
    pub config: Configuration,
    pub status: Status,
    pub detail: String,
    log: VecDeque<LogEntry>,
    worker: Option<Worker>,
    tx: mpsc::Sender<Message>,
    rx: mpsc::Receiver<Message>,
    log_tx: mpsc::SyncSender<Message>,
    log_rx: mpsc::Receiver<Message>,
    log_sequence: u64,
    restart: bool,
    stopping: bool,
    store: Option<PathBuf>,
    ca_file: Option<PathBuf>,
}
impl Controller {
    pub fn new() -> Result<Self> {
        let path = Configuration::default_path();
        let configuration = Configuration::load(&path);
        let mut owner = Self::with_configuration(configuration, Some(path.clone()), None);
        if path.exists()
            && let Err(error) = Configuration::try_load(&path)
        {
            owner.record(1, format!("Saved settings could not be loaded; the original file was preserved: {error}"));
        }
        Ok(owner)
    }
    pub fn with_configuration(config: Configuration, store: Option<PathBuf>, ca_file: Option<PathBuf>) -> Self {
        let (tx, rx) = mpsc::channel();
        let (log_tx, log_rx) = mpsc::sync_channel(512);
        let mut owner = Self {
            config,
            status: Status::Stopped,
            detail: String::new(),
            log: VecDeque::new(),
            worker: None,
            tx,
            rx,
            log_tx,
            log_rx,
            log_sequence: 0,
            restart: false,
            stopping: false,
            store,
            ca_file,
        };
        owner.record(
            2,
            format!(
                "Network Relay RS launched; Rust Tokio/rustls/Quinn transport; app {}; core {}; built {}; source {}",
                crate::VERSION,
                network_relay_rs_core::VERSION,
                crate::BUILD_TIME,
                crate::SOURCE_REVISION
            ),
        );
        owner
    }
    pub fn logs(&self) -> Vec<LogEntry> {
        self.log.iter().cloned().collect()
    }
    pub fn is_configured(&self) -> bool {
        self.config.core_config().is_ok()
    }
    pub fn launched(&mut self) {
        if self.config.connect_on_launch {
            if self.is_configured() {
                self.connect();
            } else {
                self.record(1, "Launch connection skipped: complete the selected server settings first.".into());
            }
        }
    }
    pub fn connect(&mut self) {
        if self.worker.is_some() {
            return;
        }
        let config = match self.config.core_config() {
            Ok(c) => c,
            Err(e) => {
                self.fail(format!("{e:#}"));
                return;
            }
        };
        let run = uuid::Uuid::new_v4().simple().to_string()[..8].to_uppercase();
        let server = self
            .config
            .selected_server()
            .map(|s| if s.name.trim().is_empty() { &s.domain } else { &s.name })
            .cloned()
            .unwrap_or_default();
        self.record(
            2,
            format!("Connecting to {server}; SOCKS5 {}; {} [run={run}]", config.socks.listen[0], config.transport),
        );
        self.status = Status::Connecting;
        self.detail.clear();
        self.stopping = false;
        let tx = self.tx.clone();
        let log_tx = self.log_tx.clone();
        let token = tokio_util::sync::CancellationToken::new();
        let stop = token.clone();
        let level = Arc::new(AtomicU8::new(level_number(self.config.log_level)));
        let filter_level = level.clone();
        let ca_file = self.ca_file.clone();
        let handle = thread::spawn(move || {
            let writer = LogWriter { tx: log_tx, run };
            let layer = tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(writer)
                .with_filter(runtime_filter(filter_level));
            let subscriber = tracing_subscriber::registry().with(layer);
            let _guard = subscriber.set_default();
            let result = (|| -> Result<()> {
                let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
                let outcome = runtime.block_on(async {
                    let mut backend = Backend::start(BackendOptions { ca_file })?;
                    let bridge = backend.bridge.clone();
                    let mut states = backend.status.clone();
                    let work = async {
                        let client = Arc::new(Client::new(&config, bridge.clone())?);
                        let mut listeners = Vec::new();
                        for addr in &config.socks.listen {
                            listeners.push(bridge.listen(*addr).await?);
                            tracing::info!("SOCKS TCP listener ready on {addr}");
                        }
                        socks::run(client, listeners).await
                    };
                    let outcome = {
                        tokio::pin!(work);
                        loop {
                            tokio::select! {
                                biased;
                                _ = stop.cancelled() => break Ok(()),
                                r = &mut work => break r,
                                change = states.changed() => {
                                    if change.is_err() { break Err(anyhow::anyhow!("transport status channel closed")); }
                                    let (flags, text) = states.borrow_and_update().clone();
                                    // Status messages must not be dropped by a verbose-log burst.
                                    let _ = tx.send(Message::Status(flags, text));
                                }
                            }
                        }
                    };
                    backend.shutdown().await;
                    outcome
                });
                runtime.shutdown_timeout(std::time::Duration::from_secs(1));
                outcome
            })();
            let _ = tx.send(Message::Exit(result.map_err(|e| format!("{e:#}"))));
        });
        self.worker = Some(Worker { stop: token, thread: handle, level });
    }
    pub fn disconnect(&mut self) {
        self.record(2, "Disconnect requested".into());
        self.restart = false;
        self.stop_worker();
    }
    fn stop_worker(&mut self) {
        if let Some(w) = &self.worker {
            self.stopping = true;
            w.stop.cancel();
        } else {
            self.status = Status::Stopped;
        }
    }
    pub fn apply(&mut self, new: Configuration) -> Result<()> {
        new.check()?;
        if let Some(path) = &self.store {
            new.save(path)?;
        }
        let old = self.config.core_config().ok();
        let next = new.core_config().ok();
        let changed = old.as_ref().map(config_identity) != next.as_ref().map(config_identity);
        let level_changed = new.log_level != self.config.log_level;
        self.config = new;
        if level_changed && let Some(w) = &self.worker {
            w.level.store(level_number(self.config.log_level), Ordering::Relaxed);
        }
        let should_restart = changed && self.worker.is_some() && (!self.stopping || self.restart) && next.is_some();
        if changed && self.worker.is_some() && (!self.stopping || self.restart) {
            self.restart = should_restart;
            self.stop_worker();
        }
        self.record(
            2,
            if should_restart {
                "Settings saved; reconnecting with the changed parameters; existing proxy sessions will end"
            } else {
                "Settings saved"
            }
            .into(),
        );
        Ok(())
    }
    pub fn set_log_level(&mut self, level: LogLevel) -> Result<()> {
        let mut new = self.config.clone();
        new.log_level = level;
        self.apply(new)?;
        self.record(2, "Log level changed".into());
        Ok(())
    }
    pub fn poll(&mut self) {
        while let Ok(Message::Log(line)) = self.log_rx.try_recv() {
            self.append(line);
        }
        while let Ok(message) = self.rx.try_recv() {
            match message {
                Message::Log(line) => self.append(line),
                Message::Status(flags, text) if !self.stopping => {
                    self.status = if flags == 1 { Status::Connected } else { Status::Reconnecting };
                    self.detail = text;
                }
                Message::Status(_, _) => {}
                Message::Exit(result) => {
                    // Exit is emitted only after the backend has released its listeners.
                    if let Some(w) = self.worker.take() {
                        let _ = w.thread.join();
                    }
                    if self.stopping || result.is_ok() {
                        self.status = Status::Stopped;
                        self.detail.clear();
                        self.record(2, "Disconnected".into());
                    } else if let Err(error) = result {
                        self.fail(error);
                    }
                    self.stopping = false;
                    if self.restart {
                        self.restart = false;
                        self.connect();
                    }
                }
            }
        }
    }
    pub fn stop(&mut self) {
        self.restart = false;
        self.stop_worker();
        // Keep draining the bounded channel while waiting; the worker may be
        // delivering its final status instead of doing network I/O.
        while self.worker.is_some() {
            self.poll();
            if self.worker.as_ref().is_some_and(|worker| worker.thread.is_finished()) {
                self.poll();
                if let Some(worker) = self.worker.take() {
                    if worker.thread.join().is_err() {
                        self.fail("The Rust network worker stopped unexpectedly.".into());
                    } else {
                        self.status = Status::Stopped;
                    }
                    self.stopping = false;
                    self.restart = false;
                }
            }
            thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    pub fn erase(&mut self) -> Result<()> {
        self.stop();
        if let Some(path) = &self.store {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).context("erasing RS settings"),
            }
        }
        self.config = Configuration::default();
        self.log.clear();
        Ok(())
    }
    fn fail(&mut self, error: String) {
        self.status = Status::Failed(error.clone());
        self.detail = error.clone();
        self.record(0, error);
    }
    fn record(&mut self, level: u8, text: String) {
        let severity = ["ERROR", "WARN", "INFO", "DEBUG", "TRACE"][level as usize];
        self.append(LogEntry {
            level,
            sequence: 0,
            text: format!(
                "{} {severity} app: {text}",
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            ),
        });
    }
    fn append(&mut self, mut line: LogEntry) {
        self.log_sequence += 1;
        line.sequence = self.log_sequence;
        self.log.push_back(line);
        while self.log.len() > 5000 {
            if let Some(i) = self.log.iter().position(|x| x.level >= 3) {
                self.log.remove(i);
            } else {
                self.log.pop_front();
            }
        }
    }
}
impl Drop for Controller {
    fn drop(&mut self) {
        self.stop();
    }
}
fn config_identity(c: &network_relay_rs_core::Config) -> String {
    // Used only for in-memory equality; never logged or persisted separately.
    format!(
        "{}\0{}\0{}\0{:?}\0{}\0{:?}\0{}",
        c.uri_template, c.username, c.password, c.server_name, c.transport, c.socks.listen, c.probe_target
    )
}
#[derive(Clone)]
struct LogWriter {
    tx: mpsc::SyncSender<Message>,
    run: String,
}
struct LineWriter {
    owner: LogWriter,
    bytes: Vec<u8>,
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogWriter {
    type Writer = LineWriter;
    fn make_writer(&'a self) -> LineWriter {
        LineWriter { owner: self.clone(), bytes: Vec::new() }
    }
}
impl Write for LineWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let n = (16384 - self.bytes.len()).min(bytes.len());
        self.bytes.extend_from_slice(&bytes[..n]);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Drop for LineWriter {
    fn drop(&mut self) {
        for line in String::from_utf8_lossy(&self.bytes).lines() {
            let _ = self.owner.tx.try_send(Message::Log(LogEntry::parse(format!("{line} [run={}]", self.owner.run))));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn log_level_changes_apply_to_existing_callsites_without_reconnecting() {
        fn trace_at_same_callsite() {
            tracing::trace!(target: "network_relay_rs_core", "transport metadata");
        }
        fn info_at_same_callsite() {
            tracing::info!(target: "network_relay_rs_core", "operational event");
        }
        let (tx, rx) = mpsc::sync_channel(16);
        let level = Arc::new(AtomicU8::new(level_number(LogLevel::Normal)));
        let writer = LogWriter { tx, run: "TEST".into() };
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(writer)
            .with_filter(runtime_filter(level.clone()));
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            trace_at_same_callsite();
            assert!(rx.try_recv().is_err());
            info_at_same_callsite();
            assert!(matches!(rx.try_recv().unwrap(), Message::Log(line) if line.level == 2));

            level.store(level_number(LogLevel::Everything), Ordering::Relaxed);
            trace_at_same_callsite();
            assert!(matches!(rx.try_recv().unwrap(), Message::Log(line) if line.level == 4));
            tracing::trace!(target: "third_party_transport", "sensitive packet data must stay excluded");
            assert!(rx.try_recv().is_err());

            level.store(level_number(LogLevel::Errors), Ordering::Relaxed);
            trace_at_same_callsite();
            info_at_same_callsite();
            assert!(rx.try_recv().is_err());
            tracing::error!(target: "network_relay_rs_core", "operational error");
            assert!(matches!(rx.try_recv().unwrap(), Message::Log(line) if line.level == 0));
        });
    }
    #[test]
    fn retention_prioritizes_operational_records() {
        let mut c = Controller::with_configuration(Configuration::default(), None, None);
        c.log.clear();
        c.record(0, "important".into());
        for i in 0..6000 {
            c.record(4, format!("packet metadata {i}"));
        }
        assert_eq!(c.logs().len(), 5000);
        assert!(c.logs()[0].text.contains("important"));
    }
    #[test]
    fn malformed_configuration_never_starts_worker() {
        let mut c = Controller::with_configuration(Configuration::default(), None, None);
        c.connect();
        assert!(matches!(c.status, Status::Failed(_)));
        assert!(c.worker.is_none());
    }
    #[test]
    fn incomplete_launch_settings_are_skipped_without_a_failure_state() {
        let config = Configuration { connect_on_launch: true, ..Default::default() };
        let mut c = Controller::with_configuration(config, None, None);
        c.launched();
        assert_eq!(c.status, Status::Stopped);
        assert!(c.worker.is_none());
        assert!(c.logs().iter().any(|line| line.level == 1 && line.text.contains("Launch connection skipped")));
    }
    #[test]
    fn sequence_cursor_survives_log_eviction() {
        let mut c = Controller::with_configuration(Configuration::default(), None, None);
        for i in 0..6000 {
            c.record(2, format!("event {i}"));
        }
        let seen = c.logs().last().unwrap().sequence;
        c.record(2, "after ring reached its limit".into());
        let new: Vec<_> = c.logs().into_iter().filter(|line| line.sequence > seen).collect();
        assert_eq!(new.len(), 1);
        assert!(new[0].text.contains("after ring"));
    }
    fn pending_tls_controller() -> (Controller, std::net::TcpListener, u16) {
        let relay = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let server = crate::model::Server {
            domain: format!("relay.test:{}", relay.local_addr().unwrap().port()),
            server_ip: "127.0.0.1".into(),
            username: "fixture".into(),
            password: "disposable-controller-fixture".into(),
            transport: crate::model::Transport::H2,
            ..Default::default()
        };
        let config =
            Configuration { selected_server_id: Some(server.id), servers: vec![server], port, ..Default::default() };
        (Controller::with_configuration(config, None, None), relay, port)
    }
    fn wait_until(c: &mut Controller, condition: impl Fn(&Controller) -> bool) {
        let start = std::time::Instant::now();
        loop {
            c.poll();
            if condition(c) {
                return;
            }
            assert!(
                start.elapsed() < std::time::Duration::from_secs(5),
                "controller condition timed out: {:?}",
                c.status
            );
            thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    #[test]
    fn saved_transport_restarts_after_old_listener_is_released() {
        let (mut c, _relay, port) = pending_tls_controller();
        c.connect();
        wait_until(&mut c, |c| c.logs().iter().any(|line| line.text.contains("SOCKS TCP listener ready")));
        let mut changed = c.config.clone();
        changed.servers[0].transport = crate::model::Transport::Http1;
        c.apply(changed).unwrap();
        wait_until(&mut c, |c| {
            c.logs().iter().filter(|line| line.text.contains("SOCKS TCP listener ready")).count() == 2
        });
        assert!(std::net::TcpListener::bind(("127.0.0.1", port)).is_err());
        assert!(!c.logs().iter().any(|line| line.text.contains("disposable-controller-fixture")));
        c.disconnect();
        wait_until(&mut c, |c| c.worker.is_none());
        assert!(std::net::TcpListener::bind(("127.0.0.1", port)).is_ok());
    }
    #[test]
    fn explicit_disconnect_cancels_a_pending_saved_restart() {
        let (mut c, _relay, port) = pending_tls_controller();
        c.connect();
        wait_until(&mut c, |c| c.logs().iter().any(|line| line.text.contains("SOCKS TCP listener ready")));
        let mut changed = c.config.clone();
        changed.servers[0].transport = crate::model::Transport::Http1;
        c.apply(changed).unwrap();
        c.disconnect();
        wait_until(&mut c, |c| c.worker.is_none());
        assert_eq!(c.logs().iter().filter(|line| line.text.contains("Connecting to ")).count(), 1);
        assert!(std::net::TcpListener::bind(("127.0.0.1", port)).is_ok());
        assert_eq!(c.status, Status::Stopped);
    }
}
