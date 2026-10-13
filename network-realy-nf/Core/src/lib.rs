//! No host network sockets: all I/O is requested through the native bridge.
pub mod client;
pub mod gssapi;
pub mod native;
pub mod proto;
pub mod quic;
pub mod socks;
pub mod stream;

use bytes::Bytes;
use serde::Deserialize;
use std::{
    ffi::{CStr, c_char},
    io::Write,
    ptr,
    sync::{Arc, Mutex},
    thread,
};
use tokio::sync::mpsc;
use tracing_subscriber::{EnvFilter, fmt::MakeWriter, layer::SubscriberExt};
#[derive(Clone, Deserialize)]
pub struct Config {
    pub uri_template: String,
    pub username: String,
    pub password: String,
    pub server_name: Option<String>,
    #[serde(default = "automatic")]
    pub transport: String,
    #[serde(default = "default_probe")]
    pub probe_target: std::net::SocketAddr,
    pub mode: String,
    pub socks: Socks,
}
fn default_probe() -> std::net::SocketAddr {
    "1.1.1.1:53".parse().unwrap()
}
fn automatic() -> String {
    "auto".into()
}
#[derive(Clone, Deserialize)]
pub struct Socks {
    pub listen: Vec<std::net::SocketAddr>,
    /// A keytab: SOCKS clients then authenticate with GSS-API, such as
    /// Kerberos (RFC 1961).
    #[serde(default)]
    pub gssapi_keytab: Option<std::path::PathBuf>,
    /// The GSS-API client names admitted; empty for any the keytab's realm
    /// authenticates.
    #[serde(default)]
    pub gssapi_principals: Vec<String>,
}
impl Socks {
    /// The GSS-API acceptor, if a keytab is configured.
    pub fn gssapi(&self) -> anyhow::Result<Option<Arc<dyn gssapi::Acceptor>>> {
        let Some(keytab) = &self.gssapi_keytab else {
            return Ok(None);
        };
        let acceptor = gssapi::Kerberos::new(keytab, self.gssapi_principals.clone())
            .map_err(anyhow::Error::msg)?;
        Ok(Some(Arc::new(acceptor)))
    }
}
pub struct Handle {
    pub bridge: Arc<native::Bridge>,
    events: Mutex<mpsc::Receiver<native::Event>>,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
    level: Arc<Mutex<LogControl>>,
}
struct LogControl {
    current: u32,
    update: Option<Box<dyn Fn(String) + Send + Sync>>,
}
#[repr(C)]
pub struct NfEvent {
    pub kind: u32,
    pub id: u64,
    pub token: u64,
    pub flags: u64,
    pub data: *const u8,
    pub len: usize,
}
#[repr(C)]
struct OwnedEvent {
    header: NfEvent,
    _bytes: Bytes,
}
#[derive(Clone)]
struct LogWriter(Arc<native::Bridge>);
struct LineWriter {
    bridge: Arc<native::Bridge>,
    buf: Vec<u8>,
}
impl<'a> MakeWriter<'a> for LogWriter {
    type Writer = LineWriter;
    fn make_writer(&'a self) -> LineWriter {
        LineWriter {
            bridge: self.0.clone(),
            buf: Vec::new(),
        }
    }
}
impl Write for LineWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let cap = 16384usize.saturating_sub(self.buf.len());
        self.buf.extend_from_slice(&buf[..buf.len().min(cap)]);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Drop for LineWriter {
    fn drop(&mut self) {
        let _ = self.bridge.events.try_send(native::Event {
            kind: native::LOG,
            id: 0,
            token: 0,
            flags: 0,
            data: Bytes::from(std::mem::take(&mut self.buf)),
        });
    }
}
fn filter(level: u32) -> String {
    match level {
        0 => "error".into(),
        1 => "warn".into(),
        3 => "info,network_realy_nf_core=debug".into(),
        // Third-party wire traces can dump encoded authentication or user
        // data. Only our reviewed metadata diagnostics may use TRACE.
        4 => "info,network_realy_nf_core=trace".into(),
        _ => "info".into(),
    }
}

/// Returns an opaque instance, or null for invalid input. Caller owns its lifetime.
/// # Safety
/// `input` must be null or point to a valid NUL-terminated UTF-8 string for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nf_start(input: *const c_char, level: u32) -> *mut Handle {
    if input.is_null() {
        return ptr::null_mut();
    }
    let Ok(text) = (unsafe { CStr::from_ptr(input) }).to_str() else {
        return ptr::null_mut();
    };
    if text.len() > 262144 {
        return ptr::null_mut();
    }
    let Ok(config) = toml::from_str::<Config>(text) else {
        return ptr::null_mut();
    };
    if config.mode != "socks"
        || !matches!(config.transport.as_str(), "auto" | "h3" | "h2" | "http/1.1")
        || config.socks.listen.is_empty()
        || config
            .socks
            .gssapi_keytab
            .as_deref()
            .is_some_and(|k| !k.is_absolute())
        || (!config.socks.gssapi_principals.is_empty() && config.socks.gssapi_keytab.is_none())
    {
        return ptr::null_mut();
    }
    let (events, rx) = mpsc::channel(512);
    let bridge = native::Bridge::new(events);
    let owner = Arc::new(Mutex::new(LogControl {
        current: level,
        update: None,
    }));
    let thread_bridge = bridge.clone();
    let thread_level = owner.clone();
    let thread = thread::spawn(move || {
        let mut control = thread_level.lock().unwrap();
        let (layer, reload) =
            tracing_subscriber::reload::Layer::new(EnvFilter::new(filter(control.current)));
        control.update = Some(Box::new(move |f| {
            let _ = reload.reload(EnvFilter::new(f));
        }) as Box<dyn Fn(String) + Send + Sync>);
        drop(control);
        let subscriber = tracing_subscriber::registry().with(layer).with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(LogWriter(thread_bridge.clone())),
        );
        let dispatch = tracing::Dispatch::new(subscriber);
        // A dedicated per-instance runtime keeps spawned-task diagnostics on
        // this subscriber, without a process-wide logging singleton.
        let _guard = tracing::dispatcher::set_default(&dispatch);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("protocol runtime");
        let result = runtime.block_on(async {
            let work = async {
                let client = client::Client::new(&config, thread_bridge.clone())?;
                let gssapi = config.socks.gssapi()?;
                let mut listeners = Vec::new();
                for addr in &config.socks.listen {
                    listeners.push(thread_bridge.listen(*addr).await?);
                }
                tracing::info!("Network.framework SOCKS listeners ready");
                socks::run(Arc::new(client), listeners, gssapi).await
            };
            tokio::select! {r=work=>r,_=thread_bridge.stop.cancelled()=>Ok(())}
        });
        let (exit, message) = match result {
            Ok(()) => (0, Bytes::new()),
            Err(e) => (1, Bytes::from(format!("{e:#}"))),
        };
        runtime.block_on(async {
            let _ = thread_bridge
                .events
                .send(native::Event {
                    kind: native::EXIT,
                    id: 0,
                    token: 0,
                    flags: exit,
                    data: message,
                })
                .await;
        });
        runtime.shutdown_timeout(std::time::Duration::from_secs(2));
    });
    Box::into_raw(Box::new(Handle {
        bridge,
        events: Mutex::new(rx),
        thread: Mutex::new(Some(thread)),
        level: owner,
    }))
}
/// Blocking on a dedicated background queue; never call on the GUI/native callbacks queue.
/// # Safety
/// `handle` must be null or a live instance; destroy must not overlap this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nf_next_event(handle: *mut Handle) -> *mut NfEvent {
    let Some(h) = (unsafe { handle.as_ref() }) else {
        return ptr::null_mut();
    };
    let Some(event) = h.events.lock().unwrap().blocking_recv() else {
        return ptr::null_mut();
    };
    let mut owned = Box::new(OwnedEvent {
        header: NfEvent {
            kind: event.kind,
            id: event.id,
            token: event.token,
            flags: event.flags,
            data: ptr::null(),
            len: event.data.len(),
        },
        _bytes: event.data,
    });
    owned.header.data = owned._bytes.as_ptr();
    Box::into_raw(owned).cast()
}
/// # Safety
/// `event` must be null or an event returned by `nf_next_event`, freed exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nf_free_event(event: *mut NfEvent) {
    if !event.is_null() {
        drop(unsafe { Box::from_raw(event.cast::<OwnedEvent>()) });
    }
}
/// # Safety
/// `handle` must be live or null, and nonempty `data` must contain `len` readable bytes.
/// Destruction must not overlap this call; the data is copied, not retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nf_input(
    handle: *mut Handle,
    kind: u32,
    id: u64,
    token: u64,
    flags: u64,
    data: *const u8,
    len: usize,
) -> bool {
    let Some(h) = (unsafe { handle.as_ref() }) else {
        return false;
    };
    if len > 262144 || (len > 0 && data.is_null()) {
        return false;
    }
    let bytes = if len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }
    };
    h.bridge.input(kind, id, token, flags, bytes)
}
/// Delivers nonempty stream content without mistaking a late callback for overflow.
/// # Safety
/// Same live-handle and readable-buffer requirements as `nf_input`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nf_input_data(
    handle: *mut Handle,
    id: u64,
    data: *const u8,
    len: usize,
) -> u32 {
    let Some(h) = (unsafe { handle.as_ref() }) else {
        return native::DataInputResult::Invalid as u32;
    };
    if len == 0 || len > 262144 || data.is_null() {
        return native::DataInputResult::Invalid as u32;
    }
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };
    h.bridge.input_data(id, bytes) as u32
}
/// # Safety
/// Same live-handle and readable-buffer requirements as `nf_input`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nf_accept(
    handle: *mut Handle,
    parent: u64,
    stream_id: u64,
    data: *const u8,
    len: usize,
) -> u64 {
    let Some(h) = (unsafe { handle.as_ref() }) else {
        return 0;
    };
    if len > 4096 || data.is_null() || stream_id > ((1 << 62) - 1) {
        return 0;
    }
    let Ok(ready) = serde_json::from_slice(unsafe { std::slice::from_raw_parts(data, len) }) else {
        return 0;
    };
    h.bridge.accept(parent, stream_id, ready)
}
/// # Safety
/// `handle` must be null or live; destruction must not overlap the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nf_log_level(handle: *mut Handle, level: u32) {
    if let Some(h) = unsafe { handle.as_ref() } {
        let mut control = h.level.lock().unwrap();
        control.current = level.min(4);
        if let Some(update) = control.update.as_ref() {
            update(filter(level));
        }
    }
}
/// # Safety
/// `handle` must be null or live; destruction must not overlap the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nf_stop(handle: *mut Handle) {
    if let Some(h) = unsafe { handle.as_ref() } {
        h.bridge.stop.cancel();
    }
}
/// Called once after EXIT and after native callbacks have been cancelled/invalidated.
/// # Safety
/// `handle` must be null or owned, returned by `nf_start` and not yet destroyed.
/// No other bridge call may overlap or occur afterwards. Release all events first.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nf_destroy(handle: *mut Handle) {
    if handle.is_null() {
        return;
    }
    let h = unsafe { Box::from_raw(handle) };
    h.bridge.stop.cancel();
    if let Some(t) = h.thread.lock().unwrap().take() {
        let _ = t.join();
    }
}
