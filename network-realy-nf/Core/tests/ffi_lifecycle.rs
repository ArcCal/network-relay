//! Public ABI lifetime, cancellation, fatal error and instance isolation.
use network_realy_nf_core::*;
use std::{ffi::CString, ptr};

const CONFIG: &str = r#"
uri_template = "https://127.0.0.1/.well-known/masque/udp/{target_host}/{target_port}/"
server_name = "nf.test.invalid"
username = "test"
password = "test-password-123"
mode = "socks"
transport = "auto"
dns = ["192.0.2.80"]
[socks]
listen = ["127.0.0.1:1080"]
"#;
struct Instance(*mut Handle);
impl Instance {
    fn start() -> Self {
        let config = CString::new(CONFIG).unwrap();
        let handle = unsafe { nf_start(config.as_ptr(), 2) };
        assert!(!handle.is_null());
        Self(handle)
    }
    fn next(&self) -> (u32, u64, u64, Vec<u8>) {
        let event = unsafe { nf_next_event(self.0) };
        assert!(!event.is_null());
        let value = unsafe { &*event };
        let data = if value.len == 0 {
            vec![]
        } else {
            unsafe { std::slice::from_raw_parts(value.data, value.len) }.to_vec()
        };
        let result = (value.kind, value.id, value.flags, data);
        unsafe { nf_free_event(event) };
        result
    }
    fn until(&self, kind: u32) -> (u32, u64, u64, Vec<u8>) {
        for _ in 0..100 {
            let event = self.next();
            if event.0 == kind {
                return event;
            }
            assert_ne!(event.0, 99, "unexpected runtime exit: {event:?}");
        }
        panic!("expected event {kind}")
    }
    fn input(&self, kind: u32, id: u64, flags: u64, data: &[u8]) -> bool {
        unsafe { nf_input(self.0, kind, id, 0, flags, data.as_ptr(), data.len()) }
    }
    fn stop(&self) {
        unsafe { nf_stop(self.0) }
    }
}
impl Drop for Instance {
    fn drop(&mut self) {
        unsafe { nf_destroy(self.0) }
    }
}

#[test]
fn cancelling_initialization_exits_and_discards_late_input() {
    let core = Instance::start();
    // This may run before the protocol thread installs the filter.
    unsafe { nf_log_level(core.0, 4) };
    let listener = core.until(8);
    core.stop();
    let exit = core.until(99);
    assert_eq!(exit.2, 0);
    assert!(!core.input(101, listener.1, 0, br#"{"local":"127.0.0.1:1080"}"#));
}

#[test]
fn one_instance_cannot_stop_another_and_level_changes_do_not_relisten() {
    let old = Instance::start();
    let new = Instance::start();
    let previous = old.until(8);
    let listener = new.until(8);
    assert_eq!(
        previous.1, listener.1,
        "resource IDs belong to an instance, not a global socket table"
    );
    old.stop();
    assert_eq!(old.until(99).2, 0);
    unsafe { nf_log_level(new.0, 3) };
    assert!(new.input(101, listener.1, 0, br#"{"local":"127.0.0.1:1080"}"#));
    let quic = new.until(2);
    let options: serde_json::Value = serde_json::from_slice(&quic.3).unwrap();
    assert_eq!(options["host"], "127.0.0.1");
    assert_eq!(options["port"], 443);
    assert_eq!(options["server_name"], "nf.test.invalid");
    new.stop();
    assert_eq!(new.until(99).2, 0);
}

#[test]
fn secure_handshake_failure_is_terminal_and_never_triggers_tcp_fallback() {
    let core = Instance::start();
    let listener = core.until(8);
    assert!(core.input(101, listener.1, 0, br#"{"local":"127.0.0.1:1080"}"#));
    let quic = core.until(2);
    core.input(104, quic.1, 1, b"certificate validation failed");
    let mut logs = Vec::new();
    for _ in 0..100 {
        let event = core.next();
        assert_ne!(
            event.0, 1,
            "certificate failure must not be retried over TCP"
        );
        if event.0 == 20 {
            logs.extend_from_slice(&event.3);
        }
        if event.0 == 99 {
            assert_eq!(event.2, 1);
            assert!(String::from_utf8_lossy(&event.3).contains("certificate"));
            break;
        }
    }
    let logs = String::from_utf8_lossy(&logs);
    assert!(!logs.contains("test-password-123"));
    assert!(!logs.contains("Basic dGVzdDo"));
}

#[test]
fn invalid_and_null_abi_input_is_rejected_without_a_runtime() {
    assert!(unsafe { nf_start(ptr::null(), 0) }.is_null());
    for config in [
        "not valid TOML",
        "mode='system'",
        "username='test'\npassword='secret'",
    ] {
        let value = CString::new(config).unwrap();
        assert!(unsafe { nf_start(value.as_ptr(), 2) }.is_null());
    }
    assert!(!unsafe { nf_input(ptr::null_mut(), 101, 1, 0, 0, ptr::null(), 0) });
    assert!(unsafe { nf_next_event(ptr::null_mut()) }.is_null());
    unsafe {
        nf_stop(ptr::null_mut());
        nf_destroy(ptr::null_mut());
        nf_free_event(ptr::null_mut());
    }
}
