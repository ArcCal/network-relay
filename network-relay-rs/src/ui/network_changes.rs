//! Observe route/address/link changes without linking Network.framework.
use std::sync::atomic::{AtomicBool, Ordering};
static CHANGED: AtomicBool = AtomicBool::new(false);
pub(super) fn take_change() -> bool {
    CHANGED.swap(false, Ordering::Relaxed)
}

#[cfg(any(target_os = "macos", feature = "ui-typecheck"))]
fn affects_active_path(key: &str, primary: &[String]) -> bool {
    if matches!(key, "State:/Network/Global/IPv4" | "State:/Network/Global/IPv6") {
        return true;
    }
    key.strip_prefix("State:/Network/Interface/").and_then(|tail| tail.rsplit_once('/')).is_some_and(
        |(interface, field)| matches!(field, "IPv4" | "IPv6" | "Link") && primary.iter().any(|name| name == interface),
    )
}

#[cfg(any(target_os = "macos", feature = "ui-typecheck"))]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod platform {
    use super::*;
    use std::ffi::{CStr, CString, c_char, c_void};
    use std::ptr;
    type Ref = *const c_void;
    #[cfg_attr(target_os = "macos", link(name = "CoreFoundation", kind = "framework"))]
    unsafe extern "C" {
        static kCFTypeArrayCallBacks: u8;
        static kCFRunLoopCommonModes: Ref;
        fn CFStringCreateWithCString(allocator: Ref, text: *const c_char, encoding: u32) -> Ref;
        fn CFArrayCreate(allocator: Ref, values: *const Ref, count: isize, callbacks: Ref) -> Ref;
        fn CFArrayGetCount(array: Ref) -> isize;
        fn CFArrayGetValueAtIndex(array: Ref, index: isize) -> Ref;
        fn CFDictionaryGetValue(dictionary: Ref, key: Ref) -> Ref;
        fn CFDictionaryGetTypeID() -> usize;
        fn CFStringGetTypeID() -> usize;
        fn CFGetTypeID(value: Ref) -> usize;
        fn CFEqual(left: Ref, right: Ref) -> u8;
        fn CFRetain(value: Ref) -> Ref;
        fn CFStringGetCString(string: Ref, buffer: *mut c_char, capacity: isize, encoding: u32) -> u8;
        fn CFRelease(value: Ref);
        fn CFRunLoopGetMain() -> Ref;
        fn CFRunLoopAddSource(run_loop: Ref, source: Ref, mode: Ref);
        fn CFRunLoopRemoveSource(run_loop: Ref, source: Ref, mode: Ref);
        fn CFRunLoopSourceInvalidate(source: Ref);
    }
    #[cfg_attr(target_os = "macos", link(name = "SystemConfiguration", kind = "framework"))]
    unsafe extern "C" {
        fn SCDynamicStoreCreate(
            allocator: Ref,
            name: Ref,
            callback: unsafe extern "C" fn(Ref, Ref, *mut c_void),
            context: *mut c_void,
        ) -> Ref;
        fn SCDynamicStoreSetNotificationKeys(store: Ref, keys: Ref, patterns: Ref) -> u8;
        fn SCDynamicStoreCopyValue(store: Ref, key: Ref) -> Ref;
        fn SCDynamicStoreCreateRunLoopSource(allocator: Ref, store: Ref, order: isize) -> Ref;
    }
    unsafe fn string(value: Ref) -> Option<String> {
        let mut bytes = [0; 1024];
        if value.is_null()
            || unsafe { CFGetTypeID(value) != CFStringGetTypeID() }
            || unsafe { CFStringGetCString(value, bytes.as_mut_ptr(), bytes.len() as isize, 0x08000100) } == 0
        {
            return None;
        }
        unsafe { CStr::from_ptr(bytes.as_ptr()) }.to_str().ok().map(str::to_owned)
    }
    struct Value(Ref);
    impl Drop for Value {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CFRelease(self.0) }
            }
        }
    }
    impl PartialEq for Value {
        fn eq(&self, other: &Self) -> bool {
            self.0 == other.0 || (!self.0.is_null() && !other.0.is_null() && unsafe { CFEqual(self.0, other.0) != 0 })
        }
    }
    impl Value {
        unsafe fn key(text: &CStr) -> Option<Self> {
            let value = unsafe { CFStringCreateWithCString(ptr::null(), text.as_ptr(), 0x08000100) };
            (!value.is_null()).then_some(Self(value))
        }
        unsafe fn dictionary(store: Ref, key: &CStr) -> Option<Self> {
            let key = unsafe { Self::key(key) }?;
            Some(Self(unsafe { SCDynamicStoreCopyValue(store, key.0) }))
        }
        unsafe fn field(&self, key: &CStr) -> Option<Ref> {
            if self.0.is_null() || unsafe { CFGetTypeID(self.0) != CFDictionaryGetTypeID() } {
                return Some(ptr::null());
            }
            let key = unsafe { Self::key(key) }?;
            Some(unsafe { CFDictionaryGetValue(self.0, key.0) })
        }
    }
    #[derive(Default, PartialEq)]
    struct Snapshot {
        primary: Vec<String>,
        values: Vec<Value>,
    }
    impl Snapshot {
        unsafe fn append(&mut self, dictionary: &Value, fields: &[&CStr]) -> Option<()> {
            for field in fields {
                let value = unsafe { dictionary.field(field) }?;
                self.values.push(Value(if value.is_null() { value } else { unsafe { CFRetain(value) } }));
            }
            Some(())
        }
        unsafe fn capture(store: Ref) -> Option<Self> {
            let mut snapshot = Self::default();
            for key in [c"State:/Network/Global/IPv4", c"State:/Network/Global/IPv6"] {
                let dictionary = unsafe { Value::dictionary(store, key) }?;
                if let Some(name) = unsafe { string(dictionary.field(c"PrimaryInterface")?) } {
                    snapshot.primary.push(name);
                }
                unsafe { snapshot.append(&dictionary, &[c"PrimaryInterface", c"PrimaryService", c"Router"]) }?;
            }
            snapshot.primary.sort_unstable();
            snapshot.primary.dedup();
            for interface in snapshot.primary.clone() {
                for (entity, fields) in [
                    (
                        "IPv4",
                        &[
                            c"Addresses",
                            c"SubnetMasks",
                            c"DestAddresses",
                            c"Router",
                            c"AdditionalRoutes",
                            c"ExcludedRoutes",
                            c"IncludedRoutes",
                        ][..],
                    ),
                    (
                        "IPv6",
                        &[
                            c"Addresses",
                            c"PrefixLength",
                            c"DestAddresses",
                            c"Flags",
                            c"Router",
                            c"AdditionalRoutes",
                            c"ExcludedRoutes",
                            c"IncludedRoutes",
                        ][..],
                    ),
                    ("Link", &[c"Active"][..]),
                ] {
                    let key = CString::new(format!("State:/Network/Interface/{interface}/{entity}")).ok()?;
                    let dictionary = unsafe { Value::dictionary(store, &key) }?;
                    unsafe { snapshot.append(&dictionary, fields) }?;
                }
            }
            Some(snapshot)
        }
    }
    #[repr(C)]
    struct StoreContext {
        version: isize,
        info: *mut c_void,
        retain: Option<unsafe extern "C" fn(Ref) -> Ref>,
        release: Option<unsafe extern "C" fn(Ref)>,
        copy_description: Option<unsafe extern "C" fn(Ref) -> Ref>,
    }
    unsafe extern "C" fn changed(store: Ref, keys: Ref, info: *mut c_void) {
        // The context is owned by Monitor and used only on the main run loop.
        let Some(previous) = (unsafe { info.cast::<Snapshot>().as_mut() }) else { return };
        let relevant = (0..unsafe { CFArrayGetCount(keys) }).any(|index| {
            unsafe { string(CFArrayGetValueAtIndex(keys, index)) }
                .is_some_and(|key| affects_active_path(&key, &previous.primary))
        });
        if relevant
            && let Some(current) = unsafe { Snapshot::capture(store) }
            && *previous != current
        {
            *previous = current;
            CHANGED.store(true, Ordering::Relaxed);
        }
    }
    pub struct Monitor {
        store: Ref,
        source: Ref,
        _snapshot: Box<Snapshot>,
    }
    impl Monitor {
        pub fn new() -> Option<Self> {
            unsafe {
                let name = CFStringCreateWithCString(ptr::null(), c"Network Relay RS".as_ptr(), 0x08000100);
                if name.is_null() {
                    return None;
                }
                let mut snapshot = Box::<Snapshot>::default();
                let mut context = StoreContext {
                    version: 0,
                    info: ptr::from_mut(snapshot.as_mut()).cast(),
                    retain: None,
                    release: None,
                    copy_description: None,
                };
                let store = SCDynamicStoreCreate(ptr::null(), name, changed, ptr::from_mut(&mut context).cast());
                CFRelease(name);
                if store.is_null() {
                    return None;
                }
                // Signal-strength fluctuations must not reset healthy connections.
                let values = [
                    CFStringCreateWithCString(ptr::null(), c"State:/Network/Global/IPv[46]".as_ptr(), 0x08000100),
                    CFStringCreateWithCString(
                        ptr::null(),
                        c"State:/Network/Interface/[^/]+/(IPv4|IPv6|Link)".as_ptr(),
                        0x08000100,
                    ),
                ];
                if values.iter().any(|value| value.is_null()) {
                    for value in values {
                        if !value.is_null() {
                            CFRelease(value);
                        }
                    }
                    CFRelease(store);
                    return None;
                }
                let patterns = CFArrayCreate(
                    ptr::null(),
                    values.as_ptr(),
                    values.len() as isize,
                    (&raw const kCFTypeArrayCallBacks).cast(),
                );
                for value in values {
                    CFRelease(value);
                }
                if patterns.is_null() {
                    CFRelease(store);
                    return None;
                }
                let registered = SCDynamicStoreSetNotificationKeys(store, ptr::null(), patterns) != 0;
                CFRelease(patterns);
                let source =
                    if registered { SCDynamicStoreCreateRunLoopSource(ptr::null(), store, 0) } else { ptr::null() };
                if source.is_null() {
                    CFRelease(store);
                    return None;
                }
                let Some(initial) = Snapshot::capture(store) else {
                    CFRelease(source);
                    CFRelease(store);
                    return None;
                };
                *snapshot = initial;
                CFRunLoopAddSource(CFRunLoopGetMain(), source, kCFRunLoopCommonModes);
                Some(Self { store, source, _snapshot: snapshot })
            }
        }
    }
    impl Drop for Monitor {
        fn drop(&mut self) {
            unsafe {
                CFRunLoopRemoveSource(CFRunLoopGetMain(), self.source, kCFRunLoopCommonModes);
                CFRunLoopSourceInvalidate(self.source);
                CFRelease(self.source);
                CFRelease(self.store);
            }
        }
    }
}
#[cfg(target_os = "macos")]
pub(super) use platform::Monitor;
#[cfg(not(target_os = "macos"))]
pub(super) struct Monitor;
#[cfg(not(target_os = "macos"))]
impl Monitor {
    pub fn new() -> Option<Self> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_active_interfaces_and_global_paths_trigger_recovery() {
        let primary = vec!["en0".into(), "utun5".into()];
        for key in [
            "State:/Network/Interface/en0/IPv4",
            "State:/Network/Interface/utun5/IPv6",
            "State:/Network/Interface/en0/Link",
        ] {
            assert!(affects_active_path(key, &primary), "{key}");
        }
        for key in [
            "State:/Network/Interface/en1/Link",
            "State:/Network/Interface/en01/IPv4",
            "State:/Network/Interface/lo0/IPv6",
            "State:/Network/Interface/en0/AirPort",
        ] {
            assert!(!affects_active_path(key, &primary), "{key}");
        }
        assert!(affects_active_path("State:/Network/Global/IPv4", &[]));
        assert!(affects_active_path("State:/Network/Global/IPv6", &[]));
        assert!(!affects_active_path("State:/Network/Interface/en0/Link", &[]));
    }
}

#[cfg(all(test, not(target_os = "macos"), feature = "ui-typecheck"))]
#[path = "../../scripts/network-changes-test.rs"]
mod callback_tests;
