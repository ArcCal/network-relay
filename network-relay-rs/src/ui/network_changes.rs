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
    use std::ffi::{CStr, c_char, c_void};
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
            || unsafe { CFStringGetCString(value, bytes.as_mut_ptr(), bytes.len() as isize, 0x08000100) } == 0
        {
            return None;
        }
        unsafe { CStr::from_ptr(bytes.as_ptr()) }.to_str().ok().map(str::to_owned)
    }
    unsafe fn primary_interface(store: Ref, key: &CStr) -> Option<String> {
        unsafe {
            let key = CFStringCreateWithCString(ptr::null(), key.as_ptr(), 0x08000100);
            if key.is_null() {
                return None;
            }
            let dictionary = SCDynamicStoreCopyValue(store, key);
            CFRelease(key);
            if dictionary.is_null() {
                return None;
            }
            let field = CFStringCreateWithCString(ptr::null(), c"PrimaryInterface".as_ptr(), 0x08000100);
            let result = if field.is_null() { None } else { string(CFDictionaryGetValue(dictionary, field)) };
            if !field.is_null() {
                CFRelease(field);
            }
            CFRelease(dictionary);
            result
        }
    }
    unsafe extern "C" fn changed(store: Ref, keys: Ref, _: *mut c_void) {
        // Ignore link/address churn on interfaces that carry no default path.
        // Global changes still detect a switch of the primary interface itself.
        unsafe {
            let primary = [
                primary_interface(store, c"State:/Network/Global/IPv4"),
                primary_interface(store, c"State:/Network/Global/IPv6"),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
            for index in 0..CFArrayGetCount(keys) {
                if string(CFArrayGetValueAtIndex(keys, index)).is_some_and(|key| affects_active_path(&key, &primary)) {
                    CHANGED.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }
    }
    pub struct Monitor {
        store: Ref,
        source: Ref,
    }
    impl Monitor {
        pub fn new() -> Option<Self> {
            unsafe {
                let name = CFStringCreateWithCString(ptr::null(), c"Network Relay RS".as_ptr(), 0x08000100);
                if name.is_null() {
                    return None;
                }
                let store = SCDynamicStoreCreate(ptr::null(), name, changed, ptr::null_mut());
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
                CFRunLoopAddSource(CFRunLoopGetMain(), source, kCFRunLoopCommonModes);
                Some(Self { store, source })
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
