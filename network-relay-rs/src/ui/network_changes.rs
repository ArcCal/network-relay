//! Observe route/address/link changes without linking Network.framework.
use std::sync::atomic::{AtomicBool, Ordering};
static CHANGED: AtomicBool = AtomicBool::new(false);
pub(super) fn take_change() -> bool {
    CHANGED.swap(false, Ordering::Relaxed)
}

#[cfg(any(target_os = "macos", feature = "ui-typecheck"))]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod platform {
    use super::*;
    use std::ffi::{c_char, c_void};
    use std::ptr;
    type Ref = *const c_void;
    #[cfg_attr(target_os = "macos", link(name = "CoreFoundation", kind = "framework"))]
    unsafe extern "C" {
        static kCFTypeArrayCallBacks: u8;
        static kCFRunLoopCommonModes: Ref;
        fn CFStringCreateWithCString(allocator: Ref, text: *const c_char, encoding: u32) -> Ref;
        fn CFArrayCreate(allocator: Ref, values: *const Ref, count: isize, callbacks: Ref) -> Ref;
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
        fn SCDynamicStoreCreateRunLoopSource(allocator: Ref, store: Ref, order: isize) -> Ref;
    }
    unsafe extern "C" fn changed(_: Ref, _: Ref, _: *mut c_void) {
        CHANGED.store(true, Ordering::Relaxed);
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
