//! Executes the production observer against reference-counted C API stubs.
#![allow(non_snake_case)]
use super::{platform, take_change};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    ffi::{CStr, c_char, c_void},
    ptr,
    rc::Rc,
    sync::atomic::{AtomicUsize, Ordering},
};
type Ref = *const c_void;
type Callback = unsafe extern "C" fn(Ref, Ref, *mut c_void);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static SOURCES: AtomicUsize = AtomicUsize::new(0);
static FAIL: AtomicUsize = AtomicUsize::new(0);
#[derive(Default)]
struct State {
    values: BTreeMap<String, BTreeMap<String, String>>,
    callback: Option<Callback>,
    store: Ref,
    info: *mut c_void,
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
enum Value {
    String(String),
    Array(Vec<Ref>),
    Dictionary(BTreeMap<String, Ref>),
    Source(Ref),
    Store,
}
impl Drop for Value {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Ordering::SeqCst);
        unsafe {
            match self {
                Self::Array(values) => values.iter().for_each(|v| CFRelease(*v)),
                Self::Dictionary(values) => values.values().for_each(|v| CFRelease(*v)),
                Self::Source(store) => CFRelease(*store),
                _ => {}
            }
        }
    }
}
fn allocate(value: Value) -> Ref {
    LIVE.fetch_add(1, Ordering::SeqCst);
    Rc::into_raw(Rc::new(value)).cast()
}
unsafe fn value<'a>(r: Ref) -> &'a Value {
    unsafe { &*r.cast::<Value>() }
}
unsafe fn text<'a>(r: Ref) -> &'a str {
    match unsafe { value(r) } {
        Value::String(s) => s,
        _ => panic!("not a string"),
    }
}
#[unsafe(no_mangle)]
static kCFTypeArrayCallBacks: u8 = 0;
#[unsafe(no_mangle)]
static mut kCFRunLoopCommonModes: Ref = ptr::null();
#[unsafe(no_mangle)]
unsafe extern "C" fn CFRetain(r: Ref) -> Ref {
    assert!(!r.is_null());
    unsafe { Rc::increment_strong_count(r.cast::<Value>()) };
    r
}
#[unsafe(no_mangle)]
unsafe extern "C" fn CFRelease(r: Ref) {
    assert!(!r.is_null());
    unsafe { Rc::decrement_strong_count(r.cast::<Value>()) }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn CFEqual(a: Ref, b: Ref) -> u8 {
    match (unsafe { value(a) }, unsafe { value(b) }) {
        (Value::String(a), Value::String(b)) => u8::from(a == b),
        (Value::Array(a), Value::Array(b)) => {
            u8::from(a.len() == b.len() && a.iter().zip(b).all(|(a, b)| unsafe { CFEqual(*a, *b) != 0 }))
        }
        _ => 0,
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn CFGetTypeID(r: Ref) -> usize {
    match unsafe { value(r) } {
        Value::Dictionary(_) => 2,
        Value::String(_) => 1,
        _ => 3,
    }
}
#[unsafe(no_mangle)]
extern "C" fn CFDictionaryGetTypeID() -> usize {
    2
}
#[unsafe(no_mangle)]
extern "C" fn CFStringGetTypeID() -> usize {
    1
}
#[unsafe(no_mangle)]
unsafe extern "C" fn CFStringCreateWithCString(_: Ref, s: *const c_char, _: u32) -> Ref {
    let text = unsafe { CStr::from_ptr(s) }.to_str().unwrap();
    let fail = FAIL.load(Ordering::SeqCst);
    if fail == 1 || (fail == 6 && text == "State:/Network/Global/IPv4") {
        return ptr::null();
    }
    allocate(Value::String(text.into()))
}
#[unsafe(no_mangle)]
unsafe extern "C" fn CFArrayCreate(_: Ref, values: *const Ref, n: isize, _: Ref) -> Ref {
    if FAIL.load(Ordering::SeqCst) == 3 {
        return ptr::null();
    }
    let values = unsafe { std::slice::from_raw_parts(values, n as usize) }.to_vec();
    for v in &values {
        unsafe { CFRetain(*v) };
    }
    allocate(Value::Array(values))
}
#[unsafe(no_mangle)]
unsafe extern "C" fn CFArrayGetCount(r: Ref) -> isize {
    match unsafe { value(r) } {
        Value::Array(v) => v.len() as isize,
        _ => panic!(),
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn CFArrayGetValueAtIndex(r: Ref, i: isize) -> Ref {
    match unsafe { value(r) } {
        Value::Array(v) => v[i as usize],
        _ => panic!(),
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn CFDictionaryGetValue(r: Ref, k: Ref) -> Ref {
    match unsafe { value(r) } {
        Value::Dictionary(v) => v.get(unsafe { text(k) }).copied().unwrap_or(ptr::null()),
        _ => panic!(),
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn CFStringGetCString(r: Ref, out: *mut c_char, n: isize, _: u32) -> u8 {
    let s = unsafe { text(r) }.as_bytes();
    if s.len() + 1 > n as usize {
        return 0;
    }
    unsafe {
        ptr::copy_nonoverlapping(s.as_ptr(), out.cast(), s.len());
        *out.add(s.len()) = 0;
    }
    1
}
#[unsafe(no_mangle)]
unsafe extern "C" fn SCDynamicStoreCreate(_: Ref, _: Ref, callback: Callback, context: *mut c_void) -> Ref {
    if FAIL.load(Ordering::SeqCst) == 2 {
        return ptr::null();
    }
    let store = allocate(Value::Store);
    #[repr(C)]
    struct ContextPrefix {
        version: isize,
        info: *mut c_void,
    }
    let info = if context.is_null() { ptr::null_mut() } else { unsafe { (*context.cast::<ContextPrefix>()).info } };
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        s.callback = Some(callback);
        s.store = store;
        s.info = info;
    });
    store
}
#[unsafe(no_mangle)]
extern "C" fn SCDynamicStoreSetNotificationKeys(_: Ref, _: Ref, _: Ref) -> u8 {
    u8::from(FAIL.load(Ordering::SeqCst) != 4)
}
#[unsafe(no_mangle)]
unsafe extern "C" fn SCDynamicStoreCopyValue(_: Ref, key: Ref) -> Ref {
    STATE.with(|s| {
        s.borrow().values.get(unsafe { text(key) }).map_or(ptr::null(), |fields| {
            allocate(Value::Dictionary(
                fields
                    .iter()
                    .map(|(k, v)| {
                        let value = allocate(Value::String(v.clone()));
                        let value = if matches!(
                            k.as_str(),
                            "Addresses" | "SubnetMasks" | "DestAddresses" | "PrefixLength" | "Flags"
                        ) {
                            allocate(Value::Array(vec![value]))
                        } else {
                            value
                        };
                        (k.clone(), value)
                    })
                    .collect(),
            ))
        })
    })
}
#[unsafe(no_mangle)]
unsafe extern "C" fn SCDynamicStoreCreateRunLoopSource(_: Ref, store: Ref, _: isize) -> Ref {
    if FAIL.load(Ordering::SeqCst) == 5 {
        return ptr::null();
    }
    unsafe { CFRetain(store) };
    allocate(Value::Source(store))
}
#[unsafe(no_mangle)]
extern "C" fn CFRunLoopGetMain() -> Ref {
    ptr::null()
}
#[unsafe(no_mangle)]
unsafe extern "C" fn CFRunLoopAddSource(_: Ref, source: Ref, _: Ref) {
    unsafe { CFRetain(source) };
    SOURCES.fetch_add(1, Ordering::SeqCst);
}
#[unsafe(no_mangle)]
unsafe extern "C" fn CFRunLoopRemoveSource(_: Ref, source: Ref, _: Ref) {
    SOURCES.fetch_sub(1, Ordering::SeqCst);
    unsafe { CFRelease(source) }
}
#[unsafe(no_mangle)]
extern "C" fn CFRunLoopSourceInvalidate(_: Ref) {}
fn set(key: &str, field: &str, value: &str) {
    STATE.with(|s| {
        s.borrow_mut().values.entry(key.into()).or_default().insert(field.into(), value.into());
    });
}
fn notify(key: &str, expected: bool) {
    let keys = allocate(Value::Array(vec![allocate(Value::String(key.into()))]));
    let (callback, store, info) = STATE.with(|s| {
        let s = s.borrow();
        (s.callback.unwrap(), s.store, s.info)
    });
    unsafe {
        callback(store, keys, info);
        CFRelease(keys)
    }
    assert_eq!(take_change(), expected, "{key}");
    assert!(!take_change());
}
#[test]
fn callbacks_compare_path_values_and_release_all_native_objects() {
    const V4: &str = "State:/Network/Global/IPv4";
    const V6: &str = "State:/Network/Global/IPv6";
    const IP4: &str = "State:/Network/Interface/en0/IPv4";
    const IP6: &str = "State:/Network/Interface/utun5/IPv6";
    const LINK: &str = "State:/Network/Interface/en0/Link";
    for _ in 0..50 {
        STATE.with(|s| *s.borrow_mut() = State::default());
        set(V4, "PrimaryInterface", "en0");
        set(V4, "Router", "192.0.2.1");
        set(V6, "PrimaryInterface", "utun5");
        set(IP4, "Addresses", "192.0.2.2");
        set(IP6, "Addresses", "2001:db8::1");
        set(IP6, "PrefixLength", "64");
        set(LINK, "Active", "true");
        let monitor = platform::Monitor::new().unwrap();
        assert!(!take_change());
        assert_eq!(SOURCES.load(Ordering::SeqCst), 1);
        let baseline = LIVE.load(Ordering::SeqCst);
        for _ in 0..20 {
            for key in [V4, V6, IP4, IP6, LINK] {
                notify(key, false);
            }
        }
        assert_eq!(LIVE.load(Ordering::SeqCst), baseline, "duplicate snapshots retained objects");
        set(V4, "LeaseExpiration", "tomorrow");
        notify(V4, false);
        set(LINK, "Expensive", "true");
        notify(LINK, false);
        set("State:/Network/Interface/en1/Link", "Active", "false");
        notify("State:/Network/Interface/en1/Link", false);
        set(LINK, "Active", "false");
        notify(LINK, true);
        notify(LINK, false);
        set(LINK, "Active", "true");
        notify(LINK, true);
        set(IP4, "Addresses", "192.0.2.3");
        notify(IP4, true);
        set(V4, "Router", "192.0.2.254");
        notify(V4, true);
        set(IP6, "PrefixLength", "56");
        notify(IP6, true);
        set(IP6, "Addresses", "2001:db8::2");
        notify(IP6, true);
        for (key, fields) in [
            (V4, &["PrimaryService"][..]),
            (
                IP4,
                &["SubnetMasks", "DestAddresses", "Router", "AdditionalRoutes", "ExcludedRoutes", "IncludedRoutes"][..],
            ),
            (IP6, &["DestAddresses", "Flags", "Router", "AdditionalRoutes", "ExcludedRoutes", "IncludedRoutes"][..]),
        ] {
            for field in fields {
                set(key, field, "changed");
                notify(key, true);
                notify(key, false);
            }
        }
        FAIL.store(1, Ordering::SeqCst);
        notify(V4, false);
        FAIL.store(0, Ordering::SeqCst);
        notify(V4, false);
        set(V4, "PrimaryInterface", "en1");
        notify(V4, true);
        set(LINK, "Active", "false");
        notify(LINK, false);
        STATE.with(|s| {
            s.borrow_mut().values.remove(V4);
        });
        notify(V4, true);
        notify(V4, false);
        set(V4, "PrimaryInterface", "en0");
        notify(V4, true);
        drop(monitor);
        assert_eq!(LIVE.load(Ordering::SeqCst), 0);
        assert_eq!(SOURCES.load(Ordering::SeqCst), 0);
    }
    for failure in 1..=6 {
        FAIL.store(failure, Ordering::SeqCst);
        assert!(platform::Monitor::new().is_none());
        assert_eq!(LIVE.load(Ordering::SeqCst), 0);
        assert_eq!(SOURCES.load(Ordering::SeqCst), 0);
    }
    FAIL.store(0, Ordering::SeqCst);
}
