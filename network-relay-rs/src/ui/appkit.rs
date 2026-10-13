//! Small, ARM64-only AppKit adapter. All Objective-C access stays on the main
//! thread. This module does not load or call Network.framework.
//!
//! `objc_msgSend` is cast to each selector's exact ABI before invocation. macOS
//! ARM64 uses the ordinary message-send ABI for NSRect returns; this adapter is
//! deliberately not an Intel implementation. Cocoa parents retain child views;
//! the application keeps its windows, delegate, popover and timer alive until
//! process termination. AppKit delegate callbacks use the documented selector
//! signatures and a thread-local application, never a pointer to a moved Rust
//! value. Borrowed NSString bytes are copied before another Cocoa call.
#![allow(unsafe_op_in_unsafe_fn)]

use std::ffi::{CStr, CString, c_char, c_void};

pub type Id = *mut c_void;
type Sel = *mut c_void;
pub const NIL: Id = std::ptr::null_mut();

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Size {
    pub width: f64,
    pub height: f64,
}
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Rect {
    pub origin: Point,
    pub size: Size,
}
pub fn rect(x: f64, y: f64, width: f64, height: f64) -> Rect {
    Rect { origin: Point { x, y }, size: Size { width, height } }
}

#[cfg_attr(target_os = "macos", link(name = "objc"))]
unsafe extern "C" {
    fn objc_getClass(name: *const c_char) -> Id;
    fn sel_registerName(name: *const c_char) -> Sel;
    fn objc_msgSend();
    fn objc_allocateClassPair(superclass: Id, name: *const c_char, bytes: usize) -> Id;
    fn objc_registerClassPair(class: Id);
    fn class_addMethod(class: Id, name: Sel, imp: *const c_void, types: *const c_char) -> bool;
}
#[cfg(target_os = "macos")]
#[link(name = "AppKit", kind = "framework")]
#[link(name = "Foundation", kind = "framework")]
#[link(name = "QuartzCore", kind = "framework")]
#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {}
unsafe extern "C" {
    fn CGPathCreateMutable() -> Id;
    fn CGPathAddArc(path: Id, transform: Id, x: f64, y: f64, radius: f64, start: f64, end: f64, clockwise: bool);
    fn CGPathRelease(path: Id);
}
pub unsafe fn ring_layer(parent: Id, position: Rect) -> (Id, Id) {
    let ring = view(position);
    send1::<_, ()>(ring, "setWantsLayer:", true);
    let backing: Id = send0(ring, "layer");
    let shape: Id = send0(class("CAShapeLayer"), "layer");
    frame(shape, rect(0., 0., position.size.width, position.size.height));
    let path = CGPathCreateMutable();
    CGPathAddArc(
        path,
        NIL,
        position.size.width / 2.,
        position.size.height / 2.,
        55.,
        -std::f64::consts::FRAC_PI_2,
        std::f64::consts::TAU * 0.28 - std::f64::consts::FRAC_PI_2,
        false,
    );
    send1::<_, ()>(shape, "setPath:", path);
    CGPathRelease(path);
    send1::<_, ()>(shape, "setLineWidth:", 3.0_f64);
    send1::<_, ()>(shape, "setLineCap:", string("round"));
    send1::<_, ()>(shape, "setFillColor:", NIL);
    send1::<_, ()>(backing, "addSublayer:", shape);
    add(parent, ring);
    hidden(ring, true);
    (ring, shape)
}
pub unsafe fn animate_ring(shape: Id, reduced: bool) {
    send0::<()>(shape, "removeAllAnimations");
    if reduced {
        return;
    }
    let animation: Id = send1(class("CABasicAnimation"), "animationWithKeyPath:", string("transform.rotation.z"));
    let from: Id = send1(class("NSNumber"), "numberWithDouble:", 0_f64);
    let to: Id = send1(class("NSNumber"), "numberWithDouble:", std::f64::consts::TAU);
    send1::<_, ()>(animation, "setFromValue:", from);
    send1::<_, ()>(animation, "setToValue:", to);
    send1::<_, ()>(animation, "setDuration:", 0.9_f64);
    send1::<_, ()>(animation, "setRepeatCount:", f32::INFINITY);
    send2::<_, _, ()>(shape, "addAnimation:forKey:", animation, string("connecting"));
}

pub unsafe fn class(name: &str) -> Id {
    objc_getClass(CString::new(name).unwrap().as_ptr())
}
pub unsafe fn selector(name: &str) -> Sel {
    sel_registerName(CString::new(name).unwrap().as_ptr())
}
pub unsafe fn send0<R>(object: Id, name: &str) -> R {
    let call: unsafe extern "C" fn(Id, Sel) -> R = std::mem::transmute(objc_msgSend as *const ());
    call(object, selector(name))
}
pub unsafe fn send1<A, R>(object: Id, name: &str, a: A) -> R {
    let call: unsafe extern "C" fn(Id, Sel, A) -> R = std::mem::transmute(objc_msgSend as *const ());
    call(object, selector(name), a)
}
pub unsafe fn send2<A, B, R>(object: Id, name: &str, a: A, b: B) -> R {
    let call: unsafe extern "C" fn(Id, Sel, A, B) -> R = std::mem::transmute(objc_msgSend as *const ());
    call(object, selector(name), a, b)
}
pub unsafe fn send3<A, B, C, R>(object: Id, name: &str, a: A, b: B, c: C) -> R {
    let call: unsafe extern "C" fn(Id, Sel, A, B, C) -> R = std::mem::transmute(objc_msgSend as *const ());
    call(object, selector(name), a, b, c)
}
pub unsafe fn send4<A, B, C, D, R>(object: Id, name: &str, a: A, b: B, c: C, d: D) -> R {
    let call: unsafe extern "C" fn(Id, Sel, A, B, C, D) -> R = std::mem::transmute(objc_msgSend as *const ());
    call(object, selector(name), a, b, c, d)
}
pub unsafe fn string(value: &str) -> Id {
    let value = CString::new(value.replace('\0', "")).unwrap();
    send1(class("NSString"), "stringWithUTF8String:", value.as_ptr())
}
pub unsafe fn text(object: Id) -> String {
    let value: Id = send0(object, "stringValue");
    let bytes: *const c_char = send0(value, "UTF8String");
    if bytes.is_null() { String::new() } else { CStr::from_ptr(bytes).to_string_lossy().into_owned() }
}
pub unsafe fn ns_text(value: Id) -> String {
    if value.is_null() {
        return String::new();
    }
    let bytes: *const c_char = send0(value, "UTF8String");
    if bytes.is_null() { String::new() } else { CStr::from_ptr(bytes).to_string_lossy().into_owned() }
}
pub unsafe fn new(class_name: &str) -> Id {
    send0(class(class_name), "new")
}
pub unsafe fn view(frame: Rect) -> Id {
    let value: Id = send0(class("NSView"), "alloc");
    send1(value, "initWithFrame:", frame)
}
pub unsafe fn add(parent: Id, child: Id) {
    send1::<_, ()>(parent, "addSubview:", child);
}
pub unsafe fn autoresize(object: Id, mask: usize) {
    send1::<_, ()>(object, "setAutoresizingMask:", mask);
}
pub unsafe fn frame(object: Id, value: Rect) {
    send1::<_, ()>(object, "setFrame:", value);
}
pub unsafe fn label(parent: Id, value: &str, position: Rect, points: f64, bold: bool) -> Id {
    let field: Id = send1(class("NSTextField"), "labelWithString:", string(value));
    frame(field, position);
    let font: Id = if bold {
        send1(class("NSFont"), "boldSystemFontOfSize:", points)
    } else {
        send1(class("NSFont"), "systemFontOfSize:", points)
    };
    send1::<_, ()>(field, "setFont:", font);
    send1::<_, ()>(field, "setSelectable:", true);
    add(parent, field);
    field
}
pub unsafe fn field(parent: Id, value: &str, position: Rect, secure: bool) -> Id {
    let field = new(if secure { "NSSecureTextField" } else { "NSTextField" });
    frame(field, position);
    send1::<_, ()>(field, "setStringValue:", string(value));
    send1::<_, ()>(field, "setFont:", send1::<_, Id>(class("NSFont"), "systemFontOfSize:", 13.0_f64));
    add(parent, field);
    field
}
pub unsafe fn action(object: Id, delegate: Id, tag: isize) {
    send1::<_, ()>(object, "setTarget:", delegate);
    send1::<_, ()>(object, "setAction:", selector("performAction:"));
    send1::<_, ()>(object, "setTag:", tag);
}
pub unsafe fn button(parent: Id, title: &str, position: Rect, delegate: Id, tag: isize) -> Id {
    let result = new("NSButton");
    frame(result, position);
    send1::<_, ()>(result, "setTitle:", string(title));
    send1::<_, ()>(result, "setBezelStyle:", 1_usize);
    action(result, delegate, tag);
    add(parent, result);
    result
}
pub unsafe fn checkbox(parent: Id, title: &str, position: Rect, delegate: Id, tag: isize) -> Id {
    let result = button(parent, title, position, delegate, tag);
    send1::<_, ()>(result, "setButtonType:", 3_usize);
    result
}
pub unsafe fn popup(parent: Id, position: Rect, delegate: Id, tag: isize) -> Id {
    let allocated: Id = send0(class("NSPopUpButton"), "alloc");
    let result: Id = send2(allocated, "initWithFrame:pullsDown:", position, false);
    action(result, delegate, tag);
    add(parent, result);
    result
}
pub unsafe fn menu_popup(parent: Id, title: &str, items: &[&str], position: Rect, delegate: Id, tag: isize) -> Id {
    let allocated: Id = send0(class("NSPopUpButton"), "alloc");
    let result: Id = send2(allocated, "initWithFrame:pullsDown:", position, true);
    send1::<_, ()>(result, "addItemWithTitle:", string(title));
    for item in items {
        send1::<_, ()>(result, "addItemWithTitle:", string(item));
    }
    action(result, delegate, tag);
    add(parent, result);
    result
}
pub unsafe fn popup_items(object: Id, titles: &[String], selected: usize) {
    send0::<()>(object, "removeAllItems");
    for title in titles {
        send1::<_, ()>(object, "addItemWithTitle:", string(title));
    }
    if !titles.is_empty() {
        send1::<_, ()>(object, "selectItemAtIndex:", selected.min(titles.len() - 1) as isize);
    }
}
pub unsafe fn index(object: Id) -> usize {
    send0::<isize>(object, "indexOfSelectedItem").max(0) as usize
}
pub unsafe fn set_text(object: Id, value: &str) {
    send1::<_, ()>(object, "setStringValue:", string(value));
}
pub unsafe fn hidden(object: Id, value: bool) {
    send1::<_, ()>(object, "setHidden:", value);
}
pub unsafe fn enabled(object: Id, value: bool) {
    send1::<_, ()>(object, "setEnabled:", value);
}
pub unsafe fn color(name: &str) -> Id {
    send0(class("NSColor"), name)
}
pub unsafe fn copy_text(value: &str) {
    let pasteboard: Id = send0(class("NSPasteboard"), "generalPasteboard");
    send0::<isize>(pasteboard, "clearContents");
    send2::<_, _, bool>(pasteboard, "setString:forType:", string(value), string("public.utf8-plain-text"));
}
pub unsafe fn alert(title: &str, message: &str, choices: &[&str]) -> usize {
    let alert = new("NSAlert");
    send1::<_, ()>(alert, "setMessageText:", string(title));
    send1::<_, ()>(alert, "setInformativeText:", string(message));
    for choice in choices {
        send1::<_, Id>(alert, "addButtonWithTitle:", string(choice));
    }
    let result: isize = send0(alert, "runModal");
    send0::<()>(alert, "release");
    result.saturating_sub(1000).max(0) as usize
}
pub unsafe fn choose_file(save: bool, filename: &str, message: &str) -> Option<std::path::PathBuf> {
    let panel: Id =
        send0(class(if save { "NSSavePanel" } else { "NSOpenPanel" }), if save { "savePanel" } else { "openPanel" });
    send1::<_, ()>(panel, "setMessage:", string(message));
    if save {
        send1::<_, ()>(panel, "setNameFieldStringValue:", string(filename));
    } else {
        send1::<_, ()>(panel, "setAllowsMultipleSelection:", false);
        send1::<_, ()>(panel, "setCanChooseDirectories:", false);
    }
    if send0::<isize>(panel, "runModal") != 1 {
        return None;
    }
    let url: Id = send0(panel, "URL");
    let path: Id = send0(url, "path");
    Some(ns_text(path).into())
}
pub unsafe fn make_delegate(methods: &[(&str, *const c_void, &str)]) -> Id {
    let name = CString::new("NetworkRelayRSDelegate").unwrap();
    let cls = objc_allocateClassPair(class("NSObject"), name.as_ptr(), 0);
    assert!(!cls.is_null(), "AppKit delegate class registration failed");
    for (name, imp, encoding) in methods {
        let encoding = CString::new(*encoding).unwrap();
        assert!(class_addMethod(cls, selector(name), *imp, encoding.as_ptr()));
    }
    objc_registerClassPair(cls);
    send0(cls, "new")
}
