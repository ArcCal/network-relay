//! Host network ownership primitives. No executable or automatic activation.
#[cfg(target_os = "macos")]
pub mod backend;
pub mod broker;
pub mod ipc;
pub mod ipv6;
pub mod network;
pub mod protocol;
