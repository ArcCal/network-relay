//! network-relay with every tunnel carried through a downstream VLESS
//! server (VLESS over a plaintext WebSocket, as Xray-core serves it).

pub mod config;
mod dns;
pub mod egress;
mod transport;
pub mod vless;

pub use config::{FileConfig, VlessConfig};
pub use egress::VlessEgress;
