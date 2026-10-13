pub mod controller;
pub mod model;
#[cfg(any(target_os = "macos", feature = "ui-typecheck"))]
pub mod ui;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SOURCE_REVISION: &str = env!("APP_SOURCE_REVISION");
pub const BUILD_TIME: &str = env!("APP_BUILD_TIME");
