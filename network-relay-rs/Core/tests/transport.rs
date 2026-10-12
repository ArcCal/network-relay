//! Production transport startup and cancellation boundaries.
use network_relay_rs_core::backend::{Backend, BackendOptions};

#[tokio::test]
async fn missing_trust_file_is_rejected_before_network_io() {
    let path = std::env::temp_dir().join(format!("relay-rs-missing-{}.pem", std::process::id()));
    assert!(
        Backend::start(BackendOptions {
            ca_file: Some(path)
        })
        .is_err()
    );
}

#[tokio::test]
async fn malformed_trust_file_is_rejected_before_network_io() {
    let path = std::env::temp_dir().join(format!("relay-rs-malformed-{}.pem", std::process::id()));
    std::fs::write(&path, b"this is not a certificate").unwrap();
    let result = Backend::start(BackendOptions {
        ca_file: Some(path.clone()),
    });
    std::fs::remove_file(path).unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn production_backend_shutdown_is_idempotent() {
    let mut backend = Backend::start(BackendOptions::default()).unwrap();
    assert_eq!(backend.resource_count(), 0);
    backend.shutdown().await;
    backend.shutdown().await;
    assert_eq!(backend.resource_count(), 0);
    assert!(backend.bridge.stop.is_cancelled());
}
