//! Shared shutdown handling and scoped forwarding futures.

use std::future::Future;

use anyhow::Result;

/// Register handlers before creating host resources that need cleanup.
pub struct Shutdown {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
}

impl Shutdown {
    pub fn new() -> Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            Ok(Self { interrupt: signal(SignalKind::interrupt())?, terminate: signal(SignalKind::terminate())? })
        }
        #[cfg(not(unix))]
        Ok(Self {})
    }

    pub async fn recv(&mut self) {
        #[cfg(unix)]
        tokio::select! {
            _ = self.interrupt.recv() => {},
            _ = self.terminate.recv() => {},
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Dropping the unfinished forwarding futures cancels them before returning.
/// No detached tasks can read the previous session's device or tunnel.
pub async fn relay(
    outbound: impl Future<Output = String>,
    inbound: impl Future<Output = String>,
    closed: impl Future<Output = String>,
    shutdown: impl Future<Output = ()>,
) -> String {
    tokio::select! {
        why = outbound => why,
        why = inbound => why,
        why = closed => why,
        _ = shutdown => "interrupted".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct Pending(Arc<AtomicUsize>);
    impl Future for Pending {
        type Output = String;
        fn poll(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<String> {
            std::task::Poll::Pending
        }
    }
    impl Drop for Pending {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn reconnect_and_shutdown_drop_both_forwarders() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let why = relay(
            Pending(dropped.clone()),
            Pending(dropped.clone()),
            async { "closed".into() },
            std::future::pending(),
        )
        .await;
        assert_eq!(why, "closed");
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
        let why = relay(Pending(dropped.clone()), Pending(dropped.clone()), std::future::pending(), async {}).await;
        assert_eq!(why, "interrupted");
        assert_eq!(dropped.load(Ordering::SeqCst), 4);
    }
}
