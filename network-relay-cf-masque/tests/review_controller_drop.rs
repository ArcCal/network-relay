//! Independent review: surviving sockets must not retain a dead controller.
#[path = "support/warp_peer.rs"]
mod warp_peer;

use std::future::{poll_fn, Future};
use std::io;
use std::path::PathBuf;
use std::task::Poll;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use tokio::io::AsyncReadExt;
use warp_masque_egress::{Egress, Transport, WarpEgress};
use warp_peer::{peer_addr, WarpPeer};

struct FixtureDirectory(PathBuf);
impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn final_controller_drop_interrupts_existing_tcp_and_udp_in_both_transports() -> Result<()> {
    for transport in [Transport::H2, Transport::H3] {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let directory = FixtureDirectory(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join(".build/review-fixtures")
                .join(format!("controller-drop-{}-{stamp}", std::process::id())),
        );
        let mut peer = WarpPeer::start(transport).await?;
        let config = peer.config(&directory.0)?;
        let first = WarpEgress::connect(&config).await?;
        let last = first.clone();
        let mut tcp = first.connect_tcp(peer_addr(7)).await?;
        let udp = first.connect_udp(peer_addr(7)).await?;
        drop(first);
        assert!(last.available(), "dropping a nonfinal controller invalidated its survivor");

        let mut tcp_buffer = [0; 1];
        let mut udp_buffer = [0; 1];
        let mut tcp_read = std::pin::pin!(tcp.read(&mut tcp_buffer));
        let mut udp_read = std::pin::pin!(udp.recv(&mut udp_buffer));
        poll_fn(|cx| {
            assert!(tcp_read.as_mut().poll(cx).is_pending());
            assert!(udp_read.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;

        drop(last);
        let tcp_error = tokio::time::timeout(Duration::from_secs(1), &mut tcp_read).await?.unwrap_err();
        let udp_error = tokio::time::timeout(Duration::from_secs(1), &mut udp_read).await?.unwrap_err();
        assert_eq!(tcp_error.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(udp_error.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(udp.send(b"after-drop").await.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
        peer.shutdown().await;
    }
    Ok(())
}
