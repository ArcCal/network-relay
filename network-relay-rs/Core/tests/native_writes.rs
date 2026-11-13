//! Native-bridge write accounting, using memory only.
use network_relay_rs_core::native::*;
use std::{sync::Arc, time::Duration};
use tokio::{io::AsyncWriteExt, sync::mpsc};

async fn bounded<F: std::future::Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(2), future)
        .await
        .expect("native-boundary operation must not hang")
}

async fn next_event(events: &mut mpsc::Receiver<Event>) -> Event {
    bounded(events.recv())
        .await
        .expect("native event channel closed")
}

async fn connection(bridge: &Arc<Bridge>, events: &mut mpsc::Receiver<Event>) -> Io {
    let owner = bridge.clone();
    let task = tokio::spawn(async move { owner.tcp(Vec::new()).await });
    let event = loop {
        let e = events.recv().await.unwrap();
        if e.kind == OPEN_TCP {
            break e;
        }
    };
    assert!(
        bridge.input(
            READY,
            event.id,
            0,
            0,
            &serde_json::to_vec(&Ready {
                alpn: "http/1.1".into(),
                local: "127.0.0.1:50000".into(),
                peer: "127.0.0.1:443".into(),
                ..Ready::default()
            })
            .unwrap()
        )
    );
    task.await.unwrap().unwrap()
}

#[tokio::test]
async fn a_shorter_write_after_an_abandoned_write_is_sent_and_counted_separately() {
    let (tx, mut events) = mpsc::channel(512);
    let bridge = Bridge::new(tx);
    let mut io = bounded(connection(&bridge, &mut events)).await;
    let id = io.id();
    // An HTTP/1.1 request write can still await completion when the
    // tunnel's first, shorter capsule is written to the same connection.
    let request = vec![7u8; 200];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), io.write_all(&request))
            .await
            .is_err()
    );
    let first = next_event(&mut events).await;
    assert_eq!((first.kind, first.id, first.data.len()), (WRITE, id, 200));
    let capsule = [0u8, 1, 0];
    let writer = tokio::spawn(async move {
        io.write_all(&capsule).await.unwrap();
        io
    });
    assert!(bridge.input(ACK, id, first.token, 0, b""));
    let second = next_event(&mut events).await;
    assert_eq!((second.kind, second.id, second.flags), (WRITE, id, 0));
    assert_eq!(second.data, capsule[..]);
    assert!(!writer.is_finished());
    assert!(bridge.input(ACK, id, second.token, 0, b""));
    let io = bounded(writer).await.unwrap();
    assert!(events.try_recv().is_err());
    drop(io);
}

#[tokio::test]
async fn failed_queued_child_does_not_kill_its_listener() {
    let (tx, mut events) = mpsc::channel(32);
    let bridge = Bridge::new(tx);
    let owner = bridge.clone();
    let opening = tokio::spawn(async move { owner.listen("127.0.0.1:0".parse().unwrap()).await });
    let event = next_event(&mut events).await;
    assert_eq!(event.kind, LISTEN);
    assert!(
        bridge.input(
            READY,
            event.id,
            0,
            0,
            &serde_json::to_vec(&Ready {
                local: "127.0.0.1:1080".into(),
                ..Ready::default()
            })
            .unwrap()
        )
    );
    let listener = bounded(opening).await.unwrap().unwrap();
    let ready = Ready {
        local: "127.0.0.1:1080".into(),
        peer: "127.0.0.1:50000".into(),
        ..Ready::default()
    };
    let failed = bridge.accept(event.id, 0, ready.clone());
    assert_ne!(failed, 0);
    assert!(bridge.input(ERROR, failed, 0, 4, b"connection reset before acceptance"));
    let healthy = bridge.accept(event.id, 0, ready);
    assert_ne!(healthy, 0);
    let (accepted, _) = bounded(listener.accept()).await.unwrap();
    assert_eq!(accepted.id(), healthy);
    drop(accepted);
    assert!(bridge.input(ERROR, event.id, 0, 1, b"listener access denied"));
    let error = bounded(listener.accept()).await.err().unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), "listener access denied");
    drop(listener);
    assert!(bridge.resources.lock().unwrap().is_empty());
}
