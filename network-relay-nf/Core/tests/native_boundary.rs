//! Transport-boundary tests use memory only; they do not substitute for macOS execution.
use bytes::Bytes;
use network_relay_nf_core::native::*;
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};

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
    assert_eq!(event.kind, OPEN_TCP);
    assert!(
        bridge.input(
            READY,
            event.id,
            0,
            0,
            &serde_json::to_vec(&Ready {
                alpn: "h2".into(),
                local: "127.0.0.1:50000".into(),
                peer: "127.0.0.1:443".into(),
                ..Ready::default()
            })
            .unwrap()
        )
    );
    task.await.unwrap().unwrap()
}
fn instance() -> (Arc<Bridge>, mpsc::Receiver<Event>) {
    let (tx, rx) = mpsc::channel(512);
    (Bridge::new(tx), rx)
}

#[tokio::test]
async fn reads_are_pull_driven_and_preserve_chunk_boundaries_and_eof() {
    let (bridge, mut events) = instance();
    let mut io = connection(&bridge, &mut events).await;
    let id = io.id();
    let reader = tokio::spawn(async move {
        let mut output = Vec::new();
        let mut small = [0; 3];
        loop {
            let n = io.read(&mut small).await.unwrap();
            if n == 0 {
                break;
            }
            output.extend_from_slice(&small[..n]);
        }
        output
    });
    let read = events.recv().await.unwrap();
    assert_eq!(read.kind, READ);
    assert_eq!(
        bridge.input_data(id, b"abcdefgh"),
        DataInputResult::Accepted
    );
    let read = events.recv().await.unwrap();
    assert_eq!(read.kind, READ);
    assert!(bridge.input(DATA, id, 0, 0, b"ij"));
    let read = events.recv().await.unwrap();
    assert_eq!(read.kind, READ);
    assert!(bridge.input(DATA, id, 0, 1, b""));
    assert_eq!(reader.await.unwrap(), b"abcdefghij");
    assert!(bridge.resources.lock().unwrap().is_empty());
}

#[tokio::test]
async fn writes_wait_for_native_completion_and_split_large_payloads() {
    let (bridge, mut events) = instance();
    let mut io = connection(&bridge, &mut events).await;
    let id = io.id();
    let content = vec![42u8; MAX_CHUNK + 23];
    let writer = tokio::spawn(async move {
        io.write_all(&content).await.unwrap();
        io.shutdown().await.unwrap()
    });
    let first = events.recv().await.unwrap();
    assert_eq!(first.kind, WRITE);
    assert_eq!(first.data.len(), MAX_CHUNK);
    assert!(!writer.is_finished());
    assert!(events.try_recv().is_err());
    assert!(bridge.input(ACK, id, first.token, 0, b""));
    let second = events.recv().await.unwrap();
    assert_eq!(second.data.len(), 23);
    assert!(bridge.input(ACK, id, second.token, 0, b""));
    let fin = events.recv().await.unwrap();
    assert_eq!(fin.kind, WRITE);
    assert_eq!(fin.flags, 1);
    assert!(fin.data.is_empty());
    assert!(bridge.input(ACK, id, fin.token, 0, b""));
    writer.await.unwrap();
}

#[tokio::test]
async fn native_failure_wakes_reads_writes_and_group_accept() {
    let (bridge, mut events) = instance();
    let mut io = connection(&bridge, &mut events).await;
    let id = io.id();
    let read = tokio::spawn(async move { io.read_u8().await });
    assert_eq!(events.recv().await.unwrap().kind, READ);
    assert!(bridge.input(ERROR, id, 0, 4, b"server stopped"));
    assert_eq!(
        read.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
    // Failing a group closes its accept queue and its child streams.
    let owner = bridge.clone();
    let open = tokio::spawn(async move { Quic::open(owner, vec![]).await });
    let request = loop {
        let e = events.recv().await.unwrap();
        if e.kind == OPEN_QUIC {
            break e;
        }
    };
    bridge.input(
        READY,
        request.id,
        0,
        0,
        &serde_json::to_vec(&Ready {
            alpn: "h3".into(),
            ..Ready::default()
        })
        .unwrap(),
    );
    let mut quic = open.await.unwrap().unwrap();
    let child = bridge.accept(quic.io.id(), 3, Ready::default());
    assert_ne!(child, 0);
    bridge.input(ERROR, quic.io.id(), 0, 4, b"group failed");
    assert!(bridge.accepted_io(child, Ready::default()).is_err());
    let _ = quic.accepted.recv().await; // queued metadata may precede channel closure
    assert!(quic.accepted.recv().await.is_none());
    assert!(bridge.resources.lock().unwrap().is_empty());
}

#[tokio::test]
async fn protocol_close_wakes_pending_io_and_preserves_the_application_error_code() {
    let (bridge, mut events) = instance();
    let mut io = connection(&bridge, &mut events).await;
    let id = io.id();
    let read = tokio::spawn(async move { io.read_u8().await });
    assert_eq!(events.recv().await.unwrap().kind, READ);
    bridge.control(CLOSE, id, 0x102);
    let close = events.recv().await.unwrap();
    assert_eq!((close.kind, close.id, close.flags), (CLOSE, id, 0x102));
    assert_eq!(
        read.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
    assert!(!bridge.input(DATA, id, 0, 0, b"late reply"));
    assert!(bridge.resources.lock().unwrap().is_empty());
    assert!(
        events.try_recv().is_err(),
        "no duplicate close after the lease drops"
    );
}

#[tokio::test]
async fn cancellation_during_open_releases_only_that_instance() {
    let (a, mut ae) = instance();
    let (b, mut be) = instance();
    let stable = connection(&b, &mut be).await;
    let owner = a.clone();
    let pending = tokio::spawn(async move { owner.tcp(vec![]).await });
    assert_eq!(ae.recv().await.unwrap().kind, OPEN_TCP);
    pending.abort();
    let _ = pending.await;
    assert!(a.resources.lock().unwrap().is_empty());
    assert!(b.resources.lock().unwrap().contains_key(&stable.id()));
    assert!(b.input(DATA, stable.id(), 0, 0, b"still running"));
}

#[tokio::test]
async fn shutdown_waits_for_native_ack_and_sends_fin_only_once() {
    let (bridge, mut events) = instance();
    let mut io = bounded(connection(&bridge, &mut events)).await;
    let id = io.id();
    let closer = tokio::spawn(async move {
        io.shutdown().await.unwrap();
        io.shutdown().await.unwrap();
        let error = io.write_all(b"must not follow FIN").await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        io
    });

    let fin = next_event(&mut events).await;
    assert_eq!((fin.kind, fin.id, fin.flags), (WRITE, id, 1));
    assert!(fin.data.is_empty());
    assert!(
        !closer.is_finished(),
        "shutdown must await contentProcessed"
    );
    assert!(events.try_recv().is_err());
    assert!(bridge.input(ACK, id, fin.token, 0, b""));
    let io = bounded(closer).await.unwrap();
    assert!(
        events.try_recv().is_err(),
        "repeated shutdown must not send another FIN"
    );
    assert!(
        bridge.resources.lock().unwrap().contains_key(&id),
        "write EOF keeps the read side alive"
    );
    drop(io);
    assert_eq!(
        (
            next_event(&mut events).await.kind,
            events.try_recv().is_err()
        ),
        (CLOSE, true)
    );
}

#[tokio::test]
async fn buffered_response_and_read_eof_survive_later_write_fin() {
    let (bridge, mut events) = instance();
    let mut io = bounded(connection(&bridge, &mut events)).await;
    let id = io.id();
    let first_read = tokio::spawn(async move {
        let mut first = [0; 3];
        io.read_exact(&mut first).await.unwrap();
        (io, first)
    });
    assert_eq!(next_event(&mut events).await.kind, READ);
    assert!(bridge.input(DATA, id, 0, 0, b"complete response"));
    let (mut io, first) = bounded(first_read).await.unwrap();
    assert_eq!(first, *b"com");
    // Native receive sends the final payload before its separate EOF event.
    assert!(bridge.input(DATA, id, 0, 1, b""));

    let closer = tokio::spawn(async move {
        io.shutdown().await.unwrap();
        let mut rest = Vec::new();
        io.read_to_end(&mut rest).await.unwrap();
        let mut combined = first.to_vec();
        combined.extend_from_slice(&rest);
        (io, combined)
    });
    let fin = next_event(&mut events).await;
    assert_eq!((fin.kind, fin.id, fin.flags), (WRITE, id, 1));
    assert!(bridge.input(ACK, id, fin.token, 0, b""));
    let (io, response) = bounded(closer).await.unwrap();
    assert_eq!(response, b"complete response");
    assert!(
        events.try_recv().is_err(),
        "buffered EOF must not trigger another receive"
    );
    drop(io);
}

#[tokio::test]
async fn response_arriving_after_write_half_close_is_complete_and_readable() {
    let (bridge, mut events) = instance();
    let mut io = bounded(connection(&bridge, &mut events)).await;
    let id = io.id();
    let reader = tokio::spawn(async move {
        io.write_all(b"request").await.unwrap();
        io.shutdown().await.unwrap();
        let mut response = Vec::new();
        io.read_to_end(&mut response).await.unwrap();
        (io, response)
    });
    let write = next_event(&mut events).await;
    assert_eq!((write.kind, write.id, write.flags), (WRITE, id, 0));
    assert_eq!(write.data, b"request"[..]);
    assert!(bridge.input(ACK, id, write.token, 0, b""));
    let fin = next_event(&mut events).await;
    assert_eq!((fin.kind, fin.id, fin.flags), (WRITE, id, 1));
    assert!(bridge.input(ACK, id, fin.token, 0, b""));

    let expected: Vec<u8> = (0..100_013).map(|i| (i % 251) as u8).collect();
    for chunk in expected.chunks(MAX_CHUNK) {
        let read = next_event(&mut events).await;
        assert_eq!((read.kind, read.id), (READ, id));
        assert!(bridge.input(DATA, id, 0, 0, chunk));
    }
    assert_eq!(next_event(&mut events).await.kind, READ);
    assert!(bridge.input(DATA, id, 0, 1, b""));
    let (io, actual) = bounded(reader).await.unwrap();
    assert_eq!(
        actual, expected,
        "half-close must not discard the final response"
    );
    assert!(events.try_recv().is_err());
    drop(io);
}

#[tokio::test]
async fn native_fin_error_is_reported_and_does_not_cancel_another_resource() {
    // Exercise both the send-completion error and the terminal connection
    // callback. This is an API simulation, not reproduction of Apple's errno.
    for terminal_callback in [false, true] {
        let (bridge, mut events) = instance();
        let mut failing = bounded(connection(&bridge, &mut events)).await;
        let mut stable = bounded(connection(&bridge, &mut events)).await;
        let failing_id = failing.id();
        let stable_id = stable.id();
        let closer = tokio::spawn(async move {
            let error = failing
                .shutdown()
                .await
                .expect_err("native FIN failure must not become success");
            (failing, error)
        });
        let fin = next_event(&mut events).await;
        assert_eq!((fin.kind, fin.id, fin.flags), (WRITE, failing_id, 1));
        let message = b"POSIXErrorCode(rawValue: 50): Network is down";
        if terminal_callback {
            assert!(bridge.input(ERROR, failing_id, 0, 4, message));
            assert!(!bridge.input(ACK, failing_id, fin.token, 0, b""));
            let close = next_event(&mut events).await;
            assert_eq!((close.kind, close.id), (CLOSE, failing_id));
        } else {
            assert!(bridge.input(ACK, failing_id, fin.token, 4, message));
        }
        let (failing, error) = bounded(closer).await.unwrap();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(error.to_string(), String::from_utf8_lossy(message));
        assert!(bridge.resources.lock().unwrap().contains_key(&stable_id));
        assert!(
            events.try_recv().is_err(),
            "only the failed resource may be closed"
        );

        let stable_exchange = tokio::spawn(async move {
            stable.write_all(b"independent request").await.unwrap();
            let mut reply = [0; 5];
            stable.read_exact(&mut reply).await.unwrap();
            (stable, reply)
        });
        let write = next_event(&mut events).await;
        assert_eq!((write.kind, write.id, write.flags), (WRITE, stable_id, 0));
        assert_eq!(write.data, b"independent request"[..]);
        assert!(bridge.input(ACK, stable_id, write.token, 0, b""));
        let read = next_event(&mut events).await;
        assert_eq!((read.kind, read.id), (READ, stable_id));
        assert!(bridge.input(DATA, stable_id, 0, 0, b"reply"));
        let (stable, reply) = bounded(stable_exchange).await.unwrap();
        assert_eq!(reply, *b"reply");
        drop(failing);
        drop(stable);
    }
}

#[tokio::test]
async fn read_eof_and_write_fin_close_only_after_the_last_half_is_dropped() {
    let (bridge, mut events) = instance();
    let mut writer = bounded(connection(&bridge, &mut events)).await;
    let id = writer.id();
    let mut reader = writer.read_half();
    let reading = tokio::spawn(async move {
        let mut response = Vec::new();
        reader.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            reader.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        (reader, response)
    });
    assert_eq!(next_event(&mut events).await.kind, READ);
    assert!(bridge.input(DATA, id, 0, 0, b"final response"));
    assert_eq!(next_event(&mut events).await.kind, READ);
    assert!(bridge.input(DATA, id, 0, 1, b""));
    let (reader, response) = bounded(reading).await.unwrap();
    assert_eq!(response, b"final response");
    assert!(events.try_recv().is_err());

    let closing = tokio::spawn(async move {
        writer.shutdown().await.unwrap();
        writer.shutdown().await.unwrap();
        writer
    });
    let fin = next_event(&mut events).await;
    assert_eq!((fin.kind, fin.flags), (WRITE, 1));
    assert!(bridge.input(ACK, id, fin.token, 0, b""));
    let writer = bounded(closing).await.unwrap();
    drop(writer);
    assert!(bridge.resources.lock().unwrap().contains_key(&id));
    assert!(
        events.try_recv().is_err(),
        "remaining read half still owns the resource"
    );
    drop(reader);
    let close = next_event(&mut events).await;
    assert_eq!((close.kind, close.id), (CLOSE, id));
    assert!(bridge.resources.lock().unwrap().is_empty());
    assert!(
        events.try_recv().is_err(),
        "both halves must produce exactly one close"
    );
}

#[tokio::test]
async fn shutdown_drains_an_outstanding_write_before_sending_fin() {
    let (bridge, mut events) = instance();
    let mut io = bounded(connection(&bridge, &mut events)).await;
    let id = io.id();
    let payload = vec![73; MAX_CHUNK];
    // Cancel the Rust write future while native contentProcessed is pending;
    // the underlying write must finish before shutdown may emit FIN.
    assert!(
        tokio::time::timeout(Duration::from_millis(20), io.write_all(&payload))
            .await
            .is_err()
    );
    let write = next_event(&mut events).await;
    assert_eq!((write.kind, write.id, write.flags), (WRITE, id, 0));
    assert_eq!(write.data, payload);
    let closing = tokio::spawn(async move {
        io.shutdown().await.unwrap();
        io
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(20), events.recv())
            .await
            .is_err(),
        "FIN must not overtake data"
    );
    assert!(!closing.is_finished());
    assert!(bridge.input(ACK, id, write.token, 0, b""));
    let fin = next_event(&mut events).await;
    assert_eq!((fin.kind, fin.id, fin.flags), (WRITE, id, 1));
    assert!(fin.data.is_empty());
    assert!(bridge.input(ACK, id, fin.token, 0, b""));
    let io = bounded(closing).await.unwrap();
    assert!(events.try_recv().is_err());
    drop(io);
}

#[tokio::test]
async fn a_shorter_write_after_an_abandoned_write_is_sent_and_counted_separately() {
    let (bridge, mut events) = instance();
    let mut io = bounded(connection(&bridge, &mut events)).await;
    let id = io.id();
    // An HTTP/1.1 request write can still await contentProcessed when the
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
async fn failure_of_an_outstanding_data_write_aborts_shutdown_without_fin() {
    let (bridge, mut events) = instance();
    let mut io = bounded(connection(&bridge, &mut events)).await;
    let id = io.id();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), io.write_all(b"pending data"))
            .await
            .is_err()
    );
    let write = next_event(&mut events).await;
    assert_eq!((write.kind, write.id, write.flags), (WRITE, id, 0));
    assert_eq!(write.data, b"pending data"[..]);
    let closing = tokio::spawn(async move { io.shutdown().await });
    assert!(bridge.input(ERROR, id, 0, 4, b"connection failed before data completion"));
    let close = next_event(&mut events).await;
    assert_eq!((close.kind, close.id), (CLOSE, id));
    let error = bounded(closing).await.unwrap().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    assert_eq!(
        error.to_string(),
        "connection failed before data completion"
    );
    assert!(
        !bridge.input(ACK, id, write.token, 0, b""),
        "late completion cannot revive a failed resource"
    );
    assert!(
        events.try_recv().is_err(),
        "shutdown must not send FIN after a failed data write"
    );
    assert!(bridge.resources.lock().unwrap().is_empty());
}

#[tokio::test]
async fn queued_data_is_delivered_before_a_later_native_failure() {
    let (bridge, mut events) = instance();
    let mut io = bounded(connection(&bridge, &mut events)).await;
    let id = io.id();
    // Fill the one-slot receive queue before failure closes its sender. The
    // original error must remain available even when it cannot enter that queue.
    assert_eq!(
        bridge.input_data(id, b"abcdefgh"),
        DataInputResult::Accepted
    );
    assert!(bridge.input(ERROR, id, 0, 4, b"receive failed after buffered data"));
    assert_eq!(
        (
            next_event(&mut events).await.kind,
            events.try_recv().is_err()
        ),
        (CLOSE, true)
    );

    let mut bytes = [0; 8];
    bounded(io.read_exact(&mut bytes))
        .await
        .expect("received bytes must precede failure");
    assert_eq!(bytes, *b"abcdefgh");
    let error = bounded(io.read_u8()).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    assert_eq!(error.to_string(), "receive failed after buffered data");
    let repeated = bounded(io.read_u8()).await.unwrap_err();
    assert_eq!(
        repeated.to_string(),
        error.to_string(),
        "failure must never turn into successful EOF"
    );
    assert!(
        events.try_recv().is_err(),
        "a failed resource must never request more native data"
    );
    assert!(bridge.resources.lock().unwrap().is_empty());
}

#[tokio::test]
async fn full_receive_queue_retains_its_original_data_and_recovers_after_consumption() {
    let (bridge, mut events) = instance();
    let mut io = bounded(connection(&bridge, &mut events)).await;
    let id = io.id();
    assert_eq!(bridge.input_data(id, b"first"), DataInputResult::Accepted);
    assert_eq!(bridge.input_data(id, b"rejected"), DataInputResult::Full);
    assert!(!bridge.input(DATA, id, 0, 0, b"also rejected"));
    assert_eq!(bridge.input_data(id, b""), DataInputResult::Invalid);
    assert_eq!(bridge.resources.lock().unwrap()[&id].rx.capacity(), 0);

    let mut first = [0; 5];
    bounded(io.read_exact(&mut first)).await.unwrap();
    assert_eq!(first, *b"first");
    assert_eq!(bridge.input_data(id, b"next"), DataInputResult::Accepted);
    let mut next = [0; 4];
    bounded(io.read_exact(&mut next)).await.unwrap();
    assert_eq!(next, *b"next");
    // The legacy EOF form still ignores any attached payload.
    assert!(bridge.input(DATA, id, 0, 1, b"not stream content"));
    assert_eq!(bounded(io.read(&mut [0])).await.unwrap(), 0);
    assert!(
        events.try_recv().is_err(),
        "buffered input needs no extra READ"
    );
}

#[tokio::test]
async fn late_data_before_native_close_preserves_original_error_and_parallel_flow() {
    let (bridge, mut events) = instance();
    let failed = bounded(connection(&bridge, &mut events)).await;
    let mut stable = bounded(connection(&bridge, &mut events)).await;
    let id = failed.id();
    let stable_id = stable.id();
    let mut reader = failed.read_half();
    let pending = tokio::spawn(async move { reader.read_u8().await });
    let read = next_event(&mut events).await;
    assert_eq!((read.kind, read.id), (READ, id));
    assert_eq!(bridge.resources.lock().unwrap()[&id].rx.capacity(), 1);
    assert!(bridge.input(ERROR, id, 0, 3, b"original receive deadline"));
    // Swift has not consumed the queued CLOSE when this callback arrives.
    assert_eq!(
        bridge.input_data(id, b"late content"),
        DataInputResult::Closed
    );
    assert!(!bridge.input(DATA, id, 0, 0, b"legacy late content"));
    assert!(!bridge.input(ERROR, id, 0, 4, b"must not replace original error"));
    let close = next_event(&mut events).await;
    assert_eq!((close.kind, close.id), (CLOSE, id));
    let error = bounded(pending).await.unwrap().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(error.to_string(), "original receive deadline");
    drop(failed);
    assert!(
        events.try_recv().is_err(),
        "late data must not emit a second CLOSE"
    );

    assert_eq!(
        bridge.input_data(stable_id, b"healthy"),
        DataInputResult::Accepted
    );
    let mut healthy = [0; 7];
    bounded(stable.read_exact(&mut healthy)).await.unwrap();
    assert_eq!(healthy, *b"healthy");
    assert!(bridge.resources.lock().unwrap().contains_key(&stable_id));
    assert!(events.try_recv().is_err(), "parallel flow must stay open");
}

#[tokio::test]
async fn dropped_receive_channel_is_closed_even_before_resource_release() {
    let (bridge, mut events) = instance();
    let io = bounded(connection(&bridge, &mut events)).await;
    let id = io.id();
    let lease = io.lease.clone();
    drop(io);
    assert!(bridge.resources.lock().unwrap()[&id].rx.is_closed());
    assert_eq!(
        bridge.input_data(id, b"late content"),
        DataInputResult::Closed
    );
    assert!(!bridge.input(DATA, id, 0, 0, b"legacy late content"));
    drop(lease);
    let close = next_event(&mut events).await;
    assert_eq!((close.kind, close.id), (CLOSE, id));
    assert!(events.try_recv().is_err());
}

#[tokio::test]
async fn partially_consumed_data_is_drained_before_the_original_native_failure() {
    let (bridge, mut events) = instance();
    let io = bounded(connection(&bridge, &mut events)).await;
    let id = io.id();
    let first_read = tokio::spawn(async move {
        let mut io = io;
        let mut first = [0; 3];
        io.read_exact(&mut first).await.unwrap();
        (io, first)
    });
    let read = next_event(&mut events).await;
    assert_eq!((read.kind, read.id), (READ, id));
    assert!(bridge.input(DATA, id, 0, 0, b"abcdefgh"));
    let (mut io, first) = bounded(first_read).await.unwrap();
    assert_eq!(first, *b"abc");
    assert!(bridge.input(ERROR, id, 0, 3, b"native receive deadline expired"));
    assert_eq!(
        (
            next_event(&mut events).await.kind,
            events.try_recv().is_err()
        ),
        (CLOSE, true)
    );

    let mut tail = [0; 5];
    bounded(io.read_exact(&mut tail))
        .await
        .expect("partially consumed receive must not lose its tail");
    assert_eq!(tail, *b"defgh");
    let error = bounded(io.read_u8()).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(error.to_string(), "native receive deadline expired");
    assert!(
        events.try_recv().is_err(),
        "buffer drainage must not request data from the failed resource"
    );
}

#[tokio::test]
async fn empty_reads_preserve_buffered_data_and_the_terminal_error() {
    let (bridge, mut events) = instance();
    let mut io = bounded(connection(&bridge, &mut events)).await;
    let id = io.id();
    assert_eq!(bounded(io.read(&mut [])).await.unwrap(), 0);
    assert!(
        events.try_recv().is_err(),
        "empty read must not issue native receive"
    );
    assert!(bridge.input(DATA, id, 0, 0, b"tail"));
    assert!(bridge.input(ERROR, id, 0, 4, b"failed after tail"));
    assert_eq!(next_event(&mut events).await.kind, CLOSE);
    assert_eq!(bounded(io.read(&mut [])).await.unwrap(), 0);
    let mut data = [0; 4];
    bounded(io.read_exact(&mut data)).await.unwrap();
    assert_eq!(data, *b"tail");
    assert_eq!(bounded(io.read(&mut [])).await.unwrap(), 0);
    assert_eq!(
        bounded(io.read_u8()).await.unwrap_err().to_string(),
        "failed after tail"
    );
    assert!(events.try_recv().is_err());
}

#[tokio::test]
async fn buffered_reads_do_not_delay_failed_writes_or_affect_another_resource() {
    let (bridge, mut events) = instance();
    let mut failed = bounded(connection(&bridge, &mut events)).await;
    let mut stable = bounded(connection(&bridge, &mut events)).await;
    let failed_id = failed.id();
    let stable_id = stable.id();
    assert!(bridge.input(DATA, failed_id, 0, 0, b"retained response"));
    assert!(bridge.input(ERROR, failed_id, 0, 4, b"failed with unread response"));
    let close = next_event(&mut events).await;
    assert_eq!((close.kind, close.id), (CLOSE, failed_id));
    for error in [
        bounded(failed.write_all(b"must not send"))
            .await
            .unwrap_err(),
        bounded(failed.shutdown()).await.unwrap_err(),
    ] {
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(error.to_string(), "failed with unread response");
    }
    assert!(
        events.try_recv().is_err(),
        "failure must reject writes and FIN immediately"
    );
    assert!(bridge.resources.lock().unwrap().contains_key(&stable_id));
    assert!(bridge.input(DATA, stable_id, 0, 0, b"still healthy"));
    let mut stable_response = [0; 13];
    bounded(stable.read_exact(&mut stable_response))
        .await
        .unwrap();
    assert_eq!(stable_response, *b"still healthy");
    let mut retained = [0; 17];
    bounded(failed.read_exact(&mut retained)).await.unwrap();
    assert_eq!(retained, *b"retained response");
    assert_eq!(
        bounded(failed.read_u8()).await.unwrap_err().to_string(),
        "failed with unread response"
    );
    assert!(events.try_recv().is_err());
}

#[tokio::test]
async fn native_failure_is_not_hidden_by_a_queued_or_previously_observed_eof() {
    for observed_eof in [false, true] {
        let (bridge, mut events) = instance();
        let mut io = bounded(connection(&bridge, &mut events)).await;
        let id = io.id();
        if observed_eof {
            assert!(bridge.input(DATA, id, 0, 1, b""));
            assert_eq!(bounded(io.read(&mut [0])).await.unwrap(), 0);
        } else {
            let first_read = tokio::spawn(async move {
                let mut first = [0; 3];
                io.read_exact(&mut first).await.unwrap();
                (io, first)
            });
            let read = next_event(&mut events).await;
            assert_eq!((read.kind, read.id), (READ, id));
            assert!(bridge.input(DATA, id, 0, 0, b"abcdefgh"));
            let (returned, first) = bounded(first_read).await.unwrap();
            io = returned;
            assert_eq!(first, *b"abc");
            assert!(bridge.input(DATA, id, 0, 1, b""));
        }
        assert!(bridge.input(ERROR, id, 0, 4, b"connection failed after receive EOF"));
        assert_eq!(next_event(&mut events).await.kind, CLOSE);
        if !observed_eof {
            let mut tail = [0; 5];
            bounded(io.read_exact(&mut tail)).await.unwrap();
            assert_eq!(tail, *b"defgh");
        }
        let error = bounded(io.read_u8()).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(error.to_string(), "connection failed after receive EOF");
        assert!(
            events.try_recv().is_err(),
            "failed EOF resource must not request another receive"
        );
    }
}

#[tokio::test]
async fn security_failure_rejects_purported_data_immediately() {
    let (bridge, mut events) = instance();
    let mut io = bounded(connection(&bridge, &mut events)).await;
    let id = io.id();
    assert!(bridge.input(DATA, id, 0, 0, b"untrusted peer content"));
    assert!(bridge.input(ERROR, id, 0, 1, b"TLS certificate rejected"));
    assert_eq!(next_event(&mut events).await.kind, CLOSE);
    let mut bytes = [0; 32];
    let error = bounded(io.read(&mut bytes)).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), "TLS certificate rejected");
    assert!(
        bytes.iter().all(|byte| *byte == 0),
        "rejected security data must not become caller-visible"
    );
    assert!(events.try_recv().is_err());
}

#[tokio::test]
async fn security_failure_during_open_preserves_reason_without_waiting_for_timeout() {
    for kind in [OPEN_TCP, OPEN_QUIC] {
        let (bridge, mut events) = instance();
        let owner = bridge.clone();
        let pending = tokio::spawn(async move { owner.open(kind, 0, 0, Vec::new()).await });
        let event = next_event(&mut events).await;
        assert_eq!(event.kind, kind);
        let reason = b"Certificate validation for relay.test failed: name mismatch";
        assert!(bridge.input(ERROR, event.id, 0, 1, reason));
        let error = match bounded(pending).await.unwrap() {
            Err(error) => error,
            Ok(_) => panic!("rejected native TLS connection became ready"),
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), String::from_utf8_lossy(reason));
        assert!(bridge.resources.lock().unwrap().is_empty());
        let close = next_event(&mut events).await;
        assert_eq!((close.kind, close.id), (CLOSE, event.id));
        assert!(!bridge.input(READY, event.id, 0, 0, b"{}"));
        assert!(events.try_recv().is_err());
    }
}

#[tokio::test]
async fn malformed_ready_stream_ids_and_empty_data_are_rejected() {
    let (bridge, mut events) = instance();
    let owner = bridge.clone();
    let pending = tokio::spawn(async move { owner.tcp(vec![]).await });
    let event = events.recv().await.unwrap();
    bridge.input(
        READY,
        event.id,
        0,
        0,
        &serde_json::to_vec(&Ready {
            stream_id: 1 << 62,
            ..Ready::default()
        })
        .unwrap(),
    );
    assert_eq!(
        pending
            .await
            .unwrap()
            .err()
            .expect("invalid metadata must fail")
            .kind(),
        io::ErrorKind::InvalidData
    );
    let io = connection(&bridge, &mut events).await;
    assert!(!bridge.input(DATA, io.id(), 0, 0, b""));
    assert_eq!(bridge.accept(io.id(), 1 << 62, Ready::default()), 0);
}

#[test]
fn udp_framing_supports_ipv4_ipv6_and_rejects_invalid_lengths() {
    for text in ["127.0.0.1:1080", "[::1]:1080", "[2001:db8::1]:443"] {
        let address: SocketAddr = text.parse().unwrap();
        assert_eq!(
            unpack_udp(&pack_udp(address, b"payload")),
            Some((address, Bytes::from_static(b"payload")))
        );
    }
    for invalid in [
        &b""[..],
        &b"\x00"[..],
        &b"\x00\xffshort"[..],
        &b"\x00\x04evil"[..],
    ] {
        assert!(unpack_udp(invalid).is_none())
    }
}

#[tokio::test]
async fn incoming_datagrams_are_bounded_and_report_overflow() {
    let (bridge, mut events) = instance();
    let io = connection(&bridge, &mut events).await;
    // tcp() does not keep a datagram receiver: unsolicited datagrams are rejected.
    assert!(!bridge.input(IN_DATAGRAM, io.id(), 0, 0, b"unrequested"));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), events.recv())
            .await
            .is_err()
    );
    let owner = bridge.clone();
    let pending = tokio::spawn(async move { Quic::open(owner, vec![]).await });
    let e = events.recv().await.unwrap();
    bridge.input(
        READY,
        e.id,
        0,
        0,
        &serde_json::to_vec(&Ready {
            alpn: "h3".into(),
            ..Ready::default()
        })
        .unwrap(),
    );
    let mut quic = pending.await.unwrap().unwrap();
    for _ in 0..128 {
        assert!(bridge.input(IN_DATAGRAM, quic.io.id(), 0, 0, b"datagram"));
    }
    assert!(!bridge.input(IN_DATAGRAM, quic.io.id(), 0, 0, b"overflow"));
    assert_eq!(quic.datagrams.recv().await.unwrap(), b"datagram"[..]);
    assert!(bridge.input(IN_DATAGRAM, quic.io.id(), 0, 0, b"room again"));
}

#[tokio::test]
async fn abort_resets_the_native_connection_and_wakes_pending_io() {
    let (bridge, mut events) = instance();
    let io = connection(&bridge, &mut events).await;
    let id = io.id();
    let mut reader = io.read_half();
    let read = tokio::spawn(async move { reader.read_u8().await });
    assert_eq!(events.recv().await.unwrap().kind, READ);
    io.abort();
    let close = next_event(&mut events).await;
    assert_eq!((close.kind, close.id, close.flags), (CLOSE, id, ABORT));
    assert_eq!(
        read.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
    drop(io);
    assert!(bridge.resources.lock().unwrap().is_empty());
    assert!(
        events.try_recv().is_err(),
        "no graceful close after the abort"
    );
}

async fn ready_listener(
    bridge: &Arc<Bridge>,
    events: &mut mpsc::Receiver<Event>,
) -> (TcpListener, u64) {
    let owner = bridge.clone();
    let opening = tokio::spawn(async move { owner.listen("127.0.0.1:0".parse().unwrap()).await });
    let event = next_event(events).await;
    assert_eq!(event.kind, LISTEN);
    bridge.input(
        READY,
        event.id,
        0,
        0,
        &serde_json::to_vec(&Ready {
            local: "127.0.0.1:19080".into(),
            ..Ready::default()
        })
        .unwrap(),
    );
    (opening.await.unwrap().unwrap(), event.id)
}

#[tokio::test]
async fn listener_preserves_native_resource_exhaustion() {
    let (bridge, mut events) = instance();
    let (listener, id) = ready_listener(&bridge, &mut events).await;
    assert!(bridge.input(ERROR, id, 0, 5, b"Too many open files"));
    let error = bounded(listener.accept()).await.err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
    assert!(error.to_string().contains("Too many open files"));
}

#[tokio::test]
async fn failed_queued_child_does_not_kill_its_listener() {
    let (bridge, mut events) = instance();
    let (listener, parent) = ready_listener(&bridge, &mut events).await;
    let ready = Ready {
        local: "127.0.0.1:19080".into(),
        peer: "127.0.0.1:50000".into(),
        ..Ready::default()
    };
    let failed = bridge.accept(parent, 0, ready.clone());
    assert!(bridge.input(ERROR, failed, 0, 4, b"connection reset before acceptance"));
    let healthy = bridge.accept(parent, 0, ready);
    let (accepted, _) = bounded(listener.accept()).await.unwrap();
    assert_eq!(accepted.id(), healthy);
    drop((accepted, listener));
    assert!(bridge.resources.lock().unwrap().is_empty());
}

async fn next_kind(events: &mut mpsc::Receiver<Event>, kind: u32) -> Event {
    bounded(async {
        loop {
            let event = events.recv().await.unwrap();
            if event.kind == kind {
                return event;
            }
        }
    })
    .await
}

async fn listener_recovery(mode: u8) {
    let (bridge, mut events) = instance();
    let (listener, id) = ready_listener(&bridge, &mut events).await;
    let config = network_relay_nf_core::Config {
        uri_template: "https://relay.test/.well-known/masque/udp/{target_host}/{target_port}/"
            .into(),
        username: "alice".into(),
        password: "disposable-test-password".into(),
        server_name: None,
        transport: "http/1.1".into(),
        probe_target: "127.0.0.1:53".parse().unwrap(),
        mode: "socks".into(),
        socks: network_relay_nf_core::Socks {
            listen: vec!["127.0.0.1:0".parse().unwrap()],
        },
    };
    let client =
        Arc::new(network_relay_nf_core::client::Client::new(&config, bridge.clone()).unwrap());
    let worker = tokio::spawn(network_relay_nf_core::socks::run(client, vec![listener]));
    bridge.input(ERROR, id, 0, 5, b"Too many open files");
    let retry = next_kind(&mut events, LISTEN).await;
    assert_eq!(&retry.data[..], b"127.0.0.1:19080");
    if mode != 0 {
        if mode == 1 {
            bridge.stop.cancel();
        } else {
            bridge.input(ERROR, retry.id, 0, 2, b"address already in use");
        }
        let result = bounded(worker).await.unwrap();
        assert_eq!(result.is_ok(), mode == 1);
        assert!(!std::iter::from_fn(|| events.try_recv().ok()).any(|event| event.kind == LISTEN));
        bounded(async {
            while !bridge.resources.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await;
        return;
    }
    bridge.input(ERROR, retry.id, 0, 5, b"Still out of descriptors");
    let retry = next_kind(&mut events, LISTEN).await;
    assert_eq!(&retry.data[..], b"127.0.0.1:19080");
    bridge.input(
        READY,
        retry.id,
        0,
        0,
        &serde_json::to_vec(&Ready {
            local: "127.0.0.1:19080".into(),
            ..Ready::default()
        })
        .unwrap(),
    );
    let accepted = bridge.accept(
        retry.id,
        0,
        Ready {
            local: "127.0.0.1:19080".into(),
            peer: "127.0.0.1:50000".into(),
            ..Ready::default()
        },
    );
    let read = next_kind(&mut events, READ).await;
    assert_eq!(
        read.id, accepted,
        "the recovered listener must accept new SOCKS clients"
    );
    bridge.stop.cancel();
    bounded(worker).await.unwrap().unwrap();
    bounded(async {
        while !bridge.resources.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;
}

#[tokio::test]
async fn socks_reopens_the_same_listener_after_temporary_native_exhaustion() {
    listener_recovery(0).await;
}

#[tokio::test]
async fn cancelling_listener_recovery_releases_the_pending_native_open() {
    listener_recovery(1).await;
}

#[tokio::test]
async fn listener_recovery_does_not_hide_a_permanent_bind_error() {
    listener_recovery(2).await;
}
