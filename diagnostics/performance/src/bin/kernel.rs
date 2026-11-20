#![allow(dead_code)]
#[path = "../netstack.rs"]
mod netstack;

use bytes::Bytes;
use netstack::NetStack;
use ring::digest::{Context, SHA256};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::FromRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

async fn from_kernel(tun: Arc<AsyncFd<File>>, tx: mpsc::Sender<Bytes>) -> io::Result<()> {
    let mut buf = [0; 2048];
    loop {
        let mut ready = tun.readable().await?;
        let packet = match ready.try_io(|f| (&*f.get_ref()).read(&mut buf)) {
            Ok(n) => Bytes::copy_from_slice(&buf[..n?]),
            Err(_) => continue,
        };
        if tx.send(packet).await.is_err() {
            return Ok(());
        }
    }
}

async fn to_kernel(tun: Arc<AsyncFd<File>>, mut rx: mpsc::Receiver<Bytes>) -> io::Result<()> {
    while let Some(packet) = rx.recv().await {
        loop {
            let mut ready = tun.writable().await?;
            match ready.try_io(|f| (&*f.get_ref()).write(&packet)) {
                Ok(n) => {
                    if n? != packet.len() {
                        return Err(io::Error::other("short TUN packet"));
                    }
                    break;
                }
                Err(_) => continue,
            }
        }
    }
    Ok(())
}

async fn receive_all(stream: &mut (impl AsyncRead + Unpin), length: usize, expected: &[u8]) -> io::Result<()> {
    let mut hash = Context::new(&SHA256);
    let mut buf = [0; 65536];
    let mut total = 0;
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        total += n;
        if total > length {
            return Err(io::Error::other("response too long"));
        }
        hash.update(&buf[..n]);
    }
    if total != length || hash.finish().as_ref() != expected {
        return Err(io::Error::other("bad payload or EOF"));
    }
    Ok(())
}

async fn write_all(stream: &mut (impl AsyncWrite + Unpin), pattern: &[u8], length: usize) -> io::Result<()> {
    for _ in 0..length / pattern.len() {
        stream.write_all(pattern).await?;
    }
    stream.shutdown().await
}

async fn trial(flows: usize, length: usize, mode: &str, rtt: u32) -> io::Result<()> {
    let raw = std::env::var("RELAY_TEST_TUN_FD").unwrap().parse::<i32>().unwrap();
    // The fixture passes its uniquely owned, nonblocking TUN descriptor through exec.
    let tun = Arc::new(AsyncFd::new(unsafe { File::from_raw_fd(raw) })?);
    let (a, b) = mpsc::channel(4096);
    let (c, d) = mpsc::channel(4096);
    let stack = NetStack::new(0);
    stack.set_addresses(&["198.18.0.1".parse().unwrap()]);
    let runner = tokio::spawn({
        let stack = stack.clone();
        async move { stack.run(b, c).await }
    });
    let in_task = tokio::spawn(from_kernel(tun.clone(), a));
    let out_task = tokio::spawn(to_kernel(tun, d));
    let listener = TcpListener::bind("198.18.0.2:0").await?;
    let address = listener.local_addr()?;
    let up = Bytes::from((0..65536).map(|i| ((i * 11 + 9) % 251) as u8).collect::<Vec<_>>());
    let down = Bytes::from((0..65536).map(|i| ((i * 17 + 3) % 251) as u8).collect::<Vec<_>>());
    let digest = |pattern: &[u8]| {
        let mut state = Context::new(&SHA256);
        for _ in 0..length / pattern.len() {
            state.update(pattern);
        }
        state.finish()
    };
    let up_hash = digest(&up);
    let down_hash = digest(&down);
    let linux = tokio::spawn(async move {
        let mut requests = JoinSet::new();
        for _ in 0..flows {
            let (mut stream, _) = listener.accept().await?;
            stream.set_nodelay(true)?;
            let (hash, data) = (up_hash, down.clone());
            requests.spawn(async move {
                receive_all(&mut stream, length, hash.as_ref()).await?;
                write_all(&mut stream, &data, length).await
            });
        }
        while let Some(done) = requests.join_next().await {
            done??;
        }
        Ok::<_, io::Error>(())
    });
    let mut senders = JoinSet::new();
    let wall = Instant::now();
    for _ in 0..flows {
        let (stack, up, expected) = (stack.clone(), up.clone(), down_hash);
        senders.spawn(async move {
            let mut stream = stack.connect(address).await?;
            let began = Instant::now();
            write_all(&mut stream, &up, length).await?;
            // The first reply byte proves that the independent kernel peer accepted
            // and checked the entire upload and its FIN.
            let mut first = [0; 1];
            stream.read_exact(&mut first).await?;
            let reply_at = Instant::now();
            let mut received = AsyncReadExt::chain(&first[..], &mut stream);
            receive_all(&mut received, length, expected.as_ref()).await?;
            Ok::<_, io::Error>((reply_at.duration_since(began).as_secs_f64(), reply_at.elapsed().as_secs_f64()))
        });
    }
    let mut durations = Vec::new();
    while let Some(done) = senders.join_next().await {
        durations.push(done??);
    }
    linux.await??;
    let total_s = wall.elapsed().as_secs_f64();
    let deadline = Instant::now() + Duration::from_secs(15);
    while stack.socket_counts() != (0, 0) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    if stack.queue_drops() != 0 || stack.socket_counts() != (0, 0) {
        return Err(io::Error::other("unreclaimed socket or packet queue drops"));
    }
    println!(
        "{}",
        serde_json::json!({"mode":mode,"rtt":rtt,"length":length,"flows":flows,"wall":total_s,"times":durations,"checked_bytes":2*length*flows,"drops":stack.queue_drops(),"remaining":stack.socket_counts()})
    );
    in_task.abort();
    out_task.abort();
    runner.abort();
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> io::Result<()> {
    let a: Vec<_> = std::env::args().collect();
    tokio::time::timeout(
        Duration::from_secs(150),
        trial(a[1].parse().unwrap(), a[2].parse().unwrap(), &a[3], a[4].parse().unwrap()),
    )
    .await?
}
