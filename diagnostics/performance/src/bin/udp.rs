use bytes::{BufMut, BytesMut};
use std::hint::black_box;
use std::io::{IoSlice, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Instant;

include!("../wire.rs");

fn original(payload: &[u8]) -> BytesMut {
    let mut value = BytesMut::with_capacity(payload.len() + 1);
    encode(0, &mut value);
    value.extend_from_slice(payload);
    let mut out = BytesMut::with_capacity(1 + encoded_len(value.len() as u64) + value.len());
    encode(0, &mut out);
    encode(value.len() as u64, &mut out);
    out.extend_from_slice(&value);
    out
}
fn header(payload: &[u8], out: &mut impl BufMut) {
    encode(0, out);
    encode(payload.len() as u64 + 1, out);
    encode(0, out);
}
fn trial(kind: &str, size: usize, socket: bool, round: usize) {
    let p: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let expected = original(&p);
    assert_eq!(owned(&p), expected);
    let n = if socket {
        if size > 2000 {
            1000
        } else {
            12000
        }
    } else if size > 2000 {
        4000
    } else {
        120000
    };
    let (mut tx, mut rx) = UnixStream::pair().unwrap();
    let reader = socket.then(|| {
        let frame = expected.clone();
        std::thread::spawn(move || {
            let mut wire = vec![0; frame.len()];
            for _ in 0..n {
                rx.read_exact(&mut wire).unwrap();
                assert_eq!(wire, frame);
            }
            let mut last = [0u8; 1];
            assert_eq!(rx.read(&mut last).unwrap(), 0);
        })
    });
    let mut cached = BytesMut::new();
    let start = Instant::now();
    for _ in 0..n {
        let data = black_box(p.as_slice());
        if kind == "vectored" {
            let mut h = [0u8; 10];
            let mut cursor = &mut h[..];
            header(data, &mut cursor);
            let used = 10 - cursor.len();
            if socket {
                let mut bufs = [IoSlice::new(&h[..used]), IoSlice::new(data)];
                let mut rest = &mut bufs[..];
                while !rest.is_empty() {
                    match tx.write_vectored(rest) {
                        Ok(0) => panic!("unexpected write zero"),
                        Ok(k) => IoSlice::advance_slices(&mut rest, k),
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(e) => panic!("{e}"),
                    }
                }
            } else {
                black_box((&h[..used], data));
            }
        } else {
            let owned;
            let wire: &[u8] = match kind {
                "original" => {
                    owned = original(data);
                    &owned
                }
                "one" => {
                    owned = crate::owned(data);
                    &owned
                }
                "retained" => {
                    cached.clear();
                    cached.reserve(1 + encoded_len(size as u64 + 1) + size + 1);
                    header(data, &mut cached);
                    cached.extend_from_slice(data);
                    &cached
                }
                _ => unreachable!(),
            };
            if socket {
                tx.write_all(wire).unwrap();
            } else {
                black_box(wire);
            }
        }
    }
    drop(tx);
    if let Some(h) = reader {
        h.join().unwrap();
    }
    println!("{round} {socket} {size} {kind} {:.2}", start.elapsed().as_nanos() as f64 / n as f64);
}
fn main() {
    let kinds = ["original", "one", "retained", "vectored"];
    for round in 0..4 {
        for socket in [false, true] {
            for size in [0, 63, 64, 1200, 65507] {
                for i in 0..4 {
                    let k = (if round % 2 == 0 { i } else { 3 - i } + round / 2) % 4;
                    trial(kinds[k], size, socket, round);
                }
            }
        }
    }
}
