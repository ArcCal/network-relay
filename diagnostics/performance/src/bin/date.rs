use chrono::{DateTime, Utc};
use http::HeaderValue;
use std::hint::black_box;
use std::sync::{Barrier, RwLock};
use std::time::Instant;

include!("../date.rs");

fn format_full(t: DateTime<Utc>) -> HeaderValue {
    HeaderValue::try_from(t.format("%a, %d %b %Y %H:%M:%S GMT").to_string()).unwrap()
}
fn shared(t: DateTime<Utc>) -> HeaderValue {
    static CACHE: RwLock<Option<(i64, HeaderValue)>> = RwLock::new(None);
    if let Some((sec, v)) = &*CACHE.read().unwrap() {
        if *sec == t.timestamp() {
            return v.clone();
        }
    }
    let value = format_full(t);
    *CACHE.write().unwrap() = Some((t.timestamp(), value.clone()));
    value
}
fn specialised(t: DateTime<Utc>) -> HeaderValue {
    HeaderValue::try_from(httpdate::fmt_http_date(t.into())).unwrap()
}
type Format = fn(DateTime<Utc>) -> HeaderValue;
fn main() {
    let variants: [(&str, Format); 4] =
        [("original", format_full), ("thread", http_date_at), ("shared", shared), ("specialised", specialised)];
    for (_, format) in variants {
        for second in [1_700_000_000, 1_700_000_000, 1_700_000_001, 1_699_900_000, 0, 4_102_444_800] {
            let t = DateTime::from_timestamp(second, 999_999_999).unwrap();
            assert_eq!(format(t), format_full(t));
        }
    }
    for round in 0..4 {
        for mode in ["real", "changes"] {
            for threads in [1, 4] {
                for i in 0..4 {
                    let (name, f) = variants[(if round % 2 == 0 { i } else { 3 - i } + round / 2) % 4];
                    let gate = Barrier::new(threads + 1);
                    let n = if mode == "real" { 120_000 } else { 24_000 };
                    let elapsed = std::thread::scope(|scope| {
                        for _ in 0..threads {
                            scope.spawn(|| {
                                gate.wait();
                                for j in 0..n {
                                    let t = if mode == "real" {
                                        Utc::now()
                                    } else {
                                        DateTime::from_timestamp(1_700_000_000 + (j % 300) as i64, 0).unwrap()
                                    };
                                    black_box(f(black_box(t)));
                                }
                            });
                        }
                        let start = Instant::now();
                        gate.wait();
                        start
                    })
                    .elapsed();
                    println!("{round} {mode} {threads} {name} {:.2}", elapsed.as_nanos() as f64 / (threads * n) as f64);
                }
            }
        }
    }
}
