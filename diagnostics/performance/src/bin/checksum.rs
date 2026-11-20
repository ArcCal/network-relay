use std::hint::black_box;
use std::time::Instant;

fn reference(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in data.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
        sum = (sum >> 16) + (sum & 0xffff);
    }
    sum as u16
}

fn main() {
    let variant = std::env::args().nth(1).unwrap();
    let input: Vec<u8> = (0..262160).map(|i| ((i * 31 + i / 739) % 256) as u8).collect();
    let full = vec![255u8; input.len()];
    let mut lengths: Vec<usize> = (0..1537).collect();
    lengths.extend([8191, 65534, 65535]);
    if variant == "wide" || variant == "both" {
        lengths.extend([65536, 65537, 131071, 131072, 131073, 262144, 262145]);
    }
    for offset in 0..8 {
        for input in [&input, &full] {
            for &n in &lengths {
                let data = &input[offset..offset+n];
                assert_eq!(smoltcp::wire::checksum::data(data), reference(data));
            }
        }
    }
    for n in [20, 40, 64, 1240, 1280, 65535] {
        let count = (32 << 20) / n;
        let t = Instant::now();
        for i in 0..count {
            let k = i % 8;
            black_box(smoltcp::wire::checksum::data(black_box(&input[k..k + n])));
        }
        println!("SUM {variant} {n} {count} {}", t.elapsed().as_nanos());
    }
}
