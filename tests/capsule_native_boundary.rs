//! Preserve RFC 9297 framing at the native 63-byte UDP boundary.

use network_relay::proto::{capsule::CapsuleDecoder, datagram::split_context_id, Error};

#[test]
fn native_udp63_truncation_waits_for_the_declared_value() {
    let payload: Vec<u8> = (0..63).collect();
    let mut wire = vec![0x00, 0x40, 0x40, 0x00];
    wire.extend_from_slice(&payload);
    assert_eq!(wire.len(), 67);
    let mut decoder = CapsuleDecoder::default();
    decoder.push(&wire[..66]);
    assert!(decoder.next_udp_capsule().unwrap().is_none());
    assert!(matches!(decoder.finish(), Err(Error::Malformed(_))));

    // Completing a fragmented read must preserve the exact final byte.
    decoder.push(&wire[66..]);
    let capsule = decoder.next_udp_capsule().unwrap().unwrap();
    assert_eq!(split_context_id(&capsule.value).unwrap(), (0, payload.as_slice()));
    decoder.finish().unwrap();
}

#[test]
fn native_udp63_boundary_keeps_nonminimal_encodings_and_unknown_capsules_valid() {
    let payload: Vec<u8> = (0..63).collect();
    for prefix in [
        vec![0x00, 0x40, 0x40, 0x00],
        vec![0x40, 0x00, 0x40, 0x40, 0x00],
        vec![0x00, 0x80, 0x00, 0x00, 0x40, 0x00],
        vec![0x00, 0x40, 0x41, 0x40, 0x00],
    ] {
        let mut wire = prefix;
        wire.extend_from_slice(&payload);
        // Unknown type 1450, empty value, followed by a valid DATAGRAM.
        wire.extend_from_slice(&[0x45, 0xaa, 0x00, 0x00, 0x40, 0x40, 0x00]);
        wire.extend_from_slice(&payload);
        for width in [1, 2, 17, 67] {
            let mut decoder = CapsuleDecoder::default();
            let mut received = Vec::new();
            for chunk in wire.chunks(width) {
                decoder.push(chunk);
                while let Some(capsule) = decoder.next_udp_capsule().unwrap() {
                    let (context, bytes) = split_context_id(&capsule.value).unwrap();
                    assert_eq!(context, 0);
                    received.push(bytes.to_vec());
                }
            }
            decoder.finish().unwrap();
            assert_eq!(received, [payload.clone(), payload.clone()]);
        }
    }
}
