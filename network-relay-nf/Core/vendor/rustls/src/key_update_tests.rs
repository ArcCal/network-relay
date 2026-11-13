//! RFC 9846 section 4.7.3 regression tests. Only test confidentiality limits are accelerated.
use std::boxed::Box;
use std::io::{self, Cursor, Read, Write};
use std::println;
use std::string::String;
use std::sync::{Arc, Mutex};
use std::vec;
use std::vec::Vec;

use super::{CommonState, KeyUpdateRequest, MAX_KEY_UPDATE_EPOCH, Side};
use crate::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use crate::server::UnbufferedServerConnection;
use crate::unbuffered::{ConnectionState, EncryptError};
use crate::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
use ring::{aead, hkdf};

#[derive(Debug, Default)]
struct Log(Mutex<Vec<(String, Vec<u8>)>>);
impl crate::KeyLog for Log {
    fn log(&self, label: &str, _: &[u8], secret: &[u8]) {
        self.0
            .lock()
            .unwrap()
            .push((label.into(), secret.to_vec()));
    }
}
struct Len(usize);
impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}
fn expand(secret: &[u8], label: &[u8], length: usize) -> Vec<u8> {
    let mut info = (length as u16).to_be_bytes().to_vec();
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret);
    let refs = [&info[..]];
    let okm = prk.expand(&refs, Len(length)).unwrap();
    let mut out = vec![0; length];
    okm.fill(&mut out).unwrap();
    out
}
fn configs(limit: u64) -> (Arc<ClientConfig>, Arc<ServerConfig>, Arc<Log>) {
    let original = crate::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .unwrap();
    let suite = Box::leak(Box::new(crate::Tls13CipherSuite {
        common: crate::CipherSuiteCommon {
            suite: original.common.suite,
            hash_provider: original.common.hash_provider,
            confidentiality_limit: limit,
        },
        hkdf_provider: original.hkdf_provider,
        aead_alg: original.aead_alg,
        quic: None,
    }));
    let mut provider = crate::crypto::ring::default_provider();
    provider.cipher_suites = vec![crate::SupportedCipherSuite::Tls13(suite)];
    let provider = Arc::new(provider);
    let cert = rcgen::generate_simple_self_signed(vec!["relay.test".into()]).unwrap();
    let mut roots = crate::RootCertStore::empty();
    roots
        .add(cert.cert.der().clone())
        .unwrap();
    let mut cc = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&crate::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut sc = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&crate::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
        )
        .unwrap();
    sc.send_tls13_tickets = 0;
    let log = Arc::new(Log::default());
    cc.key_log = log.clone();
    sc.key_log = log.clone();
    (Arc::new(cc), Arc::new(sc), log)
}
fn pair(limit: u64) -> (ClientConnection, ServerConnection, Arc<Log>) {
    let (cc, sc, log) = configs(limit);
    let mut c = ClientConnection::new(cc, ServerName::try_from("relay.test").unwrap()).unwrap();
    let mut s = ServerConnection::new(sc).unwrap();
    for _ in 0..16 {
        let mut bytes = Vec::new();
        c.write_tls(&mut bytes).unwrap();
        s.read_tls(&mut Cursor::new(bytes))
            .unwrap();
        s.process_new_packets().unwrap();
        let mut bytes = Vec::new();
        s.write_tls(&mut bytes).unwrap();
        c.read_tls(&mut Cursor::new(bytes))
            .unwrap();
        c.process_new_packets().unwrap();
        if !c.is_handshaking() && !s.is_handshaking() && !c.wants_write() && !s.wants_write() {
            return (c, s, log);
        }
    }
    panic!("handshake did not finish");
}
#[derive(Debug, Default)]
struct Records {
    flags: Vec<u8>,
    applications: usize,
    alerts: Vec<Vec<u8>>,
    per_epoch: Vec<usize>,
}
fn decode(output: &[u8], log: &Log, label: &str) -> Records {
    let mut secret = log
        .0
        .lock()
        .unwrap()
        .iter()
        .find(|(l, _)| l == label)
        .unwrap()
        .1
        .clone();
    let mut result = Records {
        per_epoch: vec![0],
        ..Records::default()
    };
    let mut seq = 0u64;
    let mut offset = 0;
    while offset < output.len() {
        let header: [u8; 5] = output[offset..offset + 5]
            .try_into()
            .unwrap();
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut record = output[offset + 5..offset + 5 + len].to_vec();
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_128_GCM, &expand(&secret, b"key", 16)).unwrap(),
        );
        let mut nonce: [u8; 12] = expand(&secret, b"iv", 12)
            .try_into()
            .unwrap();
        for (n, s) in nonce[4..]
            .iter_mut()
            .zip(seq.to_be_bytes())
        {
            *n ^= s;
        }
        let plain = key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(header),
                &mut record,
            )
            .unwrap();
        let type_at = plain
            .iter()
            .rposition(|&b| b != 0)
            .unwrap();
        *result.per_epoch.last_mut().unwrap() += 1;
        match plain[type_at] {
            23 => {
                result.applications += 1;
                seq += 1;
            }
            22 => {
                assert_eq!(&plain[..4], &[24, 0, 0, 1]);
                result.flags.push(plain[4]);
                secret = expand(&secret, b"traffic upd", 32);
                seq = 0;
                result.per_epoch.push(0);
            }
            21 => {
                result
                    .alerts
                    .push(plain[..type_at].to_vec());
                seq += 1;
            }
            n => panic!("unexpected record type {n}"),
        }
        offset += 5 + len;
    }
    result
}
#[test]
fn automatic_refresh_requests_only_once_without_peer_updates() {
    for server_side in [true, false] {
        let (mut c, mut s, log) = pair(16);
        let mut out = Vec::new();
        for _ in 0..48 {
            if server_side {
                s.writer()
                    .write_all(&[b'a'; 32])
                    .unwrap();
                s.write_tls(&mut out).unwrap();
            } else {
                c.writer()
                    .write_all(&[b'a'; 32])
                    .unwrap();
                c.write_tls(&mut out).unwrap();
            }
        }
        let records = decode(
            &out,
            &log,
            if server_side {
                "SERVER_TRAFFIC_SECRET_0"
            } else {
                "CLIENT_TRAFFIC_SECRET_0"
            },
        );
        println!(
            "server_side={server_side}; application_records={}; automatic_update_flags={:?}; per_epoch_records={:?}; peer_updates=0",
            records.applications, records.flags, records.per_epoch
        );
        assert_eq!(records.applications, 48);
        assert_eq!(records.flags, vec![1, 0, 0]);
        assert!(
            records
                .per_epoch
                .iter()
                .all(|&n| n <= 16)
        );
    }
}
#[test]
fn manual_refresh_uses_old_keys_and_suppresses_repeated_requests() {
    let (_, mut s, log) = pair(16);
    let mut out = Vec::new();
    for _ in 0..3 {
        s.refresh_traffic_keys().unwrap();
    }
    s.writer()
        .write_all(b"still works")
        .unwrap();
    s.write_tls(&mut out).unwrap();
    let records = decode(&out, &log, "SERVER_TRAFFIC_SECRET_0");
    assert_eq!(records.flags, vec![1, 0, 0]);
    assert_eq!(records.applications, 1);
    assert_eq!(
        s.core
            .common_state
            .key_update_state
            .send_epoch,
        3
    );
}
#[test]
fn valid_peer_update_rearms_request_invalid_update_does_not() {
    let (_, mut s, _) = pair(16);
    s.refresh_traffic_keys().unwrap();
    assert!(
        s.core
            .common_state
            .key_update_state
            .request_pending
    );
    assert!(
        !s.core
            .common_state
            .should_update_key(&KeyUpdateRequest::UpdateNotRequested)
            .unwrap()
    );
    assert!(
        !s.core
            .common_state
            .key_update_state
            .request_pending
    );
    s.refresh_traffic_keys().unwrap();
    assert!(
        s.core
            .common_state
            .key_update_state
            .request_pending
    );
    assert!(
        s.core
            .common_state
            .should_update_key(&KeyUpdateRequest::Unknown(2))
            .is_err()
    );
    assert!(
        s.core
            .common_state
            .key_update_state
            .request_pending
    );
}
#[test]
fn crossed_requests_advance_both_generations_and_exchange_data() {
    let (mut c, mut s, _) = pair(64);
    c.refresh_traffic_keys().unwrap();
    s.refresh_traffic_keys().unwrap();
    let mut co = Vec::new();
    let mut so = Vec::new();
    c.write_tls(&mut co).unwrap();
    s.write_tls(&mut so).unwrap();
    c.read_tls(&mut Cursor::new(so))
        .unwrap();
    c.process_new_packets().unwrap();
    s.read_tls(&mut Cursor::new(co))
        .unwrap();
    s.process_new_packets().unwrap();
    assert_eq!(
        c.core
            .common_state
            .key_update_state
            .send_epoch,
        2
    );
    assert_eq!(
        s.core
            .common_state
            .key_update_state
            .send_epoch,
        2
    );
    assert!(
        !c.core
            .common_state
            .key_update_state
            .request_pending
    );
    assert!(
        !s.core
            .common_state
            .key_update_state
            .request_pending
    );
    c.writer().write_all(b"client").unwrap();
    s.writer().write_all(b"server").unwrap();
    let mut co = Vec::new();
    let mut so = Vec::new();
    c.write_tls(&mut co).unwrap();
    s.write_tls(&mut so).unwrap();
    c.read_tls(&mut Cursor::new(so))
        .unwrap();
    c.process_new_packets().unwrap();
    s.read_tls(&mut Cursor::new(co))
        .unwrap();
    s.process_new_packets().unwrap();
    let mut data = [0; 6];
    c.reader()
        .read_exact(&mut data)
        .unwrap();
    assert_eq!(&data, b"server");
    s.reader()
        .read_exact(&mut data)
        .unwrap();
    assert_eq!(&data, b"client");
}
#[test]
fn final_epoch_manual_request_preserves_healthy_keys_and_buffered_usage_closes() {
    let (_, mut s, log) = pair(16);
    s.core
        .common_state
        .key_update_state
        .send_epoch = MAX_KEY_UPDATE_EPOCH - 1;
    s.refresh_traffic_keys().unwrap();
    assert_eq!(
        s.core
            .common_state
            .key_update_state
            .send_epoch,
        MAX_KEY_UPDATE_EPOCH
    );
    assert!(s.refresh_traffic_keys().is_err());
    assert!(!s.has_sent_close_notify);
    let mut out = Vec::new();
    for _ in 0..15 {
        s.writer()
            .write_all(b"application")
            .unwrap();
        s.write_tls(&mut out).unwrap();
    }
    assert!(
        s.writer()
            .write_all(b"must stop")
            .is_err()
    );
    assert!(s.has_sent_close_notify);
    assert_eq!(
        s.writer()
            .write(b"never encrypt")
            .unwrap(),
        0
    );
    s.write_tls(&mut out).unwrap();
    let records = decode(&out, &log, "SERVER_TRAFFIC_SECRET_0");
    assert_eq!(records.flags, vec![1]);
    assert_eq!(records.applications, 15);
    assert_eq!(records.alerts, vec![vec![1, 0]]);
    assert!(
        records
            .per_epoch
            .iter()
            .all(|&n| n <= 16)
    );
    assert_eq!(
        s.core
            .common_state
            .key_update_state
            .send_epoch,
        MAX_KEY_UPDATE_EPOCH
    );
}
#[test]
fn final_epoch_peer_request_updates_receive_keys_without_reply_or_close() {
    let (mut c, mut s, _) = pair(64);
    s.core
        .common_state
        .key_update_state
        .send_epoch = MAX_KEY_UPDATE_EPOCH;
    c.refresh_traffic_keys().unwrap();
    let mut out = Vec::new();
    c.write_tls(&mut out).unwrap();
    s.read_tls(&mut Cursor::new(out))
        .unwrap();
    s.process_new_packets().unwrap();
    assert!(!s.has_sent_close_notify);
    assert!(
        s.core
            .common_state
            .queued_key_update_message
            .is_none()
    );
    assert_eq!(
        s.core
            .common_state
            .key_update_state
            .send_epoch,
        MAX_KEY_UPDATE_EPOCH
    );
    c.writer()
        .write_all(b"new receive keys")
        .unwrap();
    let mut out = Vec::new();
    c.write_tls(&mut out).unwrap();
    s.read_tls(&mut Cursor::new(out))
        .unwrap();
    s.process_new_packets().unwrap();
    let mut data = [0; 16];
    s.reader()
        .read_exact(&mut data)
        .unwrap();
    assert_eq!(&data, b"new receive keys");
    s.writer()
        .write_all(b"healthy send keys")
        .unwrap();
}
#[test]
fn epoch_guard_rejects_values_above_cap_without_integer_wrap() {
    let mut common = CommonState::new(Side::Server);
    for epoch in [MAX_KEY_UPDATE_EPOCH, u64::MAX] {
        common.key_update_state.send_epoch = epoch;
        assert!(common.next_key_update(true).is_none());
        assert!(common.next_key_update(false).is_none());
        assert_eq!(common.key_update_state.send_epoch, epoch);
    }
}
#[test]
fn partial_transport_writes_do_not_recount_key_updates() {
    struct OneByte(Vec<u8>);
    impl Write for OneByte {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            if b.is_empty() {
                return Ok(0);
            }
            self.0.push(b[0]);
            Ok(1)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let (_, mut s, log) = pair(16);
    s.refresh_traffic_keys().unwrap();
    let mut out = OneByte(Vec::new());
    while s.wants_write() {
        s.write_tls(&mut out).unwrap();
    }
    assert_eq!(
        s.core
            .common_state
            .key_update_state
            .send_epoch,
        1
    );
    assert_eq!(
        decode(&out.0, &log, "SERVER_TRAFFIC_SECRET_0").flags,
        vec![1]
    );
}
fn unbuffered_pair() -> (ClientConnection, UnbufferedServerConnection, Arc<Log>) {
    let (cc, sc, log) = configs(16);
    let mut c = ClientConnection::new(cc, ServerName::try_from("relay.test").unwrap()).unwrap();
    let mut s = UnbufferedServerConnection::new(sc).unwrap();
    let mut input = Vec::new();
    let mut pending = Vec::new();
    for _ in 0..64 {
        c.write_tls(&mut input).unwrap();
        let status = s.process_tls_records(&mut input);
        let discard = status.discard;
        match status.state.unwrap() {
            ConnectionState::EncodeTlsData(mut e) => {
                let mut out = vec![0; 16384];
                let n = e.encode(&mut out).unwrap();
                pending.extend_from_slice(&out[..n]);
            }
            ConnectionState::TransmitTlsData(t) => {
                c.read_tls(&mut Cursor::new(std::mem::take(&mut pending)))
                    .unwrap();
                c.process_new_packets().unwrap();
                t.done();
            }
            ConnectionState::BlockedHandshake => (),
            ConnectionState::WriteTraffic(_) => {
                assert!(!c.is_handshaking());
                assert!(input[discard..].is_empty());
                return (c, s, log);
            }
            other => panic!("unexpected handshake state {other:?}"),
        }
        input.drain(..discard);
    }
    panic!("unbuffered handshake did not finish")
}
#[test]
fn unbuffered_final_epoch_exhaustion_rejects_application_output() {
    let (_, mut s, _) = unbuffered_pair();
    s.core
        .common_state
        .key_update_state
        .send_epoch = MAX_KEY_UPDATE_EPOCH;
    let mut out = vec![0x55; 1024];
    match s
        .process_tls_records(&mut [])
        .state
        .unwrap()
    {
        ConnectionState::WriteTraffic(mut w) => {
            for _ in 0..15 {
                w.encrypt(b"application", &mut out)
                    .unwrap();
            }
            out.fill(0x55);
            assert!(matches!(
                w.encrypt(b"must stop", &mut out),
                Err(EncryptError::EncryptExhausted)
            ));
            assert!(matches!(
                w.encrypt(b"still must stop", &mut out),
                Err(EncryptError::EncryptExhausted)
            ));
            assert!(out.iter().all(|&b| b == 0x55));
        }
        other => panic!("unexpected state {other:?}"),
    }
    assert!(s.has_sent_close_notify);
    assert_eq!(
        s.core
            .common_state
            .key_update_state
            .send_epoch,
        MAX_KEY_UPDATE_EPOCH
    );
}
#[test]
fn unbuffered_final_epoch_large_payload_is_rejected_before_any_encryption() {
    let (_, mut s, _) = unbuffered_pair();
    s.core
        .common_state
        .key_update_state
        .send_epoch = MAX_KEY_UPDATE_EPOCH;
    let mut out = vec![0x55; 400_000];
    let payload = vec![b'x'; 17 * 16384];
    match s
        .process_tls_records(&mut [])
        .state
        .unwrap()
    {
        ConnectionState::WriteTraffic(mut w) => {
            assert!(matches!(
                w.encrypt(&payload, &mut out),
                Err(EncryptError::EncryptExhausted)
            ));
            assert!(out.iter().all(|&b| b == 0x55));
        }
        other => panic!("unexpected state {other:?}"),
    }
    assert!(s.has_sent_close_notify);
    assert_eq!(
        s.core
            .common_state
            .record_layer
            .write_seq(),
        1
    );
}

#[test]
fn hard_record_refusal_does_not_advance_sending_epoch_or_encrypt_alert() {
    let (_, mut s, _) = pair(16);
    s.core
        .common_state
        .record_layer
        .exhaust_write_counter_for_test();
    assert_eq!(
        s.refresh_traffic_keys().unwrap_err(),
        crate::Error::EncryptError
    );
    assert_eq!(
        s.core
            .common_state
            .key_update_state
            .send_epoch,
        0
    );
    assert!(
        s.core
            .common_state
            .key_update_state
            .write_exhausted
    );
    assert!(!s.wants_write());
    assert!(!s.has_sent_close_notify);
    assert_eq!(
        s.writer()
            .write(b"cannot encrypt")
            .unwrap(),
        0
    );
}

#[test]
fn hard_record_refusal_of_peer_response_still_processes_incoming_update() {
    let (mut c, mut s, _) = pair(64);
    s.core
        .common_state
        .record_layer
        .exhaust_write_counter_for_test();
    c.refresh_traffic_keys().unwrap();
    let mut out = Vec::new();
    c.write_tls(&mut out).unwrap();
    s.read_tls(&mut Cursor::new(out))
        .unwrap();
    s.process_new_packets().unwrap();
    assert_eq!(
        s.core
            .common_state
            .key_update_state
            .send_epoch,
        0
    );
    assert!(
        s.core
            .common_state
            .key_update_state
            .write_exhausted
    );
    c.writer()
        .write_all(b"new receive keys")
        .unwrap();
    let mut out = Vec::new();
    c.write_tls(&mut out).unwrap();
    s.read_tls(&mut Cursor::new(out))
        .unwrap();
    s.process_new_packets().unwrap();
    let mut data = [0; 16];
    s.reader()
        .read_exact(&mut data)
        .unwrap();
    assert_eq!(&data, b"new receive keys");
}

#[test]
fn public_close_notify_after_hard_refusal_does_not_panic_or_encrypt() {
    let (_, mut s, _) = pair(16);
    s.core
        .common_state
        .record_layer
        .exhaust_write_counter_for_test();
    assert_eq!(
        s.refresh_traffic_keys().unwrap_err(),
        crate::Error::EncryptError
    );
    s.send_close_notify();
    assert!(!s.wants_write());
    assert_eq!(
        s.core
            .common_state
            .key_update_state
            .send_epoch,
        0
    );
}

#[test]
fn fatal_alert_after_hard_refusal_does_not_panic_or_encrypt() {
    let (_, mut s, _) = pair(16);
    s.core
        .common_state
        .record_layer
        .exhaust_write_counter_for_test();
    assert!(
        s.core
            .common_state
            .should_update_key(&KeyUpdateRequest::Unknown(2))
            .is_err()
    );
    assert!(!s.wants_write());
}

#[test]
fn queued_final_peer_response_precedes_application_data_and_reserved_close() {
    let (mut c, mut s, log) = pair(16);
    s.core
        .common_state
        .key_update_state
        .send_epoch = MAX_KEY_UPDATE_EPOCH - 1;
    c.refresh_traffic_keys().unwrap();
    let mut co = Vec::new();
    c.write_tls(&mut co).unwrap();
    s.read_tls(&mut Cursor::new(co))
        .unwrap();
    s.process_new_packets().unwrap();
    assert_eq!(
        s.core
            .common_state
            .key_update_state
            .send_epoch,
        MAX_KEY_UPDATE_EPOCH
    );
    assert!(
        s.core
            .common_state
            .queued_key_update_message
            .is_some()
    );
    for _ in 0..15 {
        s.writer()
            .write_all(b"application")
            .unwrap();
    }
    assert!(
        s.writer()
            .write_all(b"must stop")
            .is_err()
    );
    let mut out = Vec::new();
    s.write_tls(&mut out).unwrap();
    let records = decode(&out, &log, "SERVER_TRAFFIC_SECRET_0");
    assert_eq!(records.flags, vec![0]);
    assert_eq!(records.applications, 15);
    assert_eq!(records.alerts, vec![vec![1, 0]]);
    assert!(
        records
            .per_epoch
            .iter()
            .all(|&n| n <= 16)
    );
    c.read_tls(&mut Cursor::new(out))
        .unwrap();
    assert!(
        c.process_new_packets()
            .unwrap()
            .peer_has_closed()
    );
}
