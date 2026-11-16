//! Local SOCKS method selection through the production proxy and native
//! transport emulator, without a running relay server.
mod support;

use network_relay_tun_core::{Config, client::Client, socks};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const WAIT: Duration = Duration::from_secs(10);

async fn method(address: SocketAddr, offered: &[u8]) -> (TcpStream, u8) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let mut greeting = vec![5, offered.len() as u8];
    greeting.extend_from_slice(offered);
    stream.write_all(&greeting).await.unwrap();
    let mut chosen = [0; 2];
    tokio::time::timeout(WAIT, stream.read_exact(&mut chosen))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(chosen[0], 5);
    (stream, chosen[1])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn selects_no_authentication_and_rejects_unsupported_methods() {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["relay.test".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let ca = std::env::temp_dir().join(format!("relay-nf-methods-{}.pem", std::process::id()));
    std::fs::write(&ca, cert.pem()).unwrap();
    let backend = support::Backend::start(ca.clone());
    let settings = Config {
        uri_template: "https://127.0.0.1:9/.well-known/masque/udp/{target_host}/{target_port}/"
            .into(),
        username: "alice".into(),
        password: "disposable-fixture-password".into(),
        server_name: Some("relay.test".into()),
        transport: "h2".into(),
        probe_target: "127.0.0.1:9".parse().unwrap(),
        mode: "socks".into(),
        socks: network_relay_tun_core::Socks {
            listen: vec!["127.0.0.1:0".parse().unwrap()],
        },
    };
    let client = Arc::new(Client::new(&settings, backend.bridge.clone()).unwrap());
    let listener = backend
        .bridge
        .listen("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let worker = tokio::spawn(socks::run(client, vec![listener]));

    for offered in [&[0][..], &[1, 0, 2][..]] {
        let (mut stream, chosen) = method(address, offered).await;
        assert_eq!(chosen, 0);
        // The plain UDP ASSOCIATE request and response still work after
        // selecting method 0, even when other methods were offered first.
        stream
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut response = [0; 10];
        tokio::time::timeout(WAIT, stream.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response[..4], &[5, 0, 0, 1]);
        assert_ne!(&response[8..], &[0, 0]);
    }
    for offered in [&[1][..], &[2][..], &[][..]] {
        let (mut stream, chosen) = method(address, offered).await;
        assert_eq!(chosen, 0xff);
        assert!(
            matches!(
                tokio::time::timeout(WAIT, stream.read(&mut [0])).await,
                Ok(Ok(0) | Err(_))
            ),
            "a rejected method must close the session"
        );
    }
    // Rejecting one local program does not stop the proxy listener.
    assert_eq!(method(address, &[0]).await.1, 0);
    worker.abort();
    drop(backend);
    std::fs::remove_file(ca).unwrap();
}

#[test]
fn obsolete_local_authentication_fields_do_not_break_saved_configurations() {
    let config: Config = toml::from_str(
        r#"
uri_template = "https://relay.test/.well-known/masque/udp/{target_host}/{target_port}/"
username = "alice"
password = "disposable-fixture-password"
server_name = "relay.test"
mode = "socks"
[socks]
listen = ["127.0.0.1:1080"]
gssapi_keytab = "/nonexistent/deleted-feature.keytab"
gssapi_principals = ["unused@EXAMPLE.TEST"]
"#,
    )
    .unwrap();
    assert_eq!(
        config.socks.listen,
        vec!["127.0.0.1:1080".parse::<SocketAddr>().unwrap()]
    );
}
