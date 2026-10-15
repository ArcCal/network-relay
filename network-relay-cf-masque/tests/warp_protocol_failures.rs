//! Actual WARP-backed reset codes and authentication rejection paths.
mod support;
use anyhow::{ensure, Context, Result};
use base64::Engine;
use bytes::{Bytes, BytesMut};
use http::{Method, Request, StatusCode};
use http_body_util::Empty;
use hyper_util::rt::TokioIo;
use rcgen::PublicKeyData;
use relay_frontend::{auth, check};
use std::sync::Arc;
use support::relay::{TestEnv, TestRelay, PASSWORD, USER, WAIT};
use support::warp_peer::WarpPeer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use warp_masque_egress::{Transport, WarpConfig, WarpEgress};

struct Driver(tokio::task::JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn h2(relay: &TestRelay) -> Result<(h2::client::SendRequest<Bytes>, Driver)> {
    let opts = relay.options();
    let tls = relay_frontend::tls::client_config(opts.ca.as_deref(), &[b"h2"])?;
    let tcp = tokio::net::TcpStream::connect(relay.addr).await?;
    let io = tokio_rustls::TlsConnector::from(Arc::new(tls)).connect("relay.test".try_into()?, tcp).await?;
    let (sender, connection) = h2::client::handshake(io).await?;
    let driver = Driver(tokio::spawn(async move {
        let _ = connection.await;
    }));
    tokio::time::timeout(WAIT, async {
        while !sender.is_extended_connect_protocol_enabled() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok((sender, driver))
}
fn tcp_request(port: u16) -> Request<()> {
    Request::builder()
        .method(Method::CONNECT)
        .uri(format!("fixture.test:{port}"))
        .header("authorization", auth::basic_authorization(USER, PASSWORD))
        .body(())
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inner_rst_and_malformed_control_map_to_exact_inbound_codes() -> Result<()> {
    for mode in [Transport::H2, Transport::H3] {
        let env = TestEnv::new("protocol-errors")?;
        let mut peer = WarpPeer::start(mode).await?;
        let config = peer.config(&env.path)?;
        let warp = Arc::new(WarpEgress::connect(&config).await?);
        let mut relay = TestRelay::start(&env, warp.clone()).await?;
        {
            let options = relay.options();
            let (mut sender, _driver) = check::h1_sender(&options, &options.addresses).await?;
            let request = Request::builder()
                .method(Method::CONNECT)
                .uri("fixture.test:9")
                .header("host", "fixture.test:9")
                .header("proxy-authorization", auth::basic_authorization(USER, PASSWORD))
                .body(Empty::<Bytes>::new())?;
            let mut response = sender.send_request(request).await?;
            ensure!(response.status() == StatusCode::OK, "H1 reset fixture CONNECT refused");
            let mut stream = TokioIo::new(hyper::upgrade::on(&mut response).await?);
            stream.write_all(b"r").await?;
            let mut byte = [0; 1];
            let result = tokio::time::timeout(WAIT, stream.read(&mut byte)).await?;
            ensure!(result.is_err(), "inner TCP RST became a clean H1 tunnel EOF");
        }
        {
            let (mut sender, _driver) = h2(&relay).await?;
            let (response, mut send) = sender.send_request(tcp_request(9), false)?;
            let response = tokio::time::timeout(WAIT, response).await??;
            ensure!(response.status() == StatusCode::OK, "H2 reset fixture CONNECT refused");
            send.send_data(Bytes::from_static(b"r"), false)?;
            let mut recv = response.into_body();
            let error = tokio::time::timeout(WAIT, recv.data())
                .await?
                .context("inner reset became H2 EOF")?
                .expect_err("inner reset returned H2 data");
            ensure!(error.reason() == Some(h2::Reason::CONNECT_ERROR), "inner RST mapped to wrong H2 code: {error}");
        }
        {
            let opts = relay.options();
            let mut client = check::H3::connect(&opts, &opts.addresses).await?;
            let mut stream = client.request(tcp_request(9)).await?;
            ensure!(stream.recv_response().await?.status() == StatusCode::OK, "H3 reset fixture refused");
            stream.send_data(Bytes::from_static(b"r")).await?;
            let error =
                tokio::time::timeout(WAIT, stream.recv_data()).await?.err().context("inner RST became H3 EOF")?;
            ensure!(
                matches!(error, h3::error::StreamError::RemoteTerminate { code } if code == h3::error::Code::H3_CONNECT_ERROR),
                "inner RST mapped to wrong H3 code: {error:?}"
            );
        }
        {
            let (mut sender, _driver) = h2(&relay).await?;
            let request = Request::builder()
                .method(Method::CONNECT)
                .uri(format!("https://relay.test:{}/.well-known/masque/udp/fixture.test/7/", relay.addr.port()))
                .header("authorization", auth::basic_authorization(USER, PASSWORD))
                .header("capsule-protocol", "?1")
                .extension(h2::ext::Protocol::from_static("connect-udp"))
                .body(())?;
            let (response, mut send) = sender.send_request(request, false)?;
            let response = tokio::time::timeout(WAIT, response).await??;
            ensure!(response.status() == StatusCode::OK, "H2 UDP control fixture refused");
            let mut frame = BytesMut::new();
            relay_frontend::proto::capsule::encode(
                0,
                &relay_frontend::proto::datagram::udp_payload(&vec![0; 65_528]),
                &mut frame,
            );
            // Only the header arrives: rejection must happen without buffering the declared body.
            send.send_data(frame.freeze().slice(..16), false)?;
            let mut recv = response.into_body();
            let error = tokio::time::timeout(WAIT, recv.data())
                .await?
                .context("oversize control became clean EOF")?
                .expect_err("oversize control unexpectedly returned data");
            ensure!(error.reason() == Some(h2::Reason::PROTOCOL_ERROR), "oversize inbound capsule mapped to {error}");
        }
        {
            let opts = relay.options();
            let mut client = check::H3::connect(&opts, &opts.addresses).await?;
            let mut stream = client.request(tcp_request(7)).await?;
            ensure!(stream.recv_response().await?.status() == StatusCode::OK, "H3 TCP datagram fixture refused");
            client.send_datagram(stream.id(), Bytes::from_static(b"\0illegal-on-tcp"))?;
            let error = tokio::time::timeout(WAIT, stream.recv_data())
                .await?
                .err()
                .context("illegal TCP datagram became clean EOF")?;
            ensure!(
                matches!(error, h3::error::StreamError::RemoteTerminate { code } if code == h3::error::Code::H3_DATAGRAM_ERROR),
                "illegal TCP datagram mapped to {error:?}"
            );
        }
        relay.shutdown().await?;
        warp.shutdown().await;
        peer.shutdown().await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_pin_and_enrolled_client_key_mismatches_are_rejected() -> Result<()> {
    for mode in [Transport::H2, Transport::H3] {
        for wrong_server_pin in [true, false] {
            let env = TestEnv::new("pin-mismatch")?;
            let mut peer = WarpPeer::start(mode).await?;
            peer.config(&env.path)?;
            let mut registration: serde_json::Value =
                serde_json::from_slice(&std::fs::read(env.path.join("registration.json"))?)?;
            let wrong_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
            if wrong_server_pin {
                registration["endpoint_public_key"] = format!(
                    "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                    base64::engine::general_purpose::STANDARD.encode(wrong_key.subject_public_key_info())
                )
                .into();
            } else {
                registration["private_key"] =
                    base64::engine::general_purpose::STANDARD.encode(wrong_key.serialize_der()).into();
            }
            std::fs::write(env.path.join("registration.json"), serde_json::to_vec(&registration)?)?;
            let config = WarpConfig::load(&env.path.join("warp.toml"))?;
            let rejected = tokio::time::timeout(WAIT, WarpEgress::connect(&config))
                .await
                .context("credential rejection did not complete")?;
            ensure!(rejected.is_err(), "mismatched pin or enrolled key established a tunnel");
            ensure!(peer.snapshot().tunnels == 0, "credential rejection reached business packet session");
            peer.shutdown().await;
        }
    }
    Ok(())
}
