//! RFC 9298 section 3.1: a valid UDP payload above the destination MTU is
//! silently dropped without terminating its CONNECT-UDP flow.
mod support;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use bytes::{Bytes, BytesMut};
use http::{Method, Request, StatusCode};
use http_body_util::Empty;
use relay_frontend::{
    auth, check,
    proto::{capsule, datagram},
    tunnel::{Event, Sent, Tunnel},
};
use support::relay::{TestEnv, TestRelay, PASSWORD, USER, WAIT};
use support::warp_peer::{peer_addr, WarpPeer};
use warp_masque_egress::{Egress, Transport, WarpEgress};

const OVERSIZED_BYTES: usize = 1400;
const ACCEPTED_BYTES: usize = 1200;
const EGRESS_MAX_PAYLOAD: usize = 1252; // 1280-byte IPv4 MTU minus IP/UDP headers.
const SILENCE: Duration = Duration::from_millis(300);

struct Fixture {
    _env: TestEnv,
    peer: WarpPeer,
    warp: Arc<WarpEgress>,
    relay: TestRelay,
}

impl Fixture {
    async fn start(transport: Transport) -> Result<Self> {
        let env = TestEnv::new("udp-mtu-frontend")?;
        let peer = WarpPeer::start(transport).await?;
        let config = peer.config(&env.path)?;
        let warp = Arc::new(
            tokio::time::timeout(WAIT, WarpEgress::connect(&config)).await.context("WARP handshake deadline")??,
        );
        peer.wait_connected().await?;
        let expected_transport = match transport {
            Transport::H2 => "HTTP/2",
            Transport::H3 => "HTTP/3",
        };
        ensure!(warp.status().transport == expected_transport, "WARP transport silently changed");
        let socket = warp.connect_udp(peer_addr(7)).await?;
        ensure!(socket.max_payload() == EGRESS_MAX_PAYLOAD, "fixture UDP MTU changed");
        drop(socket);
        let relay = TestRelay::start(&env, warp.clone()).await?;
        Ok(Self { _env: env, peer, warp, relay })
    }

    async fn finish(mut self) -> Result<()> {
        self.relay.shutdown().await?;
        self.warp.shutdown().await;
        ensure!(!self.warp.available(), "shutdown left egress available");
        ensure!(self.warp.status().workers == 0, "egress workers survived shutdown");
        self.peer.shutdown().await;
        Ok(())
    }
}

#[allow(dead_code)] // Retain connection drivers until the business flow ends.
enum Owner {
    Upgraded(check::AbortOnDrop),
    H3 { client: check::H3, filter: check::AbortOnDrop },
}

struct UdpFlow {
    tunnel: Tunnel,
    owner: Owner,
}

impl UdpFlow {
    async fn open_and_send_oversized(relay: &TestRelay, inbound: &str, payload: &[u8]) -> Result<Self> {
        let opts = relay.options();
        let path = "/.well-known/masque/udp/fixture.test/7/";
        let uri = format!("https://relay.test:{}{path}", opts.port);
        let credentials = auth::basic_authorization(USER, PASSWORD);
        let wire = datagram::udp_payload(payload);
        let (mut tunnel, owner) = match inbound {
            "h1" => {
                let (mut sender, driver) = check::h1_sender(&opts, &opts.addresses).await?;
                let request = Request::builder()
                    .method(Method::GET)
                    .uri(path)
                    .header("host", format!("relay.test:{}", opts.port))
                    .header("connection", "Upgrade")
                    .header("upgrade", "connect-udp")
                    .header("capsule-protocol", "?1")
                    .header("authorization", credentials)
                    .body(Empty::<Bytes>::new())?;
                let mut response = sender.send_request(request).await?;
                ensure!(response.status() == StatusCode::SWITCHING_PROTOCOLS, "H1 UDP upgrade refused");
                ensure!(
                    response.headers().get("capsule-protocol").is_some_and(|v| v == "?1"),
                    "H1 capsules not accepted"
                );
                (Tunnel::upgraded(hyper::upgrade::on(&mut response).await?), Owner::Upgraded(driver))
            }
            "h2" => {
                let (mut sender, driver) = check::h2_sender(&opts, &opts.addresses).await?;
                let request = Request::builder()
                    .method(Method::CONNECT)
                    .uri(uri)
                    .header("capsule-protocol", "?1")
                    .header("authorization", credentials)
                    .extension(hyper::ext::Protocol::from_static("connect-udp"))
                    .body(Empty::<Bytes>::new())?;
                let mut response = sender.send_request(request).await?;
                ensure!(response.status() == StatusCode::OK, "H2 UDP CONNECT refused");
                ensure!(
                    response.headers().get("capsule-protocol").is_some_and(|v| v == "?1"),
                    "H2 capsules not accepted"
                );
                (Tunnel::upgraded(hyper::upgrade::on(&mut response).await?), Owner::Upgraded(driver))
            }
            "h3" => {
                let mut client = check::H3::connect(&opts, &opts.addresses).await?;
                let request = Request::builder()
                    .method(Method::CONNECT)
                    .uri(uri)
                    .header("capsule-protocol", "?1")
                    .header("authorization", credentials)
                    .extension(h3::ext::Protocol::CONNECT_UDP)
                    .body(())?;
                let mut stream = client.request(request).await?;
                let response = stream.recv_response().await?;
                ensure!(response.status() == StatusCode::OK, "H3 UDP CONNECT refused");
                ensure!(
                    response.headers().get("capsule-protocol").is_some_and(|v| v == "?1"),
                    "H3 capsules not accepted"
                );
                // Reliable DATA gets the entire oversized business payload to
                // the frontend. A client QUIC path-size refusal must not count
                // as proof that the frontend correctly discarded it.
                let mut capsule_wire = BytesMut::new();
                capsule::encode(capsule::types::DATAGRAM, &wire, &mut capsule_wire);
                stream.send_data(capsule_wire.freeze()).await?;
                let (tunnel, filter) = client.udp_tunnel(stream);
                return Ok(Self { tunnel, owner: Owner::H3 { client, filter } });
            }
            _ => unreachable!(),
        };
        ensure!(tunnel.send_datagram(wire)? == Sent::Sent, "oversized capsule was not sent to frontend");
        Ok(Self { tunnel, owner })
    }

    async fn require_no_event(&mut self) -> Result<()> {
        // Cancelling next_event leaves its Tunnel and request stream alive.
        // An abort, EOF or returned datagram fails immediately instead of
        // being mistaken for the expected silent drop.
        let outcome = tokio::time::timeout(SILENCE, self.tunnel.next_event()).await;
        ensure!(outcome.is_err(), "oversized payload produced a flow event: {outcome:?}");
        Ok(())
    }

    async fn echo(&mut self, payload: &[u8]) -> Result<()> {
        let wire = datagram::udp_payload(payload);
        if let Owner::H3 { client, .. } = &self.owner {
            // The standard H3 client begins at QUIC's 1200-byte minimum.
            // Wait for discovery so the valid 1200-byte business datagram
            // plus context and quarter-stream ID fits the outbound path.
            tokio::time::timeout(WAIT, async {
                while !client.connection().max_datagram_size().is_some_and(|max| max > wire.len()) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .context("H3 client path did not discover room for valid payload")?;
        }
        ensure!(self.tunnel.send_datagram(wire)? == Sent::Sent, "valid payload was not sent to frontend");
        let event = tokio::time::timeout(WAIT, self.tunnel.next_event()).await.context("valid UDP echo deadline")??;
        let Event::Datagram(wire) = event else { anyhow::bail!("CONNECT-UDP flow ended after oversized payload") };
        let (context, echoed) = datagram::split_context_id(&wire)?;
        ensure!(context == datagram::CONTEXT_ID_UDP_PAYLOAD, "UDP echo used context {context}");
        ensure!(echoed == payload, "UDP echo did not preserve the complete valid payload");
        if let Owner::H3 { client, .. } = &self.owner {
            // This fresh client sent its oversized packet only in DATA, so
            // a QUIC DATAGRAM here can only be the accepted business packet.
            ensure!(client.connection().stats().frame_tx.datagram > 0, "valid H3 send fell back to capsules");
        }
        Ok(())
    }
}

fn payload(bytes: usize, marker: u8) -> Vec<u8> {
    (0..bytes).map(|offset| marker.wrapping_add((offset.wrapping_mul(73) ^ (offset >> 4)) as u8)).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn standard_connect_udp_silently_drops_mtu_oversize_across_six_transport_pairings() -> Result<()> {
    ensure!(ACCEPTED_BYTES <= EGRESS_MAX_PAYLOAD && OVERSIZED_BYTES > EGRESS_MAX_PAYLOAD, "invalid MTU fixture sizes");
    ensure!(OVERSIZED_BYTES <= datagram::MAX_UDP_PAYLOAD, "oversized fixture is malformed UDP");
    for transport in [Transport::H2, Transport::H3] {
        let fixture = Fixture::start(transport).await?;
        for inbound in ["h1", "h2", "h3"] {
            let case = async {
                let before = fixture.peer.snapshot();
                let oversized = payload(OVERSIZED_BYTES, 0xe1);
                let accepted = payload(ACCEPTED_BYTES, 0x32);
                let mut flow = UdpFlow::open_and_send_oversized(&fixture.relay, inbound, &oversized).await?;
                flow.require_no_event().await?;
                let dropped = fixture.peer.snapshot();
                ensure!(
                    dropped.udp_datagrams_received == before.udp_datagrams_received
                        && dropped.udp_bytes_received == before.udp_bytes_received,
                    "oversized business payload reached peer UDP socket"
                );
                flow.echo(&accepted).await?;
                // The peer counts sent bytes after enqueueing its inner IP
                // packet; another worker can deliver the echo first. Wait
                // for both counters before checking their exact deltas.
                let after = tokio::time::timeout(WAIT, async {
                    loop {
                        let after = fixture.peer.snapshot();
                        if after.udp_datagrams_sent > before.udp_datagrams_sent
                            && after.udp_bytes_sent >= before.udp_bytes_sent + ACCEPTED_BYTES as u64
                        {
                            break after;
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .context("peer UDP echo counters deadline")?;
                ensure!(
                    after.udp_datagrams_received - before.udp_datagrams_received == 1,
                    "peer received extra UDP datagrams"
                );
                ensure!(
                    after.udp_bytes_received - before.udp_bytes_received == ACCEPTED_BYTES as u64,
                    "peer received oversized UDP bytes"
                );
                ensure!(after.udp_datagrams_sent - before.udp_datagrams_sent == 1, "peer sent extra UDP datagrams");
                ensure!(
                    after.udp_bytes_sent - before.udp_bytes_sent == ACCEPTED_BYTES as u64,
                    "peer did not send exactly the valid payload"
                );
                ensure!(
                    after.ip_packets_from_client > before.ip_packets_from_client
                        && after.ip_packets_to_client > before.ip_packets_to_client,
                    "UDP echo bypassed the WARP IP packet tunnel"
                );
                ensure!(fixture.warp.available(), "oversized UDP payload failed WARP egress");
                ensure!(fixture.peer.errors().is_empty(), "peer errors: {:?}", fixture.peer.errors());
                Ok::<(), anyhow::Error>(())
            };
            case.await.with_context(|| format!("WARP {transport:?}, inbound {inbound}"))?;
        }
        fixture.finish().await?;
    }
    Ok(())
}
