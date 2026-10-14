//! SOCKS5 CONNECT and UDP ASSOCIATE over Rust-owned local listeners/sockets.
//! Destination names are resolved by the relay server.
use crate::{
    client::{Client, UdpFlow},
    native,
};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Semaphore, mpsc},
    task::JoinSet,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Target {
    host: String,
    port: u16,
}
impl Target {
    fn valid(&self) -> bool {
        self.port != 0
            && !self.host.is_empty()
            && self.host.len() <= 253
            && self
                .host
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-._:".contains(&c))
    }
    fn encode(&self, out: &mut Vec<u8>) {
        match self.host.parse::<IpAddr>() {
            Ok(IpAddr::V4(a)) => {
                out.push(1);
                out.extend_from_slice(&a.octets());
            }
            Ok(IpAddr::V6(a)) => {
                out.push(4);
                out.extend_from_slice(&a.octets());
            }
            Err(_) => {
                out.extend_from_slice(&[3, self.host.len() as u8]);
                out.extend_from_slice(self.host.as_bytes());
            }
        }
        out.extend_from_slice(&self.port.to_be_bytes());
    }
}

pub async fn run(client: Arc<Client>, listeners: Vec<native::TcpListener>) -> Result<()> {
    let limit = Arc::new(Semaphore::new(256));
    let mut workers = JoinSet::new();
    let monitor = client.clone();
    workers.spawn(async move { monitor.monitor().await });
    for listener in listeners {
        let client = client.clone();
        let limit = limit.clone();
        workers.spawn(async move {
            let mut sessions = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (io, peer) = accepted?;
                        let Ok(permit) = limit.clone().try_acquire_owned() else { drop(io); continue; };
                        let client = client.clone();
                        sessions.spawn(async move {
                            let _permit = permit;
                            if let Err(e) = session(client, io, peer).await {
                                tracing::debug!(%peer, "SOCKS session ended: {e:#}");
                            }
                        });
                    }
                    _ = sessions.join_next(), if !sessions.is_empty() => {}
                }
            }
            #[allow(unreachable_code)] Ok::<_, anyhow::Error>(())
        });
    }
    tokio::select! {
        _ = client.bridge.stop.cancelled() => Ok(()),
        result = workers.join_next() => result.context("relay worker disappeared")??,
    }
}

async fn session(client: Arc<Client>, mut io: native::Io, peer: SocketAddr) -> Result<()> {
    let (command, target) = tokio::time::timeout(Duration::from_secs(10), async {
        ensure!(io.read_u8().await? == 5, "SOCKS version is not 5");
        let mut methods = vec![0; io.read_u8().await? as usize];
        io.read_exact(&mut methods).await?;
        if !methods.contains(&0) {
            io.write_all(&[5, 255]).await?;
            anyhow::bail!("SOCKS requires unsupported authentication");
        }
        io.write_all(&[5, 0]).await?;
        ensure!(io.read_u8().await? == 5, "invalid SOCKS request version");
        let command = io.read_u8().await?;
        ensure!(io.read_u8().await? == 0, "invalid SOCKS reserved field");
        let target = read_target(&mut io).await?;
        Ok::<_, anyhow::Error>((command, target))
    })
    .await
    .context("SOCKS handshake timed out")??;
    match command {
        1 => {
            let result = client.open(&target.host, target.port, false).await;
            match result {
                Ok(mut opened) => {
                    reply(&mut io, 0, None).await?;
                    tracing::debug!(%peer, host=%target.host, port=target.port, transport=opened.transport, "SOCKS CONNECT ready");
                    if let Err(e) = tokio::io::copy_bidirectional(&mut io, &mut opened.stream).await
                    {
                        // A failed tunnel, such as one whose destination
                        // reset, resets the program's connection as the
                        // relay resets the destination's (RFC 9113 section
                        // 8.5, RFC 9114 section 4.4): with a FIN, a cut-off
                        // download would look complete.
                        io.abort();
                        return Err(e.into());
                    }
                }
                Err(e) => {
                    reply(&mut io, 1, None).await?;
                    return Err(e);
                }
            }
        }
        3 => udp_association(client, io, peer, target).await?,
        _ => {
            reply(&mut io, 7, None).await?;
        }
    }
    Ok(())
}
async fn read_target(io: &mut native::Io) -> Result<Target> {
    let host = match io.read_u8().await? {
        1 => {
            let mut bytes = [0; 4];
            io.read_exact(&mut bytes).await?;
            Ipv4Addr::from(bytes).to_string()
        }
        4 => {
            let mut bytes = [0; 16];
            io.read_exact(&mut bytes).await?;
            Ipv6Addr::from(bytes).to_string()
        }
        3 => {
            let mut bytes = vec![0; io.read_u8().await? as usize];
            io.read_exact(&mut bytes).await?;
            String::from_utf8(bytes).context("invalid SOCKS domain")?
        }
        _ => anyhow::bail!("unsupported SOCKS address type"),
    };
    Ok(Target {
        host,
        port: io.read_u16().await?,
    })
}
async fn reply(io: &mut native::Io, code: u8, bound: Option<SocketAddr>) -> Result<()> {
    let bound = bound.unwrap_or(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
    let mut bytes = vec![5, code, 0];
    Target {
        host: bound.ip().to_string(),
        port: bound.port(),
    }
    .encode(&mut bytes);
    io.write_all(&bytes).await?;
    Ok(())
}
fn packet(bytes: &[u8]) -> Option<(Target, &[u8])> {
    if bytes.get(..3)? != [0, 0, 0] {
        return None;
    } // No fragmented UDP.
    let mut rest = bytes.get(4..)?;
    let host = match bytes[3] {
        1 => {
            let a: [u8; 4] = rest.get(..4)?.try_into().ok()?;
            rest = &rest[4..];
            Ipv4Addr::from(a).to_string()
        }
        4 => {
            let a: [u8; 16] = rest.get(..16)?.try_into().ok()?;
            rest = &rest[16..];
            Ipv6Addr::from(a).to_string()
        }
        3 => {
            let n = *rest.first()? as usize;
            let host = std::str::from_utf8(rest.get(1..1 + n)?).ok()?.to_string();
            rest = &rest[1 + n..];
            host
        }
        _ => return None,
    };
    let port = u16::from_be_bytes(rest.get(..2)?.try_into().ok()?);
    let target = Target { host, port };
    target.valid().then_some((target, &rest[2..]))
}
async fn udp_association(
    client: Arc<Client>,
    mut control: native::Io,
    peer: SocketAddr,
    claim: Target,
) -> Result<()> {
    let claim_ip: IpAddr = claim
        .host
        .parse()
        .context("UDP association requires an IP address or wildcard")?;
    if !claim_ip.is_unspecified() && claim_ip.to_canonical() != peer.ip().to_canonical() {
        reply(&mut control, 2, None).await?;
        anyhow::bail!("UDP source address differs from SOCKS TCP peer");
    }
    let local = control.local_addr()?;
    let socket = client.bridge.udp(SocketAddr::new(local.ip(), 0)).await?;
    reply(&mut control, 0, Some(socket.local_addr()?)).await?;
    let mut source = if claim.port == 0 {
        None
    } else {
        Some(SocketAddr::new(peer.ip(), claim.port))
    };
    let mut flows: HashMap<Target, mpsc::Sender<Bytes>> = HashMap::new();
    let mut tasks = JoinSet::new();
    let (responses, mut incoming) = mpsc::channel::<(Target, Bytes)>(32);
    let mut buffer = vec![0; 65536];
    let mut control_byte = [0; 1];
    loop {
        tokio::select! {
            read = control.read(&mut control_byte) => { read?; break; }
            datagram = socket.recv_from(&mut buffer) => {
                let (count, sender)=datagram?;
                if sender.ip().to_canonical() != peer.ip().to_canonical() || source.is_some_and(|a| a != sender) { continue; }
                let Some((target, payload))=packet(&buffer[..count]) else { continue; };
                if payload.len() > 65507 { continue; }
                source.get_or_insert(sender);
                flows.retain(|_, tx| !tx.is_closed());
                if !flows.contains_key(&target) {
                    if flows.len() >= 32 { continue; }
                    let (tx, mut rx)=mpsc::channel::<Bytes>(16);
                    flows.insert(target.clone(), tx);
                    let client=client.clone();
                    let responses=responses.clone();
                    let destination=target.clone();
                    tasks.spawn(async move {
                        let result: Result<()> = async {
                            let opened=client.open(&destination.host,destination.port,true).await?;
                            let mut flow=UdpFlow::new(opened.stream);
                            loop {
                                tokio::select! {
                                    payload=rx.recv() => { let Some(payload)=payload else { break; }; flow.send(&payload).await?; }
                                    payload=flow.recv() => {
                                        let Some(payload)=payload? else { break; };
                                        // Bound SOCKS UDP packet size, including the address header.
                                        if payload.len() <= 65240 { let _=responses.try_send((destination.clone(), payload)); }
                                    }
                                    _=tokio::time::sleep(Duration::from_secs(120)) => break,
                                }
                            }
                            Ok(())
                        }.await;
                        if let Err(e)=result { tracing::debug!(host=%destination.host,port=destination.port,"UDP relay flow ended: {e:#}"); }
                    });
                }
                if let Some(tx)=flows.get(&target) { let _=tx.try_send(Bytes::copy_from_slice(payload)); }
            }
            Some((target,payload))=incoming.recv() => {
                if let Some(source)=source {
                    let mut packet=vec![0,0,0]; target.encode(&mut packet); packet.extend_from_slice(&payload);
                    socket.send_to(&packet,source).await?;
                }
            }
            _=tasks.join_next(), if !tasks.is_empty() => {},
        }
    }
    // JoinSet drop aborts every target flow; control close releases native UDP.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn udp_packets_preserve_remote_names_and_reject_fragments() {
        let target = Target {
            host: "example.com".into(),
            port: 53,
        };
        let mut bytes = vec![0, 0, 0];
        target.encode(&mut bytes);
        bytes.extend_from_slice(b"query");
        let (parsed, payload) = packet(&bytes).unwrap();
        assert_eq!(parsed, target);
        assert_eq!(payload, b"query");
        bytes[2] = 1;
        assert!(packet(&bytes).is_none());
        assert!(packet(&[0, 0, 0, 3, 255]).is_none());
    }
}
