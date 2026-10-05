//! TLS configuration.
//!
//! The server presents a certificate from a public CA, such as Let's
//! Encrypt, and asks for no client certificate, like any web server. Clients
//! authenticate inside HTTP with a password (see `auth`) and verify the
//! server against the system's CA store.

use std::path::Path;
use std::sync::Arc;

use anyhow::{ensure, Context, Result};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ResolvesServerCert;
use rustls::RootCertStore;
use tracing::debug;

/// ALPN tokens: HTTP/3 over QUIC; HTTP/2 and HTTP/1.1 over TCP.
pub const ALPN_H3: &[u8] = b"h3";
pub const ALPN_H2: &[u8] = b"h2";
pub const ALPN_HTTP11: &[u8] = b"http/1.1";

pub(crate) fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)
        .with_context(|| format!("reading {}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing certificates in {}", path.display()))?;
    ensure!(!certs.is_empty(), "no certificate found in {}", path.display());
    Ok(certs)
}

pub fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path).with_context(|| format!("reading private key {}", path.display()))
}

/// Server side. `certs` supplies the certificate for each handshake, so it
/// can change while the server runs. TLS 1.2 is offered on TCP, as by most
/// web servers; QUIC always uses TLS 1.3.
pub fn server_config(
    certs: Arc<dyn ResolvesServerCert>,
    alpn: &[&[u8]],
    allow_tls12: bool,
) -> Result<rustls::ServerConfig> {
    let versions: &[&rustls::SupportedProtocolVersion] =
        if allow_tls12 { rustls::ALL_VERSIONS } else { &[&rustls::version::TLS13] };
    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)?
        .with_no_client_auth()
        .with_cert_resolver(certs);
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(config)
}

/// Client side: trusts the system's CA store, or only `ca` when it is given
/// (for tests with a private CA).
pub fn client_config(ca: Option<&Path>, alpn: &[&[u8]]) -> Result<rustls::ClientConfig> {
    let roots = match ca {
        Some(ca) => {
            let mut roots = RootCertStore::empty();
            for cert in load_certs(ca)? {
                roots.add(cert).context("adding CA certificate to trust store")?;
            }
            roots
        }
        None => system_roots()?,
    };
    let mut config = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(config)
}

fn system_roots() -> Result<RootCertStore> {
    let found = rustls_native_certs::load_native_certs();
    for e in &found.errors {
        debug!("reading system CA certificates: {e}");
    }
    let mut roots = RootCertStore::empty();
    let (added, _ignored) = roots.add_parsable_certificates(found.certs);
    ensure!(added > 0, "no system CA certificates found (install the ca-certificates package)");
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rustls::pki_types::ServerName;
    use rustls::{ClientConnection, ServerConnection};

    use super::*;
    use crate::certs::CertStore;

    struct Dir(PathBuf);

    impl Dir {
        /// A CA and a server certificate for `relay.test` and 192.0.2.1.
        fn new(tag: &str) -> Self {
            let d = std::env::temp_dir().join(format!("relay-tls-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            let ca_key = rcgen::KeyPair::generate().unwrap();
            let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let ca = ca_params.self_signed(&ca_key).unwrap();
            let issuer = rcgen::Issuer::new(ca_params, ca_key);
            let key = rcgen::KeyPair::generate().unwrap();
            let params = rcgen::CertificateParams::new(vec!["relay.test".into(), "192.0.2.1".into()]).unwrap();
            let cert = params.signed_by(&key, &issuer).unwrap();
            std::fs::write(d.join("ca.pem"), ca.pem()).unwrap();
            std::fs::write(d.join("fullchain.pem"), cert.pem() + &ca.pem()).unwrap();
            std::fs::write(d.join("privkey.pem"), key.serialize_pem()).unwrap();
            Self(d)
        }

        fn server(&self) -> Arc<rustls::ServerConfig> {
            let store = CertStore::open(&self.0.join("fullchain.pem"), &self.0.join("privkey.pem")).unwrap();
            Arc::new(server_config(store, &[ALPN_H2], true).unwrap())
        }

        fn client(&self) -> Arc<rustls::ClientConfig> {
            Arc::new(client_config(Some(&self.0.join("ca.pem")), &[ALPN_H2]).unwrap())
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Drives a TLS handshake between in-memory endpoints.
    fn handshake(client: &mut ClientConnection, server: &mut ServerConnection) -> Result<(), rustls::Error> {
        for _ in 0..10 {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).unwrap();
            server.read_tls(&mut &buf[..]).unwrap();
            server.process_new_packets()?;
            let mut buf = Vec::new();
            server.write_tls(&mut buf).unwrap();
            client.read_tls(&mut &buf[..]).unwrap();
            client.process_new_packets()?;
            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(());
            }
        }
        panic!("handshake did not finish");
    }

    #[test]
    fn handshake_without_client_certificate() {
        let d = Dir::new("ok");
        let (s, c) = (d.server(), d.client());
        for name in ["relay.test", "192.0.2.1"] {
            let mut client = ClientConnection::new(c.clone(), ServerName::try_from(name).unwrap()).unwrap();
            let mut server = ServerConnection::new(s.clone()).unwrap();
            handshake(&mut client, &mut server).unwrap();
            assert!(server.peer_certificates().is_none());
            assert_eq!(client.alpn_protocol(), Some(ALPN_H2));
        }
    }

    #[test]
    fn server_certificate_name_is_checked() {
        let d = Dir::new("name");
        let mut client = ClientConnection::new(d.client(), ServerName::try_from("other.test").unwrap()).unwrap();
        let mut server = ServerConnection::new(d.server()).unwrap();
        assert!(handshake(&mut client, &mut server).is_err());
    }

    #[test]
    fn server_from_another_ca_is_rejected() {
        let (a, b) = (Dir::new("ca-a"), Dir::new("ca-b"));
        let mut client = ClientConnection::new(a.client(), ServerName::try_from("relay.test").unwrap()).unwrap();
        let mut server = ServerConnection::new(b.server()).unwrap();
        assert!(handshake(&mut client, &mut server).is_err());
    }
}
