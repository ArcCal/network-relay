//! TLS configuration.
//!
//! The server presents a certificate from a public CA, such as Let's
//! Encrypt. By default it asks for no client certificate, like any web
//! server, and clients authenticate inside HTTP with a password (see
//! `auth`). With `[tls] client_certificates = true` it also offers to take a
//! client certificate: any certificate is accepted at the TLS layer once the
//! client has proven it holds the key, and the relay then recognizes users
//! by the certificate's SHA-256 fingerprint, pinned in the configuration.

use std::path::Path;
use std::sync::Arc;

use anyhow::{ensure, Context, Result};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::ResolvesServerCert;
use rustls::{DigitallySignedStruct, DistinguishedName, RootCertStore, SignatureScheme};
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

/// Accepts any client certificate whose signature over the handshake
/// checks out, without asking for one: users are told apart by the
/// fingerprint of the certificate, which the configuration pins, so no CA
/// is involved (like SSH keys).
#[derive(Debug)]
struct PinnedClientCertificates {
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for PinnedClientCertificates {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Server side. `certs` supplies the certificate for each handshake, so it
/// can change while the server runs. TLS 1.2 is offered on TCP, as by most
/// web servers; QUIC always uses TLS 1.3. With `client_certificates`, clients
/// may present a certificate (see [`PinnedClientCertificates`]).
pub fn server_config(
    certs: Arc<dyn ResolvesServerCert>,
    alpn: &[&[u8]],
    allow_tls12: bool,
    client_certificates: bool,
) -> Result<rustls::ServerConfig> {
    let versions: &[&rustls::SupportedProtocolVersion] =
        if allow_tls12 { rustls::ALL_VERSIONS } else { &[&rustls::version::TLS13] };
    let builder = rustls::ServerConfig::builder_with_provider(provider()).with_protocol_versions(versions)?;
    let builder = if client_certificates {
        builder.with_client_cert_verifier(Arc::new(PinnedClientCertificates { provider: provider() }))
    } else {
        builder.with_no_client_auth()
    };
    let mut config = builder.with_cert_resolver(certs);
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(config)
}

/// The SHA-256 fingerprint of the certificate a TLS client presented.
pub fn client_fingerprint(certs: Option<&[CertificateDer<'_>]>) -> Option<[u8; 32]> {
    certs.and_then(|c| c.first()).map(|leaf| crate::auth::fingerprint(leaf.as_ref()))
}

/// Client side: trusts the system's CA store, or only `ca` when it is given
/// (for tests with a private CA).
pub fn client_config(ca: Option<&Path>, alpn: &[&[u8]]) -> Result<rustls::ClientConfig> {
    client_config_with_identity(ca, alpn, None)
}

/// Like [`client_config`], presenting a client certificate and key.
pub fn client_config_with_identity(
    ca: Option<&Path>,
    alpn: &[&[u8]],
    identity: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> Result<rustls::ClientConfig> {
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
    let builder = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots);
    let mut config = match identity {
        Some((chain, key)) => builder.with_client_auth_cert(chain, key)?,
        None => builder.with_no_client_auth(),
    };
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
            Arc::new(server_config(store, &[ALPN_H2], true, false).unwrap())
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
    fn client_certificates_are_optional_and_identified_by_fingerprint() {
        let d = Dir::new("client");
        let store = CertStore::open(&d.0.join("fullchain.pem"), &d.0.join("privkey.pem")).unwrap();
        let server = Arc::new(server_config(store, &[ALPN_H2], true, true).unwrap());
        // Without a certificate the handshake still succeeds.
        let mut client = ClientConnection::new(d.client(), ServerName::try_from("relay.test").unwrap()).unwrap();
        let mut conn = ServerConnection::new(server.clone()).unwrap();
        handshake(&mut client, &mut conn).unwrap();
        assert_eq!(client_fingerprint(conn.peer_certificates()), None);
        // With a self-signed one, its fingerprint is seen.
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["ipad".into()]).unwrap().self_signed(&key).unwrap();
        let der = cert.der().clone();
        let identity = (vec![der.clone()], PrivateKeyDer::try_from(key.serialize_der()).unwrap());
        let with_id =
            Arc::new(client_config_with_identity(Some(&d.0.join("ca.pem")), &[ALPN_H2], Some(identity)).unwrap());
        let mut client = ClientConnection::new(with_id, ServerName::try_from("relay.test").unwrap()).unwrap();
        let mut conn = ServerConnection::new(server).unwrap();
        handshake(&mut client, &mut conn).unwrap();
        assert_eq!(client_fingerprint(conn.peer_certificates()), Some(crate::auth::fingerprint(der.as_ref())));
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
