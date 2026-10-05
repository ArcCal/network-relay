//! Client identities: a key pair and a self-signed certificate in a
//! password-protected PKCS#12 file, for profiles that authenticate devices
//! with a certificate instead of a password (`PayloadCertificateUUID`).
//!
//! The relay does not need a CA: the configuration pins each user's
//! certificate by its SHA-256 fingerprint, and the TLS handshake proves the
//! device holds the key. Once installed, the key lives in the device's
//! keychain. The generated profile requests a nonextractable key on macOS;
//! protect and delete the original PKCS#12 file and any profile copies.

use anyhow::{anyhow, Context, Result};
use chrono::{Datelike, Utc};

use crate::auth;

/// A newly made identity.
pub struct Identity {
    /// The PKCS#12 file (key and certificate), encrypted with `password`.
    pub p12: Vec<u8>,
    pub password: String,
    /// SHA-256 of the DER certificate, for `certificate_sha256`.
    pub fingerprint: [u8; 32],
}

/// Makes an ECDSA P-256 key and a self-signed client certificate for
/// `user`, valid for `days` days from today.
pub fn generate(user: &str, days: u32) -> Result<Identity> {
    auth::validate_user_name(user)?;
    anyhow::ensure!((1..=3650).contains(&days), "the certificate must be valid for 1 to 3650 days");
    let key = rcgen::KeyPair::generate().context("generating the key")?;
    let mut params = rcgen::CertificateParams::new(Vec::new()).context("certificate parameters")?;
    params.distinguished_name.push(rcgen::DnType::CommonName, user);
    params.distinguished_name.push(rcgen::DnType::OrganizationName, "network-relay");
    let today = Utc::now().date_naive();
    let until = today + chrono::Days::new(u64::from(days));
    let ymd = |d: chrono::NaiveDate| rcgen::date_time_ymd(d.year(), d.month() as u8, d.day() as u8);
    params.not_before = ymd(today - chrono::Days::new(1));
    params.not_after = ymd(until);
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params.self_signed(&key).context("signing the certificate")?;
    let password = auth::generate_password();
    let pfx = p12::PFX::new(cert.der(), &key.serialize_der(), None, &password, user)
        .ok_or_else(|| anyhow!("encoding the PKCS#12 file failed"))?;
    Ok(Identity { p12: pfx.to_der(), password, fingerprint: auth::fingerprint(cert.der()) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_decrypt_with_their_password_and_match_the_fingerprint() {
        let id = generate("ipad", 365).unwrap();
        let pfx = p12::PFX::parse(&id.p12).unwrap();
        assert!(pfx.verify_mac(&id.password));
        let certs = pfx.cert_x509_bags(&id.password).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(auth::fingerprint(&certs[0]), id.fingerprint);
        let keys = pfx.key_bags(&id.password).unwrap();
        assert_eq!(keys.len(), 1);
        assert!(!pfx.verify_mac("wrong"));
        let (_, parsed) = x509_parser::parse_x509_certificate(&certs[0]).unwrap();
        assert_eq!(parsed.subject().iter_common_name().next().unwrap().as_str().unwrap(), "ipad");
        assert!(generate("bad name", 365).is_err());
        assert!(generate("ipad", 0).is_err());
    }
}
