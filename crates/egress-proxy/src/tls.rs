//! The in-cell CA (SPEC.md "TLS termination with an in-cell CA generated at boot"): a
//! P-256 key that lives only in memory, a self-signed CA certificate that sandboxes
//! trust, and server certificates minted on demand for the names sandboxes connect to.
//! Also the client configuration for the proxy's own TLS to destinations and
//! resolvers, which trusts only the public roots.
//!
//! The agent generates the CA once ([`CaKey::generate`]) and hands the same key to
//! every proxy process it starts ([`CellCa::from_key`]), so a restarted proxy presents
//! certificates sandboxes already trust. Our copies of the key are [`SecretBuf`]s;
//! rcgen and aws-lc keep their own copies, which are not wiped.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::bundle::Host;
use common::cred::SecretBuf;
use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType};
use rustls::crypto::aws_lc_rs as provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

/// How long minted certificates are valid: past any cell's 48-hour cap.
const VALIDITY: Duration = Duration::from_secs(7 * 24 * 3600);

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("certificate: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("TLS configuration: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("no usable root certificates")]
    NoRoots,
    #[error("the CA certificate is not for the CA key")]
    CaMismatch,
}

fn validity(p: &mut CertificateParams) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let at = |s: u64| time::OffsetDateTime::from_unix_timestamp(i64::try_from(s).unwrap_or(0)).unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    p.not_before = at(now.saturating_sub(3600));
    p.not_after = at(now + VALIDITY.as_secs());
}

/// The CA certificate's parameters: the same for a fresh CA and a rebuilt one, so a
/// rebuilt CA issues under the name its certificate carries.
fn ca_params(cell: &str) -> Result<CertificateParams, TlsError> {
    let mut p = CertificateParams::new(Vec::<String>::new())?;
    p.distinguished_name.push(DnType::CommonName, format!("clovelly egress CA {cell}"));
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    Ok(p)
}

/// The in-cell CA's key (PKCS#8) and certificate, as the agent keeps them to start and
/// restart the proxy process.
pub struct CaKey {
    key: SecretBuf,
    cert: CertificateDer<'static>,
}

impl CaKey {
    /// A fresh CA named after `cell` (for people reading certificates).
    pub fn generate(cell: &str) -> Result<Self, TlsError> {
        let key = KeyPair::generate()?;
        let mut p = ca_params(cell)?;
        validity(&mut p);
        let cert = p.self_signed(&key)?;
        let mut der = key.serialize_der();
        let mut buf = SecretBuf::with_capacity(der.len());
        buf.extend(&der);
        common::dek::wipe(&mut der);
        Ok(Self { key: buf, cert: cert.der().clone() })
    }

    /// The private key, PKCS#8 DER.
    pub fn key_der(&self) -> &[u8] {
        self.key.as_slice()
    }

    /// The certificate, DER.
    pub fn cert_der(&self) -> &[u8] {
        &self.cert
    }

    /// The certificate as PEM, for sandbox trust stores.
    pub fn pem(&self) -> String {
        common::b64::pem("CERTIFICATE", &self.cert)
    }
}

/// The in-cell CA and the certificates it has minted.
pub struct CellCa {
    issuer: Issuer<'static, KeyPair>,
    cert: CertificateDer<'static>,
    /// One key for every minted certificate.
    leaf_key: KeyPair,
    minted: Mutex<HashMap<Host, Arc<CertifiedKey>>>,
}

impl CellCa {
    /// A fresh CA named after `cell` (for people reading certificates).
    pub fn generate(cell: &str) -> Result<Self, TlsError> {
        let ca = CaKey::generate(cell)?;
        Self::from_key(cell, ca.key_der(), ca.cert_der())
    }

    /// The CA of `cell` from its key (PKCS#8 DER) and certificate (DER), as
    /// [`CaKey`] made them; refused if the certificate is not for the key.
    pub fn from_key(cell: &str, key_pkcs8: &[u8], cert_der: &[u8]) -> Result<Self, TlsError> {
        let key = KeyPair::try_from(&PrivatePkcs8KeyDer::from(key_pkcs8))?;
        if !cert_der.windows(key.public_key_raw().len()).any(|w| w == key.public_key_raw()) {
            return Err(TlsError::CaMismatch);
        }
        Ok(Self {
            cert: CertificateDer::from(cert_der.to_vec()),
            issuer: Issuer::new(ca_params(cell)?, key),
            leaf_key: KeyPair::generate()?,
            minted: Mutex::new(HashMap::new()),
        })
    }

    /// The CA certificate as PEM, for sandbox trust stores.
    pub fn pem(&self) -> String {
        common::b64::pem("CERTIFICATE", &self.cert)
    }

    fn mint(&self, host: &Host) -> Result<Arc<CertifiedKey>, TlsError> {
        if let Some(c) = self.minted.lock().unwrap_or_else(|p| p.into_inner()).get(host) {
            return Ok(Arc::clone(c));
        }
        let mut p = CertificateParams::new(Vec::<String>::new())?;
        p.subject_alt_names = vec![match host {
            Host::Name(n) => SanType::DnsName(n.as_str().try_into()?),
            Host::Ip(ip) => SanType::IpAddress((*ip).into()),
        }];
        p.distinguished_name.push(DnType::CommonName, host.to_string());
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        // Strict verifiers (Python 3.13's default, OpenSSL's X509_STRICT) refuse a
        // certificate without one.
        p.use_authority_key_identifier_extension = true;
        validity(&mut p);
        let cert = p.signed_by(&self.leaf_key, &self.issuer)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.leaf_key.serialize_der()));
        let signing = provider::sign::any_supported_type(&key)?;
        let ck = Arc::new(CertifiedKey::new(vec![cert.der().clone(), self.cert.clone()], signing));
        self.minted
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(host.clone(), Arc::clone(&ck));
        Ok(ck)
    }

    /// A server configuration presenting a certificate for `host` and negotiating
    /// `alpn` (the protocol the destination chose; `None` negotiates none).
    pub fn server_config(&self, host: &Host, alpn: Option<&[u8]>) -> Result<Arc<ServerConfig>, TlsError> {
        let mut c = ServerConfig::builder_with_provider(Arc::new(provider::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Fixed(self.mint(host)?)));
        c.alpn_protocols = alpn.map(|p| vec![p.to_vec()]).unwrap_or_default();
        Ok(Arc::new(c))
    }
}

#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);

impl ResolvesServerCert for Fixed {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

/// The public roots in a PEM bundle (the image's `ca-certificates.crt`).
pub fn roots(pem: &str) -> Result<Arc<RootCertStore>, TlsError> {
    let mut store = RootCertStore::empty();
    let blocks = common::b64::pem_blocks(pem, "CERTIFICATE").map_err(|_| TlsError::NoRoots)?;
    let (added, _) = store.add_parsable_certificates(blocks.into_iter().map(CertificateDer::from));
    if added == 0 {
        return Err(TlsError::NoRoots);
    }
    Ok(Arc::new(store))
}

/// The proxy's client configuration: `roots` only, with `alpn`.
pub fn client_config(roots: Arc<RootCertStore>, alpn: &[&[u8]]) -> Result<Arc<ClientConfig>, TlsError> {
    let mut c = ClientConfig::builder_with_provider(Arc::new(provider::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(c))
}

/// The name rustls checks a destination's certificate against.
pub fn server_name(host: &Host) -> rustls::pki_types::ServerName<'static> {
    match host {
        Host::Name(n) => rustls::pki_types::ServerName::try_from(n.as_str().to_owned())
            .expect("a HostName is a valid DNS name"),
        Host::Ip(ip) => rustls::pki_types::ServerName::IpAddress(std::net::IpAddr::V4(*ip).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier;

    /// Python 3.13 and OpenSSL's strict mode refuse a leaf without an Authority Key
    /// Identifier (found by criterion 2's first TD run): minted certificates carry one,
    /// and the CA a Subject Key Identifier.
    #[test]
    fn minted_certificates_carry_key_identifiers() {
        let ca = CellCa::generate("test").unwrap();
        let leaf = ca.mint(&"api.example.com".parse().unwrap()).unwrap();
        let has = |der: &[u8], oid_tail: u8| der.windows(5).any(|w| w == [0x06, 0x03, 0x55, 0x1d, oid_tail]);
        assert!(has(&leaf.cert[0], 0x23), "authority key identifier (2.5.29.35) on the leaf");
        assert!(has(&ca.cert, 0x0e), "subject key identifier (2.5.29.14) on the CA");
    }

    /// A restarted proxy rebuilds the agent's CA from its key and certificate: the same
    /// certificate, and leaves that chain to it; another key's certificate is refused.
    #[test]
    fn a_rebuilt_ca_issues_under_the_same_certificate() {
        let key = CaKey::generate("cell-1").unwrap();
        let ca = CellCa::from_key("cell-1", key.key_der(), key.cert_der()).unwrap();
        assert_eq!(ca.pem(), key.pem());
        let leaf = ca.mint(&"api.example.com".parse().unwrap()).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(key.cert_der().to_vec())).unwrap();
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::new(provider::default_provider()))
            .build()
            .unwrap();
        let name = rustls::pki_types::ServerName::try_from("api.example.com").unwrap();
        let now = rustls::pki_types::UnixTime::now();
        assert!(verifier.verify_server_cert(&leaf.cert[0], &leaf.cert[1..], &name, &[], now).is_ok());
        let other = CaKey::generate("cell-1").unwrap();
        assert!(matches!(CellCa::from_key("cell-1", key.key_der(), other.cert_der()), Err(TlsError::CaMismatch)));
    }
}
