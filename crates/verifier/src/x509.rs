//! Certificates the verifier signs through the key helper: the environment CA (once, by
//! `verifier init` or `verifier make-ca`) and a certificate for every unlocked cell.
//!
//! The helper signs asynchronously, so the TBSCertificate is encoded here from x509-cert's
//! public types, signed, checked under the key it should be from, and wrapped as a
//! Certificate.

use std::str::FromStr;
use std::time::Duration;

use common::cellcert::{self, CellCertInfo};
use common::evidence::{EvidenceError, Spki};
use common::jws::TrustedKey;
use der::asn1::{AnyRef, BitString, Ia5String, ObjectIdentifier, OctetString, UtcTime};
use der::oid::AssociatedOid;
use der::{Decode, Encode, Sequence};
use x509_cert::Certificate;
use x509_cert::certificate::Version;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
    SubjectAltName, SubjectKeyIdentifier,
};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};

use crate::keys::{self, KeyError, Keys};

const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const KP_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
/// The CA certificate lasts ten years; rotating it is a customer procedure (phase 6).
const CA_LIFETIME: u64 = 10 * 365 * 24 * 3600;
/// Cell certificates start five minutes early to absorb clock skew.
const SKEW: u64 = 300;

#[derive(Debug, thiserror::Error)]
pub enum X509Error {
    #[error("DER: {0}")]
    Der(#[from] der::Error),
    #[error(transparent)]
    Keys(#[from] KeyError),
    #[error("the CA certificate's key: {0}")]
    CaKey(#[from] EvidenceError),
    #[error("CA certificate PEM holds no CERTIFICATE")]
    NoCaCert,
    #[error("CA certificate has no subject key identifier")]
    NoSki,
}

#[derive(Sequence)]
struct Tbs {
    #[asn1(context_specific = "0", default = "Default::default")]
    version: Version,
    serial_number: SerialNumber,
    signature: AlgorithmIdentifierOwned,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfoOwned,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    extensions: Option<Vec<Extension>>,
}

#[derive(Sequence)]
struct Signed<'a> {
    tbs: AnyRef<'a>,
    algorithm: AlgorithmIdentifierOwned,
    signature: BitString,
}

/// The environment CA, as loaded from the configuration.
#[derive(Debug, Clone)]
pub struct CaCert {
    pub der: Vec<u8>,
    subject: Name,
    ski: OctetString,
    /// The certificate's own public key: what a cell certificate's signature must verify
    /// under, whatever the key helper says its key is.
    key: TrustedKey,
}

impl CaCert {
    pub fn from_pem(pem: &str) -> Result<Self, X509Error> {
        let der = common::b64::pem_blocks(pem, "CERTIFICATE")
            .ok()
            .and_then(|b| b.into_iter().next())
            .ok_or(X509Error::NoCaCert)?;
        let cert = Certificate::from_der(&der)?;
        let (_, ski) = cert
            .tbs_certificate()
            .get_extension::<SubjectKeyIdentifier>()?
            .ok_or(X509Error::NoSki)?;
        let key = TrustedKey::from_spki(Spki::from_der(&cert.tbs_certificate().subject_public_key_info().to_der()?)?);
        Ok(Self {
            subject: cert.tbs_certificate().subject().clone(),
            ski: ski.0,
            der,
            key,
        })
    }
}

/// Creates the self-signed environment CA for `key`, valid from `now` for ten years.
///
/// `generation` is what sets a rotated CA's subject apart from its predecessor's: an SDK's
/// bundle holds both during a rotation, and TLS stacks that pick an issuer by subject alone
/// (OpenSSL, BoringSSL) would try only one of two CAs with the same subject. `None`, for a
/// first CA, adds nothing. The key's name says nothing: nothing here parses it.
pub async fn make_ca(keys: &impl Keys, key: &str, env: &str, generation: Option<u32>, now: u64) -> Result<Vec<u8>, X509Error> {
    let expected = keys::trusted(keys, key).await?;
    let spki = SubjectPublicKeyInfoOwned::from_der(expected.spki_der())?;
    let ski = key_id(&spki);
    let generation = generation.map_or(String::new(), |g| format!(" v{g}"));
    let name = Name::from_str(&format!("CN=clovelly {env} environment CA{generation},O=clovelly"))?;
    let extensions = vec![
        extension(
            &BasicConstraints {
                ca: true,
                path_len_constraint: Some(0),
            },
            true,
        )?,
        extension(&KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign), true)?,
        extension(&SubjectKeyIdentifier(ski), false)?,
    ];
    let tbs = Tbs {
        version: Version::V3,
        serial_number: serial()?,
        signature: ecdsa_sha256(),
        issuer: name.clone(),
        validity: validity(now, now + CA_LIFETIME)?,
        subject: name,
        subject_public_key_info: spki,
        extensions: Some(extensions),
    };
    sign(tbs, keys, key, &expected).await
}

/// What goes into a cell certificate.
pub struct CellRequest<'a> {
    /// The cell's key (DER SubjectPublicKeyInfo).
    pub spki: &'a [u8],
    /// The first SAN and the subject's CN, `<subenv>.<env>.cells.clovelly.internal`.
    pub dns: &'a str,
    /// The second SAN, the cell's own `<instance>.<zone>.<subenv>.<env>.cells.clovelly.internal`.
    pub cell_name: &'a str,
    pub info: &'a CellCertInfo,
    pub now: u64,
    /// The end of the cell's lifetime.
    pub not_after: u64,
}

/// Issues a cell certificate under the CA key `ca_key`.
pub async fn cell_cert(
    keys: &impl Keys,
    ca: &CaCert,
    ca_key: &str,
    req: &CellRequest<'_>,
) -> Result<Vec<u8>, X509Error> {
    let CellRequest {
        spki,
        dns,
        cell_name,
        info,
        now,
        not_after,
    } = *req;
    let extensions = vec![
        extension(
            &BasicConstraints {
                ca: false,
                path_len_constraint: None,
            },
            true,
        )?,
        extension(&KeyUsage(KeyUsages::DigitalSignature.into()), true)?,
        extension(&ExtendedKeyUsage(vec![KP_SERVER_AUTH]), false)?,
        extension(
            &SubjectAltName(vec![
                GeneralName::DnsName(Ia5String::new(dns)?),
                GeneralName::DnsName(Ia5String::new(cell_name)?),
            ]),
            false,
        )?,
        extension(
            &AuthorityKeyIdentifier {
                key_identifier: Some(ca.ski.clone()),
                authority_cert_issuer: None,
                authority_cert_serial_number: None,
            },
            false,
        )?,
        Extension {
            extn_id: cellcert::OID,
            critical: false,
            extn_value: OctetString::new(info.to_der())?,
        },
    ];
    let tbs = Tbs {
        version: Version::V3,
        serial_number: serial()?,
        signature: ecdsa_sha256(),
        issuer: ca.subject.clone(),
        validity: validity(now.saturating_sub(SKEW), not_after)?,
        subject: Name::from_str(&format!("CN={dns}"))?,
        subject_public_key_info: SubjectPublicKeyInfoOwned::from_der(spki)?,
        extensions: Some(extensions),
    };
    sign(tbs, keys, ca_key, &ca.key).await
}

async fn sign(tbs: Tbs, keys: &impl Keys, key: &str, expected: &TrustedKey) -> Result<Vec<u8>, X509Error> {
    let tbs = tbs.to_der()?;
    let signature = keys::signed(keys, key, &tbs, expected).await?;
    Ok(Signed {
        tbs: AnyRef::from_der(&tbs)?,
        algorithm: ecdsa_sha256(),
        signature: BitString::from_bytes(&signature)?,
    }
    .to_der()?)
}

fn extension<T: Encode + AssociatedOid>(value: &T, critical: bool) -> Result<Extension, X509Error> {
    Ok(Extension {
        extn_id: T::OID,
        critical,
        extn_value: OctetString::new(value.to_der()?)?,
    })
}

fn ecdsa_sha256() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ECDSA_WITH_SHA256,
        parameters: None,
    }
}

/// 16 random bytes with the top bit clear, so the serial is positive.
fn serial() -> Result<SerialNumber, X509Error> {
    let mut bytes = [0u8; 16];
    aws_lc_rs::rand::fill(&mut bytes).expect("the system RNG does not fail");
    bytes[0] &= 0x7f;
    bytes[0] |= 0x01;
    Ok(SerialNumber::new(&bytes)?)
}

fn validity(from: u64, to: u64) -> Result<Validity, X509Error> {
    let t = |s: u64| -> Result<Time, X509Error> {
        Ok(Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(s))?))
    };
    Ok(Validity::new(t(from)?, t(to)?))
}

/// RFC 7093 method 1: the leftmost 160 bits of SHA-256 of the public key.
fn key_id(spki: &SubjectPublicKeyInfoOwned) -> OctetString {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, spki.subject_public_key.raw_bytes());
    OctetString::new(&d.as_ref()[..20]).expect("20 bytes is a valid OCTET STRING")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::LocalKms;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};

    fn verifies_under(cert: &Certificate, issuer: &Certificate) -> bool {
        let key = issuer
            .tbs_certificate()
            .subject_public_key_info()
            .subject_public_key
            .raw_bytes();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key)
            .verify(
                &cert.tbs_certificate().to_der().unwrap(),
                cert.signature().raw_bytes(),
            )
            .is_ok()
    }

    /// A CA made from a later key version has its own subject, so TLS stacks that choose
    /// an issuer by subject find the right one in a bundle holding both.
    #[tokio::test]
    async fn a_rotated_ca_has_its_own_subject() {
        let keys = LocalKms::generate(&["first", "second"]);
        let subject = async |key, generation| {
            let der = make_ca(&keys, key, "acme", generation, 1_793_000_000).await.unwrap();
            Certificate::from_der(&der).unwrap().tbs_certificate().subject().to_string()
        };
        let (a, b) = (subject("first", None).await, subject("second", Some(2)).await);
        assert_eq!(a, "CN=clovelly acme environment CA,O=clovelly");
        assert_eq!(b, "CN=clovelly acme environment CA v2,O=clovelly");
    }

    #[tokio::test]
    async fn ca_signs_a_cell_certificate_that_names_the_cell() {
        let keys = LocalKms::generate(&["ca", "cell"]);
        let now = 1_793_000_000;
        let ca_der = make_ca(&keys, "ca", "acme", None, now).await.unwrap();
        let ca_cert = Certificate::from_der(&ca_der).unwrap();
        assert!(verifies_under(&ca_cert, &ca_cert));
        let ca = CaCert::from_pem(&common::b64::pem("CERTIFICATE", &ca_der)).unwrap();

        let info = CellCertInfo {
            quote_sha256: [3; 32],
            env: "acme".parse().unwrap(),
            subenv: "bank-a".parse().unwrap(),
            release: "clovelly-0.1.0-test".parse().unwrap(),
        };
        let cell_spki = keys.public_key("cell").await.unwrap();
        let req = CellRequest {
            spki: &cell_spki,
            dns: "bank-a.acme.cells.clovelly.internal",
            cell_name: "clovelly-7f.us-central1-a.bank-a.acme.cells.clovelly.internal",
            info: &info,
            now,
            not_after: now + 3600,
        };
        let der = cell_cert(&keys, &ca, "ca", &req).await.unwrap();
        let cert = Certificate::from_der(&der).unwrap();
        assert!(verifies_under(&cert, &ca_cert));
        let tbs = cert.tbs_certificate();
        assert_eq!(tbs.issuer(), ca_cert.tbs_certificate().subject());
        assert_eq!(tbs.validity().not_after.to_unix_duration().as_secs(), now + 3600);
        let (_, san) = tbs.get_extension::<SubjectAltName>().unwrap().unwrap();
        assert_eq!(
            san.0,
            vec![
                GeneralName::DnsName(Ia5String::new("bank-a.acme.cells.clovelly.internal").unwrap()),
                GeneralName::DnsName(
                    Ia5String::new("clovelly-7f.us-central1-a.bank-a.acme.cells.clovelly.internal").unwrap()
                ),
            ]
        );
        let ext = tbs
            .extensions()
            .unwrap()
            .iter()
            .find(|e| e.extn_id == cellcert::OID)
            .unwrap();
        assert_eq!(CellCertInfo::from_der(ext.extn_value.as_bytes()).unwrap(), info);
    }
}
