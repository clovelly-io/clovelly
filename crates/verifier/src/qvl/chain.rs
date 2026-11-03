//! X.509 path checks for Intel's PKI: every certificate and CRL is ECDSA P-256 with
//! SHA-256, and every chain ends at the pinned root.

use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use der::asn1::ObjectIdentifier;
use der::{Decode, Reader, SliceReader};
use x509_cert::Certificate;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::BasicConstraints;

const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ChainError {
    #[error("certificate DER: {0}")]
    Der(String),
    #[error("{0:?} is not issued by {1:?}")]
    Issuer(String, String),
    #[error("{0:?} is not signed with ecdsa-with-SHA256")]
    Algorithm(String),
    #[error("signature on {0:?} does not verify")]
    Signature(String),
    #[error("{0:?} is not valid at {1}")]
    Validity(String, u64),
    #[error("{0:?} is not a CA")]
    NotCa(String),
    #[error("empty chain")]
    Empty,
}

fn der_err(e: der::Error) -> ChainError {
    ChainError::Der(e.to_string())
}

fn name(c: &Certificate) -> String {
    c.tbs_certificate().subject().to_string()
}

/// The first element of a DER SEQUENCE, as it appears in `der`: the signed part of
/// a certificate or CRL, without re-encoding it.
fn signed_part(der: &[u8]) -> Result<&[u8], ChainError> {
    let mut r = SliceReader::new(der).map_err(der_err)?;
    der::Header::decode(&mut r).map_err(der_err)?;
    r.tlv_bytes().map_err(der_err)
}

fn verify_signature(
    issuer: &Certificate,
    signed: &[u8],
    algorithm: ObjectIdentifier,
    signature: &[u8],
    what: String,
) -> Result<(), ChainError> {
    if algorithm != ECDSA_WITH_SHA256 {
        return Err(ChainError::Algorithm(what));
    }
    let key = issuer
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key)
        .verify(signed, signature)
        .map_err(|_| ChainError::Signature(what))
}

fn is_ca(c: &Certificate) -> bool {
    matches!(
        c.tbs_certificate().get_extension::<BasicConstraints>(),
        Ok(Some((_, bc))) if bc.ca
    )
}

fn valid_at(c: &Certificate, now: u64) -> Result<(), ChainError> {
    let v = c.tbs_certificate().validity();
    let (from, to) = (
        v.not_before.to_unix_duration().as_secs(),
        v.not_after.to_unix_duration().as_secs(),
    );
    if (from..=to).contains(&now) {
        Ok(())
    } else {
        Err(ChainError::Validity(name(c), now))
    }
}

/// Checks `der` (a certificate) was issued by `issuer` and is valid at `now`.
fn issued(der: &[u8], cert: &Certificate, issuer: &Certificate, now: u64) -> Result<(), ChainError> {
    if cert.tbs_certificate().issuer() != issuer.tbs_certificate().subject() {
        return Err(ChainError::Issuer(name(cert), name(issuer)));
    }
    if !is_ca(issuer) {
        return Err(ChainError::NotCa(name(issuer)));
    }
    verify_signature(
        issuer,
        signed_part(der)?,
        cert.signature_algorithm().oid,
        cert.signature().raw_bytes(),
        name(cert),
    )?;
    valid_at(cert, now)
}

/// Verifies `chain` (DER, leaf first; may or may not end with the root) up to `root`,
/// at `now`, and returns the parsed certificates without the root.
pub fn verify(chain: &[Vec<u8>], root: &[u8], now: u64) -> Result<Vec<Certificate>, ChainError> {
    let root_cert = Certificate::from_der(root).map_err(der_err)?;
    valid_at(&root_cert, now)?;
    let chain: Vec<&Vec<u8>> = chain.iter().filter(|c| c.as_slice() != root).collect();
    let certs = chain
        .iter()
        .map(|d| Certificate::from_der(d).map_err(der_err))
        .collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(ChainError::Empty);
    }
    for i in 0..certs.len() {
        let issuer = certs.get(i + 1).unwrap_or(&root_cert);
        issued(chain[i], &certs[i], issuer, now)?;
    }
    Ok(certs)
}

/// Verifies a CRL's signature by `issuer`.
pub fn verify_crl(der: &[u8], issuer: &Certificate) -> Result<CertificateList, ChainError> {
    let crl = CertificateList::from_der(der).map_err(der_err)?;
    verify_signature(
        issuer,
        signed_part(der)?,
        crl.signature_algorithm.oid,
        crl.signature.raw_bytes(),
        format!("CRL from {}", crl.tbs_cert_list.issuer),
    )?;
    Ok(crl)
}
