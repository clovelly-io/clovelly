//! What a cell sends the verifier to unlock, parsed from the wire, and the REPORTDATA
//! that binds it to the quote.
//!
//! The cell asks for a quote over [`report_data`] and the verifier recomputes it (check
//! 8), so the quote vouches for the environment, the cell's public key and the
//! verifier's nonce:
//!
//! ```text
//! REPORTDATA = SHA-512("clovelly-v1" || env_id || SHA-256(SPKI) || nonce)
//! ```

use std::fmt;

use aws_lc_rs::digest;
use x509_cert::der::Decode;
use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::spki::SubjectPublicKeyInfoRef;

use crate::ids::{EnvId, IdError, ReleaseId, SubenvId, Zone};
use crate::proto::verifier as pb;
use crate::tdx::ReportData;

/// Domain separator for REPORTDATA, so a quote made for this protocol means nothing
/// elsewhere.
const REPORT_DATA_DOMAIN: &[u8] = b"clovelly-v1";
const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error("evidence is missing")]
    Missing,
    #[error(transparent)]
    Id(#[from] IdError),
    #[error("nonce is {0} bytes, expected 32")]
    NonceLength(usize),
    #[error("SPKI is not DER: {0}")]
    SpkiDer(#[from] x509_cert::der::Error),
    #[error("SPKI is not an uncompressed P-256 public key")]
    SpkiNotP256,
}

/// A verifier-issued nonce: 32 random bytes, single use.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce(pub [u8; 32]);

impl TryFrom<&[u8]> for Nonce {
    type Error = EvidenceError;

    fn try_from(bytes: &[u8]) -> Result<Self, EvidenceError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| EvidenceError::NonceLength(bytes.len()))
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce({})", crate::hex(&self.0))
    }
}

/// The DER SubjectPublicKeyInfo of a P-256 key, with its uncompressed point.
#[derive(Clone, PartialEq, Eq)]
pub struct Spki {
    der: Vec<u8>,
    point: [u8; 65],
}

impl Spki {
    /// Parses DER and accepts only `id-ecPublicKey` on `prime256v1` with an uncompressed
    /// point. Whether the point is on the curve is checked where it is used.
    pub fn from_der(der: &[u8]) -> Result<Self, EvidenceError> {
        let spki = SubjectPublicKeyInfoRef::from_der(der)?;
        let curve = spki
            .algorithm
            .parameters
            .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
        let point: [u8; 65] = spki
            .subject_public_key
            .as_bytes()
            .and_then(|b| b.try_into().ok())
            .ok_or(EvidenceError::SpkiNotP256)?;
        if spki.algorithm.oid != ID_EC_PUBLIC_KEY || curve != Some(PRIME256V1) || point[0] != 4 {
            return Err(EvidenceError::SpkiNotP256);
        }
        Ok(Self {
            der: der.to_vec(),
            point,
        })
    }

    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The uncompressed SEC1 point, `04 || x || y`.
    pub fn point(&self) -> &[u8; 65] {
        &self.point
    }
}

impl fmt::Debug for Spki {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Spki({})", crate::hex(&self.point))
    }
}

/// The REPORTDATA a cell's quote must carry for this environment, key and nonce.
pub fn report_data(env: &EnvId, spki: &Spki, nonce: &Nonce) -> ReportData {
    let spki_hash = digest::digest(&digest::SHA256, spki.der());
    let mut ctx = digest::Context::new(&digest::SHA512);
    ctx.update(REPORT_DATA_DOMAIN);
    ctx.update(env.as_str().as_bytes());
    ctx.update(spki_hash.as_ref());
    ctx.update(&nonce.0);
    ReportData(
        ctx.finish()
            .as_ref()
            .try_into()
            .expect("SHA-512 is 64 bytes"),
    )
}

/// The DNS name a cell of `subenv` serves under, and its certificate's SAN.
pub fn cell_dns_name(env: &EnvId, subenv: &SubenvId) -> String {
    format!("{subenv}.{env}.cells.clovelly.internal")
}

/// A cell's unlock evidence. The quote and CCEL stay raw: parsing them is the
/// verifier's check 1 and check 6.
#[derive(Debug, Clone)]
pub struct Evidence {
    pub quote: Vec<u8>,
    pub ccel_table: Vec<u8>,
    pub ccel_log: Vec<u8>,
    pub env: EnvId,
    pub subenv: SubenvId,
    pub release: ReleaseId,
    pub spki: Spki,
    pub nonce: Nonce,
    pub instance_id: u64,
    pub zone: Zone,
}

impl TryFrom<pb::Evidence> for Evidence {
    type Error = EvidenceError;

    fn try_from(e: pb::Evidence) -> Result<Self, EvidenceError> {
        Ok(Self {
            env: e.env_id.parse()?,
            subenv: e.subenv_id.parse()?,
            release: e.release_id.parse()?,
            spki: Spki::from_der(&e.spki)?,
            nonce: Nonce::try_from(e.nonce.as_slice())?,
            zone: e.zone.parse()?,
            instance_id: e.instance_id,
            quote: e.quote,
            ccel_table: e.ccel_table,
            ccel_log: e.ccel_log,
        })
    }
}

impl From<&Evidence> for pb::Evidence {
    fn from(e: &Evidence) -> Self {
        Self {
            quote: e.quote.clone(),
            ccel_table: e.ccel_table.clone(),
            ccel_log: e.ccel_log.clone(),
            env_id: e.env.to_string(),
            subenv_id: e.subenv.to_string(),
            release_id: e.release.to_string(),
            spki: e.spki.der().to_vec(),
            nonce: e.nonce.0.to_vec(),
            instance_id: e.instance_id,
            zone: e.zone.to_string(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use aws_lc_rs::agreement;
    use aws_lc_rs::encoding::AsDer;

    /// The DER SPKI of a fresh P-256 key.
    pub(crate) fn spki_der() -> Vec<u8> {
        let key = agreement::PrivateKey::generate(&agreement::ECDH_P256).unwrap();
        key.compute_public_key()
            .unwrap()
            .as_der()
            .unwrap()
            .as_ref()
            .to_vec()
    }

    #[test]
    fn spki_accepts_p256_only() {
        let der = spki_der();
        let spki = Spki::from_der(&der).unwrap();
        assert_eq!(spki.point()[0], 4);
        assert_eq!(spki.der(), der.as_slice());

        let x25519 = agreement::PrivateKey::generate(&agreement::X25519).unwrap();
        let x = x25519.compute_public_key().unwrap();
        let x = x.as_der().unwrap();
        assert!(matches!(
            Spki::from_der(x.as_ref()),
            Err(EvidenceError::SpkiNotP256)
        ));
        assert!(Spki::from_der(b"junk").is_err());
    }

    #[test]
    fn report_data_binds_each_input() {
        let env: EnvId = "staging".parse().unwrap();
        let spki = Spki::from_der(&spki_der()).unwrap();
        let other_spki = Spki::from_der(&spki_der()).unwrap();
        let nonce = Nonce([7; 32]);
        let base = report_data(&env, &spki, &nonce);
        assert_eq!(base, report_data(&env, &spki, &nonce));
        assert_ne!(base, report_data(&"prod".parse().unwrap(), &spki, &nonce));
        assert_ne!(base, report_data(&env, &other_spki, &nonce));
        assert_ne!(base, report_data(&env, &spki, &Nonce([8; 32])));

        // The construction, spelled out.
        let mut msg = b"clovelly-v1staging".to_vec();
        msg.extend_from_slice(digest::digest(&digest::SHA256, spki.der()).as_ref());
        msg.extend_from_slice(&[7; 32]);
        assert_eq!(
            base.0.as_slice(),
            digest::digest(&digest::SHA512, &msg).as_ref()
        );
    }

    #[test]
    fn cell_names_put_subenv_first() {
        let name = cell_dns_name(&"acme".parse().unwrap(), &"bank-a".parse().unwrap());
        assert_eq!(name, "bank-a.acme.cells.clovelly.internal");
    }
}
