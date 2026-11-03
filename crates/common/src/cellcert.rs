//! The custom extension in a cell certificate, which says what the verifier checked.
//!
//! ```text
//! CellCertInfo ::= SEQUENCE {
//!   version    INTEGER (1),
//!   quoteHash  OCTET STRING,  -- SHA-256 of the raw quote the cell unlocked with
//!   envId      UTF8String,
//!   subenvId   UTF8String,
//!   releaseId  UTF8String }
//! ```
//!
//! The certificate's validity ends at the cell's maximum lifetime, so there is no
//! separate expiry field. The SDK (phase 2) matches `envId` against its environment.

use der::asn1::{ObjectIdentifier, OctetString};
use der::{Decode, Encode, Sequence};

use crate::ids::{EnvId, IdError, ReleaseId, SubenvId};

/// The extension's OID. A placeholder under the IANA enterprise arc until we register
/// a private enterprise number; only certificates from an environment CA carry it.
pub const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.4294967295.1.1");
/// [`OID`]'s arcs, in the form rcgen takes.
pub const OID_ARCS: [u64; 9] = [1, 3, 6, 1, 4, 1, 4294967295, 1, 1];

#[derive(Debug, thiserror::Error)]
pub enum CellCertError {
    #[error("DER: {0}")]
    Der(#[from] der::Error),
    #[error("extension version {0} is not 1")]
    Version(u8),
    #[error("quote hash is {0} bytes, expected 32")]
    HashLength(usize),
    #[error(transparent)]
    Id(#[from] IdError),
}

/// What a cell certificate vouches for beyond its SAN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellCertInfo {
    pub quote_sha256: [u8; 32],
    pub env: EnvId,
    pub subenv: SubenvId,
    pub release: ReleaseId,
}

#[derive(Sequence)]
struct Wire {
    version: u8,
    quote_hash: OctetString,
    env: String,
    subenv: String,
    release: String,
}

impl CellCertInfo {
    /// The extension value (DER).
    pub fn to_der(&self) -> Vec<u8> {
        Wire {
            version: 1,
            quote_hash: OctetString::new(self.quote_sha256.to_vec())
                .expect("32 bytes is a valid OCTET STRING"),
            env: self.env.to_string(),
            subenv: self.subenv.to_string(),
            release: self.release.to_string(),
        }
        .to_der()
        .expect("encoding owned strings and octets cannot fail")
    }

    pub fn from_der(der: &[u8]) -> Result<Self, CellCertError> {
        let w = Wire::from_der(der)?;
        if w.version != 1 {
            return Err(CellCertError::Version(w.version));
        }
        let hash = w.quote_hash.as_bytes();
        Ok(Self {
            quote_sha256: hash
                .try_into()
                .map_err(|_| CellCertError::HashLength(hash.len()))?,
            env: w.env.parse()?,
            subenv: w.subenv.parse()?,
            release: w.release.parse()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_oid_forms_agree() {
        let info = CellCertInfo {
            quote_sha256: [9; 32],
            env: "acme".parse().unwrap(),
            subenv: "bank-a".parse().unwrap(),
            release: "clovelly-0.1.0-test".parse().unwrap(),
        };
        assert_eq!(CellCertInfo::from_der(&info.to_der()).unwrap(), info);
        let arcs: Vec<u64> = OID.arcs().map(u64::from).collect();
        assert_eq!(arcs, OID_ARCS);
    }

    #[test]
    fn rejects_other_versions() {
        let wire = Wire {
            version: 2,
            quote_hash: OctetString::new(vec![0; 32]).unwrap(),
            env: "a".into(),
            subenv: "b".into(),
            release: "c".into(),
        };
        assert!(matches!(
            CellCertInfo::from_der(&wire.to_der().unwrap()),
            Err(CellCertError::Version(2))
        ));
    }
}
