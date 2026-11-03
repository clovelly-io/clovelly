//! Google's signed launch endorsements for the GCE TDX firmware (SPEC.md decision 5).
//!
//! For each firmware build Google publishes a `VMLaunchEndorsement` at
//! `gs://gce_tcb_integrity/ovmf_x64_csm/tdx/<MRTD>.binarypb`: a serialized
//! `VMGoldenMeasurement` (the firmware digest and the MRTD for each RAM size it
//! supports) and an RSA-PSS SHA-256 signature by `GCE-uefi-signer`, whose certificate
//! is in the golden measurement and is signed by `GCE-cc-tcb-root`. [`verify`] checks
//! the whole chain against a pinned root and returns the endorsed MRTDs; the
//! verifier's check 5 then requires the quote's MRTD to be one of them.

use aws_lc_rs::signature::{self, UnparsedPublicKey};
use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use prost::Message;
use x509_cert::Certificate;

use crate::proto::endorsement::{VmGoldenMeasurement, VmLaunchEndorsement};
use crate::tdx::Measurement;

const RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

#[derive(Debug, thiserror::Error)]
pub enum EndorsementError {
    #[error("endorsement is not a VMLaunchEndorsement: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("certificate DER: {0}")]
    Der(#[from] der::Error),
    #[error("signer certificate is not issued by the pinned root")]
    WrongIssuer,
    #[error("signer certificate uses signature algorithm {0}, not RSASSA-PSS")]
    Algorithm(ObjectIdentifier),
    #[error("signer certificate signature does not verify under the pinned root")]
    CertSignature,
    #[error("signer certificate is not valid at {now} (valid {not_before}..{not_after})")]
    Expired {
        now: u64,
        not_before: u64,
        not_after: u64,
    },
    #[error("endorsement signature does not verify under the signer certificate")]
    Signature,
    #[error("endorsement has no TDX measurements")]
    NoTdx,
    #[error("endorsed MRTD is {0} bytes, expected 48")]
    MrtdLength(usize),
}

/// A verified golden measurement: what Google vouches for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Golden {
    /// SHA-384 of the firmware binary.
    pub firmware_digest: Vec<u8>,
    /// Google's security version number for this firmware on TDX.
    pub svn: u32,
    /// The MRTD for each launch configuration (RAM size, early accept).
    pub mrtds: Vec<Measurement>,
}

/// Verifies a serialized endorsement against `root` (DER, pinned by the caller) at
/// `now` (Unix seconds).
pub fn verify(serialized: &[u8], root: &[u8], now: u64) -> Result<Golden, EndorsementError> {
    let endorsement = VmLaunchEndorsement::decode(serialized)?;
    let golden = VmGoldenMeasurement::decode(endorsement.serialized_uefi_golden.as_slice())?;
    let root = Certificate::from_der(root)?;
    let signer = Certificate::from_der(&golden.cert)?;

    let tbs = signer.tbs_certificate();
    if tbs.issuer() != root.tbs_certificate().subject() {
        return Err(EndorsementError::WrongIssuer);
    }
    if signer.signature_algorithm().oid != RSASSA_PSS {
        return Err(EndorsementError::Algorithm(signer.signature_algorithm().oid));
    }
    let validity = tbs.validity();
    let (not_before, not_after) = (
        validity.not_before.to_unix_duration().as_secs(),
        validity.not_after.to_unix_duration().as_secs(),
    );
    if !(not_before..=not_after).contains(&now) {
        return Err(EndorsementError::Expired {
            now,
            not_before,
            not_after,
        });
    }
    // Google signs with RSASSA-PSS, SHA-256, MGF1-SHA-256 and a 32-byte salt (verified
    // against GCE-cc-tcb-root_1 and GCE-uefi-signer certificates).
    rsa_pss_sha256(&root, &tbs.to_der()?, signer.signature().raw_bytes())
        .map_err(|()| EndorsementError::CertSignature)?;
    rsa_pss_sha256(
        &signer,
        &endorsement.serialized_uefi_golden,
        &endorsement.signature,
    )
    .map_err(|()| EndorsementError::Signature)?;

    let tdx = golden.tdx.ok_or(EndorsementError::NoTdx)?;
    let mrtds = tdx
        .measurements
        .iter()
        .map(|m| {
            m.mrtd
                .as_slice()
                .try_into()
                .map(Measurement)
                .map_err(|_| EndorsementError::MrtdLength(m.mrtd.len()))
        })
        .collect::<Result<_, _>>()?;
    Ok(Golden {
        firmware_digest: golden.digest,
        svn: tdx.svn,
        mrtds,
    })
}

fn rsa_pss_sha256(key: &Certificate, message: &[u8], sig: &[u8]) -> Result<(), ()> {
    let spki = key.tbs_certificate().subject_public_key_info();
    let rsa_public_key = spki.subject_public_key.raw_bytes();
    UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA256, rsa_public_key)
        .verify(message, sig)
        .map_err(|_| ())
}
