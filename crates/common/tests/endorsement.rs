//! Verifies Google's real launch endorsement for the GCE TDX firmware the phase 0 and
//! phase 1 cells booted on (MRTD c1ee9c16…), fetched from gce_tcb_integrity.

use common::endorsement::{self, EndorsementError};
use common::tdx::Measurement;

const ENDORSEMENT: &[u8] = include_bytes!("data/gce-tdx-endorsement.binarypb");
const ROOT: &[u8] = include_bytes!("../../verifier/roots/GCE-cc-tcb-root_1.crt");
const MRTD: &str = "c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5";
/// 2026-10-26, inside the signer certificate's validity.
const NOW: u64 = 1_793_000_000;

#[test]
fn google_endorses_the_cells_mrtd() {
    let golden = endorsement::verify(ENDORSEMENT, ROOT, NOW).unwrap();
    assert!(golden.mrtds.contains(&MRTD.parse::<Measurement>().unwrap()));
    assert_eq!(golden.firmware_digest.len(), 48);
}

#[test]
fn a_flipped_byte_breaks_the_signature() {
    let mut tampered = ENDORSEMENT.to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 1; // inside the signature, the last field
    assert!(matches!(
        endorsement::verify(&tampered, ROOT, NOW),
        Err(EndorsementError::Signature)
    ));
}

#[test]
fn another_root_is_refused() {
    let intel = include_bytes!("../../verifier/roots/Intel_SGX_RootCA.der");
    assert!(matches!(
        endorsement::verify(ENDORSEMENT, intel, NOW),
        Err(EndorsementError::WrongIssuer)
    ));
}

#[test]
fn an_expired_signer_is_refused() {
    assert!(matches!(
        endorsement::verify(ENDORSEMENT, ROOT, 2_000_000_000),
        Err(EndorsementError::Expired { .. })
    ));
}
