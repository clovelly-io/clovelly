//! Our quote verification on a real GCE TDX quote (phase 0, run 20261026-063445) with
//! the collateral Intel PCS served for its platform on 2026-10-26.

use verifier::corpus::CollateralFile;
use verifier::qvl::{self, Collateral, QvlError, TcbStatus};

const QUOTE: &[u8] = include_bytes!("../../common/tests/data/gce-tdx-quote.bin");

fn collateral() -> Collateral {
    let f: CollateralFile =
        serde_json::from_str(include_str!("data/gce-collateral.json")).unwrap();
    (&f).into()
}

#[test]
fn a_genuine_gce_quote_verifies_to_intels_root() {
    let c = collateral();
    let v = qvl::verify_signatures(QUOTE, &c, verifier::INTEL_ROOT, c.fetched_at).unwrap();
    assert_eq!(common::hex(&v.pck.fmspc), "00806f050000");
    let t = qvl::tcb_status(&v).unwrap();
    println!("TCB status {} advisories {:?}", t.status, t.advisories);
    assert!(matches!(
        t.status,
        TcbStatus::UpToDate | TcbStatus::SWHardeningNeeded | TcbStatus::OutOfDate
    ));
}

#[test]
fn a_flipped_report_byte_breaks_the_quote_signature() {
    let c = collateral();
    let mut q = QUOTE.to_vec();
    q[48 + 520] ^= 1; // REPORTDATA
    assert_eq!(
        qvl::verify_signatures(&q, &c, verifier::INTEL_ROOT, c.fetched_at).unwrap_err(),
        QvlError::QuoteSignature
    );
}

#[test]
fn another_root_breaks_the_pck_chain() {
    let c = collateral();
    let err = qvl::verify_signatures(QUOTE, &c, verifier::GOOGLE_ROOT, c.fetched_at).unwrap_err();
    assert!(matches!(err, QvlError::PckChain(_)), "{err:?}");
}

#[test]
fn tampered_tcb_info_is_refused() {
    let mut c = collateral();
    c.tcb_info = c.tcb_info.replacen("UpToDate", "UpToDatf", 1);
    assert_eq!(
        qvl::verify_signatures(QUOTE, &c, verifier::INTEL_ROOT, c.fetched_at).unwrap_err(),
        QvlError::CollateralSignature("tcbInfo")
    );
}

#[test]
fn collateral_past_its_next_update_is_refused() {
    let c = collateral();
    let err = qvl::verify_signatures(QUOTE, &c, verifier::INTEL_ROOT, c.fetched_at + 40 * 86_400)
        .unwrap_err();
    assert!(matches!(err, QvlError::Collateral("tcbInfo", _)), "{err:?}");
}
