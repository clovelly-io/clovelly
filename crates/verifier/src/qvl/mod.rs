//! TDX quote verification: our port of the parts of Intel's Quote Verification Library
//! the verifier uses. SPEC.md decision 4 names `dcap-qvl`, with this port as the
//! fallback if its licence fails the allowlist; it does, through `parity-scale-codec`'s
//! `const_format` (Zlib), so the verifier carries its own (BLOCKERS.md).
//!
//! Two stages, one per check:
//! - [`verify_signatures`] (check 1): the quote signature by the attestation key, the
//!   QE report signature by the PCK key and its binding of the attestation key, the
//!   PCK chain to the trust root, and the signed TCB info and QE identity.
//! - [`tcb_status`] (check 3): the QE against its identity and TCB levels, the
//!   platform and TDX module against the TCB info, merged into one status.
//!
//! Revocation and CRL freshness are check 2, in the verifier.

pub mod chain;
pub mod collateral;
mod pck;
pub mod quote;

use aws_lc_rs::digest;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use der::Decode;
use x509_cert::Certificate;

pub use chain::ChainError;
pub use collateral::{Collateral, QeIdentity, TcbInfo, TcbStatus, rfc3339};
pub use pck::PckInfo;
use quote::{QeReport, SignedQuote, TdFields};

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum QvlError {
    #[error("quote format: {0}")]
    Format(&'static str),
    #[error("quote version {0} is not 4 or 5")]
    Version(u16),
    #[error("attestation key type {0} is not ECDSA P-256")]
    AttestationKeyType(u16),
    #[error("PCK certificate extension: {0}")]
    PckExtension(&'static str),
    #[error("PCK chain: {0}")]
    PckChain(ChainError),
    #[error("QE report signature does not verify under the PCK key")]
    QeReportSignature,
    #[error("QE report does not bind the attestation key")]
    QeReportData,
    #[error("quote signature does not verify under the attestation key")]
    QuoteSignature,
    #[error("{0} issuer chain: {1}")]
    CollateralChain(&'static str, ChainError),
    #[error("{0} signature does not verify")]
    CollateralSignature(&'static str),
    #[error("{0}: {1}")]
    Collateral(&'static str, String),
}

/// Why the TCB could not be evaluated (check 3).
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum TcbError {
    #[error("QE does not match its identity: {0}")]
    QeIdentity(&'static str),
    #[error("QE ISVSVN {0} is below every QE TCB level")]
    NoQeLevel(u16),
    #[error("no TCB level matches the platform")]
    NoTcbLevel,
    #[error("TDX module: {0}")]
    Module(String),
    #[error("{0} carries status {1}, which Intel does not allow there")]
    Status(&'static str, TcbStatus),
}

/// A quote whose signatures and collateral all verified.
#[derive(Debug, Clone)]
pub struct Verified {
    pub pck: PckInfo,
    pub td: TdFields,
    pub qe_report: QeReport,
    pub tcb_info: TcbInfo,
    pub qe_identity: QeIdentity,
}

/// The appraised TCB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcbVerdict {
    pub status: TcbStatus,
    pub advisories: Vec<String>,
}

fn verify_raw(key_xy: &[u8], message: &[u8], sig: &[u8; 64]) -> bool {
    let mut point = Vec::with_capacity(65);
    point.push(4);
    point.extend_from_slice(key_xy);
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
        .verify(message, sig)
        .is_ok()
}

fn verify_by_cert(cert: &Certificate, message: &[u8], sig: &[u8; 64]) -> bool {
    let point = cert
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
        .verify(message, sig)
        .is_ok()
}

/// Check that a signed collateral document verifies under its chain and is current.
fn signed_document<'a>(
    response: &'a str,
    field: &'static str,
    chain_der: &[Vec<u8>],
    root: &[u8],
    now: u64,
) -> Result<&'a str, QvlError> {
    let doc = collateral::split(response, field)?;
    let certs = chain::verify(chain_der, root, now).map_err(|e| QvlError::CollateralChain(field, e))?;
    if !verify_by_cert(&certs[0], doc.body.as_bytes(), &doc.signature) {
        return Err(QvlError::CollateralSignature(field));
    }
    Ok(doc.body)
}

fn current(field: &'static str, issue: &str, next: &str, now: u64) -> Result<(), QvlError> {
    let (Some(issue), Some(next)) = (rfc3339(issue), rfc3339(next)) else {
        return Err(QvlError::Collateral(field, "bad issueDate or nextUpdate".into()));
    };
    if (issue..=next).contains(&now) {
        Ok(())
    } else {
        Err(QvlError::Collateral(
            field,
            format!("not current at {now} (issued {issue}, next update {next})"),
        ))
    }
}

/// Check 1: every signature from the quote up to `root` (DER), at `now`.
pub fn verify_signatures(
    raw: &[u8],
    c: &Collateral,
    root: &[u8],
    now: u64,
) -> Result<Verified, QvlError> {
    let q = SignedQuote::parse(raw)?;
    let pck_chain = chain::verify(&q.pck_chain, root, now).map_err(QvlError::PckChain)?;
    let leaf = &pck_chain[0];
    // As PckCertVerifier: the PCK and its issuing CA are named as Intel names them.
    let cn = |c: &Certificate| c.tbs_certificate().subject().to_string();
    if !cn(leaf).contains("SGX PCK Certificate")
        || !pck_chain.get(1).is_some_and(|ca| cn(ca).contains("CA"))
    {
        return Err(QvlError::Format("PCK chain is not an SGX PCK certificate and CA"));
    }
    if !verify_by_cert(leaf, &q.qe_report.raw, &q.qe_report_signature) {
        return Err(QvlError::QeReportSignature);
    }
    let mut bound = digest::Context::new(&digest::SHA256);
    bound.update(&q.attestation_key);
    bound.update(q.qe_auth_data);
    if q.qe_report.report_data[..32] != *bound.finish().as_ref()
        || q.qe_report.report_data[32..].iter().any(|&b| b != 0)
    {
        return Err(QvlError::QeReportData);
    }
    if !verify_raw(&q.attestation_key, q.signed, &q.signature) {
        return Err(QvlError::QuoteSignature);
    }
    let pck = PckInfo::of(leaf)?;

    let body = signed_document(&c.tcb_info, "tcbInfo", &c.tcb_info_chain, root, now)?;
    let tcb_info: TcbInfo = serde_json::from_str(body)
        .map_err(|e| QvlError::Collateral("tcbInfo", e.to_string()))?;
    if tcb_info.id != "TDX" || tcb_info.version < 3 {
        return Err(QvlError::Collateral("tcbInfo", "not TDX TCB info v3".into()));
    }
    current("tcbInfo", &tcb_info.issue_date, &tcb_info.next_update, now)?;
    if !tcb_info.fmspc.eq_ignore_ascii_case(&common::hex(&pck.fmspc))
        || !tcb_info.pce_id.eq_ignore_ascii_case(&common::hex(&pck.pce_id))
    {
        return Err(QvlError::Collateral("tcbInfo", "FMSPC or PCE id differs from the PCK's".into()));
    }

    let body = signed_document(&c.qe_identity, "enclaveIdentity", &c.qe_identity_chain, root, now)?;
    let qe_identity: QeIdentity = serde_json::from_str(body)
        .map_err(|e| QvlError::Collateral("enclaveIdentity", e.to_string()))?;
    if qe_identity.id != "TD_QE" {
        return Err(QvlError::Collateral("enclaveIdentity", "not the TD QE identity".into()));
    }
    current("enclaveIdentity", &qe_identity.issue_date, &qe_identity.next_update, now)?;

    Ok(Verified {
        pck,
        td: q.td,
        qe_report: q.qe_report,
        tcb_info,
        qe_identity,
    })
}

fn hex_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    common::unhex(s)?.try_into().ok()
}

/// Check 3: the QE, the platform and the TDX module against Intel's TCB data, as
/// Intel QVL's `checkTcbLevel` and `tdxEvaluateTCB`: the TDX module's identity first,
/// then the launch TCB (and for a TD 1.5 the current TCB), each converged with the
/// module's and the QE's statuses, then the relaunch rule.
pub fn tcb_status(v: &Verified) -> Result<TcbVerdict, TcbError> {
    module_identity(v)?;
    qe_identity(&v.qe_report, &v.qe_identity)?;
    let launch = evaluate(v, &v.td.tee_tcb_svn)?;
    let Some(svn2) = v.td.tee_tcb_svn2 else {
        return Ok(launch);
    };
    let current = evaluate(v, &svn2)?;
    Ok(TcbVerdict {
        status: launch.status.relaunch(current.status),
        advisories: launch.advisories,
    })
}

/// The TDX module identity for the quote's module version (`TEE_TCB_SVN[1]`), or
/// `None` for version 0, which `tdxModule` describes.
fn module_for(v: &Verified, version: u8) -> Result<Option<&collateral::TdxModuleIdentity>, TcbError> {
    if version == 0 {
        return Ok(None);
    }
    let want = format!("TDX_{version:02X}");
    v.tcb_info
        .tdx_module_identities
        .iter()
        .find(|i| i.id.eq_ignore_ascii_case(&want))
        .map(Some)
        .ok_or_else(|| TcbError::Module(format!("no identity {want}")))
}

/// QuoteVerifier 4.1.2.5.12: MRSIGNERSEAM equals the module's signer, and every
/// SEAMATTRIBUTES byte is zero and equal to the module's attributes (Intel applies no
/// mask here).
fn module_identity(v: &Verified) -> Result<(), TcbError> {
    let module = |e: &str| TcbError::Module(e.to_owned());
    let (mrsigner, attrs) = match module_for(v, v.td.tee_tcb_svn[1])? {
        Some(id) => (&id.mrsigner, &id.attributes),
        None => {
            let m = v.tcb_info.tdx_module.as_ref().ok_or_else(|| module("TCB info has no tdxModule"))?;
            (&m.mrsigner, &m.attributes)
        }
    };
    let mrsigner: [u8; 48] = hex_array(mrsigner).ok_or_else(|| module("mrsigner"))?;
    let attrs: [u8; 8] = hex_array(attrs).ok_or_else(|| module("attributes"))?;
    if v.td.mr_signer_seam != mrsigner {
        return Err(module("MRSIGNERSEAM differs from Intel's"));
    }
    if v.td.seam_attributes.iter().zip(&attrs).any(|(&q, &t)| q != 0 || q != t) {
        return Err(module("SEAMATTRIBUTES are not zero and equal to Intel's"));
    }
    Ok(())
}

/// EnclaveReportVerifier 4.1.2.9.5-8: the QE report's masked MISCSELECT and
/// ATTRIBUTES equal the identity's values, MRSIGNER (when given) and ISVPRODID match.
fn qe_identity(r: &QeReport, id: &QeIdentity) -> Result<(), TcbError> {
    let (misc, misc_mask): ([u8; 4], [u8; 4]) = (
        hex_array(&id.miscselect).ok_or(TcbError::QeIdentity("miscselect"))?,
        hex_array(&id.miscselect_mask).ok_or(TcbError::QeIdentity("miscselectMask"))?,
    );
    let ours = r.misc_select.to_le_bytes();
    if ours.iter().zip(&misc_mask).map(|(a, m)| a & m).ne(misc) {
        return Err(TcbError::QeIdentity("MISCSELECT"));
    }
    let (attrs, attrs_mask): ([u8; 16], [u8; 16]) = (
        hex_array(&id.attributes).ok_or(TcbError::QeIdentity("attributes"))?,
        hex_array(&id.attributes_mask).ok_or(TcbError::QeIdentity("attributesMask"))?,
    );
    if r.attributes.iter().zip(&attrs_mask).map(|(a, m)| a & m).ne(attrs) {
        return Err(TcbError::QeIdentity("ATTRIBUTES"));
    }
    if !id.mrsigner.is_empty() {
        let mrsigner: [u8; 32] = hex_array(&id.mrsigner).ok_or(TcbError::QeIdentity("mrsigner"))?;
        if r.mr_signer != mrsigner {
            return Err(TcbError::QeIdentity("MRSIGNER"));
        }
    }
    if r.isv_prod_id != id.isvprodid {
        return Err(TcbError::QeIdentity("ISVPRODID"));
    }
    Ok(())
}

/// Every SVN from `start` on is at least the level's (`areSvnsHigherOrEqual`).
fn svns_at_least(ours: &[u8; 16], level: &[collateral::Svn], start: usize) -> Result<bool, TcbError> {
    if level.len() != 16 {
        return Err(TcbError::NoTcbLevel);
    }
    Ok(ours.iter().zip(level).skip(start).all(|(a, l)| *a >= l.svn))
}

/// `tdxEvaluateTCB` for one TEE_TCB_SVN: the first platform TCB level met (SGX
/// components, PCESVN, then TDX components, skipping the module's own two when its
/// version is non-zero), converged with the TDX module's level and the QE's level.
/// Advisories are the platform's, then the QE's, then the module's.
fn evaluate(v: &Verified, tee_tcb_svn: &[u8; 16]) -> Result<TcbVerdict, TcbError> {
    use TcbStatus::*;
    let start = if tee_tcb_svn[1] > 0 { 2 } else { 0 };
    let mut platform = None;
    for l in &v.tcb_info.tcb_levels {
        if svns_at_least(&v.pck.components, &l.tcb.sgxtcbcomponents, 0)?
            && v.pck.pce_svn >= l.tcb.pcesvn
            && svns_at_least(tee_tcb_svn, &l.tcb.tdxtcbcomponents, start)?
        {
            platform = Some(l);
            break;
        }
    }
    let platform = platform.ok_or(TcbError::NoTcbLevel)?;
    let tcb_info_statuses = [
        UpToDate,
        OutOfDate,
        ConfigurationNeeded,
        Revoked,
        OutOfDateConfigurationNeeded,
        SWHardeningNeeded,
        ConfigurationAndSWHardeningNeeded,
    ];
    if !tcb_info_statuses.contains(&platform.tcb_status) {
        return Err(TcbError::Status("TCB info", platform.tcb_status));
    }

    let mut components = Vec::new();
    let mut module_advisories = Vec::new();
    if let Some(id) = module_for(v, tee_tcb_svn[1])? {
        let l = id
            .tcb_levels
            .iter()
            .find(|l| u16::from(tee_tcb_svn[0]) >= l.tcb.isvsvn)
            .ok_or_else(|| TcbError::Module("module ISVSVN below every level".into()))?;
        if ![UpToDate, OutOfDate, Revoked].contains(&l.tcb_status) {
            return Err(TcbError::Status("TDX module identity", l.tcb_status));
        }
        components.push(l.tcb_status);
        module_advisories = l.advisory_ids.clone();
    }
    let qe = v
        .qe_identity
        .tcb_levels
        .iter()
        .find(|l| v.qe_report.isv_svn >= l.tcb.isvsvn)
        .ok_or(TcbError::NoQeLevel(v.qe_report.isv_svn))?;
    if ![UpToDate, OutOfDate, ConfigurationNeeded, Revoked, OutOfDateConfigurationNeeded].contains(&qe.tcb_status) {
        return Err(TcbError::Status("QE identity", qe.tcb_status));
    }
    components.push(qe.tcb_status);

    let status = components.iter().fold(platform.tcb_status, |s, &c| s.converge(c));
    let mut advisories = platform.advisory_ids.clone();
    advisories.extend(qe.advisory_ids.iter().cloned());
    advisories.extend(module_advisories);
    Ok(TcbVerdict { status, advisories })
}

/// The PCK leaf and its issuing CA from a quote, for check 2's revocation lookup.
pub fn pck_certificates(raw: &[u8]) -> Result<(Certificate, Certificate), QvlError> {
    let q = SignedQuote::parse(raw)?;
    let [leaf, ca, ..] = q.pck_chain.as_slice() else {
        return Err(QvlError::Format("PCK chain has fewer than two certificates"));
    };
    let parse = |d: &[u8]| {
        Certificate::from_der(d).map_err(|e| QvlError::PckChain(ChainError::Der(e.to_string())))
    };
    Ok((parse(leaf)?, parse(ca)?))
}
