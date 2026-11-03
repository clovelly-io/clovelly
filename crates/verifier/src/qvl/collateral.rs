//! Intel's collateral for a TDX platform, as Intel PCS serves it (API v4): signed TCB
//! info and QE identity JSON with their issuer chains, and the PCK and root CA CRLs.
//!
//! The raw response bodies are kept so the exact signed bytes are verified and the
//! corpus can store what PCS returned.

use serde::Deserialize;
use serde_json::value::RawValue;

use super::QvlError;

/// Everything quote verification needs besides the quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collateral {
    /// `GET /tdx/certification/v4/tcb?fmspc=…` body.
    pub tcb_info: String,
    /// Its `TCB-Info-Issuer-Chain` header, DER certificates.
    pub tcb_info_chain: Vec<Vec<u8>>,
    /// `GET /tdx/certification/v4/qe/identity` body.
    pub qe_identity: String,
    /// Its `SGX-Enclave-Identity-Issuer-Chain` header, DER certificates.
    pub qe_identity_chain: Vec<Vec<u8>>,
    /// `GET /sgx/certification/v4/pckcrl?ca=…&encoding=der` body.
    pub pck_crl: Vec<u8>,
    /// The root CA's CRL, from its distribution point.
    pub root_ca_crl: Vec<u8>,
    /// When it was fetched (Unix seconds): check 2 wants it under an hour old.
    pub fetched_at: u64,
}

/// A signed JSON document split into the exact signed bytes and the signature.
pub(super) struct Signed<'a> {
    pub body: &'a str,
    pub signature: [u8; 64],
}

pub(super) fn split<'a>(response: &'a str, field: &'static str) -> Result<Signed<'a>, QvlError> {
    #[derive(Deserialize)]
    struct Envelope<'a> {
        #[serde(borrow, rename = "tcbInfo")]
        tcb_info: Option<&'a RawValue>,
        #[serde(borrow, rename = "enclaveIdentity")]
        enclave_identity: Option<&'a RawValue>,
        signature: String,
    }
    let e: Envelope<'a> =
        serde_json::from_str(response).map_err(|_| QvlError::Collateral(field, "not JSON".into()))?;
    let body = match field {
        "tcbInfo" => e.tcb_info,
        _ => e.enclave_identity,
    }
    .ok_or_else(|| QvlError::Collateral(field, "missing".into()))?;
    let signature = common::unhex(&e.signature)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| QvlError::Collateral(field, "signature is not 64 bytes of hex".into()))?;
    Ok(Signed {
        body: body.get(),
        signature,
    })
}

/// A TCB status as Intel publishes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum TcbStatus {
    UpToDate,
    SWHardeningNeeded,
    ConfigurationNeeded,
    ConfigurationAndSWHardeningNeeded,
    OutOfDate,
    OutOfDateConfigurationNeeded,
    Revoked,
    /// Only from TD 1.5 relaunch evaluation.
    TDRelaunchAdvised,
    TDRelaunchAdvisedConfigurationNeeded,
}

impl TcbStatus {
    /// Intel QVL's `convergeTcbStatuses` for one component (TDX module or QE): an
    /// out-of-date component makes an up-to-date or SW-hardening platform out of date
    /// and a configuration-needed one out-of-date-configuration-needed; a revoked one
    /// makes it revoked. Folding components one at a time gives Intel's result.
    pub fn converge(self, component: TcbStatus) -> TcbStatus {
        use TcbStatus::*;
        match (component, self) {
            (Revoked, _) => Revoked,
            (OutOfDate, UpToDate | SWHardeningNeeded) => OutOfDate,
            (OutOfDate, ConfigurationNeeded | ConfigurationAndSWHardeningNeeded) => {
                OutOfDateConfigurationNeeded
            }
            _ => self,
        }
    }

    /// Intel QVL's `checkForRelaunch`: a TD 1.5 whose launch TCB is out of date but
    /// whose current TCB is not should be relaunched.
    pub fn relaunch(self, current: TcbStatus) -> TcbStatus {
        use TcbStatus::*;
        let config = |s| {
            matches!(
                s,
                ConfigurationNeeded
                    | OutOfDateConfigurationNeeded
                    | ConfigurationAndSWHardeningNeeded
                    | TDRelaunchAdvisedConfigurationNeeded
            )
        };
        match (self, current) {
            (
                OutOfDate | OutOfDateConfigurationNeeded,
                UpToDate | SWHardeningNeeded | ConfigurationNeeded | ConfigurationAndSWHardeningNeeded,
            ) => {
                if config(self) || config(current) {
                    TDRelaunchAdvisedConfigurationNeeded
                } else {
                    TDRelaunchAdvised
                }
            }
            _ => self,
        }
    }
}

impl std::fmt::Display for TcbStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Svn {
    pub svn: u8,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PlatformTcb {
    pub sgxtcbcomponents: Vec<Svn>,
    pub pcesvn: u16,
    #[serde(default)]
    pub tdxtcbcomponents: Vec<Svn>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevel {
    pub tcb: PlatformTcb,
    pub tcb_date: String,
    pub tcb_status: TcbStatus,
    #[serde(default, rename = "advisoryIDs")]
    pub advisory_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IsvSvn {
    pub isvsvn: u16,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IsvTcbLevel {
    pub tcb: IsvSvn,
    pub tcb_date: String,
    pub tcb_status: TcbStatus,
    #[serde(default, rename = "advisoryIDs")]
    pub advisory_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxModule {
    pub mrsigner: String,
    pub attributes: String,
    pub attributes_mask: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxModuleIdentity {
    pub id: String,
    pub mrsigner: String,
    pub attributes: String,
    pub attributes_mask: String,
    pub tcb_levels: Vec<IsvTcbLevel>,
}

/// TDX TCB info (version 3).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfo {
    pub id: String,
    pub version: u32,
    pub issue_date: String,
    pub next_update: String,
    pub fmspc: String,
    pub pce_id: String,
    pub tcb_evaluation_data_number: u32,
    pub tdx_module: Option<TdxModule>,
    #[serde(default)]
    pub tdx_module_identities: Vec<TdxModuleIdentity>,
    pub tcb_levels: Vec<TcbLevel>,
}

/// The TD quoting enclave's identity (version 2).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QeIdentity {
    pub id: String,
    pub version: u32,
    pub issue_date: String,
    pub next_update: String,
    pub tcb_evaluation_data_number: u32,
    pub miscselect: String,
    pub miscselect_mask: String,
    pub attributes: String,
    pub attributes_mask: String,
    pub mrsigner: String,
    pub isvprodid: u16,
    pub tcb_levels: Vec<IsvTcbLevel>,
}

/// Seconds since the epoch for an RFC 3339 UTC time as Intel writes it
/// (`2026-10-25T12:34:56Z`, optionally with fractional seconds).
pub fn rfc3339(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || !s.ends_with('Z') {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, m, d) = (n(0..4)?, n(5..7)?, n(8..10)?);
    let (hh, mm, ss) = (n(11..13)?, n(14..16)?, n(17..19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // Days from civil (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + hh * 3600 + mm * 60 + ss).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_matches_known_times() {
        assert_eq!(rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(rfc3339("2000-03-01T00:00:00Z"), Some(951_868_800));
        assert_eq!(rfc3339("2026-10-26T12:00:00.123Z"), Some(1_793_016_000));
        assert_eq!(rfc3339("2026-13-01T00:00:00Z"), None);
        assert_eq!(rfc3339("2026-10-26 12:00:00"), None);
    }

    #[test]
    fn statuses_converge_like_intel_qvl() {
        use TcbStatus::*;
        assert_eq!(UpToDate.converge(OutOfDate), OutOfDate);
        assert_eq!(ConfigurationNeeded.converge(OutOfDate), OutOfDateConfigurationNeeded);
        assert_eq!(SWHardeningNeeded.converge(UpToDate), SWHardeningNeeded);
        assert_eq!(UpToDate.converge(Revoked), Revoked);
        assert_eq!(OutOfDate.relaunch(UpToDate), TDRelaunchAdvised);
        assert_eq!(UpToDate.relaunch(OutOfDate), UpToDate);
    }

    #[test]
    fn split_keeps_the_exact_signed_bytes() {
        let sig = "ab".repeat(64);
        let body = format!(r#"{{"tcbInfo":{{"id":"TDX", "x" :1}},"signature":"{sig}"}}"#);
        let s = split(&body, "tcbInfo").unwrap();
        assert_eq!(s.body, r#"{"id":"TDX", "x" :1}"#);
        assert_eq!(s.signature, [0xab; 64]);
    }
}
