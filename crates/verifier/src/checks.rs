//! The ten unlock checks (SPEC.md, "The verifier") and the report of one evaluation.
//!
//! Every check is evaluated and recorded, so a test can show that evidence fails one
//! check and no other. A check whose input comes from a failed check is recorded as
//! skipped, not failed: chain verification (check 1) needs usable CRLs (check 2), TCB
//! status (3) needs the verified quote (1), and so on. The verifier refuses with the
//! lowest-numbered failure.

use std::collections::BTreeMap;
use std::fmt;

use common::ids::{ReleaseId, Zone};
use common::tdx::Measurement;

use crate::nonce::NonceFailure;
use crate::qvl::{QvlError, TcbError};

/// One unlock check, numbered as in SPEC.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Check {
    /// 1: the quote parses and its signature chain verifies to the trust root.
    Quote = 1,
    /// 2: the PCK and root CA CRLs are fresh and do not revoke the chain.
    Collateral = 2,
    /// 3: the TCB status is acceptable and the QE identity matches.
    Tcb = 3,
    /// 4: DEBUG is off; XFAM, MRSEAM and TEE_TCB_SVN meet the policy.
    Attributes = 4,
    /// 5: Google's signed endorsement lists the MRTD.
    Firmware = 5,
    /// 6: the CCEL replays to the quote and the RTMRs equal the release's.
    Measurements = 6,
    /// 7: MR_OWNER names our project and an allowed zone; the PPID is a Google host.
    Owner = 7,
    /// 8: REPORTDATA binds the environment, the cell key and a nonce we issued.
    Binding = 8,
    /// 9: the release is known and past its notice window or, on a pinned verifier,
    /// pinned.
    Window = 9,
    /// 10: the release has not passed `valid_until`.
    Expiry = 10,
}

impl Check {
    pub const ALL: [Check; 10] = [
        Check::Quote,
        Check::Collateral,
        Check::Tcb,
        Check::Attributes,
        Check::Firmware,
        Check::Measurements,
        Check::Owner,
        Check::Binding,
        Check::Window,
        Check::Expiry,
    ];

    pub fn number(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "check {}", self.number())
    }
}

/// Why a check failed. Logged by the verifier; the cell only learns the number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    QuoteParse(String),
    Signatures(QvlError),
    CollateralStale { fetched_at: u64, now: u64 },
    CrlNotCurrent { crl: &'static str, this_update: u64, next_update: Option<u64>, now: u64 },
    PckRevoked { serial: String },
    PckCaRevoked { serial: String },
    CollateralUnusable(String),
    TcbStatus { status: String, advisories: Vec<String> },
    TcbEvaluation(TcbError),
    Debug,
    Xfam { quoted: u64, policy: u64 },
    MrSeam(Measurement),
    TeeTcbSvn { quoted: [u8; 16], floor: [u8; 16] },
    NoEndorsement(Measurement),
    Endorsement(String),
    MrtdNotEndorsed(Measurement),
    CcelReplay(String),
    /// RTMR indexes (0..=3) that differ from the release's published values.
    RtmrMismatch(Vec<usize>),
    ZoneNotAllowed(Zone),
    MrOwner { quoted: Measurement, expected: Measurement },
    PpidNotRegistered(String),
    ReportData,
    Nonce(NonceFailure),
    UnknownRelease(ReleaseId),
    NoticeWindow { open_at: u64, now: u64 },
    /// The verifier is pinned, and not to this release.
    NotPinned(ReleaseId),
    ReleaseExpired { valid_until: u64, now: u64 },
}

/// The outcome of one check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    Fail(Failure),
    /// Not evaluated because the named check, which it depends on, failed.
    Skipped(Check),
}

/// Every check's outcome for one piece of evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    outcomes: BTreeMap<Check, Outcome>,
}

impl Report {
    pub(crate) fn set(&mut self, check: Check, outcome: Outcome) {
        self.outcomes.insert(check, outcome);
    }

    pub(crate) fn fail(&mut self, check: Check, failure: Failure) {
        self.set(check, Outcome::Fail(failure));
    }

    pub fn outcome(&self, check: Check) -> Option<&Outcome> {
        self.outcomes.get(&check)
    }

    /// The checks that failed, in order.
    pub fn failed(&self) -> Vec<Check> {
        self.outcomes
            .iter()
            .filter(|(_, o)| matches!(o, Outcome::Fail(_)))
            .map(|(c, _)| *c)
            .collect()
    }

    /// The lowest-numbered failure: what the verifier refuses with.
    pub fn first_failure(&self) -> Option<(Check, &Failure)> {
        self.outcomes.iter().find_map(|(c, o)| match o {
            Outcome::Fail(f) => Some((*c, f)),
            _ => None,
        })
    }

    /// True when all ten checks passed.
    pub fn accepted(&self) -> bool {
        Check::ALL
            .iter()
            .all(|c| self.outcomes.get(c) == Some(&Outcome::Pass))
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in Check::ALL {
            let o = match self.outcomes.get(&c) {
                Some(Outcome::Pass) => "pass".to_owned(),
                Some(Outcome::Fail(why)) => format!("FAIL {why:?}"),
                Some(Outcome::Skipped(on)) => format!("skipped ({on} failed)"),
                None => "not run".to_owned(),
            };
            writeln!(f, "  {c:>8}: {o}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_failure_is_the_lowest_number() {
        let mut r = Report::default();
        for c in Check::ALL {
            r.set(c, Outcome::Pass);
        }
        assert!(r.accepted());
        r.fail(Check::Window, Failure::UnknownRelease("x".parse().unwrap()));
        r.fail(Check::Firmware, Failure::Debug);
        r.set(Check::Measurements, Outcome::Skipped(Check::Window));
        assert!(!r.accepted());
        assert_eq!(r.failed(), vec![Check::Firmware, Check::Window]);
        assert_eq!(r.first_failure().map(|(c, _)| c), Some(Check::Firmware));
    }
}
