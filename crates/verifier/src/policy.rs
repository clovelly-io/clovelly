//! The release policy: what the verifier accepts, as data (SPEC.md "Policy as data").
//!
//! We publish it as a JWS signed by a release key; the verifier trusts the keys in its
//! configuration and nothing else. From phase 5 releases also arrive one at a time as
//! policy fragments with a Rekor inclusion proof ([`crate::fragments`]); the verifier
//! adds each verified fragment's release to the signed policy's own
//! ([`ReleasePolicy::with_fragments`]).
//!
//! ```json
//! { "v": 1, "project_number": 123456789012, "allowed_zones": ["us-central1-a"],
//!   "xfam": 393959, "mrseam": ["…"], "tee_tcb_svn_floor": "…32 hex…",
//!   "sw_hardening_advisories": [], "nonce_ttl_secs": 300,
//!   "endorsements_url": "https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm/tdx/",
//!   "releases": [{ "id": "clovelly-0.1.0-prod", "rtmr": ["…", "…", "…", "…"],
//!                  "rtmr0_firmware": ["…"],
//!                  "published_at": 1793000000, "notice_secs": 259200,
//!                  "valid_until": 1795592000 }] }
//! ```
//! Times are Unix seconds. `rtmr0_firmware` (optional) lists further RTMR0 values for
//! the same release, each recorded from a canary on other host firmware the release
//! runs on while Google rolls firmware across zones (phase 4 finding: us-central1-a and
//! -b reported different RTMR0 for one image and cell shape). `mrtd` (optional) lists
//! the MRTD of each of those firmwares, for the measurement set receipts are checked
//! against; check 5 takes MRTDs from Google's endorsements, not from here.

use common::ids::{ReleaseId, Zone};
use common::receipt::{MeasurementSet, ReleaseMeasurements};
use common::release::Supersession;
use common::tdx::Measurement;
use serde::Deserialize;

use crate::fragments::Applied;
use crate::jws::{self, JwsError, TrustedKey};

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("release policy signature: {0}")]
    Jws(#[from] JwsError),
    #[error("release policy JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("release policy version {0} is not 1")]
    Version(u32),
    #[error("tee_tcb_svn_floor is not 32 hex digits")]
    SvnFloor,
}

/// A verified release policy.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePolicy {
    pub v: u32,
    /// Our GCP project number, which MR_OWNER must name (check 7).
    pub project_number: u64,
    pub allowed_zones: Vec<Zone>,
    /// TD XFAM, exact (check 4).
    pub xfam: u64,
    /// Accepted TDX module measurements (check 4).
    pub mrseam: Vec<Measurement>,
    /// Minimum TEE_TCB_SVN, compared byte by byte (check 4).
    #[serde(deserialize_with = "svn_floor")]
    pub tee_tcb_svn_floor: [u8; 16],
    /// Advisories accepted when the TCB status is `SWHardeningNeeded` (check 3).
    pub sw_hardening_advisories: Vec<String>,
    pub nonce_ttl_secs: u64,
    /// Where Google's endorsements are fetched, by MRTD (check 5).
    pub endorsements_url: String,
    pub releases: Vec<Release>,
}

/// One cell-image release and its measurements.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub id: ReleaseId,
    /// RTMR0..3: RTMR0 and RTMR3 recorded from a canary cell, RTMR1 and RTMR2
    /// predicted from the image and confirmed by the canary.
    pub rtmr: [Measurement; 4],
    /// More RTMR0 values for this release, each canary-recorded on other host firmware.
    #[serde(default)]
    pub rtmr0_firmware: Vec<Measurement>,
    /// The MRTD of each host firmware the release's RTMR0 values were recorded on.
    #[serde(default)]
    pub mrtd: Vec<Measurement>,
    /// Unix seconds: for a fragment's release, when Rekor integrated its entry.
    pub published_at: u64,
    /// Accepted once `published_at + notice_secs` has passed, unless pinned (check 9).
    pub notice_secs: u64,
    /// Refused from this time on, pinned or not (check 10).
    pub valid_until: u64,
}

impl Release {
    /// Whether `rtmr0` is one this release published: its canary's, or one recorded on
    /// other firmware.
    pub fn accepts_rtmr0(&self, rtmr0: &Measurement) -> bool {
        *rtmr0 == self.rtmr[0] || self.rtmr0_firmware.contains(rtmr0)
    }

    /// When the notice window ends.
    pub fn open_at(&self) -> u64 {
        self.published_at.saturating_add(self.notice_secs)
    }
}

impl ReleasePolicy {
    /// Verifies `jws` under `keys` and parses its payload.
    pub fn from_jws(jws: &str, keys: &[TrustedKey]) -> Result<Self, PolicyError> {
        let policy: Self = serde_json::from_slice(&jws::verify(jws, keys)?)?;
        if policy.v != 1 {
            return Err(PolicyError::Version(policy.v));
        }
        Ok(policy)
    }

    pub fn release(&self, id: &ReleaseId) -> Option<&Release> {
        self.releases.iter().find(|r| &r.id == id)
    }

    /// This policy with each applied fragment's release added (a release this policy or
    /// an earlier fragment already names is left as it is), then every supersession
    /// applied: a superseded release's `valid_until` only ever goes down.
    pub fn with_fragments(&self, applied: &[Applied]) -> Self {
        let mut p = self.clone();
        for a in applied {
            if p.release(&a.release.id).is_none() {
                p.releases.push(a.release.clone());
            }
        }
        for Supersession { release, valid_until } in applied.iter().flat_map(|a| &a.supersedes) {
            if let Some(r) = p.releases.iter_mut().find(|r| &r.id == release) {
                r.valid_until = r.valid_until.min(*valid_until);
            }
        }
        p
    }

    /// The published measurement set receipts are verified against: each release's
    /// RTMRs and, where the release lists them, its firmwares' MRTDs (a release that
    /// lists none leaves a receipt's MRTD unchecked: check 5 took it from Google's
    /// endorsements at unlock).
    pub fn measurement_set(&self) -> MeasurementSet {
        MeasurementSet {
            releases: self
                .releases
                .iter()
                .map(|r| ReleaseMeasurements {
                    id: r.id.to_string(),
                    rtmr: r.rtmr.each_ref().map(ToString::to_string),
                    rtmr0_firmware: r.rtmr0_firmware.iter().map(ToString::to_string).collect(),
                    mrtd: r.mrtd.iter().map(ToString::to_string).collect(),
                })
                .collect(),
        }
    }
}

fn svn_floor<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
    common::unhex(&String::deserialize(d)?)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| serde::de::Error::custom(PolicyError::SvnFloor))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A release run on two host firmwares publishes a canary-recorded RTMR0 for each;
    /// check 6 accepts either and nothing else, and receipts are checked the same way.
    #[test]
    fn a_release_accepts_each_canary_recorded_rtmr0_and_no_other() {
        let m = |b: u8| common::hex(&[b; 48]);
        let rel: Release = serde_json::from_value(serde_json::json!({
            "id": "clovelly-0.1.0-prod", "rtmr": [m(1), m(2), m(3), m(4)], "rtmr0_firmware": [m(9)],
            "published_at": 0, "notice_secs": 0, "valid_until": 1
        }))
        .unwrap();
        let at = |b: u8| Measurement([b; 48]);
        assert!(rel.accepts_rtmr0(&at(1)) && rel.accepts_rtmr0(&at(9)));
        assert!(!rel.accepts_rtmr0(&at(2)));
        let plain: Release = serde_json::from_value(serde_json::json!({
            "id": "clovelly-0.1.0-prod", "rtmr": [m(1), m(2), m(3), m(4)], "published_at": 0, "notice_secs": 0, "valid_until": 1
        }))
        .unwrap();
        assert!(plain.rtmr0_firmware.is_empty() && !plain.accepts_rtmr0(&at(9)));
    }
}
