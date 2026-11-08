//! A cell-image release as we publish it (SPEC.md phase 5): the closed payload logged in
//! Rekor, and the policy fragment verifiers apply.
//!
//! The release pipeline builds a [`ReleasePayload`] from two
//! matching builds, signs it as a DSSE envelope with our release key and logs it in
//! Rekor. It then signs a [`Fragment`] (the payload's exact bytes, the notice window,
//! `valid_until` and, for a security release, its predecessors' new `valid_until`) and
//! publishes it with the Rekor entry as a [`FragmentBundle`]. The verifier applies a
//! bundle only if both our signatures and the log's inclusion proof verify.
//!
//! The payload schema is closed (SPEC.md decision 8): measurements, recipe hash,
//! provenance and release id, nothing else. Unknown fields are refused, and every
//! string is a typed value (release id, digest, commit, repository, store path), so no
//! field can carry free text.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ids::{ReleaseId, Zone};
use crate::rekor::LogEntry;
use crate::tdx::Measurement;

/// The DSSE payload type of a release payload.
pub const PAYLOAD_TYPE: &str = "application/vnd.clovelly.release.v1+json";
/// A release is valid this long after its fragment is made, unless superseded.
pub const DEFAULT_VALID_SECS: u64 = 30 * 86_400;
/// A superseded release stays valid this long after its successor's window ends.
pub const SUPERSEDED_GRACE_SECS: u64 = 7 * 86_400;
/// Pinned verifiers warn this long before a pinned release expires.
pub const EXPIRY_WARNING_SECS: u64 = 7 * 86_400;

#[derive(Debug, thiserror::Error)]
pub enum PayloadError {
    #[error("release payload does not match the closed schema: {0}")]
    Schema(#[from] serde_json::Error),
    #[error("release payload is not in canonical (JCS) form")]
    NotCanonical,
    #[error("release payload: {0}")]
    Invalid(&'static str),
}

/// What a release's Rekor entry holds, and nothing else.
///
/// ```json
/// { "v": 1, "release": "clovelly-0.2.0",
///   "recipe": "/nix/store/<hash>-clovelly-image-prod-unsigned.drv",
///   "provenance": {
///     "source": { "repository": "github.com/clovelly-io/clovelly",
///                 "commit": "<40 hex>", "tag": "v0.2.0" },
///     "builds": [ { "builder": "github-hosted", "run_id": 123 },
///                 { "builder": "gce", "project": "example-builder",
///                   "zone": "us-central1-a", "machine_type": "c3-standard-44" } ],
///     "disk_sha256": "<64 hex>" },
///   "measurements": {
///     "firmware": [ { "mrtd": "<96 hex>", "rtmr0": "<96 hex>", "machine_type": "c3-standard-8" } ],
///     "rtmr1": "<96 hex>", "rtmr2": "<96 hex>", "rtmr3": "<96 hex>" },
///   "images": { "verifier": "sha256:<64 hex>", "clovelly-keys": "sha256:<64 hex>" } }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePayload {
    pub v: V1,
    pub release: PublishedRelease,
    /// The Nix derivation of the unsigned `prod` image: its store path is a hash of the
    /// whole recipe, every input included.
    pub recipe: DrvPath,
    pub provenance: Provenance,
    pub measurements: Measurements,
    /// The container images built with this release, from phase 8: a customer pulls these
    /// digests. Releases before 0.4.0 have none, and their signed bytes stay as they are.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub images: Option<Images>,
}

/// The digests of the images a customer runs beside their key manager.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Images {
    pub verifier: ImageDigest,
    #[serde(rename = "clovelly-keys")]
    pub clovelly_keys: ImageDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub source: Source,
    /// The two independent builds whose outputs matched before anything was signed: one
    /// on a GitHub-hosted runner and one on a GCE builder, or GCE builders in two
    /// projects when GitHub-hosted runners cannot run (BLOCKERS.md, phase 5).
    pub builds: [Build; 2],
    /// SHA-256 of the unsigned `prod` disk image (`disk.raw`) both builds produced.
    pub disk_sha256: Sha256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub repository: Repository,
    pub commit: Commit,
    pub tag: Tag,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "builder", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Build {
    GithubHosted { run_id: u64 },
    Gce { project: GcpProject, zone: Zone, machine_type: MachineType },
}

impl FromStr for Build {
    type Err = BadValue;

    /// `github-hosted:<run id>` or `gce:<project>:<zone>:<machine type>`.
    fn from_str(s: &str) -> Result<Self, BadValue> {
        let bad = || BadValue { what: "build (github-hosted:RUN or gce:PROJECT:ZONE:MACHINE)", value: s.to_owned() };
        match s.split(':').collect::<Vec<_>>().as_slice() {
            ["github-hosted", run] => Ok(Build::GithubHosted { run_id: run.parse().map_err(|_| bad())? }),
            ["gce", project, zone, machine] => Ok(Build::Gce {
                project: project.parse()?,
                zone: zone.parse().map_err(|_| bad())?,
                machine_type: machine.parse()?,
            }),
            _ => Err(bad()),
        }
    }
}

/// The release's measurement set. RTMR1 and RTMR2 are predicted from the image (and
/// equal on both builds); RTMR0 is recorded by a canary on each host firmware and cell
/// shape, paired with that firmware's MRTD; RTMR3 is never extended (SPEC.md decisions).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Measurements {
    pub firmware: Vec<Firmware>,
    pub rtmr1: Measurement,
    pub rtmr2: Measurement,
    pub rtmr3: Measurement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Firmware {
    pub mrtd: Measurement,
    pub rtmr0: Measurement,
    /// The cell shape whose canary recorded `rtmr0` (RTMR0 measures the machine as well as
    /// the firmware), so a reviewer can tell the values apart. Verifiers accept any listed
    /// RTMR0 whatever its shape. Releases before phase 11 have none, and their signed bytes
    /// stay as they are.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_type: Option<MachineType>,
}

impl ReleasePayload {
    /// Parses payload bytes under the closed schema. They must also be canonical, so
    /// the bytes logged are the only encoding of the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, PayloadError> {
        let p: Self = serde_json::from_slice(bytes)?;
        p.check()?;
        if p.canonical() != bytes {
            return Err(PayloadError::NotCanonical);
        }
        Ok(p)
    }

    /// The payload's canonical bytes (JCS): what is signed and logged.
    pub fn canonical(&self) -> Vec<u8> {
        let v = serde_json::to_value(self).expect("the payload serialises");
        crate::jcs::canonical(&v).expect("the payload has no floats")
    }

    /// The rules the types alone do not carry.
    pub fn check(&self) -> Result<(), PayloadError> {
        if self.release.version() != self.provenance.source.tag.version() {
            return Err(PayloadError::Invalid("the tag names another version than the release"));
        }
        if self.measurements.firmware.is_empty() {
            return Err(PayloadError::Invalid("no firmware RTMR0 recorded"));
        }
        match &self.provenance.builds {
            [Build::GithubHosted { .. }, Build::Gce { .. }] => Ok(()),
            [Build::Gce { project: a, .. }, Build::Gce { project: b, .. }] if a != b => Ok(()),
            _ => Err(PayloadError::Invalid("the builds are not independent: one GitHub-hosted and one GCE, or GCE in two projects")),
        }
    }
}

/// The release kind, which sets its notice window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Window {
    /// 72 hours.
    Regular,
    /// 24 hours: a security patch.
    Security,
}

impl Window {
    pub fn notice_secs(self) -> u64 {
        match self {
            Window::Regular => 72 * 3600,
            Window::Security => 24 * 3600,
        }
    }
}

/// A policy fragment: one release, signed by our release key as a compact JWS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fragment {
    pub v: V1,
    /// The release payload's exact bytes, as logged, in base64.
    pub payload: String,
    pub window: Window,
    /// Unix seconds; the release is refused from then on, pinned or not.
    pub valid_until: u64,
    /// For a security release: every predecessor and its new `valid_until`, the end of
    /// this release's window plus 7 days. Verifiers only ever lower a `valid_until`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supersedes: Vec<Supersession>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Supersession {
    pub release: ReleaseId,
    pub valid_until: u64,
}

/// What the pipeline publishes per release and verifiers fetch (a JSON array of these
/// at the verifier's `fragments_url`): the signed fragment and the Rekor entry of its
/// payload, inclusion proof included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FragmentBundle {
    /// Compact JWS over a [`Fragment`].
    pub fragment: String,
    #[serde(default)]
    pub rekor: Option<LogEntry>,
}

/// The payload version: 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct V1;

impl TryFrom<u32> for V1 {
    type Error = &'static str;
    fn try_from(v: u32) -> Result<Self, Self::Error> {
        if v == 1 { Ok(V1) } else { Err("version is not 1") }
    }
}

impl From<V1> for u32 {
    fn from(_: V1) -> u32 {
        1
    }
}

/// Defines a string newtype that only `$parse` constructs, with serde through it.
macro_rules! checked_string {
    ($(#[$doc:meta])* $name:ident, $what:literal, $parse:expr) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = BadValue;
            fn from_str(s: &str) -> Result<Self, BadValue> {
                let ok: fn(&str) -> bool = $parse;
                if ok(s) { Ok(Self(s.to_owned())) } else { Err(BadValue { what: $what, value: s.to_owned() }) }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({:?})", stringify!($name), self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                String::deserialize(d)?.parse().map_err(serde::de::Error::custom)
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.0)
            }
        }
    };
}

checked_string!(
    /// An OCI image manifest digest, `sha256:<64 hex>`.
    ImageDigest,
    "image digest (sha256:<64 hex>)",
    |s| s.strip_prefix("sha256:").is_some_and(|h| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
);

#[derive(Debug, thiserror::Error)]
#[error("{value:?} is not a {what}")]
pub struct BadValue {
    what: &'static str,
    value: String,
}

/// `MAJOR.MINOR.PATCH` with an optional `-rc.N`, digits without leading zeros.
fn is_version(s: &str) -> bool {
    let num = |n: &str| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) && (n == "0" || !n.starts_with('0'));
    let (core, pre) = s.split_once('-').map_or((s, None), |(c, p)| (c, Some(p)));
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| num(p)) && pre.is_none_or(|p| p.strip_prefix("rc.").is_some_and(num))
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A GitHub owner or repository name.
fn is_github_name(s: &str) -> bool {
    (1..=100).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

checked_string!(
    /// A published release id: `clovelly-` and a version (`clovelly-0.2.0`, `clovelly-0.2.0-rc.1`).
    PublishedRelease,
    "published release id",
    |s| s.strip_prefix("clovelly-").is_some_and(is_version)
);

impl PublishedRelease {
    pub fn version(&self) -> &str {
        &self.0["clovelly-".len()..]
    }

    pub fn id(&self) -> ReleaseId {
        self.0.parse().expect("a published release id is a release id")
    }
}

checked_string!(
    /// A release tag: `v` and the version.
    Tag,
    "release tag",
    |s| s.strip_prefix('v').is_some_and(is_version)
);

impl Tag {
    pub fn version(&self) -> &str {
        &self.0[1..]
    }
}

checked_string!(
    /// A git commit: 40 lower-case hex digits.
    Commit,
    "commit id",
    |s| is_lower_hex(s, 40)
);

checked_string!(
    /// A SHA-256 digest: 64 lower-case hex digits.
    Sha256,
    "SHA-256 digest",
    |s| is_lower_hex(s, 64)
);

checked_string!(
    /// A source repository: `github.com/<owner>/<name>`.
    Repository,
    "GitHub repository",
    |s| s
        .strip_prefix("github.com/")
        .and_then(|r| r.split_once('/'))
        .is_some_and(|(o, n)| is_github_name(o) && is_github_name(n))
);

checked_string!(
    /// A Nix derivation path: `/nix/store/<32 nix-base32 digits>-<name>.drv`.
    DrvPath,
    "Nix derivation path",
    |s| s
        .strip_prefix("/nix/store/")
        .and_then(|r| r.strip_suffix(".drv"))
        .and_then(|r| r.split_once('-'))
        .is_some_and(|(h, name)| {
            h.len() == 32
                && h.bytes().all(|b| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&b))
                && !name.is_empty()
                && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-.".contains(&b))
        })
);

checked_string!(
    /// A GCP project id: 6 to 30 characters, lower-case letters, digits and hyphens,
    /// starting with a letter.
    GcpProject,
    "GCP project id",
    |s| (6..=30).contains(&s.len())
        && s.starts_with(|c: char| c.is_ascii_lowercase())
        && !s.ends_with('-')
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
);

checked_string!(
    /// A GCE machine type (`c3-standard-44`).
    MachineType,
    "GCE machine type",
    |s| (1..=63).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
);

#[cfg(test)]
mod tests {
    use super::*;

    fn m(b: u8) -> String {
        crate::hex(&[b; 48])
    }

    fn payload() -> serde_json::Value {
        serde_json::json!({
            "v": 1, "release": "clovelly-0.2.0-rc.1",
            "recipe": "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-clovelly-image-prod-unsigned.drv",
            "provenance": {
                "source": { "repository": "github.com/clovelly-io/clovelly",
                            "commit": "ec4005b0ec4005b0ec4005b0ec4005b0ec4005b0", "tag": "v0.2.0-rc.1" },
                "builds": [ { "builder": "github-hosted", "run_id": 18 },
                            { "builder": "gce", "project": "example-builder", "zone": "us-central1-a",
                              "machine_type": "c3-standard-44" } ],
                "disk_sha256": crate::hex(&[7; 32]) },
            "measurements": { "firmware": [ { "mrtd": m(1), "rtmr0": m(2) } ],
                              "rtmr1": m(3), "rtmr2": m(4), "rtmr3": m(0) }
        })
    }

    fn parse(v: &serde_json::Value) -> Result<ReleasePayload, PayloadError> {
        ReleasePayload::parse(&crate::jcs::canonical(v).unwrap())
    }

    #[test]
    fn a_payload_with_the_four_fields_parses_and_round_trips() {
        let p = parse(&payload()).unwrap();
        assert_eq!(p.release.id().as_str(), "clovelly-0.2.0-rc.1");
        assert_eq!(serde_json::to_value(&p).unwrap(), payload());
    }

    /// Criterion 2: the closed schema refuses any field it does not name, at the top
    /// and inside every object.
    #[test]
    fn the_closed_payload_schema_refuses_an_extra_field() {
        let objects = ["", "/provenance", "/provenance/source", "/provenance/builds/1", "/measurements", "/measurements/firmware/0"];
        for at in objects {
            let mut v = payload();
            let object = v.pointer_mut(at).and_then(|o| o.as_object_mut()).unwrap();
            object.insert("notes".into(), "1".into());
            let err = parse(&v).unwrap_err();
            assert!(matches!(err, PayloadError::Schema(_)), "{at:?}: {err}");
        }
    }

    /// Criterion 2: no field takes free text; each string is a typed value.
    #[test]
    fn the_closed_payload_schema_refuses_free_text() {
        let free = "built on my laptop, all good";
        let fields = [
            "/release",
            "/recipe",
            "/provenance/source/repository",
            "/provenance/source/commit",
            "/provenance/source/tag",
            "/provenance/builds/1/project",
            "/provenance/builds/1/machine_type",
            "/provenance/disk_sha256",
            "/measurements/rtmr1",
            "/measurements/firmware/0/mrtd",
        ];
        for at in fields {
            let mut v = payload();
            *v.pointer_mut(at).unwrap() = free.into();
            assert!(matches!(parse(&v), Err(PayloadError::Schema(_))), "{at} took free text");
        }
        let mut v = payload();
        v["release"] = "clovelly-0.2.0 final".into();
        assert!(parse(&v).is_err(), "text after a release id");
    }

    #[test]
    fn a_payload_must_be_canonical_and_consistent() {
        let bytes = serde_json::to_vec_pretty(&payload()).unwrap();
        assert!(matches!(ReleasePayload::parse(&bytes), Err(PayloadError::NotCanonical)));
        let mut v = payload();
        v["provenance"]["source"]["tag"] = "v0.2.0".into();
        assert!(matches!(parse(&v), Err(PayloadError::Invalid(_))));
        let mut v = payload();
        v["measurements"]["firmware"] = serde_json::json!([]);
        assert!(matches!(parse(&v), Err(PayloadError::Invalid(_))));
        let mut v = payload();
        let b = v["provenance"]["builds"][0].clone();
        v["provenance"]["builds"][1] = b;
        assert!(matches!(parse(&v), Err(PayloadError::Invalid(_))));
        // Two GCE builders are independent only in two projects.
        let mut v = payload();
        let gce = v["provenance"]["builds"][1].clone();
        v["provenance"]["builds"][0] = gce.clone();
        assert!(matches!(parse(&v), Err(PayloadError::Invalid(_))));
        v["provenance"]["builds"][0]["project"] = "example-project".into();
        assert!(parse(&v).is_ok());
        let mut v = payload();
        v["v"] = 2.into();
        assert!(matches!(parse(&v), Err(PayloadError::Schema(_))));
    }

    /// Phase 11 criterion 3: a firmware entry may name its cell shape; a payload without
    /// the field (every release before phase 11) parses and keeps its exact bytes.
    #[test]
    fn a_firmware_entry_may_name_its_machine_type() {
        let old = payload();
        let bytes = crate::jcs::canonical(&old).unwrap();
        let p = ReleasePayload::parse(&bytes).unwrap();
        assert_eq!(p.measurements.firmware[0].machine_type, None);
        assert_eq!(p.canonical(), bytes, "an old payload's bytes are unchanged");
        let mut v = payload();
        v["measurements"]["firmware"] = serde_json::json!([
            { "mrtd": m(1), "rtmr0": m(2), "machine_type": "c3-standard-8" },
            { "mrtd": m(1), "rtmr0": m(5), "machine_type": "c3-standard-88" } ]);
        let p = parse(&v).unwrap();
        let shapes: Vec<_> = p.measurements.firmware.iter().map(|f| f.machine_type.as_ref().map(MachineType::as_str)).collect();
        assert_eq!(shapes, [Some("c3-standard-8"), Some("c3-standard-88")]);
        assert_eq!(serde_json::to_value(&p).unwrap(), v);
        v["measurements"]["firmware"][1]["machine_type"] = "an 88, I think".into();
        assert!(matches!(parse(&v), Err(PayloadError::Schema(_))), "free text in machine_type");
    }

    #[test]
    fn versions_and_ids() {
        for ok in ["clovelly-0.2.0", "clovelly-10.0.1", "clovelly-0.2.0-rc.12"] {
            assert!(ok.parse::<PublishedRelease>().is_ok(), "{ok}");
        }
        for bad in ["clovelly-0.2", "clovelly-01.2.3", "clovelly-0.2.0-beta.1", "clovelly-0.2.0-rc.", "rel-0.2.0", "clovelly-0.2.0-test"] {
            assert!(bad.parse::<PublishedRelease>().is_err(), "{bad}");
        }
        assert!("github.com/a/b c".parse::<Repository>().is_err());
        assert!("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-x.drv".parse::<DrvPath>().is_err(), "e is not nix-base32");
    }
}
