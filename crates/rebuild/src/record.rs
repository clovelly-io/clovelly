//! A build record: what one builder's `release/rebuild.sh` produced, and the compare
//! gate between the records of two builders (SPEC.md phase 5 criterion 1).
//!
//! The record is `key=value` lines (`build.txt`), so a stranger can read and `diff`
//! two of them by eye:
//!
//! ```text
//! builder=github-hosted              or gce/<project>, or independent
//! commit=<40 hex>
//! prod.release=clovelly-0.2.0
//! prod.recipe=/nix/store/<hash>-clovelly-image-prod-unsigned.drv
//! prod.disk_sha256=<64 hex>          SHA-256 of disk.raw, from the build
//! prod.tarball_sha256=<64 hex>       SHA-256 of disk.raw.tar.gz, as the builder holds it
//! prod.rtmr1=<96 hex>
//! prod.rtmr2=<96 hex>
//! test.…                             the same for the test image
//! version.kernel=6.18.10             and runsc, cell-agent, egress-proxy, chrony
//! ```

use std::collections::BTreeMap;
use std::fmt;

use common::ids::ReleaseId;
use common::release::{Commit, DrvPath, GcpProject, Sha256};
use common::tdx::Measurement;

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("line {0} is not key=value")]
    Line(usize),
    #[error("{0} appears twice")]
    Duplicate(String),
    #[error("{0} is missing")]
    Missing(String),
    #[error("{0} is not a field of a build record")]
    Unknown(String),
    #[error("{key}: {why}")]
    Value { key: String, why: String },
}

/// Who built: the two builders must differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Builder {
    GithubHosted,
    /// A GCE builder in this project.
    Gce(GcpProject),
    /// Anyone else following REPRODUCE.md.
    Independent,
}

impl fmt::Display for Builder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Builder::GithubHosted => f.write_str("github-hosted"),
            Builder::Gce(p) => write!(f, "gce/{p}"),
            Builder::Independent => f.write_str("independent"),
        }
    }
}

/// One image variant's outputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    pub release: ReleaseId,
    pub recipe: DrvPath,
    pub disk_sha256: Sha256,
    pub tarball_sha256: Sha256,
    pub rtmr1: Measurement,
    pub rtmr2: Measurement,
}

/// Component versions, read from the build's outputs (for the release notes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Versions {
    pub kernel: String,
    pub runsc: String,
    pub cell_agent: String,
    pub egress_proxy: String,
    pub chrony: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildRecord {
    pub builder: Builder,
    pub commit: Commit,
    pub prod: Image,
    pub test: Image,
    pub versions: Versions,
    /// Every line, for the comparison.
    fields: BTreeMap<String, String>,
}

const IMAGE_KEYS: [&str; 6] = ["release", "recipe", "disk_sha256", "tarball_sha256", "rtmr1", "rtmr2"];
const VERSION_KEYS: [&str; 5] = ["kernel", "runsc", "cell-agent", "egress-proxy", "chrony"];

impl BuildRecord {
    pub fn parse(text: &str) -> Result<Self, RecordError> {
        let mut fields = BTreeMap::new();
        for (n, line) in text.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()) {
            let (k, v) = line.split_once('=').ok_or(RecordError::Line(n + 1))?;
            if fields.insert(k.to_owned(), v.to_owned()).is_some() {
                return Err(RecordError::Duplicate(k.to_owned()));
            }
        }
        let known = |k: &str| {
            matches!(k, "builder" | "commit")
                || k.split_once('.').is_some_and(|(scope, f)| match scope {
                    "prod" | "test" => IMAGE_KEYS.contains(&f),
                    "version" => VERSION_KEYS.contains(&f),
                    _ => false,
                })
        };
        if let Some(k) = fields.keys().find(|k| !known(k)) {
            return Err(RecordError::Unknown(k.clone()));
        }
        let get = |k: &str| get(&fields, k);
        let image = |v: &str| -> Result<Image, RecordError> {
            Ok(Image {
                release: typed(&fields, &format!("{v}.release"))?,
                recipe: typed(&fields, &format!("{v}.recipe"))?,
                disk_sha256: typed(&fields, &format!("{v}.disk_sha256"))?,
                tarball_sha256: typed(&fields, &format!("{v}.tarball_sha256"))?,
                rtmr1: typed(&fields, &format!("{v}.rtmr1"))?,
                rtmr2: typed(&fields, &format!("{v}.rtmr2"))?,
            })
        };
        let builder = match get("builder")? {
            "github-hosted" => Builder::GithubHosted,
            "independent" => Builder::Independent,
            other => match other.strip_prefix("gce/").map(str::parse) {
                Some(Ok(p)) => Builder::Gce(p),
                _ => {
                    return Err(RecordError::Value {
                        key: "builder".into(),
                        why: format!("{other:?} is not github-hosted, gce/<project> or independent"),
                    });
                }
            },
        };
        let version = |k: &str| get(&format!("version.{k}")).map(str::to_owned);
        Ok(Self {
            builder,
            commit: typed(&fields, "commit")?,
            prod: image("prod")?,
            test: image("test")?,
            versions: Versions {
                kernel: version("kernel")?,
                runsc: version("runsc")?,
                cell_agent: version("cell-agent")?,
                egress_proxy: version("egress-proxy")?,
                chrony: version("chrony")?,
            },
            fields,
        })
    }
}

fn get<'a>(fields: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, RecordError> {
    fields.get(key).map(String::as_str).ok_or_else(|| RecordError::Missing(key.to_owned()))
}

/// Parses the value of field `key`.
fn typed<T: std::str::FromStr>(fields: &BTreeMap<String, String>, key: &str) -> Result<T, RecordError>
where
    T::Err: fmt::Display,
{
    get(fields, key)?.parse().map_err(|e: T::Err| RecordError::Value { key: key.to_owned(), why: e.to_string() })
}

/// One line of the comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compared {
    pub key: String,
    pub a: String,
    pub b: String,
}

impl Compared {
    /// Whether this line passes: equal, except `builder`, which must differ.
    pub fn ok(&self) -> bool {
        (self.key == "builder") != (self.a == self.b)
    }
}

impl fmt::Display for Compared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.ok(), self.key == "builder") {
            (true, true) => write!(f, "ok        {:<20} {} | {}", self.key, self.a, self.b),
            (true, false) => write!(f, "identical {:<20} {}", self.key, self.a),
            (false, true) => write!(f, "REFUSED   {:<20} both builds came from {}", self.key, self.a),
            (false, false) => write!(f, "DIFFERENT {:<20} {} | {}", self.key, self.a, self.b),
        }
    }
}

/// The compare gate: every field of two independent builders' records, in order.
/// Signing goes ahead only if every line is [`Compared::ok`].
pub fn compare(a: &BuildRecord, b: &BuildRecord) -> Vec<Compared> {
    a.fields
        .iter()
        .map(|(k, va)| Compared {
            key: k.clone(),
            a: va.clone(),
            b: b.fields.get(k).cloned().unwrap_or_default(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(builder: &str) -> String {
        let h = |c: char, n: usize| c.to_string().repeat(n);
        let mut s = format!("builder={builder}\ncommit={}\n", h('a', 40));
        for (v, rel) in [("prod", "clovelly-0.2.0"), ("test", "clovelly-0.2.0-test")] {
            s += &format!(
                "{v}.release={rel}\n{v}.recipe=/nix/store/{}-clovelly-image-{v}-unsigned.drv\n{v}.disk_sha256={}\n\
                 {v}.tarball_sha256={}\n{v}.rtmr1={}\n{v}.rtmr2={}\n",
                h('0', 32),
                h('1', 64),
                h('2', 64),
                h('3', 96),
                h('4', 96)
            );
        }
        s + "version.kernel=6.18.10\nversion.runsc=20261019.0\nversion.cell-agent=0.2.0\n\
             version.egress-proxy=0.2.0\nversion.chrony=4.6.1\n"
    }

    #[test]
    fn identical_builds_from_two_builders_pass_the_gate() {
        let (a, b) = (BuildRecord::parse(&record("github-hosted")).unwrap(), BuildRecord::parse(&record("gce/example-builder")).unwrap());
        let lines = compare(&a, &b);
        assert_eq!(lines.len(), 19);
        assert!(lines.iter().all(Compared::ok), "{lines:?}");
    }

    /// Criterion 1: one byte of difference in an image refuses the gate, as does a
    /// prediction that differs or a single builder used twice.
    #[test]
    fn the_gate_refuses_one_different_byte_a_different_prediction_or_one_builder_twice() {
        let a = BuildRecord::parse(&record("github-hosted")).unwrap();
        let injected = record("gce/example-builder").replacen(&format!("prod.tarball_sha256={}", "2".repeat(64)), &format!("prod.tarball_sha256=3{}", "2".repeat(63)), 1);
        let b = BuildRecord::parse(&injected).unwrap();
        let bad: Vec<_> = compare(&a, &b).into_iter().filter(|c| !c.ok()).collect();
        assert_eq!(bad.iter().map(|c| c.key.as_str()).collect::<Vec<_>>(), ["prod.tarball_sha256"]);
        assert!(bad[0].to_string().starts_with("DIFFERENT"));

        let b = BuildRecord::parse(&record("gce/example-builder").replacen(&format!("test.rtmr2={}", "4".repeat(96)), &format!("test.rtmr2=5{}", "4".repeat(95)), 1)).unwrap();
        assert!(compare(&a, &b).iter().any(|c| c.key == "test.rtmr2" && !c.ok()));

        let same = compare(&a, &a);
        assert_eq!(same.iter().filter(|c| !c.ok()).map(|c| c.key.as_str()).collect::<Vec<_>>(), ["builder"]);
    }

    #[test]
    fn a_record_must_have_every_field_and_no_other() {
        let r = record("gce/example-builder");
        assert!(matches!(BuildRecord::parse(&r.replace("version.chrony=4.6.1\n", "")), Err(RecordError::Missing(_))));
        assert!(matches!(BuildRecord::parse(&(r.clone() + "note=hello\n")), Err(RecordError::Unknown(_))));
        assert!(matches!(BuildRecord::parse(&(r.clone() + "commit=x\n")), Err(RecordError::Duplicate(_))));
        assert!(matches!(BuildRecord::parse(&r.replace("builder=gce/example-builder", "builder=laptop")), Err(RecordError::Value { .. })));
        assert!(BuildRecord::parse(&r.replace(&format!("prod.rtmr1={}", "3".repeat(96)), "prod.rtmr1=zz")).is_err());
    }
}
