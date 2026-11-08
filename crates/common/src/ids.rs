//! Identifiers that cross the trust boundary, parsed once at the edge.
//!
//! Environment, sub-environment and zone ids and instance names become parts of DNS names
//! (the cell certificate's SANs are `<subenv>.<env>.cells.clovelly.internal` and
//! `<instance>.<zone>.<subenv>.<env>.cells.clovelly.internal`), so each is one DNS label:
//! 1 to 63 characters of `a-z`, `0-9` and `-`, not starting or ending with `-`. The
//! marker type keeps them from being mixed up.

use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdError {
    #[error("{kind} {value:?} is not a DNS label (1-63 of a-z, 0-9, '-', no leading or trailing '-')")]
    NotLabel { kind: &'static str, value: String },
    #[error("release id {0:?} is not 1-64 of a-z, 0-9, '.', '-'")]
    BadRelease(String),
    #[error("sandbox id {0:?} is not 32 lowercase hex characters")]
    BadSandboxId(String),
}

/// What a [`Label`] names.
pub trait LabelKind {
    const NAME: &'static str;
}

pub mod kind {
    /// An environment: one customer.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub enum Env {}
    /// A sub-environment: one end customer of the environment's owner.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub enum Subenv {}
    /// A GCE zone, such as `us-central1-a`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub enum Zone {}
    /// A GCE instance's name, such as `clovelly-0f3a…`: names one cell.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub enum Instance {}

    impl super::LabelKind for Env {
        const NAME: &'static str = "environment id";
    }
    impl super::LabelKind for Subenv {
        const NAME: &'static str = "sub-environment id";
    }
    impl super::LabelKind for Zone {
        const NAME: &'static str = "zone";
    }
    impl super::LabelKind for Instance {
        const NAME: &'static str = "instance name";
    }
}

/// A DNS label naming a `K`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Label<K> {
    value: String,
    kind: PhantomData<K>,
}

pub type EnvId = Label<kind::Env>;
pub type SubenvId = Label<kind::Subenv>;
pub type Zone = Label<kind::Zone>;
pub type InstanceName = Label<kind::Instance>;

impl<K> Label<K> {
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl<K: LabelKind> FromStr for Label<K> {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, IdError> {
        let ok = (1..=63).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !s.starts_with('-')
            && !s.ends_with('-');
        if !ok {
            return Err(IdError::NotLabel {
                kind: K::NAME,
                value: s.to_owned(),
            });
        }
        Ok(Self {
            value: s.to_owned(),
            kind: PhantomData,
        })
    }
}

impl<K> fmt::Display for Label<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.value)
    }
}

impl<K: LabelKind> fmt::Debug for Label<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({:?})", K::NAME, self.value)
    }
}

impl<'de, K: LabelKind> serde::Deserialize<'de> for Label<K> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

impl<K> serde::Serialize for Label<K> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.value)
    }
}

/// A cell-image release, such as `clovelly-0.1.0-test`. Baked into the image at
/// `/clovelly/release`; the verifier looks it up in its release policy.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReleaseId(String);

impl ReleaseId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ReleaseId {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, IdError> {
        let ok = (1..=64).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.');
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(IdError::BadRelease(s.to_owned()))
        }
    }
}

impl fmt::Display for ReleaseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for ReleaseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ReleaseId({:?})", self.0)
    }
}

impl<'de> serde::Deserialize<'de> for ReleaseId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for ReleaseId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

/// A sandbox id: 32 lowercase hex characters, 128 bits from the system CSPRNG.
///
/// `runsc` resolves container ids by prefix, so ids have one fixed width and none is a
/// prefix of another (SPEC.md "Sandbox ids are fixed width and so prefix-free"). Only
/// [`SandboxId::generate`] and [`FromStr`] construct one, and every `runsc` call takes
/// a `SandboxId`, so nothing else ever reaches runsc as an id.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SandboxId([u8; SandboxId::LEN]);

impl SandboxId {
    pub const LEN: usize = 32;

    /// A fresh id from the system CSPRNG.
    pub fn generate() -> Self {
        let mut random = [0u8; Self::LEN / 2];
        aws_lc_rs::rand::fill(&mut random).expect("the system CSPRNG does not fail");
        let mut id = [0u8; Self::LEN];
        id.copy_from_slice(crate::hex(&random).as_bytes());
        Self(id)
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("a sandbox id is ASCII hex")
    }
}

impl FromStr for SandboxId {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, IdError> {
        let id: [u8; Self::LEN] = s
            .as_bytes()
            .try_into()
            .map_err(|_| IdError::BadSandboxId(s.to_owned()))?;
        if !id.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(IdError::BadSandboxId(s.to_owned()));
        }
        Ok(Self(id))
    }
}

impl fmt::Display for SandboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for SandboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SandboxId({})", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Criterion 14: only 32 lowercase hex characters parse; anything else, including a
    /// prefix of a valid id, is a typed error.
    #[test]
    fn sandbox_id_rejects_anything_but_32_lowercase_hex() {
        let good = SandboxId::generate();
        assert_eq!(good.as_str().len(), 32);
        assert_eq!(good.as_str().parse::<SandboxId>().unwrap(), good);
        let upper = good.as_str().to_uppercase();
        let short = &good.as_str()[..31];
        let long = format!("{good}0");
        let spaced = format!(" {}", &good.as_str()[1..]);
        let non_hex = format!("g{}", &good.as_str()[1..]);
        for bad in ["", "lat20-00001", short, &long, &spaced, &non_hex, &"0".repeat(64)] {
            assert_eq!(bad.parse::<SandboxId>(), Err(IdError::BadSandboxId(bad.to_owned())), "{bad:?}");
        }
        if upper != good.as_str() {
            assert!(upper.parse::<SandboxId>().is_err());
        }
        assert!("ABCDEF00".repeat(4).parse::<SandboxId>().is_err());
        assert!("abcdef00".repeat(4).parse::<SandboxId>().is_ok());
    }

    #[test]
    fn generated_sandbox_ids_differ() {
        let ids: std::collections::HashSet<_> = (0..1000).map(|_| SandboxId::generate()).collect();
        assert_eq!(ids.len(), 1000);
    }

    #[test]
    fn labels_are_dns_labels() {
        for ok in ["a", "staging", "us-central1-a", "0", &"x".repeat(63)] {
            assert_eq!(ok.parse::<EnvId>().unwrap().as_str(), ok);
        }
        for bad in ["", "-a", "a-", "A", "a.b", "a_b", &"x".repeat(64)] {
            assert!(bad.parse::<SubenvId>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn release_ids_allow_dots() {
        assert!("clovelly-0.1.0-test".parse::<ReleaseId>().is_ok());
        assert!("Clovelly".parse::<ReleaseId>().is_err());
        assert!("".parse::<ReleaseId>().is_err());
    }
}
