//! Evidence bundles for the verifier test corpus (in our private test suite: its
//! genuine evidence identifies our test project): one cell's evidence with everything
//! the checks consult, recorded or crafted, so a bundle replays offline with the same
//! outcome.
//!
//! A bundle holds the evidence, the collateral Intel served (or a crafted copy under a
//! test root), Google's endorsements and host-registry entries, the release policy,
//! the customer's pins, when the nonce was issued and the clock to evaluate at.
//! [`Bundle::verifier`] builds a [`Verifier`] over it with [`FileSources`] and the keys it
//! is given: the corpus runs through a key helper (phase 8). Test code: built only under the
//! `test-keys` feature, never into a released binary.

use std::collections::BTreeMap;

use common::b64;
use common::evidence::{Evidence, Nonce, Spki};
use common::ids::ReleaseId;
use common::tdx::Measurement;
use serde::{Deserialize, Serialize};

use crate::config::{Ca, Config, Subenv};
use crate::keys::{KeyError, Keys};
use crate::policy::ReleasePolicy;
use crate::sources::{Collateral, SourceError, Sources};
use crate::verifier::Verifier;

/// Base64 for byte fields.
mod base64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&common::b64::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        common::b64::decode(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

mod base64_vec {
    use serde::{Deserialize, Deserializer, Serializer, ser::SerializeSeq};

    pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for b in v {
            seq.serialize_element(&common::b64::encode(b))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|s| common::b64::decode(s).map_err(serde::de::Error::custom))
            .collect()
    }
}

/// The evidence a cell sent, as stored in a bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceFile {
    #[serde(with = "base64")]
    pub quote: Vec<u8>,
    #[serde(with = "base64")]
    pub ccel_table: Vec<u8>,
    #[serde(with = "base64")]
    pub ccel_log: Vec<u8>,
    pub env: String,
    pub subenv: String,
    pub release: String,
    #[serde(with = "base64")]
    pub spki: Vec<u8>,
    pub nonce: String,
    pub instance_id: u64,
    pub zone: String,
}

/// Intel collateral as stored in a bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollateralFile {
    pub tcb_info: String,
    #[serde(with = "base64_vec")]
    pub tcb_info_chain: Vec<Vec<u8>>,
    pub qe_identity: String,
    #[serde(with = "base64_vec")]
    pub qe_identity_chain: Vec<Vec<u8>>,
    #[serde(with = "base64")]
    pub pck_crl: Vec<u8>,
    #[serde(with = "base64")]
    pub root_ca_crl: Vec<u8>,
    pub fetched_at: u64,
}

impl From<&Collateral> for CollateralFile {
    fn from(c: &Collateral) -> Self {
        Self {
            tcb_info: c.tcb_info.clone(),
            tcb_info_chain: c.tcb_info_chain.clone(),
            qe_identity: c.qe_identity.clone(),
            qe_identity_chain: c.qe_identity_chain.clone(),
            pck_crl: c.pck_crl.clone(),
            root_ca_crl: c.root_ca_crl.clone(),
            fetched_at: c.fetched_at,
        }
    }
}

impl From<&CollateralFile> for Collateral {
    fn from(c: &CollateralFile) -> Self {
        Self {
            tcb_info: c.tcb_info.clone(),
            tcb_info_chain: c.tcb_info_chain.clone(),
            qe_identity: c.qe_identity.clone(),
            qe_identity_chain: c.qe_identity_chain.clone(),
            pck_crl: c.pck_crl.clone(),
            root_ca_crl: c.root_ca_crl.clone(),
            fetched_at: c.fetched_at,
        }
    }
}

/// One corpus case.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    /// What the case is and how it was made.
    pub description: String,
    /// The check this bundle must fail, alone; `None` for a bundle to accept.
    pub expect: Option<u8>,
    /// The clock to evaluate at (Unix seconds).
    pub now: u64,
    pub evidence: EvidenceFile,
    /// When the verifier issued the evidence's nonce; `None` if it never did.
    pub nonce_issued_at: Option<u64>,
    pub collateral: CollateralFile,
    /// The quote trust root (DER): Intel's, or a test root for crafted quotes.
    #[serde(with = "base64")]
    pub trust_root: Vec<u8>,
    /// Google endorsements by MRTD (hex).
    pub endorsements: BTreeMap<String, String>,
    /// PPIDs (hex) the host registry lists.
    pub registered_ppids: Vec<String>,
    /// The release policy payload.
    pub policy: serde_json::Value,
    pub pinned_releases: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("bundle JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("bundle evidence: {0}")]
    Evidence(#[from] common::evidence::EvidenceError),
    #[error("bundle field: {0}")]
    Field(String),
    #[error("CA: {0}")]
    Ca(#[from] crate::x509::X509Error),
    #[error("verifier: {0}")]
    Setup(#[from] crate::verifier::SetupError),
    #[error("keys: {0}")]
    Keys(#[from] KeyError),
}

/// Serves a bundle's collateral, registry and endorsements.
pub struct FileSources {
    collateral: Collateral,
    registered: Vec<String>,
    endorsements: BTreeMap<Measurement, Vec<u8>>,
}

impl Sources for FileSources {
    async fn collateral(&self, _fmspc: &str, _ca: &str, _now: u64) -> Result<Collateral, SourceError> {
        Ok(self.collateral.clone())
    }

    async fn host_registered(&self, ppid: &str, _now: u64) -> Result<bool, SourceError> {
        Ok(self.registered.iter().any(|p| p == ppid))
    }

    async fn endorsement(&self, mrtd: &Measurement) -> Result<Option<Vec<u8>>, SourceError> {
        Ok(self.endorsements.get(mrtd).cloned())
    }
}

impl Bundle {
    pub fn parse(json: &str) -> Result<Self, BundleError> {
        Ok(serde_json::from_str(json)?)
    }

    pub fn evidence(&self) -> Result<Evidence, BundleError> {
        let e = &self.evidence;
        let field = |e: common::ids::IdError| BundleError::Field(e.to_string());
        Ok(Evidence {
            quote: e.quote.clone(),
            ccel_table: e.ccel_table.clone(),
            ccel_log: e.ccel_log.clone(),
            env: e.env.parse().map_err(field)?,
            subenv: e.subenv.parse().map_err(field)?,
            release: e.release.parse().map_err(field)?,
            spki: Spki::from_der(&e.spki)?,
            nonce: Nonce::try_from(
                common::unhex(&e.nonce)
                    .ok_or_else(|| BundleError::Field("nonce is not hex".into()))?
                    .as_slice(),
            )?,
            instance_id: e.instance_id,
            zone: e.zone.parse().map_err(field)?,
        })
    }

    /// A verifier for this bundle's environment, with a CA made under `keys`' key `ca`, a DEK
    /// wrapped under its key `dek`, and the bundle's nonce recorded as issued.
    pub async fn verifier<K: Keys>(&self, keys: K) -> Result<Verifier<FileSources, K>, BundleError> {
        let ev = self.evidence()?;
        let ca_der = crate::x509::make_ca(&keys, "ca", ev.env.as_str(), None, self.now - 86_400).await?;
        let wrapped_dek = b64::encode(&keys.encrypt("dek", &[0x5a; 32]).await?);
        let policy: ReleasePolicy = serde_json::from_value(self.policy.clone())?;
        let endorsements = self
            .endorsements
            .iter()
            .map(|(mrtd, e)| {
                let m: Measurement = mrtd.parse().map_err(|_| BundleError::Field(mrtd.clone()))?;
                let e = b64::decode(e).map_err(|e| BundleError::Field(e.to_string()))?;
                Ok((m, e))
            })
            .collect::<Result<_, BundleError>>()?;
        let config = Config {
            env: ev.env.clone(),
            subenvs: [(
                ev.subenv.clone(),
                Subenv {
                    wrapped_dek,
                    policy_bundle: r#"{"v":1,"destinations":[]}"#.into(),
                    policy_sig: String::new(),
                },
            )]
            .into(),
            ca: Ca {
                key: "ca".into(),
                cert_pem: b64::pem("CERTIFICATE", &ca_der),
                previous_cert_pem: vec![],
            },
            dek_key: "dek".into(),
            release_keys: vec![],
            policy_key_pem: String::new(),
            sdk_token_sha256: None,
            pinned_releases: self
                .pinned_releases
                .iter()
                .map(|r| r.parse::<ReleaseId>().map_err(|e| BundleError::Field(e.to_string())))
                .collect::<Result<_, _>>()?,
            fragments_url: None,
            rekor_keys: vec![],
            collateral_cache_secs: 3600,
        };
        let sources = FileSources {
            collateral: (&self.collateral).into(),
            registered: self.registered_ppids.clone(),
            endorsements,
        };
        let v = Verifier::new(
            config,
            policy,
            self.trust_root.clone(),
            crate::GOOGLE_ROOT.to_vec(),
            sources,
            keys,
        )?;
        if let Some(at) = self.nonce_issued_at {
            v.nonces().record(ev.nonce, &ev.env, at);
        }
        Ok(v)
    }
}
