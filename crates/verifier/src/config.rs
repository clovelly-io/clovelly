//! The verifier's deployment configuration: the customer's own settings, not signed by
//! us. Read from `CLOVELLY_CONFIG` (JSON) at start-up.
//!
//! ```json
//! { "env": "staging",
//!   "subenvs": { "a": { "wrapped_dek": "<KMS ciphertext, base64>",
//!                       "policy_bundle": "{…}", "policy_sig": "<detached JWS>" } },
//!   "ca": { "kms_key": "projects/…/cryptoKeyVersions/1", "cert_pem": "-----BEGIN…",
//!           "previous_cert_pem": [] },
//!   "dek_kms_key": "projects/…/cryptoKeys/dek",
//!   "release_keys": ["-----BEGIN PUBLIC KEY-----…"],
//!   "policy_key_pem": "-----BEGIN PUBLIC KEY-----…",  (two blocks during a rotation)
//!   "sdk_token_sha256": "<hex>",
//!   "pinned_releases": [],
//!   "fragments_url": "https://…/fragments.json",
//!   "rekor_keys": ["-----BEGIN PUBLIC KEY-----…"],
//!   "collateral_cache_secs": 3600 }
//! ```
//!
//! `fragments_url` and `rekor_keys` are optional. Without `rekor_keys` the verifier
//! trusts only Sigstore's public Rekor log, whose key is built in.

use std::collections::BTreeMap;

use common::ids::{EnvId, ReleaseId, SubenvId};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub env: EnvId,
    pub subenvs: BTreeMap<SubenvId, Subenv>,
    pub ca: Ca,
    /// The symmetric KMS key that wraps every sub-environment DEK at rest.
    pub dek_kms_key: String,
    /// PEM public keys whose signatures make a release policy valid.
    pub release_keys: Vec<String>,
    /// The customer's policy public keys (PEM, one block per key), handed to cells at
    /// every unlock and renewal: a policy bundle a cell accepts must verify under one of
    /// them. Two while the key rotates (docs/key-rotation.md).
    #[serde(default)]
    pub policy_key_pem: String,
    /// SHA-256 (hex) of the token the customer's SDK presents to `SealCredential`.
    /// Unset, every seal is refused.
    #[serde(default)]
    pub sdk_token_sha256: Option<String>,
    /// Releases the customer pinned by hand (check 9). Empty, the verifier accepts
    /// every release its policy lists once the release's notice window has ended.
    /// Otherwise it accepts exactly these, at once, and no other release however old:
    /// a pinned customer moves to a new release by pinning it.
    #[serde(default)]
    pub pinned_releases: Vec<ReleaseId>,
    /// Where our release pipeline publishes policy fragments (a JSON array of
    /// fragment bundles), fetched at start-up and every ten minutes. Each is applied
    /// only with our signature and a Rekor inclusion proof, so the host is untrusted.
    #[serde(default)]
    pub fragments_url: Option<String>,
    /// PEM public keys of the Rekor logs whose inclusion proofs the verifier accepts.
    #[serde(default = "public_rekor")]
    pub rekor_keys: Vec<String>,
    /// How long fetched collateral, host-registry entries and endorsements are reused;
    /// 0 fetches them for every unlock. Never more than 3600: check 2 refuses CRLs
    /// fetched over an hour ago.
    pub collateral_cache_secs: u64,
}

/// How check 9 accepts a release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acceptance<'a> {
    /// Any release in the policy, once its notice window has ended.
    Window,
    /// Exactly these releases, whatever their window.
    Pinned(&'a [ReleaseId]),
}

impl Config {
    pub fn acceptance(&self) -> Acceptance<'_> {
        if self.pinned_releases.is_empty() {
            Acceptance::Window
        } else {
            Acceptance::Pinned(&self.pinned_releases)
        }
    }
}

/// Sigstore's public Rekor log key (`rekor.sigstore.dev`).
fn public_rekor() -> Vec<String> {
    vec![crate::REKOR_PUBLIC_KEY.to_owned()]
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subenv {
    /// The DEK encrypted under `dek_kms_key`, base64. Decrypted for every unlock, so
    /// revoking the KMS key stops unlocks at once.
    pub wrapped_dek: String,
    /// The sub-environment's policy bundle (JSON) and its detached JWS.
    pub policy_bundle: String,
    pub policy_sig: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ca {
    /// The KMS key version (EC_SIGN_P256_SHA256) that signs cell certificates.
    pub kms_key: String,
    pub cert_pem: String,
    /// CA certificates this one replaced: cells' certificates under them stay good for
    /// receipts until their leases end (docs/key-rotation.md).
    #[serde(default)]
    pub previous_cert_pem: Vec<String>,
}
