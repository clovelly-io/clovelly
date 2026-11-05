//! Setting up a verifier's configuration, once its three keys exist behind [`Keys`]: the
//! environment CA certificate, one wrapped DEK and signed default-deny policy bundle per
//! sub-environment, our release key and fragments index, the release of this image pinned,
//! and an SDK token of which only the hash is kept.
//!
//! `verifier init` runs this through a key helper; `clovelly-keys init` creates the keys
//! in a key manager and runs the same thing. Neither needs anything but this binary.
//! What it writes holds no secret, and running it again keeps what exists and adds any new
//! sub-environment.

use std::collections::BTreeMap;
use std::path::Path;

use common::b64;
use common::ids::{EnvId, ReleaseId, SubenvId};
use common::jws::{self, JwsError, TrustedKey};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::config::{Ca, Config, Subenv};
use crate::keys::{self, KeyError, Keys};
use crate::policy::{PolicyError, ReleasePolicy};
use crate::x509::{self, X509Error};

/// Our release key, compiled in: `release/release-key.pub` in this repository.
pub const RELEASE_KEY: &str = include_str!("../roots/release-key.pub");
/// The index of our final releases, in this repository (`docs/releasing` of the pipeline).
pub const FRAGMENTS_URL: &str = "https://raw.githubusercontent.com/clovelly-io/clovelly/main/releases/fragments.json";
/// Where the current signed release policy is served. It is checked under [`RELEASE_KEY`],
/// so it does not matter where it came from.
pub const RELEASE_POLICY_URL: &str = "https://app.clovelly.io/release-policy.jws";
/// The address a helper listens on unless told otherwise (`docs/key-helper.md`).
pub const DEFAULT_KEYS_URL: &str = "http://127.0.0.1:8200";

/// How long a default policy bundle lasts. A customer publishes the next one by signing it
/// with the policy key (`docs/verifier-deploy.md`).
const BUNDLE_SECS: u64 = 30 * 86_400;
/// The length of a DEK and of a check vector's plaintext.
const DEK_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error(transparent)]
    Keys(#[from] KeyError),
    #[error(transparent)]
    Certificate(#[from] X509Error),
    #[error("signing a policy bundle: {0}")]
    Jws(#[from] JwsError),
    #[error("the release policy: {0}")]
    Policy(#[from] PolicyError),
    #[error("the configuration in {path}: {source}")]
    Existing { path: String, source: serde_json::Error },
    #[error("the configuration in {path} is for environment {found}, not {wanted}")]
    OtherEnvironment { path: String, found: EnvId, wanted: EnvId },
    #[error("{path}: {source}")]
    Io { path: String, source: std::io::Error },
    #[error("{0}")]
    Usage(String),
}

/// The three keys, by the names the helper or key manager understands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyNames {
    /// The environment CA: signs a certificate for every unlocked cell.
    pub ca: String,
    /// Signs each sub-environment's policy bundle.
    pub policy: String,
    /// Wraps each sub-environment's DEK at rest.
    pub dek: String,
}

/// What setup needs beyond the keys.
#[derive(Debug, Clone)]
pub struct Request {
    pub env: EnvId,
    pub subenvs: Vec<SubenvId>,
    /// PEM public keys that make a release policy valid.
    pub release_keys: Vec<String>,
    /// The signed release policy (JWS).
    pub release_policy: String,
    /// The releases to accept at once; see [`Config::pinned_releases`].
    pub pinned: Vec<ReleaseId>,
    /// The configuration of an earlier run in the same directory.
    pub existing: Option<Config>,
    /// Unix seconds.
    pub now: u64,
}

/// A ciphertext of random bytes that are no one's secret, with its plaintext. It lets
/// `verifier check-keys` tell a right decrypt from a wrong one against a helper whose
/// running identity is refused encrypt.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vector {
    pub ciphertext: String,
    pub plaintext: String,
}

/// What setup produced.
#[derive(Debug)]
pub struct Setup {
    pub config: Config,
    pub keys: KeyNames,
    pub ca_pem: String,
    pub policy_pem: String,
    pub vector: Vector,
    pub release_policy: String,
    /// Printed once by the caller. `None` if an earlier run already chose one.
    pub sdk_token: Option<String>,
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    aws_lc_rs::rand::fill(&mut bytes).expect("the system RNG does not fail");
    bytes
}

/// A new sub-environment's policy bundle: default deny (no destinations), version 1, valid
/// 30 days, and the sandbox limits: product default 1 vCPU and 2 GiB, at most a
/// c3-standard-8's placeable 7 vCPU and 27 GiB, 24 h.
fn default_bundle(env: &EnvId, subenv: &SubenvId, now: u64) -> String {
    json!({
        "v": 1, "env": env, "subenv": subenv, "version": 1, "expires": now + BUNDLE_SECS, "destinations": [],
        "sandbox": { "default": { "cpu": 1, "memory": 2 }, "max": { "cpu": 7, "memory": 27, "timeout": 86400 } },
    })
    .to_string()
}

/// `key`'s detached JWS over `payload`, checked under `expected`.
pub async fn sign_detached(keys: &impl Keys, key: &str, payload: &[u8], expected: &TrustedKey) -> Result<String, InitError> {
    let sig = keys::signed(keys, key, jws::signing_input(payload).as_bytes(), expected).await?;
    Ok(jws::assemble(payload, &sig, true)?)
}

/// Makes everything [`Setup`] holds, through `keys`, keeping what `req.existing` already has.
pub async fn init(keys: &impl Keys, names: KeyNames, req: Request) -> Result<Setup, InitError> {
    let release_keys = req
        .release_keys
        .iter()
        .map(|pem| TrustedKey::from_pem(pem))
        .collect::<Result<Vec<_>, _>>()?;
    ReleasePolicy::from_jws(&req.release_policy, &release_keys)?;

    let policy_key = keys::trusted(keys, &names.policy).await?;
    let policy_pem = b64::pem("PUBLIC KEY", policy_key.spki_der());
    let ca_pem = match &req.existing {
        Some(c) => c.ca.cert_pem.clone(),
        None => b64::pem("CERTIFICATE", &x509::make_ca(keys, &names.ca, req.env.as_str(), None, req.now).await?),
    };

    let mut subenvs = req.existing.as_ref().map_or_else(BTreeMap::new, |c| c.subenvs.clone());
    for subenv in &req.subenvs {
        if subenvs.contains_key(subenv) {
            continue;
        }
        let mut dek = random::<DEK_LEN>();
        let wrapped = keys.encrypt(&names.dek, &dek).await;
        common::dek::wipe(&mut dek);
        let policy_bundle = default_bundle(&req.env, subenv, req.now);
        let policy_sig = sign_detached(keys, &names.policy, policy_bundle.as_bytes(), &policy_key).await?;
        subenvs.insert(
            subenv.clone(),
            Subenv { wrapped_dek: b64::encode(&wrapped?), policy_bundle, policy_sig },
        );
    }

    let (sdk_token, sdk_token_sha256) = match req.existing.as_ref().and_then(|c| c.sdk_token_sha256.clone()) {
        Some(hash) => (None, Some(hash)),
        None => {
            let token = common::hex(&random::<32>());
            let hash = common::hex(&keys::sha256(token.as_bytes()));
            (Some(token), Some(hash))
        }
    };

    let plaintext = random::<DEK_LEN>();
    let vector = Vector {
        ciphertext: b64::encode(&keys.encrypt(&names.dek, &plaintext).await?),
        plaintext: b64::encode(&plaintext),
    };

    let config = match req.existing {
        Some(existing) => Config { subenvs, sdk_token_sha256, ..existing },
        None => Config {
            env: req.env,
            subenvs,
            ca: Ca { key: names.ca.clone(), cert_pem: ca_pem.clone(), previous_cert_pem: vec![] },
            dek_key: names.dek.clone(),
            release_keys: req.release_keys,
            policy_key_pem: policy_pem.clone(),
            sdk_token_sha256,
            pinned_releases: req.pinned,
            fragments_url: Some(FRAGMENTS_URL.to_owned()),
            rekor_keys: vec![crate::REKOR_PUBLIC_KEY.to_owned()],
            collateral_cache_secs: 3600,
        },
    };
    Ok(Setup {
        config,
        keys: names,
        ca_pem,
        policy_pem,
        vector,
        release_policy: req.release_policy,
        sdk_token,
    })
}

impl Setup {
    /// Writes `config.json`, `verifier.env` and `keys.env` (one `NAME=value` per line, for
    /// `docker run --env-file` and Compose), `ca.pem`, `policy.pub.pem`, `release-policy.jws`
    /// and `check-vector.json` into `dir`. None of them holds a secret.
    pub fn write(&self, dir: &Path) -> Result<(), InitError> {
        let config = serde_json::to_string(&self.config).expect("a Config serializes");
        let verifier_env = format!(
            "CLOVELLY_CONFIG={config}\nCLOVELLY_KEYS_URL={DEFAULT_KEYS_URL}\nCLOVELLY_RELEASE_POLICY={}\n",
            self.release_policy.trim()
        );
        let keys_env = format!(
            "CLOVELLY_KEYS_ALLOW={},{},{}\n",
            self.keys.ca, self.keys.policy, self.keys.dek
        );
        let vector = serde_json::to_string_pretty(&self.vector).expect("a Vector serializes");
        let files = [
            ("config.json", config),
            ("verifier.env", verifier_env),
            ("keys.env", keys_env),
            ("ca.pem", self.ca_pem.clone()),
            ("policy.pub.pem", self.policy_pem.clone()),
            ("release-policy.jws", self.release_policy.clone()),
            ("check-vector.json", vector),
        ];
        let io = |path: &Path, source| InitError::Io { path: path.display().to_string(), source };
        std::fs::create_dir_all(dir).map_err(|e| io(dir, e))?;
        for (name, content) in files {
            let path = dir.join(name);
            std::fs::write(&path, content).map_err(|e| io(&path, e))?;
        }
        Ok(())
    }

    /// What the operator reads when it finishes.
    pub fn summary(&self, dir: &Path) -> String {
        let mut out = format!("wrote {}: config.json verifier.env keys.env ca.pem policy.pub.pem release-policy.jws check-vector.json\n", dir.display());
        if let Some(token) = &self.sdk_token {
            out.push_str(&format!(
                "\nYour SDK token, shown this once and stored nowhere (only its hash is in the configuration):\n\n  CLOVELLY_VERIFIER_TOKEN={token}\n"
            ));
        }
        out
    }
}

/// The flags setup takes whichever binary runs it.
#[derive(Debug, Clone)]
pub struct Args {
    pub env: EnvId,
    pub subenvs: Vec<SubenvId>,
    /// Where the files go; default `out`.
    pub out: std::path::PathBuf,
    /// `--release-key FILE`, repeatable: instead of the compiled-in key.
    pub release_keys: Vec<String>,
    /// `--release-policy FILE`: instead of fetching [`RELEASE_POLICY_URL`].
    pub release_policy: Option<String>,
    /// `--pin RELEASE`, repeatable: instead of this image's own release.
    pub pinned: Vec<ReleaseId>,
}

impl Args {
    /// Parses `--env E --subenv S... [--out DIR] [--release-key FILE]... [--release-policy
    /// FILE] [--pin RELEASE]...` out of `flags`, ignoring any other flag.
    pub fn parse(flags: &[String]) -> Result<Self, InitError> {
        let usage = |e: String| InitError::Usage(e);
        let env = one(flags, "--env").ok_or_else(|| usage("--env is required".into()))?;
        let subenvs = all(flags, "--subenv");
        if subenvs.is_empty() {
            return Err(usage("at least one --subenv is required".into()));
        }
        let read = |path: &str| std::fs::read_to_string(path).map_err(|source| InitError::Io { path: path.to_owned(), source });
        let release_keys = all(flags, "--release-key").iter().map(|p| read(p)).collect::<Result<Vec<_>, _>>()?;
        let pinned = all(flags, "--pin")
            .iter()
            .map(|r| r.parse().map_err(|e: common::ids::IdError| usage(e.to_string())))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            env: env.parse().map_err(|e: common::ids::IdError| usage(e.to_string()))?,
            subenvs: subenvs
                .iter()
                .map(|s| s.parse().map_err(|e: common::ids::IdError| usage(e.to_string())))
                .collect::<Result<_, _>>()?,
            out: one(flags, "--out").unwrap_or("out").into(),
            release_keys,
            release_policy: one(flags, "--release-policy").map(read).transpose()?,
            pinned,
        })
    }

    /// The request these flags make: reads any earlier configuration in the output
    /// directory, and fetches the release policy if no file was named. `version` is this
    /// binary's, whose release is pinned unless `--pin` says otherwise.
    pub async fn request(self, version: &str, now: u64) -> Result<(Request, std::path::PathBuf), InitError> {
        let usage = |e: common::ids::IdError| InitError::Usage(e.to_string());
        let release_policy = match self.release_policy {
            Some(jws) => jws,
            None => fetch_release_policy().await?,
        };
        let path = self.out.join("config.json");
        let existing: Option<Config> = match std::fs::read_to_string(&path) {
            Ok(text) => Some(serde_json::from_str(&text).map_err(|source| InitError::Existing { path: path.display().to_string(), source })?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(source) => return Err(InitError::Io { path: path.display().to_string(), source }),
        };
        if let Some(c) = existing.as_ref().filter(|c| c.env != self.env) {
            return Err(InitError::OtherEnvironment { path: path.display().to_string(), found: c.env.clone(), wanted: self.env });
        }
        let pinned = if self.pinned.is_empty() {
            vec![format!("clovelly-{version}").parse().map_err(usage)?]
        } else {
            self.pinned
        };
        let release_keys = if self.release_keys.is_empty() { vec![RELEASE_KEY.to_owned()] } else { self.release_keys };
        Ok((
            Request { env: self.env, subenvs: self.subenvs, release_keys, release_policy, pinned, existing, now },
            self.out,
        ))
    }
}

async fn fetch_release_policy() -> Result<String, InitError> {
    let failed = |e: reqwest::Error| InitError::Usage(format!("fetching the release policy from {RELEASE_POLICY_URL}: {e}; name a file with --release-policy"));
    reqwest::get(RELEASE_POLICY_URL)
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(failed)?
        .text()
        .await
        .map_err(failed)
}

/// The value after the first `name`.
pub fn one<'a>(flags: &'a [String], name: &str) -> Option<&'a str> {
    flags.iter().position(|a| a == name).and_then(|i| flags.get(i + 1)).map(String::as_str)
}

/// The value after each `name`.
pub fn all<'a>(flags: &'a [String], name: &str) -> Vec<&'a str> {
    flags
        .iter()
        .enumerate()
        .filter(|(_, a)| *a == name)
        .filter_map(|(i, _)| flags.get(i + 1))
        .map(String::as_str)
        .collect()
}

#[cfg(test)]
mod tests {
    use common::bundle::Policy;

    use super::*;
    use crate::keys::LocalKms;

    /// The key the staging release policy is signed by, and the one we publish.
    #[test]
    fn the_compiled_in_release_key_is_the_published_one() {
        let published = include_str!("../../../release/release-key.pub");
        assert_eq!(RELEASE_KEY, published);
        assert!(TrustedKey::from_pem(RELEASE_KEY).is_ok());
    }

    async fn policy_signed_by(keys: &LocalKms) -> (String, String) {
        let payload = json!({
            "v": 1, "project_number": 123456789012u64, "allowed_zones": ["us-central1-a"], "xfam": 0,
            "mrseam": [], "tee_tcb_svn_floor": "00".repeat(16), "sw_hardening_advisories": [],
            "nonce_ttl_secs": 300, "endorsements_url": "https://example.invalid/", "releases": []
        })
        .to_string();
        let key = keys::trusted(keys, "release").await.unwrap();
        let sig = keys::signed(keys, "release", jws::signing_input(payload.as_bytes()).as_bytes(), &key).await.unwrap();
        (jws::assemble(payload.as_bytes(), &sig, false).unwrap(), b64::pem("PUBLIC KEY", key.spki_der()))
    }

    fn names() -> KeyNames {
        KeyNames { ca: "ca".into(), policy: "policy".into(), dek: "dek".into() }
    }

    async fn request(keys: &LocalKms, existing: Option<Config>, subenvs: &[&str]) -> Request {
        let (release_policy, release_key) = policy_signed_by(keys).await;
        Request {
            env: "acme".parse().unwrap(),
            subenvs: subenvs.iter().map(|s| s.parse().unwrap()).collect(),
            release_keys: vec![release_key],
            release_policy,
            pinned: vec!["clovelly-0.4.0".parse().unwrap()],
            existing,
            now: 1_793_000_000,
        }
    }

    #[tokio::test]
    async fn the_configuration_keeps_only_the_tokens_hash_and_its_bundles_verify() {
        let keys = LocalKms::generate(&["ca", "policy", "release"]);
        let setup = init(&keys, names(), request(&keys, None, &["main"]).await).await.unwrap();
        let token = setup.sdk_token.clone().unwrap();
        let text = serde_json::to_string(&setup.config).unwrap();
        assert!(!text.contains(&token));
        assert_eq!(setup.config.sdk_token_sha256.as_deref(), Some(common::hex(&keys::sha256(token.as_bytes()))).as_deref());
        assert_eq!(setup.config.fragments_url.as_deref(), Some(FRAGMENTS_URL));
        assert_eq!(setup.config.pinned_releases, ["clovelly-0.4.0".parse().unwrap()]);

        let subenv = setup.config.subenvs.get(&"main".parse().unwrap()).unwrap();
        let policy_key = TrustedKey::from_pem(&setup.config.policy_key_pem).unwrap();
        let verified = Policy::verify(
            subenv.policy_bundle.as_bytes(),
            &subenv.policy_sig,
            &policy_key,
            &"acme".parse().unwrap(),
            &"main".parse().unwrap(),
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_793_000_000),
            common::sandbox::Size::new(common::sandbox::CpuHalves(14), common::sandbox::MemoryGib(27)),
        );
        assert!(verified.is_ok(), "{verified:?}");
        crate::x509::CaCert::from_pem(&setup.config.ca.cert_pem).unwrap();
    }

    #[tokio::test]
    async fn running_it_again_keeps_the_ca_the_deks_and_the_token_and_adds_a_subenv() {
        let keys = LocalKms::generate(&["ca", "policy", "release"]);
        let first = init(&keys, names(), request(&keys, None, &["a"]).await).await.unwrap();
        let again = init(&keys, names(), request(&keys, Some(first.config.clone()), &["a", "b"]).await).await.unwrap();
        assert_eq!(again.sdk_token, None);
        assert_eq!(again.config.sdk_token_sha256, first.config.sdk_token_sha256);
        assert_eq!(again.config.ca.cert_pem, first.config.ca.cert_pem);
        let a = "a".parse().unwrap();
        assert_eq!(again.config.subenvs[&a].wrapped_dek, first.config.subenvs[&a].wrapped_dek);
        assert_eq!(again.config.subenvs[&a].policy_bundle, first.config.subenvs[&a].policy_bundle);
        assert!(again.config.subenvs.contains_key(&"b".parse().unwrap()));
    }

    #[tokio::test]
    async fn a_release_policy_not_signed_by_the_release_key_is_refused() {
        let keys = LocalKms::generate(&["ca", "policy", "release", "other"]);
        let mut req = request(&keys, None, &["a"]).await;
        let other = keys::trusted(&keys, "other").await.unwrap();
        req.release_keys = vec![b64::pem("PUBLIC KEY", other.spki_der())];
        assert!(matches!(init(&keys, names(), req).await, Err(InitError::Policy(_))));
    }
}
