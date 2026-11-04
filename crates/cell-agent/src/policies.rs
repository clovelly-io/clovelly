//! The sub-environment's policy bundle on the cell (SPEC.md "Policy refresh"): the
//! bundle from the unlock, then whatever the customer's verifier serves, polled every
//! 60 seconds. Every bundle is verified against the customer's policy keys, as the
//! latest unlock or renewal named them, and refused if its signature, environment,
//! expiry, version (older than the one in force) or any destination is wrong.
//!
//! The keys come with each renewal so the customer can rotate the policy key without a
//! refused bundle: the verifier names the old and the new key for at least one lease,
//! then bundles signed by the new key, then the new key alone (docs/key-rotation.md). A
//! renewal comes from the same verifier as the first unlock, over the same channel, so
//! this trusts nothing the first unlock did not.
//!
//! A refused bundle stops new sandboxes (`POLICY_REFUSED`) until the verifier serves one
//! the cell accepts: the verifier's latest word is a bundle the cell cannot trust, so
//! it admits nothing rather than guess. An unreachable verifier changes nothing.
//! Running sandboxes keep the bundle they were created under.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use common::bundle::{BundleError, Policy};
use common::ids::{EnvId, SubenvId};
use common::jws::TrustedKey;
use common::sandbox::Size;
use serde_json::json;

use crate::agent::status;

/// How often the cell asks its verifier for the bundle.
pub const POLL: Duration = Duration::from_secs(60);

#[derive(Default)]
struct State {
    current: Option<Arc<Policy>>,
    /// Why the latest bundle was refused, until one is accepted.
    refused: Option<String>,
}

/// The cell's policy state.
pub struct Policies {
    keys: Mutex<Vec<TrustedKey>>,
    env: EnvId,
    subenv: SubenvId,
    placeable: Size,
    state: Mutex<State>,
}

impl Policies {
    /// With the policy keys from the first unlock (PEM, one block per key); no key
    /// refuses every bundle.
    pub fn new(env: EnvId, subenv: SubenvId, placeable: Size, keys_pem: &str) -> Arc<Self> {
        let keys = trusted_keys(keys_pem);
        if keys.is_empty() {
            status("policy-key-missing", json!({}));
        }
        Arc::new(Self {
            keys: Mutex::new(keys),
            env,
            subenv,
            placeable,
            state: Mutex::new(State::default()),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Takes the policy keys a renewal named. A renewal naming none keeps those in force:
    /// an older verifier may not send them, and no key would stop every new sandbox.
    pub fn set_keys(&self, keys_pem: &str) {
        let keys = trusted_keys(keys_pem);
        if !keys.is_empty() {
            *self.keys.lock().unwrap_or_else(|p| p.into_inner()) = keys;
        }
    }

    /// Verifies a bundle (from an unlock, a renewal or a poll) and puts it in force, or
    /// records why not.
    pub fn offer(&self, bundle: &[u8], sig: &str, from: &str) -> Result<Arc<Policy>, BundleError> {
        let verified = {
            let keys = self.keys.lock().unwrap_or_else(|p| p.into_inner());
            let mut verdict = Err(BundleError::Invalid("no policy key from the unlock".into()));
            for key in keys.iter() {
                verdict = Policy::verify(bundle, sig, key, &self.env, &self.subenv, SystemTime::now(), self.placeable);
                if verdict.is_ok() {
                    break;
                }
            }
            // The last key's refusal stands for all: a bundle that no key opens.
            verdict
        };
        let mut state = self.lock();
        let result = verified.and_then(|p| {
            p.check_succeeds(state.current.as_deref())?;
            Ok(Arc::new(p))
        });
        match &result {
            Ok(p) => {
                let changed = state.current.as_ref().is_none_or(|c| c.hash != p.hash);
                state.current = Some(Arc::clone(p));
                if changed || state.refused.is_some() {
                    status("policy-applied", json!({ "from": from, "version": p.version, "hash": p.hash_hex() }));
                }
                state.refused = None;
            }
            Err(e) => {
                if state.refused.as_deref() != Some(&e.to_string()) {
                    status("policy-refused", json!({ "from": from, "kind": e.kind(), "reason": e.to_string() }));
                }
                state.refused = Some(format!("{}: {e}", e.kind()));
            }
        }
        result
    }

    /// The bundle new sandboxes are created under, or why there is none.
    pub fn current(&self) -> Result<Arc<Policy>, String> {
        let state = self.lock();
        if let Some(why) = &state.refused {
            return Err(why.clone());
        }
        let p = state.current.clone().ok_or_else(|| "no policy bundle yet".to_owned())?;
        if p.expires <= SystemTime::now() {
            return Err(format!("expired: policy bundle version {} has expired", p.version));
        }
        Ok(p)
    }
}

/// Each `PUBLIC KEY` block of `pem` as a key; a block that does not parse is left out.
fn trusted_keys(pem: &str) -> Vec<TrustedKey> {
    common::b64::pem_blocks(pem, "PUBLIC KEY")
        .unwrap_or_default()
        .iter()
        .filter_map(|der| TrustedKey::from_pem(&common::b64::pem("PUBLIC KEY", der)).ok())
        .collect()
}

/// Polls the verifier every [`POLL`] for the sub-environment's bundle, forever.
pub async fn poll(policies: Arc<Policies>, mut api: crate::grpc::GrpcVerifier) {
    let mut tick = tokio::time::interval(POLL);
    tick.tick().await;
    loop {
        tick.tick().await;
        match api.policy(&policies.env, &policies.subenv).await {
            Ok((bundle, sig)) => {
                let _ = policies.offer(&bundle, &sig, "poll");
            }
            Err(e) => status("policy-poll-failed", json!({ "error": e.to_string() })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
    use common::jws;
    use common::sandbox::{CpuHalves, MemoryGib};

    fn signer() -> (EcdsaKeyPair, String) {
        let kp = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
        let pem = common::b64::pem("PUBLIC KEY", kp.public_key().as_der().unwrap().as_ref());
        (kp, pem)
    }

    fn bundle(version: u64, expires_in: i64, destinations: &str) -> Vec<u8> {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64;
        format!(
            r#"{{"v":1,"env":"staging","subenv":"a","version":{version},"expires":{},"destinations":{destinations}}}"#,
            now + expires_in
        )
        .into_bytes()
    }

    fn sign(kp: &EcdsaKeyPair, b: &[u8]) -> String {
        let s = kp.sign(&SystemRandom::new(), jws::signing_input(b).as_bytes()).unwrap();
        jws::assemble(b, s.as_ref(), true).unwrap()
    }

    fn policies(pem: &str) -> Arc<Policies> {
        Policies::new("staging".parse().unwrap(), "a".parse().unwrap(), Size::new(CpuHalves(14), MemoryGib(27)), pem)
    }

    /// Criteria 10 and 11: a refused bundle stops new sandboxes until an acceptable one
    /// arrives; a newer bundle replaces the current one for new sandboxes only (a
    /// sandbox holds its own `Arc`).
    #[test]
    fn refusals_stop_creates_until_a_good_bundle_arrives() {
        let (kp, pem) = signer();
        let p = policies(&pem);
        assert!(p.current().is_err(), "nothing before the first bundle");
        let v1 = bundle(1, 3600, r#"[{"host":"a.example.com","port":443}]"#);
        let running = p.offer(&v1, &sign(&kp, &v1), "unlock").unwrap();
        assert_eq!(p.current().unwrap().version, 1);

        let (other, _) = signer();
        let v2 = bundle(2, 3600, r#"[{"host":"b.example.com","port":443}]"#);
        assert!(p.offer(&v2, &sign(&other, &v2), "poll").is_err());
        assert!(p.current().unwrap_err().starts_with("signature"));

        let expired = bundle(3, -1, "[]");
        assert!(p.offer(&expired, &sign(&kp, &expired), "poll").is_err());
        assert!(p.current().unwrap_err().starts_with("expired"));

        assert!(p.offer(&v2, &sign(&kp, &v2), "poll").is_ok());
        assert_eq!(p.current().unwrap().version, 2);
        assert_eq!(running.version, 1, "a running sandbox keeps its bundle");

        assert!(p.offer(&v1, &sign(&kp, &v1), "poll").is_err(), "an older version is a rollback");
        assert!(p.current().unwrap_err().starts_with("rollback"));
    }

    /// Criterion 11: a policy key rotates with no refused bundle. Bundles signed by the
    /// old key keep working once a renewal names both; then the new key's are accepted;
    /// then the old key's are refused once a renewal names the new key alone.
    #[test]
    fn key_rotation_keeps_unlocks_and_placements_working() {
        let (old, old_pem) = signer();
        let (new, new_pem) = signer();
        let p = policies(&old_pem);
        let v1 = bundle(1, 3600, "[]");
        p.offer(&v1, &sign(&old, &v1), "unlock").unwrap();

        // A bundle under the new key before any renewal named it is refused: why the
        // key is introduced a lease ahead of signing with it.
        let early = bundle(2, 3600, "[]");
        assert!(p.offer(&early, &sign(&new, &early), "poll").is_err());
        p.offer(&v1, &sign(&old, &v1), "poll").unwrap();
        assert_eq!(p.current().unwrap().version, 1);

        // A renewal names both: old bundles still pass, new ones too.
        p.set_keys(&format!("{old_pem}{new_pem}"));
        p.offer(&v1, &sign(&old, &v1), "poll").unwrap();
        let v2 = bundle(2, 3600, "[]");
        p.offer(&v2, &sign(&new, &v2), "poll").unwrap();
        assert_eq!(p.current().unwrap().version, 2);

        // A renewal names the new key alone: only it passes. An empty name changes nothing.
        p.set_keys(&new_pem);
        p.set_keys("");
        let v3 = bundle(3, 3600, "[]");
        assert!(p.offer(&v3, &sign(&old, &v3), "poll").is_err());
        p.offer(&v3, &sign(&new, &v3), "poll").unwrap();
        assert_eq!(p.current().unwrap().version, 3);
    }

    #[test]
    fn without_a_policy_key_every_bundle_is_refused() {
        let (kp, _) = signer();
        let p = policies("");
        let b = bundle(1, 3600, "[]");
        assert!(p.offer(&b, &sign(&kp, &b), "unlock").is_err());
        assert!(p.current().is_err());
    }
}
