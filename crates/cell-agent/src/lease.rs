//! The key lease, boot step 8 (SPEC.md "Keys are leased for 60 minutes").
//!
//! An unlock grants a cell certificate and DEKs until the certificate's notAfter, 60
//! minutes on. From [`RENEW_AFTER`] the cell unlocks again with a fresh nonce and the
//! same key; on success the listener presents the new certificate and the old lease
//! (its DEK) is dropped and wiped. If no renewal has succeeded by [`REVOKE_MARGIN`]
//! before the certificate expires, whether the verifier refused or could not be
//! reached, [`keep`] returns and the agent ends every sandbox with `revoked`.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use common::dek::Dek;
use serde_json::json;

use crate::agent::status;
use crate::boot::{self, BootConfig, CellKey, Quoter, UnlockFailure, Unlocked, VerifierApi};
use crate::sandbox::Terms;
use crate::tls::CertSwap;

/// Renewal starts this long after each unlock.
pub const RENEW_AFTER: Duration = Duration::from_secs(45 * 60);
/// Renewal gives up this long before the certificate expires, so every sandbox has
/// ended with `revoked` while the certificate is still valid.
pub const REVOKE_MARGIN: Duration = Duration::from_secs(60);
/// The wait between renewals after a refusal or another failure that a retry with
/// backoff would not cure.
pub const RETRY_AFTER_REFUSAL: Duration = Duration::from_secs(60);

/// The tokio instant at wall-clock time `t` (now, if `t` has passed).
fn instant_at(t: SystemTime) -> tokio::time::Instant {
    tokio::time::Instant::now() + t.duration_since(SystemTime::now()).unwrap_or_default()
}

/// The terms new sandboxes are admitted under and the lease's DEK, updated at each
/// renewal. The sub-environment's limits come with its policy bundle
/// ([`crate::policies`]).
#[derive(Debug)]
pub struct SharedTerms {
    terms: Mutex<Terms>,
    expires: Mutex<SystemTime>,
    dek: Mutex<Option<Arc<Dek>>>,
}

impl SharedTerms {
    /// The terms of `lease` on a cell that ends at `cell_end`.
    pub fn new(lease: &Unlocked, cell_end: SystemTime) -> Arc<Self> {
        Arc::new(Self {
            terms: Mutex::new(Terms {
                cell_end,
                valid_until: lease.valid_until,
            }),
            expires: Mutex::new(lease.expires),
            dek: Mutex::new(Some(Arc::clone(&lease.dek))),
        })
    }

    pub fn get(&self) -> Terms {
        *self.terms.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The current certificate's notAfter.
    pub fn expires(&self) -> SystemTime {
        *self.expires.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The current lease's DEK, while there is one.
    pub fn dek(&self) -> Option<Arc<Dek>> {
        self.dek.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// The lease has lapsed: let go of its DEK.
    pub fn revoke(&self) {
        self.dek.lock().unwrap_or_else(|p| p.into_inner()).take();
    }

    fn update(&self, lease: &Unlocked) {
        self.terms.lock().unwrap_or_else(|p| p.into_inner()).valid_until = lease.valid_until;
        *self.expires.lock().unwrap_or_else(|p| p.into_inner()) = lease.expires;
        *self.dek.lock().unwrap_or_else(|p| p.into_inner()) = Some(Arc::clone(&lease.dek));
    }
}

/// How renewal ended without a new lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lapsed {
    /// The last failure, for the log.
    pub last: String,
}

/// Unlocks again until one succeeds or `give_up` passes: an unavailable verifier is
/// retried with the unlock's backoff, a refusal or other final failure every
/// [`RETRY_AFTER_REFUSAL`].
pub async fn renew(
    cfg: &BootConfig,
    key: &CellKey,
    api: &mut impl VerifierApi,
    quoter: &impl Quoter,
    ccel: (&[u8], &[u8]),
    give_up: tokio::time::Instant,
) -> Result<Unlocked, Lapsed> {
    let mut last = String::from("no attempt before the deadline");
    loop {
        let left = give_up.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return Err(Lapsed { last });
        }
        match boot::unlock(cfg, key, api, quoter, ccel, left).await {
            Ok(next) => return Ok(next),
            Err(UnlockFailure::Deadline(_, e)) => return Err(Lapsed { last: e }),
            Err(other) => {
                last = other.to_string();
                status("renewal-failed", json!({ "error": last }));
                tokio::time::sleep(RETRY_AFTER_REFUSAL.min(left)).await;
            }
        }
    }
}

/// Holds the lease for the cell's life: renews from [`RENEW_AFTER`] after each unlock,
/// presents each new certificate and updates the terms. Returns once a lease has
/// lapsed, after dropping (and so wiping) its DEK.
pub async fn keep(
    cfg: &BootConfig,
    key: &CellKey,
    api: &mut impl VerifierApi,
    quoter: &impl Quoter,
    ccel: (&[u8], &[u8]),
    mut lease: Unlocked,
    on_renewal: impl Fn(&Unlocked),
) -> Lapsed {
    loop {
        // Both deadlines from the wall clock now, while it agrees with tokio's.
        let renew_at = instant_at(lease.at + RENEW_AFTER);
        let give_up = instant_at(lease.expires.checked_sub(REVOKE_MARGIN).unwrap_or(lease.expires));
        tokio::time::sleep_until(renew_at).await;
        status("renewing", json!({ "expires": boot::unix(lease.expires) }));
        match renew(cfg, key, api, quoter, ccel, give_up).await {
            Ok(next) => {
                on_renewal(&next);
                status(
                    "renewed",
                    json!({ "expires": boot::unix(next.expires), "valid_until": boot::unix(next.valid_until) }),
                );
                // The previous lease's DEK is wiped here.
                lease = next;
            }
            Err(lapsed) => {
                drop(lease);
                return lapsed;
            }
        }
    }
}

/// [`keep`]'s renewal hook for a serving cell: swap the listener's certificate and the
/// one receipts carry, update the terms and offer the renewal's policy bundle.
pub fn apply<'a>(
    certs: &'a CertSwap,
    key: &'a CellKey,
    terms: &'a SharedTerms,
    policies: &'a crate::policies::Policies,
    signer: &'a crate::receipts::Signer,
) -> impl Fn(&Unlocked) + 'a {
    move |next: &Unlocked| {
        if let Err(e) = certs.swap(&next.cell_cert, key) {
            status("certificate-swap-failed", json!({ "error": e.to_string() }));
        }
        signer.set_cert(&next.cell_cert);
        terms.update(next);
        policies.set_keys(&next.policy_key);
        let _ = policies.offer(&next.policy_bundle, &next.policy_sig, "renewal");
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::boot::{ApiError, Granted};
    use crate::guard;
    use common::dek::{self, Dek};
    use common::evidence::{Evidence, Nonce};
    use common::ids::EnvId;
    use common::tdx::ReportData;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A verifier whose `Unlock` answers from a script, then repeats its last answer.
    pub(crate) struct Scripted {
        pub replies: Vec<Result<Granted, ApiError>>,
        pub calls: Arc<AtomicUsize>,
    }

    impl VerifierApi for Scripted {
        async fn nonce(&mut self, _: &EnvId) -> Result<Nonce, ApiError> {
            Ok(Nonce([7; 32]))
        }
        async fn unlock(&mut self, _: &Evidence) -> Result<Granted, ApiError> {
            let n = self.calls.fetch_add(1, Ordering::Relaxed);
            self.replies[n.min(self.replies.len() - 1)].clone()
        }
    }

    pub(crate) struct FakeQuoter;

    impl Quoter for FakeQuoter {
        fn quote(&self, _: &ReportData) -> Result<Vec<u8>, String> {
            Ok(vec![0; 16])
        }
    }

    pub(crate) fn cfg() -> BootConfig {
        BootConfig {
            env: "acme".parse().unwrap(),
            subenv: "bank-a".parse().unwrap(),
            verifier: "https://verifier.invalid".into(),
            release: "clovelly-0.1.0-test".parse().unwrap(),
            instance_id: 1,
            zone: "us-central1-a".parse().unwrap(),
            instance_name: "clovelly-0a1b2c3d".parse().unwrap(),
            project: "1".into(),
            deadline: Duration::from_secs(5),
            control_plane: None,
            cap: Duration::from_secs(48 * 3600),
            prepull: crate::boot::Prepull::AtBoot,
        }
    }

    pub(crate) fn random() -> [u8; 32] {
        let mut b = [0u8; 32];
        aws_lc_rs::rand::fill(&mut b).unwrap();
        b
    }

    /// A DER certificate valid from now for `valid`.
    pub(crate) fn cert(valid: Duration) -> Vec<u8> {
        let mut p = rcgen::CertificateParams::new(vec!["a.acme.cells.clovelly.internal".to_owned()]).unwrap();
        let now = time::OffsetDateTime::now_utc();
        p.not_before = now - time::Duration::minutes(5);
        p.not_after = now + time::Duration::seconds(i64::try_from(valid.as_secs()).unwrap());
        let kp = rcgen::KeyPair::generate().unwrap();
        p.self_signed(&kp).unwrap().der().to_vec()
    }

    /// What the verifier grants: `dek` wrapped to `key`, a 60-minute certificate.
    pub(crate) fn granted(key: &CellKey, dek_bytes: [u8; 32]) -> Result<Granted, ApiError> {
        let c = cfg();
        let wrapped = dek::wrap(&Dek::from_bytes(dek_bytes), key.spki(), &c.env, &c.subenv).unwrap();
        Ok(Granted {
            cell_cert: cert(Duration::from_secs(3600)),
            wrapped_dek: wrapped,
            policy_bundle: b"{}".to_vec(),
            policy_sig: String::new(),
            release_valid_until: 4_000_000_000,
            policy_key: String::new(),
        })
    }

    pub(crate) fn scalar(key: &CellKey) -> [u8; 32] {
        key.private_scalar_for_tests()
    }

    /// Runs `f` on a current-thread runtime with time paused, so an hour of lease
    /// passes instantly.
    fn paused<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap()
            .block_on(f)
    }

    fn first_lease(key: &CellKey, dek_bytes: [u8; 32]) -> Unlocked {
        let mut api = Scripted {
            replies: vec![granted(key, dek_bytes)],
            calls: Arc::default(),
        };
        paused(boot::unlock(&cfg(), key, &mut api, &FakeQuoter, (b"t", b"l"), Duration::from_secs(5))).unwrap()
    }

    /// Criterion 15: a renewal at 45 minutes replaces the lease, and the old DEK is
    /// wiped when it is dropped; the new one when the lapsed lease is.
    #[test]
    fn renewal_replaces_the_lease_and_wipes_the_old_dek() {
        let key = CellKey::generate();
        let (d1, d2) = (random(), random());
        let (w1, w2, wk) = (guard::watch(&d1), guard::watch(&d2), guard::watch(&scalar(&key)));
        let lease = first_lease(&key, d1);
        let calls = Arc::new(AtomicUsize::new(0));
        // Renews once, then the verifier refuses (it never answers twice the same way).
        let mut api = Scripted {
            replies: vec![granted(&key, d2), Err(ApiError::Refused(9))],
            calls: Arc::clone(&calls),
        };
        let renewed = std::cell::RefCell::new(Vec::new());
        let lapsed = paused(keep(&cfg(), &key, &mut api, &FakeQuoter, (b"t", b"l"), lease, |u| {
            renewed.borrow_mut().push((u.dek.as_bytes() == &d2, u.at));
        }));
        assert_eq!(renewed.borrow().len(), 1, "one renewal");
        assert!(renewed.borrow()[0].0, "the renewal carried the new DEK");
        assert_eq!(lapsed.last, "verifier refused: check 9");
        drop(key);
        assert_eq!((w1.leaks(), w2.leaks(), wk.leaks()), (0, 0, 0));
    }

    /// Criterion 15: the verifier refuses every renewal; renewal gives up before the
    /// certificate expires and the DEK is wiped.
    #[test]
    fn a_refused_renewal_lapses_before_expiry_and_wipes_the_dek() {
        let key = CellKey::generate();
        let d = random();
        let (wd, wk) = (guard::watch(&d), guard::watch(&scalar(&key)));
        let lease = first_lease(&key, d);
        let expires = lease.expires;
        let calls = Arc::new(AtomicUsize::new(0));
        let mut api = Scripted {
            replies: vec![Err(ApiError::Refused(9))],
            calls: Arc::clone(&calls),
        };
        let (lapsed, waited) = paused(async {
            let started = tokio::time::Instant::now();
            let l = keep(&cfg(), &key, &mut api, &FakeQuoter, (b"t", b"l"), lease, |_| panic!("no renewal")).await;
            (l, started.elapsed())
        });
        assert!(lapsed.last.contains("check 9"), "{}", lapsed.last);
        // 45 minutes, then a refusal a minute until 59 minutes.
        assert!(calls.load(Ordering::Relaxed) >= 10, "retried: {}", calls.load(Ordering::Relaxed));
        let lease_left = expires.duration_since(SystemTime::now()).unwrap_or_default();
        assert!(waited + REVOKE_MARGIN <= lease_left + Duration::from_secs(1), "{waited:?} vs {lease_left:?}");
        drop(key);
        assert_eq!((wd.leaks(), wk.leaks()), (0, 0));
    }

    /// Criterion 15: the verifier cannot be reached; renewal retries with backoff,
    /// gives up before the certificate expires, and the DEK is wiped.
    #[test]
    fn an_unreachable_verifier_lapses_before_expiry_and_wipes_the_dek() {
        let key = CellKey::generate();
        let d = random();
        let (wd, wk) = (guard::watch(&d), guard::watch(&scalar(&key)));
        let lease = first_lease(&key, d);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut api = Scripted {
            replies: vec![Err(ApiError::Unavailable("connection refused".into()))],
            calls: Arc::clone(&calls),
        };
        let lapsed = paused(keep(&cfg(), &key, &mut api, &FakeQuoter, (b"t", b"l"), lease, |_| panic!("no renewal")));
        assert_eq!(lapsed.last, "connection refused");
        assert!(calls.load(Ordering::Relaxed) > 50, "backed off and retried");
        drop(key);
        assert_eq!((wd.leaks(), wk.leaks()), (0, 0));
    }
}
