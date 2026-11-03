//! The verifier: evaluates the ten checks on a cell's evidence and, when all pass,
//! issues the cell certificate and wraps the sub-environment DEK to the cell's key.
//!
//! ```no_run
//! # async fn demo(v: &verifier::Verifier<verifier::HttpSources, verifier::CloudKms>,
//! #               ev: &common::evidence::Evidence, now: u64) {
//! match v.unlock(ev, now).await {
//!     Ok(unlocked) => { /* return cert, wrapped DEK and policy bundle */ }
//!     Err(verifier::UnlockError::Refused { check, .. }) => { /* "check N" */ }
//!     Err(other) => { /* UNAVAILABLE or INVALID_ARGUMENT */ }
//! }
//! # }
//! ```

use std::sync::{Arc, RwLock};

use aws_lc_rs::digest;
use common::cellcert::CellCertInfo;
use common::ccel;
use common::cred::{self, Binding, Sealed};
use common::dek::{self, Dek};
use common::evidence::{self, Evidence, Nonce};
use common::ids::{EnvId, ReleaseId, SubenvId};
use common::jws::{JwsError, TrustedKey};
use common::release::{EXPIRY_WARNING_SECS, FragmentBundle};
use common::tdx::{Measurement, Quote};
use common::template::{self, Digest, SealedKey, TemplateKey};
use der::Decode;
use x509_cert::Certificate;

use crate::checks::{Check, Failure, Outcome, Report};
use crate::config::{Acceptance, Config};
use crate::fragments::{self, FragmentError};
use crate::kms::{Kms, KmsError};
use crate::nonce::Nonces;
use crate::policy::{Release, ReleasePolicy};
use crate::qvl::{self, PckInfo};
use crate::sources::{Collateral, SourceError, Sources};
use crate::x509::{self, CaCert, X509Error};

/// The key lease: how long a cell certificate and its DEKs are valid. The cell renews
/// by unlocking again from 45 minutes (SPEC.md "Keys are leased for 60 minutes").
pub const LEASE_SECS: u64 = 3600;
/// Check 2: CRLs must have been fetched within the last hour.
pub const COLLATERAL_MAX_AGE_SECS: u64 = 3600;

/// What an unlocked cell receives.
#[derive(Debug, Clone)]
pub struct Unlocked {
    pub cell_cert: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub policy_bundle: Vec<u8>,
    pub policy_sig: String,
    /// The customer's policy public key (PEM).
    pub policy_key: String,
    pub release: ReleaseId,
    /// The release's `valid_until` (Unix seconds): the cell refuses sandboxes whose
    /// timeout would reach it.
    pub release_valid_until: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    #[error("refused by {check}")]
    Refused { check: Check, report: Box<Report> },
    #[error("unknown sub-environment {0}")]
    UnknownSubenv(SubenvId),
    #[error(transparent)]
    Unavailable(#[from] SourceError),
    #[error("issuing the certificate: {0}")]
    Certificate(#[from] X509Error),
    #[error("decrypting the DEK: {0}")]
    Kms(#[from] KmsError),
    #[error("wrapping the DEK: {0}")]
    Dek(#[from] dek::DekError),
    #[error("configured DEK ciphertext is not base64: {0}")]
    DekCiphertext(#[from] common::b64::Base64Error),
}

/// Why a verifier could not be set up from its configuration.
#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    #[error("environment CA: {0}")]
    Ca(#[from] X509Error),
    #[error("{what}: {source}")]
    Key { what: &'static str, source: JwsError },
}

/// A pinned release that expires within [`EXPIRY_WARNING_SECS`], or has expired: the
/// customer must pin a newer release before then (SPEC.md "Releases expire").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiryWarning {
    pub release: ReleaseId,
    pub valid_until: u64,
    pub expired: bool,
}

/// Why a credential or a template key was not sealed.
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("unknown sub-environment {0}")]
    UnknownSubenv(SubenvId),
    #[error(transparent)]
    Credential(#[from] cred::CredError),
    #[error(transparent)]
    Template(#[from] template::TemplateError),
    #[error("decrypting the DEK: {0}")]
    Kms(#[from] KmsError),
    #[error("the DEK: {0}")]
    Dek(#[from] dek::DekError),
    #[error("configured DEK ciphertext is not base64: {0}")]
    DekCiphertext(#[from] common::b64::Base64Error),
}

/// A verifier for one environment, with its seams: the quote trust root, the
/// collateral, registry and endorsement sources, and the key manager. The clock is the
/// `now` (Unix seconds) every call takes.
pub struct Verifier<S, K> {
    config: Config,
    /// The signed release policy the verifier started with.
    base: ReleasePolicy,
    /// `base` with the releases of every applied fragment: what checks 6, 9 and 10
    /// read. Swapped whole when fragments are loaded.
    policy: RwLock<Arc<ReleasePolicy>>,
    release_keys: Vec<TrustedKey>,
    rekor_keys: Vec<TrustedKey>,
    trust_root: Vec<u8>,
    google_root: Vec<u8>,
    ca: CaCert,
    sources: S,
    kms: K,
    nonces: Nonces,
}

impl<S: Sources, K: Kms> Verifier<S, K> {
    /// `trust_root` is Intel's SGX root CA in production (DER); `google_root` is
    /// GCE-cc-tcb-root_1.
    pub fn new(
        config: Config,
        policy: ReleasePolicy,
        trust_root: Vec<u8>,
        google_root: Vec<u8>,
        sources: S,
        kms: K,
    ) -> Result<Self, SetupError> {
        let keys = |what, pems: &[String]| {
            pems.iter()
                .map(|p| TrustedKey::from_pem(p))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|source| SetupError::Key { what, source })
        };
        Ok(Self {
            ca: CaCert::from_pem(&config.ca.cert_pem)?,
            release_keys: keys("release_keys", &config.release_keys)?,
            rekor_keys: keys("rekor_keys", &config.rekor_keys)?,
            config,
            policy: RwLock::new(Arc::new(policy.clone())),
            base: policy,
            trust_root,
            google_root,
            sources,
            kms,
            nonces: Nonces::default(),
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The release policy now in force: the signed policy and every applied fragment.
    pub fn policy(&self) -> Arc<ReleasePolicy> {
        Arc::clone(&self.policy.read().unwrap_or_else(|p| p.into_inner()))
    }

    /// Verifies every bundle and puts the signed policy plus the releases of those that
    /// pass in force, replacing what earlier loads applied. Returns each bundle's
    /// outcome, in order, for the log.
    pub fn load_fragments(&self, bundles: &[FragmentBundle]) -> Vec<Result<ReleaseId, FragmentError>> {
        let results: Vec<_> = bundles
            .iter()
            .map(|b| fragments::verify(b, &self.release_keys, &self.rekor_keys))
            .collect();
        let applied: Vec<_> = results.iter().filter_map(|r| r.as_ref().ok()).cloned().collect();
        let next = Arc::new(self.base.with_fragments(&applied));
        *self.policy.write().unwrap_or_else(|p| p.into_inner()) = next;
        results.into_iter().map(|r| r.map(|a| a.release.id)).collect()
    }

    /// Pinned releases that expire within seven days of `now`, or have expired. An
    /// unpinned verifier warns of nothing: it moves to newer releases by itself.
    pub fn expiry_warnings(&self, now: u64) -> Vec<ExpiryWarning> {
        let Acceptance::Pinned(pins) = self.config.acceptance() else {
            return Vec::new();
        };
        let policy = self.policy();
        pins.iter()
            .filter_map(|id| policy.release(id))
            .filter(|r| now.saturating_add(EXPIRY_WARNING_SECS) >= r.valid_until)
            .map(|r| ExpiryWarning {
                release: r.id.clone(),
                valid_until: r.valid_until,
                expired: now >= r.valid_until,
            })
            .collect()
    }

    pub fn nonces(&self) -> &Nonces {
        &self.nonces
    }

    /// The environment CA certificate (DER).
    pub fn ca_der(&self) -> &[u8] {
        &self.ca.der
    }

    /// A nonce for an unlock in `env`, or `None` if this verifier does not serve it.
    pub fn issue_nonce(&self, env: &EnvId, now: u64) -> Option<Nonce> {
        (env == &self.config.env).then(|| self.nonces.issue(env, now, self.base.nonce_ttl_secs))
    }

    /// Runs all ten checks. Spends the evidence's nonce. Fails only when a source is
    /// unreachable.
    pub async fn check(&self, ev: &Evidence, now: u64) -> Result<Report, SourceError> {
        self.check_under(&self.policy(), ev, now).await
    }

    /// [`Self::check`] under one snapshot of the policy, so an unlock reads the same
    /// release throughout.
    async fn check_under(&self, policy: &ReleasePolicy, ev: &Evidence, now: u64) -> Result<Report, SourceError> {
        let mut r = Report::default();
        let quote = match Quote::parse(&ev.quote) {
            Ok(q) => q,
            Err(e) => {
                r.fail(Check::Quote, Failure::QuoteParse(e.to_string()));
                skip_all_but(&mut r, Check::Quote);
                return Ok(r);
            }
        };
        let platform = match Platform::of(&ev.quote) {
            Ok(p) => p,
            Err(e) => {
                r.fail(Check::Quote, Failure::Signatures(e));
                skip_all_but(&mut r, Check::Quote);
                return Ok(r);
            }
        };
        let collateral = self
            .sources
            .collateral(&platform.fmspc, platform.ca, now)
            .await?;

        // Check 2 decides whether the chain is revoked; check 1 then verifies the
        // signatures. A chain is only trusted with usable CRLs, so check 1 is skipped
        // when check 2 fails.
        let collateral_ok = collateral_check(&collateral, &platform, &self.trust_root, now);
        let verified = if collateral_ok == Outcome::Pass {
            match qvl::verify_signatures(&ev.quote, &collateral, &self.trust_root, now) {
                Ok(v) => {
                    r.set(Check::Quote, Outcome::Pass);
                    Some(v)
                }
                Err(e) => {
                    r.fail(Check::Quote, Failure::Signatures(e));
                    None
                }
            }
        } else {
            r.set(Check::Quote, Outcome::Skipped(Check::Collateral));
            None
        };
        r.set(Check::Collateral, collateral_ok);

        r.set(
            Check::Tcb,
            match &verified {
                None => Outcome::Skipped(Check::Quote),
                Some(v) => match qvl::tcb_status(v) {
                    Ok(t) => self.tcb(&t.status.to_string(), &t.advisories),
                    Err(e) => Outcome::Fail(Failure::TcbEvaluation(e)),
                },
            },
        );
        r.set(Check::Attributes, self.attributes(&quote));
        r.set(Check::Firmware, self.firmware(&quote.mr_td, now).await?);

        let release = policy.release(&ev.release);
        r.set(Check::Measurements, measurements(ev, &quote, release));
        let ppid = verified.as_ref().map(|v| common::hex(&v.pck.ppid));
        r.set(
            Check::Owner,
            self.owner(ev, &quote, ppid.as_deref(), &platform.ppid, now).await?,
        );
        r.set(Check::Binding, self.binding(ev, &quote, now));
        let (window, expiry) = self.window(&ev.release, release, now);
        r.set(Check::Window, window);
        r.set(Check::Expiry, expiry);
        Ok(r)
    }

    /// Checks `ev` and, if every check passes, issues the cell's certificate and
    /// wraps its sub-environment's DEK to the cell key.
    pub async fn unlock(&self, ev: &Evidence, now: u64) -> Result<(Unlocked, Report), UnlockError> {
        let subenv = self
            .config
            .subenvs
            .get(&ev.subenv)
            .ok_or_else(|| UnlockError::UnknownSubenv(ev.subenv.clone()))?;
        let policy = self.policy();
        let report = self.check_under(&policy, ev, now).await?;
        if let Some((check, _)) = report.first_failure() {
            return Err(UnlockError::Refused {
                check,
                report: Box::new(report),
            });
        }
        let info = CellCertInfo {
            quote_sha256: digest::digest(&digest::SHA256, &ev.quote)
                .as_ref()
                .try_into()
                .expect("SHA-256 is 32 bytes"),
            env: ev.env.clone(),
            subenv: ev.subenv.clone(),
            release: ev.release.clone(),
        };
        let request = x509::CellRequest {
            spki: ev.spki.der(),
            dns: &evidence::cell_dns_name(&ev.env, &ev.subenv),
            info: &info,
            now,
            not_after: now + LEASE_SECS,
        };
        let release_valid_until = policy
            .release(&ev.release)
            .expect("check 9 passed under this policy, so it knows the release")
            .valid_until;
        let ciphertext = common::b64::decode(&subenv.wrapped_dek)?;
        let (cell_cert, mut plain) = tokio::try_join!(
            async { Ok::<_, UnlockError>(x509::cell_cert(&self.kms, &self.ca, &self.config.ca.kms_key, &request).await?) },
            async { Ok::<_, UnlockError>(self.kms.decrypt(&self.config.dek_kms_key, &ciphertext).await?) },
        )?;
        let dek = Dek::copy_from(&plain);
        dek::wipe(&mut plain);
        let wrapped_dek = dek::wrap(&dek?, &ev.spki, &ev.env, &ev.subenv)?;
        Ok((
            Unlocked {
                cell_cert,
                wrapped_dek,
                policy_bundle: subenv.policy_bundle.as_bytes().to_vec(),
                policy_sig: subenv.policy_sig.clone(),
                policy_key: self.config.policy_key_pem.clone(),
                release: ev.release.clone(),
                release_valid_until,
            },
            report,
        ))
    }

    /// The sub-environment's current policy bundle and its detached JWS, as configured
    /// (cells verify it; the verifier only serves it).
    pub fn policy_bundle(&self, subenv: &SubenvId) -> Option<(&str, &str)> {
        self.config
            .subenvs
            .get(subenv)
            .map(|s| (s.policy_bundle.as_str(), s.policy_sig.as_str()))
    }

    /// Seals a credential under `subenv`'s DEK for `binding` (`SealCredential`).
    pub async fn seal_credential(&self, subenv: &SubenvId, binding: &Binding, secret: &[u8]) -> Result<Sealed, SealError> {
        let dek = self.subenv_dek(subenv).await?;
        Ok(cred::seal(&dek, &self.config.env, subenv, binding, secret)?)
    }

    /// A fresh key for the template with plaintext digest `digest`, and the same key
    /// sealed under `subenv`'s DEK and bound to the digest (`SealTemplateKey`).
    pub async fn seal_template_key(&self, subenv: &SubenvId, digest: &Digest) -> Result<(TemplateKey, SealedKey), SealError> {
        let dek = self.subenv_dek(subenv).await?;
        Ok(template::seal_key(&dek, &self.config.env, subenv, digest)?)
    }

    /// `subenv`'s DEK, decrypted with KMS for each call; the plaintext is wiped, and the
    /// [`Dek`] wipes itself on drop.
    async fn subenv_dek(&self, subenv: &SubenvId) -> Result<Dek, SealError> {
        let config = self
            .config
            .subenvs
            .get(subenv)
            .ok_or_else(|| SealError::UnknownSubenv(subenv.clone()))?;
        let ciphertext = common::b64::decode(&config.wrapped_dek)?;
        let mut plain = self.kms.decrypt(&self.config.dek_kms_key, &ciphertext).await?;
        let dek = Dek::copy_from(&plain);
        dek::wipe(&mut plain);
        Ok(dek?)
    }

    /// Check 3: `UpToDate`, or `SWHardeningNeeded` with only allow-listed advisories.
    fn tcb(&self, status: &str, advisories: &[String]) -> Outcome {
        let allowed = |a: &String| self.base.sw_hardening_advisories.contains(a);
        match status {
            "UpToDate" => Outcome::Pass,
            "SWHardeningNeeded" if advisories.iter().all(allowed) => Outcome::Pass,
            _ => Outcome::Fail(Failure::TcbStatus {
                status: status.to_owned(),
                advisories: advisories.to_vec(),
            }),
        }
    }

    /// Check 4.
    fn attributes(&self, q: &Quote) -> Outcome {
        let p = &self.base;
        if q.debug() {
            Outcome::Fail(Failure::Debug)
        } else if q.xfam != p.xfam {
            Outcome::Fail(Failure::Xfam {
                quoted: q.xfam,
                policy: p.xfam,
            })
        } else if !p.mrseam.contains(&q.mr_seam) {
            Outcome::Fail(Failure::MrSeam(q.mr_seam))
        } else if q.tee_tcb_svn.iter().zip(&p.tee_tcb_svn_floor).any(|(q, f)| q < f) {
            Outcome::Fail(Failure::TeeTcbSvn {
                quoted: q.tee_tcb_svn,
                floor: p.tee_tcb_svn_floor,
            })
        } else {
            Outcome::Pass
        }
    }

    /// Check 5.
    async fn firmware(&self, mrtd: &Measurement, now: u64) -> Result<Outcome, SourceError> {
        let Some(serialized) = self.sources.endorsement(mrtd).await? else {
            return Ok(Outcome::Fail(Failure::NoEndorsement(*mrtd)));
        };
        Ok(
            match common::endorsement::verify(&serialized, &self.google_root, now) {
                Err(e) => Outcome::Fail(Failure::Endorsement(e.to_string())),
                Ok(g) if g.mrtds.contains(mrtd) => Outcome::Pass,
                Ok(_) => Outcome::Fail(Failure::MrtdNotEndorsed(*mrtd)),
            },
        )
    }

    /// Check 7. `verified_ppid` comes from a chain check 1 verified; without one, the
    /// PPID in the quote's PCK certificate is looked up anyway, but can only refuse:
    /// the check is then skipped rather than passed.
    async fn owner(
        &self,
        ev: &Evidence,
        q: &Quote,
        verified_ppid: Option<&str>,
        quote_ppid: &str,
        now: u64,
    ) -> Result<Outcome, SourceError> {
        if !self.base.allowed_zones.contains(&ev.zone) {
            return Ok(Outcome::Fail(Failure::ZoneNotAllowed(ev.zone.clone())));
        }
        let ppid = verified_ppid.unwrap_or(quote_ppid);
        if !self.sources.host_registered(ppid, now).await? {
            return Ok(Outcome::Fail(Failure::PpidNotRegistered(ppid.to_owned())));
        }
        let expected = mr_owner(ev.instance_id, self.base.project_number, &ev.zone);
        if q.mr_owner != expected {
            return Ok(Outcome::Fail(Failure::MrOwner {
                quoted: q.mr_owner,
                expected,
            }));
        }
        Ok(if verified_ppid.is_some() {
            Outcome::Pass
        } else {
            Outcome::Skipped(Check::Quote)
        })
    }

    /// Check 8. The nonce is spent whether or not REPORTDATA matches.
    fn binding(&self, ev: &Evidence, q: &Quote, now: u64) -> Outcome {
        let nonce = self
            .nonces
            .consume(&ev.nonce, &ev.env, now, self.base.nonce_ttl_secs);
        if q.report_data != evidence::report_data(&ev.env, &ev.spki, &ev.nonce) {
            Outcome::Fail(Failure::ReportData)
        } else if let Err(f) = nonce {
            Outcome::Fail(Failure::Nonce(f))
        } else {
            Outcome::Pass
        }
    }

    /// Checks 9 and 10. Unpinned, a release is accepted once its notice window has
    /// ended; pinned, exactly the pinned releases are, at once. Expiry applies to both.
    fn window(&self, id: &ReleaseId, release: Option<&Release>, now: u64) -> (Outcome, Outcome) {
        let Some(rel) = release else {
            return (
                Outcome::Fail(Failure::UnknownRelease(id.clone())),
                Outcome::Skipped(Check::Window),
            );
        };
        let window = match self.config.acceptance() {
            Acceptance::Pinned(pins) if pins.contains(id) => Outcome::Pass,
            Acceptance::Pinned(_) => Outcome::Fail(Failure::NotPinned(id.clone())),
            Acceptance::Window if now >= rel.open_at() => Outcome::Pass,
            Acceptance::Window => Outcome::Fail(Failure::NoticeWindow {
                open_at: rel.open_at(),
                now,
            }),
        };
        let expiry = if now < rel.valid_until {
            Outcome::Pass
        } else {
            Outcome::Fail(Failure::ReleaseExpired {
                valid_until: rel.valid_until,
                now,
            })
        };
        (window, expiry)
    }
}

/// Check 6: replay proves the log is faithful to the quote; equality with the
/// release's published values catches a changed command line, root hash, firmware or
/// Secure Boot state. Neither half is ever relaxed. RTMR0 must equal one of the
/// release's canary-recorded values (one per host firmware it runs on).
fn measurements(ev: &Evidence, q: &Quote, release: Option<&Release>) -> Outcome {
    if let Err(e) = ccel::replay_against(&ev.ccel_table, &ev.ccel_log, &q.rtmrs) {
        return Outcome::Fail(Failure::CcelReplay(e.to_string()));
    }
    let Some(rel) = release else {
        return Outcome::Skipped(Check::Window);
    };
    let differ: Vec<usize> = (0..4)
        .filter(|&i| if i == 0 { !rel.accepts_rtmr0(&q.rtmrs[0]) } else { q.rtmrs[i] != rel.rtmr[i] })
        .collect();
    if differ.is_empty() {
        Outcome::Pass
    } else {
        Outcome::Fail(Failure::RtmrMismatch(differ))
    }
}

/// What GCE writes to MR_OWNER: SHA-384 of the instance's project, zone and instance
/// (go-tdx-guest `gce.PZIDPayload`). Zones are DNS labels, so no JSON escaping arises.
pub fn mr_owner(instance_id: u64, project_number: u64, zone: &common::ids::Zone) -> Measurement {
    Measurement::sha384(
        format!(r#"{{"instanceId":{instance_id},"numericalProjectId":{project_number},"zone":"{zone}"}}"#)
            .as_bytes(),
    )
}

fn skip_all_but(r: &mut Report, failed: Check) {
    for c in Check::ALL.into_iter().filter(|&c| c != failed) {
        r.set(c, Outcome::Skipped(failed));
    }
}

/// The platform a quote comes from: its PCK certificate and issuing CA, and the
/// collateral lookup keys.
struct Platform {
    fmspc: String,
    ca: &'static str,
    /// From the quote's PCK certificate, before any check has verified it.
    ppid: String,
    leaf: Certificate,
    pck_ca: Certificate,
}

impl Platform {
    fn of(raw: &[u8]) -> Result<Self, qvl::QvlError> {
        let (leaf, pck_ca) = qvl::pck_certificates(raw)?;
        let pck = PckInfo::of(&leaf)?;
        let issuer = pck_ca.tbs_certificate().subject().to_string();
        Ok(Self {
            fmspc: common::hex(&pck.fmspc).to_uppercase(),
            ca: if issuer.contains("Platform") { "platform" } else { "processor" },
            ppid: common::hex(&pck.ppid),
            leaf,
            pck_ca,
        })
    }
}

/// Check 2: fetched within the hour, both CRLs signed by their issuers and current,
/// neither revoking the chain.
fn collateral_check(c: &Collateral, p: &Platform, root: &[u8], now: u64) -> Outcome {
    let root = match Certificate::from_der(root) {
        Ok(r) => r,
        Err(e) => return Outcome::Fail(Failure::CollateralUnusable(format!("trust root: {e}"))),
    };
    if now.saturating_sub(c.fetched_at) > COLLATERAL_MAX_AGE_SECS {
        return Outcome::Fail(Failure::CollateralStale {
            fetched_at: c.fetched_at,
            now,
        });
    }
    for (name, der, issuer, cert) in [
        ("root CA CRL", &c.root_ca_crl, &root, &p.pck_ca),
        ("PCK CRL", &c.pck_crl, &p.pck_ca, &p.leaf),
    ] {
        let crl = match qvl::chain::verify_crl(der, issuer) {
            Ok(crl) => crl,
            Err(e) => return Outcome::Fail(Failure::CollateralUnusable(format!("{name}: {e}"))),
        };
        let tbs = &crl.tbs_cert_list;
        // As Intel QVL: the CRL's issuer is the certificate's issuer.
        if &tbs.issuer != cert.tbs_certificate().issuer() {
            return Outcome::Fail(Failure::CollateralUnusable(format!(
                "{name} is issued by {}, the certificate by {}",
                tbs.issuer,
                cert.tbs_certificate().issuer()
            )));
        }
        let this_update = tbs.this_update.to_unix_duration().as_secs();
        let next_update = tbs.next_update.map(|t| t.to_unix_duration().as_secs());
        if now < this_update || next_update.is_none_or(|n| now > n) {
            return Outcome::Fail(Failure::CrlNotCurrent {
                crl: name,
                this_update,
                next_update,
                now,
            });
        }
        let serial = cert.tbs_certificate().serial_number();
        let revoked = tbs
            .revoked_certificates
            .iter()
            .flatten()
            .any(|r| &r.serial_number == serial);
        if revoked {
            let serial = common::hex(serial.as_bytes());
            return Outcome::Fail(if name == "PCK CRL" {
                Failure::PckRevoked { serial }
            } else {
                Failure::PckCaRevoked { serial }
            });
        }
    }
    Outcome::Pass
}

/// Checks 9 and 10 for releases that arrive as fragments, under an injected clock:
/// `now` is an hour count from when the log integrated the release (SPEC.md phase 5
/// criteria 3, 4, 5 and 7).
#[cfg(test)]
mod release_window {
    use std::collections::BTreeMap;

    use common::release::{DEFAULT_VALID_SECS, SUPERSEDED_GRACE_SECS, Supersession, Window};

    use super::*;
    use crate::config::{Ca, Subenv};
    use crate::fragments::tests::{Key, bundle, payload};
    use crate::kms::LocalKms;
    use crate::sources::Collateral;

    const H: u64 = 3600;
    /// When the log integrated the previous release, and three days later the release.
    const PREV_AT: u64 = 1_800_000_000;
    const AT: u64 = PREV_AT + 72 * H;

    struct Offline;

    impl Sources for Offline {
        async fn collateral(&self, _: &str, _: &str, _: u64) -> Result<Collateral, SourceError> {
            unreachable!("checks 9 and 10 fetch nothing")
        }
        async fn host_registered(&self, _: &str, _: u64) -> Result<bool, SourceError> {
            unreachable!("checks 9 and 10 fetch nothing")
        }
        async fn endorsement(&self, _: &Measurement) -> Result<Option<Vec<u8>>, SourceError> {
            unreachable!("checks 9 and 10 fetch nothing")
        }
    }

    /// Our release key and the log's, as one release pipeline and one Rekor.
    struct World {
        us: Key,
        log: Key,
    }

    impl World {
        fn new() -> Self {
            Self { us: Key::new(), log: Key::new() }
        }

        /// A verifier trusting our key and the log, pinned to `pinned`, with no fragments.
        fn verifier(&self, pinned: &[&str]) -> Verifier<Offline, LocalKms> {
            let ca_key = rcgen::KeyPair::generate().unwrap();
            let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let config = Config {
                env: "staging".parse().unwrap(),
                subenvs: BTreeMap::from([(
                    "a".parse().unwrap(),
                    Subenv { wrapped_dek: String::new(), policy_bundle: "{}".into(), policy_sig: String::new() },
                )]),
                ca: Ca { kms_key: "ca".into(), cert_pem: common::b64::pem("CERTIFICATE", p.self_signed(&ca_key).unwrap().der()) },
                dek_kms_key: "dek".into(),
                release_keys: vec![self.us.pem()],
                policy_key_pem: String::new(),
                sdk_token_sha256: None,
                pinned_releases: pinned.iter().map(|r| r.parse().unwrap()).collect(),
                fragments_url: None,
                rekor_keys: vec![self.log.pem()],
                collateral_cache_secs: 0,
            };
            let policy: ReleasePolicy = serde_json::from_value(serde_json::json!({
                "v": 1, "project_number": 123456789012u64, "allowed_zones": ["us-central1-a"], "xfam": 0,
                "mrseam": [], "tee_tcb_svn_floor": "00".repeat(16), "sw_hardening_advisories": [],
                "nonce_ttl_secs": 300, "endorsements_url": "https://example.invalid/", "releases": []
            }))
            .unwrap();
            Verifier::new(config, policy, vec![], vec![], Offline, LocalKms::generate(&[])).unwrap()
        }

        /// A fragment the pipeline would publish for `release`, logged at `at`.
        fn fragment(&self, release: &str, seed: u8, window: Window, at: u64, supersedes: Vec<Supersession>) -> FragmentBundle {
            bundle(&self.us, &self.log, &payload(release, seed), window, at, at + DEFAULT_VALID_SECS, supersedes)
        }

        /// The previous release and the release, both regular.
        fn regular(&self) -> Vec<FragmentBundle> {
            vec![
                self.fragment("clovelly-0.2.0-rc.1", 10, Window::Regular, PREV_AT, vec![]),
                self.fragment("clovelly-0.2.0-rc.2", 20, Window::Regular, AT, vec![]),
            ]
        }
    }

    /// Checks 9 and 10 for `release` at `now`: whether each passed.
    fn accepts<S: Sources, K: Kms>(v: &Verifier<S, K>, release: &str, now: u64) -> (bool, bool) {
        let id: ReleaseId = release.parse().unwrap();
        let policy = v.policy();
        let (w, e) = v.window(&id, policy.release(&id), now);
        (w == Outcome::Pass, e == Outcome::Pass)
    }

    fn loaded<S: Sources, K: Kms>(v: &Verifier<S, K>, bundles: &[FragmentBundle]) {
        for r in v.load_fragments(bundles) {
            r.unwrap();
        }
    }

    /// Criterion 3.
    #[test]
    fn the_default_window_refuses_a_release_at_hour_71_and_accepts_it_at_hour_73() {
        let w = World::new();
        let v = w.verifier(&[]);
        loaded(&v, &w.regular());
        assert_eq!(accepts(&v, "clovelly-0.2.0-rc.2", AT + 71 * H), (false, true));
        assert_eq!(accepts(&v, "clovelly-0.2.0-rc.2", AT + 73 * H), (true, true));
        assert!(matches!(
            v.window(&"clovelly-0.2.0-rc.2".parse().unwrap(), v.policy().release(&"clovelly-0.2.0-rc.2".parse().unwrap()), AT + 71 * H).0,
            Outcome::Fail(Failure::NoticeWindow { open_at, .. }) if open_at == AT + 72 * H
        ));
    }

    /// Criterion 3: a pinned verifier takes no release by itself, however old.
    #[test]
    fn a_verifier_pinned_to_the_previous_release_refuses_the_release_at_hour_73() {
        let w = World::new();
        let v = w.verifier(&["clovelly-0.2.0-rc.1"]);
        loaded(&v, &w.regular());
        assert_eq!(accepts(&v, "clovelly-0.2.0-rc.2", AT + 73 * H), (false, true));
        assert_eq!(accepts(&v, "clovelly-0.2.0-rc.2", AT + 30 * 24 * H - 1), (false, true));
        assert_eq!(accepts(&v, "clovelly-0.2.0-rc.1", AT + 73 * H), (true, true), "the pinned release still unlocks");
    }

    /// Criterion 4.
    #[test]
    fn a_security_release_is_accepted_at_hour_25_and_refused_at_hour_23() {
        let w = World::new();
        let v = w.verifier(&[]);
        let sec_at = AT + 100 * H;
        let mut b = w.regular();
        b.push(w.fragment("clovelly-0.2.0-rc.3", 30, Window::Security, sec_at, vec![]));
        loaded(&v, &b);
        assert_eq!(accepts(&v, "clovelly-0.2.0-rc.3", sec_at + 23 * H), (false, true));
        assert_eq!(accepts(&v, "clovelly-0.2.0-rc.3", sec_at + 25 * H), (true, true));
    }

    /// Criterion 4: the security fragment carries each predecessor's new valid_until,
    /// its window end plus 7 days, and verifiers apply it; nothing raises one.
    #[test]
    fn a_security_release_sets_its_predecessors_valid_until_to_its_window_end_plus_7_days() {
        let w = World::new();
        let v = w.verifier(&[]);
        let sec_at = AT + 100 * H;
        let cap = sec_at + Window::Security.notice_secs() + SUPERSEDED_GRACE_SECS;
        let supersedes = ["clovelly-0.2.0-rc.1", "clovelly-0.2.0-rc.2"]
            .map(|r| Supersession { release: r.parse().unwrap(), valid_until: cap })
            .to_vec();
        let mut b = w.regular();
        b.push(w.fragment("clovelly-0.2.0-rc.3", 30, Window::Security, sec_at, supersedes));
        // A fragment cannot extend a release: this one names a later valid_until.
        let later = vec![Supersession { release: "clovelly-0.2.0-rc.2".parse().unwrap(), valid_until: cap + 86_400 }];
        b.push(w.fragment("clovelly-0.2.0", 40, Window::Regular, sec_at + H, later));
        loaded(&v, &b);
        let p = v.policy();
        for r in ["clovelly-0.2.0-rc.1", "clovelly-0.2.0-rc.2"] {
            assert_eq!(p.release(&r.parse().unwrap()).unwrap().valid_until, cap, "{r}");
        }
        assert_eq!(cap, sec_at + 24 * H + 7 * 24 * H);
        assert_eq!(accepts(&v, "clovelly-0.2.0-rc.2", cap - 1), (true, true));
        assert_eq!(accepts(&v, "clovelly-0.2.0-rc.2", cap), (true, false));
    }

    /// Criterion 5: expiry is refused pinned or not, and the pinned verifier warned 7
    /// days earlier, and not before.
    #[test]
    fn an_expired_release_is_refused_unpinned_and_pinned_and_the_pinned_verifier_warned_7_days_earlier() {
        let w = World::new();
        let (unpinned, pinned) = (w.verifier(&[]), w.verifier(&["clovelly-0.2.0-rc.2"]));
        for v in [&unpinned, &pinned] {
            loaded(v, &w.regular());
        }
        let expiry = AT + DEFAULT_VALID_SECS;
        for v in [&unpinned, &pinned] {
            assert_eq!(accepts(v, "clovelly-0.2.0-rc.2", expiry - 1), (true, true));
            assert_eq!(accepts(v, "clovelly-0.2.0-rc.2", expiry), (true, false));
        }
        let week = 7 * 24 * H;
        assert!(pinned.expiry_warnings(expiry - week - 1).is_empty(), "no warning before 7 days");
        assert_eq!(
            pinned.expiry_warnings(expiry - week),
            [ExpiryWarning { release: "clovelly-0.2.0-rc.2".parse().unwrap(), valid_until: expiry, expired: false }]
        );
        assert!(pinned.expiry_warnings(expiry)[0].expired);
        assert!(unpinned.expiry_warnings(expiry - week).is_empty(), "an unpinned verifier moves on by itself");
    }

    /// Criterion 7: a fragment with our valid signature but no inclusion proof never
    /// enters the policy, so its release is unknown to check 9.
    #[test]
    fn a_fragment_with_a_valid_signature_but_no_inclusion_proof_is_not_applied() {
        let w = World::new();
        let v = w.verifier(&[]);
        let mut b = w.regular();
        b[1].rekor = None;
        let results = v.load_fragments(&b);
        assert!(results[0].is_ok());
        assert!(matches!(results[1], Err(FragmentError::NoInclusionProof)));
        let id: ReleaseId = "clovelly-0.2.0-rc.2".parse().unwrap();
        assert!(v.policy().release(&id).is_none());
        assert!(matches!(v.window(&id, None, AT + 73 * H).0, Outcome::Fail(Failure::UnknownRelease(_))));
        // Reloading with the proof puts it in force.
        loaded(&v, &w.regular());
        assert_eq!(accepts(&v, "clovelly-0.2.0-rc.2", AT + 73 * H), (true, true));
    }
}
