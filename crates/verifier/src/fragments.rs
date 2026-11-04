//! Policy fragments: how a release reaches a verifier (SPEC.md "Policy as data").
//!
//! Our pipeline publishes one [`FragmentBundle`] per release. The verifier applies a
//! bundle only when all of these hold, and refuses it otherwise:
//!
//! 1. the fragment is a JWS under one of our release keys;
//! 2. its payload parses under the closed release schema;
//! 3. the bundle carries the payload's Rekor entry, and that entry's inclusion proof,
//!    checkpoint and signed timestamp verify under a log key the customer trusts;
//! 4. the entry is a DSSE entry over exactly these payload bytes, signed by one of our
//!    release keys.
//!
//! The release's notice window starts when the log integrated the entry, so we cannot
//! backdate a release. A security release's fragment may lower its predecessors'
//! `valid_until`; nothing ever raises one.

use aws_lc_rs::digest::{self, SHA256};
use common::jws::{self, JwsError, TrustedKey};
use common::rekor::{self, DsseBody, RekorError};
use common::release::{Fragment, FragmentBundle, PAYLOAD_TYPE, PayloadError, ReleasePayload, Supersession};
use common::tdx::Measurement;

use crate::policy::Release;

#[derive(Debug, thiserror::Error)]
pub enum FragmentError {
    #[error("fragment signature: {0}")]
    Signature(#[from] JwsError),
    #[error("fragment JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("fragment payload is not base64")]
    PayloadEncoding,
    #[error(transparent)]
    Payload(#[from] PayloadError),
    #[error("fragment has no Rekor inclusion proof")]
    NoInclusionProof,
    #[error("Rekor entry: {0}")]
    Rekor(RekorError),
    #[error("the Rekor entry logs another payload")]
    PayloadNotLogged,
    #[error("the Rekor entry is not signed by a release key")]
    NotSignedByUs,
}

impl From<RekorError> for FragmentError {
    fn from(e: RekorError) -> Self {
        match e {
            RekorError::NoInclusionProof => Self::NoInclusionProof,
            e => Self::Rekor(e),
        }
    }
}

/// A fragment that passed every check: its release, and the predecessors it shortens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub release: Release,
    pub supersedes: Vec<Supersession>,
}

/// Verifies `bundle` under our `release_keys` and the trusted Rekor `logs`.
pub fn verify(bundle: &FragmentBundle, release_keys: &[TrustedKey], logs: &[TrustedKey]) -> Result<Applied, FragmentError> {
    let fragment: Fragment = serde_json::from_slice(&jws::verify(&bundle.fragment, release_keys)?)?;
    let bytes = common::b64::decode(&fragment.payload).map_err(|_| FragmentError::PayloadEncoding)?;
    let payload = ReleasePayload::parse(&bytes)?;

    let logged = bundle.rekor.as_ref().ok_or(FragmentError::NoInclusionProof)?.verify(logs)?;
    let dsse = DsseBody::parse(&logged.body)?;
    if dsse.payload_sha256.as_slice() != digest::digest(&SHA256, &bytes).as_ref() {
        return Err(FragmentError::PayloadNotLogged);
    }
    let pae = rekor::pae(PAYLOAD_TYPE, &bytes);
    let ours = dsse.signatures.iter().any(|s| {
        TrustedKey::from_pem(&s.verifier_pem).is_ok_and(|k| {
            release_keys.iter().any(|r| r.spki_der() == k.spki_der()) && k.verifies_der(&pae, &s.signature)
        })
    });
    if !ours {
        return Err(FragmentError::NotSignedByUs);
    }

    let m = &payload.measurements;
    let rtmr0 = m.firmware[0].rtmr0;
    let mut rtmr0_firmware: Vec<Measurement> = Vec::new();
    for f in &m.firmware[1..] {
        if f.rtmr0 != rtmr0 && !rtmr0_firmware.contains(&f.rtmr0) {
            rtmr0_firmware.push(f.rtmr0);
        }
    }
    Ok(Applied {
        release: Release {
            id: payload.release.id(),
            rtmr: [rtmr0, m.rtmr1, m.rtmr2, m.rtmr3],
            rtmr0_firmware,
            mrtd: m.firmware.iter().map(|f| f.mrtd).collect(),
            published_at: logged.integrated_time,
            notice_secs: fragment.window.notice_secs(),
            valid_until: fragment.valid_until,
        },
        supersedes: fragment.supersedes,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    //! Bundles made the way the pipeline makes them, logged in a test Rekor: a local
    //! key that signs checkpoints and entry timestamps over a one-leaf tree.

    use super::*;
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
    use common::b64;
    use common::evidence::Spki;
    use common::rekor::{InclusionProof, LogEntry, Verification};
    use common::release::Window;

    /// A copy of `releases/fragments.json`, byte for byte as the release pipeline commits
    /// it and verifiers fetch it.
    const PUBLISHED_INDEX: &[u8] = include_bytes!("../tests/data/fragments-public.json");

    /// The published index parses, and each bundle passes every check under the release
    /// key in this repository and the built-in public log key: a verifier given the
    /// public `fragments_url` and only those applies all of it.
    #[test]
    fn the_published_index_verifies_under_our_key_and_the_public_log() {
        let bundles: Vec<FragmentBundle> = serde_json::from_slice(PUBLISHED_INDEX).unwrap();
        let us = TrustedKey::from_pem(include_str!("../../../release/release-key.pub")).unwrap();
        let log = TrustedKey::from_pem(include_str!("../roots/rekor.sigstore.dev.pub")).unwrap();
        let ids: Vec<String> = bundles
            .iter()
            .map(|b| verify(b, std::slice::from_ref(&us), std::slice::from_ref(&log)).unwrap().release.id.to_string())
            .collect();
        assert_eq!(ids, ["clovelly-0.3.0", "clovelly-0.3.1"]);
    }

    pub struct Key(EcdsaKeyPair);

    impl Key {
        pub fn new() -> Self {
            Self(EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap())
        }
        pub fn trusted(&self) -> TrustedKey {
            TrustedKey::from_spki(Spki::from_der(self.0.public_key().as_der().unwrap().as_ref()).unwrap())
        }
        pub fn pem(&self) -> String {
            b64::pem("PUBLIC KEY", self.0.public_key().as_der().unwrap().as_ref())
        }
        pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
            self.0.sign(&SystemRandom::new(), msg).unwrap().as_ref().to_vec()
        }
        pub fn jws(&self, payload: &[u8]) -> String {
            jws::assemble(payload, &self.sign(jws::signing_input(payload).as_bytes()), false).unwrap()
        }
    }

    pub fn m(b: u8) -> String {
        common::hex(&[b; 48])
    }

    /// A payload for `release` whose RTMRs are `[b; 48]`-patterned from `seed`.
    pub fn payload(release: &str, seed: u8) -> Vec<u8> {
        let v = serde_json::json!({
            "v": 1, "release": release,
            "recipe": "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-clovelly-image-prod-unsigned.drv",
            "provenance": {
                "source": { "repository": "github.com/clovelly-io/clovelly",
                            "commit": "ec4005b0ec4005b0ec4005b0ec4005b0ec4005b0",
                            "tag": format!("v{}", &release["clovelly-".len()..]) },
                "builds": [ { "builder": "github-hosted", "run_id": 18 },
                            { "builder": "gce", "project": "example-builder", "zone": "us-central1-a",
                              "machine_type": "c3-standard-44" } ],
                "disk_sha256": common::hex(&[seed; 32]) },
            "measurements": { "firmware": [ { "mrtd": m(1), "rtmr0": m(seed) }, { "mrtd": m(2), "rtmr0": m(seed + 1) } ],
                              "rtmr1": m(seed + 2), "rtmr2": m(seed + 3), "rtmr3": m(0) }
        });
        common::jcs::canonical(&v).unwrap()
    }

    /// The Rekor entry a log keyed by `log` returns for a DSSE envelope over `payload`
    /// signed by `signer`, integrated at `at`: the entry is the only leaf of its tree.
    pub fn logged(log: &Key, signer: &Key, payload: &[u8], at: u64) -> LogEntry {
        let sig = signer.sign(&rekor::pae(PAYLOAD_TYPE, payload));
        let sha = |b: &[u8]| common::hex(digest::digest(&SHA256, b).as_ref());
        let body = serde_json::json!({
            "apiVersion": "0.0.1", "kind": "dsse",
            "spec": { "envelopeHash": { "algorithm": "sha256", "value": sha(b"envelope") },
                      "payloadHash": { "algorithm": "sha256", "value": sha(payload) },
                      "signatures": [ { "signature": b64::encode(&sig), "verifier": b64::encode(signer.pem().as_bytes()) } ] }
        });
        let body = common::jcs::canonical(&body).unwrap();
        let root = rekor::leaf_hash(&body);
        let key_hash = digest::digest(&SHA256, log.trusted().spki_der());
        let log_id = common::hex(key_hash.as_ref());
        let note = format!("test.log - 1\n1\n{}\n", b64::encode(&root));
        let signed = [&key_hash.as_ref()[..4], &log.sign(note.as_bytes())].concat();
        let checkpoint = format!("{note}\n— test.log {}\n", b64::encode(&signed));
        let body_b64 = b64::encode(&body);
        let set = common::jcs::canonical(&serde_json::json!({
            "body": body_b64, "integratedTime": at, "logID": log_id, "logIndex": 7 }))
        .unwrap();
        LogEntry {
            body: body_b64,
            integrated_time: at,
            log_id,
            log_index: 7,
            verification: Some(Verification {
                inclusion_proof: Some(InclusionProof {
                    checkpoint,
                    hashes: vec![],
                    log_index: 0,
                    root_hash: common::hex(&root),
                    tree_size: 1,
                }),
                signed_entry_timestamp: Some(b64::encode(&log.sign(&set))),
            }),
        }
    }

    pub fn bundle(
        us: &Key,
        log: &Key,
        payload: &[u8],
        window: Window,
        at: u64,
        valid_until: u64,
        supersedes: Vec<Supersession>,
    ) -> FragmentBundle {
        let f = Fragment {
            v: common::release::V1,
            payload: b64::encode(payload),
            window,
            valid_until,
            supersedes,
        };
        FragmentBundle {
            fragment: us.jws(&serde_json::to_vec(&f).unwrap()),
            rekor: Some(logged(log, us, payload, at)),
        }
    }

    #[test]
    fn a_logged_signed_fragment_applies_with_its_window_from_the_log() {
        let (us, log) = (Key::new(), Key::new());
        let b = bundle(&us, &log, &payload("clovelly-0.2.0", 10), Window::Regular, 1_000, 9_000, vec![]);
        let a = verify(&b, &[us.trusted()], &[log.trusted()]).unwrap();
        let r = &a.release;
        assert_eq!(r.id.as_str(), "clovelly-0.2.0");
        assert_eq!((r.published_at, r.notice_secs, r.valid_until), (1_000, 72 * 3600, 9_000));
        assert_eq!(r.rtmr[0].to_string(), m(10));
        assert_eq!(r.rtmr0_firmware.iter().map(ToString::to_string).collect::<Vec<_>>(), [m(11)]);
        assert_eq!(r.mrtd.len(), 2);
        let s = bundle(&us, &log, &payload("clovelly-0.2.1", 20), Window::Security, 1_000, 9_000, vec![]);
        assert_eq!(verify(&s, &[us.trusted()], &[log.trusted()]).unwrap().release.notice_secs, 24 * 3600);
    }

    /// Criterion 7: a fragment our key signed but with no Rekor inclusion proof is
    /// refused, whether the entry is missing or carries no proof.
    #[test]
    fn a_fragment_with_a_valid_signature_but_no_inclusion_proof_is_refused() {
        let (us, log) = (Key::new(), Key::new());
        let mut b = bundle(&us, &log, &payload("clovelly-0.2.0", 10), Window::Regular, 1_000, 9_000, vec![]);
        let keys = ([us.trusted()], [log.trusted()]);
        assert!(jws::verify(&b.fragment, &keys.0).is_ok(), "the fragment's signature is valid");
        let entry = b.rekor.take();
        assert!(matches!(verify(&b, &keys.0, &keys.1), Err(FragmentError::NoInclusionProof)));
        let mut no_proof = entry.unwrap();
        no_proof.verification.as_mut().unwrap().inclusion_proof = None;
        b.rekor = Some(no_proof);
        assert!(matches!(verify(&b, &keys.0, &keys.1), Err(FragmentError::NoInclusionProof)));
    }

    /// Criterion 7: an inclusion proof is not enough either: the fragment and the
    /// logged envelope must both be signed by a release key, and the log trusted.
    #[test]
    fn a_fragment_needs_our_signature_a_trusted_log_and_its_own_payload_logged() {
        let (us, log, them) = (Key::new(), Key::new(), Key::new());
        let ok = ([us.trusted()], [log.trusted()]);
        let p = payload("clovelly-0.2.0", 10);
        let mut b = bundle(&us, &log, &p, Window::Regular, 1_000, 9_000, vec![]);
        assert!(matches!(verify(&b, &[them.trusted()], &ok.1), Err(FragmentError::Signature(_))));
        assert!(matches!(verify(&b, &ok.0, &[them.trusted()]), Err(FragmentError::Rekor(RekorError::UnknownLog(_)))));
        // Our fragment over an entry someone else signed.
        b.rekor = Some(logged(&log, &them, &p, 1_000));
        assert!(matches!(verify(&b, &ok.0, &ok.1), Err(FragmentError::NotSignedByUs)));
        // Our fragment over an entry that logs another payload.
        b.rekor = Some(logged(&log, &us, &payload("clovelly-0.2.0", 30), 1_000));
        assert!(matches!(verify(&b, &ok.0, &ok.1), Err(FragmentError::PayloadNotLogged)));
        // A payload outside the closed schema never applies, even signed and logged.
        let mut v: serde_json::Value = serde_json::from_slice(&p).unwrap();
        v["notes"] = "hello".into();
        let extra = common::jcs::canonical(&v).unwrap();
        let b = bundle(&us, &log, &extra, Window::Regular, 1_000, 9_000, vec![]);
        assert!(matches!(verify(&b, &ok.0, &ok.1), Err(FragmentError::Payload(_))));
    }
}
