//! Entries in Sigstore's Rekor transparency log (API v1): the inclusion proof against a
//! signed checkpoint, the signed entry timestamp, and the body of a `dsse` entry.
//!
//! A release's policy fragment carries the Rekor entry of its payload. The verifier
//! applies the fragment only if [`LogEntry::verify`] passes under a log key it trusts
//! (SPEC.md phase 5 criterion 7): the entry's leaf is in the tree the log signed, and
//! the log signed the time it integrated the entry, which starts the notice window.
//!
//! ```no_run
//! # fn demo(entry: &common::rekor::LogEntry, keys: &[common::jws::TrustedKey]) {
//! let logged = entry.verify(keys).expect("in a log we trust");
//! let dsse = common::rekor::DsseBody::parse(&logged.body).expect("a dsse entry");
//! # }
//! ```

use aws_lc_rs::digest::{self, SHA256};
use serde::{Deserialize, Serialize};

use crate::b64;
use crate::jws::TrustedKey;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RekorError {
    #[error("entry is from log {0}, which is not trusted")]
    UnknownLog(String),
    #[error("entry has no inclusion proof")]
    NoInclusionProof,
    #[error("entry has no signed entry timestamp")]
    NoTimestamp,
    #[error("{0} is not valid base64 or hex")]
    Encoding(&'static str),
    #[error("inclusion proof does not lead to the root hash it names")]
    ProofMismatch,
    #[error("checkpoint: {0}")]
    Checkpoint(&'static str),
    #[error("signed entry timestamp does not verify")]
    Timestamp,
    #[error("entry body: {0}")]
    Body(String),
}

/// One log entry as Rekor's API returns it (`GET /api/v1/log/entries/{uuid}` and the
/// `POST` that creates it), without the response's `{uuid: …}` wrapper. Fields Rekor
/// adds that we do not check (`attestation`) are kept out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    /// The canonicalised entry, base64.
    pub body: String,
    pub integrated_time: u64,
    /// Hex SHA-256 of the log's public key (PKIX DER).
    #[serde(rename = "logID")]
    pub log_id: String,
    /// The entry's index across all of the log's shards; the inclusion proof's own
    /// index is within the active shard.
    pub log_index: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<Verification>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verification {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inclusion_proof: Option<InclusionProof>,
    /// Base64 DER ECDSA signature by the log over the entry's body, time and index.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_entry_timestamp: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InclusionProof {
    /// The log's signed note for `tree_size` and `root_hash`.
    pub checkpoint: String,
    /// Hex SHA-256 sibling hashes, leaf to root.
    pub hashes: Vec<String>,
    pub log_index: u64,
    pub root_hash: String,
    pub tree_size: u64,
}

/// What a verified entry establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Logged {
    /// The canonicalised entry the log holds.
    pub body: Vec<u8>,
    /// When the log integrated the entry (Unix seconds), as the log signed it.
    pub integrated_time: u64,
    pub log_index: u64,
}

impl LogEntry {
    /// The single entry in a Rekor API response (`{uuid: entry}`), and its uuid.
    pub fn from_response(json: &[u8]) -> Result<(String, Self), RekorError> {
        let map: std::collections::BTreeMap<String, Self> =
            serde_json::from_slice(json).map_err(|e| RekorError::Body(e.to_string()))?;
        let mut entries = map.into_iter();
        match (entries.next(), entries.next()) {
            (Some(one), None) => Ok(one),
            _ => Err(RekorError::Body("the response does not hold exactly one entry".into())),
        }
    }

    /// Checks that a log in `logs` holds this entry: the inclusion proof leads from the
    /// entry's leaf to a root the log signed in a checkpoint, and the log signed the
    /// entry's body, integration time and index. Both are required.
    pub fn verify(&self, logs: &[TrustedKey]) -> Result<Logged, RekorError> {
        let log = logs
            .iter()
            .find(|k| crate::hex(&sha256(k.spki_der())) == self.log_id)
            .ok_or_else(|| RekorError::UnknownLog(self.log_id.clone()))?;
        let body = b64::decode(&self.body).map_err(|_| RekorError::Encoding("body"))?;
        let v = self.verification.as_ref();
        let proof = v.and_then(|v| v.inclusion_proof.as_ref()).ok_or(RekorError::NoInclusionProof)?;
        let set = v.and_then(|v| v.signed_entry_timestamp.as_ref()).ok_or(RekorError::NoTimestamp)?;

        let root = digest32(&proof.root_hash)?;
        let path = proof.hashes.iter().map(|h| digest32(h)).collect::<Result<Vec<_>, _>>()?;
        let leaf = leaf_hash(&body);
        if root_from_inclusion(proof.log_index, proof.tree_size, leaf, &path) != Some(root) {
            return Err(RekorError::ProofMismatch);
        }
        let (size, signed_root) = checkpoint(&proof.checkpoint, log)?;
        if size != proof.tree_size || signed_root != root {
            return Err(RekorError::Checkpoint("names another tree than the proof"));
        }

        // The log signs the JCS form of these four fields.
        let payload = crate::jcs::canonical(&serde_json::json!({
            "body": self.body,
            "integratedTime": self.integrated_time,
            "logID": self.log_id,
            "logIndex": self.log_index,
        }))
        .map_err(|e| RekorError::Body(e.to_string()))?;
        let set = b64::decode(set).map_err(|_| RekorError::Encoding("signed entry timestamp"))?;
        if !log.verifies_der(&payload, &set) {
            return Err(RekorError::Timestamp);
        }
        Ok(Logged {
            body,
            integrated_time: self.integrated_time,
            log_index: self.log_index,
        })
    }
}

/// The body of a `dsse` entry (v0.0.1): the hash of the payload the envelope signs, and
/// each signature with the public key that made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsseBody {
    pub payload_sha256: [u8; 32],
    pub signatures: Vec<DsseSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsseSignature {
    /// DER ECDSA signature over the envelope's PAE.
    pub signature: Vec<u8>,
    /// The signer's public key as Rekor holds it: PEM.
    pub verifier_pem: String,
}

impl DsseBody {
    pub fn parse(body: &[u8]) -> Result<Self, RekorError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Body {
            api_version: String,
            kind: String,
            spec: Spec,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Spec {
            payload_hash: Hash,
            signatures: Vec<Sig>,
        }
        #[derive(Deserialize)]
        struct Hash {
            algorithm: String,
            value: String,
        }
        #[derive(Deserialize)]
        struct Sig {
            signature: String,
            verifier: String,
        }
        let b: Body = serde_json::from_slice(body).map_err(|e| RekorError::Body(e.to_string()))?;
        if b.kind != "dsse" || b.api_version != "0.0.1" {
            return Err(RekorError::Body(format!("a {} v{} entry, not dsse v0.0.1", b.kind, b.api_version)));
        }
        if b.spec.payload_hash.algorithm != "sha256" {
            return Err(RekorError::Body("payload hash is not SHA-256".into()));
        }
        let signatures = b
            .spec
            .signatures
            .into_iter()
            .map(|s| {
                let pem = b64::decode(&s.verifier).map_err(|_| RekorError::Encoding("dsse verifier"))?;
                Ok(DsseSignature {
                    signature: b64::decode(&s.signature).map_err(|_| RekorError::Encoding("dsse signature"))?,
                    verifier_pem: String::from_utf8(pem).map_err(|_| RekorError::Encoding("dsse verifier"))?,
                })
            })
            .collect::<Result<_, RekorError>>()?;
        Ok(Self {
            payload_sha256: digest32(&b.spec.payload_hash.value)?,
            signatures,
        })
    }
}

/// DSSE's pre-authentication encoding of a payload: what a DSSE signature signs.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = format!("DSSEv1 {} {payload_type} {} ", payload_type.len(), payload.len()).into_bytes();
    out.extend_from_slice(payload);
    out
}

/// RFC 9162 leaf hash: SHA-256(0x00 || entry).
pub fn leaf_hash(entry: &[u8]) -> [u8; 32] {
    let mut ctx = digest::Context::new(&SHA256);
    ctx.update(&[0]);
    ctx.update(entry);
    to32(ctx.finish())
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut ctx = digest::Context::new(&SHA256);
    ctx.update(&[1]);
    ctx.update(left);
    ctx.update(right);
    to32(ctx.finish())
}

/// The root an inclusion proof leads to from `leaf` at `index` in a tree of `size`
/// leaves (RFC 9162 section 2.1.3.2), or `None` if the proof has the wrong shape.
pub fn root_from_inclusion(index: u64, size: u64, leaf: [u8; 32], path: &[[u8; 32]]) -> Option<[u8; 32]> {
    if index >= size {
        return None;
    }
    let (mut fn_, mut sn) = (index, size - 1);
    let mut r = leaf;
    for p in path {
        if sn == 0 {
            return None;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = node_hash(p, &r);
            while fn_ & 1 == 0 && fn_ != 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    (sn == 0).then_some(r)
}

/// Verifies a Rekor checkpoint (a signed note: origin, tree size, base64 root hash,
/// optional extra lines, a blank line, then `— <name> <base64(key hash || sig)>`
/// lines) under `log` and returns its tree size and root hash.
fn checkpoint(note: &str, log: &TrustedKey) -> Result<(u64, [u8; 32]), RekorError> {
    let (text, sigs) = note.split_once("\n\n").ok_or(RekorError::Checkpoint("no signature block"))?;
    let text = format!("{text}\n");
    let mut lines = text.lines();
    let _origin = lines.next().filter(|l| !l.is_empty()).ok_or(RekorError::Checkpoint("no origin"))?;
    let size = lines
        .next()
        .and_then(|l| l.parse().ok())
        .ok_or(RekorError::Checkpoint("no tree size"))?;
    let root: [u8; 32] = lines
        .next()
        .and_then(|l| b64::decode(l).ok())
        .and_then(|r| r.try_into().ok())
        .ok_or(RekorError::Checkpoint("no root hash"))?;
    let hint = sha256(log.spki_der());
    let signed = sigs.lines().filter_map(|l| l.strip_prefix("— ")).any(|l| {
        let Some(sig) = l.rsplit_once(' ').and_then(|(_, s)| b64::decode(s).ok()) else {
            return false;
        };
        sig.len() > 4 && sig[..4] == hint[..4] && log.verifies_der(text.as_bytes(), &sig[4..])
    });
    if !signed {
        return Err(RekorError::Checkpoint("not signed by the log"));
    }
    Ok((size, root))
}

fn sha256(data: &[u8]) -> [u8; 32] {
    to32(digest::digest(&SHA256, data))
}

fn to32(d: digest::Digest) -> [u8; 32] {
    d.as_ref().try_into().expect("SHA-256 is 32 bytes")
}

fn digest32(hex: &str) -> Result<[u8; 32], RekorError> {
    crate::unhex(hex)
        .and_then(|b| b.try_into().ok())
        .ok_or(RekorError::Encoding("SHA-256 hash"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Leaf hashes of a tree of `n` entries `[i]`, and its RFC 9162 root.
    fn tree(n: u64) -> (Vec<[u8; 32]>, [u8; 32]) {
        let leaves: Vec<_> = (0..n).map(|i| leaf_hash(&[i as u8])).collect();
        let root = tree_root(&leaves);
        (leaves, root)
    }

    /// The largest power of two below `n` (RFC 9162's split point), for `n > 1`.
    fn split(n: usize) -> usize {
        n.next_power_of_two() / 2
    }

    fn tree_root(l: &[[u8; 32]]) -> [u8; 32] {
        if l.len() == 1 {
            return l[0];
        }
        let k = split(l.len());
        node_hash(&tree_root(&l[..k]), &tree_root(&l[k..]))
    }

    /// The audit path for leaf `m` (RFC 9162 section 2.1.3.1).
    fn path(m: usize, l: &[[u8; 32]]) -> Vec<[u8; 32]> {
        if l.len() <= 1 {
            return vec![];
        }
        let k = split(l.len());
        let (mut p, sibling) = if m < k {
            (path(m, &l[..k]), tree_root(&l[k..]))
        } else {
            (path(m - k, &l[k..]), tree_root(&l[..k]))
        };
        p.push(sibling);
        p
    }

    #[test]
    fn inclusion_proofs_verify_for_every_leaf_of_odd_and_even_trees() {
        for n in [1u64, 2, 3, 7, 8, 13] {
            let (leaves, root) = tree(n);
            for (i, leaf) in leaves.iter().enumerate() {
                let p = path(i, &leaves);
                assert_eq!(root_from_inclusion(i as u64, n, *leaf, &p), Some(root), "n={n} i={i}");
                // Another leaf, index or size does not reach the root.
                assert_ne!(root_from_inclusion(i as u64, n, leaf_hash(b"x"), &p), Some(root));
                if n > 1 {
                    assert_ne!(root_from_inclusion((i as u64 + 1) % n, n, *leaf, &p), Some(root));
                }
            }
        }
        assert_eq!(root_from_inclusion(3, 3, [0; 32], &[]), None);
    }

    /// A hashedrekord entry from Sigstore's staging log (log index 25006000, in an
    /// inactive shard), fetched with its proof, and the staging log's key.
    fn sigstage() -> (LogEntry, TrustedKey) {
        let (uuid, e) = LogEntry::from_response(include_bytes!("../tests/data/rekor-sigstage-entry.json")).unwrap();
        assert!(uuid.ends_with(&crate::hex(&leaf_hash(&b64::decode(&e.body).unwrap()))));
        (e, TrustedKey::from_pem(include_str!("../tests/data/rekor-sigstage.pub")).unwrap())
    }

    #[test]
    fn a_staging_log_entry_verifies_and_any_change_fails() {
        let (e, key) = sigstage();
        let keys = [key];
        let logged = e.verify(&keys).unwrap();
        assert_eq!((logged.integrated_time, logged.log_index), (1710625866, 25006000));

        let fails = |f: &dyn Fn(&mut LogEntry)| {
            let mut t = e.clone();
            f(&mut t);
            t.verify(&keys).unwrap_err()
        };
        let proof = |t: &mut LogEntry| t.verification.as_mut().unwrap().inclusion_proof.as_mut().unwrap().clone();
        assert_eq!(fails(&|t| t.body = b64::encode(b"{}")), RekorError::ProofMismatch);
        assert_eq!(fails(&|t| t.integrated_time += 1), RekorError::Timestamp);
        assert_eq!(fails(&|t| t.log_index += 1), RekorError::Timestamp);
        assert_eq!(fails(&|t| t.verification.as_mut().unwrap().inclusion_proof = None), RekorError::NoInclusionProof);
        assert_eq!(fails(&|t| t.verification = None), RekorError::NoInclusionProof);
        assert_eq!(fails(&|t| t.verification.as_mut().unwrap().signed_entry_timestamp = None), RekorError::NoTimestamp);
        assert!(matches!(fails(&|t| t.log_id = "00".repeat(32)), RekorError::UnknownLog(_)));
        assert_eq!(
            fails(&|t| {
                let mut p = proof(t);
                p.hashes.swap(0, 1);
                t.verification.as_mut().unwrap().inclusion_proof = Some(p);
            }),
            RekorError::ProofMismatch
        );
        // A checkpoint for another tree size, or with its signature altered.
        assert!(matches!(
            fails(&|t| {
                let mut p = proof(t);
                p.checkpoint = p.checkpoint.replacen("\n31667593\n", "\n31667594\n", 1);
                t.verification.as_mut().unwrap().inclusion_proof = Some(p);
            }),
            RekorError::Checkpoint(_)
        ));
        // A key that is not the log's does not verify, even when named by its id.
        let other = TrustedKey::from_pem(include_str!("../../verifier/roots/rekor.sigstore.dev.pub")).unwrap();
        assert!(matches!(e.verify(&[other]), Err(RekorError::UnknownLog(_))));
    }

    #[test]
    fn pae_matches_the_dsse_spec_example() {
        // From the DSSE protocol document.
        assert_eq!(
            pae("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world".to_vec()
        );
    }
}
