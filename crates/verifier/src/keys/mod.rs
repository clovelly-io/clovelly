//! What the verifier needs of whatever holds the customer's keys (`docs/key-helper.md`).
//!
//! [`Keys`] is the four operations. The verifier's only production implementation is
//! [`HelperClient`], which reaches a key helper on its loopback; the reference helpers
//! (`crates/key-helper`) implement the same trait over a key manager and serve it.
//! [`LocalKms`], built only for tests and the evidence corpus, holds keys in memory.

use std::fmt;
use std::future::Future;

use aws_lc_rs::digest;
use common::evidence::Spki;
use common::jws::TrustedKey;

mod client;
#[cfg(any(test, feature = "test-keys"))]
mod local;
pub mod wire;

pub use client::{HelperClient, KeysUrl, NotLoopback, TIMEOUT};
#[cfg(any(test, feature = "test-keys"))]
pub use local::LocalKms;

/// A key operation, for errors and logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Sign,
    Decrypt,
    Encrypt,
    PublicKey,
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Op::Sign => "sign",
            Op::Decrypt => "decrypt",
            Op::Encrypt => "encrypt",
            Op::PublicKey => "public-key",
        })
    }
}

/// Why a key operation did not happen. The first three are the contract's errors; the
/// others are a helper that broke it. Every one of them fails an unlock closed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// This name is not a key the helper serves.
    #[error("{op} on {key}: no such key")]
    NoSuchKey { op: Op, key: String },
    /// The key exists and the key manager refuses this.
    #[error("{op} on {key}: denied")]
    Denied { op: Op, key: String },
    /// The answer is not known: the helper or its key manager is down, slow or failing.
    #[error("{op} on {key}: unavailable")]
    Unavailable { op: Op, key: String },
    /// The helper answered something the contract does not allow.
    #[error("{op} on {key}: the helper's answer breaks the contract: {why}")]
    Contract { op: Op, key: String, why: String },
    /// A signature that does not verify under the key it should be from.
    #[error("sign on {key}: the signature does not verify under that key")]
    WrongSignature { key: String },
}

/// The operations of `docs/key-helper.md`. A key is named by a string nothing here parses.
pub trait Keys: Send + Sync {
    /// An ECDSA P-256 signature, ASN.1 DER, over a SHA-256 digest. Callers go through
    /// [`signed`], which checks it.
    fn sign(&self, key: &str, digest: &[u8; 32]) -> impl Future<Output = Result<Vec<u8>, KeyError>> + Send;
    /// Decrypts `ciphertext` with `key`. The caller wipes the plaintext.
    fn decrypt(&self, key: &str, ciphertext: &[u8]) -> impl Future<Output = Result<Vec<u8>, KeyError>> + Send;
    /// Encrypts `plaintext` with `key`: setup and rotation only.
    fn encrypt(&self, key: &str, plaintext: &[u8]) -> impl Future<Output = Result<Vec<u8>, KeyError>> + Send;
    /// The DER SubjectPublicKeyInfo of `key`.
    fn public_key(&self, key: &str) -> impl Future<Output = Result<Vec<u8>, KeyError>> + Send;
}

/// SHA-256 of `message`, as [`Keys::sign`] takes it.
pub fn sha256(message: &[u8]) -> [u8; 32] {
    digest::digest(&digest::SHA256, message)
        .as_ref()
        .try_into()
        .expect("SHA-256 is 32 bytes")
}

/// `key`'s signature over `message`, checked under `expected` before anything uses it: a
/// helper that answers in the wrong format or with the wrong key is refused, not trusted.
pub async fn signed(keys: &impl Keys, key: &str, message: &[u8], expected: &TrustedKey) -> Result<Vec<u8>, KeyError> {
    let signature = keys.sign(key, &sha256(message)).await?;
    if expected.verifies_der(message, &signature) {
        Ok(signature)
    } else {
        Err(KeyError::WrongSignature { key: key.to_owned() })
    }
}

/// `key`'s public key, as a key signatures can be checked under.
pub async fn trusted(keys: &impl Keys, key: &str) -> Result<TrustedKey, KeyError> {
    let der = keys.public_key(key).await?;
    let spki = Spki::from_der(&der).map_err(|e| KeyError::Contract {
        op: Op::PublicKey,
        key: key.to_owned(),
        why: e.to_string(),
    })?;
    Ok(TrustedKey::from_spki(spki))
}
