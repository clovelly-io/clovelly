//! Keys in memory, for unit tests and the evidence corpus. Compiled into no released
//! binary: it exists only in test builds and under the `test-keys` feature.

use aws_lc_rs::digest::{self, Digest};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

use super::{KeyError, Keys, Op};

/// One P-256 signing key per name. "Encryption" is the identity, so a test can write a
/// DEK straight into a configuration.
pub struct LocalKms {
    keys: Vec<(String, EcdsaKeyPair)>,
}

impl LocalKms {
    /// Generates one P-256 signing key per name.
    pub fn generate(names: &[&str]) -> Self {
        Self {
            keys: names
                .iter()
                .map(|n| {
                    let kp = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).expect("P-256 key generation does not fail");
                    ((*n).to_owned(), kp)
                })
                .collect(),
        }
    }

    fn key(&self, op: Op, name: &str) -> Result<&EcdsaKeyPair, KeyError> {
        self.keys
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, k)| k)
            .ok_or_else(|| KeyError::NoSuchKey { op, key: name.to_owned() })
    }
}

impl Keys for LocalKms {
    async fn sign(&self, key: &str, d: &[u8; 32]) -> Result<Vec<u8>, KeyError> {
        let d = Digest::import_less_safe(d, &digest::SHA256).expect("32 bytes is a SHA-256 digest");
        let sig = self
            .key(Op::Sign, key)?
            .sign_digest(&d)
            .map_err(|_| KeyError::Unavailable { op: Op::Sign, key: key.to_owned() })?;
        Ok(sig.as_ref().to_vec())
    }

    async fn decrypt(&self, _key: &str, ciphertext: &[u8]) -> Result<Vec<u8>, KeyError> {
        Ok(ciphertext.to_vec())
    }

    async fn encrypt(&self, _key: &str, plaintext: &[u8]) -> Result<Vec<u8>, KeyError> {
        Ok(plaintext.to_vec())
    }

    async fn public_key(&self, key: &str) -> Result<Vec<u8>, KeyError> {
        let der = self
            .key(Op::PublicKey, key)?
            .public_key()
            .as_der()
            .map_err(|_| KeyError::Unavailable { op: Op::PublicKey, key: key.to_owned() })?;
        Ok(der.as_ref().to_vec())
    }
}
