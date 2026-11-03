//! Templates (SPEC.md "Credentials and templates are stored as ciphertext we cannot
//! read"): a template's plaintext (a gzipped tar of a sandbox root) is encrypted by the
//! SDK under a key of its own, which the customer's verifier issues together with the
//! same key sealed under the sub-environment DEK ([`seal_key`]). The control plane
//! stores both; a cell of the sub-environment opens the key ([`open_key`]) and decrypts
//! the template ([`Decryptor`]), checking the plaintext's SHA-256 against the digest
//! everything is bound to.
//!
//! The ciphertext is a sequence of records, one per 1 MiB of plaintext (the last may be
//! shorter or empty): a 4-byte big-endian length, then AES-256-GCM of the chunk with
//! nonce `0^4 || index (u64 BE)` and associated data `"clovelly-v1 template chunk" ||
//! digest || index (u64 BE) || last (one byte)`. Reordering, dropping, truncating or
//! moving chunks to another template fails to open.
//!
//! ```
//! # use common::template::*;
//! # use common::dek::Dek;
//! # let (env, sub) = ("e".parse().unwrap(), "s".parse().unwrap());
//! let dek = Dek::from_bytes([1; 32]);
//! let plain = b"a template".to_vec();
//! let digest = Digest::of(&plain);
//! let (key, sealed) = seal_key(&dek, &env, &sub, &digest).unwrap();   // verifier
//! let ct = encrypt(&key, &digest, &plain);                             // SDK
//! let key = open_key(&dek, &env, &sub, &digest, &sealed).unwrap();     // cell
//! let mut d = Decryptor::new(key, digest);
//! let mut out = d.push(&ct).unwrap();
//! d.finish().unwrap();
//! assert_eq!(out.concat(), plain);
//! ```

use std::fmt;
use std::str::FromStr;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::digest;
use aws_lc_rs::hkdf::{HKDF_SHA256, Salt};
use serde::{Deserialize, Serialize};

use crate::b64;
use crate::dek::{Dek, wipe};
use crate::ids::{EnvId, SubenvId};

/// Plaintext bytes per chunk.
pub const CHUNK: usize = 1 << 20;
const TAG: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    #[error("digest {0:?} is not 64 lowercase hex characters")]
    Digest(String),
    #[error("sealed template key: {0}")]
    Format(String),
    #[error("the template key does not open under this sub-environment's DEK and digest")]
    OpenKey,
    #[error("template chunk {0} does not open (tampered, reordered or for another template)")]
    Chunk(u64),
    #[error("template ciphertext is malformed: {0}")]
    Malformed(&'static str),
    #[error("template plaintext has digest {got}, not {want}")]
    Mismatch { got: String, want: String },
    #[error("sealing failed")]
    Seal,
}

/// SHA-256 of a template's plaintext.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub fn of(plain: &[u8]) -> Self {
        Self(digest::digest(&digest::SHA256, plain).as_ref().try_into().expect("SHA-256 is 32 bytes"))
    }

    pub fn hex(&self) -> String {
        crate::hex(&self.0)
    }
}

impl FromStr for Digest {
    type Err = TemplateError;

    fn from_str(s: &str) -> Result<Self, TemplateError> {
        if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(TemplateError::Digest(s.to_owned()));
        }
        let bytes = crate::unhex(s).ok_or_else(|| TemplateError::Digest(s.to_owned()))?;
        Ok(Self(bytes.try_into().map_err(|_| TemplateError::Digest(s.to_owned()))?))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", self.hex())
    }
}

/// A template's key, on the heap at one address and wiped on drop.
pub struct TemplateKey(Box<[u8; 32]>);

impl TemplateKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Takes a key from `bytes`, which the caller then wipes.
    pub fn copy_from(bytes: &[u8]) -> Result<Self, TemplateError> {
        let mut key = Box::new([0u8; 32]);
        if bytes.len() != 32 {
            return Err(TemplateError::Format(format!("key is {} bytes", bytes.len())));
        }
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    fn aead(&self) -> LessSafeKey {
        LessSafeKey::new(UnboundKey::new(&AES_256_GCM, self.as_bytes()).expect("32 bytes is an AES-256 key"))
    }
}

impl Drop for TemplateKey {
    fn drop(&mut self) {
        wipe(self.0.as_mut_slice());
    }
}

impl fmt::Debug for TemplateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TemplateKey(..)")
    }
}

/// A template key sealed under the sub-environment DEK (JSON).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedKey {
    pub v: u32,
    pub digest: String,
    /// Base64, 12 bytes.
    pub nonce: String,
    /// Base64: the key's ciphertext and tag.
    pub ciphertext: String,
}

impl SealedKey {
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a SealedKey always serialises")
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, TemplateError> {
        serde_json::from_slice(bytes).map_err(|e| TemplateError::Format(e.to_string()))
    }
}

/// The key-sealing key: HKDF-SHA256 of the DEK for this purpose, environment and
/// sub-environment.
pub(crate) fn derived(dek: &Dek, purpose: &'static [u8], env: &EnvId, subenv: &SubenvId) -> LessSafeKey {
    let info = [env.as_str().as_bytes(), subenv.as_str().as_bytes()].join(&0u8);
    let prk = Salt::new(HKDF_SHA256, purpose).extract(dek.as_bytes());
    let parts = [info.as_slice()];
    let okm = prk.expand(&parts, &AES_256_GCM).expect("32 bytes is a valid HKDF-SHA256 output length");
    LessSafeKey::new(UnboundKey::from(okm))
}

fn key_aad(env: &EnvId, subenv: &SubenvId, digest: &Digest) -> Vec<u8> {
    [b"clovelly-v1 template".as_slice(), env.as_str().as_bytes(), subenv.as_str().as_bytes(), digest.hex().as_bytes()].join(&0u8)
}

/// A fresh template key and its sealed form (the verifier's side).
pub fn seal_key(dek: &Dek, env: &EnvId, subenv: &SubenvId, digest: &Digest) -> Result<(TemplateKey, SealedKey), TemplateError> {
    let mut key = TemplateKey(Box::new([0u8; 32]));
    aws_lc_rs::rand::fill(key.0.as_mut_slice()).map_err(|_| TemplateError::Seal)?;
    let mut nonce = [0u8; NONCE_LEN];
    aws_lc_rs::rand::fill(&mut nonce).map_err(|_| TemplateError::Seal)?;
    let mut inout = Vec::with_capacity(32 + TAG);
    inout.extend_from_slice(key.as_bytes());
    let sealed = derived(dek, b"clovelly-v1 template key", env, subenv).seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(key_aad(env, subenv, digest)),
        &mut inout,
    );
    if sealed.is_err() {
        wipe(&mut inout);
        return Err(TemplateError::Seal);
    }
    Ok((
        key,
        SealedKey { v: 1, digest: digest.hex(), nonce: b64::encode(&nonce), ciphertext: b64::encode(&inout) },
    ))
}

/// Opens a sealed template key (the cell's side). Fails unless it was sealed under this
/// DEK for this environment, sub-environment and digest.
pub fn open_key(dek: &Dek, env: &EnvId, subenv: &SubenvId, digest: &Digest, sealed: &SealedKey) -> Result<TemplateKey, TemplateError> {
    if sealed.v != 1 {
        return Err(TemplateError::Format(format!("version {}", sealed.v)));
    }
    if sealed.digest != digest.hex() {
        return Err(TemplateError::OpenKey);
    }
    let nonce: [u8; NONCE_LEN] = b64::decode(&sealed.nonce)
        .map_err(|e| TemplateError::Format(e.to_string()))?
        .try_into()
        .map_err(|_| TemplateError::Format("nonce is not 12 bytes".into()))?;
    let mut buf = b64::decode(&sealed.ciphertext).map_err(|e| TemplateError::Format(e.to_string()))?;
    let opened = derived(dek, b"clovelly-v1 template key", env, subenv)
        .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(key_aad(env, subenv, digest)), &mut buf)
        .map(|plain| TemplateKey::copy_from(plain));
    wipe(&mut buf);
    opened.map_err(|_| TemplateError::OpenKey)?
}

fn chunk_nonce(index: u64) -> Nonce {
    let mut n = [0u8; NONCE_LEN];
    n[4..].copy_from_slice(&index.to_be_bytes());
    Nonce::assume_unique_for_key(n)
}

fn chunk_aad(digest: &Digest, index: u64, last: bool) -> Vec<u8> {
    let mut aad = b"clovelly-v1 template chunk".to_vec();
    aad.extend_from_slice(&digest.0);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.push(u8::from(last));
    aad
}

/// Encrypts a whole template (the SDKs do the same, streaming).
pub fn encrypt(key: &TemplateKey, digest: &Digest, plain: &[u8]) -> Vec<u8> {
    let aead = key.aead();
    let chunks: Vec<&[u8]> = if plain.is_empty() { vec![&[]] } else { plain.chunks(CHUNK).collect() };
    let mut out = Vec::with_capacity(plain.len() + chunks.len() * (4 + TAG));
    for (i, chunk) in chunks.iter().enumerate() {
        let index = i as u64;
        let mut buf = chunk.to_vec();
        aead.seal_in_place_append_tag(chunk_nonce(index), Aad::from(chunk_aad(digest, index, i + 1 == chunks.len())), &mut buf)
            .expect("sealing a chunk under a valid key does not fail");
        out.extend_from_slice(&u32::try_from(buf.len()).expect("a chunk is under 4 GiB").to_be_bytes());
        out.extend_from_slice(&buf);
    }
    out
}

/// Streaming decryption of a template, checking its digest. Feed ciphertext in any
/// pieces with [`Decryptor::push`]; [`Decryptor::finish`] fails unless the last chunk
/// arrived and the plaintext's SHA-256 is the digest.
pub struct Decryptor {
    key: LessSafeKey,
    digest: Digest,
    hash: digest::Context,
    pending: Vec<u8>,
    index: u64,
    done: bool,
    bytes: u64,
}

impl Decryptor {
    pub fn new(key: TemplateKey, digest: Digest) -> Self {
        Self {
            key: key.aead(),
            digest,
            hash: digest::Context::new(&digest::SHA256),
            pending: Vec::new(),
            index: 0,
            done: false,
            bytes: 0,
        }
    }

    /// Plaintext bytes so far.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Takes ciphertext; returns the plaintext of every chunk it completed.
    pub fn push(&mut self, ct: &[u8]) -> Result<Vec<Vec<u8>>, TemplateError> {
        self.pending.extend_from_slice(ct);
        let mut out = Vec::new();
        while let Some(len) = self.pending.get(..4).map(|b| u32::from_be_bytes(b.try_into().expect("4 bytes")) as usize) {
            if !(TAG..=CHUNK + TAG).contains(&len) {
                return Err(TemplateError::Malformed("a chunk length is out of range"));
            }
            if self.pending.len() < 4 + len {
                break;
            }
            if self.done {
                return Err(TemplateError::Malformed("data after the last chunk"));
            }
            let record: Vec<u8> = self.pending.drain(..4 + len).skip(4).collect();
            // The last chunk is marked in its associated data; try it as a middle chunk
            // first unless it is short (only the last chunk can be).
            let full = len == CHUNK + TAG;
            let plain = self.open(&record, !full).or_else(|e| if full { self.open(&record, true) } else { Err(e) })?;
            self.hash.update(&plain);
            self.bytes += plain.len() as u64;
            self.index += 1;
            out.push(plain);
        }
        Ok(out)
    }

    fn open(&mut self, record: &[u8], last: bool) -> Result<Vec<u8>, TemplateError> {
        let mut copy = record.to_vec();
        let plain = self
            .key
            .open_in_place(chunk_nonce(self.index), Aad::from(chunk_aad(&self.digest, self.index, last)), &mut copy)
            .map_err(|_| TemplateError::Chunk(self.index))?
            .to_vec();
        self.done = last;
        Ok(plain)
    }

    /// Ends the stream: the last chunk must have arrived, nothing may follow, and the
    /// digest must match.
    pub fn finish(self) -> Result<u64, TemplateError> {
        if !self.done || !self.pending.is_empty() {
            return Err(TemplateError::Malformed("the ciphertext ends before its last chunk"));
        }
        let got = Digest(self.hash.finish().as_ref().try_into().expect("SHA-256 is 32 bytes"));
        if got != self.digest {
            return Err(TemplateError::Mismatch { got: got.hex(), want: self.digest.hex() });
        }
        Ok(self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (EnvId, SubenvId) {
        ("staging".parse().unwrap(), "a".parse().unwrap())
    }

    fn decrypt(key: TemplateKey, digest: Digest, ct: &[u8], piece: usize) -> Result<Vec<u8>, TemplateError> {
        let mut d = Decryptor::new(key, digest);
        let mut out = Vec::new();
        for p in ct.chunks(piece.max(1)) {
            out.extend(d.push(p)?.concat());
        }
        d.finish()?;
        Ok(out)
    }

    /// Criterion 3: the template key the verifier issues is sealed under the
    /// sub-environment DEK and bound to the digest; only that DEK, environment,
    /// sub-environment and digest open it, and the stored form holds no key bytes.
    #[test]
    fn template_key_wrapping_binds_dek_subenv_and_digest() {
        let (env, sub) = ids();
        let dek = Dek::from_bytes([3; 32]);
        let digest = Digest::of(b"template");
        let (key, sealed) = seal_key(&dek, &env, &sub, &digest).unwrap();
        let json = sealed.to_json();
        assert!(!json.windows(32).any(|w| w == key.as_bytes()), "no key bytes in the stored form");
        let opened = open_key(&dek, &env, &sub, &digest, &SealedKey::from_json(&json).unwrap()).unwrap();
        assert_eq!(opened.as_bytes(), key.as_bytes());

        assert!(matches!(open_key(&Dek::from_bytes([4; 32]), &env, &sub, &digest, &sealed), Err(TemplateError::OpenKey)));
        assert!(matches!(open_key(&dek, &env, &"b".parse().unwrap(), &digest, &sealed), Err(TemplateError::OpenKey)));
        assert!(matches!(open_key(&dek, &"other".parse().unwrap(), &sub, &digest, &sealed), Err(TemplateError::OpenKey)));
        let other = Digest::of(b"another template");
        assert!(matches!(open_key(&dek, &env, &sub, &other, &sealed), Err(TemplateError::OpenKey)));
        let mut relabelled = sealed.clone();
        relabelled.digest = other.hex();
        assert!(matches!(open_key(&dek, &env, &sub, &other, &relabelled), Err(TemplateError::OpenKey)));
    }

    #[test]
    fn templates_round_trip_in_any_pieces() {
        let (env, sub) = ids();
        let dek = Dek::from_bytes([3; 32]);
        for len in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK + 17] {
            let plain: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let digest = Digest::of(&plain);
            let (key, sealed) = seal_key(&dek, &env, &sub, &digest).unwrap();
            let ct = encrypt(&key, &digest, &plain);
            assert!(len < 64 || !ct.windows(64).any(|w| w == &plain[..64]), "ciphertext holds no plaintext");
            for piece in [7, 4096, ct.len()] {
                let key = open_key(&dek, &env, &sub, &digest, &sealed).unwrap();
                assert_eq!(decrypt(key, digest, &ct, piece).unwrap(), plain, "len {len} piece {piece}");
            }
        }
    }

    #[test]
    fn tampered_truncated_or_moved_ciphertext_fails() {
        let key = || TemplateKey::copy_from(&[9; 32]).unwrap();
        let plain = vec![5u8; 2 * CHUNK + 10];
        let digest = Digest::of(&plain);
        let ct = encrypt(&key(), &digest, &plain);
        let mut flipped = ct.clone();
        flipped[100] ^= 1;
        assert!(matches!(decrypt(key(), digest, &flipped, 4096), Err(TemplateError::Chunk(0))));
        let record = 4 + CHUNK + TAG;
        assert!(decrypt(key(), digest, &ct[..2 * record], 4096).is_err(), "dropping the last chunk");
        let mut swapped = ct[record..2 * record].to_vec();
        swapped.extend_from_slice(&ct[..record]);
        swapped.extend_from_slice(&ct[2 * record..]);
        assert!(decrypt(key(), digest, &swapped, 4096).is_err(), "reordered chunks");
        let other = Digest::of(b"x");
        assert!(decrypt(key(), other, &ct, 4096).is_err(), "another template's digest");
        let mut extra = ct.clone();
        extra.extend_from_slice(&ct[..record]);
        assert!(decrypt(key(), digest, &extra, 4096).is_err(), "data after the last chunk");
    }

    #[test]
    fn digests_parse_lowercase_hex_only() {
        let d = Digest::of(b"x");
        assert_eq!(d.hex().parse::<Digest>().unwrap(), d);
        assert!(d.hex().to_uppercase().parse::<Digest>().is_err());
        assert!("abc".parse::<Digest>().is_err());
    }
}
