//! Credentials (SPEC.md "Credentials and templates are stored as ciphertext we cannot
//! read"): a sandbox sees only placeholders `clovelly://cred/<name>`; the egress proxy
//! replaces them with the real secret, which the cell decrypted under the
//! sub-environment DEK at sandbox start.
//!
//! A credential is uploaded with its name, adapter type and the one destination it is
//! valid for (its [`Binding`]). The customer's verifier seals it ([`seal`]):
//! AES-256-GCM under a key derived from the sub-environment DEK, with the environment,
//! sub-environment and binding as associated data, so the control plane that stores
//! the ciphertext can neither read it nor move it to another name or destination. The
//! cell opens it with the same DEK ([`open`]).
//!
//! Secrets live in [`Secret`] and [`SecretBuf`], which wipe their bytes on drop and
//! never reallocate, so no freed heap block keeps a copy.

use std::fmt;
use std::str::FromStr;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::hkdf::{HKDF_SHA256, Salt};
use serde::{Deserialize, Serialize};

use crate::b64;
use crate::bundle::HostName;
use crate::dek::{Dek, wipe};
use crate::ids::{EnvId, SubenvId};

/// What every placeholder starts with.
pub const PLACEHOLDER_PREFIX: &str = "clovelly://cred/";
/// The longest credential secret the cell accepts.
pub const MAX_SECRET: usize = 16 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum CredError {
    #[error("credential name {0:?} is not 1-64 of a-z, 0-9, '_', '-'")]
    Name(String),
    #[error("adapter type {0:?} is not bearer, basic or query")]
    Adapter(String),
    #[error("credential is {0} bytes; the limit is 16 KiB and it must not be empty")]
    Size(usize),
    #[error("credential contains a CR, LF or NUL, which would break the request it is put in")]
    Control,
    #[error("sealed credential: {0}")]
    Format(String),
    #[error("sealed credential does not open under this sub-environment's DEK and binding")]
    Open,
    #[error("sealing failed")]
    Seal,
}

/// A credential's name: 1-64 of `a-z`, `0-9`, `_`, `-`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CredName(String);

impl CredName {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The placeholder a sandbox carries for this credential.
    pub fn placeholder(&self) -> String {
        format!("{PLACEHOLDER_PREFIX}{}", self.0)
    }
}

fn name_byte(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-'
}

impl FromStr for CredName {
    type Err = CredError;

    fn from_str(s: &str) -> Result<Self, CredError> {
        if (1..=64).contains(&s.len()) && s.bytes().all(name_byte) {
            Ok(Self(s.to_owned()))
        } else {
            Err(CredError::Name(s.to_owned()))
        }
    }
}

impl fmt::Display for CredName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The start of every whole placeholder for `name` in `hay`: the prefix and name,
/// not followed by another name byte (`clovelly://cred/openai` is not found in
/// `clovelly://cred/openai2`).
pub fn find_placeholders(hay: &[u8], name: &CredName) -> Vec<usize> {
    let needle = name.placeholder();
    let needle = needle.as_bytes();
    if hay.len() < needle.len() {
        return Vec::new();
    }
    (0..=hay.len() - needle.len())
        .filter(|&i| &hay[i..i + needle.len()] == needle && hay.get(i + needle.len()).is_none_or(|b| !name_byte(*b)))
        .collect()
}

/// How a credential is presented to its destination (the policy's adapter type).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdapterType {
    Bearer,
    Basic,
    Query,
}

impl AdapterType {
    pub fn as_str(self) -> &'static str {
        match self {
            AdapterType::Bearer => "bearer",
            AdapterType::Basic => "basic",
            AdapterType::Query => "query",
        }
    }
}

impl FromStr for AdapterType {
    type Err = CredError;

    fn from_str(s: &str) -> Result<Self, CredError> {
        match s {
            "bearer" => Ok(AdapterType::Bearer),
            "basic" => Ok(AdapterType::Basic),
            "query" => Ok(AdapterType::Query),
            other => Err(CredError::Adapter(other.to_owned())),
        }
    }
}

/// What a credential is for: its name, adapter type and the one destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub name: CredName,
    pub adapter: AdapterType,
    pub destination: HostName,
}

/// A secret's bytes on the heap, wiped on drop.
pub struct Secret(Box<[u8]>);

impl Secret {
    /// Copies `bytes`, which the caller then wipes. A secret is 1 byte to 16 KiB with no
    /// CR, LF or NUL (substituted into a header, those would inject another).
    pub fn copy_from(bytes: &[u8]) -> Result<Self, CredError> {
        check(bytes)?;
        Ok(Self(bytes.into()))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({} bytes)", self.0.len())
    }
}

fn check(secret: &[u8]) -> Result<(), CredError> {
    if secret.is_empty() || secret.len() > MAX_SECRET {
        return Err(CredError::Size(secret.len()));
    }
    if secret.iter().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
        return Err(CredError::Control);
    }
    Ok(())
}

/// A buffer that may hold secret bytes: its capacity is fixed when it is made, it never
/// grows (so it never leaves a copy in a freed block), and it is wiped on drop.
pub struct SecretBuf(Vec<u8>);

impl SecretBuf {
    pub fn with_capacity(n: usize) -> Self {
        Self(Vec::with_capacity(n))
    }

    /// Appends `bytes`. Panics if they do not fit the capacity: callers size the buffer
    /// exactly first, and growing would copy the secret and free the old block.
    pub fn extend(&mut self, bytes: &[u8]) {
        assert!(
            self.0.len() + bytes.len() <= self.0.capacity(),
            "SecretBuf sized too small; growing would leave a copy behind"
        );
        self.0.extend_from_slice(bytes);
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBuf({} bytes)", self.0.len())
    }
}

/// A sealed credential as stored (JSON): the binding in the clear, the secret as
/// AES-256-GCM ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sealed {
    pub v: u32,
    pub name: String,
    pub adapter: AdapterType,
    pub destination: String,
    /// Base64, 12 bytes.
    pub nonce: String,
    /// Base64: ciphertext and tag.
    pub ciphertext: String,
}

impl Sealed {
    /// The binding the sealed credential claims (authenticated only by [`open`]).
    pub fn binding(&self) -> Result<Binding, CredError> {
        Ok(Binding {
            name: self.name.parse()?,
            adapter: self.adapter,
            destination: self
                .destination
                .parse()
                .map_err(|e: crate::bundle::HostNameError| CredError::Format(e.to_string()))?,
        })
    }

    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a Sealed always serialises")
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, CredError> {
        serde_json::from_slice(bytes).map_err(|e| CredError::Format(e.to_string()))
    }
}

/// The credential key: HKDF-SHA256 of the DEK, salted by purpose and bound to the
/// environment and sub-environment.
fn key(dek: &Dek, env: &EnvId, subenv: &SubenvId) -> LessSafeKey {
    let info = [env.as_str().as_bytes(), subenv.as_str().as_bytes()].join(&0u8);
    let prk = Salt::new(HKDF_SHA256, b"clovelly-v1 credential key").extract(dek.as_bytes());
    let parts = [info.as_slice()];
    let okm = prk
        .expand(&parts, &AES_256_GCM)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    LessSafeKey::new(UnboundKey::from(okm))
}

/// The associated data: the environment, sub-environment and binding, NUL-separated.
fn aad(env: &EnvId, subenv: &SubenvId, b: &Binding) -> Vec<u8> {
    [
        b"clovelly-v1 credential".as_slice(),
        env.as_str().as_bytes(),
        subenv.as_str().as_bytes(),
        b.name.as_str().as_bytes(),
        b.adapter.as_str().as_bytes(),
        b.destination.as_str().as_bytes(),
    ]
    .join(&0u8)
}

/// Seals `secret` for `binding` under the sub-environment's DEK (the verifier's side).
pub fn seal(dek: &Dek, env: &EnvId, subenv: &SubenvId, binding: &Binding, secret: &[u8]) -> Result<Sealed, CredError> {
    check(secret)?;
    let mut nonce = [0u8; NONCE_LEN];
    aws_lc_rs::rand::fill(&mut nonce).map_err(|_| CredError::Seal)?;
    // Sized for the tag too, so appending it never reallocates; sealing in place turns
    // the copy into ciphertext.
    let mut inout = Vec::with_capacity(secret.len() + AES_256_GCM.tag_len());
    inout.extend_from_slice(secret);
    let r = key(dek, env, subenv).seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad(env, subenv, binding)),
        &mut inout,
    );
    if r.is_err() {
        wipe(&mut inout);
        return Err(CredError::Seal);
    }
    Ok(Sealed {
        v: 1,
        name: binding.name.to_string(),
        adapter: binding.adapter,
        destination: binding.destination.to_string(),
        nonce: b64::encode(&nonce),
        ciphertext: b64::encode(&inout),
    })
}

/// Opens a sealed credential (the cell's side). Fails unless it was sealed under this
/// DEK for exactly this environment, sub-environment and binding.
pub fn open(dek: &Dek, env: &EnvId, subenv: &SubenvId, sealed: &Sealed) -> Result<(Binding, Secret), CredError> {
    if sealed.v != 1 {
        return Err(CredError::Format(format!("version {}", sealed.v)));
    }
    let binding = sealed.binding()?;
    let nonce: [u8; NONCE_LEN] = b64::decode(&sealed.nonce)
        .map_err(|e| CredError::Format(e.to_string()))?
        .try_into()
        .map_err(|_| CredError::Format("nonce is not 12 bytes".into()))?;
    let mut buf = b64::decode(&sealed.ciphertext).map_err(|e| CredError::Format(e.to_string()))?;
    let opened = key(dek, env, subenv)
        .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad(env, subenv, &binding)), &mut buf)
        .map(|plain| Secret::copy_from(plain));
    wipe(&mut buf);
    match opened {
        Ok(secret) => Ok((binding, secret?)),
        Err(_) => Err(CredError::Open),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (EnvId, SubenvId) {
        ("staging".parse().unwrap(), "a".parse().unwrap())
    }

    fn binding(name: &str, dest: &str) -> Binding {
        Binding {
            name: name.parse().unwrap(),
            adapter: AdapterType::Bearer,
            destination: dest.parse().unwrap(),
        }
    }

    #[test]
    fn a_sealed_credential_opens_only_under_its_dek_and_binding() {
        let (env, sub) = ids();
        let dek = Dek::from_bytes([3; 32]);
        let b = binding("openai", "api.openai.com");
        let sealed = seal(&dek, &env, &sub, &b, b"sk-test-123").unwrap();
        let json = sealed.to_json();
        assert!(!json.windows(11).any(|w| w == b"sk-test-123"), "no plaintext in the stored form");
        let (got, secret) = open(&dek, &env, &sub, &Sealed::from_json(&json).unwrap()).unwrap();
        assert_eq!((got, secret.expose()), (b, b"sk-test-123".as_slice()));

        // Another DEK, sub-environment, name or destination does not open it.
        assert!(matches!(open(&Dek::from_bytes([4; 32]), &env, &sub, &sealed), Err(CredError::Open)));
        assert!(matches!(open(&dek, &env, &"b".parse().unwrap(), &sealed), Err(CredError::Open)));
        for (field, value) in [("name", "other"), ("destination", "evil.example.com")] {
            let mut moved = sealed.clone();
            match field {
                "name" => moved.name = value.into(),
                _ => moved.destination = value.into(),
            }
            assert!(matches!(open(&dek, &env, &sub, &moved), Err(CredError::Open)), "{field}");
        }
        let mut retyped = sealed.clone();
        retyped.adapter = AdapterType::Query;
        assert!(matches!(open(&dek, &env, &sub, &retyped), Err(CredError::Open)));
    }

    #[test]
    fn placeholders_are_found_whole() {
        let name: CredName = "openai".parse().unwrap();
        assert_eq!(name.placeholder(), "clovelly://cred/openai");
        let hay = b"Bearer clovelly://cred/openai, clovelly://cred/openai2 clovelly://cred/openai";
        assert_eq!(find_placeholders(hay, &name), vec![7, 55]);
        assert!(find_placeholders(b"clovelly://cred/opena", &name).is_empty());
        for bad in ["", "Upper", "a b", &"x".repeat(65), "a/b"] {
            assert!(bad.parse::<CredName>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn secrets_with_line_breaks_are_refused() {
        let (env, sub) = ids();
        let dek = Dek::from_bytes([3; 32]);
        let b = binding("x", "api.example.com");
        for bad in [&b"a\r\nX-Evil: 1"[..], b"a\nb", b"a\0b", b""] {
            assert!(seal(&dek, &env, &sub, &b, bad).is_err(), "{bad:?}");
            assert!(Secret::copy_from(bad).is_err());
        }
    }

    #[test]
    #[should_panic(expected = "sized too small")]
    fn a_secret_buffer_never_grows() {
        let mut b = SecretBuf::with_capacity(4);
        b.extend(b"abcd");
        b.extend(b"e");
    }
}
