//! Volumes (SPEC.md "Volumes: one mounter at a time, committed in blocks"): a volume
//! is a dm-crypt image (AES-XTS, a random 512-bit key per volume) kept in Cloud Storage
//! as 64 MiB blocks of its ciphertext. The key is stored sealed under the
//! sub-environment DEK and bound to the volume's name and size ([`seal_key`]), so only
//! an unlocked cell of the same sub-environment can mount it. Which version of each
//! block is current is in a manifest authenticated with a key derived from the volume
//! key ([`Manifest`]), so blocks cannot be swapped, rolled back or mixed between
//! volumes unnoticed. Each commit writes changed blocks under the new epoch, then the
//! manifest.

use std::fmt;
use std::str::FromStr;

use aws_lc_rs::aead::{Aad, NONCE_LEN, Nonce};
use aws_lc_rs::hkdf::{HKDF_SHA256, Salt};
use aws_lc_rs::hmac;
use serde::{Deserialize, Serialize};

use crate::b64;
use crate::dek::{Dek, wipe};
use crate::ids::{EnvId, SubenvId};

/// Bytes per stored block.
pub const BLOCK: u64 = 64 << 20;
/// The largest volume (v1 cap).
pub const MAX_GIB: u32 = 20;
/// The volume key's length: AES-256-XTS takes two 256-bit keys.
pub const KEY_LEN: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum VolumeError {
    #[error("volume name {0:?} is not 1-64 of a-z, 0-9, '_', '-'")]
    Name(String),
    #[error("volume size {0} GiB is not 1 to 20")]
    Size(u32),
    #[error("sealed volume key: {0}")]
    Format(String),
    #[error("the volume key does not open under this sub-environment's DEK")]
    OpenKey,
    #[error("the volume manifest's MAC does not verify")]
    Manifest,
    #[error("sealing failed")]
    Seal,
}

/// A volume's name within its sub-environment.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VolumeName(String);

impl VolumeName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for VolumeName {
    type Err = VolumeError;

    fn from_str(s: &str) -> Result<Self, VolumeError> {
        let ok = (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
        if ok { Ok(Self(s.to_owned())) } else { Err(VolumeError::Name(s.to_owned())) }
    }
}

impl fmt::Display for VolumeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A volume's size in GiB, 1 to [`MAX_GIB`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct VolumeGib(u32);

impl VolumeGib {
    pub fn get(self) -> u32 {
        self.0
    }

    pub fn bytes(self) -> u64 {
        u64::from(self.0) << 30
    }

    /// How many blocks the volume's image spans.
    pub fn blocks(self) -> u32 {
        u32::try_from(self.bytes().div_ceil(BLOCK)).expect("20 GiB is 320 blocks")
    }
}

impl TryFrom<u32> for VolumeGib {
    type Error = VolumeError;

    fn try_from(n: u32) -> Result<Self, VolumeError> {
        if (1..=MAX_GIB).contains(&n) { Ok(Self(n)) } else { Err(VolumeError::Size(n)) }
    }
}

impl From<VolumeGib> for u32 {
    fn from(g: VolumeGib) -> u32 {
        g.0
    }
}

/// A volume's dm-crypt key, on the heap at one address and wiped on drop.
pub struct VolumeKey(Box<[u8; KEY_LEN]>);

impl VolumeKey {
    pub fn generate() -> Result<Self, VolumeError> {
        let mut k = Box::new([0u8; KEY_LEN]);
        aws_lc_rs::rand::fill(k.as_mut_slice()).map_err(|_| VolumeError::Seal)?;
        Ok(Self(k))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// The manifest's MAC key, derived from the volume key.
    fn mac_key(&self) -> hmac::Key {
        let prk = Salt::new(HKDF_SHA256, b"clovelly-v1 volume manifest").extract(self.as_bytes());
        let okm = prk.expand(&[], hmac::HMAC_SHA256).expect("32 bytes is a valid HKDF-SHA256 output length");
        hmac::Key::from(okm)
    }
}

impl Drop for VolumeKey {
    fn drop(&mut self) {
        wipe(self.0.as_mut_slice());
    }
}

impl fmt::Debug for VolumeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VolumeKey(..)")
    }
}

/// A volume key sealed under the sub-environment DEK (`key.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedKey {
    pub v: u32,
    pub volume: String,
    pub gib: VolumeGib,
    pub nonce: String,
    pub ciphertext: String,
}

impl SealedKey {
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a SealedKey always serialises")
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, VolumeError> {
        serde_json::from_slice(bytes).map_err(|e| VolumeError::Format(e.to_string()))
    }
}

fn key_aad(env: &EnvId, subenv: &SubenvId, name: &VolumeName, gib: VolumeGib) -> Vec<u8> {
    [b"clovelly-v1 volume".as_slice(), env.as_str().as_bytes(), subenv.as_str().as_bytes(), name.as_str().as_bytes(), gib.0.to_string().as_bytes()]
        .join(&0u8)
}

/// Seals a volume's key for its name and size (the cell that creates the volume).
pub fn seal_key(dek: &Dek, env: &EnvId, subenv: &SubenvId, name: &VolumeName, gib: VolumeGib, key: &VolumeKey) -> Result<SealedKey, VolumeError> {
    let mut nonce = [0u8; NONCE_LEN];
    aws_lc_rs::rand::fill(&mut nonce).map_err(|_| VolumeError::Seal)?;
    let mut inout = Vec::with_capacity(KEY_LEN + 16);
    inout.extend_from_slice(key.as_bytes());
    let r = crate::template::derived(dek, b"clovelly-v1 volume key", env, subenv).seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(key_aad(env, subenv, name, gib)),
        &mut inout,
    );
    if r.is_err() {
        wipe(&mut inout);
        return Err(VolumeError::Seal);
    }
    Ok(SealedKey { v: 1, volume: name.to_string(), gib, nonce: b64::encode(&nonce), ciphertext: b64::encode(&inout) })
}

/// Opens a sealed volume key (a cell that mounts the volume). Fails unless it was
/// sealed under this DEK for this environment, sub-environment, name and size.
pub fn open_key(dek: &Dek, env: &EnvId, subenv: &SubenvId, name: &VolumeName, sealed: &SealedKey) -> Result<VolumeKey, VolumeError> {
    if sealed.v != 1 || sealed.volume != name.as_str() {
        return Err(VolumeError::OpenKey);
    }
    let nonce: [u8; NONCE_LEN] = b64::decode(&sealed.nonce)
        .map_err(|e| VolumeError::Format(e.to_string()))?
        .try_into()
        .map_err(|_| VolumeError::Format("nonce is not 12 bytes".into()))?;
    let mut buf = b64::decode(&sealed.ciphertext).map_err(|e| VolumeError::Format(e.to_string()))?;
    let opened = crate::template::derived(dek, b"clovelly-v1 volume key", env, subenv)
        .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(key_aad(env, subenv, name, sealed.gib)), &mut buf)
        .map_err(|_| VolumeError::OpenKey)
        .and_then(|plain| {
            let mut k = Box::new([0u8; KEY_LEN]);
            if plain.len() != KEY_LEN {
                return Err(VolumeError::OpenKey);
            }
            k.copy_from_slice(plain);
            Ok(VolumeKey(k))
        });
    wipe(&mut buf);
    opened
}

/// One block's current version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockRef {
    pub index: u32,
    /// The epoch whose commit wrote this version.
    pub epoch: u64,
    /// SHA-256 of the block's bytes (hex).
    pub sha256: String,
}

/// Which version of each block is current (`manifest.json`). Blocks never written are
/// absent and read as zeros (the image is sparse).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub v: u32,
    pub volume: String,
    pub gib: VolumeGib,
    /// The last committed epoch (the receipt's `volume_epoch`).
    pub epoch: u64,
    pub blocks: Vec<BlockRef>,
}

/// A manifest and its MAC as stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    manifest: Manifest,
    /// HMAC-SHA256 (hex) over the manifest's JCS form.
    mac: String,
}

impl Manifest {
    fn mac(&self, key: &VolumeKey) -> hmac::Tag {
        let doc = serde_json::to_value(self).expect("a Manifest serialises");
        let bytes = crate::jcs::canonical(&doc).expect("a manifest has only integers");
        hmac::sign(&key.mac_key(), &bytes)
    }

    /// The stored form, MAC'd under `key`.
    pub fn seal(&self, key: &VolumeKey) -> Vec<u8> {
        serde_json::to_vec(&Stored { manifest: self.clone(), mac: crate::hex(self.mac(key).as_ref()) }).expect("serialises")
    }

    /// Parses a stored manifest and checks its MAC and that it is this volume's.
    pub fn open(bytes: &[u8], key: &VolumeKey, name: &VolumeName) -> Result<Self, VolumeError> {
        let s: Stored = serde_json::from_slice(bytes).map_err(|e| VolumeError::Format(e.to_string()))?;
        let mac = crate::unhex(&s.mac).ok_or(VolumeError::Manifest)?;
        let doc = serde_json::to_value(&s.manifest).expect("a Manifest serialises");
        let bytes = crate::jcs::canonical(&doc).map_err(|_| VolumeError::Manifest)?;
        hmac::verify(&key.mac_key(), &bytes, &mac).map_err(|_| VolumeError::Manifest)?;
        if s.manifest.volume != name.as_str() || s.manifest.v != 1 {
            return Err(VolumeError::Manifest);
        }
        Ok(s.manifest)
    }
}

/// A block's object name: `block-<index, 5 digits>-<epoch, 10 digits>`.
pub fn block_object(index: u32, epoch: u64) -> String {
    format!("block-{index:05}-{epoch:010}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (EnvId, SubenvId, VolumeName) {
        ("staging".parse().unwrap(), "a".parse().unwrap(), "data".parse().unwrap())
    }

    /// Criterion 5 (the cryptographic half): a volume key opens only under its own
    /// sub-environment's DEK, environment and name, so ciphertext moved to another
    /// sub-environment or environment is unreadable there.
    #[test]
    fn a_volume_key_opens_only_in_its_own_subenv() {
        let (env, sub, name) = ids();
        let dek = Dek::from_bytes([1; 32]);
        let gib = VolumeGib::try_from(2).unwrap();
        let key = VolumeKey::generate().unwrap();
        let sealed = seal_key(&dek, &env, &sub, &name, gib, &key).unwrap();
        let json = sealed.to_json();
        assert!(!json.windows(32).any(|w| w == &key.as_bytes()[..32]));
        let opened = open_key(&dek, &env, &sub, &name, &SealedKey::from_json(&json).unwrap()).unwrap();
        assert_eq!(opened.as_bytes(), key.as_bytes());

        assert!(matches!(open_key(&Dek::from_bytes([2; 32]), &env, &sub, &name, &sealed), Err(VolumeError::OpenKey)));
        assert!(matches!(open_key(&dek, &env, &"b".parse().unwrap(), &name, &sealed), Err(VolumeError::OpenKey)));
        assert!(matches!(open_key(&dek, &"other".parse().unwrap(), &sub, &name, &sealed), Err(VolumeError::OpenKey)));
        let mut renamed = sealed.clone();
        renamed.volume = "other".into();
        assert!(open_key(&dek, &env, &sub, &"other".parse().unwrap(), &renamed).is_err());
        let mut resized = sealed;
        resized.gib = VolumeGib::try_from(3).unwrap();
        assert!(open_key(&dek, &env, &sub, &name, &resized).is_err());
    }

    #[test]
    fn manifests_are_authenticated_and_bound_to_their_volume() {
        let (_, _, name) = ids();
        let key = VolumeKey::generate().unwrap();
        let m = Manifest {
            v: 1,
            volume: name.to_string(),
            gib: VolumeGib::try_from(1).unwrap(),
            epoch: 4,
            blocks: vec![BlockRef { index: 0, epoch: 4, sha256: "ab".into() }],
        };
        let stored = m.seal(&key);
        assert_eq!(Manifest::open(&stored, &key, &name).unwrap(), m);
        let rolled = String::from_utf8(stored.clone()).unwrap().replace("\"epoch\":4", "\"epoch\":3");
        assert!(matches!(Manifest::open(rolled.as_bytes(), &key, &name), Err(VolumeError::Manifest)));
        assert!(Manifest::open(&stored, &VolumeKey::generate().unwrap(), &name).is_err());
        assert!(Manifest::open(&stored, &key, &"other".parse().unwrap()).is_err());
    }

    #[test]
    fn names_sizes_and_blocks() {
        assert!("vol-1_a".parse::<VolumeName>().is_ok());
        assert!("Vol".parse::<VolumeName>().is_err() && "".parse::<VolumeName>().is_err());
        assert!(VolumeGib::try_from(0).is_err() && VolumeGib::try_from(21).is_err());
        assert_eq!(VolumeGib::try_from(20).unwrap().blocks(), 320);
        assert_eq!(VolumeGib::try_from(1).unwrap().blocks(), 16);
        assert_eq!(block_object(3, 12), "block-00003-0000000012");
    }
}
