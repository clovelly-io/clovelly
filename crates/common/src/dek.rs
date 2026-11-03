//! Data encryption keys and how the verifier hands one to a cell.
//!
//! The verifier seals a sub-environment's DEK to the cell's P-256 key with HPKE
//! (RFC 9180, base mode, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM; SPEC.md
//! decision 3). Only the holder of the cell's private key can open it, and the HPKE
//! `info` names the environment and sub-environment, so a wrap made for one cannot be
//! opened as another's.
//!
//! ```
//! # use common::dek::{self, Dek};
//! # use common::evidence::Spki;
//! # fn demo(spki: &Spki, scalar: &[u8], env: &common::ids::EnvId, sub: &common::ids::SubenvId) -> Result<(), dek::DekError> {
//! let wrapped = dek::wrap(&Dek::from_bytes([7; 32]), spki, env, sub)?; // verifier
//! let opened = dek::unwrap(&wrapped, scalar, env, sub)?; // cell
//! assert_eq!(opened.as_bytes(), &[7; 32]);
//! # Ok(()) }
//! ```

use std::fmt;

use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::DhP256HkdfSha256;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};

use crate::evidence::Spki;
use crate::ids::{EnvId, SubenvId};

type Kem = DhP256HkdfSha256;
const ENCAPPED_LEN: usize = 65;

#[derive(Debug, thiserror::Error)]
pub enum DekError {
    #[error("HPKE: {0}")]
    Hpke(#[from] hpke::HpkeError),
    #[error("wrapped DEK is {0} bytes, too short")]
    TooShort(usize),
    #[error("DEK is {0} bytes, expected 32")]
    Length(usize),
}

/// A 256-bit data encryption key, held on the heap at one address and wiped on drop.
pub struct Dek(Box<[u8; 32]>);

impl Dek {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Box::new(bytes))
    }

    /// Copies a key out of `bytes`, which the caller then wipes.
    pub fn copy_from(bytes: &[u8]) -> Result<Self, DekError> {
        let mut key = Box::new([0u8; 32]);
        if bytes.len() != key.len() {
            return Err(DekError::Length(bytes.len()));
        }
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for Dek {
    fn drop(&mut self) {
        wipe(self.0.as_mut_slice());
    }
}

impl fmt::Debug for Dek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Dek(..)")
    }
}

/// Overwrites key material with zeros. `black_box` keeps the compiler from dropping
/// the stores as dead; the guard-allocator tests in `cell-agent` check that it holds.
pub fn wipe(buf: &mut [u8]) {
    buf.fill(0);
    std::hint::black_box(buf);
}

/// HPKE `info`: the protocol, environment and sub-environment, NUL-separated.
fn info(env: &EnvId, subenv: &SubenvId) -> Vec<u8> {
    [b"clovelly-v1 dek".as_slice(), env.as_str().as_bytes(), subenv.as_str().as_bytes()].join(&0u8)
}

/// Seals `dek` to the key in `to`. The result is the encapsulated key (65 bytes)
/// followed by the ciphertext and tag.
pub fn wrap(dek: &Dek, to: &Spki, env: &EnvId, subenv: &SubenvId) -> Result<Vec<u8>, DekError> {
    let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(to.point())?;
    let (encapped, ciphertext) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, Kem>(
        &OpModeS::Base,
        &pk,
        &info(env, subenv),
        dek.as_bytes(),
        &[],
    )?;
    let mut out = encapped.to_bytes().to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Opens a wrap with the cell's private scalar (32 bytes, big-endian).
pub fn unwrap(
    wrapped: &[u8],
    scalar: &[u8],
    env: &EnvId,
    subenv: &SubenvId,
) -> Result<Dek, DekError> {
    if wrapped.len() <= ENCAPPED_LEN {
        return Err(DekError::TooShort(wrapped.len()));
    }
    let (encapped, ciphertext) = wrapped.split_at(ENCAPPED_LEN);
    let sk = <Kem as hpke::Kem>::PrivateKey::from_bytes(scalar)?;
    let encapped = <Kem as hpke::Kem>::EncappedKey::from_bytes(encapped)?;
    let mut plain = hpke::single_shot_open::<AesGcm256, HkdfSha256, Kem>(
        &OpModeR::Base,
        &sk,
        &encapped,
        &info(env, subenv),
        ciphertext,
        &[],
    )?;
    let dek = Dek::copy_from(&plain);
    wipe(&mut plain);
    dek
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::agreement::{self, PrivateKey};
    use aws_lc_rs::encoding::{AsBigEndian, AsDer, EcPrivateKeyBin};

    struct Cell {
        key: PrivateKey,
        spki: Spki,
    }

    fn cell() -> Cell {
        let key = PrivateKey::generate(&agreement::ECDH_P256).unwrap();
        let der = key.compute_public_key().unwrap();
        let spki = Spki::from_der(der.as_der().unwrap().as_ref()).unwrap();
        Cell { key, spki }
    }

    fn scalar(key: &PrivateKey) -> Vec<u8> {
        let bin: EcPrivateKeyBin<'static> = key.as_be_bytes().unwrap();
        bin.as_ref().to_vec()
    }

    fn ids() -> (EnvId, SubenvId) {
        ("acme".parse().unwrap(), "bank-a".parse().unwrap())
    }

    #[test]
    fn the_cell_key_opens_its_wrap() {
        let (env, sub) = ids();
        let c = cell();
        let wrapped = wrap(&Dek::from_bytes([0x5a; 32]), &c.spki, &env, &sub).unwrap();
        assert_eq!(wrapped.len(), 65 + 32 + 16);
        let dek = unwrap(&wrapped, &scalar(&c.key), &env, &sub).unwrap();
        assert_eq!(dek.as_bytes(), &[0x5a; 32]);
    }

    /// Criterion 5: the DEK is recoverable only with the cell's private key.
    #[test]
    fn a_second_key_cannot_open_the_wrap() {
        let (env, sub) = ids();
        let (c, other) = (cell(), cell());
        let wrapped = wrap(&Dek::from_bytes([0x5a; 32]), &c.spki, &env, &sub).unwrap();
        let err = unwrap(&wrapped, &scalar(&other.key), &env, &sub).unwrap_err();
        assert!(matches!(err, DekError::Hpke(_)), "{err:?}");
    }

    #[test]
    fn a_wrap_is_bound_to_its_subenv() {
        let (env, sub) = ids();
        let c = cell();
        let wrapped = wrap(&Dek::from_bytes([1; 32]), &c.spki, &env, &sub).unwrap();
        let other: SubenvId = "bank-b".parse().unwrap();
        assert!(unwrap(&wrapped, &scalar(&c.key), &env, &other).is_err());
        assert!(matches!(
            unwrap(&wrapped[..65], &scalar(&c.key), &env, &sub),
            Err(DekError::TooShort(65))
        ));
    }
}
