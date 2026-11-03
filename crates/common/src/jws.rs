//! Compact JWS with ES256 (RFC 7515), attached or with a detached payload.
//!
//! Release policies are attached JWS signed by our release keys; a sub-environment's
//! policy bundle travels as JSON with a detached JWS (`header..signature`) signed by
//! the customer's policy key.

use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use crate::b64;
use crate::evidence::Spki;
use der::{Decode, Sequence, asn1::Uint};

#[derive(Debug, thiserror::Error)]
pub enum JwsError {
    #[error("JWS is not three dot-separated parts")]
    Shape,
    #[error("JWS part is not base64url: {0}")]
    Base64(#[from] b64::Base64Error),
    #[error("JWS header is not {{\"alg\":\"ES256\"}}")]
    Header,
    #[error("JWS signature does not verify under any trusted key")]
    Signature,
    #[error("public key: {0}")]
    Key(String),
    #[error("ECDSA signature is not DER: {0}")]
    Der(#[from] der::Error),
}

const HEADER: &str = r#"{"alg":"ES256"}"#;

/// A P-256 public key that may sign, from PEM (`PUBLIC KEY`).
#[derive(Debug, Clone)]
pub struct TrustedKey(Spki);

impl TrustedKey {
    pub fn from_pem(pem: &str) -> Result<Self, JwsError> {
        let der = b64::pem_blocks(pem, "PUBLIC KEY")?
            .into_iter()
            .next()
            .ok_or_else(|| JwsError::Key("no PUBLIC KEY block".into()))?;
        Spki::from_der(&der)
            .map(Self)
            .map_err(|e| JwsError::Key(e.to_string()))
    }

    pub fn from_spki(spki: Spki) -> Self {
        Self(spki)
    }

    /// The key as DER SubjectPublicKeyInfo (what Rekor hashes into a log id).
    pub fn spki_der(&self) -> &[u8] {
        self.0.der()
    }

    /// Whether `der_sig` (DER `ECDSA-Sig-Value`, as Rekor and DSSE carry it) is this
    /// key's ECDSA P-256 SHA-256 signature over `msg`.
    pub fn verifies_der(&self, msg: &[u8], der_sig: &[u8]) -> bool {
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, self.0.point())
            .verify(msg, der_sig)
            .is_ok()
    }

    fn verifies(&self, input: &[u8], sig: &[u8]) -> bool {
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, self.0.point())
            .verify(input, sig)
            .is_ok()
    }
}

/// The signing input for `payload`: `BASE64URL(header) || '.' || BASE64URL(payload)`.
pub fn signing_input(payload: &[u8]) -> String {
    format!("{}.{}", b64::encode_url(HEADER.as_bytes()), b64::encode_url(payload))
}

/// Assembles a compact JWS from a DER ECDSA signature over [`signing_input`].
pub fn assemble(payload: &[u8], der_signature: &[u8], detached: bool) -> Result<String, JwsError> {
    let input = signing_input(payload);
    let sig = b64::encode_url(&fixed_signature(der_signature)?);
    Ok(if detached {
        let header = input.split('.').next().expect("signing input has a header");
        format!("{header}..{sig}")
    } else {
        format!("{input}.{sig}")
    })
}

/// Verifies an attached JWS under any of `keys` and returns its payload.
pub fn verify(jws: &str, keys: &[TrustedKey]) -> Result<Vec<u8>, JwsError> {
    let [header, payload, sig] = parts(jws)?;
    check(header, payload, sig, keys)?;
    Ok(b64::decode_url(payload)?)
}

/// Verifies a detached JWS (`header..signature`) over `payload`.
pub fn verify_detached(jws: &str, payload: &[u8], keys: &[TrustedKey]) -> Result<(), JwsError> {
    let [header, empty, sig] = parts(jws)?;
    if !empty.is_empty() {
        return Err(JwsError::Shape);
    }
    check(header, &b64::encode_url(payload), sig, keys)
}

fn parts(jws: &str) -> Result<[&str; 3], JwsError> {
    let v: Vec<&str> = jws.trim().split('.').collect();
    v.try_into().map_err(|_| JwsError::Shape)
}

fn check(header: &str, payload: &str, sig: &str, keys: &[TrustedKey]) -> Result<(), JwsError> {
    let h: serde_json::Value =
        serde_json::from_slice(&b64::decode_url(header)?).map_err(|_| JwsError::Header)?;
    if h.get("alg").and_then(|a| a.as_str()) != Some("ES256") {
        return Err(JwsError::Header);
    }
    let input = format!("{header}.{payload}");
    let sig = b64::decode_url(sig)?;
    if keys.iter().any(|k| k.verifies(input.as_bytes(), &sig)) {
        Ok(())
    } else {
        Err(JwsError::Signature)
    }
}

#[derive(Sequence)]
struct EcdsaSig {
    r: Uint,
    s: Uint,
}

/// DER `ECDSA-Sig-Value` to the fixed 64-byte `r || s` JWS uses.
fn fixed_signature(der: &[u8]) -> Result<[u8; 64], JwsError> {
    let sig = EcdsaSig::from_der(der)?;
    let mut out = [0u8; 64];
    for (half, int) in out.chunks_exact_mut(32).zip([&sig.r, &sig.s]) {
        let b = int.as_bytes();
        if b.len() > 32 {
            return Err(JwsError::Key("ECDSA integer longer than 32 bytes".into()));
        }
        half[32 - b.len()..].copy_from_slice(b);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

    fn key() -> (EcdsaKeyPair, TrustedKey) {
        let kp = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
        let spki = Spki::from_der(kp.public_key().as_der().unwrap().as_ref()).unwrap();
        (kp, TrustedKey::from_spki(spki))
    }

    fn sign(kp: &EcdsaKeyPair, payload: &[u8], detached: bool) -> String {
        let der = kp
            .sign(&SystemRandom::new(), signing_input(payload).as_bytes())
            .unwrap();
        assemble(payload, der.as_ref(), detached).unwrap()
    }

    #[test]
    fn attached_round_trip_and_wrong_key() {
        let (kp, trusted) = key();
        let jws = sign(&kp, br#"{"v":1}"#, false);
        assert_eq!(verify(&jws, &[trusted]).unwrap(), br#"{"v":1}"#);
        let (_, other) = key();
        assert!(matches!(verify(&jws, &[other]), Err(JwsError::Signature)));
    }

    #[test]
    fn detached_signature_covers_the_payload() {
        let (kp, trusted) = key();
        let jws = sign(&kp, b"bundle", true);
        assert_eq!(jws.split('.').nth(1), Some(""));
        assert!(verify_detached(&jws, b"bundle", std::slice::from_ref(&trusted)).is_ok());
        assert!(verify_detached(&jws, b"bundlf", &[trusted]).is_err());
    }

    #[test]
    fn pem_keys_parse() {
        let (kp, _) = key();
        let pem = b64::pem("PUBLIC KEY", kp.public_key().as_der().unwrap().as_ref());
        let jws = sign(&kp, b"x", false);
        assert!(verify(&jws, &[TrustedKey::from_pem(&pem).unwrap()]).is_ok());
    }
}
