//! Shared by the cell agent and the verifier.
//!
//! - [`tdx`]: the TD quote fields we read (measurements, REPORTDATA).
//! - [`ccel`]: the CC event log, its replay into RTMR values and the events we inspect.
//! - [`evidence`]: unlock evidence, REPORTDATA binding and the cell's DNS name.
//! - [`ids`]: environment, sub-environment, zone, release and sandbox identifiers.
//! - [`sandbox`]: sandbox sizes, the policy's sandbox limits and the placement rule.
//! - [`dek`]: data encryption keys and their HPKE wrap to a cell.
//! - [`cellcert`]: the cell certificate's extension.
//! - [`endorsement`]: Google's signed firmware launch endorsements.
//! - [`proto`]: the gRPC bindings generated from `proto/`.
//! - [`bundle`]: the sub-environment's signed policy bundle and its host matcher.
//! - [`cred`]: credentials: placeholders, sealing under the DEK, wiped secrets.
//! - [`jws`]: compact JWS with ES256 (release policies, policy bundles).
//! - [`jcs`]: JSON canonicalisation (RFC 8785) for signed receipts.
//! - [`receipt`]: receipt signing and the public verification.
//! - [`template`]: template keys and the chunked template ciphertext.
//! - [`volume`]: volume keys, names, sizes and the authenticated block manifest.
//! - [`rekor`]: Rekor log entries: inclusion proofs, checkpoints, entry timestamps.
//! - [`release`]: the closed release payload logged in Rekor and the policy fragment.
//! - [`b64`]: base64 and PEM.

pub mod b64;
pub mod bundle;
pub mod ccel;
pub mod cellcert;
pub mod cred;
pub mod dek;
pub mod endorsement;
pub mod evidence;
pub mod ids;
pub mod jcs;
pub mod jws;
pub mod pass;
pub mod proto;
pub mod receipt;
pub mod rekor;
pub mod release;
pub mod sandbox;
pub mod tdx;
pub mod template;
pub mod volume;

/// Lower-case hex encoding, used for measurements, nonces and logs.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            write!(s, "{b:02x}").expect("writing to a String cannot fail");
            s
        })
}

/// Decodes hex of either case, or `None` if `text` is not an even number of hex digits.
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn hex_encodes_lower_case() {
        assert_eq!(super::hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
    }

    #[test]
    fn unhex_round_trips_and_rejects_junk() {
        assert_eq!(super::unhex("000fA0ff"), Some(vec![0x00, 0x0f, 0xa0, 0xff]));
        assert_eq!(super::unhex("abc"), None);
        assert_eq!(super::unhex("zz"), None);
        assert_eq!(super::unhex("+1"), None);
    }
}
