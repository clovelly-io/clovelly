//! Receipts (SPEC.md "Receipt", decision 9): JSON in JCS canonical form, signed with
//! the cell key (ECDSA P-256, SHA-256, `r || s`), the cell certificate attached.
//!
//! [`sign`] is the cell's side. [`verify`] is the public check anyone can run with only
//! the receipt, the cell certificate, the environment CA certificate and the published
//! measurement set: it rests on the environment CA (which issued the certificate only
//! after checking the cell's quote) and on the measurement set, not on a quote in the
//! receipt. It refuses a receipt whose bytes are not canonical, whose signature does
//! not verify, whose certificate does not chain to the CA or was not valid when the
//! receipt was signed, whose environment, sub-environment or release differ from the
//! certificate's, or whose measurements are not the published ones for its release.
//!
//! `cpu_share` (SPEC.md phase 13) is the CPU sharing factor the sandbox ran under: 1 is
//! dedicated CPU, F means its guarantee was its CPU request divided by F among its own
//! sub-environment's sandboxes. Receipts written before the field existed lack it and
//! read as 1 ([`Verified::cpu_share`]); like every field it is covered by the signature.
//!
//! ```ignore
//! let (json, sig) = receipt::sign(&doc, &cell_signing_key)?;          // cell
//! let ok = receipt::verify(&json, &sig, &cell_cert, &ca_cert, &set)?;  // anyone
//! ```

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{self, EcdsaKeyPair, UnparsedPublicKey};
use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use serde::Deserialize;
use serde_json::Value;
use x509_cert::Certificate;

use crate::cellcert::{self, CellCertInfo};
use crate::evidence::Spki;
use crate::jcs::{self, JcsError};

/// ecdsa-with-SHA256.
const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

#[derive(Debug, thiserror::Error)]
pub enum ReceiptError {
    #[error("receipt is not JSON: {0}")]
    Json(String),
    #[error(transparent)]
    Canonical(#[from] JcsError),
    #[error("receipt bytes are not in JCS canonical form")]
    NotCanonical,
    #[error("receipt field {0} is missing or malformed")]
    Field(&'static str),
    #[error("receipt version {0} is not 1")]
    Version(u64),
    #[error("signing failed")]
    Sign,
    #[error("the receipt's signature does not verify under the cell certificate's key")]
    Signature,
    #[error("certificate: {0}")]
    Certificate(String),
    #[error("the cell certificate is not signed by the environment CA")]
    Chain,
    #[error("the receipt was signed at {signed} s, outside the certificate's validity {from}..{to}")]
    Validity { signed: u64, from: u64, to: u64 },
    #[error("the receipt's {field} {receipt:?} differs from the certificate's {cert:?}")]
    Identity { field: &'static str, receipt: String, cert: String },
    #[error("release {0} is not in the measurement set")]
    UnknownRelease(String),
    #[error("measurement {which} {got} is not the published value for release {release}")]
    Measurement { which: String, got: String, release: String },
    #[error("measurement set: {0}")]
    Set(String),
}

/// Canonicalises `doc` and signs it with the cell key. Returns the canonical bytes and
/// the signature (`r || s`, 64 bytes).
pub fn sign(doc: &Value, key: &EcdsaKeyPair) -> Result<(Vec<u8>, Vec<u8>), ReceiptError> {
    let json = jcs::canonical(doc)?;
    let sig = key.sign(&SystemRandom::new(), &json).map_err(|_| ReceiptError::Sign)?;
    Ok((json, sig.as_ref().to_vec()))
}

/// The published measurements of one release.
#[derive(Debug, Clone, Deserialize)]
pub struct ReleaseMeasurements {
    pub id: String,
    /// RTMR0 to RTMR3, hex.
    pub rtmr: [String; 4],
    /// More RTMR0 values the release published, each canary-recorded on other host
    /// firmware; empty: only `rtmr[0]`.
    #[serde(default)]
    pub rtmr0_firmware: Vec<String>,
    /// The MRTDs Google's endorsements allow for it (hex); empty: not checked.
    #[serde(default)]
    pub mrtd: Vec<String>,
}

/// The published measurement set: the release policy's `releases` (extra fields, such
/// as windows, are ignored).
#[derive(Debug, Clone, Deserialize)]
pub struct MeasurementSet {
    pub releases: Vec<ReleaseMeasurements>,
}

impl MeasurementSet {
    pub fn from_json(bytes: &[u8]) -> Result<Self, ReceiptError> {
        serde_json::from_slice(bytes).map_err(|e| ReceiptError::Set(e.to_string()))
    }
}

/// A receipt that verified, and what its certificate vouches for.
#[derive(Debug, Clone)]
pub struct Verified {
    pub doc: Value,
    pub cert: CellCertInfo,
    /// The receipt's `cpu_share`; 1 for a receipt without the field.
    pub cpu_share: u32,
}

impl Verified {
    pub fn sandbox_id(&self) -> &str {
        self.doc["sandbox"]["id"].as_str().unwrap_or_default()
    }

    pub fn exit_kind(&self) -> &str {
        self.doc["exit"]["kind"].as_str().unwrap_or_default()
    }
}

/// A parsed cell certificate: its key, validity and extension, and what the CA signed.
struct CellCert {
    spki: Spki,
    not_before: u64,
    not_after: u64,
    info: CellCertInfo,
    tbs: Vec<u8>,
    signature: Vec<u8>,
}

fn cert_err(e: impl std::fmt::Display) -> ReceiptError {
    ReceiptError::Certificate(e.to_string())
}

fn parse_cert(der: &[u8]) -> Result<CellCert, ReceiptError> {
    let cert = Certificate::from_der(der).map_err(cert_err)?;
    if cert.signature_algorithm().oid != ECDSA_SHA256 {
        return Err(cert_err("not signed with ecdsa-with-SHA256"));
    }
    let tbs = cert.tbs_certificate();
    let validity = tbs.validity();
    let info = tbs
        .extensions()
        .into_iter()
        .flatten()
        .find(|e| e.extn_id == cellcert::OID)
        .ok_or_else(|| cert_err("no cell certificate extension"))
        .and_then(|e| CellCertInfo::from_der(e.extn_value.as_bytes()).map_err(cert_err))?;
    Ok(CellCert {
        spki: Spki::from_der(&tbs.subject_public_key_info().to_der().map_err(cert_err)?).map_err(cert_err)?,
        not_before: validity.not_before.to_unix_duration().as_secs(),
        not_after: validity.not_after.to_unix_duration().as_secs(),
        info,
        tbs: tbs.to_der().map_err(cert_err)?,
        signature: cert.signature().raw_bytes().to_vec(),
    })
}

/// The CA certificate's public key point.
fn ca_point(der: &[u8]) -> Result<[u8; 65], ReceiptError> {
    let cert = Certificate::from_der(der).map_err(cert_err)?;
    let spki = cert.tbs_certificate().subject_public_key_info().to_der().map_err(cert_err)?;
    Ok(*Spki::from_der(&spki).map_err(cert_err)?.point())
}

/// `2026-10-26T12:00:00.123Z` to Unix seconds (UTC, the form receipts are written in).
pub fn parse_rfc3339(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || !s.ends_with('Z') {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hh, mm, ss) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // Howard Hinnant's days-from-civil.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + hh * 3600 + mm * 60 + ss).ok()
}

fn field<'a>(doc: &'a Value, path: &[&str], name: &'static str) -> Result<&'a str, ReceiptError> {
    path.iter()
        .try_fold(doc, |v, k| v.get(k))
        .and_then(Value::as_str)
        .ok_or(ReceiptError::Field(name))
}

/// [`verify`] against several CA certificates, the first that issued the cell
/// certificate deciding: during an environment CA rotation, and for receipts older than
/// one, a receipt's certificate may chain to the CA before the current one.
pub fn verify_any(json: &[u8], sig: &[u8], cell_cert: &[u8], cas: &[&[u8]], set: &MeasurementSet) -> Result<Verified, ReceiptError> {
    let mut verdict = Err(ReceiptError::Chain);
    for ca in cas {
        verdict = verify(json, sig, cell_cert, ca, set);
        if !matches!(verdict, Err(ReceiptError::Chain)) {
            break;
        }
    }
    verdict
}

/// Verifies a receipt (see the module docs). `json` must be exactly the signed,
/// canonical bytes.
pub fn verify(json: &[u8], sig: &[u8], cell_cert: &[u8], ca_cert: &[u8], set: &MeasurementSet) -> Result<Verified, ReceiptError> {
    let doc: Value = serde_json::from_slice(json).map_err(|e| ReceiptError::Json(e.to_string()))?;
    if jcs::canonical(&doc)? != json {
        return Err(ReceiptError::NotCanonical);
    }
    match doc.get("v").and_then(Value::as_u64) {
        Some(1) => {}
        Some(v) => return Err(ReceiptError::Version(v)),
        None => return Err(ReceiptError::Field("v")),
    }
    let cert = parse_cert(cell_cert)?;
    UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, ca_point(ca_cert)?)
        .verify(&cert.tbs, &cert.signature)
        .map_err(|_| ReceiptError::Chain)?;
    UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, cert.spki.point())
        .verify(json, sig)
        .map_err(|_| ReceiptError::Signature)?;

    let signed = parse_rfc3339(field(&doc, &["signed"], "signed")?).ok_or(ReceiptError::Field("signed"))?;
    if signed < cert.not_before || signed > cert.not_after {
        return Err(ReceiptError::Validity { signed, from: cert.not_before, to: cert.not_after });
    }
    for (name, receipt, ours) in [
        ("env", field(&doc, &["env"], "env")?, cert.info.env.as_str()),
        ("subenv", field(&doc, &["subenv"], "subenv")?, cert.info.subenv.as_str()),
        ("release", field(&doc, &["release"], "release")?, cert.info.release.as_str()),
    ] {
        if receipt != ours {
            return Err(ReceiptError::Identity { field: name, receipt: receipt.to_owned(), cert: ours.to_owned() });
        }
    }
    let release = cert.info.release.as_str();
    let published = set
        .releases
        .iter()
        .find(|r| r.id == release)
        .ok_or_else(|| ReceiptError::UnknownRelease(release.to_owned()))?;
    let rtmr = doc["measurements"]["rtmr"].as_array().ok_or(ReceiptError::Field("measurements.rtmr"))?;
    if rtmr.len() != 4 {
        return Err(ReceiptError::Field("measurements.rtmr"));
    }
    for (i, (got, want)) in rtmr.iter().zip(&published.rtmr).enumerate() {
        let got = got.as_str().ok_or(ReceiptError::Field("measurements.rtmr"))?;
        let firmware = i == 0 && published.rtmr0_firmware.iter().any(|m| m.eq_ignore_ascii_case(got));
        if !got.eq_ignore_ascii_case(want) && !firmware {
            return Err(ReceiptError::Measurement { which: format!("rtmr{i}"), got: got.to_owned(), release: release.to_owned() });
        }
    }
    let mrtd = field(&doc, &["measurements", "mrtd"], "measurements.mrtd")?;
    if !published.mrtd.is_empty() && !published.mrtd.iter().any(|m| m.eq_ignore_ascii_case(mrtd)) {
        return Err(ReceiptError::Measurement { which: "mrtd".into(), got: mrtd.to_owned(), release: release.to_owned() });
    }
    // Not bounded by today's maximum: a later release may allow more, and its receipts
    // must still verify here.
    let cpu_share = match doc.get("cpu_share") {
        None => 1,
        Some(v) => v.as_u64().and_then(|n| u32::try_from(n).ok()).filter(|&n| n >= 1).ok_or(ReceiptError::Field("cpu_share"))?,
    };
    Ok(Verified { doc, cert: cert.info, cpu_share })
}

/// Unix time `t` as the receipt's RFC 3339 form, e.g. `2026-10-26T12:00:00.123Z`.
pub fn rfc3339(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Howard Hinnant's civil-from-days.
    let z = i64::try_from(days).unwrap_or(0) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        d.subsec_millis()
    )
}

/// The inverse of [`rfc3339`], to the second.
pub fn from_rfc3339(s: &str) -> Option<SystemTime> {
    parse_rfc3339(s).map(|secs| UNIX_EPOCH + Duration::from_secs(secs))
}

#[cfg(test)]
mod testing {
    //! A test environment CA and the cell certificates it issues.
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
    use rcgen::{BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, Issuer, KeyPair};

    use crate::cellcert::{self, CellCertInfo};

    pub struct TestCa {
        issuer: Issuer<'static, KeyPair>,
        pub cert: Vec<u8>,
    }

    fn at(secs: u64) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(i64::try_from(secs).unwrap()).unwrap()
    }

    impl TestCa {
        pub fn new() -> Self {
            let key = KeyPair::generate().unwrap();
            let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
            p.distinguished_name.push(DnType::CommonName, "test env CA");
            p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let cert = p.self_signed(&key).unwrap().der().to_vec();
            Self { issuer: Issuer::new(p, key), cert }
        }

        /// A cell key and its certificate for `info`, valid `from..to` (Unix seconds).
        pub fn cell(&self, info: &CellCertInfo, from: u64, to: u64) -> (EcdsaKeyPair, Vec<u8>) {
            let key = KeyPair::generate().unwrap();
            let mut p = CertificateParams::new(vec!["a.staging.cells.clovelly.internal".to_owned()]).unwrap();
            p.not_before = at(from);
            p.not_after = at(to);
            p.custom_extensions = vec![CustomExtension::from_oid_content(&cellcert::OID_ARCS, info.to_der())];
            let cert = p.signed_by(&key, &self.issuer).unwrap().der().to_vec();
            let signing = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &key.serialize_der()).unwrap();
            (signing, cert)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::TestCa;
    use super::*;
    use serde_json::json;

    const RTMR: [&str; 4] = ["aa", "bb", "cc", "00"];

    fn info() -> CellCertInfo {
        CellCertInfo {
            quote_sha256: [7; 32],
            env: "staging".parse().unwrap(),
            subenv: "a".parse().unwrap(),
            release: "clovelly-0.4.0-prod".parse().unwrap(),
        }
    }

    fn set() -> MeasurementSet {
        MeasurementSet::from_json(
            br#"{"v":1,"releases":[{"id":"clovelly-0.4.0-prod","rtmr":["AA","bb","cc","00"],"mrtd":["dd"],"valid_until":1}]}"#,
        )
        .unwrap()
    }

    fn doc() -> Value {
        json!({
            "v": 1, "seq": 3, "env": "staging", "subenv": "a", "release": "clovelly-0.4.0-prod",
            "cell": {"instance": "123", "zone": "us-central1-a", "project": "p"},
            "measurements": {"mrtd": "dd", "rtmr": RTMR},
            "sandbox": {"id": "0123456789abcdef0123456789abcdef", "identity_spki": "MFkw", "template_digest": null,
                        "volume_id": null, "volume_epoch": null},
            "policy_hash": "ph", "cpu_share": 3, "creds_released": ["openai"], "egress_log_hash": "eh", "egress_log_count": 2,
            "egress_gaps": [], "signed": "2026-10-27T12:00:10.000Z",
            "started": "2026-10-27T12:00:00.000Z", "ended": "2026-10-27T12:00:10.000Z",
            "exit": {"kind": "exited", "code": 0}
        })
    }

    fn signed() -> (TestCa, Vec<u8>, Vec<u8>, Vec<u8>) {
        let ca = TestCa::new();
        let at = parse_rfc3339("2026-10-27T12:00:10.000Z").unwrap();
        let (key, cert) = ca.cell(&info(), at - 60, at + 3600);
        let (json, sig) = sign(&doc(), &key).unwrap();
        (ca, json, sig, cert)
    }

    /// Criterion 8: a receipt verifies from the receipt, the certificate chain and the
    /// measurement set alone, and the signed bytes are the JCS form.
    #[test]
    fn a_canonical_receipt_verifies_with_its_chain_and_measurement_set() {
        let (ca, json, sig, cert) = signed();
        assert_eq!(json, jcs::canonical(&doc()).unwrap());
        assert!(json.starts_with(br#"{"cell":{"instance":"123""#), "{}", String::from_utf8_lossy(&json));
        let v = verify(&json, &sig, &cert, &ca.cert, &set()).unwrap();
        assert_eq!((v.sandbox_id(), v.exit_kind()), ("0123456789abcdef0123456789abcdef", "exited"));
        // Re-serialised with whitespace, the same receipt is refused: only the signed
        // bytes verify.
        let pretty = serde_json::to_vec_pretty(&doc()).unwrap();
        assert!(matches!(verify(&pretty, &sig, &cert, &ca.cert, &set()), Err(ReceiptError::NotCanonical)));
    }

    /// Criterion 8: altering any field, at any depth, fails verification.
    #[test]
    fn a_changed_field_fails_verification() {
        let (ca, json, sig, cert) = signed();
        fn leaves(v: &Value, path: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
            match v {
                Value::Object(m) => m.iter().for_each(|(k, v)| {
                    path.push(k.clone());
                    leaves(v, path, out);
                    path.pop();
                }),
                Value::Array(a) => a.iter().enumerate().for_each(|(i, v)| {
                    path.push(i.to_string());
                    leaves(v, path, out);
                    path.pop();
                }),
                _ => out.push(path.clone()),
            }
        }
        let original: Value = serde_json::from_slice(&json).unwrap();
        let mut paths = Vec::new();
        leaves(&original, &mut Vec::new(), &mut paths);
        assert!(paths.len() > 20, "{paths:?}");
        for path in paths {
            let mut altered = original.clone();
            let slot = path.iter().fold(&mut altered, |v, k| match v {
                Value::Array(a) => &mut a[k.parse::<usize>().unwrap()],
                other => &mut other[k.as_str()],
            });
            *slot = match slot {
                Value::String(s) => Value::String(format!("{s}x")),
                Value::Number(n) => json!(n.as_u64().unwrap_or(0) + 1),
                Value::Null => json!("x"),
                Value::Bool(b) => json!(!*b),
                _ => unreachable!(),
            };
            let bytes = jcs::canonical(&altered).unwrap();
            assert!(verify(&bytes, &sig, &cert, &ca.cert, &set()).is_err(), "altering {path:?} still verified");
        }
        // Removing a field fails too.
        let mut removed = original.clone();
        removed.as_object_mut().unwrap().remove("egress_log_hash");
        assert!(matches!(verify(&jcs::canonical(&removed).unwrap(), &sig, &cert, &ca.cert, &set()), Err(ReceiptError::Signature)));
    }

    /// Phase 13 criterion 7: a receipt carries its sandbox's sharing factor, and one written
    /// before the field existed still verifies and reads as dedicated CPU.
    #[test]
    fn cpu_share_is_read_and_older_receipts_without_it_verify() {
        let (ca, json, sig, cert) = signed();
        assert_eq!(verify(&json, &sig, &cert, &ca.cert, &set()).unwrap().cpu_share, 3);

        let at = parse_rfc3339("2026-10-27T12:00:10.000Z").unwrap();
        let (key, cert) = ca.cell(&info(), at - 60, at + 3600);
        let mut old = doc();
        old.as_object_mut().unwrap().remove("cpu_share");
        let (json, sig) = sign(&old, &key).unwrap();
        assert_eq!(verify(&json, &sig, &cert, &ca.cert, &set()).unwrap().cpu_share, 1);

        for bad in [json!(0), json!("3"), json!(-1)] {
            let mut d = doc();
            d["cpu_share"] = bad;
            let (json, sig) = sign(&d, &key).unwrap();
            assert!(matches!(verify(&json, &sig, &cert, &ca.cert, &set()), Err(ReceiptError::Field("cpu_share"))));
        }
    }

    #[test]
    fn the_chain_validity_identity_and_measurements_are_checked() {
        let (ca, json, sig, cert) = signed();
        let other = TestCa::new();
        assert!(matches!(verify(&json, &sig, &cert, &other.cert, &set()), Err(ReceiptError::Chain)));

        let at = parse_rfc3339("2026-10-27T12:00:10.000Z").unwrap();
        let (key, expired) = ca.cell(&info(), at - 7200, at - 3600);
        let (json2, sig2) = sign(&doc(), &key).unwrap();
        assert!(matches!(verify(&json2, &sig2, &expired, &ca.cert, &set()), Err(ReceiptError::Validity { .. })));

        let mut foreign = info();
        foreign.subenv = "b".parse().unwrap();
        let (key, cert_b) = ca.cell(&foreign, at - 60, at + 60);
        let (json3, sig3) = sign(&doc(), &key).unwrap();
        assert!(matches!(verify(&json3, &sig3, &cert_b, &ca.cert, &set()), Err(ReceiptError::Identity { field: "subenv", .. })));

        let wrong_rtmr = MeasurementSet::from_json(br#"{"releases":[{"id":"clovelly-0.4.0-prod","rtmr":["aa","bb","ce","00"]}]}"#).unwrap();
        assert!(matches!(verify(&json, &sig, &cert, &ca.cert, &wrong_rtmr), Err(ReceiptError::Measurement { .. })));
        let no_release = MeasurementSet::from_json(br#"{"releases":[]}"#).unwrap();
        assert!(matches!(verify(&json, &sig, &cert, &ca.cert, &no_release), Err(ReceiptError::UnknownRelease(_))));
        let wrong_mrtd = MeasurementSet::from_json(br#"{"releases":[{"id":"clovelly-0.4.0-prod","rtmr":["aa","bb","cc","00"],"mrtd":["ee"]}]}"#).unwrap();
        assert!(matches!(verify(&json, &sig, &cert, &ca.cert, &wrong_mrtd), Err(ReceiptError::Measurement { .. })));
    }

    #[test]
    fn rfc3339_round_trips() {
        let t = UNIX_EPOCH + Duration::from_millis(1_793_016_000_123);
        assert_eq!(rfc3339(t), "2026-10-26T12:00:00.123Z");
        assert_eq!(parse_rfc3339("2026-10-26T12:00:00.123Z"), Some(1_793_016_000));
        assert_eq!(parse_rfc3339("2000-02-29T00:00:00Z"), Some(951_782_400));
        assert_eq!(parse_rfc3339("2000-13-01T00:00:00Z"), None);
        assert_eq!(parse_rfc3339("nonsense"), None);
    }
}
