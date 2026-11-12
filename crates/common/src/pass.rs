//! A placement pass: the control plane's word that one sandbox was placed on one cell, which
//! the cell checks before `CreateSandbox` creates anything. Without it, anyone who could reach a
//! cell could create sandboxes on it, at the cost of whoever pays for the cell.
//!
//! The control plane signs the pass with a key of its own, held only by the control plane's
//! pods, under a certificate the control-plane CA issued with the private key usage
//! [`PASS_SIGNING`] and no other use. Every cell trusts that CA already, for `Drain`; the
//! checker accepts a pass under any CA of the image's bundle (two during a rotation,
//! `docs/key-rotation.md`), and no certificate without that usage, so a `Drain` or cell-channel
//! certificate cannot sign one.
//! The text is `clp1.` then the certificate (DER, base64url) then a compact ES256 JWS over
//! [`PassClaims`] as JSON:
//!
//! ```text
//! clp1.<certificate>.<header>.<claims>.<signature>
//! ```
//!
//! The cell checks the certificate under a CA of its control-plane bundle (signature,
//! validity, the pass-signing usage), that the certificate names the cell's own deployment, the
//! JWS under the certificate's key, that the pass is unexpired, and that its claims are the
//! request's: this cell, this sandbox id, this size and timeout. A pass is used once: the cell
//! remembers each sandbox id it created until the pass's expiry.
//!
//! Every deployment holds a pass key of its own, issued by `deploy/control-plane.sh` for 30 days
//! under the one control-plane CA, and its certificate's subject names the deployment's GCP
//! project number ([`subject_name`]). A cell accepts only a certificate of its own project, so a
//! key leaked from one deployment (staging's, or a test deployment's in another project) places
//! nothing on another's cells. The cell's project is the one the verifier vouched for at
//! unlock ([`Project::attested`]): the metadata server's answer counts only when the MR_OWNER
//! it predicts is the one in the quote the verifier accepted, which GCE sets and the verifier
//! checks against its own policy's project; otherwise the cell refuses every create.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use serde::{Deserialize, Serialize};
use x509_cert::Certificate;
use x509_cert::ext::pkix::ExtendedKeyUsage;

use crate::b64;
use crate::evidence::Spki;
use crate::jws::{self, TrustedKey};

/// How long a pass is good for after it is issued: the SDK creates the sandbox as soon as the
/// placement returns, and a placement that booted a cell returns once the cell is ready.
pub const VALID_SECS: u64 = 600;
/// The clock difference allowed between the control plane and a cell (both run chrony).
pub const SKEW_SECS: u64 = 60;

const PREFIX: &str = "clp1";
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
/// The private extended key usage a pass-signing certificate carries, under the same
/// placeholder enterprise arc as the cell certificate's extension (`crate::cellcert::OID`).
pub const PASS_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.4294967295.1.2");
/// [`PASS_SIGNING`] as `openssl`'s `extendedKeyUsage` takes it.
pub const PASS_SIGNING_TEXT: &str = "1.3.6.1.4.1.4294967295.1.2";

#[derive(Debug, thiserror::Error)]
pub enum PassError {
    #[error("a placement pass is clp1. and a certificate and a JWS")]
    Shape,
    #[error("the pass's certificate: {0}")]
    Certificate(String),
    #[error("the pass's certificate is not signed by the control plane's CA")]
    NotOurs,
    #[error("the pass's certificate is not valid now")]
    CertificateExpired,
    #[error("the pass's certificate is not for signing passes")]
    NotPassSigner,
    #[error("the pass's certificate is another deployment's")]
    OtherDeployment,
    #[error("the metadata's project {0} is not the one in this TD's MR_OWNER")]
    NotAttested(String),
    #[error("the pass's signature: {0}")]
    Signature(#[from] jws::JwsError),
    #[error("the pass's claims are not JSON: {0}")]
    Claims(#[from] serde_json::Error),
    #[error("the pass expired")]
    Expired,
    #[error("the pass is for {0}, not this request")]
    Mismatch(&'static str),
    #[error("the signing key: {0}")]
    Key(String),
    #[error("base64: {0}")]
    Base64(#[from] b64::Base64Error),
    #[error("DER: {0}")]
    Der(#[from] der::Error),
}

/// A GCP project number: the deployment a pass-signing certificate belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Project(u64);

impl std::str::FromStr for Project {
    type Err = PassError;

    fn from_str(s: &str) -> Result<Self, PassError> {
        match s.trim().parse::<u64>() {
            Ok(n) if n > 0 => Ok(Project(n)),
            _ => Err(PassError::Certificate(format!("a project number, not {s:?}"))),
        }
    }
}

impl Project {
    /// The cell's project as the verifier vouched for it: `metadata`'s project number, taken
    /// only when [`crate::tdx::mr_owner`] over it, the instance and the zone the cell sent as
    /// evidence equals `quoted`, the MR_OWNER of the quote the verifier accepted at unlock (the
    /// verifier compares that MR_OWNER with its policy's project, so the two agree only on that
    /// project). The host can lie in metadata, but not in MR_OWNER.
    pub fn attested(metadata: &str, instance_id: u64, zone: &crate::ids::Zone, quoted: &crate::tdx::Measurement) -> Result<Project, PassError> {
        let project: Project = metadata.parse()?;
        if crate::tdx::mr_owner(instance_id, project.0, zone) == *quoted {
            Ok(project)
        } else {
            Err(PassError::NotAttested(metadata.trim().to_owned()))
        }
    }
}

impl std::fmt::Display for Project {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// The common name a deployment's pass-signing certificate carries in its subject:
/// `clovelly-pass-<project number>`, as `deploy/control-plane.sh` issues it.
pub fn subject_name(project: Project) -> String {
    format!("clovelly-pass-{project}")
}

/// What a pass vouches for: the sandbox, the cell (its own name,
/// `<instance>.<zone>.<subenv>.<env>.cells.clovelly.internal`), the size and timeout placed,
/// and when the pass stops being good (Unix seconds).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PassClaims {
    pub v: u8,
    pub cell: String,
    pub sandbox: String,
    pub cpu_halves: u32,
    pub memory_gib: u32,
    pub timeout_secs: u32,
    pub exp: u64,
}

impl PassClaims {
    /// Refuses a pass that is not for this cell, this sandbox, this size and timeout.
    pub fn matches(&self, cell: &str, sandbox: &str, cpu_halves: u32, memory_gib: u32, timeout_secs: u32) -> Result<(), PassError> {
        let checks = [
            (self.cell == cell, "another cell"),
            (self.sandbox == sandbox, "another sandbox"),
            (self.cpu_halves == cpu_halves && self.memory_gib == memory_gib, "another size"),
            (self.timeout_secs == timeout_secs, "another timeout"),
        ];
        match checks.into_iter().find(|(ok, _)| !ok) {
            Some((_, what)) => Err(PassError::Mismatch(what)),
            None => Ok(()),
        }
    }
}

/// The control plane's pass signer: its pass-signing key and certificate.
pub struct PassSigner {
    key: EcdsaKeyPair,
    cert_b64: String,
    rng: SystemRandom,
}

impl PassSigner {
    /// From the certificate (PEM) and its PKCS#8 P-256 private key (PEM), as the control
    /// plane's configuration names them (`pass_cert`, `pass_key`).
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, PassError> {
        let cert = b64::pem_blocks(cert_pem, "CERTIFICATE")?.into_iter().next().ok_or_else(|| PassError::Certificate("no CERTIFICATE block".into()))?;
        let key = b64::pem_blocks(key_pem, "PRIVATE KEY")?.into_iter().next().ok_or_else(|| PassError::Key("no PRIVATE KEY block".into()))?;
        Self::from_der(&cert, &key)
    }

    /// From the certificate (DER) and its PKCS#8 P-256 private key (DER).
    pub fn from_der(cert_der: &[u8], pkcs8: &[u8]) -> Result<Self, PassError> {
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8).map_err(|e| PassError::Key(e.to_string()))?;
        Ok(Self { key, cert_b64: b64::encode_url(cert_der), rng: SystemRandom::new() })
    }

    /// The pass for `claims`.
    pub fn sign(&self, claims: &PassClaims) -> Result<String, PassError> {
        let payload = serde_json::to_vec(claims)?;
        let sig = self.key.sign(&self.rng, jws::signing_input(&payload).as_bytes()).map_err(|e| PassError::Key(e.to_string()))?;
        Ok(format!("{PREFIX}.{}.{}", self.cert_b64, jws::assemble(&payload, sig.as_ref(), false)?))
    }
}

/// A cell's check of passes, under the control plane's CA bundle, for its own deployment.
#[derive(Debug, Clone)]
pub struct PassChecker {
    cas: Vec<(Certificate, TrustedKey)>,
    project: Project,
}

impl PassChecker {
    /// From the control plane's CA bundle (PEM, one or more certificates), as the cell holds
    /// it, and the cell's own project: a pass under any of the CAs is accepted, so a CA
    /// rotation's two-CA bundle takes both, but only from a certificate of `project`.
    pub fn from_ca_pem(pem: &str, project: Project) -> Result<Self, PassError> {
        let cas = b64::pem_blocks(pem, "CERTIFICATE")?
            .iter()
            .map(|der| {
                let ca = Certificate::from_der(der)?;
                let spki = Spki::from_der(&ca.tbs_certificate().subject_public_key_info().to_der()?).map_err(|e| PassError::Certificate(e.to_string()))?;
                Ok((ca, TrustedKey::from_spki(spki)))
            })
            .collect::<Result<Vec<_>, PassError>>()?;
        if cas.is_empty() {
            return Err(PassError::Certificate("no CERTIFICATE block".into()));
        }
        Ok(Self { cas, project })
    }

    /// The claims of `pass` if the control plane's CA vouches for its signer and it has not
    /// expired at `now` (Unix seconds); the caller then checks they are the request's
    /// ([`PassClaims::matches`]).
    pub fn check(&self, pass: &str, now: u64) -> Result<PassClaims, PassError> {
        let rest = pass.strip_prefix(PREFIX).and_then(|r| r.strip_prefix('.')).ok_or(PassError::Shape)?;
        let (cert_b64, token) = rest.split_once('.').ok_or(PassError::Shape)?;
        let cert = Certificate::from_der(&b64::decode_url(cert_b64)?)?;
        let tbs = cert.tbs_certificate();
        if cert.signature_algorithm().oid != ECDSA_WITH_SHA256 {
            return Err(PassError::NotOurs);
        }
        let sig = cert.signature().as_bytes().ok_or(PassError::NotOurs)?;
        let tbs_der = tbs.to_der()?;
        let ours = self.cas.iter().any(|(ca, key)| tbs.issuer() == ca.tbs_certificate().subject() && key.verifies_der(&tbs_der, sig));
        if !ours {
            return Err(PassError::NotOurs);
        }
        let validity = tbs.validity();
        let (from, to) = (validity.not_before.to_unix_duration().as_secs(), validity.not_after.to_unix_duration().as_secs());
        if !(from.saturating_sub(SKEW_SECS)..=to.saturating_add(SKEW_SECS)).contains(&now) {
            return Err(PassError::CertificateExpired);
        }
        let signer = tbs
            .extensions()
            .into_iter()
            .flatten()
            .filter(|e| e.extn_id == EXTENDED_KEY_USAGE)
            .filter_map(|e| ExtendedKeyUsage::from_der(e.extn_value.as_bytes()).ok())
            .any(|eku| eku.0.contains(&PASS_SIGNING));
        if !signer {
            return Err(PassError::NotPassSigner);
        }
        let ours = format!("CN={}", subject_name(self.project));
        if !tbs.subject().to_string().split(',').any(|rdn| rdn == ours) {
            return Err(PassError::OtherDeployment);
        }
        let key = Spki::from_der(&tbs.subject_public_key_info().to_der()?).map_err(|e| PassError::Certificate(e.to_string()))?;
        let claims: PassClaims = serde_json::from_slice(&jws::verify(token, &[TrustedKey::from_spki(key)])?)?;
        if claims.v != 1 {
            return Err(PassError::Shape);
        }
        if now > claims.exp.saturating_add(SKEW_SECS) {
            return Err(PassError::Expired);
        }
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, CustomExtension, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair};

    const PROJECT: u64 = 210_987_654_321;

    fn project(n: u64) -> Project {
        n.to_string().parse().unwrap()
    }

    /// A CA (its certificate and issuer), as rcgen makes them.
    fn ca() -> (Vec<u8>, Issuer<'static, KeyPair>) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).unwrap();
        (cert.der().to_vec(), Issuer::new(params, key))
    }

    /// A leaf the CA issued with `eku` as its only extended key usage.
    fn leaf(issuer: &Issuer<'_, KeyPair>, eku: ExtendedKeyUsagePurpose) -> PassSigner {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec!["pass".into()]).unwrap();
        p.extended_key_usages = vec![eku];
        let cert = p.signed_by(&key, issuer).unwrap();
        PassSigner::from_der(cert.der(), &key.serialize_der()).unwrap()
    }

    /// The pass-signing usage: rcgen writes a custom extended key usage as its own extension.
    fn pass_signer(issuer: &Issuer<'_, KeyPair>) -> PassSigner {
        pass_signer_of(issuer, PROJECT)
    }

    /// A pass signer of deployment `n`, as `deploy/control-plane.sh` issues one.
    fn pass_signer_of(issuer: &Issuer<'_, KeyPair>, n: u64) -> PassSigner {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec!["pass".into()]).unwrap();
        p.distinguished_name.push(DnType::OrganizationName, "clovelly");
        p.distinguished_name.push(DnType::CommonName, subject_name(project(n)));
        let eku = ExtendedKeyUsage(vec![PASS_SIGNING]).to_der().unwrap();
        p.custom_extensions = vec![CustomExtension::from_oid_content(&[2, 5, 29, 37], eku)];
        let cert = p.signed_by(&key, issuer).unwrap();
        PassSigner::from_der(cert.der(), &key.serialize_der()).unwrap()
    }

    fn claims(exp: u64) -> PassClaims {
        PassClaims { v: 1, cell: "clovelly-1a2b3c4d.us-central1-a.a.acme.cells.clovelly.internal".into(), sandbox: "sb_1".into(), cpu_halves: 2, memory_gib: 2, timeout_secs: 900, exp }
    }

    #[test]
    fn a_pass_from_the_control_plane_checks_and_binds_its_request() {
        let (ca_der, issuer) = ca();
        let checker = PassChecker::from_ca_pem(&b64::pem("CERTIFICATE", &ca_der), project(PROJECT)).unwrap();
        let now = 1_800_000_000;
        let pass = pass_signer(&issuer).sign(&claims(now + VALID_SECS)).unwrap();
        let got = checker.check(&pass, now).unwrap();
        assert_eq!(got, claims(now + VALID_SECS));
        got.matches(&got.cell.clone(), "sb_1", 2, 2, 900).unwrap();
        assert!(matches!(got.matches(&got.cell.clone(), "sb_2", 2, 2, 900), Err(PassError::Mismatch("another sandbox"))));
        assert!(matches!(got.matches("other", "sb_1", 2, 2, 900), Err(PassError::Mismatch("another cell"))));
        assert!(matches!(got.matches(&got.cell.clone(), "sb_1", 4, 2, 900), Err(PassError::Mismatch("another size"))));
        assert!(matches!(got.matches(&got.cell.clone(), "sb_1", 2, 2, 3600), Err(PassError::Mismatch("another timeout"))));
        assert!(matches!(checker.check(&pass, now + VALID_SECS + SKEW_SECS + 1), Err(PassError::Expired)));
        // The review's A2: a Drain (client) or cell-channel (server) certificate of the same CA
        // signs no pass; nor does another CA's pass signer.
        for eku in [ExtendedKeyUsagePurpose::ClientAuth, ExtendedKeyUsagePurpose::ServerAuth] {
            assert!(matches!(checker.check(&leaf(&issuer, eku).sign(&claims(now + 60)).unwrap(), now), Err(PassError::NotPassSigner)));
        }
        let (_, stranger) = ca();
        assert!(matches!(checker.check(&pass_signer(&stranger).sign(&claims(now + 60)).unwrap(), now), Err(PassError::NotOurs)));
        assert!(matches!(checker.check("", now), Err(PassError::Shape)));
        // A claim changed after signing fails the signature.
        let parts: Vec<&str> = pass.split('.').collect();
        let forged_claims = b64::encode_url(&serde_json::to_vec(&PassClaims { timeout_secs: 86_400, ..claims(now + 60) }).unwrap());
        let forged = format!("{}.{}.{}.{}.{}", parts[0], parts[1], parts[2], forged_claims, parts[4]);
        assert!(matches!(checker.check(&forged, now), Err(PassError::Signature(_))));
    }

    /// The review's A1: during a CA rotation the image's bundle holds the old CA and the new,
    /// and a pass under either is accepted.
    #[test]
    fn a_two_ca_bundle_accepts_a_pass_under_either() {
        let ((old_der, old), (new_der, new)) = (ca(), ca());
        let bundle = format!("{}{}", b64::pem("CERTIFICATE", &old_der), b64::pem("CERTIFICATE", &new_der));
        let checker = PassChecker::from_ca_pem(&bundle, project(PROJECT)).unwrap();
        let now = 1_800_000_000;
        for issuer in [&old, &new] {
            checker.check(&pass_signer(issuer).sign(&claims(now + 60)).unwrap(), now).unwrap();
        }
        let only_old = PassChecker::from_ca_pem(&b64::pem("CERTIFICATE", &old_der), project(PROJECT)).unwrap();
        assert!(matches!(only_old.check(&pass_signer(&new).sign(&claims(now + 60)).unwrap(), now), Err(PassError::NotOurs)));
    }

    /// The final read's A1: one CA serves every deployment, so a pass key from another
    /// deployment (staging's, for production's cells) is refused, as is a pass-signing
    /// certificate that names no deployment.
    #[test]
    fn a_pass_key_of_another_deployment_places_nothing_here() {
        let (ca_der, issuer) = ca();
        let checker = PassChecker::from_ca_pem(&b64::pem("CERTIFICATE", &ca_der), project(PROJECT)).unwrap();
        let now = 1_800_000_000;
        checker.check(&pass_signer_of(&issuer, PROJECT).sign(&claims(now + 60)).unwrap(), now).unwrap();
        let staging = pass_signer_of(&issuer, 123_456_789_012).sign(&claims(now + 60)).unwrap();
        assert!(matches!(checker.check(&staging, now), Err(PassError::OtherDeployment)));
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec!["pass".into()]).unwrap();
        p.custom_extensions = vec![CustomExtension::from_oid_content(&[2, 5, 29, 37], ExtendedKeyUsage(vec![PASS_SIGNING]).to_der().unwrap())];
        let unnamed = PassSigner::from_der(p.signed_by(&key, &issuer).unwrap().der(), &key.serialize_der()).unwrap();
        assert!(matches!(checker.check(&unnamed.sign(&claims(now + 60)).unwrap(), now), Err(PassError::OtherDeployment)));
        assert!("0".parse::<Project>().is_err() && "".parse::<Project>().is_err() && "12a".parse::<Project>().is_err());
    }

    /// Decided on 2026-11-11: the cell's project is the attested one. A metadata
    /// project agrees with MR_OWNER only when it is the project GCE wrote there; one the host
    /// substitutes, or no number at all, is refused.
    #[test]
    fn a_cells_project_counts_only_when_its_mr_owner_agrees() {
        let zone: crate::ids::Zone = "us-central1-a".parse().unwrap();
        let quoted = crate::tdx::mr_owner(4_242, PROJECT, &zone);
        assert_eq!(Project::attested(&PROJECT.to_string(), 4_242, &zone, &quoted).unwrap(), project(PROJECT));
        assert!(matches!(Project::attested("123456789012", 4_242, &zone, &quoted), Err(PassError::NotAttested(_))), "the host's word for another project");
        assert!(matches!(Project::attested(&PROJECT.to_string(), 4_243, &zone, &quoted), Err(PassError::NotAttested(_))), "another instance's MR_OWNER");
        assert!(Project::attested("", 4_242, &zone, &quoted).is_err());
    }
}
