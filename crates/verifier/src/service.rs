//! The verifier's gRPC API (`proto/clovelly/verifier/v1/verifier.proto`).
//!
//! `SealCredential`, `SealTemplateKey`, `ListReceipts` and `GetEgressLog` are the
//! customer's SDK's calls, authenticated by the SDK token (its SHA-256 is in the
//! configuration); every other call is open, since cells authenticate by attestation,
//! receipts by their signature and certificate chain, and the policy bundle is signed.
//! Unlock refusals carry only "check N". Every unlock attempt is logged as one JSON
//! line for Cloud Logging: the outcome of each check, the quote's measurements (public
//! values) and the caller's address, which on Cloud Run is the cell's NAT address.

use std::collections::BTreeSet;
use std::fmt::Display;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::{constant_time, digest};
use common::cred::{AdapterType, Binding, CredName};
use common::evidence::Evidence;
use common::ids::{EnvId, SandboxId, SubenvId};
use common::proto::verifier::verifier_server::Verifier as Api;
use common::proto::verifier::{
    AppendReceiptRequest, AppendReceiptResponse, GetCaRequest, GetCaResponse, GetEgressLogRequest,
    GetEgressLogResponse, GetNonceRequest, GetNonceResponse, GetPolicyRequest, GetPolicyResponse,
    ListReceiptsRequest, ListReceiptsResponse, SealCredentialRequest, SealCredentialResponse,
    SealTemplateKeyRequest, SealTemplateKeyResponse, UnlockRequest, UnlockResponse,
};
use common::receipt::MeasurementSet;
use common::tdx::Quote;
use common::template::Digest;
use serde_json::json;
use tonic::{Request, Response, Status};

use crate::checks::{Check, Outcome, Report};
use crate::keys::Keys;
use crate::receipts::{self, ReceiptLog};
use crate::sources::Sources;
use crate::verifier::{SealError, UnlockError, Verifier};

pub use common::proto::verifier::verifier_server::VerifierServer;

/// Unix seconds now: the production clock.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The clock the service evaluates unlocks and nonces at: the system clock, or, in a
/// build with the `test-clock` feature only, the system clock moved by a fixed offset,
/// so a staging verifier can be asked about hour 73 of a release now (SPEC.md phase 5
/// criteria 3 to 5). The production image is built without the feature, so its clock
/// cannot be moved.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Clock {
    offset_secs: i64,
}

impl Clock {
    pub fn system() -> Self {
        Self::default()
    }

    /// The system clock moved by `secs`.
    #[cfg(feature = "test-clock")]
    pub fn offset(secs: i64) -> Self {
        Self { offset_secs: secs }
    }

    pub fn offset_secs(&self) -> i64 {
        self.offset_secs
    }

    pub fn now(&self) -> u64 {
        now().saturating_add_signed(self.offset_secs)
    }
}

/// Unix milliseconds now, for the receipt log.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn invalid(e: impl Display) -> Status {
    Status::invalid_argument(e.to_string())
}

pub struct Service<S, K> {
    verifier: Arc<Verifier<S, K>>,
    /// The customer's receipt log. Its records are verified against the measurement
    /// set of the release policy in force when they arrive.
    receipts: ReceiptLog,
    clock: Clock,
}

impl<S: Sources, K: Keys> Service<S, K> {
    pub fn new(verifier: Arc<Verifier<S, K>>, clock: Clock) -> Self {
        Self {
            verifier,
            receipts: ReceiptLog::default(),
            clock,
        }
    }

    /// Refuses a call without the SDK token.
    fn sdk_only<T>(&self, req: &Request<T>, call: &str) -> Result<(), Status> {
        if sdk_token_ok(req.metadata(), self.verifier.config().sdk_token_sha256.as_deref()) {
            Ok(())
        } else {
            Err(Status::unauthenticated(format!("{call} needs the SDK token")))
        }
    }

    /// Refuses a call for an environment this verifier does not serve.
    fn our_env(&self, env: &str) -> Result<(), Status> {
        if env == self.verifier.config().env.as_str() {
            Ok(())
        } else {
            Err(Status::not_found("this verifier does not serve that environment"))
        }
    }
}

#[tonic::async_trait]
impl<S: Sources + 'static, K: Keys + 'static> Api for Service<S, K> {
    async fn get_nonce(
        &self,
        req: Request<GetNonceRequest>,
    ) -> Result<Response<GetNonceResponse>, Status> {
        let env: EnvId = req
            .into_inner()
            .env_id
            .parse()
            .map_err(|e| Status::invalid_argument(format!("{e}")))?;
        let nonce = self
            .verifier
            .issue_nonce(&env, self.clock.now())
            .ok_or_else(|| Status::not_found("this verifier does not serve that environment"))?;
        Ok(Response::new(GetNonceResponse {
            nonce: nonce.0.to_vec(),
        }))
    }

    async fn unlock(&self, req: Request<UnlockRequest>) -> Result<Response<UnlockResponse>, Status> {
        let started = Instant::now();
        let client = req
            .metadata()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .or_else(|| req.remote_addr().map(|a| a.ip().to_string()))
            .unwrap_or_default();
        let ev: Evidence = req
            .into_inner()
            .evidence
            .ok_or_else(|| Status::invalid_argument("no evidence"))?
            .try_into()
            .map_err(|e| Status::invalid_argument(format!("{e}")))?;
        let result = self.verifier.unlock(&ev, self.clock.now()).await;
        log_unlock(&ev, &client, &result, started.elapsed().as_secs_f64() * 1e3);
        match result {
            Ok((u, _)) => Ok(Response::new(UnlockResponse {
                cell_cert: u.cell_cert,
                wrapped_env_dek: u.wrapped_dek,
                policy_bundle: u.policy_bundle,
                policy_sig: u.policy_sig,
                release_valid_until: u.release_valid_until,
                policy_key: u.policy_key,
            })),
            Err(UnlockError::Refused { check, .. }) => {
                Err(Status::permission_denied(format!("check {}", check.number())))
            }
            Err(e @ UnlockError::UnknownSubenv(_)) => Err(Status::invalid_argument(e.to_string())),
            Err(e) => Err(Status::unavailable(e.to_string())),
        }
    }

    async fn get_ca(&self, req: Request<GetCaRequest>) -> Result<Response<GetCaResponse>, Status> {
        if req.into_inner().env_id != self.verifier.config().env.as_str() {
            return Err(Status::not_found("this verifier does not serve that environment"));
        }
        Ok(Response::new(GetCaResponse {
            ca_cert: self.verifier.ca_der().to_vec(),
            previous_ca_certs: self.verifier.ca_ders().skip(1).map(<[u8]>::to_vec).collect(),
        }))
    }

    async fn get_policy(&self, req: Request<GetPolicyRequest>) -> Result<Response<GetPolicyResponse>, Status> {
        let r = req.into_inner();
        if r.env_id != self.verifier.config().env.as_str() {
            return Err(Status::not_found("this verifier does not serve that environment"));
        }
        let subenv: SubenvId = r.subenv_id.parse().map_err(|e| Status::invalid_argument(format!("{e}")))?;
        let (bundle, sig) = self
            .verifier
            .policy_bundle(&subenv)
            .ok_or_else(|| Status::not_found("no such sub-environment"))?;
        Ok(Response::new(GetPolicyResponse {
            policy_bundle: bundle.as_bytes().to_vec(),
            policy_sig: sig.to_owned(),
        }))
    }

    async fn seal_credential(
        &self,
        req: Request<SealCredentialRequest>,
    ) -> Result<Response<SealCredentialResponse>, Status> {
        self.sdk_only(&req, "SealCredential")?;
        let mut r = req.into_inner();
        let sealed = seal(&self.verifier, &r).await;
        common::dek::wipe(&mut r.secret);
        let sealed = sealed?;
        println!(
            "{}",
            json!({ "severity": "INFO", "event": "seal", "subenv": r.subenv_id, "name": r.name,
                    "adapter": r.adapter, "destination": r.destination })
        );
        Ok(Response::new(SealCredentialResponse {
            sealed: sealed.to_json(),
        }))
    }

    async fn seal_template_key(
        &self,
        req: Request<SealTemplateKeyRequest>,
    ) -> Result<Response<SealTemplateKeyResponse>, Status> {
        self.sdk_only(&req, "SealTemplateKey")?;
        let r = req.into_inner();
        self.our_env(&r.env_id)?;
        let subenv: SubenvId = r.subenv_id.parse().map_err(invalid)?;
        let digest: Digest = r.digest.parse().map_err(invalid)?;
        let (key, sealed) = self
            .verifier
            .seal_template_key(&subenv, &digest)
            .await
            .map_err(seal_status)?;
        println!(
            "{}",
            json!({ "severity": "INFO", "event": "seal-template-key", "subenv": r.subenv_id, "digest": r.digest })
        );
        // The key goes to the SDK over TLS; `key` itself is wiped when dropped here.
        Ok(Response::new(SealTemplateKeyResponse {
            key: key.as_bytes().to_vec(),
            sealed_key: sealed.to_json(),
        }))
    }

    async fn append_receipt(
        &self,
        req: Request<AppendReceiptRequest>,
    ) -> Result<Response<AppendReceiptResponse>, Status> {
        let env = &self.verifier.config().env;
        let cas: Vec<&[u8]> = self.verifier.ca_ders().collect();
        let measurements: MeasurementSet = self.verifier.policy().measurement_set();
        let checked = req
            .into_inner()
            .records
            .into_iter()
            .enumerate()
            .map(|(i, r)| receipts::check(r, env, &cas, &measurements).map_err(|e| (i, e)))
            .collect::<Result<Vec<_>, _>>();
        match checked {
            Ok(records) => {
                self.receipts.append(records, now_ms());
                Ok(Response::new(AppendReceiptResponse {}))
            }
            Err((i, e)) => {
                println!(
                    "{}",
                    json!({ "severity": "WARNING", "event": "receipt-refused", "record": i, "error": e.to_string() })
                );
                Err(Status::invalid_argument(format!("record {i}: {e}")))
            }
        }
    }

    async fn list_receipts(
        &self,
        req: Request<ListReceiptsRequest>,
    ) -> Result<Response<ListReceiptsResponse>, Status> {
        self.sdk_only(&req, "ListReceipts")?;
        let r = req.into_inner();
        self.our_env(&r.env_id)?;
        let subenv: Option<SubenvId> = match r.subenv_id.as_str() {
            "" => None,
            s => Some(s.parse().map_err(invalid)?),
        };
        let sandboxes: BTreeSet<SandboxId> = r
            .sandbox_ids
            .iter()
            .map(|s| s.parse())
            .collect::<Result<_, _>>()
            .map_err(invalid)?;
        Ok(Response::new(ListReceiptsResponse {
            receipts: self.receipts.list(subenv.as_ref(), &sandboxes, now_ms()),
        }))
    }

    async fn get_egress_log(
        &self,
        req: Request<GetEgressLogRequest>,
    ) -> Result<Response<GetEgressLogResponse>, Status> {
        self.sdk_only(&req, "GetEgressLog")?;
        let r = req.into_inner();
        self.our_env(&r.env_id)?;
        let sandbox: SandboxId = r.sandbox_id.parse().map_err(invalid)?;
        let lines = self
            .receipts
            .egress_log(&sandbox)
            .ok_or_else(|| Status::not_found("no final receipt for that sandbox"))?;
        let sha256 = receipts::egress_log_sha256(&lines);
        Ok(Response::new(GetEgressLogResponse { lines, sha256 }))
    }
}

/// Whether the call carries `authorization: Bearer <t>` with SHA-256(t) equal to the
/// configured hash.
fn sdk_token_ok(md: &tonic::metadata::MetadataMap, want_hex: Option<&str>) -> bool {
    let (Some(want), Some(got)) = (
        want_hex.and_then(common::unhex),
        md.get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer ")),
    ) else {
        return false;
    };
    let hash = digest::digest(&digest::SHA256, got.as_bytes());
    constant_time::verify_slices_are_equal(hash.as_ref(), &want).is_ok()
}

async fn seal<S: Sources + 'static, K: Keys + 'static>(
    v: &Verifier<S, K>,
    r: &SealCredentialRequest,
) -> Result<common::cred::Sealed, Status> {
    let bad = |e: String| Status::invalid_argument(e);
    if r.env_id != v.config().env.as_str() {
        return Err(Status::not_found("this verifier does not serve that environment"));
    }
    let subenv: SubenvId = r.subenv_id.parse().map_err(|e| bad(format!("{e}")))?;
    let binding = Binding {
        name: r.name.parse::<CredName>().map_err(|e| bad(e.to_string()))?,
        adapter: r.adapter.parse::<AdapterType>().map_err(|e| bad(e.to_string()))?,
        destination: r.destination.parse().map_err(|e: common::bundle::HostNameError| bad(e.to_string()))?,
    };
    v.seal_credential(&subenv, &binding, &r.secret).await.map_err(seal_status)
}

fn seal_status(e: SealError) -> Status {
    match e {
        SealError::UnknownSubenv(_) => Status::not_found(e.to_string()),
        SealError::Credential(_) | SealError::Template(_) => invalid(e),
        other => Status::unavailable(other.to_string()),
    }
}

fn outcomes(report: &Report) -> serde_json::Value {
    Check::ALL
        .iter()
        .map(|c| {
            let o = match report.outcome(*c) {
                Some(Outcome::Pass) => "pass".to_owned(),
                Some(Outcome::Fail(f)) => format!("fail: {f:?}"),
                Some(Outcome::Skipped(on)) => format!("skipped: {on} failed"),
                None => "not run".to_owned(),
            };
            (c.number().to_string(), json!(o))
        })
        .collect::<serde_json::Map<_, _>>()
        .into()
}

fn log_unlock(ev: &Evidence, client: &str, result: &Result<(crate::Unlocked, Report), UnlockError>, ms: f64) {
    let quote = Quote::parse(&ev.quote).ok().map(|q| {
        json!({
            "mrtd": q.mr_td.to_string(),
            "rtmr": q.rtmrs.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "mrseam": q.mr_seam.to_string(),
            "xfam": q.xfam,
            "tee_tcb_svn": common::hex(&q.tee_tcb_svn),
            "td_attributes": q.td_attributes,
        })
    });
    let (result, check, report, error) = match result {
        Ok((_, r)) => ("accepted", None, Some(outcomes(r)), None),
        Err(UnlockError::Refused { check, report }) => {
            ("refused", Some(check.number()), Some(outcomes(report)), None)
        }
        Err(e) => ("error", None, None, Some(e.to_string())),
    };
    let line = json!({
        "severity": if result == "accepted" { "INFO" } else { "WARNING" },
        "message": format!("unlock {result} for instance {} ({})", ev.instance_id, ev.release),
        "event": "unlock",
        "result": result,
        "check": check,
        "env": ev.env.as_str(),
        "subenv": ev.subenv.as_str(),
        "release": ev.release.as_str(),
        "instance_id": ev.instance_id.to_string(),
        "zone": ev.zone.as_str(),
        "client_ip": client,
        "ms": ms,
        "checks": report,
        "error": error,
        "quote": quote,
    });
    println!("{line}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::metadata::{MetadataMap, MetadataValue};

    fn bearer(token: &str) -> MetadataMap {
        let mut md = MetadataMap::new();
        md.insert("authorization", MetadataValue::try_from(format!("Bearer {token}")).unwrap());
        md
    }

    /// SealCredential needs the SDK token: its SHA-256 must equal the configured hash.
    #[test]
    fn the_sdk_token_must_match_its_hash() {
        let hash = common::hex(digest::digest(&digest::SHA256, b"s3cret").as_ref());
        assert!(sdk_token_ok(&bearer("s3cret"), Some(&hash)));
        assert!(!sdk_token_ok(&bearer("other"), Some(&hash)));
        assert!(!sdk_token_ok(&MetadataMap::new(), Some(&hash)));
        assert!(!sdk_token_ok(&bearer("s3cret"), None), "no configured token refuses every seal");
    }

    /// The service's tests: a verifier for environment `staging` (sub-environments `a`
    /// and `b`) whose environment CA is a test CA, and cells it certifies.
    mod fixture {
        use std::collections::BTreeMap;

        use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
        use common::cellcert::{self, CellCertInfo};
        use common::tdx::Measurement;
        use rcgen::{BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, Issuer, KeyPair};
        use serde_json::{Value, json};
        use tonic::Request;
        use tonic::metadata::MetadataValue;

        use crate::config::{Ca, Config, Subenv};
        use crate::keys::LocalKms;
        use crate::policy::ReleasePolicy;
        use crate::service::Service;
        use crate::sources::{Collateral, SourceError, Sources};
        use crate::verifier::Verifier;

        pub const TOKEN: &str = "sdk-token";
        pub const RELEASE: &str = "clovelly-0.4.0-prod";
        /// Sub-environment `a`'s DEK (`LocalKms` "decrypts" to the configured bytes).
        pub const DEK_A: [u8; 32] = [7; 32];

        /// Unlock is not exercised here, so nothing is ever fetched.
        pub struct NoSources;

        fn unused() -> SourceError {
            SourceError {
                what: "test",
                source: "these tests fetch nothing".into(),
            }
        }

        impl Sources for NoSources {
            async fn collateral(&self, _: &str, _: &str, _: u64) -> Result<Collateral, SourceError> {
                Err(unused())
            }

            async fn host_registered(&self, _: &str, _: u64) -> Result<bool, SourceError> {
                Err(unused())
            }

            async fn endorsement(&self, _: &Measurement) -> Result<Option<Vec<u8>>, SourceError> {
                Err(unused())
            }
        }

        /// An environment CA and the cell certificates it issues.
        pub struct TestCa {
            issuer: Issuer<'static, KeyPair>,
            pub pem: String,
        }

        impl TestCa {
            pub fn new() -> Self {
                let key = KeyPair::generate().unwrap();
                let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
                p.distinguished_name.push(DnType::CommonName, "test staging environment CA");
                p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                let pem = common::b64::pem("CERTIFICATE", p.self_signed(&key).unwrap().der());
                Self { issuer: Issuer::new(p, key), pem }
            }

            /// A cell key of sub-environment `a` and its certificate.
            pub fn cell(&self) -> (EcdsaKeyPair, Vec<u8>) {
                let info = CellCertInfo {
                    quote_sha256: [9; 32],
                    env: "staging".parse().unwrap(),
                    subenv: "a".parse().unwrap(),
                    release: RELEASE.parse().unwrap(),
                };
                let key = KeyPair::generate().unwrap();
                let mut p = CertificateParams::new(vec!["a.staging.cells.clovelly.internal".to_owned()]).unwrap();
                p.custom_extensions = vec![CustomExtension::from_oid_content(&cellcert::OID_ARCS, info.to_der())];
                let cert = p.signed_by(&key, &self.issuer).unwrap().der().to_vec();
                let signing = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &key.serialize_der()).unwrap();
                (signing, cert)
            }
        }

        pub fn rtmr(i: u8) -> String {
            Measurement([i; 48]).to_string()
        }

        pub fn service(ca: &TestCa) -> Service<NoSources, LocalKms> {
            rotated_service(ca, &[])
        }

        /// A service whose current CA is `ca` and which `previous` handed over to.
        pub fn rotated_service(ca: &TestCa, previous: &[&TestCa]) -> Service<NoSources, LocalKms> {
            let subenv = |dek: [u8; 32]| Subenv {
                wrapped_dek: common::b64::encode(&dek),
                policy_bundle: "{}".into(),
                policy_sig: String::new(),
            };
            let config = Config {
                env: "staging".parse().unwrap(),
                subenvs: BTreeMap::from([("a".parse().unwrap(), subenv(DEK_A)), ("b".parse().unwrap(), subenv([8; 32]))]),
                ca: Ca {
                    key: "ca".into(),
                    cert_pem: ca.pem.clone(),
                    previous_cert_pem: previous.iter().map(|c| c.pem.clone()).collect(),
                },
                dek_key: "dek".into(),
                release_keys: vec![],
                policy_key_pem: String::new(),
                sdk_token_sha256: Some(common::hex(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, TOKEN.as_bytes()).as_ref())),
                pinned_releases: vec![],
                fragments_url: None,
                rekor_keys: vec![],
                collateral_cache_secs: 0,
            };
            let policy: ReleasePolicy = serde_json::from_value(json!({
                "v": 1, "project_number": 123456789012u64, "allowed_zones": ["us-central1-a"], "xfam": 0,
                "mrseam": [], "tee_tcb_svn_floor": "00".repeat(16), "sw_hardening_advisories": [],
                "nonce_ttl_secs": 300, "endorsements_url": "https://example.invalid/",
                "releases": [{ "id": RELEASE, "rtmr": [rtmr(0), rtmr(1), rtmr(2), rtmr(3)],
                               "published_at": 0, "notice_secs": 0, "valid_until": 4_000_000_000u64 }]
            }))
            .unwrap();
            let v = Verifier::new(config, policy, vec![], vec![], NoSources, LocalKms::generate(&[])).unwrap();
            Service::new(std::sync::Arc::new(v), crate::service::Clock::system())
        }

        pub fn authed<T>(msg: T, token: &str) -> Request<T> {
            let mut r = Request::new(msg);
            r.metadata_mut().insert("authorization", MetadataValue::try_from(format!("Bearer {token}")).unwrap());
            r
        }

        /// A receipt of sandbox `id` in sub-environment `a`, as a cell writes it.
        pub fn doc(id: &str, seq: u64, kind: &str, egress_log_hash: &str) -> Value {
            json!({
                "v": 1, "seq": seq, "env": "staging", "subenv": "a", "release": RELEASE,
                "cell": {"instance": "123", "zone": "us-central1-a", "project": "123456789012"},
                "measurements": {"mrtd": "dd", "rtmr": [rtmr(0), rtmr(1), rtmr(2), rtmr(3)]},
                "sandbox": {"id": id, "identity_spki": "MFkw", "template_digest": null, "volume_id": null,
                            "volume_epoch": null},
                "policy_hash": "ph", "creds_released": [], "egress_log_hash": egress_log_hash,
                "egress_log_count": 2, "egress_gaps": [], "signed": "2026-10-27T12:00:10.000Z",
                "started": "2026-10-27T12:00:00.000Z", "ended": null, "exit": {"kind": kind, "code": null}
            })
        }
    }

    use common::proto::verifier::LogRecord;
    use common::template::{SealedKey, open_key};
    use fixture::*;

    fn record(doc: &serde_json::Value, key: &aws_lc_rs::signature::EcdsaKeyPair, cert: &[u8], egress: Option<&[&str]>) -> LogRecord {
        let (json, signature) = common::receipt::sign(doc, key).unwrap();
        LogRecord {
            receipt: json,
            signature,
            cell_cert: cert.to_vec(),
            r#final: egress.is_some(),
            egress_log: egress.into_iter().flatten().map(|l| (*l).to_owned()).collect(),
        }
    }

    async fn listed(svc: &Service<NoSources, crate::keys::LocalKms>) -> Vec<common::proto::verifier::LoggedReceipt> {
        let req = ListReceiptsRequest { env_id: "staging".into(), ..Default::default() };
        svc.list_receipts(authed(req, TOKEN)).await.unwrap().into_inner().receipts
    }

    /// Criterion 3: the template key the verifier issues opens only under its
    /// sub-environment's DEK and for its digest, and only the SDK token gets one.
    #[tokio::test]
    async fn seal_template_key_issues_a_key_only_its_subenvs_dek_opens() {
        let svc = service(&TestCa::new());
        let digest = Digest::of(b"a template");
        let req = |subenv: &str, digest: &str| SealTemplateKeyRequest {
            env_id: "staging".into(),
            subenv_id: subenv.into(),
            digest: digest.into(),
        };
        let r = svc.seal_template_key(authed(req("a", &digest.hex()), TOKEN)).await.unwrap().into_inner();
        let sealed = SealedKey::from_json(&r.sealed_key).unwrap();
        let (env, a, b) = ("staging".parse().unwrap(), "a".parse().unwrap(), "b".parse().unwrap());
        let opened = open_key(&common::dek::Dek::from_bytes(DEK_A), &env, &a, &digest, &sealed).unwrap();
        assert_eq!(opened.as_bytes().as_slice(), r.key.as_slice());
        assert!(open_key(&common::dek::Dek::from_bytes([8; 32]), &env, &b, &digest, &sealed).is_err());
        assert!(open_key(&common::dek::Dek::from_bytes(DEK_A), &env, &a, &Digest::of(b"other"), &sealed).is_err());

        let code = |r: Result<Response<SealTemplateKeyResponse>, Status>| r.map(drop).unwrap_err().code();
        assert_eq!(code(svc.seal_template_key(authed(req("a", &digest.hex()), "wrong")).await), tonic::Code::Unauthenticated);
        assert_eq!(code(svc.seal_template_key(Request::new(req("a", &digest.hex()))).await), tonic::Code::Unauthenticated);
        assert_eq!(code(svc.seal_template_key(authed(req("zz", &digest.hex()), TOKEN)).await), tonic::Code::NotFound);
        assert_eq!(code(svc.seal_template_key(authed(req("a", "ABC"), TOKEN)).await), tonic::Code::InvalidArgument);
    }

    /// AppendReceipt keeps a receipt that verifies under the environment CA and the
    /// release policy's measurements, and refuses the whole call, keeping nothing, when
    /// one record has a changed field or a certificate from another CA.
    #[tokio::test]
    async fn append_receipt_keeps_signed_receipts_and_refuses_altered_or_foreign_ones() {
        let ca = TestCa::new();
        let svc = service(&ca);
        let (key, cert) = ca.cell();
        let (a, b) = ("0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210");
        let good = record(&doc(a, 1, "cell_lost", "eh"), &key, &cert, None);
        svc.append_receipt(Request::new(AppendReceiptRequest { records: vec![good.clone()] })).await.unwrap();
        let logged = listed(&svc).await;
        assert_eq!(logged.len(), 1);
        assert_eq!((logged[0].receipt.as_slice(), logged[0].r#final, logged[0].records), (good.receipt.as_slice(), false, 1));

        // A changed field: the exit kind, re-canonicalised, under the old signature.
        let mut altered = record(&doc(b, 2, "exited", "eh"), &key, &cert, Some(&[]));
        altered.receipt = common::jcs::canonical(&doc(b, 2, "killed", "eh")).unwrap();
        let fine = record(&doc(b, 1, "cell_lost", "eh"), &key, &cert, None);
        let err = svc
            .append_receipt(Request::new(AppendReceiptRequest { records: vec![fine.clone(), altered] }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().starts_with("record 1: the receipt's signature"), "{}", err.message());

        // A cell certificate from another CA.
        let (foreign_key, foreign_cert) = TestCa::new().cell();
        let foreign = record(&doc(b, 3, "exited", "eh"), &foreign_key, &foreign_cert, Some(&[]));
        let err = svc
            .append_receipt(Request::new(AppendReceiptRequest { records: vec![fine, foreign] }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("not signed by the environment CA"), "{}", err.message());

        assert_eq!(listed(&svc).await.len(), 1, "nothing from a refused call was kept");
    }

    /// Criterion 11: after the environment CA rotates, a cell still on its old lease
    /// signs receipts the verifier accepts and GetCA names both; once the old CA leaves
    /// the configuration its certificates are refused.
    #[tokio::test]
    async fn ca_rotation_keeps_receipts_of_cells_on_the_old_lease() {
        let (old, new) = (TestCa::new(), TestCa::new());
        let svc = rotated_service(&new, &[&old]);
        let id = "0123456789abcdef0123456789abcdef";
        let (old_key, old_cert) = old.cell();
        let (new_key, new_cert) = new.cell();
        for (key, cert, seq) in [(&old_key, &old_cert, 1), (&new_key, &new_cert, 2)] {
            let r = record(&doc(id, seq, "cell_lost", "eh"), key, cert, None);
            svc.append_receipt(Request::new(AppendReceiptRequest { records: vec![r] })).await.unwrap();
        }
        let got = svc.get_ca(Request::new(GetCaRequest { env_id: "staging".into() })).await.unwrap().into_inner();
        assert_eq!(common::b64::pem("CERTIFICATE", &got.ca_cert), new.pem);
        assert_eq!(got.previous_ca_certs.len(), 1);
        assert_eq!(common::b64::pem("CERTIFICATE", &got.previous_ca_certs[0]), old.pem);

        let retired = service(&new);
        let r = record(&doc(id, 3, "cell_lost", "eh"), &old_key, &old_cert, None);
        let err = retired.append_receipt(Request::new(AppendReceiptRequest { records: vec![r] })).await.unwrap_err();
        assert!(err.message().contains("not signed by the environment CA"), "{}", err.message());
    }

    /// Criterion 10: GetEgressLog returns the lines that came with a sandbox's final
    /// receipt and their SHA-256, which equals the receipt's egress_log_hash.
    #[tokio::test]
    async fn get_egress_log_returns_the_final_receipts_lines_and_their_hash() {
        let ca = TestCa::new();
        let svc = service(&ca);
        let (key, cert) = ca.cell();
        let id = "0123456789abcdef0123456789abcdef";
        let lines = [r#"{"dest":"api.openai.com:443","result":"allowed"}"#, r#"{"dest":"x:443","result":"denied"}"#];
        let hash = common::hex(digest::digest(&digest::SHA256, format!("{}\n{}\n", lines[0], lines[1]).as_bytes()).as_ref());
        let req = || GetEgressLogRequest { env_id: "staging".into(), sandbox_id: id.into() };

        let interim = record(&doc(id, 1, "cell_lost", &hash), &key, &cert, None);
        svc.append_receipt(Request::new(AppendReceiptRequest { records: vec![interim] })).await.unwrap();
        assert_eq!(svc.get_egress_log(authed(req(), TOKEN)).await.unwrap_err().code(), tonic::Code::NotFound);

        let fin = record(&doc(id, 2, "exited", &hash), &key, &cert, Some(&lines));
        svc.append_receipt(Request::new(AppendReceiptRequest { records: vec![fin] })).await.unwrap();
        let got = svc.get_egress_log(authed(req(), TOKEN)).await.unwrap().into_inner();
        assert_eq!(got.lines, lines);
        assert_eq!(got.sha256, hash);
        let logged = listed(&svc).await;
        let receipt: serde_json::Value = serde_json::from_slice(&logged[0].receipt).unwrap();
        assert_eq!(receipt["egress_log_hash"], got.sha256.as_str());
        assert_eq!((logged[0].r#final, logged[0].records, logged[0].finals), (true, 2, 1));

        assert_eq!(svc.get_egress_log(Request::new(req())).await.unwrap_err().code(), tonic::Code::Unauthenticated);
    }
}
