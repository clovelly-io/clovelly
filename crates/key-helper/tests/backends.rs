//! The two backends against fakes of their key managers' wire protocols: the requests they
//! send and how each answer maps onto the contract. The real services are in the TDX job,
//! and for AWS in `docs/independent/` until an account exists (phase 8 criterion 7).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use aws_lc_rs::digest::{self, Digest};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use aws_sdk_kms::config::{Credentials, Region};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use common::b64;
use key_helper::aws::AwsKms;
use key_helper::gcp::{CloudKms, Place, Token};
use key_helper::server::{self, Allowed};
use serde_json::{Value, json};
use verifier::check_keys::{self, Suite};
use verifier::keys::{KeyError, Keys, Op};

fn generate() -> Arc<EcdsaKeyPair> {
    Arc::new(EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap())
}

fn spki(pair: &EcdsaKeyPair) -> Vec<u8> {
    pair.public_key().as_der().unwrap().as_ref().to_vec()
}

fn sign_digest(pair: &EcdsaKeyPair, d: &[u8]) -> Vec<u8> {
    let d = Digest::import_less_safe(d, &digest::SHA256).unwrap();
    pair.sign_digest(&d).unwrap().as_ref().to_vec()
}

async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    url
}

/// Cloud KMS as its REST API behaves: the operations this backend uses, on one ring.
#[derive(Default)]
struct FakeGcp {
    pairs: BTreeMap<String, Arc<EcdsaKeyPair>>,
    /// Every request, `METHOD path?query`.
    seen: Vec<String>,
    /// Every `setIamPolicy` body, by key path.
    grants: BTreeMap<String, Value>,
    /// A status every use of a key answers, as a disabled version does.
    forced: Option<u16>,
}

type Gcp = Arc<Mutex<FakeGcp>>;

fn gcp_error(status: u16, message: &str) -> Response {
    (StatusCode::from_u16(status).unwrap(), json!({ "error": { "code": status, "message": message } }).to_string()).into_response()
}

async fn fake_gcp(State(state): State<Gcp>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let body: Bytes = axum::body::to_bytes(body, 1 << 20).await.unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let path = parts.uri.path().trim_start_matches("/v1/").to_owned();
    let query = parts.uri.query().unwrap_or_default().to_owned();
    let mut fake = state.lock().unwrap();
    fake.seen.push(format!("{} {path}?{query}", parts.method));
    assert_eq!(
        parts.headers.get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()),
        Some("Bearer operator-token"),
        "{path}"
    );
    if let Some(status) = fake.forced {
        return gcp_error(status, "forced");
    }
    if let Some(key) = path.strip_suffix(":setIamPolicy") {
        fake.grants.insert(key.to_owned(), body);
        return Json(json!({})).into_response();
    }
    if parts.method == Method::POST && path.ends_with("/keyRings") {
        return Json(json!({})).into_response();
    }
    if parts.method == Method::POST && path.ends_with("/cryptoKeys") {
        let id = query.split("cryptoKeyId=").nth(1).unwrap().to_owned();
        let name = format!("{path}/{id}");
        if fake.pairs.contains_key(&name) {
            return gcp_error(409, "already exists");
        }
        fake.pairs.insert(name, generate());
        return Json(json!({})).into_response();
    }
    if parts.method == Method::GET && path.contains("/cryptoKeyVersions/") && !path.ends_with("/publicKey") {
        return Json(json!({ "state": "ENABLED" })).into_response();
    }
    let key_of = |p: &str| p.split("/cryptoKeyVersions/").next().unwrap().to_owned();
    if let Some(version) = path.strip_suffix("/publicKey") {
        return match fake.pairs.get(&key_of(version)) {
            Some(pair) => Json(json!({ "pem": b64::pem("PUBLIC KEY", &spki(pair)) })).into_response(),
            None => gcp_error(404, "not found"),
        };
    }
    if let Some(version) = path.strip_suffix(":asymmetricSign") {
        let d = b64::decode(body["digest"]["sha256"].as_str().unwrap()).unwrap();
        return match fake.pairs.get(&key_of(version)) {
            Some(pair) => Json(json!({ "signature": b64::encode(&sign_digest(pair, &d)) })).into_response(),
            None => gcp_error(404, "not found"),
        };
    }
    // Symmetric "encryption": a reversal, tagged so that garbage does not open.
    if let Some(key) = path.strip_suffix(":encrypt") {
        if !fake.pairs.contains_key(key) {
            return gcp_error(404, "not found");
        }
        let mut c = b64::decode(body["plaintext"].as_str().unwrap()).unwrap();
        c.reverse();
        c.extend_from_slice(b"sealed");
        return Json(json!({ "ciphertext": b64::encode(&c) })).into_response();
    }
    if let Some(key) = path.strip_suffix(":decrypt") {
        if !fake.pairs.contains_key(key) {
            return gcp_error(404, "not found");
        }
        let c = b64::decode(body["ciphertext"].as_str().unwrap()).unwrap();
        let Some(rest) = c.strip_suffix(b"sealed") else {
            return gcp_error(400, "Decryption failed: verify that 'name' refers to the correct CryptoKey.");
        };
        let mut p = rest.to_vec();
        p.reverse();
        return Json(json!({ "plaintext": b64::encode(&p) })).into_response();
    }
    gcp_error(403, "permission denied")
}

/// `axum::Json` needs a feature nothing else wants.
struct Json(Value);

impl IntoResponse for Json {
    fn into_response(self) -> Response {
        ([(header::CONTENT_TYPE, "application/json")], self.0.to_string()).into_response()
    }
}

async fn gcp_world() -> (Gcp, CloudKms) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let state: Gcp = Arc::default();
    let url = serve(Router::new().fallback(fake_gcp).with_state(state.clone())).await;
    let kms = CloudKms::at(Token::Fixed("operator-token".into()), &format!("{url}/v1"), "http://127.0.0.1:1/unused").unwrap();
    (state, kms)
}

fn place() -> Place {
    Place {
        project: "acme".into(),
        location: "antarctica".into(),
        key_ring: "acme-ring".into(),
        env: "prod".into(),
        service_account: "verifier@acme.example".into(),
    }
}

/// Criterion 4, on the fake: three keys, version-qualified where a key signs, and on each only
/// the grants the running role needs.
#[tokio::test]
async fn gcp_init_makes_three_keys_with_least_privilege_grants() {
    let (state, kms) = gcp_world().await;
    let names = kms.make_keys(&place()).await.unwrap();
    let ring = "projects/acme/locations/antarctica/keyRings/acme-ring";
    assert_eq!(names.ca, format!("{ring}/cryptoKeys/prod-env-ca/cryptoKeyVersions/1"));
    assert_eq!(names.policy, format!("{ring}/cryptoKeys/prod-policy/cryptoKeyVersions/1"));
    assert_eq!(names.dek, format!("{ring}/cryptoKeys/prod-dek"));

    let fake = state.lock().unwrap();
    let member = "serviceAccount:verifier@acme.example";
    let roles = |key: &str| -> Vec<String> {
        fake.grants[key]["policy"]["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| {
                assert_eq!(b["members"], json!([member]));
                b["role"].as_str().unwrap().to_owned()
            })
            .collect()
    };
    for k in ["prod-env-ca", "prod-policy"] {
        assert_eq!(roles(&format!("{ring}/cryptoKeys/{k}")), ["roles/cloudkms.signer", "roles/cloudkms.publicKeyViewer"]);
    }
    assert_eq!(roles(&format!("{ring}/cryptoKeys/prod-dek")), ["roles/cloudkms.cryptoKeyDecrypter"]);
}

/// A key that exists is not granted on again: re-running `init` changes nothing.
#[tokio::test]
async fn gcp_init_run_again_leaves_existing_keys_alone() {
    let (state, kms) = gcp_world().await;
    let first = kms.make_keys(&place()).await.unwrap();
    state.lock().unwrap().grants.clear();
    assert_eq!(kms.make_keys(&place()).await.unwrap(), first);
    assert!(state.lock().unwrap().grants.is_empty());
}

#[tokio::test]
async fn gcp_answers_map_onto_the_contract() {
    let (state, kms) = gcp_world().await;
    let names = kms.make_keys(&place()).await.unwrap();
    assert_eq!(kms.sign("absent", &[0; 32]).await, Err(KeyError::NoSuchKey { op: Op::Sign, key: "absent".into() }));
    for (status, want_denied) in [(403, true), (400, true), (401, false), (429, false), (500, false), (503, false)] {
        state.lock().unwrap().forced = Some(status);
        let got = kms.sign(&names.ca, &[0; 32]).await.unwrap_err();
        match got {
            KeyError::Denied { .. } => assert!(want_denied, "{status}"),
            KeyError::Unavailable { .. } => assert!(!want_denied, "{status}"),
            other => panic!("{status}: {other:?}"),
        }
    }
    // Nothing is listening: unavailable, not a panic and not denied.
    let dead = CloudKms::at(Token::Fixed("t".into()), "http://127.0.0.1:1/v1", "http://127.0.0.1:1/").unwrap();
    assert!(matches!(dead.decrypt("k", b"x").await, Err(KeyError::Unavailable { .. })));
}

/// The whole contract, through the reference server, with its allow list.
#[tokio::test]
async fn check_keys_passes_against_the_google_backend_on_its_fake() {
    let (_state, kms) = gcp_world().await;
    let names = kms.make_keys(&place()).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let served = Allowed::new(kms, [names.ca.clone(), names.policy.clone(), names.dek.clone()]);
    tokio::spawn(async move { axum::serve(listener, server::router(served)).await.unwrap() });
    let lines = check_keys::run(&url, &Suite { sign_keys: vec![names.ca, names.policy], dek_key: names.dek, vector: None }).await;
    assert!(check_keys::passed(&lines), "{lines:#?}");
}

/// A key the role may not touch and one that does not exist look alike to Cloud KMS at key level;
/// the allow list keeps them apart.
#[tokio::test]
async fn the_allow_list_answers_no_such_key_without_asking_the_key_manager() {
    let (state, kms) = gcp_world().await;
    let names = kms.make_keys(&place()).await.unwrap();
    state.lock().unwrap().forced = Some(403);
    let served = Allowed::new(kms, [names.dek.clone()]);
    assert_eq!(served.public_key("other").await, Err(KeyError::NoSuchKey { op: Op::PublicKey, key: "other".into() }));
    assert!(matches!(served.decrypt(&names.dek, b"x").await, Err(KeyError::Denied { .. })));
}

#[tokio::test]
async fn gcp_check_role_passes_only_if_every_act_is_refused() {
    let (state, kms) = gcp_world().await;
    let names = kms.make_keys(&place()).await.unwrap();
    state.lock().unwrap().forced = Some(403);
    let report = kms.check_role(&names.ca, &names.dek).await;
    assert_eq!(report.len(), 4);
    assert!(report.iter().all(|r| r.result.is_ok()), "{report:?}");
    state.lock().unwrap().forced = None;
    let too_strong = kms.check_role(&names.ca, &names.dek).await;
    assert!(too_strong.iter().any(|r| r.result.is_err()), "{too_strong:?}");
}

/// AWS KMS as its JSON protocol behaves: `POST /` with the operation in `x-amz-target`.
#[derive(Default)]
struct FakeAws {
    /// Key id to its pair, or to `None` for a symmetric key.
    keys: BTreeMap<String, Option<Arc<EcdsaKeyPair>>>,
    aliases: BTreeMap<String, String>,
    policies: BTreeMap<String, Value>,
    seen: Vec<(String, Value)>,
    /// An exception every operation answers.
    forced: Option<&'static str>,
}

type Aws = Arc<Mutex<FakeAws>>;

fn aws_error(code: &str) -> Response {
    let status = if code == "KMSInternalException" { StatusCode::INTERNAL_SERVER_ERROR } else { StatusCode::BAD_REQUEST };
    (status, [(header::CONTENT_TYPE, "application/x-amz-json-1.1")], json!({ "__type": code, "message": code }).to_string()).into_response()
}

fn aws_ok(v: Value) -> Response {
    ([(header::CONTENT_TYPE, "application/x-amz-json-1.1")], v.to_string()).into_response()
}

async fn fake_aws(State(state): State<Aws>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let op = parts.headers.get("x-amz-target").unwrap().to_str().unwrap().rsplit('.').next().unwrap().to_owned();
    let body: Bytes = axum::body::to_bytes(body, 1 << 20).await.unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    let mut fake = state.lock().unwrap();
    fake.seen.push((op.clone(), body.clone()));
    if let Some(code) = fake.forced {
        return aws_error(code);
    }
    let resolve = |fake: &FakeAws| {
        let id = body["KeyId"].as_str().unwrap();
        fake.aliases.get(id).cloned().unwrap_or_else(|| id.to_owned())
    };
    match op.as_str() {
        "DescribeKey" => {
            let id = resolve(&fake);
            if fake.keys.contains_key(&id) { aws_ok(json!({ "KeyMetadata": { "KeyId": id } })) } else { aws_error("NotFoundException") }
        }
        "CreateKey" => {
            let id = format!("key-{}", fake.keys.len());
            let signing = body["KeySpec"] == "ECC_NIST_P256";
            fake.keys.insert(id.clone(), signing.then(generate));
            fake.policies.insert(id.clone(), serde_json::from_str(body["Policy"].as_str().unwrap()).unwrap());
            aws_ok(json!({ "KeyMetadata": { "KeyId": id } }))
        }
        "CreateAlias" => {
            fake.aliases.insert(body["AliasName"].as_str().unwrap().to_owned(), body["TargetKeyId"].as_str().unwrap().to_owned());
            aws_ok(json!({}))
        }
        "GetPublicKey" => match fake.keys.get(&resolve(&fake)) {
            Some(Some(pair)) => aws_ok(json!({ "PublicKey": b64::encode(&spki(pair)) })),
            Some(None) => aws_error("InvalidKeyUsageException"),
            None => aws_error("NotFoundException"),
        },
        "Sign" => {
            assert_eq!(body["MessageType"], "DIGEST");
            assert_eq!(body["SigningAlgorithm"], "ECDSA_SHA_256");
            let d = b64::decode(body["Message"].as_str().unwrap()).unwrap();
            match fake.keys.get(&resolve(&fake)) {
                Some(Some(pair)) => aws_ok(json!({ "Signature": b64::encode(&sign_digest(pair, &d)) })),
                Some(None) => aws_error("InvalidKeyUsageException"),
                None => aws_error("NotFoundException"),
            }
        }
        "Encrypt" => {
            if !fake.keys.contains_key(&resolve(&fake)) {
                return aws_error("NotFoundException");
            }
            let mut c = b64::decode(body["Plaintext"].as_str().unwrap()).unwrap();
            c.reverse();
            c.extend_from_slice(b"sealed");
            aws_ok(json!({ "CiphertextBlob": b64::encode(&c) }))
        }
        "Decrypt" => {
            if !fake.keys.contains_key(&resolve(&fake)) {
                return aws_error("NotFoundException");
            }
            let c = b64::decode(body["CiphertextBlob"].as_str().unwrap()).unwrap();
            let Some(rest) = c.strip_suffix(b"sealed") else {
                return aws_error("InvalidCiphertextException");
            };
            let mut p = rest.to_vec();
            p.reverse();
            aws_ok(json!({ "Plaintext": b64::encode(&p) }))
        }
        _ => aws_error("AccessDeniedException"),
    }
}

async fn aws_world() -> (Aws, AwsKms) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let state: Aws = Arc::default();
    let url = serve(Router::new().fallback(fake_aws).with_state(state.clone())).await;
    let config = aws_sdk_kms::Config::builder()
        .behavior_version(aws_sdk_kms::config::BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .endpoint_url(url)
        .credentials_provider(Credentials::new("fake", "fake", None, None, "the fake's own"))
        .retry_config(aws_sdk_kms::config::retry::RetryConfig::disabled())
        .build();
    (state, AwsKms::from_client(aws_sdk_kms::Client::from_conf(config)))
}

const ROLE: &str = "arn:aws:iam::111122223333:role/clovelly-verifier";

#[tokio::test]
async fn aws_init_makes_three_keys_with_least_privilege_key_policies() {
    let (state, kms) = aws_world().await;
    let names = kms.make_keys("prod", ROLE).await.unwrap();
    assert_eq!(names.ca, "alias/clovelly-prod-env-ca");
    assert_eq!(names.dek, "alias/clovelly-prod-dek");
    let fake = state.lock().unwrap();
    let actions = |alias: &str| fake.policies[&fake.aliases[alias]]["Statement"][1]["Action"].clone();
    assert_eq!(actions(&names.ca), json!(["kms:Sign", "kms:GetPublicKey"]));
    assert_eq!(actions(&names.policy), json!(["kms:Sign", "kms:GetPublicKey"]));
    assert_eq!(actions(&names.dek), json!(["kms:Decrypt"]));
}

#[tokio::test]
async fn aws_init_run_again_leaves_existing_keys_alone() {
    let (state, kms) = aws_world().await;
    kms.make_keys("prod", ROLE).await.unwrap();
    let count = state.lock().unwrap().keys.len();
    kms.make_keys("prod", ROLE).await.unwrap();
    assert_eq!(state.lock().unwrap().keys.len(), count);
}

#[tokio::test]
async fn aws_answers_map_onto_the_contract() {
    let (state, kms) = aws_world().await;
    let names = kms.make_keys("prod", ROLE).await.unwrap();
    assert!(matches!(kms.sign("alias/absent", &[0; 32]).await, Err(KeyError::NoSuchKey { .. })));
    for (code, denied) in [
        ("AccessDeniedException", true),
        ("DisabledException", true),
        ("KMSInvalidStateException", true),
        ("InvalidCiphertextException", true),
        ("KMSInternalException", false),
        ("ThrottlingException", false),
    ] {
        state.lock().unwrap().forced = Some(code);
        match kms.decrypt(&names.dek, b"x").await.unwrap_err() {
            KeyError::Denied { .. } => assert!(denied, "{code}"),
            KeyError::Unavailable { .. } => assert!(!denied, "{code}"),
            other => panic!("{code}: {other:?}"),
        }
    }
}

#[tokio::test]
async fn check_keys_passes_against_the_aws_backend_on_its_fake() {
    let (_state, kms) = aws_world().await;
    let names = kms.make_keys("prod", ROLE).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let served = Allowed::new(kms, [names.ca.clone(), names.policy.clone(), names.dek.clone()]);
    tokio::spawn(async move { axum::serve(listener, server::router(served)).await.unwrap() });
    let lines = check_keys::run(&url, &Suite { sign_keys: vec![names.ca, names.policy], dek_key: names.dek, vector: None }).await;
    assert!(check_keys::passed(&lines), "{lines:#?}");
}

#[tokio::test]
async fn aws_check_role_passes_only_if_every_act_is_refused() {
    let (state, kms) = aws_world().await;
    let names = kms.make_keys("prod", ROLE).await.unwrap();
    state.lock().unwrap().forced = Some("AccessDeniedException");
    let report = kms.check_role(&names.ca, &names.dek).await;
    assert_eq!(report.len(), 4);
    assert!(report.iter().all(|r| r.result.is_ok()), "{report:?}");
    state.lock().unwrap().forced = Some("KMSInternalException");
    let unknown = kms.check_role(&names.ca, &names.dek).await;
    assert!(unknown.iter().all(|r| r.result.is_err()), "{unknown:?}");
}
