//! Google Cloud KMS behind the key helper's interface: copy this for another key manager.
//!
//! A key's name is its resource path: `projects/P/locations/L/keyRings/R/cryptoKeys/K`, with
//! `/cryptoKeyVersions/N` for a signing key. Calls the REST API with a token from the
//! metadata server (the platform's service account) or one given at start (an operator's
//! login, for `init`).

use std::sync::Mutex;
use std::time::{Duration, Instant};

use common::b64;
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use verifier::init::KeyNames;
use verifier::keys::{KeyError, Keys, Op};

use crate::Refused;

const KMS: &str = "https://cloudkms.googleapis.com/v1";
/// The attached service account's token, from the metadata server.
pub const METADATA_TOKEN: &str = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
/// Inside the verifier's 10 seconds, so that a slow KMS is `unavailable` and not a timeout.
const TIMEOUT: Duration = Duration::from_secs(8);

/// Where [`CloudKms`] gets its OAuth token.
#[derive(Debug, Clone)]
pub enum Token {
    /// The attached service account, from the metadata server.
    Metadata,
    /// A fixed token, such as `gcloud auth print-access-token` for an operator.
    Fixed(String),
}

/// Cloud KMS over REST.
#[derive(Debug)]
pub struct CloudKms {
    http: reqwest::Client,
    token: Token,
    cached: Mutex<Option<(String, Instant)>>,
    kms: String,
    metadata: String,
}

/// Why setup or a role check could not go on.
#[derive(Debug, thiserror::Error)]
pub enum GcpError {
    #[error("Cloud KMS request: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Cloud KMS {what}: HTTP {status}: {body}")]
    Status { what: String, status: u16, body: String },
    #[error("key version {0} never became enabled")]
    NeverEnabled(String),
}

impl CloudKms {
    pub fn new(token: Token) -> Result<Self, reqwest::Error> {
        Self::at(token, KMS, METADATA_TOKEN)
    }

    /// Against other endpoints: tests.
    pub fn at(token: Token, kms: &str, metadata: &str) -> Result<Self, reqwest::Error> {
        Ok(Self {
            http: reqwest::Client::builder().timeout(TIMEOUT).build()?,
            token,
            cached: Mutex::new(None),
            kms: kms.to_owned(),
            metadata: metadata.to_owned(),
        })
    }

    async fn bearer(&self) -> Result<String, reqwest::Error> {
        if let Token::Fixed(t) = &self.token {
            return Ok(t.clone());
        }
        let cached = self.cached.lock().unwrap_or_else(|p| p.into_inner()).clone();
        if let Some((t, _)) = cached.filter(|(_, until)| Instant::now() < *until) {
            return Ok(t);
        }
        #[derive(Deserialize)]
        struct Tok {
            access_token: String,
            expires_in: u64,
        }
        let tok: Tok = self
            .http
            .get(&self.metadata)
            .header("Metadata-Flavor", "Google")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let until = Instant::now() + Duration::from_secs(tok.expires_in.saturating_sub(60));
        *self.cached.lock().unwrap_or_else(|p| p.into_inner()) = Some((tok.access_token.clone(), until));
        Ok(tok.access_token)
    }

    /// One KMS call; returns the status and the body as JSON if it is any.
    async fn raw(&self, req: reqwest::RequestBuilder) -> Result<(StatusCode, Value, String), reqwest::Error> {
        let resp = req.bearer_auth(self.bearer().await?).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null), text))
    }

    /// One operation of the contract. How Cloud KMS's answers map onto its three errors:
    /// a key version that is disabled or destroyed is `400 FAILED_PRECONDITION`, a
    /// ciphertext that does not open is `400 INVALID_ARGUMENT`, and both are `denied`; a
    /// token that has expired says nothing about the key, so it is `unavailable`.
    async fn call(&self, op: Op, key: &str, req: reqwest::RequestBuilder) -> Result<Value, KeyError> {
        let unavailable = || KeyError::Unavailable { op, key: key.to_owned() };
        let (status, value, _) = self.raw(req).await.map_err(|_| unavailable())?;
        match status {
            s if s.is_success() => Ok(value),
            StatusCode::NOT_FOUND => Err(KeyError::NoSuchKey { op, key: key.to_owned() }),
            StatusCode::FORBIDDEN | StatusCode::BAD_REQUEST => Err(KeyError::Denied { op, key: key.to_owned() }),
            _ => Err(unavailable()),
        }
    }

    fn field(op: Op, key: &str, v: &Value, name: &str) -> Result<String, KeyError> {
        v.get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| KeyError::Contract { op, key: key.to_owned(), why: format!("no {name} in Cloud KMS's answer") })
    }

    fn bytes(op: Op, key: &str, v: &Value, name: &str) -> Result<Vec<u8>, KeyError> {
        b64::decode(&Self::field(op, key, v, name)?).map_err(|e| KeyError::Contract { op, key: key.to_owned(), why: e.to_string() })
    }
}

impl Keys for CloudKms {
    async fn sign(&self, key: &str, digest: &[u8; 32]) -> Result<Vec<u8>, KeyError> {
        let body = json!({ "digest": { "sha256": b64::encode(digest) } });
        let url = format!("{}/{key}:asymmetricSign", self.kms);
        let v = self.call(Op::Sign, key, self.http.post(url).json(&body)).await?;
        Self::bytes(Op::Sign, key, &v, "signature")
    }

    async fn decrypt(&self, key: &str, ciphertext: &[u8]) -> Result<Vec<u8>, KeyError> {
        let body = json!({ "ciphertext": b64::encode(ciphertext) });
        let url = format!("{}/{key}:decrypt", self.kms);
        let v = self.call(Op::Decrypt, key, self.http.post(url).json(&body)).await?;
        Self::bytes(Op::Decrypt, key, &v, "plaintext")
    }

    async fn encrypt(&self, key: &str, plaintext: &[u8]) -> Result<Vec<u8>, KeyError> {
        let body = json!({ "plaintext": b64::encode(plaintext) });
        let url = format!("{}/{key}:encrypt", self.kms);
        let v = self.call(Op::Encrypt, key, self.http.post(url).json(&body)).await?;
        Self::bytes(Op::Encrypt, key, &v, "ciphertext")
    }

    async fn public_key(&self, key: &str) -> Result<Vec<u8>, KeyError> {
        let url = format!("{}/{key}/publicKey", self.kms);
        let v = self.call(Op::PublicKey, key, self.http.get(url)).await?;
        let pem = Self::field(Op::PublicKey, key, &v, "pem")?;
        b64::pem_blocks(&pem, "PUBLIC KEY")
            .ok()
            .and_then(|b| b.into_iter().next())
            .ok_or_else(|| KeyError::Contract { op: Op::PublicKey, key: key.to_owned(), why: "no PEM block".into() })
    }
}

/// Where `init gcp` makes the keys, and who the helper will run as.
#[derive(Debug, Clone)]
pub struct Place {
    pub project: String,
    pub location: String,
    /// Created if it does not exist. A key ring cannot be deleted.
    pub key_ring: String,
    /// The environment, in each key's name and label.
    pub env: String,
    /// The service account the helper will run as.
    pub service_account: String,
}

impl Place {
    fn ring(&self) -> String {
        format!("projects/{}/locations/{}/keyRings/{}", self.project, self.location, self.key_ring)
    }
}

/// Each key, its purpose and what the running role may do with it, and nothing else.
const SIGNING_ROLES: [&str; 2] = ["roles/cloudkms.signer", "roles/cloudkms.publicKeyViewer"];
const DEK_ROLES: [&str; 1] = ["roles/cloudkms.cryptoKeyDecrypter"];

impl CloudKms {
    async fn expect(&self, what: String, req: reqwest::RequestBuilder, tolerated: Option<StatusCode>) -> Result<(StatusCode, Value), GcpError> {
        let (status, value, body) = self.raw(req).await?;
        if status.is_success() || Some(status) == tolerated {
            Ok((status, value))
        } else {
            Err(GcpError::Status { what, status: status.as_u16(), body })
        }
    }

    /// Makes one key and, only if it has just been made, grants `roles` on it. A key that
    /// already exists is left as it is: re-running `init` changes nothing.
    async fn make_key(&self, place: &Place, id: &str, body: Value, roles: &[&str]) -> Result<(), GcpError> {
        let url = format!("{}/{}/cryptoKeys?cryptoKeyId={id}", self.kms, place.ring());
        let (status, _) = self.expect(format!("creating {id}"), self.http.post(url).json(&body), Some(StatusCode::CONFLICT)).await?;
        if status == StatusCode::CONFLICT {
            return Ok(());
        }
        let member = format!("serviceAccount:{}", place.service_account);
        let bindings: Vec<Value> = roles.iter().map(|r| json!({ "role": r, "members": [member] })).collect();
        let url = format!("{}/{}/cryptoKeys/{id}:setIamPolicy", self.kms, place.ring());
        self.expect(format!("granting on {id}"), self.http.post(url).json(&json!({ "policy": { "bindings": bindings } })), None).await?;
        Ok(())
    }

    /// Asymmetric keys are generated in the background.
    async fn wait_enabled(&self, version: &str) -> Result<(), GcpError> {
        for _ in 0..60 {
            let url = format!("{}/{version}", self.kms);
            let (_, v) = self.expect(format!("reading {version}"), self.http.get(url), None).await?;
            if v.get("state").and_then(Value::as_str) == Some("ENABLED") {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        Err(GcpError::NeverEnabled(version.to_owned()))
    }

    /// Creates the key ring if it is missing and the environment's three keys: the CA and
    /// policy keys (EC P-256), the DEK key (symmetric). The service account may sign with
    /// the first two and read their public keys, and decrypt with the third.
    pub async fn make_keys(&self, place: &Place) -> Result<KeyNames, GcpError> {
        let parent = format!("projects/{}/locations/{}", place.project, place.location);
        let url = format!("{}/{parent}/keyRings?keyRingId={}", self.kms, place.key_ring);
        self.expect(format!("creating key ring {}", place.key_ring), self.http.post(url).json(&json!({})), Some(StatusCode::CONFLICT)).await?;

        let labels = json!({ "clovelly-env": place.env });
        let signing = json!({
            "purpose": "ASYMMETRIC_SIGN", "labels": labels,
            "versionTemplate": { "algorithm": "EC_SIGN_P256_SHA256", "protectionLevel": "SOFTWARE" },
        });
        let (ca, policy, dek) = (format!("{}-env-ca", place.env), format!("{}-policy", place.env), format!("{}-dek", place.env));
        self.make_key(place, &ca, signing.clone(), &SIGNING_ROLES).await?;
        self.make_key(place, &policy, signing, &SIGNING_ROLES).await?;
        self.make_key(place, &dek, json!({ "purpose": "ENCRYPT_DECRYPT", "labels": labels }), &DEK_ROLES).await?;

        let ring = place.ring();
        let names = KeyNames {
            ca: format!("{ring}/cryptoKeys/{ca}/cryptoKeyVersions/1"),
            policy: format!("{ring}/cryptoKeys/{policy}/cryptoKeyVersions/1"),
            dek: format!("{ring}/cryptoKeys/{dek}"),
        };
        self.wait_enabled(&names.ca).await?;
        self.wait_enabled(&names.policy).await?;
        Ok(names)
    }

    /// Run as the helper's role: tries to create a key beside `sign_version`, re-key `dek`,
    /// disable and destroy `sign_version`. Passes only if Cloud KMS refuses each. On a role
    /// that is too strong this really does those things, to the keys named: both undo.
    pub async fn check_role(&self, sign_version: &str, dek: &str) -> Vec<Refused> {
        let ring = sign_version.split("/cryptoKeys/").next().unwrap_or_default();
        let url = |tail: String| format!("{}/{tail}", self.kms);
        let attempts = [
            (
                "create a key",
                self.http
                    .post(url(format!("{ring}/cryptoKeys?cryptoKeyId=clovelly-check-role")))
                    .json(&json!({ "purpose": "ENCRYPT_DECRYPT" })),
            ),
            ("re-key (a new version)", self.http.post(url(format!("{dek}/cryptoKeyVersions"))).json(&json!({}))),
            (
                "disable a key version",
                self.http.patch(url(format!("{sign_version}?updateMask=state"))).json(&json!({ "state": "DISABLED" })),
            ),
            ("delete (destroy) a key version", self.http.post(url(format!("{sign_version}:destroy"))).json(&json!({}))),
        ];
        let mut report = Vec::new();
        for (act, req) in attempts {
            let result = match self.raw(req).await {
                Ok((StatusCode::FORBIDDEN, _, _)) => Ok(()),
                Ok((status, _, body)) => Err(format!("HTTP {status}: {}", body.chars().take(200).collect::<String>())),
                Err(e) => Err(e.to_string()),
            };
            report.push(Refused { act, result });
        }
        report
    }
}
