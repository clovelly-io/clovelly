//! The customer's key management: signing with the environment CA key and decrypting
//! sub-environment DEKs.
//!
//! [`CloudKms`] calls the Cloud KMS REST API with the service account's token from the
//! metadata server (Cloud Run) or a token given at start (operator tools).
//! [`LocalKms`] holds keys in memory for tests and the evidence corpus; it is never
//! deployed.

use std::future::Future;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use aws_lc_rs::digest;
use common::b64;
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum KmsError {
    #[error("KMS request: {0}")]
    Http(#[from] reqwest::Error),
    #[error("KMS {op} on {key}: HTTP {status}: {body}")]
    Status {
        op: &'static str,
        key: String,
        status: u16,
        body: String,
    },
    #[error("KMS response: {0}")]
    Response(String),
    #[error("no such key {0}")]
    NoKey(String),
}

/// What the verifier needs from a key manager.
pub trait Kms: Send + Sync {
    /// An ECDSA P-256 SHA-256 signature (DER) over `message` with key version `key`.
    fn sign(&self, key: &str, message: &[u8]) -> impl Future<Output = Result<Vec<u8>, KmsError>> + Send;
    /// Decrypts `ciphertext` with `key`. The caller wipes the plaintext.
    fn decrypt(&self, key: &str, ciphertext: &[u8]) -> impl Future<Output = Result<Vec<u8>, KmsError>> + Send;
    /// The DER SubjectPublicKeyInfo of key version `key`.
    fn public_key(&self, key: &str) -> impl Future<Output = Result<Vec<u8>, KmsError>> + Send;
}

/// Where [`CloudKms`] gets its OAuth token.
#[derive(Debug, Clone)]
pub enum Token {
    /// The attached service account, from the metadata server (Cloud Run, GCE).
    Metadata,
    /// A fixed token, such as `gcloud auth print-access-token` for operator tools.
    Fixed(String),
}

/// Cloud KMS over REST.
#[derive(Debug)]
pub struct CloudKms {
    http: reqwest::Client,
    token: Token,
    cached: Mutex<Option<(String, Instant)>>,
}

const KMS: &str = "https://cloudkms.googleapis.com/v1";
const METADATA_TOKEN: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

impl CloudKms {
    pub fn new(token: Token) -> Self {
        Self {
            http: reqwest::Client::new(),
            token,
            cached: Mutex::new(None),
        }
    }

    async fn bearer(&self) -> Result<String, KmsError> {
        let fixed = match &self.token {
            Token::Fixed(t) => return Ok(t.clone()),
            Token::Metadata => self
                .cached
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
                .filter(|(_, until)| Instant::now() < *until),
        };
        if let Some((t, _)) = fixed {
            return Ok(t);
        }
        #[derive(Deserialize)]
        struct Tok {
            access_token: String,
            expires_in: u64,
        }
        let tok: Tok = self
            .http
            .get(METADATA_TOKEN)
            .header("Metadata-Flavor", "Google")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let until = Instant::now() + Duration::from_secs(tok.expires_in.saturating_sub(60));
        *self.cached.lock().unwrap_or_else(|p| p.into_inner()) =
            Some((tok.access_token.clone(), until));
        Ok(tok.access_token)
    }

    async fn call(
        &self,
        op: &'static str,
        key: &str,
        req: reqwest::RequestBuilder,
    ) -> Result<serde_json::Value, KmsError> {
        let resp = req.bearer_auth(self.bearer().await?).send().await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(KmsError::Status {
                op,
                key: key.to_owned(),
                status: status.as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }
        Ok(resp.json().await?)
    }

    fn field(v: &serde_json::Value, name: &str) -> Result<String, KmsError> {
        v.get(name)
            .and_then(|f| f.as_str())
            .map(str::to_owned)
            .ok_or_else(|| KmsError::Response(format!("no {name}")))
    }
}

impl Kms for CloudKms {
    async fn sign(&self, key: &str, message: &[u8]) -> Result<Vec<u8>, KmsError> {
        let d = digest::digest(&digest::SHA256, message);
        let body = json!({ "digest": { "sha256": b64::encode(d.as_ref()) } });
        let url = format!("{KMS}/{key}:asymmetricSign");
        let v = self.call("asymmetricSign", key, self.http.post(url).json(&body)).await?;
        b64::decode(&Self::field(&v, "signature")?).map_err(|e| KmsError::Response(e.to_string()))
    }

    async fn decrypt(&self, key: &str, ciphertext: &[u8]) -> Result<Vec<u8>, KmsError> {
        let body = json!({ "ciphertext": b64::encode(ciphertext) });
        let url = format!("{KMS}/{key}:decrypt");
        let v = self.call("decrypt", key, self.http.post(url).json(&body)).await?;
        b64::decode(&Self::field(&v, "plaintext")?).map_err(|e| KmsError::Response(e.to_string()))
    }

    async fn public_key(&self, key: &str) -> Result<Vec<u8>, KmsError> {
        let url = format!("{KMS}/{key}/publicKey");
        let v = self.call("getPublicKey", key, self.http.get(url)).await?;
        b64::pem_blocks(&Self::field(&v, "pem")?, "PUBLIC KEY")
            .ok()
            .and_then(|b| b.into_iter().next())
            .ok_or_else(|| KmsError::Response("publicKey has no PEM block".into()))
    }
}

/// Keys in memory, for tests and the corpus tool. `decrypt` returns the "ciphertext"
/// unchanged: DEKs are stored in the clear in a local configuration.
pub struct LocalKms {
    keys: Vec<(String, aws_lc_rs::signature::EcdsaKeyPair)>,
}

impl LocalKms {
    /// Generates one P-256 signing key per name.
    pub fn generate(names: &[&str]) -> Self {
        use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
        Self {
            keys: names
                .iter()
                .map(|n| {
                    let kp = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING)
                        .expect("P-256 key generation does not fail");
                    ((*n).to_owned(), kp)
                })
                .collect(),
        }
    }

    fn key(&self, name: &str) -> Result<&aws_lc_rs::signature::EcdsaKeyPair, KmsError> {
        self.keys
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, k)| k)
            .ok_or_else(|| KmsError::NoKey(name.to_owned()))
    }
}

impl Kms for LocalKms {
    async fn sign(&self, key: &str, message: &[u8]) -> Result<Vec<u8>, KmsError> {
        let sig = self
            .key(key)?
            .sign(&aws_lc_rs::rand::SystemRandom::new(), message)
            .map_err(|_| KmsError::Response("signing failed".into()))?;
        Ok(sig.as_ref().to_vec())
    }

    async fn decrypt(&self, _key: &str, ciphertext: &[u8]) -> Result<Vec<u8>, KmsError> {
        Ok(ciphertext.to_vec())
    }

    async fn public_key(&self, key: &str) -> Result<Vec<u8>, KmsError> {
        use aws_lc_rs::encoding::AsDer;
        use aws_lc_rs::signature::KeyPair;
        Ok(self
            .key(key)?
            .public_key()
            .as_der()
            .map_err(|_| KmsError::Response("public key DER".into()))?
            .as_ref()
            .to_vec())
    }
}
