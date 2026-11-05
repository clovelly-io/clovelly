//! The key helper's JSON bodies and errors (`docs/key-helper.md`), shared by the
//! verifier's client and every helper written in Rust.

use serde::{Deserialize, Serialize};

pub const HEALTH: &str = "/v1/health";
pub const SIGN: &str = "/v1/sign";
pub const DECRYPT: &str = "/v1/decrypt";
pub const ENCRYPT: &str = "/v1/encrypt";
pub const PUBLIC_KEY: &str = "/v1/public-key";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    pub key: String,
    pub digest: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignResponse {
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecryptRequest {
    pub key: String,
    pub ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptResponse {
    pub plaintext: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptRequest {
    pub key: String,
    pub plaintext: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptResponse {
    pub ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicKeyRequest {
    pub key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyResponse {
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
}

/// The three errors a helper may answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    NoSuchKey,
    Denied,
    Unavailable,
}

impl ErrorCode {
    /// The HTTP status the contract pairs with this error.
    pub fn status(self) -> u16 {
        match self {
            ErrorCode::NoSuchKey => 404,
            ErrorCode::Denied => 403,
            ErrorCode::Unavailable => 503,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ErrorCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
