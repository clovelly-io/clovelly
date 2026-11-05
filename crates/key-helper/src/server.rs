//! The HTTP side of `docs/key-helper.md`, over anything that implements [`Keys`].
//!
//! ```no_run
//! # async fn demo(backend: impl verifier::Keys + 'static) -> anyhow::Result<()> {
//! use key_helper::server::{self, Allowed, Listen};
//! let listen: Listen = "127.0.0.1:8200".parse()?;
//! let served = Allowed::new(backend, ["my-ca-key", "my-policy-key", "my-dek-key"]);
//! server::serve(listen, served).await?;
//! # Ok(()) }
//! ```

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use common::b64;
use serde::Serialize;
use serde::de::DeserializeOwned;
use verifier::keys::wire::{self, ErrorBody, ErrorCode};
use verifier::keys::{KeyError, Keys, Op};

/// The address a helper binds: loopback, whatever anyone asked for. Whoever can reach a
/// helper can sign and decrypt, and the interface has no authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listen(SocketAddr);

/// Why an address to listen on was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("a key helper listens on a loopback address and nothing else, not {0:?}")]
pub struct NotLoopback(String);

impl FromStr for Listen {
    type Err = NotLoopback;

    fn from_str(s: &str) -> Result<Self, NotLoopback> {
        match s.parse::<SocketAddr>() {
            Ok(addr) if addr.ip().is_loopback() => Ok(Self(addr)),
            _ => Err(NotLoopback(s.to_owned())),
        }
    }
}

impl Default for Listen {
    fn default() -> Self {
        Self("127.0.0.1:8200".parse().expect("an address"))
    }
}

/// The keys a helper serves. Every other name answers `no_such_key` without asking the key
/// manager, some of which answer a name you may not use and a name that does not exist with
/// one refusal, so a helper cannot otherwise keep the contract's two errors apart.
pub struct Allowed<K> {
    inner: K,
    names: BTreeSet<String>,
}

impl<K> Allowed<K> {
    pub fn new<S: Into<String>>(inner: K, names: impl IntoIterator<Item = S>) -> Self {
        Self { inner, names: names.into_iter().map(Into::into).collect() }
    }

    fn check(&self, op: Op, key: &str) -> Result<(), KeyError> {
        if self.names.contains(key) {
            Ok(())
        } else {
            Err(KeyError::NoSuchKey { op, key: key.to_owned() })
        }
    }
}

impl<K: Keys> Keys for Allowed<K> {
    async fn sign(&self, key: &str, digest: &[u8; 32]) -> Result<Vec<u8>, KeyError> {
        self.check(Op::Sign, key)?;
        self.inner.sign(key, digest).await
    }

    async fn decrypt(&self, key: &str, ciphertext: &[u8]) -> Result<Vec<u8>, KeyError> {
        self.check(Op::Decrypt, key)?;
        self.inner.decrypt(key, ciphertext).await
    }

    async fn encrypt(&self, key: &str, plaintext: &[u8]) -> Result<Vec<u8>, KeyError> {
        self.check(Op::Encrypt, key)?;
        self.inner.encrypt(key, plaintext).await
    }

    async fn public_key(&self, key: &str) -> Result<Vec<u8>, KeyError> {
        self.check(Op::PublicKey, key)?;
        self.inner.public_key(key).await
    }
}

/// Binds `listen` and answers the contract with `keys` until the process ends.
pub async fn serve<K: Keys + 'static>(listen: Listen, keys: K) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen.0).await?;
    axum::serve(listener, router(keys)).await
}

/// The contract's routes over `keys`.
pub fn router<K: Keys + 'static>(keys: K) -> Router {
    Router::new()
        .route(wire::HEALTH, get(health))
        .route(wire::SIGN, post(sign::<K>))
        .route(wire::DECRYPT, post(decrypt::<K>))
        .route(wire::ENCRYPT, post(encrypt::<K>))
        .route(wire::PUBLIC_KEY, post(public_key::<K>))
        .with_state(Arc::new(keys))
}

fn json<T: Serialize>(status: StatusCode, body: &T) -> Response {
    let bytes = serde_json::to_vec(body).expect("the contract's bodies serialize");
    (status, [(header::CONTENT_TYPE, "application/json")], bytes).into_response()
}

/// Why a request got no `200`.
enum Failure {
    /// It does not parse: `400`. The verifier sends only well-formed requests.
    BadRequest(String),
    Keys(KeyError),
}

impl From<KeyError> for Failure {
    fn from(e: KeyError) -> Self {
        Self::Keys(e)
    }
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let e = match self {
            Failure::BadRequest(why) => return (StatusCode::BAD_REQUEST, why).into_response(),
            Failure::Keys(e) => e,
        };
        let code = match e {
            KeyError::NoSuchKey { .. } => ErrorCode::NoSuchKey,
            KeyError::Denied { .. } => ErrorCode::Denied,
            // A key manager's answer this helper could not make sense of: the answer is not known.
            KeyError::Unavailable { .. } | KeyError::Contract { .. } | KeyError::WrongSignature { .. } => ErrorCode::Unavailable,
        };
        let status = StatusCode::from_u16(code.status()).expect("the contract's statuses are valid");
        json(status, &ErrorBody { error: code, message: Some(e.to_string()) })
    }
}

fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, Failure> {
    serde_json::from_slice(body).map_err(|e| Failure::BadRequest(e.to_string()))
}

fn base64(field: &str) -> Result<Vec<u8>, Failure> {
    b64::decode(field).map_err(|e| Failure::BadRequest(e.to_string()))
}

async fn health() -> Response {
    json(StatusCode::OK, &wire::HealthResponse { status: "ok".to_owned() })
}

async fn sign<K: Keys>(State(keys): State<Arc<K>>, body: Bytes) -> Result<Response, Failure> {
    let r: wire::SignRequest = parse(&body)?;
    let digest: [u8; 32] = base64(&r.digest)?
        .try_into()
        .map_err(|_| Failure::BadRequest("digest is not 32 bytes".to_owned()))?;
    let signature = keys.sign(&r.key, &digest).await?;
    Ok(json(StatusCode::OK, &wire::SignResponse { signature: b64::encode(&signature) }))
}

async fn decrypt<K: Keys>(State(keys): State<Arc<K>>, body: Bytes) -> Result<Response, Failure> {
    let r: wire::DecryptRequest = parse(&body)?;
    let plaintext = keys.decrypt(&r.key, &base64(&r.ciphertext)?).await?;
    Ok(json(StatusCode::OK, &wire::DecryptResponse { plaintext: b64::encode(&plaintext) }))
}

async fn encrypt<K: Keys>(State(keys): State<Arc<K>>, body: Bytes) -> Result<Response, Failure> {
    let r: wire::EncryptRequest = parse(&body)?;
    let ciphertext = keys.encrypt(&r.key, &base64(&r.plaintext)?).await?;
    Ok(json(StatusCode::OK, &wire::EncryptResponse { ciphertext: b64::encode(&ciphertext) }))
}

async fn public_key<K: Keys>(State(keys): State<Arc<K>>, body: Bytes) -> Result<Response, Failure> {
    let r: wire::PublicKeyRequest = parse(&body)?;
    let der = keys.public_key(&r.key).await?;
    Ok(json(StatusCode::OK, &wire::PublicKeyResponse { public_key: b64::encode(&der) }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_helper_cannot_be_told_to_listen_off_loopback() {
        for good in ["127.0.0.1:8200", "127.0.0.2:1", "[::1]:8200"] {
            assert!(good.parse::<Listen>().is_ok(), "{good}");
        }
        for bad in ["0.0.0.0:8200", "[::]:8200", "10.0.0.1:8200", "localhost:8200", "8200", ""] {
            assert!(bad.parse::<Listen>().is_err(), "{bad}");
        }
    }
}
