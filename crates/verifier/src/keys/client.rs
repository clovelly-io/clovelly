//! The verifier's client for the key helper on its loopback.

use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use common::b64;
use reqwest::{StatusCode, Url};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::wire::{self, ErrorBody, ErrorCode};
use super::{KeyError, Keys, Op};

/// The contract's limit on one request, from connection to the last byte of the body.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// Why `CLOVELLY_KEYS_URL` was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} is not a key helper on this loopback (http://127.0.0.1:PORT or http://[::1]:PORT, nothing else): {1}")]
pub struct NotLoopback(String, &'static str);

/// The address of a key helper, parsed: `http`, a numeric loopback host, a port, and
/// nothing else. Whoever can reach a helper can sign and decrypt, and the interface has no
/// authentication, so an address that leaves this machine cannot be constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysUrl(Url);

impl FromStr for KeysUrl {
    type Err = NotLoopback;

    fn from_str(s: &str) -> Result<Self, NotLoopback> {
        let refuse = |why| NotLoopback(s.to_owned(), why);
        let url = Url::parse(s).map_err(|_| refuse("not a URL"))?;
        if url.scheme() != "http" {
            return Err(refuse("the scheme is not http"));
        }
        // A name, `localhost` included, is whatever a resolver says it is.
        let host = url.host_str().unwrap_or_default().trim_matches(['[', ']']);
        let Ok(ip) = host.parse::<IpAddr>() else {
            return Err(refuse("the host is not a number"));
        };
        if !ip.is_loopback() {
            return Err(refuse("the host is not a loopback address"));
        }
        if url.port().is_none() {
            return Err(refuse("there is no port"));
        }
        if !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
            return Err(refuse("it has a user, query or fragment"));
        }
        if url.path() != "/" {
            return Err(refuse("it has a path"));
        }
        Ok(Self(url))
    }
}

impl KeysUrl {
    /// The helper's port.
    pub fn port(&self) -> u16 {
        self.0.port().expect("a KeysUrl has a port")
    }

    /// The URL of `path` on the helper.
    pub fn at(&self, path: &str) -> Url {
        self.0.join(path).expect("the contract's paths join onto a host")
    }
}

/// [`Keys`] through a helper. Sends each request once, within [`TIMEOUT`].
#[derive(Debug, Clone)]
pub struct HelperClient {
    url: KeysUrl,
    http: reqwest::Client,
}

impl HelperClient {
    pub fn new(url: KeysUrl) -> Result<Self, reqwest::Error> {
        Ok(Self {
            url,
            http: reqwest::Client::builder()
                .timeout(TIMEOUT)
                // Loopback is never proxied, whatever HTTP_PROXY says, and a helper cannot
                // send the verifier's digests and ciphertexts somewhere else.
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        })
    }

    /// The helper's address.
    pub fn url(&self) -> &KeysUrl {
        &self.url
    }

    async fn call<Req: Serialize, Resp: DeserializeOwned>(&self, op: Op, key: &str, path: &str, req: &Req) -> Result<Resp, KeyError> {
        let contract = |why: String| KeyError::Contract { op, key: key.to_owned(), why };
        // No answer at all: the helper is stopped or hung.
        let unavailable = |e: reqwest::Error| {
            log(op, key, "unavailable", &e.to_string());
            KeyError::Unavailable { op, key: key.to_owned() }
        };
        let resp = self.http.post(self.url.at(path)).json(req).send().await.map_err(unavailable)?;
        let status = resp.status();
        let body = resp.bytes().await.map_err(unavailable)?;
        if status == StatusCode::OK {
            return serde_json::from_slice(&body).map_err(|e| contract(format!("200 with a body that does not parse: {e}")));
        }
        let error: ErrorBody = serde_json::from_slice(&body).map_err(|_| contract(format!("status {status} with no error body")))?;
        log(op, key, code_name(error.error), error.message.as_deref().unwrap_or(""));
        if status.as_u16() != error.error.status() {
            return Err(contract(format!("status {status} with error {}", code_name(error.error))));
        }
        Err(match error.error {
            ErrorCode::NoSuchKey => KeyError::NoSuchKey { op, key: key.to_owned() },
            ErrorCode::Denied => KeyError::Denied { op, key: key.to_owned() },
            ErrorCode::Unavailable => KeyError::Unavailable { op, key: key.to_owned() },
        })
    }

    fn bytes(op: Op, key: &str, field: &str) -> Result<Vec<u8>, KeyError> {
        b64::decode(field).map_err(|e| KeyError::Contract { op, key: key.to_owned(), why: e.to_string() })
    }
}

fn code_name(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::NoSuchKey => "no_such_key",
        ErrorCode::Denied => "denied",
        ErrorCode::Unavailable => "unavailable",
    }
}

/// One JSON line for the operator. Goes to the log and not to the cell: `Status` carries
/// only [`KeyError`]'s text, which holds no word of the helper's.
fn log(op: Op, key: &str, error: &str, detail: &str) {
    eprintln!(
        "{}",
        serde_json::json!({ "severity": "ERROR", "event": "key-helper", "op": op.to_string(), "key": key, "error": error, "detail": detail })
    );
}

impl Keys for HelperClient {
    async fn sign(&self, key: &str, digest: &[u8; 32]) -> Result<Vec<u8>, KeyError> {
        let req = wire::SignRequest { key: key.to_owned(), digest: b64::encode(digest) };
        let r: wire::SignResponse = self.call(Op::Sign, key, wire::SIGN, &req).await?;
        Self::bytes(Op::Sign, key, &r.signature)
    }

    async fn decrypt(&self, key: &str, ciphertext: &[u8]) -> Result<Vec<u8>, KeyError> {
        let req = wire::DecryptRequest { key: key.to_owned(), ciphertext: b64::encode(ciphertext) };
        let r: wire::DecryptResponse = self.call(Op::Decrypt, key, wire::DECRYPT, &req).await?;
        Self::bytes(Op::Decrypt, key, &r.plaintext)
    }

    async fn encrypt(&self, key: &str, plaintext: &[u8]) -> Result<Vec<u8>, KeyError> {
        let req = wire::EncryptRequest { key: key.to_owned(), plaintext: b64::encode(plaintext) };
        let r: wire::EncryptResponse = self.call(Op::Encrypt, key, wire::ENCRYPT, &req).await?;
        Self::bytes(Op::Encrypt, key, &r.ciphertext)
    }

    async fn public_key(&self, key: &str) -> Result<Vec<u8>, KeyError> {
        let req = wire::PublicKeyRequest { key: key.to_owned() };
        let r: wire::PublicKeyResponse = self.call(Op::PublicKey, key, wire::PUBLIC_KEY, &req).await?;
        Self::bytes(Op::PublicKey, key, &r.public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Criterion 2: every way out of loopback is refused when the address is parsed.
    #[test]
    fn a_keys_url_that_is_not_loopback_cannot_be_constructed() {
        for good in ["http://127.0.0.1:8200", "http://127.0.0.1:8200/", "http://127.9.9.9:1", "http://[::1]:8200"] {
            assert!(good.parse::<KeysUrl>().is_ok(), "{good}");
        }
        for bad in [
            "http://10.0.0.1:8200",
            "http://100.64.0.1:80",
            "http://0.0.0.0:8200",
            "http://[::]:8200",
            "http://localhost:8200",
            "http://127.0.0.1.nip.io:8200",
            "http://keys.example.com:8200",
            "https://127.0.0.1:8200",
            "http://127.0.0.1",
            "http://127.0.0.1:8200/v1",
            "http://user@127.0.0.1:8200",
            "http://user:pw@127.0.0.1:8200",
            "http://127.0.0.1:8200/?a=b",
            "127.0.0.1:8200",
            "",
        ] {
            assert!(bad.parse::<KeysUrl>().is_err(), "{bad}");
        }
    }
}
