//! `verifier check-keys`: the conformance suite for a key helper (`docs/key-helper.md`,
//! "Checking a helper"). Each check gives one line; a failure names its reason.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use aws_lc_rs::rand;
use common::b64;
use common::evidence::Spki;
use common::jws::TrustedKey;
use der::Sequence;
use der::asn1::UintRef;
use der::Decode;

use crate::init::Vector;
use crate::keys::wire::{self, HealthResponse};
use crate::keys::{self, HelperClient, KeyError, Keys, KeysUrl};

/// Why a helper failed. The names are the contract's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    NotLoopback,
    HealthFailed,
    PublicKeyInvalid,
    SignatureNotDer,
    SignatureWrongKey,
    EncryptFailed,
    DecryptWrongPlaintext,
    DecryptAcceptsGarbage,
    UnknownKeyAnswer,
    BadErrorBody,
    OperationFailed,
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Reason::NotLoopback => "not_loopback",
            Reason::HealthFailed => "health_failed",
            Reason::PublicKeyInvalid => "public_key_invalid",
            Reason::SignatureNotDer => "signature_not_der",
            Reason::SignatureWrongKey => "signature_wrong_key",
            Reason::EncryptFailed => "encrypt_failed",
            Reason::DecryptWrongPlaintext => "decrypt_wrong_plaintext",
            Reason::DecryptAcceptsGarbage => "decrypt_accepts_garbage",
            Reason::UnknownKeyAnswer => "unknown_key_answer",
            Reason::BadErrorBody => "bad_error_body",
            Reason::OperationFailed => "operation_failed",
        })
    }
}

/// One check's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub check: String,
    pub result: Result<String, (Reason, String)>,
}

impl fmt::Display for Line {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.result {
            Ok(note) => write!(f, "ok    {}{}{}", self.check, if note.is_empty() { "" } else { ": " }, note),
            Err((reason, detail)) => write!(f, "FAIL  {}: {reason}: {detail}", self.check),
        }
    }
}

/// What to check. The helper's key names are its own; the suite is told them.
#[derive(Debug, Clone)]
pub struct Suite {
    pub sign_keys: Vec<String>,
    pub dek_key: String,
    /// Stands in for encrypt when the helper's identity is refused it.
    pub vector: Option<Vector>,
}

/// An ECDSA signature as ASN.1 DER: `SEQUENCE { r INTEGER, s INTEGER }`, nothing after it.
#[derive(Sequence)]
struct DerSignature<'a> {
    r: UintRef<'a>,
    s: UintRef<'a>,
}

fn is_der(signature: &[u8]) -> bool {
    DerSignature::from_der(signature).is_ok_and(|s| !s.r.is_empty() && !s.s.is_empty())
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::fill(&mut bytes).expect("the system RNG does not fail");
    bytes
}

/// A name no helper serves.
fn unknown_key() -> String {
    format!("clovelly-check-keys-no-such-key-{}", common::hex(&random::<8>()))
}

/// The failure of an operation that should have worked. An answer the contract does not
/// allow is its own reason.
fn failed(e: &KeyError) -> (Reason, String) {
    match e {
        KeyError::Contract { .. } => (Reason::BadErrorBody, e.to_string()),
        _ => (Reason::OperationFailed, e.to_string()),
    }
}

/// Runs the whole suite against the helper at `url`. Every check runs unless the address
/// itself is refused: nothing is sent to an address off loopback.
pub async fn run(url: &str, suite: &Suite) -> Vec<Line> {
    let mut lines = Vec::new();
    let mut add = |check: String, result| lines.push(Line { check, result });
    let url: KeysUrl = match url.parse() {
        Ok(u) => u,
        Err(e) => {
            add("loopback".into(), Err((Reason::NotLoopback, format!("{e}"))));
            return lines;
        }
    };
    add("loopback".into(), only_on_loopback(url.port()).await);
    add("health".into(), health(&url).await);
    let client = match HelperClient::new(url) {
        Ok(c) => c,
        Err(e) => {
            add("client".into(), Err((Reason::OperationFailed, e.to_string())));
            return lines;
        }
    };

    let mut public_keys: Vec<(String, Vec<u8>)> = Vec::new();
    for key in &suite.sign_keys {
        match public_key(&client, key).await {
            Ok(trusted) => {
                add(format!("public-key {key}"), Ok(String::new()));
                if let Some((other, _)) = public_keys.iter().find(|(_, der)| der == trusted.spki_der()) {
                    add(
                        format!("distinct keys {key}"),
                        Err((Reason::PublicKeyInvalid, format!("{key} and {other} answer with one public key"))),
                    );
                }
                public_keys.push((key.clone(), trusted.spki_der().to_vec()));
                add(format!("sign {key}"), sign(&client, key, &trusted).await);
            }
            Err(failure) => {
                add(format!("public-key {key}"), Err(failure));
            }
        }
    }

    add(format!("encrypt and decrypt {}", suite.dek_key), roundtrip(&client, suite).await);
    add(format!("decrypt garbage {}", suite.dek_key), garbage(&client, &suite.dek_key).await);
    for (op, result) in unknown(&client).await {
        add(format!("unknown key: {op}"), result);
    }
    lines
}

/// Whether any check failed.
pub fn passed(lines: &[Line]) -> bool {
    lines.iter().all(|l| l.result.is_ok())
}

/// This machine's address towards the rest of a network, if it has one. `connect` on a UDP
/// socket picks the route and sends nothing; the addresses are the documentation ranges.
async fn other_address(unspecified: IpAddr, towards: IpAddr) -> Option<IpAddr> {
    let socket = tokio::net::UdpSocket::bind(SocketAddr::new(unspecified, 0)).await.ok()?;
    socket.connect(SocketAddr::new(towards, 9)).await.ok()?;
    socket.local_addr().ok().map(|a| a.ip()).filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
}

/// Fails if the helper's port also answers on this machine's other address, which is how a
/// helper listening on `0.0.0.0` shows from its own loopback.
async fn only_on_loopback(port: u16) -> Result<String, (Reason, String)> {
    let candidates = [
        other_address(Ipv4Addr::UNSPECIFIED.into(), Ipv4Addr::new(192, 0, 2, 1).into()).await,
        other_address(Ipv6Addr::UNSPECIFIED.into(), "2001:db8::1".parse::<Ipv6Addr>().expect("an address").into()).await,
    ];
    let mut tried = Vec::new();
    for ip in candidates.into_iter().flatten() {
        let addr = SocketAddr::new(ip, port);
        tried.push(ip.to_string());
        let connected = tokio::time::timeout(Duration::from_secs(1), tokio::net::TcpStream::connect(addr)).await;
        if matches!(connected, Ok(Ok(_))) {
            return Err((Reason::NotLoopback, format!("the helper also answers on {addr}; bind 127.0.0.1")));
        }
    }
    Ok(if tried.is_empty() { "this machine has no other address to try".into() } else { format!("not listening on {}", tried.join(", ")) })
}

async fn health(url: &KeysUrl) -> Result<String, (Reason, String)> {
    let bad = |why: String| (Reason::HealthFailed, why);
    let http = reqwest::Client::builder()
        .timeout(crate::keys_timeout())
        .no_proxy()
        .build()
        .map_err(|e| bad(e.to_string()))?;
    let resp = http.get(url.at(wire::HEALTH)).send().await.map_err(|e| bad(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(bad(format!("status {status}")));
    }
    let body: HealthResponse = resp.json().await.map_err(|e| bad(e.to_string()))?;
    if body.status == "ok" { Ok(String::new()) } else { Err(bad(format!("status {:?}", body.status))) }
}

async fn public_key(client: &HelperClient, key: &str) -> Result<TrustedKey, (Reason, String)> {
    let der = client.public_key(key).await.map_err(|e| failed(&e))?;
    let spki = Spki::from_der(&der).map_err(|e| (Reason::PublicKeyInvalid, e.to_string()))?;
    Ok(TrustedKey::from_spki(spki))
}

async fn sign(client: &HelperClient, key: &str, trusted: &TrustedKey) -> Result<String, (Reason, String)> {
    let message = random::<48>();
    let signature = client.sign(key, &keys::sha256(&message)).await.map_err(|e| failed(&e))?;
    if !is_der(&signature) {
        return Err((Reason::SignatureNotDer, format!("{} bytes that are not ASN.1 DER (raw r||s is 64)", signature.len())));
    }
    if !trusted.verifies_der(&message, &signature) {
        return Err((Reason::SignatureWrongKey, "DER, and it does not verify under this key's public key (another key, or the digest hashed again)".into()));
    }
    Ok(String::new())
}

async fn roundtrip(client: &HelperClient, suite: &Suite) -> Result<String, (Reason, String)> {
    let plaintext = random::<32>();
    let key = suite.dek_key.as_str();
    let (ciphertext, expected, note) = match (client.encrypt(key, &plaintext).await, &suite.vector) {
        (Ok(c), _) => (c, plaintext.to_vec(), "encrypted and decrypted".to_owned()),
        (Err(KeyError::Denied { .. }), Some(v)) => {
            let bytes = |s: &str| b64::decode(s).map_err(|e| (Reason::OperationFailed, format!("the vector: {e}")));
            (bytes(&v.ciphertext)?, bytes(&v.plaintext)?, "encrypt is denied to this identity; decrypted the vector".to_owned())
        }
        (Err(e @ KeyError::Contract { .. }), _) => return Err(failed(&e)),
        (Err(e), _) => return Err((Reason::EncryptFailed, e.to_string())),
    };
    let decrypted = client.decrypt(key, &ciphertext).await.map_err(|e| failed(&e))?;
    if decrypted == expected {
        Ok(note)
    } else {
        Err((Reason::DecryptWrongPlaintext, format!("{} bytes that are not the {} encrypted", decrypted.len(), expected.len())))
    }
}

async fn garbage(client: &HelperClient, key: &str) -> Result<String, (Reason, String)> {
    match client.decrypt(key, &random::<64>()).await {
        Err(KeyError::Denied { .. }) => Ok(String::new()),
        Err(e @ KeyError::Contract { .. }) => Err(failed(&e)),
        Err(e) => Err((Reason::DecryptAcceptsGarbage, format!("{e}, where the contract says denied"))),
        Ok(p) => Err((Reason::DecryptAcceptsGarbage, format!("200 with {} bytes", p.len()))),
    }
}

async fn unknown(client: &HelperClient) -> Vec<(&'static str, Result<String, (Reason, String)>)> {
    let key = unknown_key();
    fn answer(result: Result<Vec<u8>, KeyError>) -> Result<String, (Reason, String)> {
        match result {
            Err(KeyError::NoSuchKey { .. }) => Ok(String::new()),
            Err(e @ KeyError::Contract { .. }) => Err(failed(&e)),
            Err(e) => Err((Reason::UnknownKeyAnswer, e.to_string())),
            Ok(b) => Err((Reason::UnknownKeyAnswer, format!("200 with {} bytes", b.len()))),
        }
    }
    vec![
        ("sign", answer(client.sign(&key, &random::<32>()).await)),
        ("decrypt", answer(client.decrypt(&key, &random::<32>()).await)),
        ("encrypt", answer(client.encrypt(&key, &random::<32>()).await)),
        ("public-key", answer(client.public_key(&key).await)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_raw_signature_is_not_der_and_a_der_one_is() {
        let raw = [0x30u8; 64];
        assert!(!is_der(&raw));
        // SEQUENCE { INTEGER 1, INTEGER 2 }
        assert!(is_der(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]));
        // Trailing bytes.
        assert!(!is_der(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00]));
    }
}
