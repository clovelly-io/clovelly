//! A key helper with its keys in memory, and every way a helper can be wrong. Test code:
//! nothing that ships depends on this crate, and a test scans the released binaries for it.
//!
//! [`Helper::start`] runs one on its own runtime, on a loopback port, so that dropping the
//! runtime really does stop it, mid-request connections included.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::digest::{self, Digest};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use key_helper::server;
use tokio::runtime::Runtime;
use verifier::keys::{KeyError, Keys, Op};

/// Marks this crate's code in a binary. `released.rs` fails if a released binary holds it.
pub const MARKER: &str = "clovelly-memory-helper-is-test-code";

/// What the helper does, changed at any time with [`Helper::set`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behaviour {
    /// Meets the contract.
    Good,
    /// Meets it as a running role does: encrypt is `denied`.
    RefusesEncrypt,
    /// Signatures are raw `r||s`.
    RawSignature,
    /// Signatures are from another key.
    OtherKey,
    /// Decrypt flips a byte.
    WrongPlaintext,
    /// A key that does not exist answers `denied`.
    UnknownKeyDenied,
    /// Decrypt of bytes that were never encrypted answers `200`.
    AcceptsGarbage,
    /// Every operation answers `denied`.
    Denied,
    /// Every operation answers `unavailable`.
    Unavailable,
    /// Every operation never answers.
    Hung,
}

struct Memory {
    behaviour: Arc<Mutex<Behaviour>>,
    signing: Vec<(String, EcdsaKeyPair)>,
    other: EcdsaKeyPair,
    wrapping: Vec<(String, LessSafeKey)>,
}

fn new_pair() -> EcdsaKeyPair {
    EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).expect("P-256 key generation does not fail")
}

/// DER `SEQUENCE { r, s }` to the 64 bytes of `r||s`.
fn raw(der: &[u8]) -> Vec<u8> {
    fn int(b: &[u8]) -> (Vec<u8>, &[u8]) {
        let len = usize::from(b[1]);
        let value = &b[2..2 + len];
        let trimmed = value.iter().position(|x| *x != 0).map_or(&[][..], |i| &value[i..]);
        let mut out = vec![0u8; 32 - trimmed.len()];
        out.extend_from_slice(trimmed);
        (out, &b[2 + len..])
    }
    let (mut r, rest) = int(&der[2..]);
    let (s, _) = int(rest);
    r.extend(s);
    r
}

impl Memory {
    fn behaviour(&self) -> Behaviour {
        *self.behaviour.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The failure this behaviour puts before every operation, if any.
    async fn before(&self, op: Op, key: &str) -> Result<(), KeyError> {
        match self.behaviour() {
            Behaviour::Denied => Err(KeyError::Denied { op, key: key.to_owned() }),
            Behaviour::Unavailable => Err(KeyError::Unavailable { op, key: key.to_owned() }),
            Behaviour::Hung => {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                Err(KeyError::Unavailable { op, key: key.to_owned() })
            }
            _ => Ok(()),
        }
    }

    fn unknown(&self, op: Op, key: &str) -> KeyError {
        if self.behaviour() == Behaviour::UnknownKeyDenied {
            KeyError::Denied { op, key: key.to_owned() }
        } else {
            KeyError::NoSuchKey { op, key: key.to_owned() }
        }
    }

    fn signing(&self, op: Op, key: &str) -> Result<&EcdsaKeyPair, KeyError> {
        self.signing.iter().find(|(n, _)| n == key).map(|(_, k)| k).ok_or_else(|| self.unknown(op, key))
    }

    fn wrapping(&self, op: Op, key: &str) -> Result<&LessSafeKey, KeyError> {
        self.wrapping.iter().find(|(n, _)| n == key).map(|(_, k)| k).ok_or_else(|| self.unknown(op, key))
    }
}

impl Keys for Memory {
    async fn sign(&self, key: &str, d: &[u8; 32]) -> Result<Vec<u8>, KeyError> {
        self.before(Op::Sign, key).await?;
        let pair = self.signing(Op::Sign, key)?;
        let d = Digest::import_less_safe(d, &digest::SHA256).expect("32 bytes is a SHA-256 digest");
        let failed = |_| KeyError::Unavailable { op: Op::Sign, key: key.to_owned() };
        Ok(match self.behaviour() {
            Behaviour::RawSignature => raw(pair.sign_digest(&d).map_err(failed)?.as_ref()),
            Behaviour::OtherKey => self.other.sign_digest(&d).map_err(failed)?.as_ref().to_vec(),
            _ => pair.sign_digest(&d).map_err(failed)?.as_ref().to_vec(),
        })
    }

    async fn decrypt(&self, key: &str, ciphertext: &[u8]) -> Result<Vec<u8>, KeyError> {
        self.before(Op::Decrypt, key).await?;
        let wrapping = self.wrapping(Op::Decrypt, key)?;
        let denied = || KeyError::Denied { op: Op::Decrypt, key: key.to_owned() };
        let opened = (ciphertext.len() > 12)
            .then(|| {
                let (nonce, sealed) = ciphertext.split_at(12);
                let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
                let mut buffer = sealed.to_vec();
                let plain = wrapping.open_in_place(nonce, Aad::empty(), &mut buffer).ok()?;
                Some(plain.to_vec())
            })
            .flatten();
        match (opened, self.behaviour()) {
            (Some(mut plain), Behaviour::WrongPlaintext) => {
                plain[0] ^= 1;
                Ok(plain)
            }
            (Some(plain), _) => Ok(plain),
            (None, Behaviour::AcceptsGarbage) => Ok(vec![0; 32]),
            (None, _) => Err(denied()),
        }
    }

    async fn encrypt(&self, key: &str, plaintext: &[u8]) -> Result<Vec<u8>, KeyError> {
        self.before(Op::Encrypt, key).await?;
        let wrapping = self.wrapping(Op::Encrypt, key)?;
        if self.behaviour() == Behaviour::RefusesEncrypt {
            return Err(KeyError::Denied { op: Op::Encrypt, key: key.to_owned() });
        }
        let mut nonce = [0u8; 12];
        aws_lc_rs::rand::fill(&mut nonce).expect("the system RNG does not fail");
        let mut sealed = plaintext.to_vec();
        wrapping
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut sealed)
            .map_err(|_| KeyError::Unavailable { op: Op::Encrypt, key: key.to_owned() })?;
        let mut out = nonce.to_vec();
        out.extend(sealed);
        Ok(out)
    }

    async fn public_key(&self, key: &str) -> Result<Vec<u8>, KeyError> {
        self.before(Op::PublicKey, key).await?;
        let der = self
            .signing(Op::PublicKey, key)?
            .public_key()
            .as_der()
            .map_err(|_| KeyError::Unavailable { op: Op::PublicKey, key: key.to_owned() })?;
        Ok(der.as_ref().to_vec())
    }
}

/// Where a helper binds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bind {
    Loopback,
    /// Off loopback as well: what the suite must catch from the helper's own loopback.
    AllInterfaces,
}

/// A running memory helper, with keys `ca` and `policy` (P-256) and `dek` (AES-256-GCM).
pub struct Helper {
    pub port: u16,
    bind: Bind,
    behaviour: Arc<Mutex<Behaviour>>,
    keys: Arc<Memory>,
    runtime: Option<Runtime>,
}

struct Shared(Arc<Memory>);

impl Keys for Shared {
    async fn sign(&self, key: &str, digest: &[u8; 32]) -> Result<Vec<u8>, KeyError> {
        self.0.sign(key, digest).await
    }
    async fn decrypt(&self, key: &str, ciphertext: &[u8]) -> Result<Vec<u8>, KeyError> {
        self.0.decrypt(key, ciphertext).await
    }
    async fn encrypt(&self, key: &str, plaintext: &[u8]) -> Result<Vec<u8>, KeyError> {
        self.0.encrypt(key, plaintext).await
    }
    async fn public_key(&self, key: &str) -> Result<Vec<u8>, KeyError> {
        self.0.public_key(key).await
    }
}

impl Helper {
    /// Starts a helper on a free loopback port.
    pub fn start(behaviour: Behaviour) -> Self {
        Self::start_on(behaviour, Bind::Loopback)
    }

    /// Starts a helper with the given bind.
    pub fn start_on(behaviour: Behaviour, bind: Bind) -> Self {
        let behaviour = Arc::new(Mutex::new(behaviour));
        let mut dek = [0u8; 32];
        aws_lc_rs::rand::fill(&mut dek).expect("the system RNG does not fail");
        let keys = Arc::new(Memory {
            behaviour: Arc::clone(&behaviour),
            signing: vec![("ca".to_owned(), new_pair()), ("policy".to_owned(), new_pair())],
            other: new_pair(),
            wrapping: vec![(
                "dek".to_owned(),
                LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &dek).expect("32 bytes is an AES-256 key")),
            )],
        });
        let mut helper = Self { port: 0, bind, behaviour, keys, runtime: None };
        helper.run();
        helper
    }

    fn run(&mut self) {
        // reqwest needs a crypto provider chosen before its first client, in every test.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().expect("a runtime");
        let host = match self.bind {
            Bind::Loopback => "127.0.0.1",
            Bind::AllInterfaces => "0.0.0.0",
        };
        // Bound outside the runtime: this may be called from inside a test's own.
        let listener = std::net::TcpListener::bind((host, self.port)).expect("binding the memory helper");
        listener.set_nonblocking(true).expect("a nonblocking socket");
        self.port = listener.local_addr().expect("a bound address").port();
        let router = server::router(Shared(Arc::clone(&self.keys)));
        runtime.spawn(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("a tokio listener");
            let _ = axum::serve(listener, router).await;
        });
        self.runtime = Some(runtime);
    }

    /// `http://127.0.0.1:PORT`.
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// A client for this helper.
    pub fn client(&self) -> verifier::HelperClient {
        verifier::HelperClient::new(self.url().parse().expect("a loopback URL")).expect("a client")
    }

    /// Changes what it does from the next request on.
    pub fn set(&self, behaviour: Behaviour) {
        *self.behaviour.lock().unwrap_or_else(|p| p.into_inner()) = behaviour;
    }

    /// Stops it: its port refuses connections, and every open one ends.
    pub fn stop(&mut self) {
        if let Some(r) = self.runtime.take() {
            r.shutdown_background();
        }
    }

    /// Starts it again on the same port with the same keys.
    pub fn resume(&mut self) {
        if self.runtime.is_none() {
            self.run();
        }
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        self.stop();
    }
}
