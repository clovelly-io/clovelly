//! The customer's verifier (SPEC.md, "The verifier").
//!
//! A cell asks for a nonce, quotes over its key and the nonce, and sends the quote and
//! its event log to [`Verifier::unlock`]. Ten checks decide whether it is our image on
//! Google's TDX hardware in our project; if so the verifier issues the cell a
//! certificate under the environment CA and seals the sub-environment DEK to the
//! cell's key.
//!
//! - [`checks`]: the checks and the report of one evaluation.
//! - [`verifier`]: the evaluation itself, certificate issuance and DEK wrap.
//! - [`sources`]: the injectable seam for collateral, Google's registry and endorsements.
//! - [`keys`]: the customer's keys, reached through the key helper (`docs/key-helper.md`);
//!   this crate holds no key manager's code.
//! - [`init`], [`check_keys`]: setting up a configuration through a helper, and the
//!   conformance suite for one.
//! - [`policy`], [`config`]: the signed release policy and the deployment settings.
//! - [`fragments`]: per-release policy fragments, applied with a Rekor inclusion proof.
//! - [`receipts`]: the customer's receipt log.
//! - [`service`]: the gRPC API.

pub mod check_keys;
pub mod checks;
pub mod config;
#[cfg(any(test, feature = "test-keys"))]
pub mod corpus;
pub mod fragments;
pub mod init;
pub use common::jws;
pub mod keys;
pub mod nonce;
pub mod policy;
pub mod qvl;
pub mod receipts;
pub mod service;
pub mod sources;
pub mod verifier;
pub mod x509;

pub use checks::{Check, Failure, Outcome, Report};
pub use keys::{HelperClient, KeyError, Keys, KeysUrl};
#[cfg(any(test, feature = "test-keys"))]
pub use keys::LocalKms;
pub use sources::{HttpSources, Sources};
pub use verifier::{UnlockError, Unlocked, Verifier};

/// How long the verifier waits for one answer from the key helper.
pub fn keys_timeout() -> std::time::Duration {
    keys::TIMEOUT
}

/// Intel's SGX provisioning root CA, the production trust root for quotes.
pub const INTEL_ROOT: &[u8] = include_bytes!("../roots/Intel_SGX_RootCA.der");
/// Google's GCE-cc-tcb-root_1, which signs the firmware endorsement signers.
pub const GOOGLE_ROOT: &[u8] = include_bytes!("../roots/GCE-cc-tcb-root_1.crt");
/// The key of Sigstore's public Rekor log (`rekor.sigstore.dev/api/v1/log/publicKey`),
/// trusted for fragment inclusion proofs unless the configuration names others.
pub const REKOR_PUBLIC_KEY: &str = include_str!("../roots/rekor.sigstore.dev.pub");
