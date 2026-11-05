//! The reference key helpers (`docs/key-helper.md`): examples, not the product.
//!
//! - [`server`]: the HTTP side of the contract over anything that implements
//!   [`verifier::Keys`], and what any Rust helper can reuse as it is.
//! - [`gcp`], [`aws`]: one backend each, small enough to read in one sitting. Copy one to
//!   reach a key manager we ship nothing for.
//!
//! The `clovelly-keys` binary serves a backend, creates its keys (`init`) and proves its
//! running role can do nothing but use them (`check-role`).

#[cfg(feature = "aws")]
pub mod aws;
#[cfg(feature = "gcp")]
pub mod gcp;
pub mod server;

/// One line of a `check-role` report: an administrative act the role must be refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub act: &'static str,
    /// `Ok` when the key manager refused it; `Err` says what happened instead.
    pub result: Result<(), String>,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.result {
            Ok(()) => write!(f, "ok    refused: {}", self.act),
            Err(what) => write!(f, "FAIL  not refused: {}: {what}", self.act),
        }
    }
}
