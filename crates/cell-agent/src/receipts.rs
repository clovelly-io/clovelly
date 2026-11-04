//! Signed receipts and the customer's receipt log (SPEC.md "Receipt", "Receipts:
//! latest-per-sandbox with a `final` flag", decision 7).
//!
//! [`Signer`] signs receipt documents with the cell key over their JCS form and attaches
//! the current cell certificate (swapped at each lease renewal). [`Log`] delivers
//! records to the customer's verifier (`AppendReceipt`): every [`FLUSH_EVERY`] a
//! last-will record for each running sandbox (`exit.kind = cell_lost`, `ended` now, not
//! final), which is what the log keeps if the cell stops without notice, and each
//! sandbox's final record as soon as it ends, retried until the log has it. A cell ending
//! in order waits for [`Log::delivered`] before it may be deleted, or its sandboxes' last
//! wills would stand as `cell_lost`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use common::proto::verifier::LogRecord;
use common::tdx::Quote;
use serde_json::{Value, json};
use tokio::sync::Notify;

use crate::agent::status;
use crate::boot::CellKey;
use crate::grpc::GrpcVerifier;

/// How often last-will records are flushed. Under 10 s, so that with signing and
/// delivery the newest record is never more than 10 s older than a hard stop
/// (criterion 11; DECISIONS).
pub const FLUSH_EVERY: Duration = Duration::from_secs(9);
/// Final records kept for delivery while the log is unreachable.
const MAX_PENDING: usize = 100_000;

#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("the cell key does not make a signing key")]
    Key,
    #[error("the unlock quote does not parse: {0}")]
    Quote(#[from] common::tdx::QuoteError),
    #[error(transparent)]
    Receipt(#[from] common::receipt::ReceiptError),
}

/// A signed receipt: its canonical bytes, the signature and the signing certificate.
#[derive(Debug, Clone)]
pub struct Signed {
    pub json: Vec<u8>,
    pub signature: Vec<u8>,
    pub cell_cert: Vec<u8>,
}

impl Signed {
    pub fn record(self, last: bool, egress_log: Vec<String>) -> LogRecord {
        LogRecord { receipt: self.json, signature: self.signature, cell_cert: self.cell_cert, r#final: last, egress_log }
    }
}

/// Signs receipts with the cell key.
pub struct Signer {
    key: EcdsaKeyPair,
    cert: RwLock<Vec<u8>>,
    measurements: Value,
}

impl Signer {
    /// The cell key as a signing key, the first lease's certificate, and the
    /// measurements from the quote the cell unlocked with.
    pub fn new(cell: &CellKey, cert: &[u8], quote: &[u8]) -> Result<Self, SignerError> {
        let mut der = cell.private_sec1_der();
        let key = EcdsaKeyPair::from_private_key_der(&ECDSA_P256_SHA256_FIXED_SIGNING, &der).map_err(|_| SignerError::Key);
        common::dek::wipe(&mut der);
        let q = Quote::parse(quote)?;
        Ok(Self {
            key: key?,
            cert: RwLock::new(cert.to_vec()),
            measurements: json!({ "mrtd": q.mr_td.to_string(), "rtmr": q.rtmrs.iter().map(ToString::to_string).collect::<Vec<_>>() }),
        })
    }

    /// A signer with its own key, for tests and the dev server (whose receipts chain to
    /// nothing).
    pub fn ephemeral() -> Self {
        Self {
            key: EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).expect("P-256 key generation does not fail"),
            cert: RwLock::new(Vec::new()),
            measurements: json!({ "mrtd": "", "rtmr": ["", "", "", ""] }),
        }
    }

    /// The certificate from a renewed lease (same key).
    pub fn set_cert(&self, cert: &[u8]) {
        *self.cert.write().unwrap_or_else(|p| p.into_inner()) = cert.to_vec();
    }

    /// `{"mrtd", "rtmr"}` for the receipt's `measurements`.
    pub fn measurements(&self) -> Value {
        self.measurements.clone()
    }

    pub fn sign(&self, doc: &Value) -> Result<Signed, SignerError> {
        let (json, signature) = common::receipt::sign(doc, &self.key)?;
        Ok(Signed { json, signature, cell_cert: self.cert.read().unwrap_or_else(|p| p.into_inner()).clone() })
    }
}

/// Where records go, and the finals not yet delivered.
pub struct Log {
    verifier: Option<GrpcVerifier>,
    pending: Mutex<VecDeque<LogRecord>>,
    /// Finals the log has not confirmed: those pending and those in a batch on its way.
    undelivered: AtomicUsize,
    wake: Notify,
}

impl Log {
    /// A log delivering to `verifier`; none keeps nothing (the dev server).
    pub fn new(verifier: Option<GrpcVerifier>) -> Arc<Self> {
        Arc::new(Self { verifier, pending: Mutex::new(VecDeque::new()), undelivered: AtomicUsize::new(0), wake: Notify::new() })
    }

    /// Queues a sandbox's final record and delivers it at once.
    pub fn push_final(&self, record: LogRecord) {
        if self.verifier.is_none() {
            return;
        }
        let mut q = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        if q.len() >= MAX_PENDING {
            q.pop_front();
            self.undelivered.fetch_sub(1, Ordering::Relaxed);
        }
        q.push_back(record);
        self.undelivered.fetch_add(1, Ordering::Relaxed);
        drop(q);
        self.wake.notify_one();
    }

    /// Asks for a flush now (a sandbox's state changed, e.g. its volume committed).
    pub fn flush_soon(&self) {
        self.wake.notify_one();
    }

    /// Waits until the log has confirmed every final record, for at most `within`; says
    /// whether it did. A verifier that stays unreachable must not keep a cell up for ever.
    pub async fn delivered(&self, within: Duration) -> bool {
        self.wake.notify_one();
        let deadline = tokio::time::Instant::now() + within;
        while self.undelivered.load(Ordering::Relaxed) > 0 {
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        true
    }

    /// Delivers until the cell ends: every [`FLUSH_EVERY`], and whenever woken, the
    /// pending finals and a last will for each sandbox `wills` returns.
    pub async fn run(self: Arc<Self>, wills: impl Fn() -> Vec<LogRecord>) {
        let Some(mut verifier) = self.verifier.clone() else { return };
        let mut tick = tokio::time::interval(FLUSH_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                () = self.wake.notified() => {}
            }
            let finals: Vec<LogRecord> = self.pending.lock().unwrap_or_else(|p| p.into_inner()).drain(..).collect();
            let mut batch = finals.clone();
            batch.extend(wills());
            if batch.is_empty() {
                continue;
            }
            let n = batch.len();
            match verifier.append_receipts(batch).await {
                Ok(_) => {
                    self.undelivered.fetch_sub(finals.len(), Ordering::Relaxed);
                }
                Err(e) => {
                    status("receipts-undelivered", json!({ "records": n, "error": e }));
                    let mut q = self.pending.lock().unwrap_or_else(|p| p.into_inner());
                    for r in finals.into_iter().rev() {
                        q.push_front(r);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cell's ending waits for its finals, and gives up rather than stay up for ever.
    #[tokio::test]
    async fn delivered_waits_for_the_finals_and_gives_up() {
        let log = Log::new(None);
        assert!(log.delivered(Duration::ZERO).await, "nothing owed");
        log.undelivered.store(1, Ordering::Relaxed);
        assert!(!log.delivered(Duration::from_millis(1)).await, "one still owed");
        let waiting = tokio::spawn({
            let log = Arc::clone(&log);
            async move { log.delivered(Duration::from_secs(30)).await }
        });
        log.undelivered.store(0, Ordering::Relaxed);
        assert!(waiting.await.unwrap());
    }

    #[test]
    fn signed_records_carry_their_parts() {
        let s = Signer::ephemeral();
        let signed = s.sign(&json!({ "v": 1, "b": [1, 2], "a": "x" })).unwrap();
        assert_eq!(signed.json, br#"{"a":"x","b":[1,2],"v":1}"#);
        assert_eq!(signed.signature.len(), 64);
        let r = signed.record(true, vec!["{}".into()]);
        assert!(r.r#final && r.egress_log.len() == 1);
    }
}
