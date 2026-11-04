//! The customer's receipt log (SPEC.md "Receipts: latest-per-sandbox with a `final`
//! flag"). Cells append signed receipts: an interim record every 10 seconds while a
//! sandbox runs (the last-will flush, `exit.kind = cell_lost`) and a final one when it
//! ends. The log keeps the latest record per sandbox and how many it received; the SDK
//! lists them and reads a final record's egress log.
//!
//! Every record is verified before anything is kept ([`check`]): its signature under
//! its cell certificate, the certificate's chain to this environment's CA, and its
//! measurements against the release policy's (`common::receipt::verify`).
//!
//! A sandbox's latest record is the one with the highest `seq`, except that a final
//! record always supersedes an interim one and an interim record never supersedes a
//! final one. An interim record after which nothing for its sandbox has arrived for
//! [`LAST_WILL_MS`] is listed as final: its cell stopped flushing, so its signed
//! `cell_lost` stands. More than one final record for a sandbox id means two sandboxes
//! ran under one id, which only a misbehaving control plane (which hands out ids) can
//! cause; the counts in [`ReceiptLog::list`] show it.
//!
//! The log lives in this process's memory: staging runs the verifier as one Cloud Run
//! instance kept up for the length of a job (DECISIONS.md); a production deployment
//! backs it with the customer's own storage. Memory is bounded: past [`MAX_SANDBOXES`]
//! sandboxes or [`MAX_BYTES`] of stored records, the log evicts down to 90% of both,
//! ended sandboxes first and, among those, the longest silent first.
//!
//! Every call takes the clock as `now_ms` (Unix milliseconds).

use std::collections::{BTreeMap, BTreeSet, btree_map};
use std::sync::{Mutex, MutexGuard};

use aws_lc_rs::digest;
use common::ids::{EnvId, IdError, SandboxId, SubenvId};
use common::proto::verifier::{LogRecord, LoggedReceipt};
use common::receipt::{self, MeasurementSet, ReceiptError};
use serde_json::Value;

/// How long an interim record must go unfollowed to stand as its sandbox's final one.
pub const LAST_WILL_MS: u64 = 30_000;
/// The most sandboxes the log holds.
pub const MAX_SANDBOXES: usize = 200_000;
/// The most bytes of records (receipts, signatures, certificates, egress logs) it holds.
pub const MAX_BYTES: usize = 512 << 20;
/// What an entry costs beyond its records' bytes: the entry, its map node and headers.
const ENTRY_OVERHEAD: usize = 256;

/// Why a record was refused.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error(transparent)]
    Receipt(#[from] ReceiptError),
    #[error("the receipt is for environment {0}, not this verifier's")]
    Env(EnvId),
    #[error("receipt field seq is missing or not an integer")]
    Seq,
    #[error("receipt field sandbox.id: {0}")]
    SandboxId(#[from] IdError),
}

/// A record that verified, ready to append.
#[derive(Debug)]
pub struct Checked {
    sandbox: SandboxId,
    subenv: SubenvId,
    seq: u64,
    record: Record,
}

#[derive(Debug)]
struct Record {
    receipt: Vec<u8>,
    signature: Vec<u8>,
    cell_cert: Vec<u8>,
    kind: Kind,
}

#[derive(Debug)]
enum Kind {
    Interim,
    /// Appended as final, with the sandbox's egress log.
    Final { egress_log: Vec<String> },
}

impl Record {
    fn is_final(&self) -> bool {
        matches!(self.kind, Kind::Final { .. })
    }

    fn bytes(&self) -> usize {
        let lines = match &self.kind {
            Kind::Interim => 0,
            Kind::Final { egress_log } => egress_log.iter().map(|l| l.len() + size_of::<String>()).sum(),
        };
        self.receipt.len() + self.signature.len() + self.cell_cert.len() + lines
    }
}

/// Verifies `r` for environment `env`, against the environment CA certificates `cas`
/// (DER; more than one while the CA rotates) and the published measurement set. An interim record's egress log lines, if
/// any, are dropped: only a final record carries the log.
pub fn check(r: LogRecord, env: &EnvId, cas: &[&[u8]], set: &MeasurementSet) -> Result<Checked, RecordError> {
    let v = receipt::verify_any(&r.receipt, &r.signature, &r.cell_cert, cas, set)?;
    if &v.cert.env != env {
        return Err(RecordError::Env(v.cert.env));
    }
    let seq = v.doc.get("seq").and_then(Value::as_u64).ok_or(RecordError::Seq)?;
    let sandbox: SandboxId = v.sandbox_id().parse()?;
    let kind = if r.r#final { Kind::Final { egress_log: r.egress_log } } else { Kind::Interim };
    Ok(Checked {
        sandbox,
        subenv: v.cert.subenv,
        seq,
        record: Record {
            receipt: r.receipt,
            signature: r.signature,
            cell_cert: r.cell_cert,
            kind,
        },
    })
}

/// SHA-256 (lowercase hex) over `lines`, each followed by a newline: what the
/// receipt's `egress_log_hash` is, for a log the cell kept in full.
pub fn egress_log_sha256(lines: &[String]) -> String {
    let mut hash = digest::Context::new(&digest::SHA256);
    for line in lines {
        hash.update(line.as_bytes());
        hash.update(b"\n");
    }
    common::hex(hash.finish().as_ref())
}

/// One sandbox's entry.
#[derive(Debug)]
struct Entry {
    subenv: SubenvId,
    seq: u64,
    record: Record,
    /// When the kept record arrived.
    received_ms: u64,
    /// When any record for the sandbox last arrived, kept or not.
    last_ms: u64,
    records: u32,
    finals: u32,
}

impl Entry {
    fn is_final(&self, now_ms: u64) -> bool {
        self.record.is_final() || now_ms.saturating_sub(self.last_ms) >= LAST_WILL_MS
    }

    fn bytes(&self) -> usize {
        self.record.bytes() + ENTRY_OVERHEAD
    }

    fn logged(&self, now_ms: u64) -> LoggedReceipt {
        LoggedReceipt {
            receipt: self.record.receipt.clone(),
            signature: self.record.signature.clone(),
            cell_cert: self.record.cell_cert.clone(),
            r#final: self.is_final(now_ms),
            received_unix_ms: self.received_ms,
            records: self.records,
            finals: self.finals,
        }
    }
}

#[derive(Debug)]
struct Inner {
    entries: BTreeMap<SandboxId, Entry>,
    bytes: usize,
    max_sandboxes: usize,
    max_bytes: usize,
}

impl Inner {
    fn with_limits(max_sandboxes: usize, max_bytes: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            bytes: 0,
            max_sandboxes,
            max_bytes,
        }
    }

    fn append(&mut self, c: Checked, now_ms: u64) {
        let is_final = c.record.is_final();
        match self.entries.entry(c.sandbox) {
            btree_map::Entry::Vacant(slot) => {
                let entry = slot.insert(Entry {
                    subenv: c.subenv,
                    seq: c.seq,
                    record: c.record,
                    received_ms: now_ms,
                    last_ms: now_ms,
                    records: 1,
                    finals: u32::from(is_final),
                });
                self.bytes += entry.bytes();
            }
            btree_map::Entry::Occupied(mut slot) => {
                let e = slot.get_mut();
                e.records = e.records.saturating_add(1);
                e.finals = e.finals.saturating_add(u32::from(is_final));
                e.last_ms = now_ms;
                let supersedes = match (e.record.is_final(), is_final) {
                    (true, false) => false,
                    (false, true) => true,
                    _ => c.seq > e.seq,
                };
                if supersedes {
                    self.bytes = self.bytes - e.record.bytes() + c.record.bytes();
                    e.subenv = c.subenv;
                    e.seq = c.seq;
                    e.record = c.record;
                    e.received_ms = now_ms;
                }
            }
        }
    }

    /// Past either limit, evicts down to 90% of both: ended sandboxes first, the
    /// longest silent first.
    fn evict(&mut self, now_ms: u64) {
        if self.entries.len() <= self.max_sandboxes && self.bytes <= self.max_bytes {
            return;
        }
        let (keep_sandboxes, keep_bytes) = (self.max_sandboxes / 10 * 9, self.max_bytes / 10 * 9);
        let mut order: Vec<(bool, u64, SandboxId)> =
            self.entries.iter().map(|(id, e)| (!e.is_final(now_ms), e.last_ms, *id)).collect();
        order.sort_unstable();
        for (_, _, id) in order {
            if self.entries.len() <= keep_sandboxes && self.bytes <= keep_bytes {
                break;
            }
            if let Some(e) = self.entries.remove(&id) {
                self.bytes -= e.bytes();
            }
        }
    }
}

/// The receipt log (see the module docs).
#[derive(Debug)]
pub struct ReceiptLog {
    inner: Mutex<Inner>,
}

impl Default for ReceiptLog {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner::with_limits(MAX_SANDBOXES, MAX_BYTES)),
        }
    }
}

impl ReceiptLog {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Appends records [`check`] passed, received at `now_ms`, in order.
    pub fn append(&self, records: Vec<Checked>, now_ms: u64) {
        let mut inner = self.lock();
        for c in records {
            inner.append(c, now_ms);
        }
        inner.evict(now_ms);
    }

    /// The latest record of each sandbox in `subenv` (every sub-environment when
    /// `None`) and in `sandboxes` (every sandbox when empty), by sandbox id.
    pub fn list(&self, subenv: Option<&SubenvId>, sandboxes: &BTreeSet<SandboxId>, now_ms: u64) -> Vec<LoggedReceipt> {
        let inner = self.lock();
        let wanted = |e: &&Entry| subenv.is_none_or(|s| &e.subenv == s);
        let logged = |e: &Entry| e.logged(now_ms);
        if sandboxes.is_empty() {
            inner.entries.values().filter(wanted).map(logged).collect()
        } else {
            sandboxes.iter().filter_map(|id| inner.entries.get(id)).filter(wanted).map(logged).collect()
        }
    }

    /// The egress log that came with the sandbox's final record; `None` if no final
    /// record has arrived (an interim record that stands as final carries no log).
    pub fn egress_log(&self, sandbox: &SandboxId) -> Option<Vec<String>> {
        match &self.lock().entries.get(sandbox)?.record.kind {
            Kind::Final { egress_log } => Some(egress_log.clone()),
            Kind::Interim => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> SandboxId {
        format!("{n:032x}").parse().unwrap()
    }

    /// A record as `check` would pass it; `receipt` stands for the signed bytes.
    fn rec(sandbox: SandboxId, seq: u64, receipt: &str, egress: Option<&[&str]>) -> Checked {
        Checked {
            sandbox,
            subenv: "a".parse().unwrap(),
            seq,
            record: Record {
                receipt: receipt.as_bytes().to_vec(),
                signature: vec![0; 64],
                cell_cert: vec![1; 600],
                kind: match egress {
                    None => Kind::Interim,
                    Some(lines) => Kind::Final { egress_log: lines.iter().map(|l| (*l).to_owned()).collect() },
                },
            },
        }
    }

    fn only(log: &ReceiptLog, sandbox: SandboxId, now_ms: u64) -> LoggedReceipt {
        let mut all = log.list(None, &BTreeSet::from([sandbox]), now_ms);
        assert_eq!(all.len(), 1);
        all.remove(0)
    }

    /// The log keeps the latest record per sandbox by seq; a final record supersedes
    /// any interim one, and once it is in, later interim records are counted and
    /// ignored.
    #[test]
    fn the_latest_record_by_seq_is_kept_and_a_final_one_is_never_superseded_by_an_interim() {
        let log = ReceiptLog::default();
        let sb = id(1);
        log.append(vec![rec(sb, 2, "interim 2", None), rec(sb, 1, "interim 1, late", None)], 1_000);
        let l = only(&log, sb, 1_000);
        assert_eq!((l.receipt.as_slice(), l.r#final, l.records, l.finals), (b"interim 2".as_slice(), false, 2, 0));

        log.append(vec![rec(sb, 3, "interim 3", None)], 2_000);
        assert_eq!(only(&log, sb, 2_000).receipt, b"interim 3");
        // A final record wins even with a lower seq (the cell signed it with the seq
        // it had when the sandbox ended).
        log.append(vec![rec(sb, 3, "final", Some(&["line"]))], 3_000);
        log.append(vec![rec(sb, 9, "interim 9, after the end", None)], 4_000);
        let l = only(&log, sb, 4_000);
        assert_eq!((l.receipt.as_slice(), l.r#final, l.records, l.finals), (b"final".as_slice(), true, 5, 1));
        assert_eq!(l.received_unix_ms, 3_000);
        assert_eq!(log.egress_log(&sb), Some(vec!["line".to_owned()]));

        // Other sandboxes and sub-environments are listed apart.
        log.append(vec![rec(id(2), 1, "other", None)], 4_000);
        assert_eq!(log.list(None, &BTreeSet::new(), 4_000).len(), 2);
        assert_eq!(log.list(Some(&"a".parse().unwrap()), &BTreeSet::new(), 4_000).len(), 2);
        assert!(log.list(Some(&"b".parse().unwrap()), &BTreeSet::new(), 4_000).is_empty());
        assert!(log.list(None, &BTreeSet::from([id(3)]), 4_000).is_empty());
    }

    /// The last-will rule: an interim record stands as final once nothing for its
    /// sandbox has arrived for 30 s, and a later record (here a duplicate, ignored)
    /// starts the 30 s again.
    #[test]
    fn an_interim_record_is_final_after_30_s_without_another() {
        let log = ReceiptLog::default();
        let sb = id(1);
        log.append(vec![rec(sb, 5, "interim 5", None)], 10_000);
        assert!(!only(&log, sb, 10_000 + LAST_WILL_MS - 1).r#final);
        assert!(only(&log, sb, 10_000 + LAST_WILL_MS).r#final);
        assert_eq!(log.egress_log(&sb), None, "a last-will record carries no egress log");

        log.append(vec![rec(sb, 5, "interim 5 again", None)], 45_000);
        let l = only(&log, sb, 45_000);
        assert_eq!((l.receipt.as_slice(), l.r#final, l.records), (b"interim 5".as_slice(), false, 2));
        assert!(!only(&log, sb, 45_000 + LAST_WILL_MS - 1).r#final);
        assert!(only(&log, sb, 45_000 + LAST_WILL_MS).r#final);
    }

    /// Memory is bounded: past the limit, ended sandboxes go first, oldest first, and
    /// the byte count follows every insert, supersession and eviction.
    #[test]
    fn eviction_takes_ended_sandboxes_first() {
        let mut inner = Inner::with_limits(10, usize::MAX);
        // 0..5 ended at 90-94 s; 5..12 are running, though last heard from earlier (80 s).
        for n in 0..5 {
            inner.append(rec(id(n), 1, "r", Some(&[])), 90_000 + u64::from(n) * 1_000);
        }
        for n in 5..12 {
            inner.append(rec(id(n), 1, "r", None), 80_000 + u64::from(n) * 100);
        }
        inner.append(rec(id(11), 2, "running, newer", None), 81_200);
        inner.evict(101_000);
        assert_eq!(inner.entries.len(), 9);
        assert!((0..3).all(|n| !inner.entries.contains_key(&id(n))), "the oldest ended sandboxes went");
        assert!((3..12).all(|n| inner.entries.contains_key(&id(n))));
        assert_eq!(inner.bytes, inner.entries.values().map(Entry::bytes).sum::<usize>());

        let mut by_bytes = Inner::with_limits(usize::MAX, 3 * (ENTRY_OVERHEAD + 665));
        for n in 0..4 {
            by_bytes.append(rec(id(n), 1, "r", None), 0);
        }
        by_bytes.evict(1_000);
        assert_eq!(by_bytes.entries.len(), 2);
    }

    #[test]
    fn the_egress_log_hash_is_over_lines_each_followed_by_a_newline() {
        let lines = ["a".to_owned(), "bc".to_owned()];
        let want = common::hex(digest::digest(&digest::SHA256, b"a\nbc\n").as_ref());
        assert_eq!(egress_log_sha256(&lines), want);
    }
}
