//! Replays a CCEL captured from a GCE c3-standard-4 TD booting the phase 0 test image
//! (TDX job run 20261026-063445) against the quote taken during the same boot.

use common::ccel::{self, CcelError, CcelTable, EventLog};
use common::tdx::Quote;

const TABLE: &[u8] = include_bytes!("data/gce-tdx-ccel-table.bin");
const QUOTE: &[u8] = include_bytes!("data/gce-tdx-quote.bin");
/// The log with the area's trailing 0xFF padding removed, to keep the fixture small.
const LOG: &[u8] = include_bytes!("data/gce-tdx-ccel-log.bin");

/// The log as the kernel exposes it: padded with 0xFF to the table's log-area length.
fn padded_log() -> Vec<u8> {
    let area = CcelTable::parse(TABLE).unwrap().log_area_len as usize;
    let mut log = LOG.to_vec();
    log.resize(area, 0xff);
    log
}

#[test]
fn gce_tdx_ccel_replays_to_its_quote() {
    let quote = Quote::parse(QUOTE).unwrap();
    let replayed = ccel::replay_against(TABLE, &padded_log(), &quote.rtmrs).unwrap();
    assert_eq!(replayed.rtmrs, quote.rtmrs);
    assert!(replayed.events > 10, "only {} events", replayed.events);
}

#[test]
fn changing_one_logged_digest_breaks_the_match() {
    let quote = Quote::parse(QUOTE).unwrap();
    let mut log = padded_log();
    let parsed = EventLog::parse(&log).unwrap();
    let event = parsed
        .events
        .iter()
        .find(|e| e.sha384.is_some() && (1..=4).contains(&e.mr_index) && e.event_type != 0x3)
        .expect("the log extends some RTMR");
    let (offset, rtmr) = (event.offset, event.mr_index as usize - 1);
    // MR index, event type, digest count, algorithm id, then the first digest byte. The
    // GCE log declares SHA-384 only, so it is the first digest.
    log[offset + 14] ^= 1;
    match ccel::replay_against(TABLE, &log, &quote.rtmrs) {
        Err(CcelError::Mismatch { index, .. }) => assert_eq!(index, rtmr),
        other => panic!("expected a mismatch on RTMR{rtmr}, got {other:?}"),
    }
}

/// The events step 1 of the boot sequence reads, as GCE's TDVF and systemd-stub log
/// them: the phase 0 image booted without Secure Boot, and the stub logged each UKI
/// section's name as UTF-16 event data.
#[test]
fn gce_tdx_ccel_has_the_events_the_agent_reads() {
    let log = padded_log();
    let parsed = EventLog::parse(&log).unwrap();
    assert_eq!(parsed.secure_boot(), Some(false));
    for section in [".linux", ".osrel", ".cmdline", ".initrd", ".uname", ".sbat"] {
        assert!(parsed.uki_section(section).is_some(), "{section}");
    }
    assert!(parsed.boot_authorities().is_empty());
}
