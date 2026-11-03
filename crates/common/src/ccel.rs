//! CC event log (CCEL) parsing and RTMR replay.
//!
//! TDVF and the boot chain record every RTMR extension in a TCG2 crypto-agile event log.
//! Linux exposes the ACPI `CCEL` table, which says which TEE wrote the log and how long
//! the log area is, at [`TABLE_PATH`], and the log itself at [`LOG_PATH`].
//!
//! Each event names a measurement-register index: 0 is MRTD and 1..=4 are RTMR0..3.
//! Replay folds each event's SHA-384 digest into its register,
//! `RTMR[i-1] = SHA384(RTMR[i-1] || digest)`, starting from zero, and must reproduce the
//! RTMRs in the quote. Replay never interprets event contents, so it holds for any boot
//! loader; deciding whether the events describe an image we published is the verifier's
//! job (phase 1).
//!
//! ```no_run
//! # fn run(quote: &common::tdx::Quote) -> Result<(), Box<dyn std::error::Error>> {
//! use common::ccel;
//! let table = std::fs::read(ccel::TABLE_PATH)?;
//! let log = std::fs::read(ccel::LOG_PATH)?;
//! let replayed = ccel::replay_against(&table, &log, &quote.rtmrs)?;
//! println!("{} events reproduce the quote's RTMRs", replayed.events);
//! # Ok(()) }
//! ```

use crate::tdx::Measurement;

pub const TABLE_PATH: &str = "/sys/firmware/acpi/tables/CCEL";
pub const LOG_PATH: &str = "/sys/firmware/acpi/tables/data/CCEL";

/// TCG event type for events that are logged but never extended into a register.
const EV_NO_ACTION: u32 = 0x3;
/// systemd-stub logs each UKI section it measures as two `EV_IPL` events.
const EV_IPL: u32 = 0xd;
const EV_EFI_VARIABLE_DRIVER_CONFIG: u32 = 0x8000_0001;
const EV_EFI_VARIABLE_AUTHORITY: u32 = 0x8000_00e0;
/// EFI_GLOBAL_VARIABLE, the vendor GUID of `SecureBoot`, `PK` and `KEK`.
const EFI_GLOBAL_VARIABLE: [u8; 16] = [
    0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c,
];
/// Measurement-register indexes as the log numbers them.
const MR_RTMR0: u32 = 1;
const MR_RTMR2: u32 = 3;
const TPM_ALG_SHA384: u16 = 0x000c;
const SPEC_ID_SIGNATURE: &[u8; 16] = b"Spec ID Event03\0";
/// ACPI CC type for Intel TDX.
const CC_TYPE_TDX: u8 = 2;
const TABLE_LEN: usize = 56;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CcelError {
    #[error("CCEL ACPI table is {0} bytes, expected at least {TABLE_LEN}")]
    TableTooShort(usize),
    #[error("ACPI table signature is {0:?}, not CCEL")]
    NotCcel([u8; 4]),
    #[error("CCEL ACPI table checksum does not sum to zero")]
    BadChecksum,
    #[error("CCEL was written by CC type {0}, not TDX ({CC_TYPE_TDX})")]
    NotTdx(u8),
    #[error("event log truncated in the event at offset {offset}")]
    Truncated { offset: usize },
    #[error("first event is not a TCG2 Spec ID event")]
    NoSpecIdEvent,
    #[error(
        "event at offset {offset} uses digest algorithm {alg:#06x}, not declared by the Spec ID event"
    )]
    UndeclaredAlgorithm { offset: usize, alg: u16 },
    #[error("event at offset {offset} has no SHA-384 digest")]
    NoSha384 { offset: usize },
    #[error("event at offset {offset} extends measurement register {index}, which is not an RTMR")]
    NotAnRtmr { offset: usize, index: u32 },
    #[error("non-padding bytes after the end of the log at offset {offset}")]
    TrailingData { offset: usize },
    #[error("RTMR{index} replays to {replayed} but the quote has {quoted}")]
    Mismatch {
        index: usize,
        replayed: Measurement,
        quoted: Measurement,
    },
}

/// The fields of the ACPI CCEL table that locate the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CcelTable {
    /// Log area minimum length (LAML): the size of the area the log was written into.
    pub log_area_len: u64,
    /// Log area start address (LASA), a guest-physical address.
    pub log_area_start: u64,
}

impl CcelTable {
    /// Parses the ACPI table and checks that it describes a TDX log.
    pub fn parse(raw: &[u8]) -> Result<Self, CcelError> {
        if raw.len() < TABLE_LEN {
            return Err(CcelError::TableTooShort(raw.len()));
        }
        let signature: [u8; 4] = array(&raw[0..4]);
        if &signature != b"CCEL" {
            return Err(CcelError::NotCcel(signature));
        }
        if raw.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) != 0 {
            return Err(CcelError::BadChecksum);
        }
        if raw[36] != CC_TYPE_TDX {
            return Err(CcelError::NotTdx(raw[36]));
        }
        Ok(Self {
            log_area_len: u64::from_le_bytes(array(&raw[40..48])),
            log_area_start: u64::from_le_bytes(array(&raw[48..56])),
        })
    }
}

/// One logged extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event<'a> {
    /// Byte offset of the event in the log, for error messages.
    pub offset: usize,
    /// Measurement-register index: 0 is MRTD, 1..=4 are RTMR0..3.
    pub mr_index: u32,
    pub event_type: u32,
    /// The SHA-384 digest, if the event carries one.
    pub sha384: Option<Measurement>,
    pub data: &'a [u8],
}

/// A parsed crypto-agile event log, without its Spec ID header event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventLog<'a> {
    pub events: Vec<Event<'a>>,
}

impl<'a> EventLog<'a> {
    /// Parses a TCG2 crypto-agile log: a SHA-1-format Spec ID event that declares the
    /// digest algorithms and sizes, then `TCG_PCR_EVENT2` records until the log ends
    /// or the rest of the area is padding (all 0xFF or all 0x00).
    pub fn parse(log: &'a [u8]) -> Result<Self, CcelError> {
        let mut r = Reader { log, at: 0 };
        let algorithms = r.spec_id_event()?;
        let mut events = Vec::new();
        while let Some(event) = r.event(&algorithms)? {
            events.push(event);
        }
        Ok(Self { events })
    }

    /// Folds the events into RTMR0..3.
    pub fn replay(&self) -> Result<[Measurement; 4], CcelError> {
        let mut rtmrs = [Measurement::ZERO; 4];
        for e in self.events.iter().filter(|e| e.event_type != EV_NO_ACTION) {
            let rtmr = match e.mr_index {
                1..=4 => &mut rtmrs[e.mr_index as usize - 1],
                index => {
                    return Err(CcelError::NotAnRtmr {
                        offset: e.offset,
                        index,
                    });
                }
            };
            let digest = e.sha384.ok_or(CcelError::NoSha384 { offset: e.offset })?;
            *rtmr = rtmr.extend(&digest);
        }
        Ok(rtmrs)
    }
}

/// A UEFI variable as logged in an `EV_EFI_VARIABLE_*` event (UEFI_VARIABLE_DATA).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variable<'a> {
    pub vendor: [u8; 16],
    pub name: String,
    pub data: &'a [u8],
}

impl<'a> Variable<'a> {
    /// Parses `VariableName` (GUID), name and data lengths, UTF-16LE name, data.
    pub fn parse(event_data: &'a [u8]) -> Option<Self> {
        let vendor: [u8; 16] = event_data.get(..16)?.try_into().ok()?;
        let name_len = usize::try_from(u64::from_le_bytes(event_data.get(16..24)?.try_into().ok()?)).ok()?;
        let data_len = usize::try_from(u64::from_le_bytes(event_data.get(24..32)?.try_into().ok()?)).ok()?;
        let name_end = 32usize.checked_add(name_len.checked_mul(2)?)?;
        let units: Vec<u16> = event_data
            .get(32..name_end)?
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some(Self {
            vendor,
            name: String::from_utf16(&units).ok()?,
            data: event_data.get(name_end..name_end.checked_add(data_len)?)?,
        })
    }
}

impl EventLog<'_> {
    /// The `SecureBoot` variable as the firmware measured it into RTMR0: `Some(true)`
    /// when Secure Boot was enforcing. Trust it only after the log replays to the
    /// quote's RTMRs.
    pub fn secure_boot(&self) -> Option<bool> {
        self.events
            .iter()
            .filter(|e| e.mr_index == MR_RTMR0 && e.event_type == EV_EFI_VARIABLE_DRIVER_CONFIG)
            .filter_map(|e| Variable::parse(e.data))
            .find(|v| v.vendor == EFI_GLOBAL_VARIABLE && v.name == "SecureBoot")
            .map(|v| v.data == [1])
    }

    /// The certificates (DER) of the signature-database entries that authorised the
    /// images firmware loaded under Secure Boot (`EV_EFI_VARIABLE_AUTHORITY`, RTMR0).
    /// Each entry is an EFI_SIGNATURE_DATA: owner GUID, then the certificate.
    pub fn boot_authorities(&self) -> Vec<&[u8]> {
        self.events
            .iter()
            .filter(|e| e.mr_index == MR_RTMR0 && e.event_type == EV_EFI_VARIABLE_AUTHORITY)
            .filter_map(|e| Variable::parse(e.data))
            .filter_map(|v| v.data.get(16..))
            .collect()
    }

    /// The digest systemd-stub measured for the contents of UKI section `name` (such as
    /// `.cmdline`) into RTMR2. The stub logs each section as two events whose data is
    /// the section name in UTF-16LE with its NUL: first the digest of the name (as
    /// ASCII with its NUL), then the digest of the contents.
    pub fn uki_section(&self, name: &str) -> Option<Measurement> {
        self.uki_section_event(name)?.sha384
    }

    /// The event that carries `name`'s contents digest (see [`Self::uki_section`]).
    pub fn uki_section_event(&self, name: &str) -> Option<&Event<'_>> {
        let tag: Vec<u8> = name
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut tagged = self
            .events
            .iter()
            .filter(|e| e.mr_index == MR_RTMR2 && e.event_type == EV_IPL && e.data == tag.as_slice());
        tagged.next()?;
        tagged.next()
    }
}

/// The outcome of a replay that matched the quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replayed {
    pub table: CcelTable,
    pub rtmrs: [Measurement; 4],
    /// Number of logged events, including those that extend nothing.
    pub events: usize,
}

/// Parses the ACPI table and the log, replays the log and compares every RTMR with
/// the values from the quote. The log is read only up to the table's log-area length.
pub fn replay_against(
    table: &[u8],
    log: &[u8],
    quoted: &[Measurement; 4],
) -> Result<Replayed, CcelError> {
    let table = CcelTable::parse(table)?;
    let area = usize::try_from(table.log_area_len).unwrap_or(usize::MAX);
    let log = EventLog::parse(&log[..log.len().min(area)])?;
    let rtmrs = log.replay()?;
    if let Some(index) = (0..4).find(|&i| rtmrs[i] != quoted[i]) {
        return Err(CcelError::Mismatch {
            index,
            replayed: rtmrs[index],
            quoted: quoted[index],
        });
    }
    Ok(Replayed {
        table,
        rtmrs,
        events: log.events.len(),
    })
}

/// A cursor over the raw log.
struct Reader<'a> {
    log: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize, offset: usize) -> Result<&'a [u8], CcelError> {
        let bytes = self
            .log
            .get(self.at..self.at.saturating_add(n))
            .ok_or(CcelError::Truncated { offset })?;
        self.at += n;
        Ok(bytes)
    }

    fn u16(&mut self, offset: usize) -> Result<u16, CcelError> {
        Ok(u16::from_le_bytes(array(self.take(2, offset)?)))
    }

    fn u32(&mut self, offset: usize) -> Result<u32, CcelError> {
        Ok(u32::from_le_bytes(array(self.take(4, offset)?)))
    }

    /// Reads the SHA-1-format header event and returns the declared (algorithm, size) pairs.
    fn spec_id_event(&mut self) -> Result<Vec<(u16, usize)>, CcelError> {
        // The register index is not checked: the TCG PC Client spec says 0, and GCE's TDVF
        // writes 1. The event type and signature identify the event.
        self.u32(0)?;
        let event_type = self.u32(0)?;
        self.take(20, 0)?; // SHA-1 digest, always zero for this event
        let size = self.u32(0)? as usize;
        let data = self.take(size, 0)?;
        // signature[16], platformClass u32, version u8 x2, errata u8, uintnSize u8,
        // numberOfAlgorithms u32, then {algorithmId u16, digestSize u16} per algorithm.
        if event_type != EV_NO_ACTION || data.get(..16) != Some(SPEC_ID_SIGNATURE) {
            return Err(CcelError::NoSpecIdEvent);
        }
        let count = data.get(24..28).ok_or(CcelError::NoSpecIdEvent)?;
        let count = u32::from_le_bytes(array(count)) as usize;
        let list = data
            .get(28..28 + count.saturating_mul(4))
            .ok_or(CcelError::NoSpecIdEvent)?;
        Ok(list
            .chunks_exact(4)
            .map(|a| {
                let alg = u16::from_le_bytes([a[0], a[1]]);
                (alg, u16::from_le_bytes([a[2], a[3]]) as usize)
            })
            .collect())
    }

    /// Reads the next `TCG_PCR_EVENT2`, or `None` at the end of the log.
    fn event(&mut self, algorithms: &[(u16, usize)]) -> Result<Option<Event<'a>>, CcelError> {
        let offset = self.at;
        let rest = &self.log[offset..];
        let Some(head) = rest.get(..8) else {
            return padding_only(rest, offset).map(|()| None);
        };
        if head.iter().all(|&b| b == 0xff) || head.iter().all(|&b| b == 0) {
            return padding_only(rest, offset).map(|()| None);
        }
        let mr_index = self.u32(offset)?;
        let event_type = self.u32(offset)?;
        let mut sha384 = None;
        for _ in 0..self.u32(offset)? {
            let alg = self.u16(offset)?;
            let &(_, size) = algorithms
                .iter()
                .find(|(a, _)| *a == alg)
                .ok_or(CcelError::UndeclaredAlgorithm { offset, alg })?;
            let digest = self.take(size, offset)?;
            if alg == TPM_ALG_SHA384 && size == 48 {
                sha384 = Some(Measurement(array(digest)));
            }
        }
        let size = self.u32(offset)? as usize;
        let data = self.take(size, offset)?;
        Ok(Some(Event {
            offset,
            mr_index,
            event_type,
            sha384,
            data,
        }))
    }
}

/// Accepts the unused tail of the log area, which must be one repeated padding byte.
fn padding_only(rest: &[u8], offset: usize) -> Result<(), CcelError> {
    match rest.first() {
        None => Ok(()),
        Some(&pad) if (pad == 0xff || pad == 0) && rest.iter().all(|&b| b == pad) => Ok(()),
        Some(_) => Err(CcelError::TrailingData { offset }),
    }
}

/// Copies a slice whose length the caller has already fixed into an array.
fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().expect("caller slices exactly N bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    const EV_EFI_BOOT_SERVICES_APPLICATION: u32 = 0x8000_0003;
    const TPM_ALG_SHA256: u16 = 0x000b;

    use aws_lc_rs::digest;

    fn sha384(parts: &[&[u8]]) -> [u8; 48] {
        let mut ctx = digest::Context::new(&digest::SHA384);
        parts.iter().for_each(|p| ctx.update(p));
        array(ctx.finish().as_ref())
    }

    /// A Spec ID event declaring SHA-256 and SHA-384, as TDVF writes it.
    fn spec_id_event() -> Vec<u8> {
        let mut data = SPEC_ID_SIGNATURE.to_vec();
        data.extend_from_slice(&0u32.to_le_bytes()); // platform class
        data.extend_from_slice(&[0, 2, 0, 2]); // version 2.0, errata, uintn size
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&TPM_ALG_SHA256.to_le_bytes());
        data.extend_from_slice(&32u16.to_le_bytes());
        data.extend_from_slice(&TPM_ALG_SHA384.to_le_bytes());
        data.extend_from_slice(&48u16.to_le_bytes());
        data.push(0); // vendor info size
        let mut e = Vec::new();
        e.extend_from_slice(&0u32.to_le_bytes());
        e.extend_from_slice(&EV_NO_ACTION.to_le_bytes());
        e.extend_from_slice(&[0; 20]);
        e.extend_from_slice(&(data.len() as u32).to_le_bytes());
        e.extend_from_slice(&data);
        e
    }

    fn event2(mr_index: u32, event_type: u32, digests: &[(u16, &[u8])], data: &[u8]) -> Vec<u8> {
        let mut e = Vec::new();
        e.extend_from_slice(&mr_index.to_le_bytes());
        e.extend_from_slice(&event_type.to_le_bytes());
        e.extend_from_slice(&(digests.len() as u32).to_le_bytes());
        for (alg, d) in digests {
            e.extend_from_slice(&alg.to_le_bytes());
            e.extend_from_slice(d);
        }
        e.extend_from_slice(&(data.len() as u32).to_le_bytes());
        e.extend_from_slice(data);
        e
    }

    /// A log with two RTMR0 events, one RTMR2 event and one EV_NO_ACTION event,
    /// followed by 0xFF padding as in a real log area.
    fn sample_log() -> (Vec<u8>, [Measurement; 4]) {
        let (d1, d2, d3) = ([0x11; 48], [0x22; 48], [0x33; 48]);
        let mut log = spec_id_event();
        log.extend(event2(
            1,
            EV_EFI_BOOT_SERVICES_APPLICATION,
            &[(TPM_ALG_SHA256, &[9; 32]), (TPM_ALG_SHA384, &d1)],
            b"fw",
        ));
        log.extend(event2(
            0,
            EV_NO_ACTION,
            &[(TPM_ALG_SHA384, &[0x99; 48])],
            b"ignored",
        ));
        log.extend(event2(1, EV_IPL, &[(TPM_ALG_SHA384, &d2)], b""));
        log.extend(event2(3, EV_IPL, &[(TPM_ALG_SHA384, &d3)], b"cmdline"));
        log.extend_from_slice(&[0xff; 64]);
        let rtmr0 = sha384(&[&sha384(&[&[0; 48], &d1]), &d2]);
        let rtmr2 = sha384(&[&[0; 48], &d3]);
        (
            log,
            [
                Measurement(rtmr0),
                Measurement::ZERO,
                Measurement(rtmr2),
                Measurement::ZERO,
            ],
        )
    }

    fn table(cc_type: u8, log_len: u64) -> Vec<u8> {
        let mut t = vec![0u8; TABLE_LEN];
        t[0..4].copy_from_slice(b"CCEL");
        t[4..8].copy_from_slice(&(TABLE_LEN as u32).to_le_bytes());
        t[36] = cc_type;
        t[40..48].copy_from_slice(&log_len.to_le_bytes());
        t[48..56].copy_from_slice(&0x7f00_0000u64.to_le_bytes());
        let sum = t.iter().fold(0u8, |s, b| s.wrapping_add(*b));
        t[9] = 0u8.wrapping_sub(sum);
        t
    }

    #[test]
    fn replay_folds_sha384_digests_by_register() {
        let (log, expected) = sample_log();
        let parsed = EventLog::parse(&log).unwrap();
        assert_eq!(parsed.events.len(), 4);
        assert_eq!(parsed.events[3].data, b"cmdline");
        assert_eq!(parsed.replay().unwrap(), expected);
    }

    #[test]
    fn replay_against_matches_quote_and_reports_first_mismatch() {
        let (log, expected) = sample_log();
        let t = table(CC_TYPE_TDX, log.len() as u64);
        let ok = replay_against(&t, &log, &expected).unwrap();
        assert_eq!(ok.events, 4);
        assert_eq!(ok.table.log_area_start, 0x7f00_0000);

        let mut quoted = expected;
        quoted[2] = Measurement([0xee; 48]);
        assert_eq!(
            replay_against(&t, &log, &quoted),
            Err(CcelError::Mismatch {
                index: 2,
                replayed: expected[2],
                quoted: quoted[2]
            })
        );
    }

    #[test]
    fn log_is_bounded_by_the_table_log_area() {
        let (mut log, expected) = sample_log();
        let area = log.len() as u64;
        log.extend_from_slice(b"junk past the log area");
        let t = table(CC_TYPE_TDX, area);
        assert!(replay_against(&t, &log, &expected).is_ok());
    }

    #[test]
    fn table_must_be_a_valid_tdx_ccel() {
        assert_eq!(
            CcelTable::parse(&[0; 10]),
            Err(CcelError::TableTooShort(10))
        );
        let mut wrong_sig = table(CC_TYPE_TDX, 0);
        wrong_sig[0..4].copy_from_slice(b"TDEL");
        assert_eq!(
            CcelTable::parse(&wrong_sig),
            Err(CcelError::NotCcel(*b"TDEL"))
        );
        let mut bad_sum = table(CC_TYPE_TDX, 0);
        bad_sum[20] ^= 1;
        assert_eq!(CcelTable::parse(&bad_sum), Err(CcelError::BadChecksum));
        assert_eq!(CcelTable::parse(&table(1, 0)), Err(CcelError::NotTdx(1)));
    }

    #[test]
    fn malformed_logs_are_rejected() {
        let (log, _) = sample_log();
        let header_len = spec_id_event().len();

        // Cut inside the first event after the header.
        assert_eq!(
            EventLog::parse(&log[..header_len + 20]),
            Err(CcelError::Truncated { offset: header_len })
        );

        let mut no_spec_id = log.clone();
        no_spec_id[4] = 0x1; // header event type is no longer EV_NO_ACTION
        assert_eq!(EventLog::parse(&no_spec_id), Err(CcelError::NoSpecIdEvent));

        let mut undeclared = spec_id_event();
        undeclared.extend(event2(1, EV_IPL, &[(0x0012, &[0; 32])], b""));
        assert_eq!(
            EventLog::parse(&undeclared),
            Err(CcelError::UndeclaredAlgorithm {
                offset: header_len,
                alg: 0x0012
            })
        );

        let mut trailing = log.clone();
        let last = trailing.len() - 1;
        trailing[last] = 0x42;
        assert!(matches!(
            EventLog::parse(&trailing),
            Err(CcelError::TrailingData { .. })
        ));
    }

    #[test]
    fn replay_rejects_mrtd_extensions_and_missing_sha384() {
        let mut mrtd = spec_id_event();
        mrtd.extend(event2(0, EV_IPL, &[(TPM_ALG_SHA384, &[0; 48])], b""));
        let log = EventLog::parse(&mrtd).unwrap();
        assert!(matches!(
            log.replay(),
            Err(CcelError::NotAnRtmr { index: 0, .. })
        ));

        let mut sha256_only = spec_id_event();
        sha256_only.extend(event2(2, EV_IPL, &[(TPM_ALG_SHA256, &[0; 32])], b""));
        let log = EventLog::parse(&sha256_only).unwrap();
        assert!(matches!(log.replay(), Err(CcelError::NoSha384 { .. })));
    }
}
