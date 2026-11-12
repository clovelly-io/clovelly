//! TD quote fields, parsed from the raw quote that configfs-tsm returns.
//!
//! This is parsing only. The quote's signature, collateral and TCB status are checked by
//! the verifier (check 1, through `dcap-qvl`).

use std::fmt;

/// A SHA-384 measurement register value: MRTD, RTMR0..3 or MR_OWNER.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Measurement(pub [u8; 48]);

impl Measurement {
    /// The value every RTMR starts from at TD build.
    pub const ZERO: Self = Self([0; 48]);

    /// SHA-384 of `data`.
    pub fn sha384(data: &[u8]) -> Self {
        Self(array(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA384, data).as_ref()))
    }

    /// `SHA-384(self || digest)`: how an RTMR is extended.
    pub fn extend(&self, digest: &Measurement) -> Self {
        let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA384);
        ctx.update(&self.0);
        ctx.update(&digest.0);
        Self(array(ctx.finish().as_ref()))
    }
}

/// What GCE writes to MR_OWNER: SHA-384 of the instance's project, zone and instance
/// (go-tdx-guest `gce.PZIDPayload`). The verifier checks a quote's MR_OWNER against this at
/// unlock, with its policy's project; a cell recomputes it with its metadata's project to
/// learn whether that is the project the verifier vouched for (`crate::pass::Project::attested`).
/// One function for both, so the two cannot drift. Zones are DNS labels, so no JSON escaping
/// arises.
pub fn mr_owner(instance_id: u64, project_number: u64, zone: &crate::ids::Zone) -> Measurement {
    Measurement::sha384(format!(r#"{{"instanceId":{instance_id},"numericalProjectId":{project_number},"zone":"{zone}"}}"#).as_bytes())
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{0:?} is not 96 hex digits")]
pub struct BadMeasurement(String);

impl std::str::FromStr for Measurement {
    type Err = BadMeasurement;

    fn from_str(s: &str) -> Result<Self, BadMeasurement> {
        crate::unhex(s)
            .and_then(|b| b.try_into().ok())
            .map(Self)
            .ok_or_else(|| BadMeasurement(s.to_owned()))
    }
}

impl<'de> serde::Deserialize<'de> for Measurement {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for Measurement {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl fmt::Display for Measurement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&crate::hex(&self.0))
    }
}

impl fmt::Debug for Measurement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Measurement({self})")
    }
}

/// The 64 bytes a TD binds into its quote's REPORTDATA.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReportData(pub [u8; 64]);

impl fmt::Display for ReportData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&crate::hex(&self.0))
    }
}

impl fmt::Debug for ReportData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ReportData({self})")
    }
}

/// Quote format, from the quote header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteVersion {
    V4,
    V5,
}

/// The TD report fields of a quote that the harness and verifier read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quote {
    pub version: QuoteVersion,
    /// The TDX module's security version, one byte per component.
    pub tee_tcb_svn: [u8; 16],
    /// Measurement of the TDX module.
    pub mr_seam: Measurement,
    pub td_attributes: u64,
    /// Extended features (XSAVE) the TD may use.
    pub xfam: u64,
    pub mr_td: Measurement,
    pub mr_owner: Measurement,
    pub rtmrs: [Measurement; 4],
    pub report_data: ReportData,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum QuoteError {
    #[error("quote is {len} bytes, too short for its TD report")]
    TooShort { len: usize },
    #[error("unsupported quote version {0}")]
    UnsupportedVersion(u16),
    #[error("TEE type {0:#x} is not TDX (0x81)")]
    NotTdx(u32),
    #[error("v5 quote body type {0} is not a TD report")]
    NotTdReport(u16),
}

const HEADER_LEN: usize = 48;
const TEE_TYPE_TDX: u32 = 0x81;
/// v5 body types for TDX 1.0 and TDX 1.5 reports; both start with the TD 1.0 layout.
const V5_TD_REPORT_TYPES: [u16; 2] = [2, 3];
/// Length of the TD 1.0 report body, the part of the layout we read.
const TD_REPORT_LEN: usize = 584;

impl Quote {
    /// Parses the header and TD report body of a v4 or v5 TDX quote.
    pub fn parse(raw: &[u8]) -> Result<Self, QuoteError> {
        let too_short = || QuoteError::TooShort { len: raw.len() };
        let header = raw.get(..HEADER_LEN).ok_or_else(too_short)?;
        let tee_type = u32::from_le_bytes(array(&header[4..8]));
        let (version, body_at) = match u16::from_le_bytes(array(&header[0..2])) {
            4 => (QuoteVersion::V4, HEADER_LEN),
            5 => {
                let body_type = raw.get(HEADER_LEN..HEADER_LEN + 2).ok_or_else(too_short)?;
                let body_type = u16::from_le_bytes(array(body_type));
                if !V5_TD_REPORT_TYPES.contains(&body_type) {
                    return Err(QuoteError::NotTdReport(body_type));
                }
                // u16 body type, then u32 body size.
                (QuoteVersion::V5, HEADER_LEN + 6)
            }
            v => return Err(QuoteError::UnsupportedVersion(v)),
        };
        if tee_type != TEE_TYPE_TDX {
            return Err(QuoteError::NotTdx(tee_type));
        }
        let body = raw
            .get(body_at..body_at + TD_REPORT_LEN)
            .ok_or_else(too_short)?;
        let mr = |at: usize| Measurement(array(&body[at..at + 48]));
        Ok(Self {
            version,
            tee_tcb_svn: array(&body[0..16]),
            mr_seam: mr(16),
            td_attributes: u64::from_le_bytes(array(&body[120..128])),
            xfam: u64::from_le_bytes(array(&body[128..136])),
            mr_td: mr(136),
            mr_owner: mr(232),
            rtmrs: [mr(328), mr(376), mr(424), mr(472)],
            report_data: ReportData(array(&body[520..584])),
        })
    }

    /// True when the TD was launched with DEBUG set (TD_ATTRIBUTES bit 0).
    pub fn debug(&self) -> bool {
        self.td_attributes & 1 == 1
    }
}

/// Copies a slice whose length the caller has already fixed into an array.
fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().expect("caller slices exactly N bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MR_OWNER's preimage, byte for byte: the digest computed independently (Python's
    /// hashlib over the same JSON) for a made-up instance and project.
    #[test]
    fn mr_owner_is_sha384_of_gces_project_zone_and_instance() {
        let got = mr_owner(1_234_567_890_123_456_789, 210_987_654_321, &"us-central1-a".parse().unwrap());
        let want: Measurement = "8b94d43c64e54a08516e2e55c2c386a3c53ce323d971e94e36e636a6f5b5e29b4f448f7a044f66b7383c3e1e641703e2".parse().unwrap();
        assert_eq!(got, want);
    }

    /// Builds a quote with distinct, recognisable field values.
    fn quote(version: u16, rtmrs: [[u8; 48]; 4], report_data: [u8; 64]) -> Vec<u8> {
        let mut q = vec![0u8; HEADER_LEN];
        q[0..2].copy_from_slice(&version.to_le_bytes());
        q[4..8].copy_from_slice(&TEE_TYPE_TDX.to_le_bytes());
        if version == 5 {
            q.extend_from_slice(&2u16.to_le_bytes());
            q.extend_from_slice(&(TD_REPORT_LEN as u32).to_le_bytes());
        }
        let mut body = vec![0u8; TD_REPORT_LEN];
        body[0..16].fill(0x5c);
        body[16..64].fill(0x5e);
        body[120] = 1;
        body[128] = 0xe7;
        body[136..184].fill(0xd0);
        body[232..280].fill(0x0e);
        for (i, r) in rtmrs.iter().enumerate() {
            body[328 + 48 * i..376 + 48 * i].copy_from_slice(r);
        }
        body[520..584].copy_from_slice(&report_data);
        q.extend_from_slice(&body);
        q.extend_from_slice(&[0xaa; 100]); // signature data, not parsed
        q
    }

    #[test]
    fn parses_v4_and_v5_fields() {
        let rtmrs = [[1; 48], [2; 48], [3; 48], [4; 48]];
        let rd = [7; 64];
        for (v, version) in [(4, QuoteVersion::V4), (5, QuoteVersion::V5)] {
            let q = Quote::parse(&quote(v, rtmrs, rd)).unwrap();
            assert_eq!(q.version, version);
            assert!(q.debug());
            assert_eq!(q.tee_tcb_svn, [0x5c; 16]);
            assert_eq!(q.mr_seam, Measurement([0x5e; 48]));
            assert_eq!(q.xfam, 0xe7);
            assert_eq!(q.mr_td, Measurement([0xd0; 48]));
            assert_eq!(q.mr_owner, Measurement([0x0e; 48]));
            assert_eq!(q.rtmrs, rtmrs.map(Measurement));
            assert_eq!(q.report_data, ReportData(rd));
        }
    }

    #[test]
    fn rejects_short_foreign_and_unknown_quotes() {
        let good = quote(4, [[0; 48]; 4], [0; 64]);
        assert_eq!(
            Quote::parse(&good[..600]),
            Err(QuoteError::TooShort { len: 600 })
        );

        let mut sgx = good.clone();
        sgx[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(Quote::parse(&sgx), Err(QuoteError::NotTdx(0)));

        let mut v3 = good;
        v3[0] = 3;
        assert_eq!(Quote::parse(&v3), Err(QuoteError::UnsupportedVersion(3)));

        let mut enclave = quote(5, [[0; 48]; 4], [0; 64]);
        enclave[48] = 1;
        assert_eq!(Quote::parse(&enclave), Err(QuoteError::NotTdReport(1)));
    }
}
