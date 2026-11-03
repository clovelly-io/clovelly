//! The signed structure of a DCAP TDX quote (Intel TDX DCAP Quoting Library API,
//! "Quote Format"): header, TD report body, and the ECDSA signature data with the QE
//! report and the PCK certificate chain.

use super::QvlError;

const HEADER_LEN: usize = 48;
const TD10_LEN: usize = 584;
const TD15_LEN: usize = 648;
const QE_REPORT_LEN: usize = 384;
/// Attestation key type 2: ECDSA-256 with P-256.
const ECDSA_P256: u16 = 2;
const TEE_TDX: u32 = 0x81;
/// Intel's QE vendor id.
const INTEL_QE_VENDOR: [u8; 16] = [
    0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07,
];
/// Certification data types: 6 wraps the QE report; 5 is a PEM PCK chain.
const QE_REPORT_CERT_DATA: u16 = 6;
const PCK_CHAIN: u16 = 5;

/// The TD report fields quote verification reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdFields {
    pub tee_tcb_svn: [u8; 16],
    pub mr_signer_seam: [u8; 48],
    pub seam_attributes: [u8; 8],
    /// TDX 1.5 reports also carry the current TCB, after module updates.
    pub tee_tcb_svn2: Option<[u8; 16]>,
}

/// The QE's SGX report (`sgx_report_body_t`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QeReport {
    pub raw: Vec<u8>,
    pub misc_select: u32,
    pub attributes: [u8; 16],
    pub mr_signer: [u8; 32],
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    pub report_data: [u8; 64],
}

/// A parsed quote, borrowing the raw bytes.
#[derive(Debug, Clone)]
pub struct SignedQuote<'a> {
    /// The bytes the attestation key signs: header and body.
    pub signed: &'a [u8],
    pub td: TdFields,
    pub signature: [u8; 64],
    pub attestation_key: [u8; 64],
    pub qe_report: QeReport,
    pub qe_report_signature: [u8; 64],
    pub qe_auth_data: &'a [u8],
    /// PCK chain, DER, leaf first.
    pub pck_chain: Vec<Vec<u8>>,
}

struct Cursor<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], QvlError> {
        let s = self
            .b
            .get(self.at..self.at.checked_add(n).ok_or(QvlError::Format(what))?)
            .ok_or(QvlError::Format(what))?;
        self.at += n;
        Ok(s)
    }

    fn u16(&mut self, what: &'static str) -> Result<u16, QvlError> {
        Ok(u16::from_le_bytes(arr(self.take(2, what)?)))
    }

    fn u32(&mut self, what: &'static str) -> Result<u32, QvlError> {
        Ok(u32::from_le_bytes(arr(self.take(4, what)?)))
    }
}

fn arr<const N: usize>(s: &[u8]) -> [u8; N] {
    s.try_into().expect("caller takes exactly N bytes")
}

impl<'a> SignedQuote<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self, QvlError> {
        let mut c = Cursor { b: raw, at: 0 };
        let header = c.take(HEADER_LEN, "header")?;
        let version = u16::from_le_bytes(arr(&header[0..2]));
        let key_type = u16::from_le_bytes(arr(&header[2..4]));
        let tee = u32::from_le_bytes(arr(&header[4..8]));
        if key_type != ECDSA_P256 {
            return Err(QvlError::AttestationKeyType(key_type));
        }
        if tee != TEE_TDX || header[12..28] != INTEL_QE_VENDOR {
            return Err(QvlError::Format("not an Intel TDX quote"));
        }
        let (body, td15) = match version {
            4 => (c.take(TD10_LEN, "TD report")?, false),
            5 => {
                let ty = c.u16("body type")?;
                let len = c.u32("body size")? as usize;
                match (ty, len) {
                    (2, TD10_LEN) => (c.take(len, "TD report")?, false),
                    (3, TD15_LEN) => (c.take(len, "TD report")?, true),
                    _ => return Err(QvlError::Format("v5 body is not a TD 1.0 or 1.5 report")),
                }
            }
            v => return Err(QvlError::Version(v)),
        };
        let signed = &raw[..c.at];
        let td = TdFields {
            tee_tcb_svn: arr(&body[0..16]),
            mr_signer_seam: arr(&body[64..112]),
            seam_attributes: arr(&body[112..120]),
            tee_tcb_svn2: td15.then(|| arr(&body[584..600])),
        };

        let sig_len = c.u32("signature data length")? as usize;
        let mut s = Cursor {
            b: c.take(sig_len, "signature data")?,
            at: 0,
        };
        let signature = arr(s.take(64, "quote signature")?);
        let attestation_key = arr(s.take(64, "attestation key")?);
        if s.u16("certification data type")? != QE_REPORT_CERT_DATA {
            return Err(QvlError::Format("certification data is not a QE report"));
        }
        let outer_len = s.u32("certification data size")? as usize;
        let mut d = Cursor {
            b: s.take(outer_len, "certification data")?,
            at: 0,
        };
        let qe = d.take(QE_REPORT_LEN, "QE report")?;
        let qe_report = QeReport {
            raw: qe.to_vec(),
            misc_select: u32::from_le_bytes(arr(&qe[16..20])),
            attributes: arr(&qe[48..64]),
            mr_signer: arr(&qe[128..160]),
            isv_prod_id: u16::from_le_bytes(arr(&qe[256..258])),
            isv_svn: u16::from_le_bytes(arr(&qe[258..260])),
            report_data: arr(&qe[320..384]),
        };
        let qe_report_signature = arr(d.take(64, "QE report signature")?);
        let auth_len = d.u16("QE auth data size")? as usize;
        let qe_auth_data = d.take(auth_len, "QE auth data")?;
        if d.u16("PCK certification data type")? != PCK_CHAIN {
            return Err(QvlError::Format("QE certification data is not a PCK chain"));
        }
        let pem_len = d.u32("PCK chain size")? as usize;
        let pem = d.take(pem_len, "PCK chain")?;
        let pem = std::str::from_utf8(pem).map_err(|_| QvlError::Format("PCK chain is not PEM"))?;
        let pck_chain = common::b64::pem_blocks(pem, "CERTIFICATE")
            .map_err(|_| QvlError::Format("PCK chain is not PEM"))?;
        Ok(Self {
            signed,
            td,
            signature,
            attestation_key,
            qe_report,
            qe_report_signature,
            qe_auth_data,
            pck_chain,
        })
    }
}
