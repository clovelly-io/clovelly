//! The Intel SGX extension of a PCK certificate (OID 1.2.840.113741.1.13.1): the
//! platform's PPID, FMSPC, PCE id and its TCB as certified.

use der::asn1::{Any, ObjectIdentifier, OctetString};
use der::{Decode, Sequence};
use x509_cert::Certificate;

use super::QvlError;

const SGX_EXTENSION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1");
const PPID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.1");
const TCB: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2");
const PCE_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.3");
const FMSPC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.4");
/// TCB children: .1 to .16 are the SGX TCB component SVNs, .17 the PCE SVN.
const TCB_PCESVN_ARC: u32 = 17;

#[derive(Sequence)]
struct Entry {
    id: ObjectIdentifier,
    value: Any,
}

/// What the PCK certificate says about its platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PckInfo {
    pub ppid: [u8; 16],
    pub fmspc: [u8; 6],
    pub pce_id: [u8; 2],
    /// SGX TCB component SVNs 1..=16.
    pub components: [u8; 16],
    pub pce_svn: u16,
}

fn octets<const N: usize>(v: &Any, what: &'static str) -> Result<[u8; N], QvlError> {
    v.decode_as::<OctetString>()
        .ok()
        .and_then(|o| o.as_bytes().try_into().ok())
        .ok_or(QvlError::PckExtension(what))
}

impl PckInfo {
    pub fn of(leaf: &Certificate) -> Result<Self, QvlError> {
        let ext = leaf
            .tbs_certificate()
            .extensions()
            .into_iter()
            .flatten()
            .find(|e| e.extn_id == SGX_EXTENSION)
            .ok_or(QvlError::PckExtension("no SGX extension"))?;
        let entries = Vec::<Entry>::from_der(ext.extn_value.as_bytes())
            .map_err(|_| QvlError::PckExtension("SGX extension is not a sequence"))?;
        let find = |id: ObjectIdentifier, what| {
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| &e.value)
                .ok_or(QvlError::PckExtension(what))
        };
        let tcb = find(TCB, "TCB")?
            .decode_as::<Vec<Entry>>()
            .map_err(|_| QvlError::PckExtension("TCB is not a sequence"))?;
        let mut components = [0u8; 16];
        let mut pce_svn = None;
        for e in &tcb {
            let arc = e.id.arcs().last().unwrap_or_default();
            match arc {
                1..=16 => {
                    components[arc as usize - 1] = e
                        .value
                        .decode_as::<u8>()
                        .map_err(|_| QvlError::PckExtension("TCB component"))?;
                }
                TCB_PCESVN_ARC => {
                    pce_svn = Some(
                        e.value
                            .decode_as::<u16>()
                            .map_err(|_| QvlError::PckExtension("PCESVN"))?,
                    );
                }
                _ => {}
            }
        }
        Ok(Self {
            ppid: octets(find(PPID, "PPID")?, "PPID")?,
            fmspc: octets(find(FMSPC, "FMSPC")?, "FMSPC")?,
            pce_id: octets(find(PCE_ID, "PCE id")?, "PCE id")?,
            components,
            pce_svn: pce_svn.ok_or(QvlError::PckExtension("PCESVN"))?,
        })
    }
}
