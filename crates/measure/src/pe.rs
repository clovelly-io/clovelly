//! Just enough PE/COFF to compute an Authenticode digest and read sections.

use aws_lc_rs::digest;
use common::tdx::Measurement;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PeError {
    #[error("PE image is truncated at {0}")]
    Truncated(&'static str),
    #[error("no PE signature at the e_lfanew offset")]
    NotPe,
    #[error("optional header magic {0:#06x} is not PE32+")]
    NotPe32Plus(u16),
    #[error("the certificate table does not end the file")]
    CertTableNotLast,
}

/// A section header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub virtual_size: usize,
    pub raw_size: usize,
    pub raw_offset: usize,
}

/// A parsed PE32+ image.
pub struct Pe<'a> {
    bytes: &'a [u8],
    checksum_at: usize,
    cert_dir_at: usize,
    size_of_headers: usize,
    cert_table: Option<(usize, usize)>,
    pub sections: Vec<Section>,
}

fn u16_at(b: &[u8], at: usize, what: &'static str) -> Result<u16, PeError> {
    b.get(at..at + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or(PeError::Truncated(what))
}

fn u32_at(b: &[u8], at: usize, what: &'static str) -> Result<u32, PeError> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(PeError::Truncated(what))
}

impl<'a> Pe<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PeError> {
        let pe = u32_at(bytes, 0x3c, "e_lfanew")? as usize;
        if bytes.get(pe..pe + 4) != Some(b"PE\0\0") {
            return Err(PeError::NotPe);
        }
        let sections = u16_at(bytes, pe + 6, "section count")? as usize;
        let optional_size = u16_at(bytes, pe + 20, "optional header size")? as usize;
        let optional = pe + 24;
        let magic = u16_at(bytes, optional, "magic")?;
        if magic != 0x20b {
            return Err(PeError::NotPe32Plus(magic));
        }
        // PE32+: data directories start at 112; the certificate table is entry 4.
        let cert_dir_at = optional + 112 + 4 * 8;
        let cert_offset = u32_at(bytes, cert_dir_at, "certificate table")? as usize;
        let cert_size = u32_at(bytes, cert_dir_at + 4, "certificate table")? as usize;
        let table = optional + optional_size;
        let sections = (0..sections)
            .map(|i| {
                let at = table + 40 * i;
                let name = bytes.get(at..at + 8).ok_or(PeError::Truncated("section"))?;
                Ok(Section {
                    name: String::from_utf8_lossy(name)
                        .trim_end_matches('\0')
                        .to_owned(),
                    virtual_size: u32_at(bytes, at + 8, "section")? as usize,
                    raw_size: u32_at(bytes, at + 16, "section")? as usize,
                    raw_offset: u32_at(bytes, at + 20, "section")? as usize,
                })
            })
            .collect::<Result<Vec<_>, PeError>>()?;
        let cert_table = (cert_size != 0).then_some((cert_offset, cert_size));
        if let Some((at, len)) = cert_table
            && at + len != bytes.len()
        {
            return Err(PeError::CertTableNotLast);
        }
        Ok(Self {
            bytes,
            checksum_at: optional + 64,
            cert_dir_at,
            size_of_headers: u32_at(bytes, optional + 60, "SizeOfHeaders")? as usize,
            cert_table,
            sections,
        })
    }

    /// The Authenticode digest (SHA-384), as UEFI firmware measures a loaded image:
    /// the headers without the checksum and the certificate-table directory entry, the
    /// sections in file order, then any data after them up to the certificate table.
    pub fn authenticode_sha384(&self) -> Result<Measurement, PeError> {
        let b = self.bytes;
        let headers = b
            .get(..self.size_of_headers)
            .ok_or(PeError::Truncated("headers"))?;
        let mut ctx = digest::Context::new(&digest::SHA384);
        ctx.update(&headers[..self.checksum_at]);
        ctx.update(&headers[self.checksum_at + 4..self.cert_dir_at]);
        ctx.update(&headers[self.cert_dir_at + 8..]);
        let mut sorted: Vec<&Section> = self.sections.iter().filter(|s| s.raw_size > 0).collect();
        sorted.sort_by_key(|s| s.raw_offset);
        let mut hashed = self.size_of_headers;
        for s in sorted {
            let raw = b
                .get(s.raw_offset..s.raw_offset + s.raw_size)
                .ok_or(PeError::Truncated("section data"))?;
            ctx.update(raw);
            hashed += s.raw_size;
        }
        let end = self.cert_table.map_or(b.len(), |(at, _)| at);
        if end > hashed {
            ctx.update(&b[hashed..end]);
        }
        Ok(Measurement(
            ctx.finish().as_ref().try_into().expect("SHA-384 is 48 bytes"),
        ))
    }

    /// The in-memory contents of the section named `name` (its virtual size, as
    /// systemd-stub measures it), if present.
    pub fn section(&self, name: &str) -> Option<&'a [u8]> {
        let s = self.sections.iter().find(|s| s.name == name)?;
        self.bytes
            .get(s.raw_offset..s.raw_offset + s.virtual_size.min(s.raw_size))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal PE32+ image: headers (0x200 bytes) and two sections, the second
    /// first in the section table but later in the file, plus `trailer`.
    pub(crate) fn image(sections: &[(&str, &[u8])], trailer: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 0x200];
        b[0x3c] = 0x40;
        b[0x40..0x44].copy_from_slice(b"PE\0\0");
        b[0x46..0x48].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        let optional_size: u16 = 112 + 16 * 8;
        b[0x54..0x56].copy_from_slice(&optional_size.to_le_bytes());
        let opt = 0x58;
        b[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        b[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes());
        b[opt + 64..opt + 68].copy_from_slice(&0xdead_beefu32.to_le_bytes()); // checksum
        let table = opt + optional_size as usize;
        for (i, (name, data)) in sections.iter().enumerate() {
            let at = table + 40 * i;
            let raw = b.len().max(0x200);
            b[at..at + name.len()].copy_from_slice(name.as_bytes());
            b[at + 8..at + 12].copy_from_slice(&(data.len() as u32).to_le_bytes());
            let padded = data.len().div_ceil(0x20) * 0x20;
            b[at + 16..at + 20].copy_from_slice(&(padded as u32).to_le_bytes());
            b[at + 20..at + 24].copy_from_slice(&(raw as u32).to_le_bytes());
            b.extend_from_slice(data);
            b.resize(raw + padded, 0);
        }
        b.extend_from_slice(trailer);
        b
    }

    #[test]
    fn authenticode_skips_checksum_and_signature() {
        let img = image(&[(".linux", b"kernel"), (".cmdline", b"x=1\n")], b"");
        let pe = Pe::parse(&img).unwrap();
        let base = pe.authenticode_sha384().unwrap();

        // The checksum field is not hashed.
        let mut other = img.clone();
        other[0x58 + 64] ^= 0xff;
        assert_eq!(Pe::parse(&other).unwrap().authenticode_sha384().unwrap(), base);

        // A certificate table appended at the end, and its directory entry, are not
        // hashed either.
        let mut signed = img.clone();
        let at = signed.len() as u32;
        signed.extend_from_slice(&[0xcc; 24]);
        let dir = 0x58 + 112 + 32;
        signed[dir..dir + 4].copy_from_slice(&at.to_le_bytes());
        signed[dir + 4..dir + 8].copy_from_slice(&24u32.to_le_bytes());
        assert_eq!(Pe::parse(&signed).unwrap().authenticode_sha384().unwrap(), base);

        // Section contents are.
        let changed = image(&[(".linux", b"kernel"), (".cmdline", b"x=2\n")], b"");
        assert_ne!(Pe::parse(&changed).unwrap().authenticode_sha384().unwrap(), base);
    }

    #[test]
    fn authenticode_is_sha384_of_the_hashed_ranges() {
        let img = image(&[(".a", b"abc")], b"tail");
        let pe = Pe::parse(&img).unwrap();
        let dir = 0x58 + 112 + 32;
        let mut expected = img[..0x58 + 64].to_vec();
        expected.extend_from_slice(&img[0x58 + 68..dir]);
        expected.extend_from_slice(&img[dir + 8..]); // headers, section, then trailer
        assert_eq!(pe.authenticode_sha384().unwrap(), Measurement::sha384(&expected));
    }

    #[test]
    fn sections_are_read_at_virtual_size() {
        let img = image(&[(".cmdline", b"console=ttyS0\n")], b"");
        let pe = Pe::parse(&img).unwrap();
        assert_eq!(pe.section(".cmdline"), Some(&b"console=ttyS0\n"[..]));
        assert_eq!(pe.section(".missing"), None);
        assert_eq!(Pe::parse(b"MZ").err(), Some(PeError::Truncated("e_lfanew")));
    }
}
