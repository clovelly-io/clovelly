//! The firmware's `EV_EFI_GPT_EVENT`: the disk's GPT as UEFI_GPT_DATA.

const LBA: u64 = 512;

#[derive(Debug, thiserror::Error)]
pub enum GptError {
    #[error("reading the disk: {0}")]
    Io(#[from] std::io::Error),
    #[error("no GPT header at LBA 1")]
    NoHeader,
    #[error("GPT header field {0} is out of range")]
    Range(&'static str),
}

/// UEFI_GPT_DATA as TDVF logs it: the primary header (`HeaderSize` bytes), the number
/// of partitions in use as a u64, then each in-use entry (non-zero type GUID) in
/// table order.
pub fn gpt_event_data(disk: &mut (impl std::io::Read + std::io::Seek)) -> Result<Vec<u8>, GptError> {
    let mut lba1 = [0u8; LBA as usize];
    disk.seek(std::io::SeekFrom::Start(LBA))?;
    disk.read_exact(&mut lba1)?;
    if &lba1[..8] != b"EFI PART" {
        return Err(GptError::NoHeader);
    }
    let u32_at = |at: usize| u32::from_le_bytes(lba1[at..at + 4].try_into().expect("4 bytes"));
    let header_size = u32_at(12) as usize;
    let header = lba1.get(..header_size).ok_or(GptError::Range("HeaderSize"))?;
    let entries_lba = u64::from_le_bytes(lba1[72..80].try_into().expect("8 bytes"));
    let (count, entry_size) = (u32_at(80) as usize, u32_at(84) as usize);
    if !(128..=4096).contains(&entry_size) || count > 1024 {
        return Err(GptError::Range("partition entries"));
    }
    let mut table = vec![0u8; count * entry_size];
    disk.seek(std::io::SeekFrom::Start(entries_lba * LBA))?;
    disk.read_exact(&mut table)?;
    let used: Vec<&[u8]> = table
        .chunks_exact(entry_size)
        .filter(|e| e[..16].iter().any(|&b| b != 0))
        .collect();
    let mut data = header.to_vec();
    data.extend_from_slice(&(used.len() as u64).to_le_bytes());
    used.iter().for_each(|e| data.extend_from_slice(e));
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::tdx::Measurement;

    /// The first 34 LBAs of the phase 0 test image (disk.raw SHA-256 bd016f48…), whose
    /// GPT event a GCE TD logged with this digest.
    #[test]
    fn matches_the_digest_a_td_logged() {
        let head = include_bytes!("../tests/data/gpt-head.bin");
        let data = gpt_event_data(&mut std::io::Cursor::new(&head[..])).unwrap();
        assert_eq!(data.len(), 92 + 8 + 3 * 128);
        assert!(
            Measurement::sha384(&data)
                .to_string()
                .starts_with("06851a98da1b0c8a")
        );
    }
}
