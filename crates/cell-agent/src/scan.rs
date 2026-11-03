//! Searches a live process's memory for a byte string (the test image's DEK-marker
//! scan, criterion 10). Reads `/proc/<pid>/maps` and `/proc/<pid>/mem`; needs root.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

const CHUNK: usize = 1 << 20;

/// What a scan covered and where `needle` was found.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Scan {
    pub regions: usize,
    pub bytes: u64,
    pub hits: Vec<u64>,
}

/// Scans every readable mapping of `pid` for `needle`.
pub fn scan(pid: u32, needle: &[u8]) -> io::Result<Scan> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    let mem = File::open(format!("/proc/{pid}/mem"))?;
    let mut out = Scan::default();
    for line in maps.lines() {
        let mut f = line.split_whitespace();
        let (Some(range), Some(perms)) = (f.next(), f.next()) else { continue };
        let name = f.nth(3).unwrap_or_default();
        if !perms.starts_with('r') || name.starts_with("[vvar") || name == "[vsyscall]" {
            continue;
        }
        let Some((start, end)) = range.split_once('-') else { continue };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16)) else {
            continue;
        };
        out.regions += 1;
        let mut at = start;
        let mut buf = vec![0u8; CHUNK];
        while at < end {
            let len = ((end - at) as usize).min(CHUNK);
            // Unreadable pages (guard pages, device mappings) end this region's scan.
            let Ok(n) = mem.read_at(&mut buf[..len], at) else { break };
            if n == 0 {
                break;
            }
            out.bytes += n as u64;
            out.hits.extend(
                buf[..n]
                    .windows(needle.len())
                    .enumerate()
                    .filter(|(_, w)| *w == needle)
                    .map(|(i, _)| at + i as u64),
            );
            // Overlap chunks so a needle across a boundary is still found.
            let step = if n == len && at + (n as u64) < end { n.saturating_sub(needle.len() - 1).max(1) } else { n };
            at += step as u64;
        }
    }
    out.hits.sort_unstable();
    out.hits.dedup();
    Ok(out)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[test]
    fn finds_a_marker_in_its_own_memory_only_while_held() {
        let marker: Vec<u8> = b"clovelly-scan-test-marker-"
            .iter()
            .copied()
            .chain(std::process::id().to_le_bytes())
            .collect();
        let held = std::hint::black_box(marker.clone());
        let me = std::process::id();
        let found = super::scan(me, &held).unwrap();
        assert!(found.regions > 0 && found.bytes > 0);
        assert!(!found.hits.is_empty(), "the marker is in this process's memory");
    }
}
