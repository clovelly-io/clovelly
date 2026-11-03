//! Quotes through the Linux configfs-tsm report interface
//! (Documentation/ABI/testing/configfs-tsm-report).

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use common::tdx::ReportData;

const REPORTS: &str = "/sys/kernel/config/tsm/report";

#[derive(Debug, thiserror::Error)]
pub enum TsmError {
    #[error("{op} {path}: {source}")]
    Io {
        op: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error("generation went from {before} to {after}; another writer raced this report")]
    Raced { before: u64, after: u64 },
    #[error("generation file holds {0:?}, not a number")]
    BadGeneration(String),
}

/// A quote and the provider that produced it (`tdx_guest` inside a TD).
#[derive(Debug)]
pub struct Report {
    pub provider: String,
    pub quote: Vec<u8>,
}

/// Fresh REPORTDATA from the kernel's CSPRNG.
pub fn random_report_data() -> io::Result<ReportData> {
    let mut bytes = [0u8; 64];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(ReportData(bytes))
}

/// Requests a quote over `report_data`. Creates a private report entry, writes
/// `inblob`, reads `outblob`, and checks `generation` advanced by exactly that one
/// write, so the quote cannot belong to someone else's request.
pub fn quote(report_data: &ReportData) -> Result<Report, TsmError> {
    let entry = Entry::create()?;
    let before = entry.generation()?;
    entry.write("inblob", &report_data.0)?;
    let quote = entry.read("outblob")?;
    let after = entry.generation()?;
    if after != before + 1 {
        return Err(TsmError::Raced { before, after });
    }
    let provider = String::from_utf8_lossy(&entry.read("provider")?)
        .trim()
        .to_owned();
    Ok(Report { provider, quote })
}

/// A report directory under configfs, removed on drop.
struct Entry(PathBuf);

impl Entry {
    fn create() -> Result<Self, TsmError> {
        let path = Path::new(REPORTS).join(format!("clovelly-{}", std::process::id()));
        fs::create_dir(&path).map_err(io_err("mkdir", &path))?;
        Ok(Self(path))
    }

    fn read(&self, attr: &str) -> Result<Vec<u8>, TsmError> {
        let path = self.0.join(attr);
        fs::read(&path).map_err(io_err("read", &path))
    }

    fn write(&self, attr: &str, bytes: &[u8]) -> Result<(), TsmError> {
        let path = self.0.join(attr);
        fs::write(&path, bytes).map_err(io_err("write", &path))
    }

    fn generation(&self) -> Result<u64, TsmError> {
        let raw = String::from_utf8_lossy(&self.read("generation")?)
            .trim()
            .to_owned();
        raw.parse().map_err(|_| TsmError::BadGeneration(raw))
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        // Best effort: a leftover entry only costs a configfs directory until reboot.
        let _ = fs::remove_dir(&self.0);
    }
}

fn io_err(op: &'static str, path: &Path) -> impl FnOnce(io::Error) -> TsmError {
    let path = path.to_owned();
    move |source| TsmError::Io { op, path, source }
}
