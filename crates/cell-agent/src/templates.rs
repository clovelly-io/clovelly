//! The cell's template cache (SPEC.md "Templates are a shared read-only lower layer").
//!
//! A template is a gzipped tar of files layered over the base bundle. The first sandbox
//! (or the boot pre-pull) that needs a template fetches its ciphertext from Cloud
//! Storage, opens its key under the sub-environment DEK, decrypts it checking the
//! digest, unpacks it once into the tmpfs cache and mounts a read-only overlay of it
//! over the base bundle's root. Every sandbox from that template uses that one root as
//! its lower layer, with runsc's per-sandbox memory upper (`--overlay2=root:memory`),
//! so a cell full of sandboxes holds one copy of the template.
//!
//! Unpacking is the one place the cell parses customer content outside gVisor; the
//! `tar` crate refuses absolute paths, `..` and writes through symlinks outside the
//! destination.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use common::dek::Dek;
use common::ids::{EnvId, SubenvId};
use common::template::{self, Decryptor, Digest, SealedKey, TemplateError};
use serde::Deserialize;
use serde_json::json;

use crate::agent::status;
use crate::storage::{Locator, StorageError};

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("the lease has no DEK")]
    NoKey,
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("template {0} is not stored for this sub-environment")]
    Missing(Digest),
    #[error("template {0}: part {1} is missing")]
    MissingPart(Digest, u32),
    #[error("template metadata: {0}")]
    Meta(String),
    #[error(transparent)]
    Template(#[from] TemplateError),
    #[error("unpacking: {0}")]
    Io(#[from] std::io::Error),
    #[error("mounting the template's root: {0}")]
    Mount(String),
}

/// `templates/<digest>/meta.json`, written by the control plane.
#[derive(Deserialize)]
struct Meta {
    sealed_key: SealedKey,
    parts: u32,
}

/// A template in the cache.
#[derive(Debug)]
pub struct Cached {
    pub digest: Digest,
    /// The read-only root sandboxes from this template use.
    pub root: PathBuf,
    /// Its unpacked size.
    pub bytes: u64,
}

/// One template's place in the cache: empty until its fetch succeeds.
type Slot = Arc<tokio::sync::Mutex<Option<Arc<Cached>>>>;

/// The cache. One fetch per digest at a time; others asking for it wait for that one.
pub struct Templates {
    locator: Arc<Locator>,
    env: EnvId,
    subenv: SubenvId,
    dir: PathBuf,
    base: PathBuf,
    entries: Mutex<HashMap<Digest, Slot>>,
}

impl Templates {
    /// A cache under `dir` whose templates overlay the base root `base`.
    pub fn new(locator: Arc<Locator>, env: EnvId, subenv: SubenvId, dir: PathBuf, base: PathBuf) -> Self {
        Self { locator, env, subenv, dir, base, entries: Mutex::new(HashMap::new()) }
    }

    /// The template's root, fetching it first if this cell has not.
    pub async fn get(&self, digest: Digest, dek: Option<Arc<Dek>>) -> Result<Arc<Cached>, FetchError> {
        let slot = Arc::clone(self.entries.lock().unwrap_or_else(|p| p.into_inner()).entry(digest).or_default());
        let mut held = slot.lock().await;
        if let Some(c) = held.as_ref() {
            return Ok(Arc::clone(c));
        }
        let started = Instant::now();
        let dek = dek.ok_or(FetchError::NoKey)?;
        let cached = Arc::new(self.fetch(digest, &dek).await?);
        drop(dek);
        status(
            "template-ready",
            json!({ "digest": digest.hex(), "bytes": cached.bytes, "ms": started.elapsed().as_millis() as u64,
                    "copies": self.resident().len() + 1 }),
        );
        *held = Some(Arc::clone(&cached));
        Ok(cached)
    }

    /// The templates this cell holds and their unpacked sizes: one entry per template,
    /// however many sandboxes use it.
    pub fn resident(&self) -> Vec<(Digest, u64)> {
        let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries
            .iter()
            .filter_map(|(d, slot)| slot.try_lock().ok()?.as_ref().map(|c| (*d, c.bytes)))
            .collect()
    }

    async fn fetch(&self, digest: Digest, dek: &Dek) -> Result<Cached, FetchError> {
        let storage = self.locator.storage().await?;
        let prefix = format!("templates/{digest}");
        let meta = storage.get(&format!("{prefix}/meta.json")).await?.ok_or(FetchError::Missing(digest))?;
        let meta: Meta = serde_json::from_slice(&meta).map_err(|e| FetchError::Meta(e.to_string()))?;
        let key = template::open_key(dek, &self.env, &self.subenv, &digest, &meta.sealed_key)?;
        let dir = self.dir.join(digest.hex());
        // A failed earlier attempt may have left pieces.
        let _ = tokio::process::Command::new("umount").arg(dir.join("root")).output().await;
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await?;
        let archive = dir.join("template.tar.gz");
        let mut file = std::fs::File::create(&archive)?;
        let mut dec = Decryptor::new(key, digest);
        for part in 0..meta.parts {
            let found = storage
                .get_each(&format!("{prefix}/part-{part:05}"), |chunk| -> Result<(), FetchError> {
                    for plain in dec.push(chunk)? {
                        file.write_all(&plain)?;
                    }
                    Ok(())
                })
                .await??;
            if !found {
                return Err(FetchError::MissingPart(digest, part));
            }
        }
        dec.finish()?;
        file.sync_all()?;
        drop(file);
        let files = dir.join("files");
        let bytes = {
            let (archive, files) = (archive.clone(), files.clone());
            tokio::task::spawn_blocking(move || unpack(&archive, &files, true))
                .await
                .map_err(|e| FetchError::Io(std::io::Error::other(e)))??
        };
        tokio::fs::remove_file(&archive).await?;
        let root = dir.join("root");
        tokio::fs::create_dir_all(&root).await?;
        overlay(&files, &self.base, &root).await?;
        Ok(Cached { digest, root, bytes })
    }
}

/// Unpacks a gzipped tar into `into`; returns the bytes of the files written. The cell
/// (root) keeps the archive's owners; tests, run as a user, cannot.
pub fn unpack(archive: &Path, into: &Path, owners: bool) -> Result<u64, FetchError> {
    std::fs::create_dir_all(into)?;
    let gz = flate2::read::GzDecoder::new(std::io::BufReader::new(std::fs::File::open(archive)?));
    let mut tar = tar::Archive::new(gz);
    tar.set_preserve_permissions(true);
    tar.set_preserve_ownerships(owners);
    tar.set_overwrite(true);
    let mut bytes = 0u64;
    for entry in tar.entries()? {
        let mut entry = entry?;
        bytes += entry.header().size().unwrap_or(0);
        // `unpack_in` refuses paths that leave `into`, including through symlinks it
        // unpacked earlier, and skips such entries rather than writing them.
        if !entry.unpack_in(into)? {
            return Err(FetchError::Io(std::io::Error::other(format!(
                "entry {:?} would be written outside the template",
                entry.path().map(|p| p.display().to_string()).unwrap_or_default()
            ))));
        }
    }
    Ok(bytes)
}

/// Mounts a read-only overlay of `files` over `base` at `at`.
async fn overlay(files: &Path, base: &Path, at: &Path) -> Result<(), FetchError> {
    let opts = format!("ro,lowerdir={}:{}", files.display(), base.display());
    let out = tokio::process::Command::new("mount")
        .args(["-t", "overlay", "overlay", "-o", &opts])
        .arg(at)
        .output()
        .await?;
    if !out.status.success() {
        return Err(FetchError::Mount(String::from_utf8_lossy(&out.stderr).trim().to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tarball(dir: &Path, entries: impl FnOnce(&mut tar::Builder<flate2::write::GzEncoder<std::fs::File>>)) -> PathBuf {
        let path = dir.join("t.tar.gz");
        let gz = flate2::write::GzEncoder::new(std::fs::File::create(&path).unwrap(), flate2::Compression::fast());
        let mut b = tar::Builder::new(gz);
        entries(&mut b);
        b.into_inner().unwrap().finish().unwrap();
        path
    }

    fn file(b: &mut tar::Builder<flate2::write::GzEncoder<std::fs::File>>, path: &str, data: &[u8]) {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_uid(0);
        h.set_gid(0);
        h.set_mtime(0);
        h.set_entry_type(tar::EntryType::Regular);
        // `append_data` would normalise the path; write it raw to test what we refuse.
        h.as_gnu_mut().unwrap().name[..path.len()].copy_from_slice(path.as_bytes());
        h.set_cksum();
        b.append(&h, data).unwrap();
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("clovelly-templates-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_template_unpacks_its_files() {
        let d = scratch("ok");
        let t = tarball(&d, |b| {
            file(b, "srv/app.py", b"print(1)\n");
            file(b, "data/blob", &[7u8; 5000]);
        });
        assert_eq!(unpack(&t, &d.join("files"), false).unwrap(), 5009);
        assert_eq!(std::fs::read(d.join("files/srv/app.py")).unwrap(), b"print(1)\n");
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// The cell refuses a template that would write outside its directory, through
    /// `..` or through a symlink it unpacked first.
    #[test]
    fn a_template_cannot_write_outside_its_directory() {
        let d = scratch("escape");
        let t = tarball(&d, |b| file(b, "../escaped", b"x"));
        assert!(unpack(&t, &d.join("files"), false).is_err());
        assert!(!d.join("escaped").exists());

        let outside = scratch("outside");
        let t = tarball(&d, |b| {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_size(0);
            h.set_mode(0o777);
            h.set_uid(0);
            h.set_gid(0);
            h.set_mtime(0);
            b.append_link(&mut h, "link", &outside).unwrap();
            file(b, "link/planted", b"x");
        });
        let _ = unpack(&t, &d.join("files2"), false);
        assert!(!outside.join("planted").exists(), "nothing was written through the symlink");
        std::fs::remove_dir_all(&d).unwrap();
        std::fs::remove_dir_all(&outside).unwrap();
    }
}
