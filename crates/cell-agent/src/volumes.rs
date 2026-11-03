//! Persistent volumes (SPEC.md "Volumes: one mounter at a time, committed in blocks").
//!
//! Mounting a volume for a sandbox takes its single-mounter lease from the control
//! plane, opens (or, the first time, creates and seals) its 512-bit key under the
//! sub-environment DEK, rebuilds its dm-crypt image on tmpfs from the blocks its
//! authenticated manifest names (each checked against its SHA-256), and maps it:
//! loop device, `cryptsetup --type plain` (AES-XTS with the raw key), ext2, mounted on
//! the host and bound into the sandbox at `/volume`. The image is ciphertext, so its
//! 64 MiB blocks go to Cloud Storage as they are.
//!
//! [`Volumes::commit`] runs every [`COMMIT_EVERY`] and at close: it freezes the
//! filesystem (so the image is consistent), hashes every block, copies the changed
//! ones, thaws, uploads them under the next epoch and then writes the manifest naming
//! that epoch. A hard stop therefore loses at most the writes since the last manifest.
//! The volume key lives in the agent only while the volume is mounted and is wiped
//! when the sandbox ends; the kernel's copy goes with the dm-crypt mapping.

use std::collections::HashMap;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aws_lc_rs::digest;
use common::dek::Dek;
use common::ids::{EnvId, SandboxId, SubenvId};
use common::proto::control::cell_channel_client::CellChannelClient;
use common::proto::control::{AcquireVolumeRequest, ReleaseVolumeRequest};
use common::volume::{self, BLOCK, BlockRef, Manifest, VolumeError as CryptoError, VolumeGib, VolumeKey, VolumeName};
use serde_json::json;
use tokio::io::AsyncWriteExt;
use tonic::transport::Channel;

use crate::agent::status;
use crate::storage::{Locator, StorageError};

/// How often mounted volumes commit. A hard stop loses at most the writes since the
/// last manifest: this interval plus one commit's upload, kept under 60 s (DECISIONS).
pub const COMMIT_EVERY: Duration = Duration::from_secs(50);
/// Where volumes appear inside sandboxes.
pub const MOUNT_POINT: &str = "/volume";
/// Changed blocks are copied out while the filesystem is frozen up to this many bytes;
/// beyond it the rest upload while it stays frozen.
const COPY_BUDGET: u64 = 1 << 30;

#[derive(Debug, thiserror::Error)]
pub enum VolumeError {
    #[error("volume {0} is mounted by another sandbox")]
    Busy(VolumeName),
    #[error("volume {name} is unreadable here: {why}")]
    Unreadable { name: VolumeName, why: String },
    #[error("the lease has no DEK")]
    NoKey,
    #[error("this cell has no control plane to lease volumes from")]
    NoControlPlane,
    #[error("volume lease: {0}")]
    Lease(String),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("{cmd}: {why}")]
    Command { cmd: String, why: String },
    #[error("volume image: {0}")]
    Io(#[from] std::io::Error),
}

/// A volume mounted for one sandbox.
pub struct Mounted {
    pub name: VolumeName,
    pub sandbox: SandboxId,
    gib: VolumeGib,
    key: VolumeKey,
    image: PathBuf,
    loop_dev: String,
    mapper: String,
    /// Where it is mounted on the host; bound into the sandbox at [`MOUNT_POINT`].
    pub mnt: PathBuf,
    epoch: AtomicU64,
    /// Each block's committed version (absent: never written, all zeros).
    committed: Mutex<HashMap<u32, BlockRef>>,
    /// One commit at a time; close waits for a running one.
    commit: tokio::sync::Mutex<()>,
}

impl Mounted {
    /// The last committed epoch: what the sandbox's receipt names.
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Relaxed)
    }
}

/// The cell's volumes.
pub struct Volumes {
    locator: Arc<Locator>,
    client: Option<CellChannelClient<Channel>>,
    instance_id: u64,
    zone: String,
    env: EnvId,
    subenv: SubenvId,
    dir: PathBuf,
    mounted: Mutex<Vec<Arc<Mounted>>>,
    /// `losetup -f` then attach is two steps; one mount sets up at a time.
    setup: tokio::sync::Mutex<()>,
}

async fn run(cmd: &str, args: &[&str]) -> Result<String, VolumeError> {
    let out = tokio::process::Command::new(cmd).args(args).stdin(Stdio::null()).output().await?;
    if !out.status.success() {
        return Err(VolumeError::Command {
            cmd: format!("{cmd} {}", args.join(" ")),
            why: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// Maps `dev` through dm-crypt with the raw key, written to cryptsetup's stdin so it is
/// never in an argument or a file.
async fn open_mapping(program: &str, dev: &str, name: &str, key: &VolumeKey) -> Result<(), VolumeError> {
    let mut child = tokio::process::Command::new(program)
        .args(["open", "--type", "plain", "--hash", "plain", "--cipher", "aes-xts-plain64", "--key-size", "512"])
        .args(["--key-file", "-", "--keyfile-size", "64", dev, name])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().expect("stdin is piped");
    stdin.write_all(key.as_bytes()).await?;
    drop(stdin);
    let out = child.wait_with_output().await?;
    if !out.status.success() {
        return Err(VolumeError::Command { cmd: format!("{program} open {dev}"), why: String::from_utf8_lossy(&out.stderr).trim().to_owned() });
    }
    Ok(())
}

fn sha256(data: &[u8]) -> String {
    common::hex(digest::digest(&digest::SHA256, data).as_ref())
}

/// The hash of a block that was never written.
fn zero_block_hash() -> &'static str {
    static H: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    H.get_or_init(|| sha256(&vec![0u8; BLOCK as usize]))
}

impl Volumes {
    pub fn new(locator: Arc<Locator>, env: EnvId, subenv: SubenvId, dir: PathBuf) -> Self {
        let (client, instance_id, zone) = (locator.client.clone(), locator.instance_id, locator.zone.clone());
        Self { locator, client, instance_id, zone, env, subenv, dir, mounted: Mutex::new(Vec::new()), setup: tokio::sync::Mutex::new(()) }
    }

    fn unreadable(name: &VolumeName, why: impl Into<String>) -> VolumeError {
        VolumeError::Unreadable { name: name.clone(), why: why.into() }
    }

    async fn lease(&self, name: &VolumeName, sandbox: &SandboxId, acquire: bool) -> Result<(), VolumeError> {
        let mut client = self.client.clone().ok_or(VolumeError::NoControlPlane)?;
        let r = if acquire {
            client
                .acquire_volume(AcquireVolumeRequest {
                    instance_id: self.instance_id,
                    zone: self.zone.clone(),
                    volume: name.to_string(),
                    sandbox_id: sandbox.to_string(),
                })
                .await
                .map(|_| ())
        } else {
            client
                .release_volume(ReleaseVolumeRequest {
                    instance_id: self.instance_id,
                    zone: self.zone.clone(),
                    volume: name.to_string(),
                    sandbox_id: sandbox.to_string(),
                })
                .await
                .map(|_| ())
        };
        r.map_err(|s| {
            let busy = s.metadata().get("clovelly-error").and_then(|v| v.to_str().ok()) == Some("VOLUME_BUSY");
            if busy { VolumeError::Busy(name.clone()) } else { VolumeError::Lease(format!("{:?}: {}", s.code(), s.message())) }
        })
    }

    /// Leases, opens and mounts `name` for `sandbox` (creating it with `gib` the first
    /// time). On failure everything taken so far is given back.
    pub async fn mount(&self, name: VolumeName, gib: VolumeGib, sandbox: SandboxId, dek: Option<Arc<Dek>>) -> Result<Arc<Mounted>, VolumeError> {
        let dek = dek.ok_or(VolumeError::NoKey)?;
        self.lease(&name, &sandbox, true).await?;
        let r = self.mount_leased(&name, gib, sandbox, &dek).await;
        drop(dek);
        match r {
            Ok(m) => {
                self.mounted.lock().unwrap_or_else(|p| p.into_inner()).push(Arc::clone(&m));
                Ok(m)
            }
            Err(e) => {
                let _ = self.lease(&name, &sandbox, false).await;
                Err(e)
            }
        }
    }

    async fn mount_leased(&self, name: &VolumeName, gib: VolumeGib, sandbox: SandboxId, dek: &Dek) -> Result<Arc<Mounted>, VolumeError> {
        let started = Instant::now();
        let storage = self.locator.storage().await?;
        let prefix = format!("volumes/{name}");
        let (key, gib, fresh) = match storage.get(&format!("{prefix}/key.json")).await? {
            Some(bytes) => {
                let sealed = volume::SealedKey::from_json(&bytes)?;
                let key = volume::open_key(dek, &self.env, &self.subenv, name, &sealed).map_err(|e| Self::unreadable(name, e.to_string()))?;
                (key, sealed.gib, false)
            }
            None => {
                let key = VolumeKey::generate()?;
                let sealed = volume::seal_key(dek, &self.env, &self.subenv, name, gib, &key)?;
                if !storage.put(&format!("{prefix}/key.json"), sealed.to_json(), true).await? {
                    return Err(VolumeError::Lease(format!("volume {name} was created by another sandbox meanwhile")));
                }
                (key, gib, true)
            }
        };
        let manifest = match storage.get(&format!("{prefix}/manifest.json")).await? {
            Some(bytes) => Some(Manifest::open(&bytes, &key, name).map_err(|e| Self::unreadable(name, e.to_string()))?),
            None => None,
        };
        // A key with no manifest is a volume whose creator stopped before its first
        // commit: nothing was kept, so it starts empty.
        let fresh = fresh || manifest.is_none();
        let dir = self.dir.join(sandbox.as_str());
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(dir.join("mnt")).await?;
        let image = dir.join("image");
        std::fs::File::create(&image)?.set_len(gib.bytes())?;
        let mut committed = HashMap::new();
        for b in manifest.iter().flat_map(|m| &m.blocks) {
            let data = storage
                .get(&format!("{prefix}/{}", volume::block_object(b.index, b.epoch)))
                .await?
                .ok_or_else(|| Self::unreadable(name, format!("block {} of epoch {} is missing", b.index, b.epoch)))?;
            if sha256(&data) != b.sha256 || data.len() as u64 != BLOCK {
                return Err(Self::unreadable(name, format!("block {} does not match its manifest", b.index)));
            }
            std::fs::OpenOptions::new().write(true).open(&image)?.write_all_at(&data, u64::from(b.index) * BLOCK)?;
            committed.insert(b.index, b.clone());
        }
        let epoch = manifest.as_ref().map_or(0, |m| m.epoch);
        let mapper = format!("clovelly-vol-{sandbox}");
        let image_s = image.to_string_lossy().into_owned();
        let loop_dev = {
            let _one = self.setup.lock().await;
            let dev = run("losetup", &["-f"]).await?;
            run("losetup", &[&dev, &image_s]).await?;
            dev
        };
        let m = Mounted {
            name: name.clone(),
            sandbox,
            gib,
            key,
            image,
            loop_dev,
            mapper,
            mnt: dir.join("mnt"),
            epoch: AtomicU64::new(epoch),
            committed: Mutex::new(committed),
            commit: tokio::sync::Mutex::new(()),
        };
        if let Err(e) = self.map(&m, fresh).await {
            teardown(&m).await;
            return Err(e);
        }
        // A new filesystem is committed at once, so the volume mounts whenever its cell
        // is lost.
        if fresh && let Err(e) = self.commit(&m, true).await {
            teardown(&m).await;
            return Err(e);
        }
        status(
            "volume-mounted",
            json!({ "volume": name.as_str(), "sandbox": sandbox.as_str(), "gib": gib.get(), "epoch": epoch, "fresh": fresh,
                    "ms": started.elapsed().as_millis() as u64 }),
        );
        Ok(Arc::new(m))
    }

    async fn map(&self, m: &Mounted, fresh: bool) -> Result<(), VolumeError> {
        open_mapping("cryptsetup", &m.loop_dev, &m.mapper, &m.key).await?;
        let dev = format!("/dev/mapper/{}", m.mapper);
        if fresh {
            run("mke2fs", &["-F", &dev]).await?;
        }
        run("mount", &["-t", "ext4", &dev, &m.mnt.to_string_lossy()]).await.map_err(|e| match e {
            VolumeError::Command { why, .. } => Self::unreadable(&m.name, format!("the image does not mount: {why}")),
            other => other,
        })?;
        Ok(())
    }

    /// Commits `m`'s changed blocks under the next epoch; returns the epoch now
    /// committed. `mounted` freezes the filesystem around the snapshot; at close it is
    /// already unmounted.
    pub async fn commit(&self, m: &Mounted, mounted: bool) -> Result<u64, VolumeError> {
        let _one = m.commit.lock().await;
        let started = Instant::now();
        let storage = self.locator.storage().await?;
        let mnt = m.mnt.to_string_lossy().into_owned();
        if mounted {
            run("fsfreeze", &["--freeze", &mnt]).await?;
        }
        let snapshot = {
            let (image, blocks) = (m.image.clone(), m.gib.blocks());
            let committed: HashMap<u32, String> =
                m.committed.lock().unwrap_or_else(|p| p.into_inner()).iter().map(|(i, b)| (*i, b.sha256.clone())).collect();
            tokio::task::spawn_blocking(move || changed_blocks(&image, blocks, &committed)).await.map_err(std::io::Error::other)
        };
        let mut frozen = mounted;
        let thaw = |frozen: &mut bool| {
            let was = std::mem::replace(frozen, false);
            let mnt = mnt.clone();
            async move {
                if was {
                    let _ = run("fsfreeze", &["--unfreeze", &mnt]).await;
                }
            }
        };
        let changed = match snapshot {
            Ok(Ok(c)) => c,
            Ok(Err(e)) | Err(e) => {
                thaw(&mut frozen).await;
                return Err(e.into());
            }
        };
        // Copied blocks need the filesystem no longer; the rest are read frozen.
        if changed.iter().all(|c| c.data.is_some()) {
            thaw(&mut frozen).await;
        }
        let epoch = m.epoch() + 1;
        let prefix = format!("volumes/{}", m.name);
        let mut refs = Vec::with_capacity(changed.len());
        let uploaded = async {
            for c in changed {
                let data = match c.data {
                    Some(d) => d,
                    None => read_block(&m.image, c.index)?,
                };
                storage.put(&format!("{prefix}/{}", volume::block_object(c.index, epoch)), data, false).await?;
                refs.push(BlockRef { index: c.index, epoch, sha256: c.sha256 });
            }
            Ok::<(), VolumeError>(())
        }
        .await;
        thaw(&mut frozen).await;
        uploaded?;
        let uploaded = refs.len();
        if uploaded == 0 {
            return Ok(m.epoch());
        }
        let (manifest, superseded) = {
            let mut committed = m.committed.lock().unwrap_or_else(|p| p.into_inner());
            let superseded: Vec<BlockRef> = refs.iter().filter_map(|r| committed.insert(r.index, r.clone())).collect();
            let mut blocks: Vec<BlockRef> = committed.values().cloned().collect();
            blocks.sort_by_key(|b| b.index);
            (Manifest { v: 1, volume: m.name.to_string(), gib: m.gib, epoch, blocks }, superseded)
        };
        storage.put(&format!("{prefix}/manifest.json"), manifest.seal(&m.key), false).await?;
        m.epoch.store(epoch, Ordering::Relaxed);
        for old in superseded {
            let _ = storage.delete(&format!("{prefix}/{}", volume::block_object(old.index, old.epoch))).await;
        }
        status(
            "volume-committed",
            json!({ "volume": m.name.as_str(), "sandbox": m.sandbox.as_str(), "epoch": epoch, "blocks": uploaded,
                    "ms": started.elapsed().as_millis() as u64 }),
        );
        Ok(epoch)
    }

    /// Commits every mounted volume; returns whether any epoch moved.
    pub async fn commit_all(&self) -> bool {
        let all: Vec<Arc<Mounted>> = self.mounted.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let mut moved = false;
        for m in all {
            let before = m.epoch();
            match self.commit(&m, true).await {
                Ok(e) => moved |= e != before,
                Err(e) => status("volume-commit-failed", json!({ "volume": m.name.as_str(), "error": e.to_string() })),
            }
        }
        moved
    }

    /// Unmounts `m` after its sandbox ended, commits it a last time, removes the
    /// mapping and releases the lease. The volume key is wiped when the last reference
    /// to `m` goes (the sandbox's record keeps only the epoch). Returns the final epoch.
    pub async fn close(&self, m: Arc<Mounted>) -> u64 {
        self.mounted.lock().unwrap_or_else(|p| p.into_inner()).retain(|x| !Arc::ptr_eq(x, &m));
        let unmounted = run("umount", &[&m.mnt.to_string_lossy()]).await;
        let epoch = match unmounted {
            Ok(_) => self.commit(&m, false).await,
            Err(e) => Err(e),
        };
        let epoch = match epoch {
            Ok(e) => e,
            Err(e) => {
                status("volume-close-failed", json!({ "volume": m.name.as_str(), "error": e.to_string() }));
                m.epoch()
            }
        };
        teardown(&m).await;
        if let Err(e) = self.lease(&m.name, &m.sandbox, false).await {
            status("volume-release-failed", json!({ "volume": m.name.as_str(), "error": e.to_string() }));
        }
        epoch
    }
}

/// Removes the mapping, loop device and image (best effort).
async fn teardown(m: &Mounted) {
    let _ = run("umount", &[&m.mnt.to_string_lossy()]).await;
    let _ = run("cryptsetup", &["close", &m.mapper]).await;
    let _ = run("losetup", &["-d", &m.loop_dev]).await;
    if let Some(dir) = m.image.parent() {
        let _ = tokio::fs::remove_dir_all(dir).await;
    }
}

/// A block whose content differs from its committed version.
struct Changed {
    index: u32,
    sha256: String,
    /// Its bytes, copied while the filesystem was frozen (within the copy budget).
    data: Option<Vec<u8>>,
}

fn read_block(image: &Path, index: u32) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; BLOCK as usize];
    std::fs::File::open(image)?.read_exact_at(&mut buf, u64::from(index) * BLOCK)?;
    Ok(buf)
}

/// Every block of the image whose hash is not its committed one (or, never committed,
/// that is not all zeros).
fn changed_blocks(image: &Path, blocks: u32, committed: &HashMap<u32, String>) -> std::io::Result<Vec<Changed>> {
    let mut out = Vec::new();
    let mut copied = 0u64;
    for index in 0..blocks {
        let data = read_block(image, index)?;
        let hash = sha256(&data);
        let before = committed.get(&index).map_or(zero_block_hash(), String::as_str);
        if hash == before {
            continue;
        }
        let keep = copied + BLOCK <= COPY_BUDGET;
        copied += if keep { BLOCK } else { 0 };
        out.push(Changed { index, sha256: hash, data: keep.then_some(data) });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard;

    /// Criterion 12: a volume's key is zeroised when its sandbox ends. Under the guard
    /// allocator, the key is created, sealed under the DEK, opened again as a mount
    /// would, handed to the mapping command (a script standing in for cryptsetup),
    /// used for the manifest's MAC and dropped, and no freed block still holds it.
    #[tokio::test]
    async fn volume_keys_are_zeroised_at_sandbox_end_under_the_guard_allocator() {
        let (env, sub): (EnvId, SubenvId) = ("staging".parse().unwrap(), "a".parse().unwrap());
        let name: VolumeName = "data".parse().unwrap();
        let gib = VolumeGib::try_from(1).unwrap();
        let dek = Dek::from_bytes([6; 32]);
        let key = VolumeKey::generate().unwrap();
        let halves: [[u8; 32]; 2] = [key.as_bytes()[..32].try_into().unwrap(), key.as_bytes()[32..].try_into().unwrap()];
        let watches = [guard::watch(&halves[0]), guard::watch(&halves[1])];
        let sealed = volume::seal_key(&dek, &env, &sub, &name, gib, &key).unwrap();
        drop(key);
        let opened = volume::open_key(&dek, &env, &sub, &name, &volume::SealedKey::from_json(&sealed.to_json()).unwrap()).unwrap();
        assert_eq!(&opened.as_bytes()[..32], &halves[0]);
        // A stand-in for cryptsetup that reads the key from stdin and drops it.
        let script = std::env::temp_dir().join(format!("clovelly-fake-cryptsetup-{}", std::process::id()));
        std::fs::write(&script, "#!/bin/sh\ncat > /dev/null\n").unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        open_mapping(&script.to_string_lossy(), "/dev/null", "-", &opened).await.unwrap();
        std::fs::remove_file(&script).unwrap();
        let manifest = Manifest { v: 1, volume: name.to_string(), gib, epoch: 1, blocks: Vec::new() };
        let stored = manifest.seal(&opened);
        assert_eq!(Manifest::open(&stored, &opened, &name).unwrap(), manifest);
        drop(opened);
        for w in &watches {
            assert_eq!(w.leaks(), 0, "no freed block held the volume key");
        }
    }

    /// Criterion 12: the sub-environment DEK is zeroised at cell end. Under the guard
    /// allocator, a lease's DEK is shared with every phase 4 use of it (a template key
    /// sealed and opened, a template decrypted, a volume key sealed and opened, a
    /// credential sealed and opened) and then let go, as the agent's terms do when the
    /// cell ends; no freed block still holds it.
    #[test]
    fn the_dek_is_zeroised_at_cell_end_after_templates_and_volumes_under_the_guard_allocator() {
        use common::cred::{self, AdapterType, Binding};
        use common::template::{self, Decryptor, Digest};
        let mut raw = [0u8; 32];
        aws_lc_rs::rand::fill(&mut raw).unwrap();
        let w = guard::watch(&raw);
        let dek = Arc::new(Dek::from_bytes(raw));
        common::dek::wipe(&mut raw);
        let (env, sub): (EnvId, SubenvId) = ("staging".parse().unwrap(), "a".parse().unwrap());

        let plain = vec![3u8; 3 * template::CHUNK / 2];
        let digest = Digest::of(&plain);
        let (key, sealed) = template::seal_key(&dek, &env, &sub, &digest).unwrap();
        let ct = template::encrypt(&key, &digest, &plain);
        drop(key);
        let held = Arc::clone(&dek);
        let mut d = Decryptor::new(template::open_key(&held, &env, &sub, &digest, &sealed).unwrap(), digest);
        assert_eq!(d.push(&ct).unwrap().concat(), plain);
        d.finish().unwrap();
        drop(held);

        let name: VolumeName = "data".parse().unwrap();
        let gib = VolumeGib::try_from(1).unwrap();
        let vkey = VolumeKey::generate().unwrap();
        let vsealed = volume::seal_key(&dek, &env, &sub, &name, gib, &vkey).unwrap();
        assert!(volume::open_key(&dek, &env, &sub, &name, &vsealed).is_ok());

        let b = Binding { name: "svc".parse().unwrap(), adapter: AdapterType::Bearer, destination: "api.example.com".parse().unwrap() };
        let c = cred::seal(&dek, &env, &sub, &b, b"secret").unwrap();
        assert!(cred::open(&dek, &env, &sub, &c).is_ok());

        assert!(w.leaks() == 0, "no copy freed while the lease held it");
        drop(dek);
        assert_eq!(w.leaks(), 0, "no freed block held the DEK");
    }

    #[test]
    fn only_blocks_that_changed_are_committed() {
        let dir = std::env::temp_dir().join(format!("clovelly-vol-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let image = dir.join("image");
        let f = std::fs::File::create(&image).unwrap();
        f.set_len(3 * BLOCK).unwrap();
        f.write_all_at(b"hello", BLOCK + 10).unwrap();
        let first = changed_blocks(&image, 3, &HashMap::new()).unwrap();
        assert_eq!(first.iter().map(|c| c.index).collect::<Vec<_>>(), vec![1], "zero blocks are not stored");
        let committed = HashMap::from([(1, first[0].sha256.clone())]);
        assert!(changed_blocks(&image, 3, &committed).unwrap().is_empty());
        f.write_all_at(b"x", 2 * BLOCK).unwrap();
        let next = changed_blocks(&image, 3, &committed).unwrap();
        assert_eq!(next.iter().map(|c| c.index).collect::<Vec<_>>(), vec![2]);
        assert!(next[0].data.as_ref().is_some_and(|d| d[0] == b'x'));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
