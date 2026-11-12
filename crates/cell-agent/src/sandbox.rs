//! The sandboxes on this cell (SPEC.md "Sandbox lifecycle").
//!
//! [`Sandboxes::create`] admits a sandbox only if the cell is serving, the size and
//! timeout are within the policy's maximum, the placement window holds
//! ([`check_window`]), the size fits the cell's physical placeable size, and the cell's
//! unreserved capacity holds it (the placeable size with the CPU multiplied by the cell's
//! sharing factor, [`CpuShare::capacity`]); then it gives
//! the sandbox a network namespace whose only way out is the egress proxy
//! ([`crate::net`]), registers it with the proxy under the policy bundle in force and
//! its released credentials, writes an OCI bundle with the sandbox's cgroup limits, its
//! resolver and the in-cell CA in its trust store, and starts it under runsc. A watcher
//! task per sandbox ends it on the first of: its main process exiting (`exited`), its
//! timeout (`timeout`) or a kill (`killed`, `revoked`, `cell_end`); it then removes the
//! sandbox from the proxy (ending its connections and wiping its credentials) and its
//! namespace. An ended sandbox leaves a record for [`Sandboxes::receipt`].
//!
//! A sandbox from a template runs on the template's cached root as its read-only lower
//! layer ([`crate::templates`]); one with a volume gets it mounted at `/volume` and
//! committed in blocks ([`crate::volumes`]). Every sandbox has a P-256 identity key of
//! its own, named in its receipts and dropped (wiped) when it ends. Receipts are signed
//! by the cell key ([`crate::receipts`]): while a sandbox runs the log gets a last-will
//! record for it every few seconds, and its final record when it ends.
//!
//! Every call on an existing sandbox presents its access key; only the key's SHA-256 is
//! kept, and the control plane, which knows sandbox ids, never sees keys.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use aws_lc_rs::{constant_time, digest};
use common::bundle::Policy;
use common::dek::Dek;
use common::proto::verifier::LogRecord;
use common::template::Digest;
use common::volume::{VolumeGib, VolumeName};
use common::ids::{EnvId, IdError, ReleaseId, SandboxId, SubenvId, Zone};
use common::proto::cell::{ErrorReason, ExitKind};
use common::sandbox::{AboveMaximum, CpuShare, Crossing, Size, check_window};
use egress_proxy::{LogSnapshot, Supervisor, SupervisorError};
use serde_json::{Value, json};
use tokio::sync::{oneshot, watch};

use crate::agent::status;
use crate::cgroup;
use crate::credentials::{CredentialError, Released};
use crate::net::{self, NetError, Slot, Slots};
use crate::receipts::{Log, Signer, SignerError};
use crate::runsc::{Bind, Bundle, Network, Resources, Runsc, RunscError, Spec, Waiting};
use crate::templates::{Cached, FetchError};
use crate::volumes::{self, Mounted, VolumeError, Volumes};

pub use common::receipt::rfc3339;

/// How many ended sandboxes keep a record for GetReceipt.
const KEEP_ENDED: usize = 50_000;
/// How many of the most recently ended sandboxes keep their egress log's lines (the
/// rest keep its hash and count).
const KEEP_LOGS: usize = 1_000;
/// Where a sandbox's trust store is mounted, and the variables that point clients at
/// it.
const TRUST_STORE: &str = "/etc/ssl/certs/ca-certificates.crt";
const TRUST_ENV: [&str; 5] = ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO"];
/// Every sandbox's init: it idles for the sandbox's life (its main command, if any, is
/// an exec; see [`Running`]).
const IDLE: [&str; 2] = ["/bin/sleep", "2147483647"];
/// What a networked sandbox's main process runs under: it turns the sandbox netstack's
/// RACK-TLP loss detection off (`tcp_recovery=0`), then becomes the main process. Every
/// connection from a sandbox ends at the proxy in the same cell, where RACK-TLP's
/// timers fired in a busy cell and resent data the proxy already had (phase 3
/// criterion 8); runsc has no flag for it and does not apply the OCI sysctl.
const RACK_OFF: [&str; 4] = ["/bin/sh", "-c", "echo 0 > /proc/sys/net/ipv4/tcp_recovery; exec \"$@\"", "sh"];

/// Why a call on the cell API was refused. Each maps to one `clovelly-error` reason.
#[derive(Debug, thiserror::Error)]
pub enum CellError {
    #[error(transparent)]
    InvalidId(#[from] IdError),
    #[error("invalid request: {0}")]
    Invalid(String),
    #[error("no sandbox {0} on this cell")]
    NoSuchSandbox(SandboxId),
    #[error("wrong access key for sandbox {0}")]
    Permission(SandboxId),
    #[error("a sandbox {0} already exists on this cell")]
    Exists(SandboxId),
    /// `free` is the most one sandbox could have now: the cell's unreserved capacity, and
    /// never more than its physical placeable size. The message names the resource that
    /// binds (SPEC.md phase 13: CPU, memory or both).
    #[error("{}", short_of(*.need, *.free))]
    Capacity { need: Size, free: Size },
    #[error(transparent)]
    AboveMaximum(#[from] AboveMaximum),
    #[error(transparent)]
    Crossing(#[from] Crossing),
    #[error("the cell is draining or recycling")]
    Draining,
    #[error("the cell's key lease has ended")]
    Revoked,
    #[error("sandbox {0} has ended")]
    Ended(SandboxId),
    #[error("cannot read {0}")]
    NoSuchFile(String),
    #[error(transparent)]
    Runtime(#[from] RunscError),
    #[error("Drain needs the control plane's client certificate")]
    NotControlPlane,
    #[error("no acceptable policy bundle: {0}")]
    PolicyRefused(String),
    #[error(transparent)]
    Credentials(#[from] CredentialError),
    #[error("sandbox network: {0}")]
    Network(#[from] NetError),
    #[error("template: {0}")]
    Template(#[from] FetchError),
    #[error(transparent)]
    Volume(#[from] VolumeError),
    #[error("signing the receipt: {0}")]
    Receipt(#[from] SignerError),
    #[error("egress proxy: {0}")]
    Proxy(#[from] SupervisorError),
    #[error("no placement for this create: {0}")]
    PlacementRefused(String),
}

impl CellError {
    /// The `clovelly-error` reason and the gRPC code it travels with.
    pub fn reason(&self) -> (ErrorReason, tonic::Code) {
        use tonic::Code;
        match self {
            CellError::InvalidId(_) => (ErrorReason::InvalidSandboxId, Code::InvalidArgument),
            CellError::Invalid(_) => (ErrorReason::InvalidRequest, Code::InvalidArgument),
            CellError::NoSuchSandbox(_) => (ErrorReason::NoSuchSandbox, Code::NotFound),
            CellError::Permission(_) | CellError::NotControlPlane => (ErrorReason::Permission, Code::PermissionDenied),
            CellError::Exists(_) => (ErrorReason::SandboxExists, Code::AlreadyExists),
            CellError::Capacity { .. } => (ErrorReason::Capacity, Code::ResourceExhausted),
            CellError::AboveMaximum(_) => (ErrorReason::AbovePolicyMaximum, Code::InvalidArgument),
            CellError::Crossing(Crossing::CellEnd) => (ErrorReason::CrossesCellEnd, Code::FailedPrecondition),
            CellError::Crossing(Crossing::ReleaseExpiry) => {
                (ErrorReason::CrossesReleaseExpiry, Code::FailedPrecondition)
            }
            CellError::Draining => (ErrorReason::Draining, Code::Unavailable),
            CellError::Revoked => (ErrorReason::Revoked, Code::Unavailable),
            CellError::Ended(_) => (ErrorReason::SandboxEnded, Code::FailedPrecondition),
            CellError::NoSuchFile(_) => (ErrorReason::NoSuchFile, Code::NotFound),
            CellError::Runtime(_) | CellError::Network(_) | CellError::Receipt(_) | CellError::Proxy(_) => {
                (ErrorReason::Runtime, Code::Internal)
            }
            CellError::Template(_) => (ErrorReason::TemplateUnavailable, Code::Unavailable),
            CellError::Volume(VolumeError::Busy(_)) => (ErrorReason::VolumeBusy, Code::FailedPrecondition),
            CellError::Volume(VolumeError::Unreadable { .. }) => (ErrorReason::VolumeUnreadable, Code::PermissionDenied),
            CellError::Volume(_) => (ErrorReason::VolumeUnavailable, Code::Unavailable),
            CellError::PolicyRefused(_) => (ErrorReason::PolicyRefused, Code::FailedPrecondition),
            CellError::Credentials(_) => (ErrorReason::CredentialUnavailable, Code::Unavailable),
            CellError::PlacementRefused(_) => (ErrorReason::PlacementRefused, Code::PermissionDenied),
        }
    }
}

/// What a refused size is short of, resource by resource: "the cell has too little
/// unreserved memory (1 GiB asked, 0 GiB free)".
fn short_of(need: Size, free: Size) -> String {
    let mut short = Vec::new();
    if need.cpu > free.cpu {
        short.push(format!("CPU ({} vCPU asked, {} vCPU free)", need.cpu.vcpus(), free.cpu.vcpus()));
    }
    if need.memory > free.memory {
        short.push(format!("memory ({} GiB asked, {} GiB free)", need.memory.0, free.memory.0));
    }
    format!("the cell has too little unreserved {}", short.join(" and "))
}

/// A sandbox's access key: 32 bytes the SDK chose, wiped on drop.
pub struct AccessKey([u8; 32]);

impl AccessKey {
    pub fn parse(bytes: &[u8]) -> Result<Self, CellError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| CellError::Invalid(format!("access key is {} bytes, expected 32", bytes.len())))
    }

    fn hash(&self) -> [u8; 32] {
        digest::digest(&digest::SHA256, &self.0)
            .as_ref()
            .try_into()
            .expect("SHA-256 is 32 bytes")
    }
}

impl Drop for AccessKey {
    fn drop(&mut self) {
        common::dek::wipe(&mut self.0);
    }
}

/// How a sandbox ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndKind {
    /// Its main process exited with this status.
    Exited(i32),
    Killed,
    Timeout,
    Drained,
    Revoked,
    CellEnd,
}

impl EndKind {
    pub fn proto(self) -> ExitKind {
        match self {
            EndKind::Exited(_) => ExitKind::Exited,
            EndKind::Killed => ExitKind::Killed,
            EndKind::Timeout => ExitKind::Timeout,
            EndKind::Drained => ExitKind::Drained,
            EndKind::Revoked => ExitKind::Revoked,
            EndKind::CellEnd => ExitKind::CellEnd,
        }
    }

    /// The receipt's `exit.kind`.
    pub fn name(self) -> &'static str {
        match self {
            EndKind::Exited(_) => "exited",
            EndKind::Killed => "killed",
            EndKind::Timeout => "timeout",
            EndKind::Drained => "drained",
            EndKind::Revoked => "revoked",
            EndKind::CellEnd => "cell_end",
        }
    }

    fn code(self) -> Option<i32> {
        match self {
            EndKind::Exited(c) => Some(c),
            _ => None,
        }
    }
}

/// Whether the cell takes new sandboxes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Serving,
    /// Draining or recycling: running sandboxes continue, no new ones.
    Draining,
    /// The lease ended; every sandbox was ended with `revoked`.
    Revoked,
    /// The cell reached its end; any sandbox left was ended with `cell_end`.
    Ended,
}

/// What the cell's terms are at the moment of a create: its end and its release's
/// validity (from the current lease).
#[derive(Debug, Clone, Copy)]
pub struct Terms {
    pub cell_end: SystemTime,
    pub valid_until: SystemTime,
}

/// How sandboxes reach the world: the egress proxy and the namespaces that route to it.
pub struct Egress {
    /// The egress proxy, its own process.
    pub proxy: Arc<Supervisor>,
    pub slots: Arc<Slots>,
    /// The trust store every sandbox gets: the public roots and the in-cell CA (PEM).
    pub trust_store: PathBuf,
    pub mtu: u32,
}

/// What a sandbox was given and did, for its receipt.
#[derive(Debug, Clone)]
struct EgressRecord {
    policy_hash: String,
    creds: Vec<String>,
    log: Option<LogSnapshot>,
}

/// A started sandbox: its bundle, the `runsc wait` on its init and its main process.
///
/// The container's init only idles; a sandbox's main command runs as a `runsc exec`
/// child of the agent, which always learns its exit status. (runsc cannot report a root
/// container's status to a process that is not the sandbox's parent once the sandbox
/// has gone: in run 20261027-222952, 82 of 100 sandboxes whose command exited at once
/// were reported lost.)
struct Running {
    bundle: Bundle,
    init: Waiting,
    main: Option<tokio::process::Child>,
}

/// A started sandbox, its network slot and volume.
type Started = (Running, Option<Slot>, Option<Arc<Mounted>>);
/// Why a start failed, and the slot and volume to give back.
type Unstarted = (CellError, Option<Slot>, Option<Arc<Mounted>>);

/// When a receipt is signed and how far the sandbox has got.
#[derive(Debug, Clone, Copy)]
struct Moment {
    seq: u64,
    started: SystemTime,
    ended: Option<SystemTime>,
    stage: Stage,
    volume_epoch: Option<u64>,
}

/// What a sandbox's receipts say about it besides its egress and exit.
#[derive(Debug, Clone)]
struct Facts {
    /// Its identity key's SubjectPublicKeyInfo (base64 DER).
    identity_spki: String,
    template: Option<Digest>,
    volume: Option<VolumeName>,
}

/// How a receipt ends: still running (an interim receipt), a last will, or for good.
#[derive(Debug, Clone, Copy)]
enum Stage {
    Running,
    /// Signed now, for the log to keep if the cell is lost.
    Will,
    Ended(EndKind),
}

/// A parsed `CreateSandbox`.
pub struct CreateRequest {
    pub id: SandboxId,
    pub key: AccessKey,
    pub size: Size,
    pub timeout: Duration,
    pub command: Vec<String>,
    pub env: Vec<(String, String)>,
    /// The template whose cached root is the sandbox's lower layer; none: the base.
    pub template: Option<Arc<Cached>>,
    /// The volume to mount at `/volume`, and its size if this creates it.
    pub volume: Option<(VolumeName, VolumeGib)>,
}

/// What `CreateSandbox` answers.
#[derive(Debug, Clone, Copy)]
pub struct Created {
    pub started: SystemTime,
    pub runsc: Duration,
}

/// Who this cell is, for receipts.
#[derive(Debug, Clone)]
pub struct Identity {
    /// The sharing factor the cell runs at, fixed at its unlock: every receipt's
    /// `cpu_share`.
    pub cpu_share: CpuShare,
    pub env: EnvId,
    pub subenv: SubenvId,
    pub release: ReleaseId,
    pub instance_id: u64,
    pub zone: Zone,
    pub project: String,
}

/// A running sandbox.
pub struct Live {
    pub id: SandboxId,
    key: [u8; 32],
    pub size: Size,
    slot: Option<Slot>,
    egress: EgressRecord,
    facts: Facts,
    /// The sandbox's identity key; dropped (and wiped by aws-lc) with the sandbox.
    _identity: EcdsaKeyPair,
    volume: Mutex<Option<Arc<Mounted>>>,
    /// Receipts signed for it so far (the log keeps the highest).
    seq: std::sync::atomic::AtomicU64,
    started: SystemTime,
    created_at: tokio::time::Instant,
    deadline: tokio::time::Instant,
    first_exec: AtomicBool,
    trigger: Mutex<Option<oneshot::Sender<EndKind>>>,
    /// Set once the sandbox is ending: a kill was asked for or its main process exited.
    ending: AtomicBool,
    done: watch::Sender<Option<EndKind>>,
}

impl Live {
    /// Asks the watcher to end the sandbox; the first reason wins.
    pub fn end(&self, kind: EndKind) {
        self.ending.store(true, Ordering::Relaxed);
        if let Some(tx) = self.trigger.lock().unwrap_or_else(|p| p.into_inner()).take() {
            let _ = tx.send(kind);
        }
    }

    /// Whether the sandbox is ending or has ended.
    pub fn ending(&self) -> bool {
        self.ending.load(Ordering::Relaxed)
    }

    /// Waits until the sandbox has ended and returns how.
    pub async fn ended(&self) -> EndKind {
        let mut rx = self.done.subscribe();
        let r = rx.wait_for(Option::is_some).await;
        r.map(|k| k.expect("waited for Some")).unwrap_or(EndKind::Killed)
    }

    /// Claims this sandbox's first exec (only one caller gets `true`).
    pub fn claim_first_exec(&self) -> bool {
        !self.first_exec.swap(true, Ordering::Relaxed)
    }

    /// Time since runsc create was called.
    pub fn since_create(&self) -> Duration {
        self.created_at.elapsed()
    }
}

struct Ended {
    key: [u8; 32],
    kind: EndKind,
    started: SystemTime,
    ended: SystemTime,
    egress: EgressRecord,
    facts: Facts,
    /// The volume's last committed epoch.
    volume_epoch: Option<u64>,
    seq: u64,
    /// The final receipt, signed once at the end and appended to the log; GetReceipt and
    /// Kill return these same bytes.
    receipt: Option<crate::receipts::Signed>,
}

struct Inner {
    mode: Mode,
    used: Size,
    starting: HashSet<SandboxId>,
    live: HashMap<SandboxId, Arc<Live>>,
    ended: HashMap<SandboxId, Ended>,
    order: VecDeque<SandboxId>,
}

/// What a report says about the sandboxes.
#[derive(Debug, Clone, Copy)]
pub struct Snapshot {
    pub unreserved: Size,
    pub count: u32,
}

/// The cell's sandboxes. Shared by the cell API and the agent's lifecycle tasks.
pub struct Sandboxes {
    runsc: Runsc,
    rootfs: PathBuf,
    bundles: PathBuf,
    binds: Vec<Bind>,
    /// What sandboxes may use; the cell places this with the CPU multiplied by its sharing
    /// factor ([`Sandboxes::capacity`]).
    placeable: Size,
    identity: Identity,
    /// None: sandboxes have no network (the dev server).
    egress: Option<Egress>,
    /// None: sandboxes cannot have volumes (no control plane).
    volumes: Option<Arc<Volumes>>,
    signer: Arc<Signer>,
    log: Arc<Log>,
    inner: Mutex<Inner>,
    /// Bumped whenever a sandbox ends, for drain and revoke waiters.
    changes: watch::Sender<u64>,
}

/// Where a sandbox's files and state live, and any host files every sandbox gets
/// read-only (the throughput harness's client; cells have none).
#[derive(Debug, Clone)]
pub struct Paths {
    pub rootfs: PathBuf,
    pub bundles: PathBuf,
    pub binds: Vec<Bind>,
}

/// How receipts are signed and where they go.
pub struct Receipting {
    pub signer: Arc<Signer>,
    pub log: Arc<Log>,
}

impl Receipting {
    /// Unsigned-in-effect receipts that go nowhere: the harness and the dev server.
    pub fn local() -> Self {
        Self { signer: Arc::new(Signer::ephemeral()), log: Log::new(None) }
    }
}

impl Sandboxes {
    /// `placeable` is what the cell's sandboxes may use (the `clovelly` cgroup's limits);
    /// the cell places it with the CPU multiplied by `identity.cpu_share`.
    pub fn new(
        runsc: Runsc,
        paths: Paths,
        placeable: Size,
        identity: Identity,
        egress: Option<Egress>,
        volumes: Option<Arc<Volumes>>,
        receipting: Receipting,
    ) -> Arc<Self> {
        Arc::new(Self {
            runsc,
            rootfs: paths.rootfs,
            bundles: paths.bundles,
            binds: paths.binds,
            placeable,
            identity,
            egress,
            volumes,
            signer: receipting.signer,
            log: receipting.log,
            inner: Mutex::new(Inner {
                mode: Mode::Serving,
                used: Size::ZERO,
                starting: HashSet::new(),
                live: HashMap::new(),
                ended: HashMap::new(),
                order: VecDeque::new(),
            }),
            changes: watch::Sender::new(0),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// What the cell places: its placeable size with the CPU times its sharing factor.
    pub fn capacity(&self) -> Size {
        self.identity.cpu_share.capacity(self.placeable)
    }

    pub fn snapshot(&self) -> Snapshot {
        let inner = self.lock();
        Snapshot {
            unreserved: self.capacity() - inner.used,
            count: u32::try_from(inner.live.len() + inner.starting.len()).unwrap_or(u32::MAX),
        }
    }

    /// The proxy's open connections (telemetry).
    pub fn proxy_connections(&self) -> u32 {
        self.egress.as_ref().map_or(0, |e| e.proxy.connections())
    }

    /// Bytes the proxy has sent toward destinations since the cell unlocked (telemetry, and
    /// what egress is billed from: SPEC.md phase 10). A cell serves one sub-environment, so
    /// this is that sub-environment's count. 0 on a cell with no egress.
    pub fn egress_bytes(&self) -> u64 {
        self.egress.as_ref().map_or(0, |e| e.proxy.egress_bytes())
    }

    /// Admits and starts a sandbox under `policy` (the bundle in force now, which the
    /// sandbox keeps for its life) with the credentials released for it.
    pub async fn create(
        self: &Arc<Self>,
        req: CreateRequest,
        terms: Terms,
        policy: Arc<Policy>,
        released: Released,
        dek: Option<Arc<Dek>>,
    ) -> Result<Created, CellError> {
        let started = SystemTime::now();
        {
            let mut inner = self.lock();
            match inner.mode {
                Mode::Serving => {}
                Mode::Draining | Mode::Ended => return Err(CellError::Draining),
                Mode::Revoked => return Err(CellError::Revoked),
            }
            policy.limits.check(req.size, req.timeout)?;
            check_window(started, req.timeout, terms.cell_end, terms.valid_until)?;
            if inner.live.contains_key(&req.id) || inner.ended.contains_key(&req.id) || inner.starting.contains(&req.id)
            {
                return Err(CellError::Exists(req.id));
            }
            // One sandbox never asks for more than the cell has, whatever the factor.
            let unreserved = self.capacity() - inner.used;
            let free = Size::new(unreserved.cpu.min(self.placeable.cpu), unreserved.memory.min(self.placeable.memory));
            if !req.size.fits_in(free) {
                return Err(CellError::Capacity { need: req.size, free });
            }
            inner.used = inner.used + req.size;
            inner.starting.insert(req.id);
        }
        let created_at = tokio::time::Instant::now();
        let record = EgressRecord {
            policy_hash: policy.hash_hex(),
            creds: released.names.clone(),
            log: None,
        };
        let identity = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).expect("P-256 key generation does not fail");
        let facts = Facts {
            identity_spki: common::b64::encode(identity.public_key().as_der().expect("a P-256 public key encodes").as_ref()),
            template: req.template.as_ref().map(|t| t.digest),
            volume: req.volume.as_ref().map(|(n, _)| n.clone()),
        };
        let (bundle, slot, volume) = match self.start(&req, policy, released, dek).await {
            Ok(b) => b,
            Err((e, slot, volume)) => {
                {
                    let mut inner = self.lock();
                    inner.starting.remove(&req.id);
                    inner.used = inner.used - req.size;
                }
                // Best effort: a half-created sandbox would otherwise linger in runsc.
                let _ = self.runsc.remove(&req.id).await;
                if let Some(slot) = slot {
                    self.release_network(slot).await;
                }
                if let (Some(m), Some(vols)) = (volume, &self.volumes) {
                    vols.close(m).await;
                }
                return Err(e);
            }
        };
        let (trigger, kill) = oneshot::channel();
        let live = Arc::new(Live {
            id: req.id,
            key: req.key.hash(),
            size: req.size,
            slot,
            egress: record,
            facts,
            _identity: identity,
            volume: Mutex::new(volume),
            seq: std::sync::atomic::AtomicU64::new(0),
            started,
            created_at,
            deadline: created_at + req.timeout,
            first_exec: AtomicBool::new(false),
            trigger: Mutex::new(Some(trigger)),
            ending: AtomicBool::new(false),
            done: watch::Sender::new(None),
        });
        // The lease or the cell may have ended while runsc was starting it.
        let late = {
            let mut inner = self.lock();
            inner.starting.remove(&req.id);
            inner.live.insert(req.id, Arc::clone(&live));
            match inner.mode {
                Mode::Revoked => Some(EndKind::Revoked),
                Mode::Ended => Some(EndKind::CellEnd),
                Mode::Serving | Mode::Draining => None,
            }
        };
        if let Some(kind) = late {
            live.end(kind);
        }
        tokio::spawn(Arc::clone(self).watch(Arc::clone(&live), kill, bundle));
        Ok(Created {
            started,
            runsc: created_at.elapsed(),
        })
    }

    /// Mounts its volume, networks, registers and starts the sandbox. On failure, the
    /// slot and volume it took (if any) come back with the error for the caller to
    /// release.
    async fn start(&self, req: &CreateRequest, policy: Arc<Policy>, released: Released, dek: Option<Arc<Dek>>) -> Result<Started, Unstarted> {
        let volume = match (&req.volume, &self.volumes) {
            (None, _) => None,
            (Some((name, _)), None) => {
                return Err((VolumeError::Lease(format!("volume {name}: this cell has no control plane")).into(), None, None));
            }
            (Some((name, gib)), Some(vols)) => match vols.mount(name.clone(), *gib, req.id, dek).await {
                Ok(m) => Some(m),
                Err(e) => return Err((e.into(), None, None)),
            },
        };
        let mount = volume.as_ref().map(|m| Bind { source: m.mnt.clone(), destination: volumes::MOUNT_POINT.into(), writable: true });
        match self.start_networked(req, policy, released, mount).await {
            Ok((bundle, slot)) => Ok((bundle, slot, volume)),
            Err((e, slot)) => Err((e, slot, volume)),
        }
    }

    async fn start_networked(
        &self,
        req: &CreateRequest,
        policy: Arc<Policy>,
        released: Released,
        volume: Option<Bind>,
    ) -> Result<(Running, Option<Slot>), (CellError, Option<Slot>)> {
        let resources = Resources {
            cgroup: cgroup::sandbox_path(&req.id),
            size: req.size,
        };
        let dir = self.bundles.join(req.id.as_str());
        let (network, mut binds, env, slot) = match &self.egress {
            None => (Network::None, Vec::new(), req.env.clone(), None),
            Some(eg) => {
                let slot = eg.slots.take().map_err(|e| (e.into(), None))?;
                let fail = |e: CellError| (e, Some(slot));
                net::create(slot, eg.mtu).await.map_err(|e| fail(e.into()))?;
                eg.proxy
                    .register(slot.address(), req.id, policy, released.credentials)
                    .await
                    .map_err(|e| fail(e.into()))?;
                std::fs::create_dir_all(&dir).map_err(|e| fail(RunscError::Bundle(e).into()))?;
                let resolv = dir.join("resolv.conf");
                std::fs::write(&resolv, slot.resolv_conf()).map_err(|e| fail(RunscError::Bundle(e).into()))?;
                let binds = vec![
                    Bind { source: resolv, destination: "/etc/resolv.conf".into(), writable: false },
                    Bind { source: eg.trust_store.clone(), destination: TRUST_STORE.into(), writable: false },
                ];
                let mut env = req.env.clone();
                for name in TRUST_ENV {
                    if !env.iter().any(|(k, _)| k == name) {
                        env.push((name.to_owned(), TRUST_STORE.to_owned()));
                    }
                }
                (Network::Netns(slot.netns_path()), binds, env, Some(slot))
            }
        };
        let under_rack_off = |args: Vec<&'static str>| -> Vec<&str> {
            match network {
                Network::None => args,
                Network::Netns(_) => RACK_OFF.into_iter().chain(args).collect(),
            }
        };
        let command = under_rack_off(IDLE.to_vec());
        binds.extend(self.binds.iter().cloned());
        binds.extend(volume);
        let fail = |e: CellError| (e, slot);
        let rootfs = req.template.as_ref().map_or(self.rootfs.as_path(), |t| t.root.as_path());
        let bundle = Bundle::write(
            dir,
            &Spec {
                rootfs,
                args: &command,
                env: &env,
                network: &network,
                binds: &binds,
                resources: Some(&resources),
            },
        )
        .map_err(|e| fail(RunscError::Bundle(e).into()))?;
        let init = self
            .runsc
            .create_and_start(req.id, bundle.dir().to_path_buf(), &network)
            .await
            .map_err(|e| fail(e.into()))?;
        let main = if req.command.is_empty() {
            None
        } else {
            let mut args: Vec<String> = under_rack_off(Vec::new()).into_iter().map(str::to_owned).collect();
            args.extend(req.command.iter().cloned());
            Some(self.runsc.main_exec(&req.id, &args, &env).map_err(|e| fail(e.into()))?)
        };
        Ok((Running { bundle, init, main }, slot))
    }

    /// Removes a sandbox from the proxy (ending its connections and wiping its
    /// credentials) and deletes its namespace; returns its egress log.
    async fn release_network(&self, slot: Slot) -> Option<LogSnapshot> {
        let eg = self.egress.as_ref()?;
        let log = eg.proxy.unregister(slot.address()).await;
        net::destroy(slot).await;
        eg.slots.give_back(slot);
        log
    }

    /// Ends `live` on the first of its main process exiting, its timeout or a kill,
    /// then removes it from runsc and records how it ended.
    async fn watch(self: Arc<Self>, live: Arc<Live>, kill: oneshot::Receiver<EndKind>, running: Running) {
        let Running { bundle, init, main } = running;
        let kind = {
            let wait = init.status();
            tokio::pin!(wait);
            let exited = async {
                match main {
                    Some(mut child) => child.wait().await,
                    None => std::future::pending().await,
                }
            };
            let kind = tokio::select! {
                // The init idles for the sandbox's life; its end means runsc lost it.
                r = &mut wait => {
                    let why = r.map_or_else(|e| e.to_string(), |code| format!("init exited {code}"));
                    status("runsc-lost", json!({ "sandbox": live.id.as_str(), "error": why }));
                    EndKind::Killed
                },
                r = exited => {
                    // The main process ended; if the sandbox went with it, runsc lost it.
                    let code = r.ok().and_then(|s| {
                        use std::os::unix::process::ExitStatusExt;
                        s.code().or_else(|| s.signal().map(|sig| 128 + sig))
                    });
                    match (code, self.runsc.running(&live.id).await) {
                        (Some(code), true) => EndKind::Exited(code),
                        (code, _) => {
                            status("runsc-lost", json!({ "sandbox": live.id.as_str(), "error": format!("main process ended ({code:?}) with the sandbox") }));
                            EndKind::Killed
                        }
                    }
                },
                // During a drain a sandbox that reaches its timeout ends `drained`.
                () = tokio::time::sleep_until(live.deadline) => match self.lock().mode {
                    Mode::Draining => EndKind::Drained,
                    _ => EndKind::Timeout,
                },
                Ok(kind) = kill => kind,
            };
            live.ending.store(true, Ordering::Relaxed);
            kind
        };
        if let Err(e) = self.runsc.remove(&live.id).await {
            status("runsc-delete-failed", json!({ "sandbox": live.id.as_str(), "error": e.to_string() }));
        }
        drop(bundle);
        let mut egress = live.egress.clone();
        if let Some(slot) = live.slot {
            egress.log = self.release_network(slot).await;
        }
        let mounted = live.volume.lock().unwrap_or_else(|p| p.into_inner()).take();
        let volume_epoch = match (mounted, &self.volumes) {
            (Some(m), Some(vols)) => Some(vols.close(m).await),
            _ => None,
        };
        let ended = SystemTime::now();
        let mut record = Ended {
            key: live.key,
            kind,
            started: live.started,
            ended,
            egress,
            facts: live.facts.clone(),
            volume_epoch,
            seq: live.seq.fetch_add(1, Ordering::Relaxed) + 1,
            receipt: None,
        };
        let at = Moment { seq: record.seq, started: record.started, ended: Some(ended), stage: Stage::Ended(kind), volume_epoch };
        match self.signed(&live.id, &record.facts, &record.egress, at) {
            Ok(r) => {
                let lines = record.egress.log.as_ref().map(|l| l.lines.clone()).unwrap_or_default();
                self.log.push_final(r.clone().record(true, lines));
                record.receipt = Some(r);
            }
            Err(e) => status("receipt-unsigned", json!({ "sandbox": live.id.as_str(), "error": e.to_string() })),
        }
        {
            let mut inner = self.lock();
            inner.live.remove(&live.id);
            inner.used = inner.used - live.size;
            inner.ended.insert(live.id, record);
            inner.order.push_back(live.id);
            while inner.order.len() > KEEP_ENDED {
                if let Some(old) = inner.order.pop_front() {
                    inner.ended.remove(&old);
                }
            }
            if let Some(old) = inner.order.len().checked_sub(KEEP_LOGS + 1).and_then(|i| inner.order.get(i).copied())
                && let Some(log) = inner.ended.get_mut(&old).and_then(|e| e.egress.log.as_mut())
            {
                log.lines = Vec::new();
            }
        }
        live.done.send_replace(Some(kind));
        self.changes.send_modify(|n| *n += 1);
        status(
            "sandbox-end",
            json!({ "sandbox": live.id.as_str(), "kind": kind.name(), "code": kind.code() }),
        );
    }

    /// The running sandbox `id`, if `key` is its access key.
    pub fn authorize(&self, id: &SandboxId, key: &AccessKey) -> Result<Arc<Live>, CellError> {
        let hash = key.hash();
        let inner = self.lock();
        if let Some(live) = inner.live.get(id) {
            return match constant_time::verify_slices_are_equal(&live.key, &hash) {
                Ok(()) => Ok(Arc::clone(live)),
                Err(_) => Err(CellError::Permission(*id)),
            };
        }
        match inner.ended.get(id) {
            Some(e) if constant_time::verify_slices_are_equal(&e.key, &hash).is_ok() => Err(CellError::Ended(*id)),
            Some(_) => Err(CellError::Permission(*id)),
            None => Err(CellError::NoSuchSandbox(*id)),
        }
    }

    /// Ends the sandbox with `killed` and returns its receipt.
    pub async fn kill(&self, id: &SandboxId, key: &AccessKey) -> Result<Receipt, CellError> {
        let live = self.authorize(id, key)?;
        live.end(EndKind::Killed);
        live.ended().await;
        self.receipt(id, key)
    }

    /// The sandbox's signed receipt: interim while it runs, final once it has ended.
    pub fn receipt(&self, id: &SandboxId, key: &AccessKey) -> Result<Receipt, CellError> {
        match self.authorize(id, key) {
            Ok(live) => {
                let mut egress = live.egress.clone();
                egress.log = self.current_log(&live);
                let epoch = live.volume.lock().unwrap_or_else(|p| p.into_inner()).as_ref().map(|m| m.epoch());
                let seq = live.seq.fetch_add(1, Ordering::Relaxed) + 1;
                let at = Moment { seq, started: live.started, ended: None, stage: Stage::Running, volume_epoch: epoch };
                let r = self.signed(id, &live.facts, &egress, at)?;
                Ok(Receipt::from_signed(r, ExitKind::Running, false))
            }
            Err(CellError::Ended(_)) => {
                let inner = self.lock();
                let e = inner.ended.get(id).ok_or(CellError::NoSuchSandbox(*id))?;
                let r = match &e.receipt {
                    Some(r) => r.clone(),
                    None => {
                        let at = Moment { seq: e.seq, started: e.started, ended: Some(e.ended), stage: Stage::Ended(e.kind), volume_epoch: e.volume_epoch };
                        self.signed(id, &e.facts, &e.egress, at)?
                    }
                };
                Ok(Receipt::from_signed(r, e.kind.proto(), true))
            }
            Err(e) => Err(e),
        }
    }

    /// A running sandbox's egress log as it stands.
    fn current_log(&self, live: &Live) -> Option<LogSnapshot> {
        live.slot.and_then(|s| self.egress.as_ref()?.proxy.log(s.address()))
    }

    /// A last-will record for every running sandbox: what the log keeps if this cell
    /// stops without notice (`cell_lost`, ended now, the volume's last commit).
    pub fn wills(&self) -> Vec<LogRecord> {
        let lives: Vec<Arc<Live>> = self.lock().live.values().filter(|l| !l.ending()).cloned().collect();
        lives
            .iter()
            .filter_map(|live| {
                let mut egress = live.egress.clone();
                egress.log = self.current_log(live);
                let epoch = live.volume.lock().unwrap_or_else(|p| p.into_inner()).as_ref().map(|m| m.epoch());
                let seq = live.seq.fetch_add(1, Ordering::Relaxed) + 1;
                let now = SystemTime::now();
                let at = Moment { seq, started: live.started, ended: Some(now), stage: Stage::Will, volume_epoch: epoch };
                self.signed(&live.id, &live.facts, &egress, at)
                    .ok()
                    .map(|r| r.record(false, Vec::new()))
            })
            .collect()
    }

    /// The receipt document (SPEC.md "Receipt"), signed.
    fn signed(&self, id: &SandboxId, facts: &Facts, egress: &EgressRecord, at: Moment) -> Result<crate::receipts::Signed, SignerError> {
        let Moment { seq, started, ended, stage, volume_epoch } = at;
        let i = &self.identity;
        let (kind, code) = match stage {
            Stage::Running => ("running", None),
            Stage::Will => ("cell_lost", None),
            Stage::Ended(k) => (k.name(), k.code()),
        };
        let gaps: Vec<Value> = egress
            .log
            .as_ref()
            .map(|l| l.gaps.iter().map(|g| json!({ "from": rfc3339(g.from), "to": rfc3339(g.to) })).collect())
            .unwrap_or_default();
        let doc = json!({
            "v": 1,
            "seq": seq,
            "env": i.env.as_str(),
            "subenv": i.subenv.as_str(),
            "release": i.release.as_str(),
            "cell": { "instance": i.instance_id.to_string(), "zone": i.zone.as_str(), "project": i.project },
            "measurements": self.signer.measurements(),
            "sandbox": {
                "id": id.as_str(),
                "identity_spki": facts.identity_spki,
                "template_digest": facts.template.map(|d| d.hex()),
                "volume_id": facts.volume.as_ref().map(VolumeName::as_str),
                "volume_epoch": volume_epoch,
            },
            "policy_hash": egress.policy_hash,
            "cpu_share": i.cpu_share.get(),
            "creds_released": egress.creds,
            "egress_log_hash": egress.log.as_ref().map(|l| l.sha256.clone()),
            "egress_log_count": egress.log.as_ref().map_or(0, |l| l.count),
            "egress_gaps": gaps,
            "signed": rfc3339(SystemTime::now()),
            "started": rfc3339(started),
            "ended": ended.map(rfc3339),
            "exit": { "kind": kind, "code": code },
        });
        self.signer.sign(&doc)
    }

    /// Stops taking sandboxes; running ones continue. Resolves when none is left.
    pub async fn drain(&self) {
        {
            let mut inner = self.lock();
            if inner.mode == Mode::Serving {
                inner.mode = Mode::Draining;
            }
        }
        self.until_empty().await;
    }

    /// The count of running (and starting) sandboxes.
    pub fn count(&self) -> usize {
        let inner = self.lock();
        inner.live.len() + inner.starting.len()
    }

    async fn until_empty(&self) {
        let mut changes = self.changes.subscribe();
        loop {
            if self.count() == 0 {
                return;
            }
            // Starting sandboxes do not bump `changes` when they become live, so poll.
            let _ = tokio::time::timeout(Duration::from_millis(500), changes.changed()).await;
        }
    }

    /// Ends every sandbox with `kind` and takes no more: the lease ended (`Revoked`) or
    /// the cell reached its end (`CellEnd`). Resolves when all have ended.
    pub async fn end_all(&self, kind: EndKind) {
        let lives: Vec<Arc<Live>> = {
            let mut inner = self.lock();
            inner.mode = match kind {
                EndKind::Revoked => Mode::Revoked,
                _ => Mode::Ended,
            };
            inner.live.values().cloned().collect()
        };
        for live in &lives {
            live.end(kind);
        }
        self.until_empty().await;
    }
}

/// A signed receipt as the cell API returns it.
#[derive(Debug, Clone)]
pub struct Receipt {
    pub json: Vec<u8>,
    pub signature: Vec<u8>,
    pub cell_cert: Vec<u8>,
    pub kind: ExitKind,
    pub last: bool,
}

impl Receipt {
    fn from_signed(r: crate::receipts::Signed, kind: ExitKind, last: bool) -> Self {
        Self { json: r.json, signature: r.signature, cell_cert: r.cell_cert, kind, last }
    }
}

/// Where a sandbox exec writes its in-sandbox pid.
pub fn pid_file(dir: &Path, id: &SandboxId, n: u64) -> PathBuf {
    dir.join(format!("{id}-{n}.pid"))
}

impl Sandboxes {
    /// Starts `args` in the running sandbox. The caller streams its stdio.
    pub fn spawn_exec(
        &self,
        live: &Live,
        args: &[String],
        env: &[(String, String)],
        cwd: &str,
        pid_file: &Path,
    ) -> Result<tokio::process::Child, CellError> {
        Ok(self.runsc.exec(&live.id, args, env, cwd, pid_file)?)
    }

    /// Kills one exec'd process, by the pid runsc wrote for it.
    pub async fn kill_exec(&self, live: &Live, pid_file: &Path) {
        let Ok(pid) = tokio::fs::read_to_string(pid_file).await else { return };
        if let Ok(pid) = pid.trim().parse() {
            let _ = self.runsc.kill_pid(&live.id, pid).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runsc::{Cgroups, NetworkMode};
    use common::sandbox::{CpuHalves, MemoryGib};

    #[test]
    fn errors_carry_their_reasons() {
        let id = SandboxId::generate();
        assert_eq!(
            CellError::from("x".parse::<SandboxId>().unwrap_err()).reason(),
            (ErrorReason::InvalidSandboxId, tonic::Code::InvalidArgument)
        );
        assert_eq!(CellError::Crossing(Crossing::CellEnd).reason().0, ErrorReason::CrossesCellEnd);
        assert_eq!(
            CellError::Crossing(Crossing::ReleaseExpiry).reason().0,
            ErrorReason::CrossesReleaseExpiry
        );
        assert_eq!(
            CellError::Capacity { need: Size::ZERO, free: Size::ZERO }.reason(),
            (ErrorReason::Capacity, tonic::Code::ResourceExhausted)
        );
        assert_eq!(CellError::Permission(id).reason().0, ErrorReason::Permission);
    }

    fn cell(share: u32) -> Arc<Sandboxes> {
        Sandboxes::new(
            Runsc { bin: "/nonexistent/runsc".into(), state: "/nonexistent".into(), cgroups: Cgroups::Ignore, network: NetworkMode::None, extra: Vec::new() },
            Paths { rootfs: "/nonexistent".into(), bundles: "/nonexistent".into(), binds: Vec::new() },
            Size::new(CpuHalves(174), MemoryGib(342)),
            Identity {
                cpu_share: CpuShare::try_from(share).unwrap(),
                env: "staging".parse().unwrap(),
                subenv: "a".parse().unwrap(),
                release: "clovelly-test".parse().unwrap(),
                instance_id: 0,
                zone: "us-central1-a".parse().unwrap(),
                project: "0".into(),
            },
            None,
            None,
            Receipting::local(),
        )
    }

    /// Phase 13 criterion 2: a c3-standard-88's 87 vCPU places 87 x F vCPU of sandboxes and
    /// its memory as it is; no one sandbox may ask for more than the cell has.
    #[test]
    fn a_shared_cell_places_its_cpu_times_the_factor_and_no_sandbox_above_the_machine() {
        for f in 1..=4 {
            let c = cell(f);
            assert_eq!(c.snapshot().unreserved, Size::new(CpuHalves(174 * f), MemoryGib(342)));
        }
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let bundle = br#"{"v":1,"env":"staging","subenv":"a","version":1,"expires":1,"destinations":[],"cpu_share":4,
            "sandbox":{"default":{"cpu":1,"memory":1},"max":{"cpu":200,"memory":400,"timeout":3600}}}"#;
        let policy = Arc::new(Policy::parse_trusted(bundle, Size::ZERO).unwrap());
        let far = SystemTime::now() + Duration::from_secs(86_400);
        for size in [Size::new(CpuHalves(176), MemoryGib(1)), Size::new(CpuHalves(2), MemoryGib(343))] {
            let req = CreateRequest {
                id: SandboxId::generate(),
                key: AccessKey::parse(&[7; 32]).unwrap(),
                size,
                timeout: Duration::from_secs(60),
                command: vec!["true".into()],
                env: Vec::new(),
                template: None,
                volume: None,
            };
            let r = rt.block_on(cell(4).create(req, Terms { cell_end: far, valid_until: far }, Arc::clone(&policy), Released::default(), None));
            let Err(e @ CellError::Capacity { .. }) = r else { panic!("{size:?}: {:?}", r.err()) };
            let binds = if size.memory.0 > 342 { "memory" } else { "CPU" };
            assert!(e.to_string().starts_with(&format!("the cell has too little unreserved {binds}")), "{e}");
        }
        assert_eq!(
            CellError::Capacity { need: Size::new(CpuHalves(2), MemoryGib(1)), free: Size::new(CpuHalves(12), MemoryGib(0)) }.to_string(),
            "the cell has too little unreserved memory (1 GiB asked, 0 GiB free)"
        );
    }
}
