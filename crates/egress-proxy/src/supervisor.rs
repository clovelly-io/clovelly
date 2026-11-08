//! The agent's side of the egress proxy process (SPEC.md "The egress proxy is its own
//! process"): a [`Supervisor`] starts `egress-proxy`, feeds it over its stdin and stdout
//! ([`crate::ipc`]) and, whenever it dies, starts another with the same in-cell CA.
//!
//! ```ignore
//! let sup = Supervisor::start(SupervisorConfig {
//!     bin: "/clovelly/bin/egress-proxy".into(),
//!     roots_pem,
//!     cell: instance_id.to_string(),
//!     network: Network::default(),
//!     status: Box::new(|state, detail| println!("CLOVELLY-AGENT {state} {detail}")),
//! })
//! .await?;
//! std::fs::write(trust_store, sup.ca_pem())?; // the same across restarts
//! sup.register(ip, id, policy, credentials).await?; // before the sandbox starts
//! let log = sup.unregister(ip).await; // its egress log, hash and gaps
//! ```
//!
//! The agent keeps what a restart needs: the CA key, the cell's own addresses, and each
//! live sandbox's policy and credentials. A new process gets all of them before anything
//! else, and each live sandbox's log records a [`Gap`] from the moment the old process
//! died to the moment the new one held the sandbox. The log itself is kept here, not in
//! the proxy: each line is appended and hashed as it arrives, so a crash loses no line
//! that was recorded (a connection open at the crash is reset and logs nothing).
//!
//! The DEK never reaches the proxy process: no message carries it ([`crate::ipc`]).

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use common::bundle::{HostName, Policy};
use common::cred::{CredName, SecretBuf};
use common::ids::SandboxId;
use serde_json::json;
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::watch;

use crate::ipc::{self, FromProxy, IpcError, ToProxy, WireCredential};
use crate::{CaKey, Credential, EgressLog, Gap, LogSnapshot, Ports, TlsError};

/// How long a new process may take to answer Hello.
const READY_WITHIN: Duration = Duration::from_secs(10);
/// How long a registration may wait for a process to hold the sandbox.
const REGISTER_WITHIN: Duration = Duration::from_secs(10);
/// How long an unregistration waits for the sandbox's connections to end.
const UNREGISTER_WITHIN: Duration = Duration::from_secs(5);
/// A process that dies sooner than this after it started is replaced after a pause
/// that doubles each time, from [`FIRST_PAUSE`] to [`MAX_PAUSE`], so one that cannot
/// run does not spin; otherwise it is replaced at once.
const STEADY: Duration = Duration::from_secs(1);
const FIRST_PAUSE: Duration = Duration::from_millis(100);
const MAX_PAUSE: Duration = Duration::from_secs(5);

/// Reports the proxy's state changes: `proxy-exited`, `proxy-restarted` and
/// `proxy-start-failed`, each with a JSON detail.
pub type StatusFn = Box<dyn Fn(&str, serde_json::Value) + Send + Sync>;

/// What a [`Supervisor`] is started with.
pub struct SupervisorConfig {
    /// The `egress-proxy` binary.
    pub bin: PathBuf,
    /// The public roots (PEM) destinations and resolvers must chain to.
    pub roots_pem: String,
    /// Names the in-cell CA (the instance id).
    pub cell: String,
    pub network: Network,
    pub status: StatusFn,
}

/// Where the proxy listens and what it may reach besides public addresses. A cell uses
/// [`Network::default`]: every address, [`Ports::CELL`], no fixed answers and no
/// exemptions.
#[derive(Debug, Clone)]
pub struct Network {
    pub listen: Ipv4Addr,
    /// The ports to bind; 0 picks a free one the first time, kept for every restart.
    pub ports: Ports,
    /// Fixed name-to-address answers that bypass DNS (tests).
    pub hosts: HashMap<HostName, Vec<Ipv4Addr>>,
    /// Addresses allowed although not public (tests).
    pub exempt: Vec<Ipv4Addr>,
}

impl Default for Network {
    fn default() -> Self {
        Self {
            listen: Ipv4Addr::UNSPECIFIED,
            ports: Ports::CELL,
            hosts: HashMap::new(),
            exempt: Vec::new(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    #[error("in-cell CA: {0}")]
    Ca(#[from] TlsError),
    #[error("starting {bin}: {source}")]
    Spawn { bin: String, source: std::io::Error },
    #[error("the proxy process: {0}")]
    Ipc(#[from] IpcError),
    #[error("the proxy process did not answer Hello")]
    NotReady,
    #[error("no proxy process took the sandbox at {0} in time")]
    NoProxy(Ipv4Addr),
    #[error("a sandbox is already registered at {0}")]
    Busy(Ipv4Addr),
    #[error("the proxy refused the sandbox at {ip}: {reason}")]
    Refused { ip: Ipv4Addr, reason: String },
}

/// Where a sandbox stands with the running proxy process.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Held {
    /// Not (yet, or no longer) held by a running process.
    Pending,
    /// Held by the process of this generation.
    By(u64),
    Refused(String),
    /// Unregistered.
    Gone,
}

/// A sandbox's log as the agent keeps it.
struct Kept {
    log: EgressLog,
    gaps: Vec<Gap>,
    /// When the process that held the sandbox died, until a new one holds it.
    since: Option<SystemTime>,
}

/// A sandbox as the agent keeps it for the proxy.
struct Sandbox {
    id: SandboxId,
    policy: Arc<Policy>,
    /// Emptied, wiping the secrets, when the sandbox is unregistered.
    credentials: Mutex<HashMap<CredName, Credential>>,
    /// Being unregistered: a new process is not given it.
    ending: AtomicBool,
    held: watch::Sender<Held>,
    unregistered: watch::Sender<bool>,
    log: Mutex<Kept>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Sandbox {
    /// The log as it stands; a gap still open ends now.
    fn snapshot(&self) -> LogSnapshot {
        let kept = lock(&self.log);
        let mut gaps = kept.gaps.clone();
        if let Some(from) = kept.since {
            gaps.push(Gap { from, to: SystemTime::now() });
        }
        kept.log.snapshot(gaps)
    }

    /// Held by process generation `g`: closes the open gap, if any.
    fn held_by(&self, g: u64) {
        {
            let mut kept = lock(&self.log);
            if let Some(from) = kept.since.take() {
                kept.gaps.push(Gap { from, to: SystemTime::now() });
            }
        }
        self.held.send_replace(Held::By(g));
    }

    /// Its Register frame: the header, and every secret concatenated into one buffer of
    /// exactly their size.
    fn register_frame(&self, ip: Ipv4Addr) -> (ToProxy, SecretBuf) {
        let creds = lock(&self.credentials);
        let mut secret = SecretBuf::with_capacity(creds.values().map(|c| c.secret.expose().len()).sum());
        let credentials = creds
            .iter()
            .map(|(name, c)| {
                secret.extend(c.secret.expose());
                WireCredential {
                    name: name.to_string(),
                    adapter: c.binding.adapter,
                    destination: c.binding.destination.to_string(),
                    len: c.secret.expose().len(),
                }
            })
            .collect();
        let frame = ToProxy::Register {
            ip,
            sandbox: self.id.to_string(),
            bundle: common::b64::encode(self.policy.bytes()),
            ceiling: self.policy.limits.max.into(),
            credentials,
        };
        (frame, secret)
    }
}

/// The running process's stdin, and which generation it is.
struct Link {
    stdin: Option<ChildStdin>,
    generation: u64,
}

/// Starts the egress proxy process, keeps it running, and keeps each sandbox's egress
/// log. Shared as `Arc<Supervisor>`; the process lives as long as the runtime it was
/// started on.
pub struct Supervisor {
    cfg: SupervisorConfig,
    ca: CaKey,
    /// The ports the first process bound, asked of every later one.
    ports: Mutex<Ports>,
    /// Held while writing to the process and while a new one is being given the cell's
    /// state, so no message goes to a process before it has that state.
    link: tokio::sync::Mutex<Link>,
    /// The generation of the running process; 0 while there is none.
    alive: watch::Sender<u64>,
    sandboxes: Mutex<HashMap<Ipv4Addr, Arc<Sandbox>>>,
    own: Mutex<Vec<Ipv4Addr>>,
    pid: AtomicU32,
    connections: AtomicU32,
    /// Each proxy process's last egress byte count, by generation: each counts from zero,
    /// and a late report from a dead process still counts. Bytes a process sent after its
    /// last report (at most a second's) die with it.
    egress: Mutex<BTreeMap<u64, u64>>,
    restarts: AtomicU32,
}



impl Supervisor {
    /// Generates the in-cell CA, starts the proxy process and waits until it serves.
    pub async fn start(cfg: SupervisorConfig) -> Result<Arc<Self>, SupervisorError> {
        let ca = CaKey::generate(&cfg.cell)?;
        let ports = cfg.network.ports;
        let sup = Arc::new(Self {
            cfg,
            ca,
            ports: Mutex::new(ports),
            link: tokio::sync::Mutex::new(Link { stdin: None, generation: 0 }),
            alive: watch::Sender::new(0),
            sandboxes: Mutex::new(HashMap::new()),
            own: Mutex::new(Vec::new()),
            pid: AtomicU32::new(0),
            connections: AtomicU32::new(0),
            egress: Mutex::new(BTreeMap::new()),
            restarts: AtomicU32::new(0),
        });
        let (child, stdin, stdout) = sup.spawn().await?;
        sup.attach(1, child.id(), stdin, stdout).await;
        tokio::spawn(Arc::clone(&sup).keep(child, 1));
        Ok(sup)
    }

    /// The in-cell CA certificate (PEM) sandboxes trust; the same for every process.
    pub fn ca_pem(&self) -> String {
        self.ca.pem()
    }

    /// The ports the proxy listens on.
    pub fn ports(&self) -> Ports {
        *lock(&self.ports)
    }

    /// Connections open now (the telemetry's proxy connection count), as the process
    /// last reported it.
    pub fn connections(&self) -> u32 {
        self.connections.load(Ordering::Relaxed)
    }

    /// Bytes the proxy has sent toward destinations since this supervisor started (the
    /// cell's unlock), across process restarts: the `egress_bytes` the cell reports (SPEC.md
    /// phase 10). Only the proxy process counts; nothing a sandbox reaches can change it.
    pub fn egress_bytes(&self) -> u64 {
        lock(&self.egress).values().fold(0u64, |sum, b| sum.saturating_add(*b))
    }

    /// The running process's id; `None` between a death and its replacement.
    pub fn pid(&self) -> Option<u32> {
        Some(self.pid.load(Ordering::Relaxed)).filter(|p| *p != 0)
    }

    /// How many times the process has been replaced.
    pub fn restarts(&self) -> u32 {
        self.restarts.load(Ordering::Relaxed)
    }

    /// Adds one of the cell's own addresses, which the proxy never connects to (now and
    /// in every later process).
    pub async fn add_own(&self, ip: Ipv4Addr) {
        {
            let mut own = lock(&self.own);
            if own.contains(&ip) {
                return;
            }
            own.push(ip);
        }
        let mut link = self.link.lock().await;
        if let Some(stdin) = link.stdin.as_mut() {
            let _ = ipc::write(stdin, &ToProxy::AddOwn { ip }, &[]).await;
        }
    }

    /// Serves the sandbox at `ip` under `policy` (the bundle in force when it was
    /// created, kept past its expiry) with `credentials`; returns once the proxy holds
    /// it, so the sandbox may start. The credentials are kept here, for later processes,
    /// until [`Supervisor::unregister`].
    pub async fn register(
        &self,
        ip: Ipv4Addr,
        sandbox: SandboxId,
        policy: Arc<Policy>,
        credentials: HashMap<CredName, Credential>,
    ) -> Result<(), SupervisorError> {
        let sb = Arc::new(Sandbox {
            id: sandbox,
            policy,
            credentials: Mutex::new(credentials),
            ending: AtomicBool::new(false),
            held: watch::Sender::new(Held::Pending),
            unregistered: watch::Sender::new(false),
            log: Mutex::new(Kept { log: EgressLog::new(), gaps: Vec::new(), since: None }),
        });
        let mut held = sb.held.subscribe();
        {
            let mut link = self.link.lock().await;
            {
                let mut map = lock(&self.sandboxes);
                if map.contains_key(&ip) {
                    return Err(SupervisorError::Busy(ip));
                }
                map.insert(ip, Arc::clone(&sb));
            }
            // No process, or a write that fails because it is dying: the next process
            // is given the sandbox.
            if let Some(stdin) = link.stdin.as_mut() {
                let (frame, secret) = sb.register_frame(ip);
                let _ = ipc::write(stdin, &frame, secret.as_slice()).await;
            }
        }
        let outcome = tokio::time::timeout(REGISTER_WITHIN, held.wait_for(|h| *h != Held::Pending))
            .await
            .map(|r| r.map(|h| h.clone()));
        match outcome {
            Ok(Ok(Held::By(_))) => Ok(()),
            Ok(Ok(Held::Refused(reason))) => {
                self.forget(ip, &sb);
                Err(SupervisorError::Refused { ip, reason })
            }
            _ => {
                self.unregister(ip).await;
                Err(SupervisorError::NoProxy(ip))
            }
        }
    }

    /// The egress log of the sandbox at `ip`, while it is registered.
    pub fn log(&self, ip: Ipv4Addr) -> Option<LogSnapshot> {
        lock(&self.sandboxes).get(&ip).map(|sb| sb.snapshot())
    }

    /// Stops serving the sandbox at `ip`: the proxy ends its connections, and once
    /// their lines have arrived (or 5 s have passed, or the process died) the sandbox's
    /// credentials are wiped. Returns its log.
    pub async fn unregister(&self, ip: Ipv4Addr) -> Option<LogSnapshot> {
        let sb = lock(&self.sandboxes).get(&ip).cloned()?;
        sb.ending.store(true, Ordering::SeqCst);
        let mut done = sb.unregistered.subscribe();
        let sent_to = {
            let mut link = self.link.lock().await;
            let g = link.generation;
            let unregister = ToProxy::Unregister { ip, sandbox: sb.id.to_string() };
            match link.stdin.as_mut() {
                Some(stdin) => ipc::write(stdin, &unregister, &[]).await.ok().map(|()| g),
                None => None,
            }
        };
        if let Some(g) = sent_to {
            let mut alive = self.alive.subscribe();
            let _ = tokio::time::timeout(UNREGISTER_WITHIN, async {
                tokio::select! {
                    _ = done.wait_for(|d| *d) => {}
                    _ = alive.wait_for(|a| *a != g) => {}
                }
            })
            .await;
        }
        self.forget(ip, &sb);
        Some(sb.snapshot())
    }

    /// Drops the sandbox at `ip` (if it is still `sb`) and wipes its credentials.
    fn forget(&self, ip: Ipv4Addr, sb: &Arc<Sandbox>) {
        {
            let mut map = lock(&self.sandboxes);
            if map.get(&ip).is_some_and(|s| Arc::ptr_eq(s, sb)) {
                map.remove(&ip);
            }
        }
        drop(std::mem::take(&mut *lock(&sb.credentials)));
        sb.held.send_replace(Held::Gone);
    }

    /// The sandbox registered at `ip`, if it is `id`.
    fn sandbox(&self, ip: Ipv4Addr, id: &str) -> Option<Arc<Sandbox>> {
        lock(&self.sandboxes).get(&ip).filter(|sb| sb.id.as_str() == id).cloned()
    }

    /// Starts a process, says Hello (with the CA key) and waits for Ready.
    async fn spawn(&self) -> Result<(Child, ChildStdin, ChildStdout), SupervisorError> {
        let mut child = Command::new(&self.cfg.bin)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .map_err(|source| SupervisorError::Spawn { bin: self.cfg.bin.display().to_string(), source })?;
        let mut stdin = child.stdin.take().expect("stdin is piped");
        let mut stdout = child.stdout.take().expect("stdout is piped");
        let n = &self.cfg.network;
        let hello = ToProxy::Hello {
            cell: self.cfg.cell.clone(),
            ca_cert: common::b64::encode(self.ca.cert_der()),
            roots_pem: self.cfg.roots_pem.clone(),
            listen: n.listen,
            ports: self.ports(),
            hosts: n.hosts.iter().map(|(name, ips)| (name.to_string(), ips.clone())).collect(),
            exempt: n.exempt.clone(),
        };
        ipc::write(&mut stdin, &hello, self.ca.key_der()).await?;
        match tokio::time::timeout(READY_WITHIN, ipc::read::<_, FromProxy>(&mut stdout)).await {
            Ok(Ok(Some((FromProxy::Ready { ports }, _)))) => *lock(&self.ports) = ports,
            _ => return Err(SupervisorError::NotReady),
        }
        Ok((child, stdin, stdout))
    }

    /// Makes a started process generation `g`: reads its events, then gives it the
    /// cell's own addresses and every live sandbox. Returns the sandboxes it was given.
    async fn attach(self: &Arc<Self>, g: u64, pid: Option<u32>, mut stdin: ChildStdin, stdout: ChildStdout) -> Vec<Arc<Sandbox>> {
        let mut link = self.link.lock().await;
        self.alive.send_replace(g);
        self.pid.store(pid.unwrap_or(0), Ordering::Relaxed);
        tokio::spawn(Arc::clone(self).events(g, stdout));
        let own = lock(&self.own).clone();
        for ip in own {
            let _ = ipc::write(&mut stdin, &ToProxy::AddOwn { ip }, &[]).await;
        }
        let live: Vec<(Ipv4Addr, Arc<Sandbox>)> = lock(&self.sandboxes)
            .iter()
            .filter(|(_, sb)| !sb.ending.load(Ordering::SeqCst))
            .map(|(ip, sb)| (*ip, Arc::clone(sb)))
            .collect();
        for (ip, sb) in &live {
            let (frame, secret) = sb.register_frame(*ip);
            let _ = ipc::write(&mut stdin, &frame, secret.as_slice()).await;
        }
        *link = Link { stdin: Some(stdin), generation: g };
        live.into_iter().map(|(_, sb)| sb).collect()
    }

    /// The running process died at `died`: every sandbox it held opens a gap. Returns
    /// how many.
    async fn detach(&self, died: SystemTime) -> usize {
        let mut link = self.link.lock().await;
        link.stdin = None;
        self.alive.send_replace(0);
        self.pid.store(0, Ordering::Relaxed);
        self.connections.store(0, Ordering::Relaxed);
        let mut affected = 0;
        for sb in lock(&self.sandboxes).values() {
            let was_held = matches!(*sb.held.borrow(), Held::By(_));
            if was_held {
                sb.held.send_replace(Held::Pending);
                lock(&sb.log).since.get_or_insert(died);
                affected += 1;
            }
        }
        affected
    }

    /// Reads the events of process generation `g` until it ends.
    async fn events(self: Arc<Self>, g: u64, mut stdout: ChildStdout) {
        while let Ok(Some((event, _))) = ipc::read::<_, FromProxy>(&mut stdout).await {
            // Acknowledgements count only from the running process; log lines from any.
            let current = *self.alive.borrow() == g;
            match event {
                FromProxy::Registered { ip, sandbox } if current => {
                    if let Some(sb) = self.sandbox(ip, &sandbox) {
                        sb.held_by(g);
                    }
                }
                FromProxy::Refused { ip, sandbox, reason } if current => {
                    if let Some(sb) = self.sandbox(ip, &sandbox) {
                        sb.held.send_replace(Held::Refused(reason));
                    }
                }
                FromProxy::Log { ip, sandbox, line } => {
                    if let Some(sb) = self.sandbox(ip, &sandbox) {
                        lock(&sb.log).log.push(line);
                    }
                }
                FromProxy::Unregistered { ip, sandbox } => {
                    if let Some(sb) = self.sandbox(ip, &sandbox) {
                        sb.unregistered.send_replace(true);
                    }
                }
                FromProxy::Connections { count, egress_bytes } => {
                    let mut by_generation = lock(&self.egress);
                    let last = by_generation.entry(g).or_default();
                    *last = (*last).max(egress_bytes);
                    if current {
                        self.connections.store(count, Ordering::Relaxed);
                    }
                }
                _ => {}
            }
        }
    }

    /// Waits for the process to die, and replaces it, forever.
    async fn keep(self: Arc<Self>, mut child: Child, mut generation: u64) {
        let mut started = Instant::now();
        let mut pause = FIRST_PAUSE;
        loop {
            let pid = child.id();
            let exit = child.wait().await;
            let (died, died_at) = (SystemTime::now(), Instant::now());
            let affected = self.detach(died).await;
            (self.cfg.status)(
                "proxy-exited",
                json!({ "pid": pid, "status": exit.map_or_else(|e| e.to_string(), |s| s.to_string()), "sandboxes": affected }),
            );
            if started.elapsed() < STEADY {
                tokio::time::sleep(pause).await;
                pause = (pause * 2).min(MAX_PAUSE);
            } else {
                pause = FIRST_PAUSE;
            }
            let (next, stdin, stdout) = loop {
                match self.spawn().await {
                    Ok(started) => break started,
                    Err(e) => {
                        (self.cfg.status)("proxy-start-failed", json!({ "error": e.to_string() }));
                        tokio::time::sleep(pause).await;
                        pause = (pause * 2).min(MAX_PAUSE);
                    }
                }
            };
            child = next;
            started = Instant::now();
            generation += 1;
            let restarts = self.restarts.fetch_add(1, Ordering::Relaxed) + 1;
            let given = self.attach(generation, child.id(), stdin, stdout).await;
            // Recovered once the new process holds every sandbox it was given; watched
            // apart, so a death meanwhile is seen at once.
            let status = Arc::clone(&self);
            let pid = child.id();
            tokio::spawn(async move {
                for sb in &given {
                    let mut held = sb.held.subscribe();
                    let _ = tokio::time::timeout(REGISTER_WITHIN, held.wait_for(|h| *h != Held::Pending)).await;
                }
                (status.cfg.status)(
                    "proxy-restarted",
                    json!({ "pid": pid, "recovery_ms": died_at.elapsed().as_millis() as u64, "restarts": restarts, "sandboxes": given.len() }),
                );
            });
        }
    }
}
