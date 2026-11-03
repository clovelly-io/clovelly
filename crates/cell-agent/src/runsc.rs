//! Drives `runsc` through its CLI: writes OCI bundles to tmpfs and runs the create,
//! start, exec, wait and delete steps, synchronously for the phase 0 and 1 harness and
//! asynchronously for the cell API ([`crate::sandbox`]).
//!
//! Every sandbox runs under `--platform=systrap` with its root overlaid by a
//! memory-backed upper layer (`--overlay2=root:memory`), so many sandboxes share one
//! read-only base rootfs. Every call names its container by a [`SandboxId`], so no id
//! of another width ever reaches runsc, which resolves ids by prefix.

use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::time::Instant;

use common::ids::SandboxId;
use common::sandbox::Size;

/// How a sandbox is networked.
#[derive(Debug, Clone)]
pub enum Network {
    /// No interfaces besides loopback (`--network=none`).
    None,
    /// gVisor's netstack over the interfaces of an existing network namespace
    /// (`--network=sandbox`): every cell sandbox, routed only to the egress proxy, and
    /// the phase 0 transfer benchmark.
    Netns(PathBuf),
}

/// Whether runsc puts sandboxes in cgroups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cgroups {
    /// `--ignore-cgroups`: the phase 0 and 1 harness, which sets no limits.
    Ignore,
    /// Each sandbox in the cgroup its spec names, with its limits.
    Enforce,
}

/// A host file or directory bind-mounted into the sandbox, read-only unless
/// `writable` (a volume).
#[derive(Debug, Clone)]
pub struct Bind {
    pub source: PathBuf,
    pub destination: String,
    pub writable: bool,
}

/// A sandbox's cgroup (relative to the cgroup2 root) and its size: `memory.max` at the
/// memory, `cpu.max` at the CPU (a hard cap) and a CPU weight in proportion to it (the
/// guarantee).
#[derive(Debug, Clone)]
pub struct Resources {
    pub cgroup: String,
    pub size: Size,
}

/// The most processes (tasks) a sandbox may hold, so a fork bomb stops there.
pub const MAX_PROCESSES: u32 = 4096;

/// What goes into a bundle's `config.json`.
#[derive(Debug, Clone)]
pub struct Spec<'a> {
    pub rootfs: &'a Path,
    pub args: &'a [&'a str],
    pub env: &'a [(String, String)],
    pub network: &'a Network,
    pub binds: &'a [Bind],
    pub resources: Option<&'a Resources>,
}

/// An OCI bundle directory holding `config.json`; deleted on drop.
#[derive(Debug)]
pub struct Bundle {
    dir: PathBuf,
}

impl Bundle {
    pub fn write(dir: PathBuf, spec: &Spec<'_>) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        let bundle = Self { dir };
        fs::write(bundle.dir.join("config.json"), config_json(spec))?;
        Ok(bundle)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

impl Drop for Bundle {
    fn drop(&mut self) {
        // Best effort: a leftover bundle only costs tmpfs space.
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// The runsc subcommand that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Run,
    Create,
    Start,
    Exec,
    Wait,
    Kill,
    Delete,
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Step::Run => "run",
            Step::Create => "create",
            Step::Start => "start",
            Step::Exec => "exec",
            Step::Wait => "wait",
            Step::Kill => "kill",
            Step::Delete => "delete",
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RunscError {
    #[error("writing bundle: {0}")]
    Bundle(#[from] io::Error),
    #[error("runsc {step}: {source}")]
    Io { step: Step, source: io::Error },
    #[error("runsc {step} exited with {status}: {stderr}")]
    Failed {
        step: Step,
        status: ExitStatus,
        stderr: String,
    },
    #[error("runsc exec closed stdout without output: {stderr}")]
    NoOutput { stderr: String },
    #[error("runsc wait printed {0:?}, not an exit status")]
    WaitOutput(String),
}

/// The runsc binary, the state directory its containers are tracked in, whether it
/// uses cgroups and the `--network` mode the cell API's sandboxes are created with
/// (every later command for them passes the same).
#[derive(Debug, Clone)]
pub struct Runsc {
    pub bin: PathBuf,
    pub state: PathBuf,
    pub cgroups: Cgroups,
    pub network: NetworkMode,
    /// More global flags (the throughput diagnosis's `--gso=false`); cells pass none.
    pub extra: Vec<String>,
}

/// runsc's `--network` for the cell API's sandboxes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// `--network=none` (the dev server, the phase 0 and 1 harness).
    None,
    /// `--network=sandbox`, the namespace named in each sandbox's spec.
    Sandbox,
    /// `--network=host`: the host kernel's stack in that same namespace (decision 6's
    /// fallback, measured by the throughput harness).
    Host,
}

impl NetworkMode {
    fn flag(self) -> &'static str {
        match self {
            NetworkMode::None => "--network=none",
            NetworkMode::Sandbox => "--network=sandbox",
            NetworkMode::Host => "--network=host",
        }
    }
}

impl Runsc {
    /// Global flags. `--network` is this Runsc's own mode for calls naming no
    /// namespace, and for a namespace `--network=host` in host mode, else `sandbox`.
    fn global_args(&self, network: &Network) -> Vec<std::ffi::OsString> {
        let flag = match (network, self.network) {
            (Network::None, mode) => mode.flag(),
            (Network::Netns(_), NetworkMode::Host) => NetworkMode::Host.flag(),
            (Network::Netns(_), _) => NetworkMode::Sandbox.flag(),
        };
        let mut args: Vec<std::ffi::OsString> = vec![
            "--root".into(),
            self.state.clone().into(),
            "--platform=systrap".into(),
            "--overlay2=root:memory".into(),
            flag.into(),
        ];
        if self.cgroups == Cgroups::Ignore {
            args.push("--ignore-cgroups".into());
        }
        args.extend(self.extra.iter().map(Into::into));
        args
    }

    fn command(&self, network: &Network) -> Command {
        let mut c = Command::new(&self.bin);
        c.args(self.global_args(network)).stdin(Stdio::null());
        c
    }

    fn tokio_command(&self) -> tokio::process::Command {
        let mut c = tokio::process::Command::new(&self.bin);
        c.args(self.global_args(&Network::None)).stdin(Stdio::null()).kill_on_drop(true);
        c
    }

    /// Runs a container to completion and returns its output, whatever its exit status.
    pub fn run(&self, id: &SandboxId, bundle: &Bundle, network: &Network) -> Result<Output, RunscError> {
        self.command(network)
            .args(["run", "--bundle"])
            .arg(bundle.dir())
            .arg(id.as_str())
            .output()
            .map_err(|source| RunscError::Io {
                step: Step::Run,
                source,
            })
    }

    /// Creates the sandbox and its container without starting the container's process.
    pub fn create(&self, id: &SandboxId, bundle: &Bundle, network: &Network) -> Result<(), RunscError> {
        let mut c = self.command(network);
        c.args(["create", "--bundle"]).arg(bundle.dir()).arg(id.as_str());
        // The container inherits create's stdio; nothing should hold a pipe open.
        c.stdout(Stdio::null());
        checked(Step::Create, id, c)
    }

    pub fn start(&self, id: &SandboxId) -> Result<(), RunscError> {
        let mut c = self.command(&Network::None);
        c.args(["start", id.as_str()]).stdout(Stdio::null());
        checked(Step::Start, id, c)
    }

    /// Runs `args` in the container and returns the instant its first stdout byte
    /// arrived. Waits for the process to exit and requires success.
    pub fn exec_first_byte(&self, id: &SandboxId, args: &[&str]) -> Result<Instant, RunscError> {
        let io = |source| RunscError::Io {
            step: Step::Exec,
            source,
        };
        let mut child = self
            .command(&Network::None)
            .args(["exec", id.as_str()])
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(io)?;
        let mut stdout = child.stdout.take().expect("stdout is piped");
        let mut first = [0u8; 1];
        let n = stdout.read(&mut first).map_err(io)?;
        let at = Instant::now();
        io::copy(&mut stdout, &mut io::sink()).map_err(io)?;
        let out = child.wait_with_output().map_err(io)?;
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        if !out.status.success() {
            return Err(RunscError::Failed {
                step: Step::Exec,
                status: out.status,
                stderr,
            });
        }
        if n == 0 {
            return Err(RunscError::NoOutput { stderr });
        }
        Ok(at)
    }

    /// Kills the container if it is running and removes the sandbox.
    pub fn delete(&self, id: &SandboxId) -> Result<(), RunscError> {
        let mut c = self.command(&Network::None);
        c.args(["delete", "--force", id.as_str()]).stdout(Stdio::null());
        checked(Step::Delete, id, c)
    }

    /// `create` then `start`, then `runsc wait` attached, for the cell API. Blocking
    /// runsc calls run on the blocking pool. (A wait attached before `start` gives up
    /// after two minutes, found in run 20261027-222952.)
    pub async fn create_and_start(&self, id: SandboxId, bundle_dir: PathBuf, network: &Network) -> Result<Waiting, RunscError> {
        let (runsc, net) = (self.clone(), network.clone());
        tokio::task::spawn_blocking(move || {
            let mut c = runsc.command(&net);
            c.args(["create", "--bundle"]).arg(&bundle_dir).arg(id.as_str());
            c.stdout(Stdio::null());
            checked(Step::Create, &id, c)?;
            let mut c = runsc.command(&net);
            c.args(["start", id.as_str()]).stdout(Stdio::null());
            checked(Step::Start, &id, c)
        })
        .await
        .expect("runsc create does not panic")?;
        Ok(Waiting(
            self.tokio_command()
                .args(["wait", id.as_str()])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|source| RunscError::Io { step: Step::Wait, source })?,
        ))
    }
}

/// A `runsc wait` attached to a sandbox (killed if dropped).
#[derive(Debug)]
pub struct Waiting(tokio::process::Child);

impl Waiting {
    /// The container's exit status (128 + signal for a signal) when its main process
    /// ends, or when the container is deleted.
    pub async fn status(self) -> Result<i32, RunscError> {
        let out = self.0.wait_with_output().await.map_err(|source| RunscError::Io {
            step: Step::Wait,
            source,
        })?;
        if !out.status.success() {
            return Err(RunscError::Failed {
                step: Step::Wait,
                status: out.status,
                stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            });
        }
        parse_wait(&String::from_utf8_lossy(&out.stdout))
    }
}

impl Runsc {
    /// Starts `runsc exec` with piped stdio. The process's in-sandbox pid is written to
    /// `pid_file`, for [`Runsc::kill_pid`].
    pub fn exec(
        &self,
        id: &SandboxId,
        args: &[String],
        env: &[(String, String)],
        cwd: &str,
        pid_file: &Path,
    ) -> Result<tokio::process::Child, RunscError> {
        let mut c = self.tokio_command();
        c.arg("exec")
            .arg(format!("--cwd={cwd}"))
            .arg(format!("--internal-pid-file={}", pid_file.display()));
        for (k, v) in env {
            c.arg(format!("--env={k}={v}"));
        }
        c.arg(id.as_str())
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| RunscError::Io {
                step: Step::Exec,
                source,
            })
    }

    /// Starts a sandbox's main command as `runsc exec` (stdio to /dev/null, killed if
    /// dropped): its exit status is the main process's.
    pub fn main_exec(&self, id: &SandboxId, args: &[String], env: &[(String, String)]) -> Result<tokio::process::Child, RunscError> {
        let mut c = self.tokio_command();
        c.arg("exec").arg("--cwd=/");
        for (k, v) in env {
            c.arg(format!("--env={k}={v}"));
        }
        c.arg(id.as_str())
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|source| RunscError::Io { step: Step::Exec, source })
    }

    /// Whether the sandbox is still running (`runsc state`).
    pub async fn running(&self, id: &SandboxId) -> bool {
        let Ok(out) = self.tokio_command().args(["state", id.as_str()]).stdout(Stdio::piped()).output().await else {
            return false;
        };
        serde_json::from_slice::<serde_json::Value>(&out.stdout).is_ok_and(|v| v["status"] == "running")
    }

    /// Sends SIGKILL to one process in the sandbox.
    pub async fn kill_pid(&self, id: &SandboxId, pid: u32) -> Result<(), RunscError> {
        let out = self
            .tokio_command()
            .arg("kill")
            .arg(format!("--pid={pid}"))
            .args([id.as_str(), "KILL"])
            .output()
            .await
            .map_err(|source| RunscError::Io {
                step: Step::Kill,
                source,
            })?;
        tokio_checked(Step::Kill, out)
    }

    /// `delete --force`, for the cell API.
    pub async fn remove(&self, id: &SandboxId) -> Result<(), RunscError> {
        let out = self
            .tokio_command()
            .args(["delete", "--force", id.as_str()])
            .output()
            .await
            .map_err(|source| RunscError::Io {
                step: Step::Delete,
                source,
            })?;
        tokio_checked(Step::Delete, out)
    }
}

fn tokio_checked(step: Step, out: Output) -> Result<(), RunscError> {
    if out.status.success() {
        return Ok(());
    }
    Err(RunscError::Failed {
        step,
        status: out.status,
        stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
    })
}

/// `runsc wait` prints `{"id":"…","exitStatus":N}`.
fn parse_wait(stdout: &str) -> Result<i32, RunscError> {
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).map_err(|_| RunscError::WaitOutput(stdout.to_owned()))?;
    v.get("exitStatus")
        .and_then(serde_json::Value::as_i64)
        .and_then(|n| i32::try_from(n).ok())
        .ok_or_else(|| RunscError::WaitOutput(stdout.to_owned()))
}

/// Runs a runsc subcommand for container `id` and requires success. Its stderr goes to a
/// temporary file rather than a pipe: `create` leaves the sandbox and the container's
/// process holding the stdio they were given, so a pipe would never reach EOF.
fn checked(step: Step, id: &SandboxId, mut c: Command) -> Result<(), RunscError> {
    let io = |source| RunscError::Io { step, source };
    let path = std::env::temp_dir().join(format!("runsc-{id}-{step}.err"));
    let status = c
        .stderr(fs::File::create(&path).map_err(io)?)
        .status()
        .map_err(io);
    let stderr = fs::read_to_string(&path).unwrap_or_default();
    let _ = fs::remove_file(&path);
    match status? {
        s if s.success() => Ok(()),
        status => Err(RunscError::Failed {
            step,
            status,
            stderr: stderr.trim().to_owned(),
        }),
    }
}

/// Renders a minimal OCI runtime spec: no capabilities, no device nodes beyond what
/// runsc provides, a private PID/IPC/UTS/mount namespace, the given network and, with
/// resources, the sandbox's cgroup and limits.
fn config_json(spec: &Spec<'_>) -> String {
    use serde_json::json;
    let mut mounts = vec![
        json!({"destination": "/proc", "type": "proc", "source": "proc"}),
        json!({"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev"]}),
    ];
    mounts.extend(spec.binds.iter().map(|b| {
        json!({"destination": b.destination, "type": "bind",
               "source": b.source.to_string_lossy(), "options": ["rbind", if b.writable { "rw" } else { "ro" }]})
    }));
    let netns = match spec.network {
        Network::None => json!({"type": "network"}),
        Network::Netns(path) => json!({"type": "network", "path": path.to_string_lossy()}),
    };
    let mut env = vec!["PATH=/bin".to_owned(), "HOME=/tmp".to_owned()];
    env.extend(spec.env.iter().map(|(k, v)| format!("{k}={v}")));
    let mut linux = json!({
        "namespaces": [{"type": "pid"}, {"type": "ipc"}, {"type": "uts"}, {"type": "mount"}, netns],
    });
    if let Some(r) = spec.resources {
        // cpu.max = quota/period; runsc maps shares to cpu.weight (1024 shares per vCPU).
        let halves = u64::from(r.size.cpu.0);
        linux["cgroupsPath"] = json!(r.cgroup);
        linux["resources"] = json!({
            "memory": {"limit": r.size.memory.bytes(), "swap": r.size.memory.bytes()},
            "cpu": {"shares": halves * 512, "quota": halves * 50_000, "period": 100_000},
            "pids": {"limit": MAX_PROCESSES},
        });
    }
    json!({
        "ociVersion": "1.0.2",
        "process": {
            "terminal": false,
            "user": {"uid": 0, "gid": 0},
            "args": spec.args,
            "env": env,
            "cwd": "/",
            "noNewPrivileges": true,
            "rlimits": [{"type": "RLIMIT_NPROC", "hard": MAX_PROCESSES, "soft": MAX_PROCESSES}],
        },
        "root": {"path": spec.rootfs.to_string_lossy(), "readonly": false},
        "hostname": "sandbox",
        "mounts": mounts,
        "linux": linux,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::sandbox::{CpuHalves, MemoryGib};

    fn parse(spec: &Spec<'_>) -> serde_json::Value {
        serde_json::from_str(&config_json(spec)).unwrap()
    }

    #[test]
    fn config_carries_args_binds_and_netns() {
        let spec = Spec {
            rootfs: Path::new("/run/clovelly/base/rootfs"),
            args: &["/bin/python3", "-c", "print(\"1\")"],
            env: &[],
            network: &Network::Netns(PathBuf::from("/run/netns/bench")),
            binds: &[Bind {
                source: PathBuf::from("/bin/cell-agent"),
                destination: "/clovelly-agent".into(),
                writable: false,
            }],
            resources: None,
        };
        let c = parse(&spec);
        assert_eq!(c["process"]["args"][2], "print(\"1\")");
        assert_eq!(c["root"]["path"], "/run/clovelly/base/rootfs");
        assert_eq!(c["mounts"][2]["source"], "/bin/cell-agent");
        assert_eq!(c["linux"]["namespaces"][4]["path"], "/run/netns/bench");
        assert!(c["linux"].get("resources").is_none());
        assert_eq!(c["process"]["capabilities"], serde_json::Value::Null, "no capabilities");
    }

    #[test]
    fn config_sets_the_sandbox_cgroup_and_limits() {
        let r = Resources {
            cgroup: "/clovelly/0123".into(),
            size: Size::new(CpuHalves(3), MemoryGib(2)),
        };
        let spec = Spec {
            rootfs: Path::new("/r"),
            args: &["/bin/sleep", "1"],
            env: &[("A".into(), "b=c".into())],
            network: &Network::None,
            binds: &[],
            resources: Some(&r),
        };
        let c = parse(&spec);
        assert_eq!(c["linux"]["cgroupsPath"], "/clovelly/0123");
        assert_eq!(c["linux"]["resources"]["memory"]["limit"], 2u64 << 30);
        assert_eq!(c["linux"]["resources"]["cpu"]["quota"], 150_000);
        assert_eq!(c["linux"]["resources"]["cpu"]["period"], 100_000);
        assert_eq!(c["linux"]["resources"]["cpu"]["shares"], 1536);
        assert_eq!(c["process"]["env"][2], "A=b=c");
        assert_eq!(c["linux"]["namespaces"][4], serde_json::json!({"type": "network"}));
    }

    #[test]
    fn wait_output_parses() {
        assert_eq!(parse_wait("{\"id\":\"x\",\"exitStatus\":137}\n").unwrap(), 137);
        assert!(parse_wait("nope").is_err());
    }
}
