//! The cell API's gRPC service (`proto/clovelly/cell/v1/cell.proto`) over [`Sandboxes`].
//!
//! Requests are parsed here into typed values (a [`SandboxId`], an [`AccessKey`], a
//! [`Size`]) before anything reaches the sandbox manager or runsc. Refusals carry their
//! reason in the `clovelly-error` trailer.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::ids::SandboxId;
use common::pass::{PassChecker, SKEW_SECS};
use common::proto::cell as pb;
use common::proto::cell::cell_server::Cell;
use common::proto::control::DrainState;
use common::sandbox::{CpuHalves, MAX_TIMEOUT, MemoryGib, Size};
use common::template::Digest;
use common::volume::{VolumeGib, VolumeName};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Child;
use tokio::sync::{mpsc, watch};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::{Request, Response, Status, Streaming};

use crate::agent::status;
use crate::credentials;
use crate::lease::SharedTerms;
use crate::policies::Policies;
use crate::sandbox::{self, AccessKey, CellError, CreateRequest, Live, Sandboxes};
use crate::templates::Templates;

const CHUNK: usize = 64 * 1024;

/// A refusal as a gRPC status with its `clovelly-error` trailer.
pub fn refusal(e: &CellError) -> Status {
    let (reason, code) = e.reason();
    let mut md = MetadataMap::new();
    md.insert("clovelly-error", MetadataValue::from_static(reason.as_str_name()));
    Status::with_metadata(code, e.to_string(), md)
}

fn invalid(msg: impl Into<String>) -> Status {
    refusal(&CellError::Invalid(msg.into()))
}

/// The Cell service.
pub struct CellApi {
    pub sandboxes: Arc<Sandboxes>,
    pub terms: Arc<SharedTerms>,
    /// The policy bundle new sandboxes are created under.
    pub policies: Arc<Policies>,
    pub credentials: Arc<credentials::Store>,
    /// Set to `Draining` by `Drain`; the agent watches it.
    pub drain: watch::Sender<DrainState>,
    /// Where exec'd processes' pids are written.
    pub pids: PathBuf,
    pub execs: AtomicU64,
    /// The template cache; none: creates naming a template are refused.
    pub templates: Option<Arc<Templates>>,
    /// Whether a create needs the control plane's placement pass.
    pub passes: Passes,
}

/// Whether this cell checks placement passes (`common::pass`) before it creates a sandbox.
pub enum Passes {
    /// No control plane (`dev-serve`, the in-guest harness): nothing is placed here, so there is
    /// no pass to check.
    Unchecked,
    /// A control plane but not its CA: no pass can be checked, so every create is refused.
    Refused,
    /// Every create needs a pass the control plane's CA vouches for, for this cell.
    Checked(Box<PassGate>),
}

/// A cell's check of placement passes: the control plane's CA, the cell's own name, and the
/// sandbox ids it has created, each kept until its pass's expiry, so a pass is used once.
pub struct PassGate {
    checker: PassChecker,
    cell: String,
    used: Mutex<HashMap<String, u64>>,
}

impl PassGate {
    pub fn new(checker: PassChecker, cell: String) -> Self {
        Self { checker, cell, used: Mutex::new(HashMap::new()) }
    }

    /// Checks a create's pass: issued by the control plane for this cell and exactly this
    /// sandbox, size and timeout, unexpired at `now` (Unix seconds) and not used before. The
    /// pass's expiry, for [`PassGate::spend`] once the create has succeeded.
    fn admit(&self, req: &pb::CreateSandboxRequest, now: u64) -> Result<u64, CellError> {
        let refused = |e: common::pass::PassError| CellError::PlacementRefused(e.to_string());
        let claims = self.checker.check(&req.placement_pass, now).map_err(refused)?;
        claims.matches(&self.cell, &req.sandbox_id, req.cpu_halves, req.memory_gib, req.timeout_secs).map_err(refused)?;
        if self.used.lock().unwrap_or_else(|p| p.into_inner()).contains_key(&req.sandbox_id) {
            return Err(CellError::PlacementRefused("this placement's pass was used before".into()));
        }
        Ok(claims.exp)
    }

    /// Records a sandbox id whose create succeeded, until its pass's expiry, so the pass is
    /// not taken again; a create that failed spends nothing, and its refusal says why. Two
    /// creates racing on one pass cannot both succeed: the sandbox id is the same.
    fn spend(&self, sandbox: &str, exp: u64, now: u64) {
        let mut used = self.used.lock().unwrap_or_else(|p| p.into_inner());
        used.retain(|_, e| e.saturating_add(SKEW_SECS) >= now);
        used.insert(sandbox.to_owned(), exp);
    }
}

fn parse_id(s: &str) -> Result<SandboxId, Status> {
    s.parse().map_err(|e| refusal(&CellError::InvalidId(e)))
}

fn parse_target(id: &str, key: &[u8]) -> Result<(SandboxId, AccessKey), Status> {
    Ok((parse_id(id)?, AccessKey::parse(key).map_err(|e| refusal(&e))?))
}

fn parse_env(env: std::collections::HashMap<String, String>) -> Result<Vec<(String, String)>, Status> {
    let mut out: Vec<(String, String)> = env.into_iter().collect();
    if let Some((k, _)) = out
        .iter()
        .find(|(k, v)| k.is_empty() || k.contains(['=', '\0']) || v.contains('\0'))
    {
        return Err(invalid(format!("environment variable {k:?} is not valid")));
    }
    out.sort();
    Ok(out)
}

fn parse_args(args: Vec<String>, what: &str) -> Result<Vec<String>, Status> {
    if args.iter().any(|a| a.contains('\0')) {
        return Err(invalid(format!("{what} contains a NUL byte")));
    }
    Ok(args)
}

/// A create's template digest and volume (name and size), each optional.
type Extras = (Option<Digest>, Option<(VolumeName, VolumeGib)>);

/// A create's template digest (empty: none) and volume (name, and size defaulting to
/// 1 GiB).
fn parse_extras(r: &pb::CreateSandboxRequest) -> Result<Extras, Status> {
    let template = match r.template_digest.as_str() {
        "" => None,
        d => Some(d.parse::<Digest>().map_err(|e| invalid(e.to_string()))?),
    };
    let volume = match r.volume.as_str() {
        "" => None,
        n => {
            let name = n.parse::<VolumeName>().map_err(|e| invalid(e.to_string()))?;
            let gib = VolumeGib::try_from(r.volume_gib.max(1)).map_err(|e| invalid(e.to_string()))?;
            Some((name, gib))
        }
    };
    Ok((template, volume))
}

fn parse_create(r: pb::CreateSandboxRequest) -> Result<CreateRequest, Status> {
    let (id, key) = parse_target(&r.sandbox_id, &r.access_key)?;
    let size = Size::new(CpuHalves(r.cpu_halves), MemoryGib(r.memory_gib));
    if !size.is_nonzero() {
        return Err(invalid("cpu_halves and memory_gib must both be nonzero"));
    }
    let timeout = Duration::from_secs(u64::from(r.timeout_secs));
    if timeout.is_zero() || timeout > MAX_TIMEOUT {
        return Err(invalid(format!("timeout_secs {} is not 1 to 86400", r.timeout_secs)));
    }
    let (_, volume) = parse_extras(&r)?;
    Ok(CreateRequest {
        id,
        key,
        size,
        timeout,
        command: parse_args(r.command, "command")?,
        env: parse_env(r.env)?,
        template: None,
        volume,
    })
}

fn absolute(path: &str) -> Result<&str, Status> {
    if !path.starts_with('/') || path.contains('\0') {
        return Err(invalid(format!("path {path:?} is not absolute")));
    }
    Ok(path)
}

/// One exec'd process and how to end it.
struct Process {
    child: Child,
    live: Arc<Live>,
    pid_file: PathBuf,
}

impl CellApi {
    fn spawn(&self, live: Arc<Live>, args: &[String], env: &[(String, String)], cwd: &str) -> Result<Process, Status> {
        let n = self.execs.fetch_add(1, Ordering::Relaxed);
        let pid_file = sandbox::pid_file(&self.pids, &live.id, n);
        let child = self
            .sandboxes
            .spawn_exec(&live, args, env, cwd, &pid_file)
            .map_err(|e| refusal(&e))?;
        Ok(Process { child, live, pid_file })
    }

    fn authorize(&self, id: &str, key: &[u8]) -> Result<Arc<Live>, Status> {
        let (id, key) = parse_target(id, key)?;
        self.sandboxes.authorize(&id, &key).map_err(|e| refusal(&e))
    }
}

/// Copies `from` into `tx` as messages made by `wrap` until EOF or the receiver goes.
async fn pump<R, T>(mut from: R, tx: mpsc::Sender<Result<T, Status>>, wrap: impl Fn(Vec<u8>) -> T, mut first: impl FnMut())
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = vec![0u8; CHUNK];
    loop {
        match from.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                first();
                if tx.send(Ok(wrap(buf[..n].to_vec()))).await.is_err() {
                    return;
                }
            }
        }
    }
}

#[tonic::async_trait]
impl Cell for CellApi {
    async fn create_sandbox(
        &self,
        req: Request<pb::CreateSandboxRequest>,
    ) -> Result<Response<pb::CreateSandboxResponse>, Status> {
        let req = req.into_inner();
        // Before anything else: only a placement the control plane issued for this cell.
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let spend = match &self.passes {
            Passes::Unchecked => None,
            Passes::Refused => {
                return Err(refusal(&CellError::PlacementRefused("this cell holds no control-plane CA to check passes with".into())));
            }
            Passes::Checked(gate) => Some((gate, req.sandbox_id.clone(), gate.admit(&req, now).map_err(|e| refusal(&e))?)),
        };
        let (template, _) = parse_extras(&req)?;
        let mut create = parse_create(req)?;
        if let Some(digest) = template {
            let cache = self.templates.as_ref().ok_or_else(|| invalid("this cell has no template cache"))?;
            let cached = cache.get(digest, self.terms.dek()).await.map_err(|e| refusal(&CellError::Template(e)))?;
            create.template = Some(cached);
        }
        let policy = self
            .policies
            .current()
            .map_err(|why| refusal(&CellError::PolicyRefused(why)))?;
        let released = self
            .credentials
            .release(&policy, self.terms.dek())
            .await
            .map_err(|e| refusal(&CellError::Credentials(e)))?;
        let created = self
            .sandboxes
            .create(create, self.terms.get(), policy, released, self.terms.dek())
            .await
            .map_err(|e| refusal(&e))?;
        if let Some((gate, sandbox, exp)) = spend {
            gate.spend(&sandbox, exp, now);
        }
        Ok(Response::new(pb::CreateSandboxResponse {
            started_unix_ms: u64::try_from(
                created.started.duration_since(UNIX_EPOCH).unwrap_or_default().as_millis(),
            )
            .unwrap_or(u64::MAX),
            runsc_ms: u32::try_from(created.runsc.as_millis()).unwrap_or(u32::MAX),
        }))
    }

    type ExecStream = ReceiverStream<Result<pb::ExecResponse, Status>>;

    async fn exec(&self, req: Request<Streaming<pb::ExecRequest>>) -> Result<Response<Self::ExecStream>, Status> {
        let mut input = req.into_inner();
        let start = match input.message().await? {
            Some(pb::ExecRequest {
                msg: Some(pb::exec_request::Msg::Start(s)),
            }) => s,
            _ => return Err(invalid("the first Exec message must be ExecStart")),
        };
        let live = self.authorize(&start.sandbox_id, &start.access_key)?;
        let args = parse_args(start.args, "args")?;
        if args.is_empty() {
            return Err(invalid("args is empty"));
        }
        let env = parse_env(start.env)?;
        let cwd = if start.cwd.is_empty() { "/".to_owned() } else { absolute(&start.cwd)?.to_owned() };
        let first = live.claim_first_exec();
        let mut p = self.spawn(Arc::clone(&live), &args, &env, &cwd)?;
        let (tx, rx) = mpsc::channel(32);

        // stdin: from the request stream until stdin_eof or the stream ends.
        let mut stdin = p.child.stdin.take().expect("stdin is piped");
        tokio::spawn(async move {
            while let Some(Ok(msg)) = input.next().await {
                match msg.msg {
                    Some(pb::exec_request::Msg::Stdin(data)) if stdin.write_all(&data).await.is_ok() => {}
                    Some(pb::exec_request::Msg::Stdin(_) | pb::exec_request::Msg::StdinEof(_)) => break,
                    _ => {}
                }
            }
            drop(stdin);
        });

        let since_create = Arc::new(AtomicU64::new(0));
        let out = p.child.stdout.take().expect("stdout is piped");
        let err = p.child.stderr.take().expect("stderr is piped");
        let stdout = tokio::spawn(pump(
            out,
            tx.clone(),
            |d| pb::ExecResponse {
                msg: Some(pb::exec_response::Msg::Stdout(d)),
            },
            {
                let (since, live) = (Arc::clone(&since_create), Arc::clone(&live));
                move || {
                    if first && since.load(Ordering::Relaxed) == 0 {
                        let ms = u64::try_from(live.since_create().as_millis()).unwrap_or(u64::MAX).max(1);
                        since.store(ms, Ordering::Relaxed);
                    }
                }
            },
        ));
        let stderr = tokio::spawn(pump(
            err,
            tx.clone(),
            |d| pb::ExecResponse {
                msg: Some(pb::exec_response::Msg::Stderr(d)),
            },
            || {},
        ));
        let sandboxes = Arc::clone(&self.sandboxes);
        let timeout = (start.timeout_secs > 0).then(|| Duration::from_secs(u64::from(start.timeout_secs)));
        tokio::spawn(async move {
            let killer = async {
                match timeout {
                    Some(t) => tokio::time::sleep(t).await,
                    None => std::future::pending().await,
                }
            };
            let status = tokio::select! {
                s = p.child.wait() => s.ok(),
                () = killer => None,
                () = tx.closed() => None,
            };
            let status = match status {
                Some(s) => Some(s),
                None => {
                    // Timed out, or the client went away: end the process in the sandbox.
                    sandboxes.kill_exec(&p.live, &p.pid_file).await;
                    p.child.wait().await.ok()
                }
            };
            let _ = tokio::fs::remove_file(&p.pid_file).await;
            let _ = stdout.await;
            let _ = stderr.await;
            let code = status.map_or(-1, exit_code);
            // A process that ended because its sandbox did reports how the sandbox ended.
            // runsc exec answers 128 when the sandbox went away under it (the host's OOM
            // killer, for example) before the watcher has noticed.
            let ended = if p.live.ending() || code == 128 || code < 0 {
                tokio::time::timeout(Duration::from_secs(if p.live.ending() { 30 } else { 3 }), p.live.ended())
                    .await
                    .map_or(pb::ExitKind::Unspecified, |k| k.proto())
            } else {
                pb::ExitKind::Unspecified
            };
            let _ = tx
                .send(Ok(pb::ExecResponse {
                    msg: Some(pb::exec_response::Msg::Exit(pb::ExecExit {
                        code,
                        first_exec_ms: u32::try_from(since_create.load(Ordering::Relaxed)).unwrap_or(u32::MAX),
                        sandbox_ended: ended.into(),
                    })),
                }))
                .await;
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    type ReadFileStream = ReceiverStream<Result<pb::FileChunk, Status>>;

    async fn read_file(&self, req: Request<pb::ReadFileRequest>) -> Result<Response<Self::ReadFileStream>, Status> {
        let r = req.into_inner();
        let live = self.authorize(&r.sandbox_id, &r.access_key)?;
        let path = absolute(&r.path)?.to_owned();
        let mut p = self.spawn(live, &["/bin/cat".to_owned(), path.clone()], &[], "/")?;
        drop(p.child.stdin.take());
        let (tx, rx) = mpsc::channel(32);
        let out = p.child.stdout.take().expect("stdout is piped");
        let mut err = p.child.stderr.take().expect("stderr is piped");
        tokio::spawn(async move {
            let mut stderr = Vec::new();
            let (_, _, status) = tokio::join!(
                pump(out, tx.clone(), |data| pb::FileChunk { data }, || {}),
                err.read_to_end(&mut stderr),
                p.child.wait(),
            );
            let _ = tokio::fs::remove_file(&p.pid_file).await;
            if !status.is_ok_and(|s| s.success()) {
                let why = String::from_utf8_lossy(&stderr).trim().to_owned();
                let _ = tx.send(Err(refusal(&CellError::NoSuchFile(format!("{path}: {why}"))))).await;
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn write_file(
        &self,
        req: Request<Streaming<pb::WriteFileRequest>>,
    ) -> Result<Response<pb::WriteFileResponse>, Status> {
        let mut input = req.into_inner();
        let header = match input.message().await? {
            Some(pb::WriteFileRequest {
                msg: Some(pb::write_file_request::Msg::Header(h)),
            }) => h,
            _ => return Err(invalid("the first WriteFile message must be the header")),
        };
        let live = self.authorize(&header.sandbox_id, &header.access_key)?;
        let path = absolute(&header.path)?.to_owned();
        let args = ["/bin/sh", "-c", "cat > \"$1\"", "sh", &path].map(str::to_owned);
        let mut p = self.spawn(live, &args, &[], "/")?;
        let mut stdin = p.child.stdin.take().expect("stdin is piped");
        let mut written = 0u64;
        while let Some(msg) = input.message().await? {
            if let Some(pb::write_file_request::Msg::Data(d)) = msg.msg {
                stdin.write_all(&d).await.map_err(|e| invalid(format!("writing {path}: {e}")))?;
                written += d.len() as u64;
            }
        }
        drop(stdin);
        let out = p.child.wait_with_output().await.map_err(|e| invalid(e.to_string()))?;
        let _ = tokio::fs::remove_file(&p.pid_file).await;
        if !out.status.success() {
            return Err(invalid(format!(
                "writing {path}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(Response::new(pb::WriteFileResponse { bytes_written: written }))
    }

    async fn kill(&self, req: Request<pb::KillRequest>) -> Result<Response<pb::Receipt>, Status> {
        let r = req.into_inner();
        let (id, key) = parse_target(&r.sandbox_id, &r.access_key)?;
        let receipt = self.sandboxes.kill(&id, &key).await.map_err(|e| refusal(&e))?;
        Ok(Response::new(proto_receipt(receipt)))
    }

    async fn get_receipt(&self, req: Request<pb::GetReceiptRequest>) -> Result<Response<pb::Receipt>, Status> {
        let r = req.into_inner();
        let (id, key) = parse_target(&r.sandbox_id, &r.access_key)?;
        let receipt = self.sandboxes.receipt(&id, &key).map_err(|e| refusal(&e))?;
        Ok(Response::new(proto_receipt(receipt)))
    }

    async fn drain(&self, req: Request<pb::DrainRequest>) -> Result<Response<pb::DrainResponse>, Status> {
        // rustls verified any client certificate against the control-plane CA; Drain
        // needs one.
        if req.peer_certs().is_none_or(|c| c.is_empty()) {
            return Err(refusal(&CellError::NotControlPlane));
        }
        self.drain.send_if_modified(|d| {
            let start = *d == DrainState::Serving;
            if start {
                *d = DrainState::Draining;
            }
            start
        });
        status("drain", json!({ "sandboxes": self.sandboxes.count() }));
        Ok(Response::new(pb::DrainResponse {
            sandboxes: u32::try_from(self.sandboxes.count()).unwrap_or(u32::MAX),
        }))
    }
}

fn proto_receipt(r: sandbox::Receipt) -> pb::Receipt {
    pb::Receipt {
        json: r.json,
        signature: r.signature,
        exit_kind: r.kind.into(),
        cell_cert: r.cell_cert,
        r#final: r.last,
    }
}

/// The exit status, or 128 + signal.
fn exit_code(s: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    s.code().unwrap_or_else(|| 128 + s.signal().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create(id: &str, key: usize, cpu: u32, mem: u32, timeout: u32) -> pb::CreateSandboxRequest {
        pb::CreateSandboxRequest {
            sandbox_id: id.into(),
            access_key: vec![1; key],
            cpu_halves: cpu,
            memory_gib: mem,
            timeout_secs: timeout,
            command: vec![],
            env: Default::default(),
            template_digest: String::new(),
            volume: String::new(),
            volume_gib: 0,
            placement_pass: String::new(),
        }
    }

    fn reason(s: &Status) -> &str {
        s.metadata().get("clovelly-error").and_then(|v| v.to_str().ok()).unwrap_or("")
    }

    /// The phase 20 review's A1 and the audit's 2.1.1, as decided 2026-11-11 (1A): a cell with a
    /// control plane creates a sandbox only with a pass the control plane's CA vouches for,
    /// for this cell and exactly this sandbox, size and timeout, once.
    #[test]
    fn a_create_without_the_control_planes_placement_is_refused() {
        use common::pass::{PASS_SIGNING, PassClaims, PassSigner};
        use der::Encode;
        use rcgen::{BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, Issuer, KeyPair};
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let pass_key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["pass".into()]).unwrap();
        let project: common::pass::Project = "210987654321".parse().unwrap();
        params.distinguished_name.push(DnType::CommonName, common::pass::subject_name(project));
        let eku = x509_cert::ext::pkix::ExtendedKeyUsage(vec![PASS_SIGNING]).to_der().unwrap();
        params.custom_extensions = vec![CustomExtension::from_oid_content(&[2, 5, 29, 37], eku)];
        let signer = PassSigner::from_der(params.signed_by(&pass_key, &issuer).unwrap().der(), &pass_key.serialize_der()).unwrap();
        let checker = PassChecker::from_ca_pem(&common::b64::pem("CERTIFICATE", ca.der()), project).unwrap();
        let cell = "clovelly-1a2b3c4d.us-central1-a.a.acme.cells.clovelly.internal";
        let gate = PassGate::new(checker, cell.into());
        let now = 1_800_000_000;
        let id = SandboxId::generate().to_string();
        let pass = |sandbox: &str, timeout: u32| {
            signer
                .sign(&PassClaims { v: 1, cell: cell.into(), sandbox: sandbox.into(), cpu_halves: 2, memory_gib: 2, timeout_secs: timeout, exp: now + 600 })
                .unwrap()
        };
        let with = |p: String| pb::CreateSandboxRequest { placement_pass: p, ..create(&id, 32, 2, 2, 900) };
        let refused = |r: Result<u64, CellError>| reason(&refusal(&r.unwrap_err())).to_owned();
        assert_eq!(refused(gate.admit(&create(&id, 32, 2, 2, 900), now)), "PLACEMENT_REFUSED", "no pass");
        assert_eq!(refused(gate.admit(&with(pass(&SandboxId::generate().to_string(), 900)), now)), "PLACEMENT_REFUSED", "another sandbox's");
        assert_eq!(refused(gate.admit(&with(pass(&id, 86_400)), now)), "PLACEMENT_REFUSED", "a longer timeout than asked");
        assert_eq!(refused(gate.admit(&with(pass(&id, 900)), now + 3600)), "PLACEMENT_REFUSED", "expired");
        // A create that fails after the check spends nothing (the review's A5); one that
        // succeeds spends the pass.
        let exp = gate.admit(&with(pass(&id, 900)), now).unwrap();
        gate.admit(&with(pass(&id, 900)), now).unwrap();
        gate.spend(&id, exp, now);
        assert_eq!(refused(gate.admit(&with(pass(&id, 900)), now)), "PLACEMENT_REFUSED", "used once");
        assert_eq!(refusal(&CellError::PlacementRefused(String::new())).code(), tonic::Code::PermissionDenied);
    }

    /// Criterion 14: an id of another length is a typed error at the API, before
    /// anything reaches runsc.
    #[test]
    fn the_api_refuses_a_bad_sandbox_id_with_a_typed_error() {
        let ok = SandboxId::generate().to_string();
        assert!(parse_create(create(&ok, 32, 2, 2, 60)).is_ok());
        for bad in ["", "lat20-00001", &ok[..31], &format!("{ok}0"), &ok.to_uppercase()] {
            let e = parse_create(create(bad, 32, 2, 2, 60)).err().unwrap();
            assert_eq!(e.code(), tonic::Code::InvalidArgument);
            assert_eq!(reason(&e), "INVALID_SANDBOX_ID", "{bad:?}");
        }
        let e = parse_target("x", &[0; 32]).err().unwrap();
        assert_eq!(reason(&e), "INVALID_SANDBOX_ID");
    }

    #[test]
    fn creates_need_a_key_a_size_and_a_timeout() {
        let id = SandboxId::generate().to_string();
        for (key, cpu, mem, timeout) in [(31, 2, 2, 60), (32, 0, 2, 60), (32, 2, 0, 60), (32, 2, 2, 0), (32, 2, 2, 86_401)] {
            let e = parse_create(create(&id, key, cpu, mem, timeout)).err().unwrap();
            assert_eq!(reason(&e), "INVALID_REQUEST");
        }
        assert!(parse_create(create(&id, 32, 1, 1, 86_400)).is_ok());
    }

    #[test]
    fn templates_and_volumes_are_parsed_at_the_boundary() {
        let id = SandboxId::generate().to_string();
        let mut r = create(&id, 32, 2, 2, 60);
        r.template_digest = common::template::Digest::of(b"t").hex();
        r.volume = "data".into();
        let (t, v) = parse_extras(&r).unwrap();
        assert_eq!(t, Some(common::template::Digest::of(b"t")));
        assert_eq!(v.map(|(n, g)| (n.to_string(), g.get())), Some(("data".into(), 1)));
        for (digest, volume, gib) in [("abc", "", 0), ("", "Bad Name", 0), ("", "data", 21)] {
            let mut r = create(&id, 32, 2, 2, 60);
            (r.template_digest, r.volume, r.volume_gib) = (digest.into(), volume.into(), gib);
            assert_eq!(reason(&parse_extras(&r).err().unwrap()), "INVALID_REQUEST", "{digest:?} {volume:?} {gib}");
        }
    }

    #[test]
    fn environment_and_paths_are_checked() {
        let bad = std::collections::HashMap::from([("A=B".to_owned(), "c".to_owned())]);
        assert!(parse_env(bad).is_err());
        let ok = std::collections::HashMap::from([("A".to_owned(), "b=c".to_owned())]);
        assert_eq!(parse_env(ok).unwrap(), vec![("A".to_owned(), "b=c".to_owned())]);
        assert!(absolute("work/x").is_err());
        assert!(absolute("/work/x").is_ok());
    }
}
