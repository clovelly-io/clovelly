//! `cell-agent` without arguments (prod) or `cell-agent boot` (test image): the boot
//! sequence, then the cell until it ends.
//!
//! After the unlock the agent starts the egress proxy with a fresh in-cell CA and the
//! nftables rules that make it the sandboxes' only way out, puts the unlock's policy
//! bundle in force (polling the verifier for newer ones), serves the cell API on :443,
//! reports to the control plane (when the metadata names one) and holds the lease. The cell ends at the first of:
//! the lease lapsing (every sandbox ends `revoked`), the cell's cap (any sandbox left
//! ends `cell_end`), a drain completing, or the listener failing. It then reports
//! `RECYCLE` so the control plane deletes it, and exits.
//!
//! Progress goes to stdout as `CLOVELLY-AGENT <state> <json>` lines; nothing secret is
//! printed. Exit codes: 0 cell end, 3 refused to start, 4 refused by the verifier,
//! 5 no unlock before the deadline, 6 any other failure. PID 1 powers the VM off when
//! the agent exits, which recycles the cell.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::time::SystemTime;

use anyhow::Context;
use common::b64;
use common::ccel;
use common::evidence::Evidence;
use common::proto::cell::cell_server::CellServer;
use common::proto::control::DrainState;
use common::sandbox::CpuShare;
use common::proto::health::health_server::HealthServer;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::watch;
use tonic::transport::Server;

use egress_proxy::{Network, Ports, Supervisor, SupervisorConfig};

use crate::boot::{self, BootConfig, CellKey, Prepull, TsmQuoter, UnlockFailure, Unlocked};
use crate::cellapi::CellApi;
use crate::credentials;
use crate::net::{self, Slots};
use crate::policies::{self, Policies};
use crate::grpc::GrpcVerifier;
use crate::lease::{self, SharedTerms};
use crate::listener::{self, Serving};
use crate::report::{self, Reported};
use crate::receipts::{Log, Signer};
use crate::runsc::{Cgroups, NetworkMode, Runsc};
use crate::sandbox::{Egress, EndKind, Identity, Paths, Receipting, Sandboxes};
use crate::storage::Locator;
use crate::templates::Templates;
use crate::volumes::{self, Volumes};
use crate::{cgroup, tls};

/// The control-plane CA, baked into the image (Drain's client certificates and the
/// control plane's cell-channel certificate chain to it).
pub const CONTROL_PLANE_CA: &str = "/clovelly/control-plane-ca.pem";
/// How long a cell ending in order waits for the log to confirm its final receipts: two of the
/// log's retries and a slow verifier.
const RECEIPTS_AT_END: std::time::Duration = std::time::Duration::from_secs(30);
const BASE_ROOTFS: &str = "/run/clovelly/base/rootfs";
const RUNSC_STATE: &str = "/run/clovelly/runsc";
const BUNDLES: &str = "/run/clovelly/bundles";
const PIDS: &str = "/run/clovelly/pids";
/// The template cache and the volumes' images (tmpfs).
const TEMPLATES: &str = "/run/clovelly/templates";
const VOLUMES: &str = "/run/clovelly/volumes";
/// The public roots in the image: what destinations and resolvers must chain to, and
/// what sandboxes trust besides the in-cell CA.
const ROOTS: &str = "/etc/ssl/certs/ca-certificates.crt";
/// The egress proxy's binary in the image.
pub const PROXY_BIN: &str = "/bin/egress-proxy";
/// Every sandbox's trust store: the public roots and the in-cell CA.
const TRUST_STORE: &str = "/run/clovelly/egress/ca-certificates.crt";

/// `cell-agent boot` options.
#[derive(Debug, Default)]
pub struct Options {
    /// After a refusal or the deadline, keep the process (wiped) for a memory scan.
    pub hold_on_failure: bool,
    /// After the cell ends (keys wiped, sandboxes ended), wait for a line on stdin
    /// before reporting `RECYCLE` and exiting, so the test harness can scan memory.
    pub hold_on_end: bool,
    /// Write the unlock evidence here (test image, for the corpus).
    pub evidence: Option<PathBuf>,
}

pub fn status(state: &str, detail: serde_json::Value) {
    println!("CLOVELLY-AGENT {state} {detail}");
}

/// Writes evidence as the corpus tool reads it: the raw quote and CCEL and the claims.
pub fn save_evidence(dir: &Path, ev: &Evidence, at: u64) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("quote.bin"), &ev.quote)?;
    std::fs::write(dir.join("ccel-table.bin"), &ev.ccel_table)?;
    std::fs::write(dir.join("ccel-log.bin"), &ev.ccel_log)?;
    let claims = json!({
        "env": ev.env.as_str(),
        "subenv": ev.subenv.as_str(),
        "release": ev.release.as_str(),
        "spki": b64::encode(ev.spki.der()),
        "nonce": common::hex(&ev.nonce.0),
        "instance_id": ev.instance_id,
        "zone": ev.zone.as_str(),
        "at": at,
    });
    std::fs::write(dir.join("evidence.json"), format!("{claims:#}\n"))
}

fn hold() -> ! {
    loop {
        std::thread::park();
    }
}

pub async fn run(opts: Options) -> anyhow::Result<ExitCode> {
    // The cell's forwarding rule appears once the control plane has created it; the
    // cell reports ready only when its address is routed.
    let routed = Arc::new(AtomicBool::new(false));
    let (own_tx, own) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(crate::forwarded::keep_routes(Arc::clone(&routed), Some(own_tx)));
    let integrity = match tokio::task::spawn_blocking(boot::integrity).await? {
        Ok(i) => i,
        Err(refusal) => {
            status("refused-start", json!({ "reason": refusal.to_string() }));
            return Ok(ExitCode::from(3));
        }
    };
    status(
        "integrity",
        json!({
            "rtmr": integrity.rtmrs.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "events": integrity.events,
            "root_hash": integrity.root_hash,
        }),
    );
    let cfg = tokio::task::spawn_blocking(BootConfig::from_metadata).await??;
    let key = Arc::new(CellKey::generate());
    let table = std::fs::read(ccel::TABLE_PATH).context(ccel::TABLE_PATH)?;
    let log = std::fs::read(ccel::LOG_PATH).context(ccel::LOG_PATH)?;
    let mut api = GrpcVerifier::new(&cfg.verifier)?;
    status(
        "unlocking",
        json!({ "verifier": cfg.verifier, "release": cfg.release.as_str(), "deadline_s": cfg.deadline.as_secs() }),
    );
    let failure = match boot::unlock(&cfg, &key, &mut api, &TsmQuoter, (&table, &log), cfg.deadline).await {
        Ok(unlocked) => {
            if let Some(dir) = &opts.evidence {
                save_evidence(dir, &unlocked.evidence, boot::unix(unlocked.at))?;
            }
            status(
                "unlocked",
                json!({
                    "cell_cert": b64::encode(&unlocked.cell_cert),
                    "policy_bundle": String::from_utf8_lossy(&unlocked.policy_bundle),
                    "policy_sig": unlocked.policy_sig,
                    "expires": boot::unix(unlocked.expires),
                    "valid_until": boot::unix(unlocked.valid_until),
                }),
            );
            return serve(cfg, key, api, (table, log), unlocked, (routed, own), &opts).await;
        }
        Err(f) => f,
    };
    let code = match &failure {
        UnlockFailure::Refused(check, ev) => {
            if let Some(dir) = &opts.evidence {
                save_evidence(dir, ev, boot::unix(SystemTime::now()))?;
            }
            status("refused", json!({ "check": check }));
            4
        }
        UnlockFailure::Deadline(d, last) => {
            status("gave-up", json!({ "after_s": d.as_secs(), "last_error": last }));
            5
        }
        other => {
            status("failed", json!({ "error": other.to_string() }));
            6
        }
    };
    drop(failure);
    drop(key);
    if opts.hold_on_failure {
        status("holding", json!({ "pid": std::process::id() }));
        hold();
    }
    Ok(ExitCode::from(code))
}

/// Starts the egress proxy as its own process with a fresh in-cell CA (its supervisor
/// restarts it with the same CA if it dies), writes the sandboxes' trust store,
/// installs the nftables rules and hands the proxy the cell's own addresses as they are
/// routed. The proxy never receives the DEK.
async fn start_proxy(cfg: &BootConfig, mut own: UnboundedReceiver<Ipv4Addr>) -> anyhow::Result<Arc<Supervisor>> {
    let roots = std::fs::read_to_string(ROOTS).context(ROOTS)?;
    let upstream_roots = format!("{roots}\n{}", test_upstream_ca().unwrap_or_default());
    let proxy = Supervisor::start(SupervisorConfig {
        bin: PROXY_BIN.into(),
        roots_pem: upstream_roots,
        cell: cfg.instance_id.to_string(),
        network: Network::default(),
        status: Box::new(status),
    })
    .await?;
    let store = Path::new(TRUST_STORE);
    std::fs::create_dir_all(store.parent().expect("the trust store has a directory"))?;
    std::fs::write(store, format!("{roots}\n{}", proxy.ca_pem())).context(TRUST_STORE)?;
    net::setup_cell(Ports::CELL).await?;
    let supervisor = Arc::clone(&proxy);
    tokio::spawn(async move {
        while let Some(ip) = own.recv().await {
            supervisor.add_own(ip).await;
        }
    });
    status("proxy", json!({ "ports": format!("{:?}", Ports::CELL), "pid": proxy.pid() }));
    Ok(proxy)
}

/// Test image only: an extra certificate the proxy trusts for destinations, from
/// metadata `clovelly-test-upstream-ca` (hex DER): the test destination's self-signed
/// certificate, so HTTP/2 to it can be inspected (phase 4 criterion 14). The prod image
/// never reads it, and sandboxes never trust it.
fn test_upstream_ca() -> Option<String> {
    if std::fs::read_to_string("/clovelly/variant").ok()?.trim() != "test" {
        return None;
    }
    let der = common::unhex(crate::metadata::attribute("clovelly-test-upstream-ca").ok()??.trim())?;
    status("test-upstream-ca", json!({ "bytes": der.len() }));
    Some(b64::pem("CERTIFICATE", &der))
}

/// Why the cell ended.
#[derive(Debug)]
enum Ending {
    Lapsed(lease::Lapsed),
    CellEnd,
    Drained,
    Listener(String),
}

/// Serves the cell from its first lease until it ends.
async fn serve(
    cfg: BootConfig,
    key: Arc<CellKey>,
    mut api: GrpcVerifier,
    (table, log): (Vec<u8>, Vec<u8>),
    first: Unlocked,
    (routed, own): (Arc<AtomicBool>, UnboundedReceiver<Ipv4Addr>),
    opts: &Options,
) -> anyhow::Result<ExitCode> {
    let machine = cgroup::machine()?;
    let placeable = cgroup::placeable(machine);
    cgroup::setup(placeable)?;
    for dir in [BUNDLES, PIDS] {
        std::fs::create_dir_all(dir).with_context(|| dir.to_owned())?;
    }
    let proxy = start_proxy(&cfg, own).await?;
    let policies = Policies::new(cfg.env.clone(), cfg.subenv.clone(), placeable, &first.policy_key);
    let _ = policies.offer(&first.policy_bundle, &first.policy_sig, "unlock");
    // The sharing factor is the unlock's bundle's, fixed for the cell's life, so the
    // capacity the control plane sees never changes under it (SPEC.md phase 13). A refused
    // unlock bundle leaves the cell dedicated; it creates nothing until a bundle arrives.
    let cpu_share = policies.current().map_or(CpuShare::DEDICATED, |p| p.cpu_share);
    tokio::spawn(policies::poll(Arc::clone(&policies), api.clone()));
    let control_ca_pem = std::fs::read(CONTROL_PLANE_CA).ok();
    let channel = match (&cfg.control_plane, &control_ca_pem) {
        (Some(url), Some(ca)) => Some(report::client(url, ca)?),
        _ => None,
    };
    let locator = Arc::new(Locator::new(channel.clone(), cfg.instance_id, cfg.zone.to_string()));
    let templates = Arc::new(Templates::new(Arc::clone(&locator), cfg.env.clone(), cfg.subenv.clone(), TEMPLATES.into(), BASE_ROOTFS.into()));
    let volumes = channel
        .is_some()
        .then(|| Arc::new(Volumes::new(Arc::clone(&locator), cfg.env.clone(), cfg.subenv.clone(), VOLUMES.into())));
    let signer = Arc::new(Signer::new(&key, &first.cell_cert, &first.evidence.quote)?);
    let receipt_log = Log::new(Some(api.clone()));
    let cell_end = first.at + cfg.cap;
    let identity = Identity {
        cpu_share,
        env: cfg.env.clone(),
        subenv: cfg.subenv.clone(),
        release: cfg.release.clone(),
        instance_id: cfg.instance_id,
        zone: cfg.zone.clone(),
        project: cfg.project.clone(),
    };
    let sandboxes = Sandboxes::new(
        Runsc {
            bin: "runsc".into(),
            state: RUNSC_STATE.into(),
            cgroups: Cgroups::Enforce,
            network: NetworkMode::Sandbox,
        extra: Vec::new(),
        },
        Paths {
            rootfs: BASE_ROOTFS.into(),
            bundles: BUNDLES.into(),
            binds: Vec::new(),
        },
        placeable,
        identity,
        Some(Egress {
            proxy,
            slots: Arc::new(Slots::default()),
            trust_store: TRUST_STORE.into(),
            mtu: net::MTU,
        }),
        volumes.clone(),
        Receipting { signer: Arc::clone(&signer), log: Arc::clone(&receipt_log) },
    );
    tokio::spawn(Arc::clone(&receipt_log).run({
        let sandboxes = Arc::clone(&sandboxes);
        move || sandboxes.wills()
    }));
    if let Some(vols) = &volumes {
        let (vols, receipt_log) = (Arc::clone(vols), Arc::clone(&receipt_log));
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(volumes::COMMIT_EVERY);
            tick.tick().await;
            loop {
                tick.tick().await;
                // The last-will records name the new epoch at once.
                if vols.commit_all().await {
                    receipt_log.flush_soon();
                }
            }
        });
    }
    let terms = SharedTerms::new(&first, cell_end);
    let certs = tls::CertSwap::new(&first.cell_cert, &key)?;
    let control_cas = control_ca_pem
        .as_deref()
        .and_then(|pem| b64::pem_blocks(std::str::from_utf8(pem).ok()?, "CERTIFICATE").ok())
        .unwrap_or_default();
    let tls_config = Arc::new(tls::server_config(Arc::clone(&certs), &control_cas)?);
    let (drain_tx, drain_rx) = watch::channel(DrainState::Serving);
    let cell_api = CellApi {
        sandboxes: Arc::clone(&sandboxes),
        terms: Arc::clone(&terms),
        policies: Arc::clone(&policies),
        credentials: Arc::new(credentials::Store {
            client: channel.clone(),
            instance_id: cfg.instance_id,
            zone: cfg.zone.clone(),
            env: cfg.env.clone(),
            subenv: cfg.subenv.clone(),
        }),
        drain: drain_tx.clone(),
        pids: PIDS.into(),
        execs: AtomicU64::new(0),
        templates: Some(Arc::clone(&templates)),
    };
    let listener = TcpListener::bind(("0.0.0.0", listener::PORT)).await?;
    let mut server = tokio::spawn(
        Server::builder()
            .http2_keepalive_interval(Some(std::time::Duration::from_secs(30)))
            .add_service(HealthServer::new(Serving))
            .add_service(CellServer::new(cell_api))
            .serve_with_incoming(tls::incoming(listener, tls_config)),
    );
    // Boot step 7: the policy's templates are fetched on first use, or before the first
    // ready report when the pool asks for it (`clovelly-prepull=boot`).
    if let Ok(policy) = policies.current()
        && !policy.templates.is_empty()
    {
        let fetch = {
            let (templates, terms, digests) = (Arc::clone(&templates), Arc::clone(&terms), policy.templates.clone());
            async move {
                let started = std::time::Instant::now();
                for d in digests {
                    if let Err(e) = templates.get(d, terms.dek()).await {
                        status("prepull-failed", json!({ "digest": d.hex(), "error": e.to_string() }));
                    }
                }
                status("prepulled", json!({ "templates": templates.resident().len(), "ms": started.elapsed().as_millis() as u64 }));
            }
        };
        match cfg.prepull {
            Prepull::AtBoot => fetch.await,
            Prepull::OnFirstUse => status("prepull-deferred", json!({ "templates": policy.templates.len() })),
        }
    }
    let reported = Reported {
        sandboxes: Arc::clone(&sandboxes),
        terms: Arc::clone(&terms),
        drain: drain_rx.clone(),
        ready: routed,
        cpu_share,
    };
    let reporter = match (channel, &control_ca_pem) {
        (Some(client), _) => Some(tokio::spawn(report::run(cfg.clone(), client, reported))),
        (None, None) if cfg.control_plane.is_some() => {
            status("no-control-plane-ca", json!({ "path": CONTROL_PLANE_CA }));
            None
        }
        (None, _) => None,
    };
    status(
        "serving",
        json!({
            "placeable": { "cpu": placeable.cpu.vcpus(), "memory_gib": placeable.memory.0 },
            "cpu_share": cpu_share.get(),
            "capacity": { "cpu": sandboxes.capacity().cpu.vcpus(), "memory_gib": sandboxes.capacity().memory.0 },
            "cell_end": boot::unix(cell_end),
            "control_plane": cfg.control_plane,
        }),
    );

    let mut keeper = {
        let (cfg, key, certs, terms, policies, signer) =
            (cfg.clone(), Arc::clone(&key), Arc::clone(&certs), Arc::clone(&terms), Arc::clone(&policies), Arc::clone(&signer));
        tokio::spawn(async move {
            let on_renewal = lease::apply(&certs, &key, &terms, &policies, &signer);
            lease::keep(&cfg, &key, &mut api, &TsmQuoter, (&table, &log), first, on_renewal).await
        })
    };
    let drained = {
        let (sandboxes, mut drain) = (Arc::clone(&sandboxes), drain_rx.clone());
        async move {
            let _ = drain.wait_for(|d| *d == DrainState::Draining).await;
            sandboxes.drain().await;
        }
    };
    let cap = tokio::time::Instant::now() + cell_end.duration_since(SystemTime::now()).unwrap_or_default();
    let ending = tokio::select! {
        r = &mut keeper => match r {
            Ok(lapsed) => Ending::Lapsed(lapsed),
            Err(e) => Ending::Listener(format!("lease keeper: {e}")),
        },
        () = tokio::time::sleep_until(cap) => Ending::CellEnd,
        () = drained => Ending::Drained,
        r = &mut server => Ending::Listener(format!("{r:?}")),
    };
    // On a lapse the keeper has dropped the lease, wiping its DEK; otherwise aborting
    // the keeper drops it.
    if !keeper.is_finished() {
        keeper.abort();
        let _ = (&mut keeper).await;
    }
    match &ending {
        Ending::Lapsed(l) => {
            sandboxes.end_all(EndKind::Revoked).await;
            terms.revoke();
            status(
                "revoked",
                json!({ "last_error": l.last, "expires": boot::unix(terms.expires()), "at": boot::unix(SystemTime::now()) }),
            );
        }
        Ending::CellEnd => {
            sandboxes.end_all(EndKind::CellEnd).await;
            status("cell-end", json!({}));
        }
        Ending::Drained => status("drained", json!({})),
        Ending::Listener(e) => {
            sandboxes.end_all(EndKind::Killed).await;
            status("listener-stopped", json!({ "error": e }));
        }
    }
    // Every sandbox has ended: the sub-environment DEK goes at cell end, whatever ended
    // it (criterion 12), not only when the lease lapses.
    terms.revoke();
    if opts.hold_on_end {
        status("ended", json!({ "pid": std::process::id() }));
        let mut line = String::new();
        let _ = tokio::task::spawn_blocking(move || std::io::stdin().read_line(&mut line)).await;
    }
    // The report below lets the control plane delete this VM: the log has every final record
    // first, or those sandboxes' last wills stand as `cell_lost`.
    if !receipt_log.delivered(RECEIPTS_AT_END).await {
        status("receipts-undelivered-at-end", json!({}));
    }
    drain_tx.send_replace(DrainState::Recycle);
    if let Some(reporter) = reporter {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(70), reporter).await;
    }
    drop(drain_tx);
    status("exit", json!({ "ending": format!("{ending:?}") }));
    Ok(ExitCode::SUCCESS)
}
