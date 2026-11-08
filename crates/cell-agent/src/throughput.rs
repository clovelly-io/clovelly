//! Phase 3 criterion 8 on the test image (`harness --tests throughput --peer IP:80`):
//! egress throughput on the production path, sandbox → egress proxy → a destination VM
//! in the same zone (`cell-agent dest`, its `/sink`), and first the diagnosis of phase
//! 0's retransmissions on its own path.
//!
//! 1. Diagnosis, in SPEC.md's order, on phase 0's path (the sandbox's netstack → veth →
//!    masquerade → gve, no proxy), 5 transfers of 100 MB per variant: the phase 0
//!    configuration; conntrack told to accept out-of-window segments
//!    (`nf_conntrack_tcp_be_liberal=1`), with conntrack's `invalid` count read around
//!    every variant; netstack's segmentation offload off (`--gso=false
//!    --software-gso=false`, if this runsc has them); the veth at 1500 against gve's 1460.
//!    Retransmitted segments per GB come from the sandbox's own netstack (the sender);
//!    the destination's DSACK count (its `/netstat`) says how many of them repeated
//!    data it already had. Then a variant the spec does not list, found while
//!    diagnosing: netstack's RACK-TLP loss detection off (`tcp_recovery=0` inside the
//!    sandbox) on phase 0's path, and on the production path at a full cell the
//!    kernel's default input backlog and RACK-TLP on (runsc's default, which a cell's
//!    sandboxes turn off).
//! 2. The production path, with the cell's own code (the proxy, the per-sandbox
//!    namespaces and nftables, `Sandboxes::create`, so RACK-TLP off): 10 transfers of
//!    100 MB from one sandbox of 1 vCPU; then 10 from each sandbox of a full cell at once
//!    (as many of 0.5 vCPU and 2 GiB as it places: 14 on a c3-standard-8, 171 on a
//!    c3-standard-88); then at least
//!    2,000 connections held at once, spread over a full cell. Per hop:
//!    sandbox → proxy retransmissions from inside each sandbox, proxy → destination from
//!    the cell's host stack, each with its receiver's DSACK count (the cell's, the
//!    destination's). The hop target (under 100 per GB) is judged at both loads.
//! 3. If a transfer is slower than 3× the median, decision 6's fallback (runsc's host
//!    network in the same namespaces, the same nftables rules) is measured the same way.
//!
//! `throughput-cell` (phase 11 criterion 9, on the big cell) runs step 2 alone, on
//! netstack, with step 3 only if it stalls: [`Scope::Production`].
//!
//! The destination is the peer VM's internal address, allowed by this harness's proxy
//! guard only (cells never allow a non-public address): reaching it through Cloud NAT
//! would cap concurrent connections at the NAT's per-VM port allocation.

use std::collections::{BTreeSet, HashMap};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _};
use common::bundle::Policy;
use common::ids::SandboxId;
use common::sandbox::{CpuHalves, MemoryGib, Size};
use egress_proxy::{Ports, Supervisor, SupervisorConfig};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use crate::bench::{self, TCPEXT, tcpext};
use crate::credentials::Released;
use crate::harness::{Checks, Status};
use crate::net::{self, Slots};
use crate::runsc::{Bind, Bundle, Cgroups, Network, NetworkMode, Runsc, Spec};
use crate::sandbox::{AccessKey, CreateRequest, Egress, Identity, Live, Paths, Sandboxes, Terms};
use crate::{cgroup, stats};

const BASE_ROOTFS: &str = "/run/clovelly/base/rootfs";
const ROOTS: &str = "/etc/ssl/certs/ca-certificates.crt";
const TRUST_STORE: &str = "/run/clovelly/egress/ca-certificates.crt";
const BYTES: u64 = 100_000_000;
/// The concurrent connections criterion 8 asks for, spread over a full cell.
const CONNECTIONS: usize = 2_000;
const MASQ_NETNS: &str = "clovelly-masq";

/// One measured run of transfers.
#[derive(Debug, Default)]
struct Run {
    times_ms: Vec<f64>,
    errors: Vec<String>,
    /// Retransmitted and sent segments by the sandboxes' netstacks (hop 1).
    sandbox_retrans: u64,
    sandbox_out: u64,
    /// The cell's host stack (hop 2 on the production path).
    host_retrans: u64,
    host_out: u64,
    conntrack_invalid: u64,
    /// Packets the cell dropped from its per-CPU input backlog (softnet_stat).
    softnet_dropped: u64,
    /// Receive-side TCP counters ([`bench::TCPEXT`]) over the run: the cell's (the
    /// receiver on the sandbox → proxy hop) and the destination's (the receiver on the
    /// proxy → destination hop, or of the sandbox's own connections on phase 0's path).
    host_tcpext: Value,
    peer_tcpext: Value,
    /// The `tcp_recovery` values the sandboxes reported.
    tcp_recovery: BTreeSet<u64>,
    wall_ms: f64,
}

impl Run {
    fn mbps(&self) -> Vec<f64> {
        self.times_ms.iter().map(|t| BYTES as f64 / 1e6 / (t / 1e3)).collect()
    }

    fn gb(&self) -> f64 {
        self.times_ms.len() as f64 * BYTES as f64 / 1e9
    }

    fn summary(&self) -> Value {
        let mut times = self.times_ms.clone();
        times.sort_by(f64::total_cmp);
        let median = stats::percentile_f64(&times, 50.0);
        let slowest = times.last().copied().unwrap_or(f64::NAN);
        let mut mbps = self.mbps();
        mbps.sort_by(f64::total_cmp);
        let per_gb = |n: u64| if self.gb() > 0.0 { n as f64 / self.gb() } else { f64::NAN };
        json!({
            "transfers": self.times_ms.len(),
            "errors": self.errors,
            "p50_mb_s": stats::percentile_f64(&mbps, 50.0),
            "best_mb_s": mbps.last(),
            "median_ms": median,
            "slowest_ms": slowest,
            "slowest_over_median": slowest / median,
            "aggregate_mb_s": if self.wall_ms > 0.0 { self.gb() * 1e3 / (self.wall_ms / 1e3) } else { f64::NAN },
            "wall_ms": self.wall_ms,
            "sandbox_retrans_segs": self.sandbox_retrans,
            "sandbox_out_segs": self.sandbox_out,
            "sandbox_retrans_per_gb": per_gb(self.sandbox_retrans),
            "host_retrans_segs": self.host_retrans,
            "host_out_segs": self.host_out,
            "host_retrans_per_gb": per_gb(self.host_retrans),
            "conntrack_invalid": self.conntrack_invalid,
            "softnet_dropped": self.softnet_dropped,
            "host_tcpext": self.host_tcpext,
            "peer_tcpext": self.peer_tcpext,
            "tcp_recovery": self.tcp_recovery,
            "times_ms": self.times_ms,
        })
    }

    /// Adds one `bench-http` result line.
    fn add(&mut self, line: &str) -> anyhow::Result<()> {
        let v: Value = serde_json::from_str(line.trim()).with_context(|| format!("bench-http printed {line:?}"))?;
        self.times_ms.extend(v["times_ms"].as_array().into_iter().flatten().filter_map(Value::as_f64));
        self.errors.extend(v["errors"].as_array().into_iter().flatten().filter_map(|e| e.as_str().map(str::to_owned)));
        let pair = |k: &str| (v[k][0].as_u64().unwrap_or(0), v[k][1].as_u64().unwrap_or(0));
        let ((out0, re0), (out1, re1)) = (pair("tcp_before"), pair("tcp_after"));
        self.sandbox_out += out1.saturating_sub(out0);
        self.sandbox_retrans += re1.saturating_sub(re0);
        self.tcp_recovery.extend(v["tcp_recovery"].as_u64());
        Ok(())
    }
}

/// Packets dropped from the per-CPU input backlogs so far (column 2 of softnet_stat).
fn softnet_dropped() -> u64 {
    std::fs::read_to_string("/proc/net/softnet_stat")
        .map(|t| {
            t.lines()
                .filter_map(|l| l.split_whitespace().nth(1))
                .filter_map(|h| u64::from_str_radix(h, 16).ok())
                .sum()
        })
        .unwrap_or(0)
}

/// The destination's [`TCPEXT`] counters (its `/netstat`); empty if it does not answer.
fn peer_tcpext(peer: SocketAddr) -> HashMap<&'static str, u64> {
    let Ok(body) = bench::get(peer, "/netstat") else { return HashMap::new() };
    let v: Value = serde_json::from_str(&body).unwrap_or_default();
    TCPEXT.iter().filter_map(|k| Some((*k, v[*k].as_u64()?))).collect()
}

/// `after - before` for each of [`TCPEXT`]; null where either side is missing.
fn tcpext_delta(before: &HashMap<&'static str, u64>, after: &HashMap<&'static str, u64>) -> Value {
    TCPEXT
        .iter()
        .map(|k| {
            let d = before.get(k).zip(after.get(k)).map(|(b, a)| a.saturating_sub(*b));
            ((*k).to_owned(), json!(d))
        })
        .collect::<serde_json::Map<_, _>>()
        .into()
}

fn set_backlog(packets: u32) -> std::io::Result<()> {
    std::fs::write("/proc/sys/net/core/netdev_max_backlog", packets.to_string())
}

/// The cell's host TCP counters and conntrack's `invalid` count (summed over CPUs).
fn host_counters() -> (u64, u64, u64) {
    let (out, re) = crate::bench::tcp_counters().unwrap_or((0, 0));
    let invalid = std::fs::read_to_string("/proc/net/stat/nf_conntrack")
        .ok()
        .map(|t| {
            let mut lines = t.lines();
            let col = lines.next().and_then(|h| h.split_whitespace().position(|c| c == "invalid"));
            col.map_or(0, |c| {
                lines
                    .filter_map(|l| l.split_whitespace().nth(c))
                    .filter_map(|h| u64::from_str_radix(h, 16).ok())
                    .sum()
            })
        })
        .unwrap_or(0);
    (out, re, invalid)
}

fn sh(cmd: &str) -> anyhow::Result<String> {
    let o = Command::new("sh").args(["-c", cmd]).output()?;
    if !o.status.success() {
        bail!("{cmd}: {}", String::from_utf8_lossy(&o.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Phase 0's path: a netns on a veth of `mtu`, forwarding, masquerade out of eth0.
fn masq_netns(mtu: u32) -> anyhow::Result<PathBuf> {
    let _ = sh(&format!("ip netns del {MASQ_NETNS}; ip link del clovelly-mh; nft delete table ip clovelly_masq"));
    for c in [
        format!("ip netns add {MASQ_NETNS}"),
        format!("ip link add clovelly-mh mtu {mtu} type veth peer name eth0 mtu {mtu} netns {MASQ_NETNS}"),
        "ip addr add 10.201.0.1/30 dev clovelly-mh".to_owned(),
        "ip link set clovelly-mh up".to_owned(),
        format!("ip -n {MASQ_NETNS} addr add 10.201.0.2/30 dev eth0"),
        format!("ip -n {MASQ_NETNS} link set eth0 up"),
        format!("ip -n {MASQ_NETNS} link set lo up"),
        format!("ip -n {MASQ_NETNS} route add default via 10.201.0.1"),
        "sysctl -w net.ipv4.ip_forward=1".to_owned(),
        "nft add table ip clovelly_masq".to_owned(),
        "nft 'add chain ip clovelly_masq post { type nat hook postrouting priority 100 ; }'".to_owned(),
        "nft add rule ip clovelly_masq post ip saddr 10.201.0.0/30 oifname eth0 masquerade".to_owned(),
    ] {
        sh(&c)?;
    }
    Ok(Path::new("/run/netns").join(MASQ_NETNS))
}

/// Netstack's loss detection in the benchmark's sandboxes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Recovery {
    /// As the sandbox started: RACK-TLP on phase 0's path (runsc's default), off in a
    /// cell's sandboxes (`sandbox.rs`).
    AsStarted,
    /// `tcp_recovery=1`: RACK-TLP.
    Rack,
    /// `tcp_recovery=0`: duplicate ACKs and the retransmission timer only.
    Classic,
}

impl Recovery {
    /// `bench-http` arguments selecting it.
    fn args(self) -> &'static [&'static str] {
        match self {
            Recovery::AsStarted => &[],
            Recovery::Rack => &["--tcp-recovery", "1"],
            Recovery::Classic => &["--tcp-recovery", "0"],
        }
    }
}

/// One diagnosis variant on phase 0's path.
fn diagnose(name: &str, mtu: u32, flags: &[&str], liberal: bool, recovery: Recovery, peer: SocketAddr, agent: &Path) -> anyhow::Result<Run> {
    let netns = masq_netns(mtu)?;
    std::fs::create_dir_all("/run/clovelly/runsc-diag")?;
    let liberal_path = "/proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal";
    std::fs::write(liberal_path, if liberal { "1" } else { "0" }).context(liberal_path)?;
    let runsc = Runsc {
        bin: "runsc".into(),
        state: "/run/clovelly/runsc-diag".into(),
        cgroups: Cgroups::Ignore,
        network: NetworkMode::None,
        extra: flags.iter().map(|f| (*f).to_owned()).collect(),
    };
    let to = peer.to_string();
    let mut args = vec!["/clovelly-agent", "bench-http", "--to", &to, "--bytes", "100000000", "--count", "5"];
    args.extend(recovery.args());
    let network = Network::Netns(netns);
    let bundle = Bundle::write(
        Path::new("/run/clovelly/diag").join(name),
        &Spec {
            rootfs: Path::new(BASE_ROOTFS),
            args: &args,
            env: &[],
            network: &network,
            binds: &[Bind {
                source: agent.to_path_buf(),
                destination: "/clovelly-agent".into(),
                writable: false,
            }],
            resources: None,
        },
    )?;
    let (_, _, inv0) = host_counters();
    let (drops0, ext0, peer0) = (softnet_dropped(), tcpext(), peer_tcpext(peer));
    let t = Instant::now();
    let o = runsc.run(&SandboxId::generate(), &bundle, &network)?;
    let mut run = Run {
        wall_ms: t.elapsed().as_secs_f64() * 1e3,
        ..Run::default()
    };
    let (_, _, inv1) = host_counters();
    run.conntrack_invalid = inv1.saturating_sub(inv0);
    run.softnet_dropped = softnet_dropped().saturating_sub(drops0);
    run.host_tcpext = tcpext_delta(&ext0, &tcpext());
    run.peer_tcpext = tcpext_delta(&peer0, &peer_tcpext(peer));
    let stdout = String::from_utf8_lossy(&o.stdout);
    if !o.status.success() {
        bail!("{name}: runsc exited {}: {}", o.status, String::from_utf8_lossy(&o.stderr).trim());
    }
    run.add(stdout.lines().last().unwrap_or_default())?;
    std::fs::write(liberal_path, "0")?;
    Ok(run)
}

/// A policy allowing only `peer:80`, signed by a key made here (the harness has no
/// verifier).
fn policy(peer: Ipv4Addr, placeable: Size) -> anyhow::Result<Arc<Policy>> {
    let signer = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING)?;
    let expires = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() + 86_400;
    let bundle = format!(
        r#"{{"v":1,"env":"bench","subenv":"a","version":1,"expires":{expires},"destinations":[{{"host":"{peer}","port":80}}]}}"#
    );
    let sig = signer.sign(&aws_lc_rs::rand::SystemRandom::new(), common::jws::signing_input(bundle.as_bytes()).as_bytes())?;
    let sig = common::jws::assemble(bundle.as_bytes(), sig.as_ref(), true)?;
    let key = common::jws::TrustedKey::from_pem(&common::b64::pem("PUBLIC KEY", signer.public_key().as_der()?.as_ref()))?;
    Ok(Arc::new(Policy::verify(
        bundle.as_bytes(),
        &sig,
        &key,
        &"bench".parse()?,
        &"a".parse()?,
        std::time::SystemTime::now(),
        placeable,
    )?))
}

struct Cell {
    sandboxes: Arc<Sandboxes>,
    policy: Arc<Policy>,
    proxy: Arc<Supervisor>,
}

impl Cell {
    async fn create(&self, size: Size) -> anyhow::Result<(Arc<Live>, SandboxId)> {
        let id = SandboxId::generate();
        let key = [7u8; 32];
        let far = std::time::SystemTime::now() + Duration::from_secs(10 * 86_400);
        self.sandboxes
            .create(
                CreateRequest {
                    id,
                    key: AccessKey::parse(&key)?,
                    size,
                    timeout: Duration::from_secs(4 * 3600),
                    command: Vec::new(),
                    env: Vec::new(),
                    template: None,
                    volume: None,
                },
                Terms { cell_end: far, valid_until: far },
                Arc::clone(&self.policy),
                Released::default(),
                None,
            )
            .await?;
        Ok((self.sandboxes.authorize(&id, &AccessKey::parse(&key)?)?, id))
    }

    fn exec(&self, live: &Live, args: &[&str], env: &[(String, String)], n: u64) -> anyhow::Result<tokio::process::Child> {
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        let pid = PathBuf::from(format!("/run/clovelly/pids/bench-{n}.pid"));
        Ok(self.sandboxes.spawn_exec(live, &args, env, "/", &pid)?)
    }

    async fn kill(&self, id: SandboxId) {
        let _ = self.sandboxes.kill(&id, &AccessKey::parse(&[7u8; 32]).expect("32 bytes")).await;
    }
}

/// `count` transfers from each of `sizes.len()` sandboxes at once.
async fn transfers(cell: &Cell, sizes: &[Size], count: usize, peer: SocketAddr, recovery: Recovery) -> anyhow::Result<Run> {
    let mut made = Vec::new();
    for s in sizes {
        made.push(cell.create(*s).await?);
    }
    let to = peer.to_string();
    let n = count.to_string();
    let (out0, re0, inv0) = host_counters();
    let (drops0, ext0, peer0) = (softnet_dropped(), tcpext(), peer_tcpext(peer));
    let t = Instant::now();
    let mut children = Vec::new();
    for (i, (live, _)) in made.iter().enumerate() {
        let mut args = vec!["/clovelly-agent", "bench-http", "--to", &to, "--bytes", "100000000", "--count", &n];
        args.extend(recovery.args());
        children.push(cell.exec(live, &args, &[], i as u64)?);
    }
    let mut run = Run::default();
    for child in children {
        let o = child.wait_with_output().await?;
        let stdout = String::from_utf8_lossy(&o.stdout);
        match stdout.lines().last() {
            Some(line) if o.status.success() => run.add(line)?,
            _ => run.errors.push(format!("exec exited {}: {}", o.status, String::from_utf8_lossy(&o.stderr).trim())),
        }
    }
    run.wall_ms = t.elapsed().as_secs_f64() * 1e3;
    let (out1, re1, inv1) = host_counters();
    (run.host_out, run.host_retrans, run.conntrack_invalid) =
        (out1.saturating_sub(out0), re1.saturating_sub(re0), inv1.saturating_sub(inv0));
    run.softnet_dropped = softnet_dropped().saturating_sub(drops0);
    run.host_tcpext = tcpext_delta(&ext0, &tcpext());
    run.peer_tcpext = tcpext_delta(&peer0, &peer_tcpext(peer));
    for (_, id) in made {
        cell.kill(id).await;
    }
    Ok(run)
}

/// At least 2,000 connections held at once, spread over `full` sandboxes.
async fn held(cell: &Cell, peer: SocketAddr, full: usize) -> anyhow::Result<Value> {
    let mut made = Vec::new();
    for _ in 0..full {
        made.push(cell.create(Size::new(CpuHalves(1), MemoryGib(1))).await?);
    }
    let to = peer.to_string();
    let each = CONNECTIONS.div_ceil(full).to_string();
    let env = [("CLOVELLY_HOLD_UNTIL_STDIN".to_owned(), "1".to_owned())];
    let mut children = Vec::new();
    for (i, (live, _)) in made.iter().enumerate() {
        children.push(cell.exec(live, &["/clovelly-agent", "bench-hold", "--to", &to, "--connections", &each], &env, 100 + i as u64)?);
    }
    let mut reports = Vec::new();
    let mut stdins = Vec::new();
    for child in &mut children {
        let mut lines = BufReader::new(child.stdout.take().context("stdout")?).lines();
        let line = tokio::time::timeout(Duration::from_secs(300), lines.next_line()).await??.unwrap_or_default();
        reports.push(serde_json::from_str::<Value>(&line).unwrap_or(json!({ "unparsed": line })));
        stdins.push(child.stdin.take());
    }
    // Every sandbox has reported and still holds its connections.
    let proxy_open = cell.proxy.connections();
    for stdin in stdins.iter_mut().flatten() {
        let _ = stdin.write_all(b"\n").await;
    }
    for child in &mut children {
        let mut rest = Vec::new();
        if let Some(mut e) = child.stderr.take() {
            let _ = e.read_to_end(&mut rest).await;
        }
        let _ = child.wait().await;
    }
    for (_, id) in made {
        cell.kill(id).await;
    }
    let total: u64 = reports.iter().filter_map(|r| r["held"].as_u64()).sum();
    let max_count = reports
        .iter()
        .filter_map(|r| r["count"]["Ok"].as_str().and_then(|b| serde_json::from_str::<Value>(b).ok()))
        .filter_map(|c| c["open"].as_u64())
        .max();
    Ok(json!({ "held": total, "destination_open_max": max_count, "proxy_open": proxy_open, "sandboxes": reports }))
}

/// How much of the measurement to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Phase 3: the diagnosis on phase 0's path, then the production path with its two
    /// full-cell diagnoses.
    Diagnose,
    /// Phase 11: the production path's verdicts alone.
    Production,
}

pub fn run(checks: &mut Checks, out: &Path, peer: SocketAddr, scope: Scope) -> anyhow::Result<()> {
    let SocketAddr::V4(peer4) = peer else { bail!("--peer must be IPv4") };
    let agent = std::env::current_exe()?;
    let flags = Command::new("runsc").arg("flags").output().map(|o| {
        let mut t = String::from_utf8_lossy(&o.stdout).into_owned();
        t.push_str(&String::from_utf8_lossy(&o.stderr));
        t
    })?;
    std::fs::write(out.join("runsc-flags.txt"), &flags)?;
    let has = |f: &str| flags.lines().any(|l| l.trim_start().starts_with(&format!("-{f} ")) || l.trim_start() == format!("-{f}"));
    let gso_flags: Vec<&str> = [("gso", "--gso=false"), ("software-gso", "--software-gso=false")]
        .iter()
        .filter(|(name, _)| has(name))
        .map(|(_, f)| *f)
        .collect();

    // 1. The diagnosis on phase 0's path, in SPEC.md's order.
    let mut results = serde_json::Map::new();
    let variants: Vec<(&str, u32, Vec<&str>, bool, Recovery)> = match scope {
        Scope::Production => Vec::new(),
        Scope::Diagnose => vec![
        ("p0-baseline", 1460, vec![], false, Recovery::AsStarted),
        ("d1-conntrack-liberal", 1460, vec![], true, Recovery::AsStarted),
        ("d2-gso-off", 1460, gso_flags.clone(), false, Recovery::AsStarted),
        ("d3-veth-1500", 1500, vec![], false, Recovery::AsStarted),
        ("d5-rack-off", 1460, vec![], false, Recovery::Classic),
        ],
    };
    for (name, mtu, flags, liberal, recovery) in variants {
        if name == "d2-gso-off" && gso_flags.is_empty() {
            checks.record(&format!("c8-{name}"), Status::Measured, "runsc has neither -gso nor -software-gso; not measured");
            continue;
        }
        match diagnose(name, mtu, &flags, liberal, recovery, peer, &agent) {
            Ok(r) => {
                let s = r.summary();
                checks.record(
                    &format!("c8-{name}"),
                    Status::Measured,
                    format!(
                        "phase 0 path, veth {mtu}, runsc {flags:?}, be_liberal {}, tcp_recovery {}: p50 {:.0} MB/s, slowest/median {:.2}, {} retransmitted segments ({:.0} per GB, sandbox), the destination's DSACKs for data it already had {}, conntrack invalid {}, backlog drops {}",
                        u8::from(liberal),
                        s["tcp_recovery"],
                        s["p50_mb_s"].as_f64().unwrap_or(f64::NAN),
                        s["slowest_over_median"].as_f64().unwrap_or(f64::NAN),
                        s["sandbox_retrans_segs"],
                        s["sandbox_retrans_per_gb"].as_f64().unwrap_or(f64::NAN),
                        s["peer_tcpext"]["TCPDSACKOldSent"],
                        s["conntrack_invalid"],
                        s["softnet_dropped"]
                    ),
                );
                results.insert(name.to_owned(), s);
            }
            Err(e) => checks.record(&format!("c8-{name}"), Status::Fail, format!("{e:#}")),
        }
    }
    if scope == Scope::Diagnose {
        let _ = sh(&format!("ip netns del {MASQ_NETNS}; ip link del clovelly-mh; nft delete table ip clovelly_masq; sysctl -w net.ipv4.ip_forward=0"));
    }

    // 2. The production path.
    let rt = tokio::runtime::Runtime::new()?;
    let production = rt.block_on(async {
        let placeable = cgroup::placeable(cgroup::machine()?);
        cgroup::setup(placeable)?;
        // A full cell: as many sandboxes of 0.5 vCPU and 2 GiB as it places (14 on a
        // c3-standard-8, 171 on a c3-standard-88, where memory binds).
        let full = usize::try_from(placeable.cpu.0.min(placeable.memory.0 / 2)).unwrap_or(0).max(1);
        net::setup_cell(Ports::CELL).await?;
        let roots = std::fs::read_to_string(ROOTS)?;
        // The production path since phase 4: the proxy is its own process.
        let proxy = Supervisor::start(SupervisorConfig {
            bin: crate::agent::PROXY_BIN.into(),
            roots_pem: roots.clone(),
            cell: "throughput".into(),
            network: egress_proxy::Network { exempt: vec![*peer4.ip()], ..egress_proxy::Network::default() },
            status: Box::new(crate::agent::status),
        })
        .await?;
        std::fs::create_dir_all("/run/clovelly/egress")?;
        std::fs::write(TRUST_STORE, format!("{roots}\n{}", proxy.ca_pem()))?;
        for dir in ["/run/clovelly/bundles", "/run/clovelly/pids"] {
            std::fs::create_dir_all(dir)?;
        }
        let slots = Arc::new(Slots::default());
        let make = |network: NetworkMode| {
            Sandboxes::new(
                Runsc {
                    bin: "runsc".into(),
                    state: "/run/clovelly/runsc".into(),
                    cgroups: Cgroups::Enforce,
                    network,
                    extra: Vec::new(),
                },
                Paths {
                    rootfs: BASE_ROOTFS.into(),
                    bundles: "/run/clovelly/bundles".into(),
                    binds: vec![Bind {
                        source: agent.clone(),
                        destination: "/clovelly-agent".into(),
                        writable: false,
                    }],
                },
                placeable,
                Identity {
                    env: "bench".parse().expect("label"),
                    subenv: "a".parse().expect("label"),
                    release: "clovelly-bench".parse().expect("release id"),
                    instance_id: 0,
                    zone: "bench".parse().expect("label"),
                    project: "0".into(),
                },
                Some(Egress {
                    proxy: Arc::clone(&proxy),
                    slots: Arc::clone(&slots),
                    trust_store: TRUST_STORE.into(),
                    mtu: net::MTU,
                }),
                None,
                crate::sandbox::Receipting::local(),
            )
        };
        let mut out = serde_json::Map::new();
        // Diagnosis 4: the production path at a full cell with the kernel's default input
        // backlog, against the cell's (net::NETDEV_BACKLOG, set by setup_cell). Diagnosis
        // 5: the production path at a full cell with netstack's RACK-TLP on, as runsc
        // starts it and as cells ran before they turned it off.
        if scope == Scope::Diagnose {
            let cell = Cell {
                sandboxes: make(NetworkMode::Sandbox),
                policy: policy(*peer4.ip(), placeable)?,
                proxy: Arc::clone(&proxy),
            };
            let sizes = vec![Size::new(CpuHalves(1), MemoryGib(2)); full];
            set_backlog(1000)?;
            let d4 = transfers(&cell, &sizes, 10, peer, Recovery::AsStarted).await;
            set_backlog(net::NETDEV_BACKLOG)?;
            out.insert("d4-default-backlog".to_owned(), json!({ "full_cell": d4?.summary(), "full_cell_sandboxes": full }));
            let d5 = transfers(&cell, &sizes, 10, peer, Recovery::Rack).await?;
            out.insert("d5-rack-on".to_owned(), json!({ "full_cell": d5.summary(), "full_cell_sandboxes": full }));
        }
        for (label, network) in [("netstack", NetworkMode::Sandbox), ("hostinet", NetworkMode::Host)] {
            let cell = Cell {
                sandboxes: make(network),
                policy: policy(*peer4.ip(), placeable)?,
                proxy: Arc::clone(&proxy),
            };
            let one = transfers(&cell, &[Size::new(CpuHalves(2), MemoryGib(2))], 10, peer, Recovery::AsStarted).await?;
            let all = transfers(&cell, &vec![Size::new(CpuHalves(1), MemoryGib(2)); full], 10, peer, Recovery::AsStarted).await?;
            let hold = held(&cell, peer, full).await?;
            let stalled = [&one, &all].iter().any(|r| r.summary()["slowest_over_median"].as_f64().is_none_or(|x| x > 3.0));
            out.insert(
                label.to_owned(),
                json!({ "concurrency_1": one.summary(), "full_cell": all.summary(), "full_cell_sandboxes": full,
                        "connections": hold, "stalled": stalled }),
            );
            // Decision 6's fallback is measured only if netstack fails the stall bound.
            if label == "netstack" && !stalled {
                break;
            }
        }
        Ok::<_, anyhow::Error>(out)
    })?;
    results.insert("production".to_owned(), Value::Object(production.clone()));
    std::fs::write(out.join("throughput.json"), serde_json::to_string_pretty(&Value::Object(results))?)?;

    for (key, what) in [
        ("d4-default-backlog", "kernel default backlog (1000)"),
        ("d5-rack-on", "netstack's RACK-TLP on (runsc's default; cells turn it off)"),
    ] {
        let Some(d) = production.get(key) else { continue };
        let full = &d["full_cell"];
        checks.record(
            &format!("c8-{key}-full-cell"),
            Status::Measured,
            format!(
                "production path, a full cell, {what}, tcp_recovery {}: {} retransmitted segments ({:.1} per GB) sandbox → proxy, the cell's DSACKs for data it already had {}, backlog drops {}; aggregate {:.0} MB/s, slowest/median {:.2}",
                full["tcp_recovery"],
                full["sandbox_retrans_segs"],
                full["sandbox_retrans_per_gb"].as_f64().unwrap_or(f64::NAN),
                full["host_tcpext"]["TCPDSACKOldSent"],
                full["softnet_dropped"],
                full["aggregate_mb_s"].as_f64().unwrap_or(f64::NAN),
                full["slowest_over_median"].as_f64().unwrap_or(f64::NAN)
            ),
        );
    }
    // Verdicts, on netstack (the production configuration).
    for (label, r) in production.iter().filter(|(l, _)| !l.starts_with('d')) {
        let c1 = &r["concurrency_1"];
        let full = &r["full_cell"];
        let held = &r["connections"];
        let f = |v: &Value| v.as_f64().unwrap_or(f64::NAN);
        let tag = if label == "netstack" { String::new() } else { format!("-{label}") };
        let ok = |b: bool| if b { Status::Pass } else { Status::Fail };
        checks.record(
            &format!("c8-single-p50{tag}"),
            ok(f(&c1["p50_mb_s"]) >= 500.0),
            format!("{label}: one sandbox (1 vCPU), 10 × 100 MB through the proxy: p50 {:.0} MB/s (target ≥ 500), best {:.0}", f(&c1["p50_mb_s"]), f(&c1["best_mb_s"])),
        );
        checks.record(
            &format!("c8-aggregate{tag}"),
            ok(f(&full["aggregate_mb_s"]) >= 500.0),
            format!("{label}: a full cell ({} sandboxes of 0.5 vCPU, 2 GiB), 10 × 100 MB each at once: aggregate {:.0} MB/s (target ≥ 500), per-transfer p50 {:.0} MB/s", r["full_cell_sandboxes"], f(&full["aggregate_mb_s"]), f(&full["p50_mb_s"])),
        );
        checks.record(
            &format!("c8-stall-bound{tag}"),
            ok(f(&c1["slowest_over_median"]) <= 3.0 && f(&full["slowest_over_median"]) <= 3.0),
            format!("{label}: slowest over median {:.2} (one sandbox), {:.2} (full cell); target ≤ 3", f(&c1["slowest_over_median"]), f(&full["slowest_over_median"])),
        );
        checks.record(
            &format!("c8-connections{tag}"),
            ok(held["destination_open_max"].as_u64().unwrap_or(0) >= 2000),
            format!("{label}: {} connections held from {} sandboxes; the destination saw {} open at once, the proxy {} (target ≥ 2,000)", held["held"], r["full_cell_sandboxes"], held["destination_open_max"], held["proxy_open"]),
        );
        // Both hops, each with its receiver's count of duplicates of data it already had
        // (spurious retransmissions).
        let hops = |r: &Value| {
            format!(
                "sandbox → proxy {} retransmitted segments ({:.1} per GB), the cell's DSACKs {}; proxy → destination {} ({:.1} per GB), the destination's DSACKs {}; conntrack invalid {}, backlog drops {}",
                r["sandbox_retrans_segs"], f(&r["sandbox_retrans_per_gb"]), r["host_tcpext"]["TCPDSACKOldSent"],
                r["host_retrans_segs"], f(&r["host_retrans_per_gb"]), r["peer_tcpext"]["TCPDSACKOldSent"],
                r["conntrack_invalid"], r["softnet_dropped"]
            )
        };
        checks.record(
            &format!("c8-hop-retransmissions{tag}"),
            ok(f(&c1["sandbox_retrans_per_gb"]) < 100.0 && f(&full["sandbox_retrans_per_gb"]) < 100.0),
            format!(
                "{label}, tcp_recovery {} (target under 100 per GB sandbox → proxy): one sandbox: {}; a full cell ({} sandboxes): {}",
                c1["tcp_recovery"], hops(c1), r["full_cell_sandboxes"], hops(full)
            ),
        );
    }
    Ok(())
}
