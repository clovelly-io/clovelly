//! Phase 11 criterion 11a on the test image (`harness --tests sharing`): many gVisor
//! sandboxes sharing CPUs inside one TD, the measurement that decides phase 13's sharing
//! factor.
//!
//! The cell's cgroup layout is the agent's ([`cgroup::setup`]: the parent capped at the
//! placeable capacity), and every sandbox gets the limits the agent gives a default
//! sandbox of 1 vCPU, through runsc from its OCI spec: `cpu.max` at the request (the cap)
//! and a CPU weight, except that the weight is the request divided by the sharing factor
//! (OCI `shares` 1024 / factor, which runsc turns into `cpu.weight`). Memory is capped at
//! 1 GiB each; the rollout uses a small part of it, and the cap is not a reservation.
//!
//! For each factor (1, 3 and 4) the cell runs `factor × placeable vCPUs` sandboxes at
//! once (87, 261 and 348 on a c3-standard-88), network off, each looping the rollout mix:
//! a Python step of fixed work (calibrated to about 200 ms of CPU on an idle cell), a 2 s
//! idle wait, a 1 MB file write. Every iteration prints its start time and the three
//! steps' wall times. Iterations that start inside the window (after a minute for every
//! sandbox to be up, for three minutes) are kept: per-step p50 and p95, and iterations per
//! second per sandbox. Results: `sharing.json`, `sharing.tsv`.

use std::path::Path;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use common::ids::SandboxId;
use common::sandbox::{CpuHalves, MemoryGib, Size};
use serde_json::{Value, json};

use crate::cgroup;
use crate::harness::{Checks, Status};
use crate::runsc::{Bundle, Cgroups, Network, NetworkMode, Resources, Runsc, Spec};
use crate::stats::percentile_f64;

const BASE_ROOTFS: &str = "/run/clovelly/base/rootfs";
const BUNDLES: &str = "/run/clovelly/bundles";
const FACTORS: [u32; 3] = [1, 3, 4];
/// Time for every sandbox to be up before the window opens.
const SETTLE: Duration = Duration::from_secs(60);
const WINDOW: Duration = Duration::from_secs(180);
/// The Python step's target CPU time on an idle cell.
const STEP_MS: f64 = 200.0;
/// The weight runsc gives 1 vCPU (OCI `shares`; runsc maps shares to `cpu.weight`).
const SHARES_PER_VCPU: u64 = 1024;

/// The rollout, run inside each sandbox: `python3 -c ROLLOUT WORK END` loops until the
/// epoch second END, printing `start cpu_ms idle_ms write_ms` per iteration.
/// `python3 -c ROLLOUT WORK calibrate` prints the fastest of five steps, in ms.
const ROLLOUT: &str = r#"
import os, sys, time
work = int(sys.argv[1])
def step():
    x = 0
    for k in range(work):
        x += k * k
    return x
if sys.argv[2] == "calibrate":
    best = None
    for _ in range(5):
        t = time.time(); step(); d = (time.time() - t) * 1e3
        best = d if best is None or d < best else best
    print("%.3f" % best, flush=True)
    sys.exit(0)
end = float(sys.argv[2])
buf = os.urandom(1 << 20)
i = 0
while time.time() < end:
    t0 = time.time(); step(); t1 = time.time()
    time.sleep(2); t2 = time.time()
    with open("/tmp/f%d" % (i % 4), "wb") as f:
        f.write(buf); f.flush(); os.fsync(f.fileno())
    t3 = time.time()
    print("%.3f %.3f %.3f %.3f" % (t0, (t1 - t0) * 1e3, (t2 - t1) * 1e3, (t3 - t2) * 1e3), flush=True)
    i += 1
"#;

/// One iteration as a sandbox printed it.
#[derive(Debug, Clone, Copy)]
struct Iteration {
    start: f64,
    cpu_ms: f64,
    idle_ms: f64,
    write_ms: f64,
}

fn parse(stdout: &str) -> Vec<Iteration> {
    stdout
        .lines()
        .filter_map(|l| {
            let v: Vec<f64> = l.split_whitespace().filter_map(|f| f.parse().ok()).collect();
            match v.as_slice() {
                [start, cpu_ms, idle_ms, write_ms] => Some(Iteration { start: *start, cpu_ms: *cpu_ms, idle_ms: *idle_ms, write_ms: *write_ms }),
                _ => None,
            }
        })
        .collect()
}

fn epoch() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64())
}

/// The runsc the agent uses for sandboxes, without a network.
fn runsc() -> Runsc {
    Runsc {
        bin: "runsc".into(),
        state: "/run/clovelly/runsc".into(),
        cgroups: Cgroups::Enforce,
        network: NetworkMode::None,
        extra: Vec::new(),
    }
}

/// Runs one sandbox of 1 vCPU at `factor` to completion: its stdout, and its cgroup's
/// `cpu.weight` as runsc set it (read once it is running).
fn sandbox(args: &[&str], factor: u32) -> anyhow::Result<(String, Option<String>)> {
    let id = SandboxId::generate();
    let size = Size::new(CpuHalves(2), MemoryGib(1));
    let resources = Resources { cgroup: cgroup::sandbox_path(&id), size };
    let mut argv = vec!["/bin/python3", "-c", ROLLOUT];
    argv.extend_from_slice(args);
    let bundle = Bundle::write(
        Path::new(BUNDLES).join(id.as_str()),
        &Spec { rootfs: Path::new(BASE_ROOTFS), args: &argv, env: &[], network: &Network::None, binds: &[], resources: Some(&resources) },
    )?;
    // The agent's weight is the request's; the trial divides it by the factor.
    let config = bundle.dir().join("config.json");
    let mut spec: Value = serde_json::from_slice(&std::fs::read(&config)?)?;
    spec["linux"]["resources"]["cpu"]["shares"] = json!(SHARES_PER_VCPU / u64::from(factor));
    std::fs::write(&config, serde_json::to_vec(&spec)?)?;
    let weight_path = Path::new("/sys/fs/cgroup").join(cgroup::sandbox_path(&id).trim_start_matches('/')).join("cpu.weight");
    let reader = thread::spawn(move || {
        thread::sleep(Duration::from_secs(5));
        std::fs::read_to_string(weight_path).ok().map(|w| w.trim().to_owned())
    });
    let out = runsc().run(&id, &bundle, &Network::None)?;
    let weight = reader.join().unwrap_or(None);
    let _ = runsc().delete(&id);
    if !out.status.success() {
        bail!("exit {}: {}", out.status, String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok((String::from_utf8_lossy(&out.stdout).into_owned(), weight))
}

fn summary(mut v: Vec<f64>) -> Value {
    v.sort_by(f64::total_cmp);
    json!({ "n": v.len(), "p50": percentile_f64(&v, 50.0), "p95": percentile_f64(&v, 95.0), "max": v.last() })
}

/// Runs the trial at every factor and records one `measured` check per factor.
pub fn run(checks: &mut Checks, out: &Path) -> anyhow::Result<()> {
    let placeable = cgroup::placeable(cgroup::machine()?);
    cgroup::setup(placeable)?;
    std::fs::create_dir_all(BUNDLES)?;
    let full = usize::try_from(placeable.cpu.0 / 2).context("placeable vCPUs")?;

    // Calibration: the Python step's work for STEP_MS on an idle cell.
    const PROBE: u64 = 1_000_000;
    let (stdout, _) = sandbox(&[&PROBE.to_string(), "calibrate"], 1).context("calibration sandbox")?;
    let probe_ms: f64 = stdout.trim().parse().context("calibration output")?;
    let work = ((PROBE as f64) * STEP_MS / probe_ms).round() as u64;
    checks.record(
        "c11a-rollout-mix",
        Status::Measured,
        format!(
            "each sandbox (1 vCPU cap, 1 GiB cap, network off) loops: a Python step of {work} loop iterations ({probe_ms:.1} ms per million on an idle cell, so about {STEP_MS:.0} ms), a 2 s sleep, a 1 MB write and fsync to /tmp; window {} s after {} s to settle; {full} placeable vCPUs",
            WINDOW.as_secs(),
            SETTLE.as_secs()
        ),
    );

    let mut table = String::from("factor\tsandboxes\tfailed\tcpu.weight\tcpu_p50_ms\tcpu_p95_ms\titer_p50_ms\titer_p95_ms\twrite_p50_ms\twrite_p95_ms\titer_per_s_mean\titer_per_s_min\tcell_cpu_util\n");
    let mut results = serde_json::Map::new();
    let mut baseline: Option<(f64, f64)> = None;
    for factor in FACTORS {
        let n = full * factor as usize;
        let launched = epoch();
        let open = launched + SETTLE.as_secs_f64();
        let close = open + WINDOW.as_secs_f64();
        let end = format!("{close:.3}");
        let work = work.to_string();
        let (used0, _) = cgroup::usage().unwrap_or((0, 0));
        let outcomes: Vec<anyhow::Result<(String, Option<String>)>> = thread::scope(|s| {
            let handles: Vec<_> = (0..n).map(|_| s.spawn(|| sandbox(&[&work, &end], factor))).collect();
            handles.into_iter().map(|h| h.join().unwrap_or_else(|_| Err(anyhow::anyhow!("worker panicked")))).collect()
        });
        let (used1, _) = cgroup::usage().unwrap_or((0, 0));
        let wall = epoch() - launched;
        let mut failures = Vec::new();
        let mut weight = None;
        let mut iters: Vec<Vec<Iteration>> = Vec::new();
        for o in outcomes {
            match o {
                Ok((stdout, w)) => {
                    weight = weight.or(w);
                    iters.push(parse(&stdout).into_iter().filter(|i| i.start >= open && i.start < close).collect());
                }
                Err(e) => failures.push(format!("{e:#}")),
            }
        }
        let all: Vec<Iteration> = iters.iter().flatten().copied().collect();
        let rates: Vec<f64> = iters.iter().map(|v| v.len() as f64 / WINDOW.as_secs_f64()).collect();
        let cpu = summary(all.iter().map(|i| i.cpu_ms).collect());
        let iter = summary(all.iter().map(|i| i.cpu_ms + i.idle_ms + i.write_ms).collect());
        let write = summary(all.iter().map(|i| i.write_ms).collect());
        let rate_mean = if rates.is_empty() { f64::NAN } else { rates.iter().sum::<f64>() / rates.len() as f64 };
        let rate_min = rates.iter().copied().fold(f64::INFINITY, f64::min);
        // CPU time all sandboxes used over the run, against what the placeable vCPUs give.
        let util = (used1.saturating_sub(used0)) as f64 / 1e6 / (wall * full as f64);
        let f = |v: &Value, k: &str| v[k].as_f64().unwrap_or(f64::NAN);
        let base = *baseline.get_or_insert((f(&cpu, "p95"), rate_mean));
        table.push_str(&format!(
            "{factor}\t{n}\t{}\t{}\t{:.1}\t{:.1}\t{:.1}\t{:.1}\t{:.1}\t{:.1}\t{rate_mean:.4}\t{rate_min:.4}\t{util:.2}\n",
            failures.len(),
            weight.as_deref().unwrap_or("-"),
            f(&cpu, "p50"),
            f(&cpu, "p95"),
            f(&iter, "p50"),
            f(&iter, "p95"),
            f(&write, "p50"),
            f(&write, "p95"),
        ));
        checks.record(
            &format!("c11a-sharing-{factor}x"),
            Status::Measured,
            format!(
                "{n} sandboxes ({factor}x), cpu.weight {}, {} failed: Python step p50 {:.0} ms, p95 {:.0} ms ({:.2}x the 1x p95); iteration p50 {:.0} ms, p95 {:.0} ms; write p95 {:.1} ms; {rate_mean:.3} iterations/s per sandbox (min {rate_min:.3}, {:.2}x the 1x rate); the sandboxes used {:.0}% of the placeable vCPUs",
                weight.as_deref().unwrap_or("unread"),
                failures.len(),
                f(&cpu, "p50"),
                f(&cpu, "p95"),
                f(&cpu, "p95") / base.0,
                f(&iter, "p50"),
                f(&iter, "p95"),
                f(&write, "p95"),
                rate_mean / base.1,
                util * 100.0
            ),
        );
        results.insert(
            format!("{factor}x"),
            json!({ "sandboxes": n, "failed": failures.len(), "failures": failures.iter().take(5).collect::<Vec<_>>(), "cpu_weight": weight,
                    "cpu_ms": cpu, "iteration_ms": iter, "write_ms": write, "iterations_per_s_mean": rate_mean,
                    "iterations_per_s_min": rate_min, "cell_cpu_utilisation": util, "wall_s": wall }),
        );
    }
    std::fs::write(out.join("sharing.tsv"), table)?;
    std::fs::write(out.join("sharing.json"), serde_json::to_string_pretty(&json!({ "work": work, "probe_ms_per_million": probe_ms, "factors": results }))?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iterations_parse_and_noise_is_skipped() {
        let v = parse("1700000000.125 201.5 2000.3 1.2\nTraceback\n1700000003.400 199.0 2001.0 0.9\n");
        assert_eq!(v.len(), 2);
        assert!((v[1].cpu_ms - 199.0).abs() < 1e-9 && (v[0].start - 1_700_000_000.125).abs() < 1e-6);
    }
}
