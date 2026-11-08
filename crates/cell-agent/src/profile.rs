//! Phase 11 criterion 11b on the test image (`harness --tests profile`): where the
//! create path's time goes on a big TD (the c3-standard-176, whose creates the big-cell
//! run measured 10 to 50 times slower than the 88's under load).
//!
//! Create-to-first-exec is measured as phase 0 measures it ([`latency`]: `runsc create`,
//! `start` and the first `exec` byte timed separately) at each `--concurrency`, for each
//! variant:
//!
//! - `baseline`: as the big-cell run, no cgroup limits;
//! - `cgroup`: every sandbox in its own cgroup at the default size (1 vCPU, 2 GiB) under
//!   the agent's parent, as cells create them;
//! - `cpu-num-from-quota`: `cgroup`, and runsc sizing the sandbox's CPU count from its
//!   cgroup quota (`--cpu-num-from-quota`), when this runsc has the flag;
//! - `gomaxprocs`: `baseline` with `GOMAXPROCS` pinned to 2 (what the quota gives a
//!   1 vCPU sandbox) in every runsc process's environment;
//! - `cpuset-88`: `baseline` with every runsc process confined to 88 CPUs by a cpuset
//!   cgroup: the 176 behaving as an 88 says the cost follows the CPU count;
//! - `combined`: `cpu-num-from-quota` and `gomaxprocs` together.
//!
//! Around the baseline's largest concurrency, `perf record` samples every CPU (cpu-clock,
//! with call graphs) and `perf report` is kept, by command, object and symbol, so the
//! results can name the dominant cost; `/proc/meminfo`'s unaccepted memory (TDX guests
//! accept private memory on first use) is read before and after. Results:
//! `profile.tsv`, `perf-report.txt`, `perf-comm.txt`, `profile-env.txt`.

use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use anyhow::Context;
use common::sandbox::{CpuHalves, MemoryGib, Size};

use crate::cgroup;
use crate::harness::{Checks, Status};
use crate::latency::{self, Setup};
use crate::runsc::{Cgroups, NetworkMode, Runsc};
use crate::stats::{Summary, ms};

const BASE_ROOTFS: &str = "/run/clovelly/base/rootfs";
const BUNDLES: &str = "/run/clovelly/bundles";
const BUDGET: Duration = Duration::from_secs(15 * 60);
/// Target 3: a full cell's create-to-first-exec p95.
const TARGET: Duration = Duration::from_millis(500);
const GOMAXPROCS: u32 = 2;
const PIN_CGROUP: &str = "/sys/fs/cgroup/pin88";

/// One way of running runsc.
struct Variant {
    name: &'static str,
    runsc: Runsc,
    sized: Option<Size>,
}

fn runsc(bin: &str, cgroups: Cgroups, extra: &[&str]) -> Runsc {
    Runsc {
        bin: bin.into(),
        state: "/run/clovelly/runsc".into(),
        cgroups,
        network: NetworkMode::None,
        extra: extra.iter().map(|s| (*s).to_owned()).collect(),
    }
}

/// Writes an executable wrapper at `path` that runs `prelude`, then execs runsc with its
/// arguments; runsc re-executes itself from `/proc/self/exe`, so its children inherit the
/// environment and cgroup the wrapper set.
fn wrapper(path: &str, prelude: &str) -> anyhow::Result<()> {
    fs::write(path, format!("#!/bin/sh\n{prelude}\nexec runsc \"$@\"\n"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

fn meminfo(key: &str) -> String {
    fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|m| m.lines().find(|l| l.starts_with(key)).map(|l| l.split_whitespace().skip(1).collect::<Vec<_>>().join(" ")))
        .unwrap_or_else(|| "absent".into())
}

fn perf_available() -> bool {
    Command::new("perf").arg("--version").output().is_ok_and(|o| o.status.success())
}

fn perf_start(data: &Path) -> Option<Child> {
    Command::new("perf")
        .args(["record", "-a", "-g", "-F", "499", "-e", "cpu-clock", "-o"])
        .arg(data)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()
}

/// Stops `perf record` with SIGINT, as its own Ctrl-C, so it writes its data.
fn perf_stop(child: &mut Child) {
    let _ = Command::new("kill").args(["-INT", &child.id().to_string()]).status();
    let _ = child.wait();
}

fn perf_report(data: &Path, sort: &str, out: &Path) -> anyhow::Result<String> {
    let o = Command::new("perf")
        .args(["report", "--stdio", "--no-children", "-g", "none", "--percent-limit", "0.5", "--sort", sort, "-i"])
        .arg(data)
        .output()?;
    let text = String::from_utf8_lossy(&o.stdout).into_owned();
    fs::write(out, &text)?;
    // The first rows, for the check line.
    Ok(text.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()).take(8).map(str::trim).collect::<Vec<_>>().join("; "))
}

/// Runs every variant at every concurrency in `levels`, `samples` creates each.
pub fn run(checks: &mut Checks, out: &Path, levels: &[usize], samples: usize) -> anyhow::Result<()> {
    let placeable = cgroup::placeable(cgroup::machine()?);
    cgroup::setup(placeable)?;
    fs::create_dir_all(BUNDLES)?;
    let flags = Command::new("runsc").arg("flags").output().map(|o| {
        let mut t = String::from_utf8_lossy(&o.stdout).into_owned();
        t.push_str(&String::from_utf8_lossy(&o.stderr));
        t
    })?;
    fs::write(out.join("runsc-flags.txt"), &flags)?;
    let quota_flag = flags.lines().any(|l| l.trim_start().starts_with("-cpu-num-from-quota"));

    wrapper("/run/clovelly/runsc-gomaxprocs", &format!("export GOMAXPROCS={GOMAXPROCS}"))?;
    // 88 CPUs for every runsc process of `cpuset-88`.
    let pinned = (|| -> anyhow::Result<()> {
        fs::write("/sys/fs/cgroup/cgroup.subtree_control", "+cpuset").context("enabling the cpuset controller")?;
        fs::create_dir_all(PIN_CGROUP)?;
        fs::write(Path::new(PIN_CGROUP).join("cpuset.cpus"), "0-87").context("cpuset.cpus")?;
        wrapper("/run/clovelly/runsc-pin88", &format!("echo $$ > {PIN_CGROUP}/cgroup.procs"))
    })();
    if let Err(e) = &pinned {
        checks.record("c11b-cpuset-88", Status::Fail, format!("could not confine runsc to 88 CPUs: {e:#}"));
    }

    let default = Size::new(CpuHalves(2), MemoryGib(2));
    let mut variants = vec![
        Variant { name: "baseline", runsc: runsc("runsc", Cgroups::Ignore, &[]), sized: None },
        Variant { name: "cgroup", runsc: runsc("runsc", Cgroups::Enforce, &[]), sized: Some(default) },
    ];
    if quota_flag {
        variants.push(Variant { name: "cpu-num-from-quota", runsc: runsc("runsc", Cgroups::Enforce, &["--cpu-num-from-quota"]), sized: Some(default) });
    } else {
        checks.record("c11b-cpu-num-from-quota", Status::Measured, "this runsc has no -cpu-num-from-quota flag (runsc-flags.txt); variant not measured");
    }
    variants.push(Variant { name: "gomaxprocs", runsc: runsc("/run/clovelly/runsc-gomaxprocs", Cgroups::Ignore, &[]), sized: None });
    if pinned.is_ok() {
        variants.push(Variant { name: "cpuset-88", runsc: runsc("/run/clovelly/runsc-pin88", Cgroups::Ignore, &[]), sized: None });
    }
    if quota_flag {
        variants.push(Variant {
            name: "combined",
            runsc: runsc("/run/clovelly/runsc-gomaxprocs", Cgroups::Enforce, &["--cpu-num-from-quota"]),
            sized: Some(default),
        });
    }

    let perf = perf_available();
    let data = out.join("perf.data");
    let full = levels.iter().copied().max().unwrap_or(1);
    let mut env = format!("cpus={}\nunaccepted_before={}\nperf={perf}\n", std::thread::available_parallelism().map_or(0, usize::from), meminfo("Unaccepted:"));
    let mut table = String::from("variant\tconcurrency\tok\tfailed\tp50_ms\tp95_ms\tmax_ms\tcreate_p50_ms\tstart_p50_ms\texec_p50_ms\tcreate_p95_ms\tstart_p95_ms\texec_p95_ms\twall_s\ttimed_out\n");
    for v in &variants {
        let setup = Setup { runsc: &v.runsc, rootfs: Path::new(BASE_ROOTFS), scratch: Path::new(BUNDLES), sized: v.sized };
        if let Err(e) = latency::warm_up(setup, 3, BUDGET) {
            checks.record(&format!("c11b-{}", v.name), Status::Fail, format!("warm-up: {e}"));
            continue;
        }
        let mut full_p95 = None;
        for &c in levels {
            let record = perf && v.name == "baseline" && c == full;
            let mut recorder = if record { perf_start(&data) } else { None };
            let o = latency::measure(setup, c, samples, BUDGET);
            if let Some(child) = recorder.as_mut() {
                perf_stop(child);
            }
            let step = |f: fn(&latency::Sample) -> Duration| Summary::of(&o.samples.iter().map(f).collect::<Vec<_>>());
            let total = step(|s| s.total);
            let (create, start, exec) = (step(|s| s.create), step(|s| s.start), step(|s| s.exec));
            let p = |s: Option<Summary>, f: fn(&Summary) -> Duration| s.map_or("-".into(), |s| ms(f(&s)));
            writeln!(
                table,
                "{}\t{c}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.1}\t{}",
                v.name,
                o.samples.len(),
                o.failures.len(),
                p(total, |s| s.p50),
                p(total, |s| s.p95),
                p(total, |s| s.max),
                p(create, |s| s.p50),
                p(start, |s| s.p50),
                p(exec, |s| s.p50),
                p(create, |s| s.p95),
                p(start, |s| s.p95),
                p(exec, |s| s.p95),
                o.wall.as_secs_f64(),
                o.timed_out
            )?;
            if c == full {
                full_p95 = total.map(|s| s.p95);
            }
            if let Some(f) = o.failures.first() {
                writeln!(env, "first_failure_{}_{c}={f}", v.name)?;
            }
        }
        let verdict = full_p95.map_or("no samples".to_owned(), |p| {
            format!("{} ms, {} target 3's 500 ms", ms(p), if p < TARGET { "under" } else { "over" })
        });
        checks.record(&format!("c11b-{}", v.name), Status::Measured, format!("full-cell ({full} concurrent) create-to-first-exec p95 {verdict} (profile.tsv)"));
    }
    writeln!(env, "unaccepted_after={}", meminfo("Unaccepted:"))?;
    fs::write(out.join("profile.tsv"), &table)?;
    if perf && data.exists() {
        let top = perf_report(&data, "comm,dso,sym", &out.join("perf-report.txt"))?;
        let comm = perf_report(&data, "comm,dso", &out.join("perf-comm.txt"))?;
        let _ = fs::remove_file(&data);
        checks.record("c11b-perf", Status::Measured, format!("perf record -a -g (cpu-clock) over the baseline at {full} concurrent: by command and object: {comm}; top symbols: {top}"));
    } else {
        checks.record("c11b-perf", Status::Fail, format!("no perf profile (perf in image: {perf})"));
    }
    fs::write(out.join("profile-env.txt"), env)?;
    Ok(())
}
