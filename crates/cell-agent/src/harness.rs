//! The in-guest harness: runs the selected checks and benchmarks (phase 0's, and phase
//! 1's in [`crate::phase1`]) and writes their results to one directory, which the test
//! image's init uploads.
//!
//! Results directory:
//! - `checks.tsv`: `id  status  detail`, one line per check; status is `pass`, `fail`
//!   or `measured` (a benchmark that ran; failures inside it are data, not errors).
//! - `latency.tsv`, `latency-samples.tsv`: create-to-first-exec per concurrency.
//! - `micro.txt`: in-sandbox microbenchmark results.
//! - `env.txt`, `quote.bin`, `quote.txt`, `ccel-*.bin`, `ccel-replay.txt` and one
//!   `<check>.log` per external tool.
//!
//! Every check line is also printed to stdout as `CLOVELLY-CHECK ...` for the serial log.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, bail};
use common::{ccel, tdx::Quote};

use crate::Flags;
use crate::latency::{self, Setup};
use crate::phase1;
use crate::runsc::{Bind, Bundle, Cgroups, Network, NetworkMode, Runsc, Spec};
use common::ids::SandboxId;
use crate::stats::{Summary, ms};
use crate::tsm;

const BASE_ROOTFS: &str = "/run/clovelly/base/rootfs";
const RUNSC_STATE: &str = "/run/clovelly/runsc";
const BUNDLES: &str = "/run/clovelly/bundles";
const BENCH_NETNS: &str = "clovelly-bench";
/// Wall-clock budget per latency configuration before the watchdog steps in.
const LATENCY_BUDGET: Duration = Duration::from_secs(15 * 60);

/// A group of checks the harness can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Test {
    /// Criterion 2: python3 in a systrap sandbox from the base bundle.
    Runsc,
    /// Criteria 3 to 6: configfs-tsm quote, CCEL replay and the Google tools.
    Attest,
    /// Criterion 7 (in-boot half): root is mounted through dm-verity.
    Verity,
    /// Criterion 8: create-to-first-exec latency.
    Latency,
    /// Criterion 9: in-sandbox microbenchmarks.
    Micro,
    /// Phase 1 criteria 13 and 14: Secure Boot and boot integrity.
    SecureBoot,
    /// Phase 1 criteria 1 and 10: unlock, certificate, TLS, positive scan control.
    Unlock,
    /// Phase 1 criterion 14: the verifier refuses this (altered) cell with check 6.
    Refused,
    /// Phase 1 criterion 9: the agent refuses a root hash other than the mounted one.
    RootHash,
    /// Phase 1 criterion 10: a wrong verifier URL never unlocks; no DEK in memory.
    WrongUrl,
    /// Phase 1 criterion 4: unlock latency, warm and cold.
    UnlockLatency,
    /// Phase 1 criterion 11: egress through Cloud NAT.
    Egress,
    /// Phase 3 criterion 8: throughput through the egress proxy, and the diagnosis of
    /// phase 0's retransmissions.
    Throughput,
    /// Phase 5: the clock within 1 s of Google's NTP (chrony).
    Clock,
}

impl std::str::FromStr for Test {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        Ok(match s {
            "runsc" => Test::Runsc,
            "attest" => Test::Attest,
            "verity" => Test::Verity,
            "latency" => Test::Latency,
            "micro" => Test::Micro,
            "secureboot" => Test::SecureBoot,
            "unlock" => Test::Unlock,
            "refused" => Test::Refused,
            "roothash" => Test::RootHash,
            "wrong-url" => Test::WrongUrl,
            "unlock-latency" => Test::UnlockLatency,
            "egress" => Test::Egress,
            "throughput" => Test::Throughput,
            "clock" => Test::Clock,
            other => bail!("unknown test {other:?}"),
        })
    }
}

/// `cell-agent harness --out DIR --tests a,b,.. [--concurrency 1,10,..] [--samples N]
/// [--peer IP:PORT]`
#[derive(Debug)]
pub struct Config {
    pub out: PathBuf,
    pub tests: Vec<Test>,
    pub concurrency: Vec<usize>,
    pub samples: usize,
    pub peer: Option<SocketAddr>,
}

impl Config {
    pub fn parse(args: &[String]) -> anyhow::Result<Self> {
        let flags = Flags::new(
            args,
            &["--out", "--tests", "--concurrency", "--samples", "--peer"],
        )?;
        Ok(Self {
            out: flags.require("--out")?.into(),
            tests: flags.list("--tests")?.unwrap_or_default(),
            concurrency: flags
                .list("--concurrency")?
                .unwrap_or_else(|| vec![1, 10, 20, 50]),
            samples: flags.parse("--samples")?.unwrap_or(200),
            peer: flags.parse("--peer")?,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Status {
    Pass,
    Fail,
    Measured,
}

/// Appends check results to `checks.tsv` and echoes them to stdout.
pub(crate) struct Checks {
    file: fs::File,
}

impl Checks {
    pub(crate) fn record(&mut self, id: &str, status: Status, detail: impl std::fmt::Display) {
        let status = match status {
            Status::Pass => "pass",
            Status::Fail => "fail",
            Status::Measured => "measured",
        };
        let detail = detail.to_string().replace(['\t', '\n', '\r'], " ");
        println!("CLOVELLY-CHECK {id} {status} {detail}");
        // Results are best effort per line; the serial echo above is the fallback.
        let _ = writeln!(self.file, "{id}\t{status}\t{detail}");
    }

    pub(crate) fn outcome(&mut self, id: &str, r: anyhow::Result<String>) {
        match r {
            Ok(detail) => self.record(id, Status::Pass, detail),
            Err(e) => self.record(id, Status::Fail, format!("{e:#}")),
        }
    }
}

pub fn run(cfg: &Config) -> anyhow::Result<()> {
    fs::create_dir_all(&cfg.out).with_context(|| format!("creating {}", cfg.out.display()))?;
    fs::create_dir_all(BUNDLES)?;
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(cfg.out.join("checks.tsv"))?;
    let mut checks = Checks { file };
    let runsc = Runsc {
        bin: "runsc".into(),
        state: RUNSC_STATE.into(),
        cgroups: Cgroups::Ignore,
        network: NetworkMode::None,
        extra: Vec::new(),
    };
    write_env(&cfg.out, &runsc)?;
    let setup = Setup {
        runsc: &runsc,
        rootfs: Path::new(BASE_ROOTFS),
        scratch: Path::new(BUNDLES),
    };
    for test in &cfg.tests {
        match test {
            Test::Runsc => checks.outcome("c2-runsc-python", python_in_sandbox(&runsc)),
            Test::Attest => attest(&mut checks, &cfg.out),
            Test::Verity => checks.outcome("c7-root-verity", root_on_verity(&cfg.out)),
            Test::Latency => latency(&mut checks, &cfg.out, setup, cfg)?,
            Test::Micro => checks.outcome("c9-micro", micro(&cfg.out, &runsc, cfg.peer)),
            Test::SecureBoot => phase1::secure_boot(&mut checks),
            Test::Unlock => phase1::unlock(&mut checks, &cfg.out),
            Test::Refused => phase1::refused(&mut checks, &cfg.out),
            Test::RootHash => phase1::root_hash_refused(&mut checks),
            Test::WrongUrl => phase1::wrong_url(&mut checks),
            Test::UnlockLatency => phase1::unlock_latency(&mut checks, &cfg.out, cfg.samples),
            Test::Egress => phase1::egress(&mut checks),
            Test::Throughput => match cfg.peer {
                Some(peer) => {
                    let r = crate::throughput::run(&mut checks, &cfg.out, peer);
                    if let Err(e) = r {
                        checks.record("c8-throughput", Status::Fail, format!("{e:#}"));
                    }
                }
                None => checks.record("c8-throughput", Status::Fail, "needs --peer (the destination VM's IP:80)"),
            },
            Test::Clock => crate::clock::clock(&mut checks, &cfg.out),
        }
    }
    Ok(())
}

fn write_env(out: &Path, runsc: &Runsc) -> anyhow::Result<()> {
    let version = Command::new(&runsc.bin).arg("--version").output()?;
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")?;
    let cmdline = fs::read_to_string("/proc/cmdline")?;
    let mem = fs::read_to_string("/proc/meminfo")?;
    let mem = mem.lines().next().unwrap_or_default();
    let cpus = std::thread::available_parallelism().map_or(0, usize::from);
    let runsc_version = String::from_utf8_lossy(&version.stdout);
    let env = format!(
        "kernel={}\ncpus={cpus}\n{mem}\ncmdline={}\nrunsc={}\n",
        kernel.trim(),
        cmdline.trim(),
        runsc_version.lines().next().unwrap_or_default(),
    );
    print!("{env}");
    Ok(fs::write(out.join("env.txt"), env)?)
}

fn python_in_sandbox(runsc: &Runsc) -> anyhow::Result<String> {
    let bundle = Bundle::write(
        Path::new(BUNDLES).join("c2"),
        &Spec {
            rootfs: Path::new(BASE_ROOTFS),
            args: &["/bin/python3", "-c", "print(1)"],
            env: &[],
            network: &Network::None,
            binds: &[],
            resources: None,
        },
    )?;
    let out = runsc.run(&SandboxId::generate(), &bundle, &Network::None)?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() || stdout != "1\n" {
        bail!(
            "exit {}, stdout {stdout:?}, stderr {:?}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok("python3 -c 'print(1)' printed 1 and exited 0".into())
}

/// Criteria 3 to 6, all on one fresh quote.
fn attest(checks: &mut Checks, out: &Path) {
    let quoted = (|| -> anyhow::Result<(Quote, String)> {
        let nonce = tsm::random_report_data()?;
        let report = tsm::quote(&nonce)?;
        fs::write(out.join("quote.bin"), &report.quote)?;
        let quote = Quote::parse(&report.quote)?;
        let rtmrs: Vec<String> = quote.rtmrs.iter().map(ToString::to_string).collect();
        fs::write(
            out.join("quote.txt"),
            format!(
                "provider={}\nversion={:?}\ntd_attributes={:#018x}\ndebug={}\nmr_td={}\nmr_owner={}\nrtmr={}\nreport_data={}\nnonce={nonce}\nmr_seam={}\nxfam={}\ntee_tcb_svn={}\n",
                report.provider,
                quote.version,
                quote.td_attributes,
                quote.debug(),
                quote.mr_td,
                quote.mr_owner,
                rtmrs.join(","),
                quote.report_data,
                quote.mr_seam,
                quote.xfam,
                common::hex(&quote.tee_tcb_svn),
            ),
        )?;
        if report.provider != "tdx_guest" {
            bail!("provider is {:?}, not tdx_guest", report.provider);
        }
        if quote.report_data != nonce {
            bail!(
                "REPORTDATA {} differs from the nonce {nonce}",
                quote.report_data
            );
        }
        Ok((quote, nonce.to_string()))
    })();
    let (quote, nonce) = match quoted {
        Ok(q) => q,
        Err(e) => {
            checks.record("c3-tsm-reportdata", Status::Fail, format!("{e:#}"));
            return;
        }
    };
    checks.record(
        "c3-tsm-reportdata",
        Status::Pass,
        format!(
            "{:?} quote, REPORTDATA equals 64 fresh random bytes",
            quote.version
        ),
    );
    checks.outcome("c4-ccel-replay", replay(out, &quote));
    checks.outcome(
        "c4-check-quote",
        tool(
            out,
            "c4-check-quote",
            "check",
            &[
                "-in",
                "quote.bin",
                "-get_collateral=true",
                "-check_crl=true",
                "-report_data",
                &nonce,
            ],
        ),
    );
    checks.outcome(
        "c5-gceprovenance",
        tool(
            out,
            "c5-gceprovenance",
            "gceprovenance",
            &[
                "verify",
                "-quote",
                "quote.bin",
                "-challenge",
                &nonce,
                "-out-dir",
                ".",
            ],
        ),
    );
    checks.outcome(
        "c6-gcetcbendorsement",
        tool(
            out,
            "c6-gcetcbendorsement",
            "gcetcbendorsement",
            &["tdx", "validate", "quote.bin"],
        ),
    );
}

/// Criterion 4: our replay of the CCEL reproduces the quote's RTMRs.
fn replay(out: &Path, quote: &Quote) -> anyhow::Result<String> {
    let table = fs::read(ccel::TABLE_PATH).context(ccel::TABLE_PATH)?;
    let log = fs::read(ccel::LOG_PATH).context(ccel::LOG_PATH)?;
    fs::write(out.join("ccel-table.bin"), &table)?;
    fs::write(out.join("ccel-log.bin"), &log)?;
    let replayed = ccel::replay_against(&table, &log, &quote.rtmrs)?;
    let report: String = replayed
        .rtmrs
        .iter()
        .enumerate()
        .map(|(i, r)| format!("rtmr{i}={r}\n"))
        .collect();
    fs::write(
        out.join("ccel-replay.txt"),
        format!("events={}\n{report}", replayed.events),
    )?;
    Ok(format!(
        "{} events replay to RTMR0..3 in the quote",
        replayed.events
    ))
}

/// Runs an external checker in `out`, saving its output to `<name>.log`.
fn tool(out: &Path, name: &str, prog: &str, args: &[&str]) -> anyhow::Result<String> {
    let o = Command::new(prog)
        .args(args)
        .current_dir(out)
        .output()
        .with_context(|| format!("running {prog}"))?;
    let mut log = format!("$ {prog} {}\n", args.join(" ")).into_bytes();
    log.extend_from_slice(&o.stdout);
    log.extend_from_slice(&o.stderr);
    fs::write(out.join(format!("{name}.log")), &log)?;
    let text = String::from_utf8_lossy(&log);
    let last = text
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or_default();
    if o.status.success() {
        Ok(format!("{prog} exited 0: {last}"))
    } else {
        bail!("{prog} exited {}: {last}", o.status)
    }
}

/// Criterion 7, in-boot half: `/` is erofs on the dm-verity device and verified.
fn root_on_verity(out: &Path) -> anyhow::Result<String> {
    let mounts = fs::read_to_string("/proc/mounts")?;
    let root = mounts
        .lines()
        .find(|l| l.split_whitespace().nth(1) == Some("/"))
        .context("no / in /proc/mounts")?
        .to_owned();
    let status = Command::new("veritysetup")
        .args(["status", "root"])
        .output()?;
    let status = String::from_utf8_lossy(&status.stdout).into_owned();
    fs::write(out.join("verity.txt"), format!("{root}\n{status}"))?;
    let mut fields = root.split_whitespace();
    let (dev, fstype) = (
        fields.next().unwrap_or_default(),
        fields.nth(1).unwrap_or_default(),
    );
    let verified = status
        .lines()
        .any(|l| l.split_whitespace().eq(["status:", "verified"]));
    if dev != "/dev/mapper/root" || fstype != "erofs" || !verified {
        bail!(
            "root is {dev} ({fstype}); veritysetup status: {}",
            status.trim()
        );
    }
    Ok(format!("/ is erofs on {dev}, veritysetup reports verified"))
}

fn latency(checks: &mut Checks, out: &Path, setup: Setup<'_>, cfg: &Config) -> anyhow::Result<()> {
    latency::warm_up(setup, 3, LATENCY_BUDGET).context("warm-up sandboxes")?;
    let mut table = OpenOptions::new()
        .create(true)
        .append(true)
        .open(out.join("latency.tsv"))?;
    let mut raw = OpenOptions::new()
        .create(true)
        .append(true)
        .open(out.join("latency-samples.tsv"))?;
    writeln!(
        table,
        "concurrency\tok\tfailed\tp50_ms\tp95_ms\tmin_ms\tmax_ms\tcreate_p50_ms\tstart_p50_ms\texec_p50_ms\tdelete_p50_ms\twall_s\ttimed_out\tfirst_error"
    )?;
    writeln!(
        raw,
        "concurrency\ttotal_ms\tcreate_ms\tstart_ms\texec_ms\tdelete_ms"
    )?;
    for &c in &cfg.concurrency {
        let o = latency::measure(setup, c, cfg.samples, LATENCY_BUDGET);
        for s in &o.samples {
            let (t, cr, st, ex, de) = (
                ms(s.total),
                ms(s.create),
                ms(s.start),
                ms(s.exec),
                ms(s.delete),
            );
            writeln!(raw, "{c}\t{t}\t{cr}\t{st}\t{ex}\t{de}")?;
        }
        let first_error = o
            .failures
            .first()
            .map(String::as_str)
            .unwrap_or("-")
            .replace(['\t', '\n'], " ");
        let step = |f: fn(&latency::Sample) -> Duration| {
            let v: Vec<Duration> = o.samples.iter().map(f).collect();
            Summary::of(&v).map_or_else(|| "-".to_owned(), |s| ms(s.p50))
        };
        let summary = total_summary(&o.samples);
        let cols = summary.map_or_else(
            || "-\t-\t-\t-".to_owned(),
            |s| format!("{}\t{}\t{}\t{}", ms(s.p50), ms(s.p95), ms(s.min), ms(s.max)),
        );
        writeln!(
            table,
            "{c}\t{}\t{}\t{cols}\t{}\t{}\t{}\t{}\t{:.1}\t{}\t{first_error}",
            o.samples.len(),
            o.failures.len(),
            step(|s| s.create),
            step(|s| s.start),
            step(|s| s.exec),
            step(|s| s.delete),
            o.wall.as_secs_f64(),
            o.timed_out,
        )?;
        let detail = match summary {
            Some(s) => format!(
                "{}/{} ok, {} failed, p50 {} ms, p95 {} ms",
                s.n,
                o.target,
                o.failures.len(),
                ms(s.p50),
                ms(s.p95)
            ),
            None => format!("0/{} ok; first error: {first_error}", o.target),
        };
        checks.record(&format!("c8-latency-c{c}"), Status::Measured, detail);
    }
    Ok(())
}

/// Summary of the criterion's interval (`total`) over the samples.
fn total_summary(samples: &[latency::Sample]) -> Option<Summary> {
    Summary::of(&samples.iter().map(|s| s.total).collect::<Vec<_>>())
}

/// Criterion 9: runs `cell-agent bench` inside a sandbox whose netns is bridged to the
/// host by a veth pair and masqueraded out of eth0.
/// The same benchmark also runs on the host first, as a baseline that separates the VM's
/// own costs (for example TDX I/O) from gVisor's; its results go to `micro-host.txt`.
fn micro(out: &Path, runsc: &Runsc, peer: Option<SocketAddr>) -> anyhow::Result<String> {
    let agent = std::env::current_exe()?;
    let peer_arg = peer.map(|p| p.to_string());
    let mut args = vec!["/clovelly-agent", "bench"];
    if let Some(p) = &peer_arg {
        args.extend(["--peer", p]);
    }

    let host = Command::new(&agent)
        .args(&args[1..])
        .args(["--dir", "/run/clovelly/bench-host"])
        .output()?;
    fs::write(out.join("micro-host.txt"), &host.stdout)?;
    if !host.status.success() {
        bail!(
            "host bench exited {}: {}",
            host.status,
            String::from_utf8_lossy(&host.stderr).trim()
        );
    }

    let netns = bench_netns()?;
    let network = Network::Netns(netns);
    let bundle = Bundle::write(
        Path::new(BUNDLES).join("micro"),
        &Spec {
            rootfs: Path::new(BASE_ROOTFS),
            args: &args,
            env: &[],
            network: &network,
            binds: &[Bind {
                source: agent,
                destination: "/clovelly-agent".into(),
                writable: false,
            }],
            resources: None,
        },
    )?;
    let o = runsc.run(&SandboxId::generate(), &bundle, &network)?;
    fs::write(out.join("micro.txt"), &o.stdout)?;
    fs::write(out.join("micro.stderr"), &o.stderr)?;
    print!("{}", String::from_utf8_lossy(&o.stdout));
    if !o.status.success() {
        bail!(
            "bench exited {}: {}",
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&o.stdout)
        .lines()
        .collect::<Vec<_>>()
        .join(" "))
}

/// Creates the benchmark netns: veth 10.200.0.1/30 (host) <-> 10.200.0.2/30 (sandbox),
/// default route via the host, forwarding on, and masquerade out of eth0.
fn bench_netns() -> anyhow::Result<PathBuf> {
    let ns = |args: &[&str]| -> Vec<String> {
        ["ip", "netns", "exec", BENCH_NETNS]
            .iter()
            .chain(args)
            .map(|s| s.to_string())
            .collect()
    };
    let steps: Vec<Vec<String>> = vec![
        words("ip netns add clovelly-bench"),
        words("ip link add clovelly-h mtu 1460 type veth peer name clovelly-s mtu 1460"),
        words("ip link set clovelly-s netns clovelly-bench"),
        words("ip addr add 10.200.0.1/30 dev clovelly-h"),
        words("ip link set clovelly-h up"),
        ns(&["ip", "addr", "add", "10.200.0.2/30", "dev", "clovelly-s"]),
        ns(&["ip", "link", "set", "clovelly-s", "up"]),
        ns(&["ip", "link", "set", "lo", "up"]),
        ns(&["ip", "route", "add", "default", "via", "10.200.0.1"]),
        words("sysctl -w net.ipv4.ip_forward=1"),
        words("nft add table ip clovelly"),
        vec![
            "nft".into(),
            "add".into(),
            "chain".into(),
            "ip".into(),
            "clovelly".into(),
            "post".into(),
            "{ type nat hook postrouting priority 100 ; }".into(),
        ],
        words("nft add rule ip clovelly post ip saddr 10.200.0.0/30 oifname eth0 masquerade"),
    ];
    for step in &steps {
        let o = Command::new(&step[0]).args(&step[1..]).output()?;
        if !o.status.success() {
            bail!(
                "{}: {}",
                step.join(" "),
                String::from_utf8_lossy(&o.stderr).trim()
            );
        }
    }
    Ok(Path::new("/run/netns").join(BENCH_NETNS))
}

fn words(s: &str) -> Vec<String> {
    s.split_whitespace().map(str::to_owned).collect()
}
