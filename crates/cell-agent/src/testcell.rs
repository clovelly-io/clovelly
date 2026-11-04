//! `cell-agent test-cell` (test image only): runs the agent as a child (`cell-agent boot
//! --hold-on-end`) exactly as the prod image runs it, and when the cell ends (lease
//! lapsed, cap, drain), scans the agent's memory for the DEK marker before letting it
//! report `RECYCLE` (phase 2 criterion 15). The marker is the staging DEK, read from
//! test-only metadata `clovelly-dek-marker` at scan time, so it is never in the control
//! plane's records. Check lines go to stdout, which the test image sends to serial.
//!
//! It also acts on request: when test-only metadata `clovelly-scan` changes to
//! `<seq> <kind> [<arg>]` it runs one request and prints `CLOVELLY-SCAN {seq, kind, ...}`.
//! Kinds: `memory <marker hex>` and `tmpfs <marker hex>` search the agent's memory or
//! every file on the cell's tmpfs mounts (phase 3 criteria 9 and 12); `proxy-memory
//! <marker hex>` searches the egress proxy's process (phase 4 criterion 13);
//! `kill-proxy` kills the egress proxy (criteria 7 and 13); `kill-runsc <id>[,<id>...]`
//! kills those sandboxes' runsc sandbox processes, a runsc crash (criterion 7); `templates`
//! reports the template cache: overlay roots, their unpacked sizes and how many
//! sandboxes use each (criterion 1). The driver sets markers and judges the results.
//! A `CLOVELLY-HEARTBEAT <unix ms> <boot id>` line every second marks when the cell last
//! ran, and in which boot. A `CLOVELLY-RSS {agent_kib, proxy_kib, at}` line every minute
//! gives the two processes' resident memory, for the soak (phase 6 criterion 3).

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use anyhow::Context;
use serde_json::json;

use crate::{metadata, scan};

fn check(id: &str, status: &str, detail: impl std::fmt::Display) {
    let detail = detail.to_string().replace(['\t', '\n', '\r'], " ");
    println!("CLOVELLY-CHECK {id} {status} {detail}");
}

/// Runs the agent to its end and scans it. Returns when the agent has exited.
pub fn run() -> anyhow::Result<()> {
    let mut child = Command::new(std::env::current_exe()?)
        .args(["boot", "--hold-on-end"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("spawning cell-agent boot")?;
    let pid = child.id();
    std::thread::spawn(move || scans_on_request(pid));
    // A heartbeat on serial every second: after a hard stop, the last one is when this
    // boot last ran (phase 4 criterion 11).
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap_or_default().trim().to_owned();
    std::thread::spawn(move || {
        loop {
            println!("CLOVELLY-HEARTBEAT {} {boot}", unix_ms());
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    });
    std::thread::spawn(move || {
        loop {
            println!(
                "CLOVELLY-RSS {}",
                json!({ "agent_kib": rss_kib(pid), "proxy_kib": proxy_pid().ok().and_then(rss_kib), "at": unix_ms() })
            );
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    });
    let stdout = child.stdout.take().context("child stdout")?;
    let mut stdin = child.stdin.take().context("child stdin")?;
    let mut ending = None;
    for line in BufReader::new(stdout).lines().map_while(Result::ok) {
        println!("{line}");
        let Some(rest) = line.strip_prefix("CLOVELLY-AGENT ") else { continue };
        let (state, detail) = rest.split_once(' ').unwrap_or((rest, "{}"));
        match state {
            // The positive control: while the lease is held the marker is in memory.
            "renewing" => scan_agent(pid, Expect::Held, "renewing", detail),
            "revoked" | "cell-end" | "drained" | "listener-stopped" => ending = Some(state.to_owned()),
            "ended" => {
                let what = ending.clone().unwrap_or_else(|| "unknown".into());
                scan_agent(pid, Expect::Wiped, &what, detail);
                // Let the agent report RECYCLE and exit.
                let _ = writeln!(stdin);
            }
            _ => {}
        }
    }
    let status = child.wait()?;
    println!("CLOVELLY-TESTCELL exit {}", json!({ "agent_status": status.to_string(), "ending": ending }));
    Ok(())
}

/// What a scan should find.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// The lease is held: the DEK is in the agent's memory.
    Held,
    /// The cell has ended: no copy of the DEK is left.
    Wiped,
}

fn scan_agent(pid: u32, expect: Expect, when: &str, detail: &str) {
    let id = match expect {
        Expect::Held => format!("c15-dek-scan-control-while-{when}"),
        Expect::Wiped => format!("c15-dek-scan-after-{when}"),
    };
    let marker = match metadata::attribute("clovelly-dek-marker") {
        Ok(Some(hex)) => match common::unhex(hex.trim()) {
            Some(m) if !m.is_empty() => m,
            _ => return check(&id, "fail", "clovelly-dek-marker is not hex"),
        },
        Ok(None) => return check(&id, "measured", "no clovelly-dek-marker in this cell's metadata; not scanned"),
        Err(e) => return check(&id, "fail", e),
    };
    match (scan::scan(pid, &marker), expect) {
        (Ok(s), Expect::Wiped) if s.hits.is_empty() => check(
            &id,
            "pass",
            format!(
                "agent pid {pid} after {when} ({detail}): {} regions, {} MiB scanned, no DEK marker",
                s.regions,
                s.bytes >> 20
            ),
        ),
        (Ok(s), Expect::Held) if !s.hits.is_empty() => check(
            &id,
            "pass",
            format!("agent pid {pid} while {when}: the DEK marker is at {} address(es)", s.hits.len()),
        ),
        (Ok(s), _) => check(&id, "fail", format!("expected {expect:?}; DEK marker at {} addresses", s.hits.len())),
        (Err(e), _) => check(&id, "fail", format!("scanning pid {pid}: {e}")),
    }
}

/// Polls `clovelly-scan` every 2 seconds and runs each new request.
fn scans_on_request(pid: u32) {
    let mut last = String::new();
    loop {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let Ok(Some(req)) = metadata::attribute("clovelly-scan") else { continue };
        let req = req.trim().to_owned();
        if req == last {
            continue;
        }
        last.clone_from(&req);
        let mut f = req.split_whitespace();
        let (Some(seq), Some(kind)) = (f.next(), f.next()) else {
            println!("CLOVELLY-SCAN {}", json!({ "request": req, "error": "expected <seq> <kind> [<arg>]" }));
            continue;
        };
        let arg = f.next().unwrap_or_default();
        let marker = || common::unhex(arg).filter(|m| !m.is_empty()).ok_or_else(|| std::io::Error::other("the marker is not hex"));
        let started = std::time::Instant::now();
        let result = match kind {
            "memory" => marker().and_then(|m| scan::scan(pid, &m)).map(|s| json!({ "pid": pid, "regions": s.regions, "bytes": s.bytes, "hits": s.hits.len() })),
            "proxy-memory" => marker().and_then(|m| {
                let proxy = proxy_pid()?;
                scan::scan(proxy, &m).map(|s| json!({ "pid": proxy, "regions": s.regions, "bytes": s.bytes, "hits": s.hits.len() }))
            }),
            "tmpfs" => marker().and_then(|m| scan_tmpfs(&m)).map(|(files, bytes, hits)| json!({ "files": files, "bytes": bytes, "hits": hits.len(), "in": hits })),
            "kill-proxy" => proxy_pid().and_then(|p| kill(p).map(|()| json!({ "pid": p, "killed_unix_ms": unix_ms() }))),
            "kill-runsc" => Ok(json!({ "killed": arg.split(',').map(|id| match runsc_pid(id).and_then(|p| kill(p).map(|()| p)) {
                Ok(p) => json!({ "sandbox": id, "pid": p, "at_unix_ms": unix_ms() }),
                Err(e) => json!({ "sandbox": id, "error": e.to_string() }),
            }).collect::<Vec<_>>() })),
            "templates" => templates(),
            other => Ok(json!({ "error": format!("unknown request kind {other}") })),
        };
        let mut line = result.unwrap_or_else(|e| json!({ "error": e.to_string() }));
        line["seq"] = json!(seq);
        line["kind"] = json!(kind);
        line["ms"] = json!(started.elapsed().as_millis() as u64);
        println!("CLOVELLY-SCAN {line}");
    }
}

/// A process's resident memory in KiB.
fn rss_kib(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status.lines().find_map(|l| l.strip_prefix("VmRSS:")?.split_whitespace().next()?.parse().ok())
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// The processes whose argument lists satisfy `matches`.
fn pids(matches: impl Fn(&[&str]) -> bool) -> Vec<u32> {
    let Ok(dir) = std::fs::read_dir("/proc") else { return Vec::new() };
    dir.flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| {
            let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else { return false };
            let args: Vec<&str> = raw.split(|b| *b == 0).filter_map(|a| std::str::from_utf8(a).ok()).filter(|a| !a.is_empty()).collect();
            !args.is_empty() && matches(&args)
        })
        .collect()
}

fn proxy_pid() -> std::io::Result<u32> {
    pids(|a| a[0].rsplit('/').next() == Some("egress-proxy"))
        .into_iter()
        .next()
        .ok_or_else(|| std::io::Error::other("no egress-proxy process"))
}

/// The runsc sandbox process (the Sentry) of `sandbox`.
fn runsc_pid(sandbox: &str) -> std::io::Result<u32> {
    if sandbox.parse::<common::ids::SandboxId>().is_err() {
        return Err(std::io::Error::other("not a sandbox id"));
    }
    pids(|a| a[0].contains("runsc-sandbox") && a.contains(&"boot") && a.contains(&sandbox))
        .into_iter()
        .next()
        .ok_or_else(|| std::io::Error::other(format!("no runsc sandbox process for {sandbox}")))
}

fn kill(pid: u32) -> std::io::Result<()> {
    let out = Command::new("kill").args(["-9", &pid.to_string()]).output()?;
    if out.status.success() { Ok(()) } else { Err(std::io::Error::other(String::from_utf8_lossy(&out.stderr).trim().to_owned())) }
}

/// The template cache: each overlay root under /run/clovelly/templates, the unpacked size
/// of its files, and how many sandbox bundles name it as their root.
fn templates() -> std::io::Result<serde_json::Value> {
    let mounts = std::fs::read_to_string("/proc/mounts")?;
    let roots: Vec<String> = mounts
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let (_, at, kind) = (f.next()?, f.next()?, f.next()?);
            (kind == "overlay" && at.starts_with("/run/clovelly/templates/")).then(|| at.to_owned())
        })
        .collect();
    let mut users: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for e in std::fs::read_dir("/run/clovelly/bundles").into_iter().flatten().flatten() {
        let Ok(cfg) = std::fs::read(e.path().join("config.json")) else { continue };
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&cfg) else { continue };
        if let Some(root) = v["root"]["path"].as_str() {
            *users.entry(root.to_owned()).or_default() += 1;
        }
    }
    let entries: Vec<serde_json::Value> = roots
        .iter()
        .map(|r| {
            let files = std::path::Path::new(r).with_file_name("files");
            json!({ "root": r, "bytes": du(&files), "sandboxes": users.get(r).copied().unwrap_or(0) })
        })
        .collect();
    let meminfo = std::fs::read_to_string("/proc/meminfo")?;
    let shmem = meminfo.lines().find_map(|l| l.strip_prefix("Shmem:")).map(|v| v.trim().to_owned());
    Ok(json!({ "copies": roots.len(), "templates": entries, "bases": users.iter().filter(|(r, _)| !roots.contains(r)).map(|(r, n)| json!({ "root": r, "sandboxes": n })).collect::<Vec<_>>(), "shmem": shmem }))
}

/// Bytes of regular files under `dir`.
fn du(dir: &std::path::Path) -> u64 {
    let mut total = 0;
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(d) = dirs.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            match e.file_type() {
                Ok(t) if t.is_dir() => dirs.push(e.path()),
                Ok(t) if t.is_file() => total += e.metadata().map_or(0, |m| m.len()),
                _ => {}
            }
        }
    }
    total
}

/// Every regular file under the cell's tmpfs mounts (`/run`, `/tmp`, `/var`,
/// `/dev/shm`) searched for `marker`: files and bytes read, and the files it is in.
fn scan_tmpfs(marker: &[u8]) -> std::io::Result<(u64, u64, Vec<String>)> {
    let (mut files, mut bytes, mut hits) = (0u64, 0u64, Vec::new());
    let mut dirs: Vec<std::path::PathBuf> = ["/run", "/tmp", "/var", "/dev/shm"].iter().map(Into::into).collect();
    while let Some(dir) = dirs.pop() {
        // Namespace handles and runsc's sockets are not files to read.
        if dir.starts_with("/run/netns") {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for e in entries.flatten() {
            let Ok(t) = e.file_type() else { continue };
            if t.is_dir() {
                dirs.push(e.path());
            } else if t.is_file() {
                let Ok(data) = std::fs::read(e.path()) else { continue };
                files += 1;
                bytes += data.len() as u64;
                if data.windows(marker.len()).any(|w| w == marker) {
                    hits.push(e.path().display().to_string());
                }
            }
        }
    }
    Ok((files, bytes, hits))
}
