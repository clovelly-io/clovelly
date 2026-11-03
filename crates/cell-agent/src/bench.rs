//! Microbenchmarks (phase 0 criterion 9), and the TCP sink the transfer benchmark sends
//! to on a second VM.
//!
//! `cell-agent bench [--peer IP:PORT] [--dir DIR]` prints one `key=value` line per
//! result. The harness runs it inside a sandbox (the criterion) and on the host as a
//! baseline, writing files under DIR (default `/work`).
//!
//! Phase 3's production-path benchmark runs these inside sandboxes, against the test
//! destination's HTTP server (`cell-agent dest`), through the egress proxy:
//!
//! - `cell-agent bench-http --to IP:PORT --bytes N --count C [--tcp-recovery V]` POSTs
//!   N bytes to `/sink` C times, one connection each, and prints one JSON line: each
//!   transfer's time, this network stack's TCP counters before and after, and its
//!   `tcp_recovery` (1 is RACK-TLP loss detection, 0 is off, as a cell's sandboxes
//!   start). `--tcp-recovery V` sets it first (`/proc/sys/net/ipv4/tcp_recovery`; the
//!   throughput diagnosis only).
//! - `cell-agent bench-hold --to IP:PORT --connections N` opens N connections, sends
//!   `GET /hold` on each and waits for every answer, then asks `/count` how many the
//!   destination holds open, and prints one JSON line.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use crate::stats::{Summary, ms};

const SYSCALL_ROUNDS: usize = 5;
const SYSCALLS_PER_ROUND: u32 = 200_000;
/// 100 MB, decimal, per transfer.
const TRANSFER_BYTES: usize = 100_000_000;
const TRANSFERS: usize = 10;

/// Runs every benchmark and prints its results to stdout.
pub fn run(peer: Option<SocketAddr>, dir: &Path) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "syscall_getppid_ns={:.1}", syscall_round_trip_ns())?;
    for (name, size, iters) in [("write_4k", 4096, 2000), ("write_1m", 1 << 20, 200)] {
        let s = file_write(dir, size, iters)?;
        writeln!(out, "{name}_p50_ms={}", ms(s.p50))?;
        writeln!(out, "{name}_p95_ms={}", ms(s.p95))?;
    }
    if let Some(peer) = peer {
        let retrans_before = tcp_retrans_segs();
        let runs = tcp_transfer(peer)?;
        let s = Summary::of(&runs).expect("TRANSFERS > 0");
        let mbps = |d: Duration| TRANSFER_BYTES as f64 / 1e6 / d.as_secs_f64();
        writeln!(out, "tcp_100mb_p50_ms={}", ms(s.p50))?;
        writeln!(out, "tcp_100mb_p50_MBps={:.1}", mbps(s.p50))?;
        writeln!(out, "tcp_100mb_best_MBps={:.1}", mbps(s.min))?;
        let runs: Vec<String> = runs.iter().map(|d| ms(*d)).collect();
        writeln!(out, "tcp_100mb_runs_ms={}", runs.join(","))?;
        if let (Some(before), Some(after)) = (retrans_before, tcp_retrans_segs()) {
            writeln!(out, "tcp_retrans_segs={}", after.saturating_sub(before))?;
        }
    }
    Ok(())
}

/// Median cost of a `getppid` round trip into the sandbox kernel. glibc does not cache
/// getppid, so each call is a real syscall.
fn syscall_round_trip_ns() -> f64 {
    let mut rounds: Vec<f64> = (0..SYSCALL_ROUNDS)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..SYSCALLS_PER_ROUND {
                std::hint::black_box(std::os::unix::process::parent_id());
            }
            t.elapsed().as_nanos() as f64 / f64::from(SYSCALLS_PER_ROUND)
        })
        .collect();
    rounds.sort_by(f64::total_cmp);
    rounds[SYSCALL_ROUNDS / 2]
}

/// Per-operation time to create, write and close a file of `size` bytes in `dir` (in a
/// sandbox, its root overlay).
fn file_write(dir: &Path, size: usize, iters: usize) -> io::Result<Summary> {
    fs::create_dir_all(dir)?;
    let path = dir.join(format!("bench-{size}"));
    let buf = vec![0x5a; size];
    let times = (0..iters)
        .map(|_| {
            let t = Instant::now();
            fs::write(&path, &buf)?;
            Ok(t.elapsed())
        })
        .collect::<io::Result<Vec<_>>>()?;
    fs::remove_file(&path)?;
    Ok(Summary::of(&times).expect("iters > 0"))
}

/// Times of sending 100 MB to the sink and seeing it close the connection, which it
/// does only after reading everything.
fn tcp_transfer(peer: SocketAddr) -> io::Result<Vec<Duration>> {
    let chunk = vec![0xa5; 1 << 20];
    (0..TRANSFERS)
        .map(|_| {
            let t = Instant::now();
            let mut s = TcpStream::connect(peer)?;
            let mut left = TRANSFER_BYTES;
            while left > 0 {
                let n = left.min(chunk.len());
                s.write_all(&chunk[..n])?;
                left -= n;
            }
            s.shutdown(Shutdown::Write)?;
            s.read_to_end(&mut Vec::new())?;
            Ok(t.elapsed())
        })
        .collect()
}

/// TCP segments retransmitted so far by this network stack, from `/proc/net/snmp`.
fn tcp_retrans_segs() -> Option<u64> {
    let snmp = fs::read_to_string("/proc/net/snmp").ok()?;
    let mut tcp = snmp.lines().filter(|l| l.starts_with("Tcp:"));
    let (names, values) = (tcp.next()?, tcp.next()?);
    names
        .split_whitespace()
        .zip(values.split_whitespace())
        .find(|(name, _)| *name == "RetransSegs")
        .and_then(|(_, v)| v.parse().ok())
}

/// Accepts connections forever, reads each to EOF, then closes it.
pub fn sink(listen: SocketAddr) -> io::Result<()> {
    let listener = TcpListener::bind(listen)?;
    eprintln!("sink listening on {listen}");
    for stream in listener.incoming() {
        let mut stream = stream?;
        thread::spawn(move || {
            let peer = stream.peer_addr().ok();
            let t = Instant::now();
            let r = io::copy(&mut stream, &mut io::sink());
            let _ = stream.shutdown(Shutdown::Both);
            eprintln!("sink {peer:?}: {r:?} in {:?}", t.elapsed());
        });
    }
    Ok(())
}

/// This network stack's TCP counters from `/proc/net/snmp` (`OutSegs`, `RetransSegs`).
pub fn tcp_counters() -> Option<(u64, u64)> {
    let snmp = fs::read_to_string("/proc/net/snmp").ok()?;
    let mut tcp = snmp.lines().filter(|l| l.starts_with("Tcp:"));
    let (names, values) = (tcp.next()?, tcp.next()?);
    let field = |want: &str| {
        names
            .split_whitespace()
            .zip(values.split_whitespace())
            .find(|(name, _)| *name == want)
            .and_then(|(_, v)| v.parse().ok())
    };
    Some((field("OutSegs")?, field("RetransSegs")?))
}

/// The receive-side TcpExt counters the throughput benchmark reads on both ends of a
/// hop: backlog and receive-queue drops, out-of-order drops, and the duplicate-data
/// reports (DSACK) that mark the sender's retransmissions as spurious.
pub const TCPEXT: [&str; 5] = ["TCPBacklogDrop", "TCPRcvQDrop", "TCPDSACKOldSent", "TCPDSACKOfoSent", "TCPOFODrop"];

/// This machine's [`TCPEXT`] counters, from `/proc/net/netstat`.
pub fn tcpext() -> HashMap<&'static str, u64> {
    let text = fs::read_to_string("/proc/net/netstat").unwrap_or_default();
    let mut lines = text.lines().filter(|l| l.starts_with("TcpExt:"));
    let (Some(names), Some(values)) = (lines.next(), lines.next()) else { return HashMap::new() };
    names
        .split_whitespace()
        .zip(values.split_whitespace())
        .filter_map(|(n, v)| Some((*TCPEXT.iter().find(|t| **t == n)?, v.parse().ok()?)))
        .collect()
}

/// `GET path` from `to` on a fresh connection; the body of a 200.
pub fn get(to: SocketAddr, path: &str) -> io::Result<String> {
    let mut s = TcpStream::connect_timeout(&to, Duration::from_secs(10))?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    write!(s, "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", to.ip())?;
    response(&mut s)
}

/// Reads an HTTP response head and a body of its Content-Length; the body.
fn response(s: &mut TcpStream) -> io::Result<String> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            while buf.len() < end + 4 + len {
                let n = s.read(&mut chunk)?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            if !head.starts_with("http/1.1 200") {
                return Err(io::Error::other(format!("answered {}", head.lines().next().unwrap_or_default())));
            }
            return Ok(String::from_utf8_lossy(&buf[end + 4..]).into_owned());
        }
        let n = s.read(&mut chunk)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// `bench-http`: `count` POSTs of `bytes` to `to`'s `/sink`, after setting this
/// netstack's `tcp_recovery` to `recovery` if given.
pub fn http(to: SocketAddr, bytes: u64, count: usize, recovery: Option<u8>) -> io::Result<()> {
    const TCP_RECOVERY: &str = "/proc/sys/net/ipv4/tcp_recovery";
    if let Some(v) = recovery {
        fs::write(TCP_RECOVERY, v.to_string())?;
    }
    let in_force: Option<u8> = fs::read_to_string(TCP_RECOVERY).ok().and_then(|t| t.trim().parse().ok());
    let chunk = vec![0xa5u8; 1 << 20];
    let before = tcp_counters();
    let mut times = Vec::with_capacity(count);
    let mut errors = Vec::new();
    for _ in 0..count {
        let t = Instant::now();
        let r = (|| {
            let mut s = TcpStream::connect(to)?;
            s.set_nodelay(true)?;
            write!(s, "POST /sink HTTP/1.1\r\nHost: {}\r\nContent-Length: {bytes}\r\nConnection: close\r\n\r\n", to.ip())?;
            let mut left = bytes;
            while left > 0 {
                let n = usize::try_from(left).unwrap_or(usize::MAX).min(chunk.len());
                s.write_all(&chunk[..n])?;
                left -= n as u64;
            }
            response(&mut s)
        })();
        match r {
            Ok(_) => times.push(t.elapsed().as_secs_f64() * 1e3),
            Err(e) => errors.push(e.to_string()),
        }
    }
    let after = tcp_counters();
    println!(
        "{}",
        serde_json::json!({ "bytes": bytes, "times_ms": times, "errors": errors,
                            "tcp_before": before, "tcp_after": after, "tcp_recovery": in_force })
    );
    Ok(())
}

/// `bench-hold`: `n` connections held open at once.
pub fn hold(to: SocketAddr, n: usize) -> io::Result<()> {
    let t = Instant::now();
    let mut held = Vec::with_capacity(n);
    let mut errors = 0usize;
    let mut first_error = None;
    for _ in 0..n {
        let r = (|| {
            let mut s = TcpStream::connect(to)?;
            s.set_read_timeout(Some(Duration::from_secs(30)))?;
            write!(s, "GET /hold HTTP/1.1\r\nHost: {}\r\n\r\n", to.ip())?;
            response(&mut s)?;
            Ok::<_, io::Error>(s)
        })();
        match r {
            Ok(s) => held.push(s),
            Err(e) => {
                errors += 1;
                first_error.get_or_insert(e.to_string());
            }
        }
    }
    let open = (|| {
        let mut s = TcpStream::connect(to)?;
        write!(s, "GET /count HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", to.ip())?;
        response(&mut s)
    })();
    println!(
        "{}",
        serde_json::json!({ "held": held.len(), "errors": errors, "first_error": first_error,
                            "count": open.map_err(|e| e.to_string()), "ms": t.elapsed().as_millis() as u64 })
    );
    // Hold until told, so every sandbox's connections overlap.
    if std::env::var_os("CLOVELLY_HOLD_UNTIL_STDIN").is_some() {
        let mut line = String::new();
        let _ = io::stdin().read_line(&mut line);
    }
    drop(held);
    Ok(())
}
