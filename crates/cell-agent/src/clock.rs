//! Phase 5: the cell's clock against Google's NTP server (`cell-agent harness --tests
//! clock`, test image only).
//!
//! chronyd keeps the clock from `metadata.google.internal` (image/chrony.conf). This
//! check does not trust chronyd's own report: it asks the same server directly with
//! SNTP (RFC 4330) and measures the offset, which must be within 1 s.

use std::fs;
use std::net::UdpSocket;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};

use crate::harness::Checks;

/// Google's NTP server, on the metadata server.
const SERVER: &str = "metadata.google.internal:123";
/// Seconds from the NTP epoch (1900) to the Unix epoch.
const NTP_UNIX: f64 = 2_208_988_800.0;
const SAMPLES: usize = 7;
/// The criterion: the clock within 1 s of Google's NTP.
const BOUND_SECS: f64 = 1.0;

/// Records chrony's view, then the measured offset.
pub(crate) fn clock(checks: &mut Checks, out: &Path) {
    for (file, args) in [("chrony-tracking.txt", ["-n", "tracking"]), ("chrony-sources.txt", ["-n", "sources"])] {
        let report = Command::new("chronyc")
            .args(args)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr))
            .unwrap_or_else(|e| format!("chronyc: {e}"));
        let _ = fs::write(out.join(file), report);
    }
    checks.outcome("p5-clock-google-ntp", measure(out));
}

fn measure(out: &Path) -> anyhow::Result<String> {
    let mut offsets = (0..SAMPLES)
        .map(|_| {
            let o = offset();
            std::thread::sleep(Duration::from_millis(500));
            o
        })
        .collect::<anyhow::Result<Vec<f64>>>()?;
    offsets.sort_by(f64::total_cmp);
    let median = offsets[SAMPLES / 2];
    let line = offsets.iter().map(|o| format!("{o:+.6}")).collect::<Vec<_>>().join(" ");
    fs::write(out.join("clock.txt"), format!("server={SERVER}\noffsets_s={line}\nmedian_s={median:+.6}\n"))?;
    if median.abs() > BOUND_SECS {
        bail!("clock is {median:+.3} s from Google's NTP (samples {line}); the bound is {BOUND_SECS} s");
    }
    Ok(format!("median offset {median:+.6} s from {SERVER} over {SAMPLES} SNTP queries (bound {BOUND_SECS} s); samples {line}"))
}

/// One SNTP exchange: (server receive - client send + server send - client receive) / 2,
/// the server's clock minus ours, in seconds.
fn offset() -> anyhow::Result<f64> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))?;
    sock.connect(SERVER).context("resolving the NTP server")?;
    let mut req = [0u8; 48];
    req[0] = 0x23; // LI 0, version 4, mode 3 (client)
    let t1 = unix_now();
    sock.send(&req)?;
    let mut resp = [0u8; 48];
    let n = sock.recv(&mut resp)?;
    let t4 = unix_now();
    if n < 48 || resp[0] & 0x07 != 4 {
        bail!("not an NTP server reply ({n} bytes, mode {})", resp[0] & 0x07);
    }
    let (t2, t3) = (timestamp(&resp[32..40]), timestamp(&resp[40..48]));
    Ok(((t2 - t1) + (t3 - t4)) / 2.0)
}

fn unix_now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64())
}

/// An NTP timestamp (32.32 fixed point from 1900) as Unix seconds.
fn timestamp(b: &[u8]) -> f64 {
    let secs = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    let frac = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
    f64::from(secs) - NTP_UNIX + f64::from(frac) / 4_294_967_296.0
}

#[cfg(test)]
mod tests {
    #[test]
    fn ntp_timestamps_convert_to_unix_seconds() {
        // 2026-10-28 00:00:00 UTC is 1792972800 Unix, 4_001_961_600 NTP; half a second.
        let mut b = [0u8; 8];
        b[..4].copy_from_slice(&4_001_961_600u32.to_be_bytes());
        b[4..].copy_from_slice(&(1u32 << 31).to_be_bytes());
        assert_eq!(super::timestamp(&b), 1_792_972_800.5);
    }
}
