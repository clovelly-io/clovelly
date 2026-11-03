//! Sandbox create-to-first-exec latency (phase 0 criterion 8).
//!
//! One sample is the interval from calling `runsc create` to the first stdout byte of
//! `exec echo ok` in that sandbox, with `start` in between. Teardown is not timed.
//! At concurrency `c`, `c` workers run samples back to back until the target count is
//! reached, so about `c` sandboxes are alive at once. Each sample also records its steps
//! (create, start, exec to first byte) and the untimed teardown, to show where time goes.

use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use common::ids::SandboxId;

use crate::runsc::{Bundle, Network, Runsc, RunscError, Spec};

/// One measured sandbox.
#[derive(Debug, Clone, Copy)]
pub struct Sample {
    /// `runsc create` call to the first stdout byte of `exec echo ok`: the criterion.
    pub total: Duration,
    pub create: Duration,
    pub start: Duration,
    /// `runsc exec` call to its first stdout byte.
    pub exec: Duration,
    /// `runsc delete --force` afterwards; not part of `total`.
    pub delete: Duration,
}

/// Samples and failures for one concurrency level.
#[derive(Debug)]
pub struct Outcome {
    pub target: usize,
    pub samples: Vec<Sample>,
    pub failures: Vec<String>,
    pub wall: Duration,
    /// The configuration overran its budget and its runsc processes were killed.
    pub timed_out: bool,
}

/// Where sandboxes come from: the shared base rootfs and a tmpfs dir for bundles.
#[derive(Debug, Clone, Copy)]
pub struct Setup<'a> {
    pub runsc: &'a Runsc,
    pub rootfs: &'a Path,
    pub scratch: &'a Path,
}

/// Runs unmeasured samples so runsc and the rootfs are in page cache, under the same
/// watchdog as a measurement.
pub fn warm_up(setup: Setup<'_>, n: usize, budget: Duration) -> Result<(), RunscError> {
    let watchdog = Watchdog::arm(budget);
    let warmed = (0..n).try_for_each(|_| sample(setup, &SandboxId::generate()).map(drop));
    watchdog.disarm();
    warmed
}

/// Measures `target` samples at `concurrency`. Stops starting samples once `budget`
/// has passed, and kills all runsc processes a minute later if any are still stuck.
pub fn measure(setup: Setup<'_>, concurrency: usize, target: usize, budget: Duration) -> Outcome {
    let started = Instant::now();
    let deadline = started + budget;
    let next = AtomicUsize::new(0);
    let results = Mutex::new((Vec::with_capacity(target), Vec::new()));
    let watchdog = Watchdog::arm(budget + Duration::from_secs(60));
    thread::scope(|s| {
        for _ in 0..concurrency {
            s.spawn(|| {
                while Instant::now() < deadline {
                    let n = next.fetch_add(1, Ordering::Relaxed);
                    if n >= target {
                        break;
                    }
                    // Fixed width: runsc resolves ids by prefix.
                    let r = sample(setup, &SandboxId::generate());
                    let mut guard = results
                        .lock()
                        .expect("no worker panics while holding the lock");
                    match r {
                        Ok(d) => guard.0.push(d),
                        Err(e) => guard.1.push(e.to_string()),
                    }
                }
            });
        }
    });
    let timed_out = watchdog.disarm();
    let (samples, failures) = results.into_inner().expect("workers have exited");
    Outcome {
        target,
        samples,
        failures,
        wall: started.elapsed(),
        timed_out,
    }
}

fn sample(setup: Setup<'_>, id: &SandboxId) -> Result<Sample, RunscError> {
    let bundle = Bundle::write(
        setup.scratch.join(id.as_str()),
        &Spec {
            rootfs: setup.rootfs,
            args: &["/bin/sleep", "3600"],
            env: &[],
            network: &Network::None,
            binds: &[],
            resources: None,
        },
    )?;
    let runsc = setup.runsc;
    let t0 = Instant::now();
    let steps = (|| {
        runsc.create(id, &bundle, &Network::None)?;
        let created = Instant::now();
        runsc.start(id)?;
        let started = Instant::now();
        let first_byte = runsc.exec_first_byte(id, &["/bin/echo", "ok"])?;
        Ok::<_, RunscError>((created, started, first_byte))
    })();
    let teardown = Instant::now();
    let deleted = runsc.delete(id);
    let delete = teardown.elapsed();
    let (created, started, first_byte) = steps?;
    deleted?;
    Ok(Sample {
        total: first_byte - t0,
        create: created - t0,
        start: started - created,
        exec: first_byte - started,
        delete,
    })
}

/// Kills every runsc process if not disarmed in time, so a wedged sandbox (for
/// example under memory pressure) fails its sample instead of hanging the harness.
struct Watchdog {
    cancel: mpsc::Sender<()>,
    thread: thread::JoinHandle<bool>,
}

impl Watchdog {
    fn arm(after: Duration) -> Self {
        let (cancel, rx) = mpsc::channel::<()>();
        let thread = thread::spawn(move || match rx.recv_timeout(after) {
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Match on the full command line: runsc re-execs itself as /proc/self/exe.
                let _ = Command::new("pkill")
                    .args(["-KILL", "-f", "runsc"])
                    .status();
                true
            }
            _ => false,
        });
        Self { cancel, thread }
    }

    /// Returns true if the watchdog fired.
    fn disarm(self) -> bool {
        let _ = self.cancel.send(());
        self.thread.join().unwrap_or(true)
    }
}
