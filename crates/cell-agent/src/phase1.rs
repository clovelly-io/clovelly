//! Phase 1's in-guest checks, run by the test image's harness. Each records check
//! lines for the job. The agent under test runs as a child process (`cell-agent boot`)
//! so its memory can be scanned from outside it.

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use common::cellcert::{self, CellCertInfo};
use common::proto::health::HealthCheckRequest;
use common::proto::health::health_client::HealthClient;
use der::Decode;
use tonic::transport::{Certificate as TlsCa, Channel, ClientTlsConfig};
use x509_cert::Certificate;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::pkix::name::GeneralName;

use crate::boot::{self, BootConfig, CellKey, Refusal, TsmQuoter};
use crate::grpc::GrpcVerifier;
use crate::harness::{Checks, Status};
use crate::stats::{Summary, ms};
use crate::{listener, metadata, scan};

/// Our Secure Boot db certificate, baked into the image.
const DB_CERT: &str = "/clovelly/secureboot/db.der";

/// The agent under test, with its stdout as `(state, json)` events.
struct Agent {
    child: Child,
    events: mpsc::Receiver<(String, serde_json::Value)>,
}

impl Agent {
    fn spawn(args: &[&str]) -> anyhow::Result<Self> {
        let mut child = Command::new(std::env::current_exe()?)
            .arg("boot")
            .args(args)
            .stdout(Stdio::piped())
            .spawn()
            .context("spawning cell-agent boot")?;
        let stdout = child.stdout.take().context("child stdout")?;
        let (tx, events) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                println!("{line}");
                let Some(rest) = line.strip_prefix("CLOVELLY-AGENT ") else { continue };
                let (state, json) = rest.split_once(' ').unwrap_or((rest, "{}"));
                let json = serde_json::from_str(json).unwrap_or_default();
                if tx.send((state.to_owned(), json)).is_err() {
                    break;
                }
            }
        });
        Ok(Self { child, events })
    }

    /// Waits for one of `states`; fails on timeout or the agent exiting first.
    fn wait_for(&mut self, states: &[&str], timeout: Duration) -> anyhow::Result<(String, serde_json::Value)> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.events.recv_timeout(left) {
                Ok((s, j)) if states.contains(&s.as_str()) => return Ok((s, j)),
                Ok(_) => {}
                Err(mpsc::RecvTimeoutError::Timeout) => bail!("no {states:?} within {timeout:?}"),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    bail!("agent exited ({:?}) before {states:?}", self.child.wait()?)
                }
            }
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        // Recycling the cell: the agent process ends.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn dek_marker() -> anyhow::Result<Vec<u8>> {
    let hex = metadata::attribute("clovelly-dek-marker")?.context("clovelly-dek-marker is not set")?;
    common::unhex(hex.trim()).context("clovelly-dek-marker is not hex")
}

/// Criteria 13 and 14 (in-boot halves): Secure Boot on per the kernel and the
/// measured log, our db certificate authorised the UKI, and the boot integrity checks
/// of step 1 pass.
pub fn secure_boot(checks: &mut Checks) {
    let dmesg = Command::new("dmesg").output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned());
    let line = dmesg
        .as_deref()
        .unwrap_or_default()
        .lines()
        .find(|l| l.contains("Secure boot"))
        .map(|l| l.trim().to_owned());
    match line {
        Some(l) if l.contains("enabled") => checks.record("c13-kernel-secure-boot", Status::Pass, l),
        other => checks.record("c13-kernel-secure-boot", Status::Fail, format!("{other:?}")),
    }
    let outcome = (|| -> anyhow::Result<String> {
        let integrity = boot::integrity()?;
        let ours = std::fs::read(DB_CERT).context(DB_CERT)?;
        let subject = Certificate::from_der(&ours)?.tbs_certificate().subject().to_string();
        if !integrity.boot_authorities.contains(&ours) {
            bail!("our db certificate ({subject}) is not among {} RTMR0 authority events", integrity.boot_authorities.len());
        }
        Ok(format!(
            "SecureBoot=1 measured in RTMR0; EV_EFI_VARIABLE_AUTHORITY carries our db certificate {subject}; RTMR0 {}",
            integrity.rtmrs[0]
        ))
    })();
    checks.outcome("c13-rtmr0-db-certificate", outcome);
    checks.outcome(
        "c14-boot-integrity",
        boot::integrity()
            .map(|i| {
                format!(
                    "{} events replay to RTMR0..3; /proc/cmdline is the measured .cmdline; clovelly.roothash={} is the mounted dm-verity root",
                    i.events, i.root_hash
                )
            })
            .map_err(Into::into),
    );
}

/// Criterion 9 on the wrong-root-hash image: the agent refuses to start.
pub fn root_hash_refused(checks: &mut Checks) {
    let outcome = (|| -> anyhow::Result<String> {
        match boot::integrity() {
            Err(e @ Refusal::RootHashMismatch { .. }) => {
                let mut agent = Agent::spawn(&[])?;
                let (_, j) = agent.wait_for(&["refused-start", "unlocking"], Duration::from_secs(60))?;
                if let Some(reason) = j["reason"].as_str() {
                    return Ok(format!("cell-agent refused to start: {reason}"));
                }
                bail!("integrity() refused ({e}) but the agent went on to unlock")
            }
            Err(other) => bail!("boot integrity refused for another reason: {other}"),
            Ok(_) => bail!("boot integrity accepted a command line naming another root"),
        }
    })();
    checks.outcome("c9-roothash-refused", outcome);
}

/// Criteria 1 and 10 (positive control): the agent unlocks; the certificate names the
/// cell and carries the extension; the listener serves TLS with it; while unlocked
/// the agent's memory holds the DEK, so the scan can see it.
pub fn unlock(checks: &mut Checks, out: &Path) {
    let outcome = (|| -> anyhow::Result<()> {
        let marker = dek_marker()?;
        let evidence = out.join("evidence");
        let mut agent = Agent::spawn(&["--hold-on-failure", "--evidence", &evidence.to_string_lossy()])?;
        let (state, j) = agent.wait_for(&["unlocked", "refused", "gave-up", "failed", "refused-start"], Duration::from_secs(360))?;
        if state != "unlocked" {
            bail!("agent {state}: {j}");
        }
        let cert_der = common::b64::decode(j["cell_cert"].as_str().unwrap_or_default())?;
        std::fs::write(out.join("cell-cert.der"), &cert_der)?;
        let cert = Certificate::from_der(&cert_der)?;
        let tbs = cert.tbs_certificate();
        let (_, san) = tbs.get_extension::<SubjectAltName>()?.context("no SAN")?;
        let names: Vec<String> = san
            .0
            .iter()
            .map(|n| match n {
                GeneralName::DnsName(d) => d.to_string(),
                other => format!("{other:?}"),
            })
            .collect();
        let ext = tbs
            .extensions()
            .into_iter()
            .flatten()
            .find(|e| e.extn_id == cellcert::OID)
            .context("no clovelly extension")?;
        let info = CellCertInfo::from_der(ext.extn_value.as_bytes())?;
        let quote = std::fs::read(evidence.join("quote.bin"))?;
        let quote_hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &quote);
        let lifetime = tbs.validity().not_after.to_unix_duration().as_secs()
            - tbs.validity().not_before.to_unix_duration().as_secs();
        checks.record(
            "c1-unlock-certificate",
            if info.quote_sha256 == quote_hash.as_ref() { Status::Pass } else { Status::Fail },
            format!(
                "issuer {}; SAN DNS {}; extension {} = {{quote_sha256 {}, env {}, subenv {}, release {}}}; quote hash matches: {}; validity {} s (5 min skew + 60 min lifetime)",
                tbs.issuer(),
                names.join(","),
                cellcert::OID,
                common::hex(&info.quote_sha256),
                info.env,
                info.subenv,
                info.release,
                info.quote_sha256 == quote_hash.as_ref(),
                lifetime,
            ),
        );

        let cfg = BootConfig::from_metadata()?;
        let rt = tokio::runtime::Runtime::new()?;
        let tls = rt.block_on(async {
            let ca = GrpcVerifier::new(&cfg.verifier)?.ca(&cfg.env).await?;
            std::fs::write(out.join("env-ca.der"), &ca)?;
            let san = names.first().context("SAN has no name")?.clone();
            let endpoint = Channel::from_shared(format!("https://127.0.0.1:{}", listener::PORT))?
                .tls_config(
                    ClientTlsConfig::new()
                        .ca_certificate(TlsCa::from_pem(common::b64::pem("CERTIFICATE", &ca)))
                        .domain_name(san.clone()),
                )?;
            // The agent starts listening just after it reports the unlock.
            let mut tries = 0;
            let channel = loop {
                match endpoint.connect().await {
                    Ok(c) => break c,
                    Err(_) if tries < 20 => {
                        tries += 1;
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                    Err(e) => return Err(e.into()),
                }
            };
            let resp = HealthClient::new(channel)
                .check(HealthCheckRequest { service: String::new() })
                .await?
                .into_inner();
            anyhow::Ok(format!(
                "TLS to the cell API as {san}, verified against the environment CA from GetCA: health {:?}",
                resp.status()
            ))
        });
        checks.outcome("c1-cell-api-tls", tls);

        let found = scan::scan(agent.pid(), &marker)?;
        checks.record(
            "c10-scan-unlocked-control",
            if found.hits.is_empty() { Status::Fail } else { Status::Pass },
            format!(
                "positive control: unlocked agent pid {} holds the DEK marker at {} address(es) ({} regions, {} MiB scanned)",
                agent.pid(),
                found.hits.len(),
                found.regions,
                found.bytes >> 20
            ),
        );
        Ok(())
    })();
    if let Err(e) = outcome {
        checks.record("c1-unlock-certificate", Status::Fail, format!("{e:#}"));
    }
}

/// Criterion 14 (verifier half) on the altered-command-line image: the verifier
/// refuses the cell with check 6.
pub fn refused(checks: &mut Checks, out: &Path) {
    let outcome = (|| -> anyhow::Result<String> {
        let evidence = out.join("evidence");
        let mut agent = Agent::spawn(&["--evidence", &evidence.to_string_lossy()])?;
        let (state, j) = agent.wait_for(&["unlocked", "refused", "gave-up", "failed", "refused-start"], Duration::from_secs(360))?;
        match (state.as_str(), j["check"].as_u64()) {
            ("refused", Some(6)) => Ok("the verifier refused this cell: check 6".into()),
            _ => bail!("expected a check 6 refusal, got {state} {j}"),
        }
    })();
    checks.outcome("c14-altered-cmdline-refused", outcome);
}

/// Criterion 10 on a cell given a wrong verifier URL: it never unlocks, gives up at
/// its deadline, and its memory holds no DEK.
pub fn wrong_url(checks: &mut Checks) {
    let outcome = (|| -> anyhow::Result<String> {
        let marker = dek_marker()?;
        let started = Instant::now();
        let mut agent = Agent::spawn(&["--hold-on-failure"])?;
        let (state, j) = agent.wait_for(&["unlocked", "refused", "gave-up", "failed", "refused-start"], Duration::from_secs(900))?;
        if state != "gave-up" {
            bail!("expected the agent to give up, got {state} {j}");
        }
        agent.wait_for(&["holding"], Duration::from_secs(30))?;
        let found = scan::scan(agent.pid(), &marker)?;
        if !found.hits.is_empty() {
            bail!("DEK marker found at {:?}", found.hits);
        }
        Ok(format!(
            "no unlock; agent gave up after {:.0} s ({}); memory scan of pid {}: {} regions, {} MiB, no DEK marker; agent then recycled",
            started.elapsed().as_secs_f64(),
            j["last_error"].as_str().unwrap_or_default(),
            agent.pid(),
            found.regions,
            found.bytes >> 20
        ))
    })();
    checks.outcome("c10-wrong-url-no-dek", outcome);
}

/// Criterion 4: 100 unlocks warm (collateral cached) and 100 cold (a verifier with
/// caching off), each from a fresh nonce through the unwrapped DEK.
pub fn unlock_latency(checks: &mut Checks, out: &Path, samples: usize) {
    let outcome = (|| -> anyhow::Result<()> {
        let cfg = BootConfig::from_metadata()?;
        let cold_url = metadata::attribute("clovelly-verifier-cold")?.context("clovelly-verifier-cold")?;
        let table = std::fs::read(common::ccel::TABLE_PATH)?;
        let log = std::fs::read(common::ccel::LOG_PATH)?;
        let key = CellKey::generate();
        let rt = tokio::runtime::Runtime::new()?;
        // `GrpcVerifier::new` spawns the channel's worker onto the current runtime.
        let _rt = rt.enter();
        let mut tsv = String::from("kind\tsample\tms\n");
        for (kind, url) in [("warm", cfg.verifier.clone()), ("cold", cold_url.trim().to_owned())] {
            let mut api = GrpcVerifier::new(&url)?;
            let once = |api: &mut GrpcVerifier| {
                let t = Instant::now();
                rt.block_on(boot::unlock(&cfg, &key, api, &TsmQuoter, (&table, &log), cfg.deadline))
                    .map(|_| t.elapsed())
                    .map_err(anyhow::Error::from)
            };
            if kind == "warm" {
                once(&mut api).context("warm-up unlock")?;
            }
            let mut times = Vec::with_capacity(samples);
            for i in 0..samples {
                let d = once(&mut api).with_context(|| format!("{kind} unlock {i}"))?;
                tsv.push_str(&format!("{kind}\t{i}\t{}\n", ms(d)));
                times.push(d);
            }
            let s = Summary::of(&times).context("no samples")?;
            checks.record(
                &format!("c4-unlock-{kind}"),
                Status::Measured,
                format!("{} unlocks: p50 {} ms, p95 {} ms, min {} ms, max {} ms", s.n, ms(s.p50), ms(s.p95), ms(s.min), ms(s.max)),
            );
        }
        std::fs::write(out.join("unlock-latency.tsv"), tsv)?;
        Ok(())
    })();
    if let Err(e) = outcome {
        checks.record("c4-unlock-latency", Status::Fail, format!("{e:#}"));
    }
}

/// Criterion 11 (in-cell half): with no external IP, the cell reaches the verifier,
/// Intel PCS and Google's endorsement bucket. The job checks the source addresses.
pub fn egress(checks: &mut Checks) {
    let verifier = metadata::attribute("clovelly-verifier").ok().flatten().unwrap_or_default();
    let targets = [
        ("verifier", verifier.trim().to_owned()),
        ("intel-pcs", "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity".into()),
        (
            "google-endorsements",
            "https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm/tdx/c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5.binarypb".into(),
        ),
    ];
    for (name, url) in targets {
        let o = Command::new("curl")
            .args(["-sS", "-o", "/dev/null", "--max-time", "20", "-w", "%{http_code} %{remote_ip}", &url])
            .output();
        let r = match o {
            Ok(o) => {
                let text = String::from_utf8_lossy(&o.stdout).into_owned();
                // Any HTTP answer shows the path out works; gRPC services answer plain GETs with an error status.
                if text.split_whitespace().next().is_some_and(|c| c != "000") {
                    Ok(format!("{url}: HTTP {text}"))
                } else {
                    Err(anyhow::anyhow!("{url}: {text} {}", String::from_utf8_lossy(&o.stderr).trim()))
                }
            }
            Err(e) => Err(e.into()),
        };
        checks.outcome(&format!("c11-egress-{name}"), r);
    }
    let addrs = Command::new("ip")
        .args(["-4", "-o", "addr", "show", "eth0"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();
    checks.record("c11-cell-addresses", Status::Measured, addrs);
}
