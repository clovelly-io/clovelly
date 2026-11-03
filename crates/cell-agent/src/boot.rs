//! The cell's boot sequence, steps 1 to 6 of SPEC.md "Boot sequence (cell-agent)":
//!
//! 1. [`integrity`]: the CCEL replays to the TD's RTMRs, Secure Boot was on, the
//!    kernel command line is the one systemd-stub measured, and its `clovelly.roothash=`
//!    is the root hash dm-verity mounted. Otherwise the cell refuses to start.
//! 2. [`CellKey::generate`]: a P-256 key in memory, the cell's TLS and receipt key.
//! 3. to 5. [`unlock`]: a nonce from the verifier, a quote over
//!    `SHA-512("clovelly-v1" || env || SHA-256(SPKI) || nonce)`, and the evidence sent to
//!    `Unlock`. A refusal ends the attempt; an unreachable verifier is retried until
//!    the deadline.
//! 6. The DEK is unwrapped with the cell key ([`Unlocked`]); the agent serves the
//!    cell API with the issued certificate.
//!
//! Step 8, the lease renewal, repeats steps 3 to 6 with the same key ([`crate::lease`]).

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::agreement::{self, PrivateKey};
use aws_lc_rs::encoding::{AsBigEndian, AsDer, EcPrivateKeyBin, EcPrivateKeyRfc5915Der};
use common::ccel::{self, EventLog};
use common::dek::{self, Dek};
use common::evidence::{self, Evidence, Nonce, Spki};
use common::ids::{EnvId, ReleaseId, SubenvId, Zone};
use common::sandbox::MAX_CELL_CAP;
use common::tdx::{Measurement, Quote, ReportData};

use crate::{metadata, tsm};

/// Where the image says which release it is.
pub const RELEASE_PATH: &str = "/clovelly/release";
/// How long a cell tries to unlock before giving up to be recycled.
pub const UNLOCK_DEADLINE: Duration = Duration::from_secs(300);

/// Why the cell refuses to start (step 1).
#[derive(Debug, thiserror::Error)]
pub enum Refusal {
    #[error("reading {what}: {source}")]
    Read {
        what: &'static str,
        source: std::io::Error,
    },
    #[error("quote for the RTMRs: {0}")]
    Quote(String),
    #[error("CCEL does not replay to the TD's RTMRs: {0}")]
    Replay(#[from] ccel::CcelError),
    #[error("Secure Boot is reported off")]
    SecureBootOff,
    #[error("no measured .cmdline section in the CCEL")]
    NoMeasuredCmdline,
    #[error("the running command line (SHA-384 {running}) is not the measured one ({measured})")]
    CmdlineNotMeasured {
        running: Measurement,
        measured: Measurement,
    },
    #[error("no clovelly.roothash= on the command line")]
    NoRootHash,
    #[error("veritysetup status root: {0}")]
    Verity(String),
    #[error("the command line's clovelly.roothash={cmdline} is not the mounted root's {mounted}")]
    RootHashMismatch { cmdline: String, mounted: String },
}

/// What step 1 established.
#[derive(Debug, Clone)]
pub struct Integrity {
    pub rtmrs: [Measurement; 4],
    pub events: usize,
    pub root_hash: String,
    /// The DER certificates that authorised boot images under Secure Boot.
    pub boot_authorities: Vec<Vec<u8>>,
}

/// The kernel command line's `clovelly.roothash=`.
pub fn cmdline_root_hash(cmdline: &str) -> Option<&str> {
    cmdline
        .split_whitespace()
        .find_map(|a| a.strip_prefix("clovelly.roothash="))
}

/// The root hash of the active dm-verity device `root`, from `veritysetup status`.
fn mounted_root_hash() -> Result<String, Refusal> {
    let out = std::process::Command::new("veritysetup")
        .args(["status", "root"])
        .output()
        .map_err(|e| Refusal::Verity(e.to_string()))?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.trim().strip_prefix("root hash:").map(|h| h.trim().to_owned()))
        .ok_or_else(|| Refusal::Verity(String::from_utf8_lossy(&out.stderr).trim().to_owned()))
}

/// Step 1, on this TD's own files. `cmdline` is `/proc/cmdline`.
pub fn integrity() -> Result<Integrity, Refusal> {
    let read = |what, path| std::fs::read(path).map_err(|source| Refusal::Read { what, source });
    let table = read("CCEL table", ccel::TABLE_PATH)?;
    let log = read("CCEL log", ccel::LOG_PATH)?;
    let cmdline = String::from_utf8_lossy(&read("command line", "/proc/cmdline")?).into_owned();
    let report = tsm::quote(&ReportData([0; 64])).map_err(|e| Refusal::Quote(e.to_string()))?;
    let quote = Quote::parse(&report.quote).map_err(|e| Refusal::Quote(e.to_string()))?;
    check_integrity(&table, &log, &quote.rtmrs, &cmdline, mounted_root_hash)
}

/// Step 1's logic, with the inputs given: the CCEL, the RTMRs from a quote, the
/// running command line and how to read the mounted root's hash.
pub fn check_integrity(
    table: &[u8],
    log: &[u8],
    rtmrs: &[Measurement; 4],
    cmdline: &str,
    mounted_root_hash: impl FnOnce() -> Result<String, Refusal>,
) -> Result<Integrity, Refusal> {
    let replayed = ccel::replay_against(table, log, rtmrs)?;
    let area = usize::try_from(replayed.table.log_area_len).unwrap_or(usize::MAX);
    let events = EventLog::parse(&log[..log.len().min(area)])?;
    if events.secure_boot() != Some(true) {
        return Err(Refusal::SecureBootOff);
    }
    // The UKI's .cmdline section holds the command line without a trailing newline;
    // /proc/cmdline ends with one.
    let running = Measurement::sha384(cmdline.trim_end_matches('\n').as_bytes());
    let measured = events.uki_section(".cmdline").ok_or(Refusal::NoMeasuredCmdline)?;
    if running != measured {
        return Err(Refusal::CmdlineNotMeasured { running, measured });
    }
    let named = cmdline_root_hash(cmdline).ok_or(Refusal::NoRootHash)?;
    let mounted = mounted_root_hash()?;
    if named != mounted {
        return Err(Refusal::RootHashMismatch {
            cmdline: named.to_owned(),
            mounted,
        });
    }
    Ok(Integrity {
        rtmrs: replayed.rtmrs,
        events: replayed.events,
        root_hash: mounted,
        boot_authorities: events.boot_authorities().into_iter().map(<[u8]>::to_vec).collect(),
    })
}

/// The cell's P-256 key: its TLS key, receipt key and HPKE recipient key. It lives in
/// aws-lc's memory, which aws-lc wipes on free; our own copies are wiped by
/// [`dek::unwrap`] and [`CellKey::private_pem`]'s caller.
pub struct CellKey {
    key: PrivateKey,
    spki: Spki,
}

impl CellKey {
    pub fn generate() -> Self {
        let key = PrivateKey::generate(&agreement::ECDH_P256).expect("P-256 key generation does not fail");
        let public = key.compute_public_key().expect("a P-256 key has a public key");
        let spki = Spki::from_der(public.as_der().expect("P-256 public keys encode").as_ref())
            .expect("aws-lc encodes a P-256 SPKI");
        Self { key, spki }
    }

    pub fn spki(&self) -> &Spki {
        &self.spki
    }

    /// The private scalar, for the guard-allocator tests to watch.
    #[cfg(test)]
    pub(crate) fn private_scalar_for_tests(&self) -> [u8; 32] {
        let bin: EcPrivateKeyBin<'static> = self.key.as_be_bytes().expect("a P-256 private key has a scalar");
        bin.as_ref().try_into().expect("a P-256 scalar is 32 bytes")
    }

    /// Opens a wrapped DEK with this key.
    pub fn unwrap_dek(&self, wrapped: &[u8], env: &EnvId, subenv: &SubenvId) -> Result<Dek, dek::DekError> {
        let scalar: EcPrivateKeyBin<'static> = self
            .key
            .as_be_bytes()
            .expect("a P-256 private key has a scalar");
        dek::unwrap(wrapped, scalar.as_ref(), env, subenv)
    }

    /// The private key as SEC 1 DER, for the TLS listener. The caller wipes it.
    pub fn private_sec1_der(&self) -> Vec<u8> {
        let der: EcPrivateKeyRfc5915Der<'static> = self.key.as_der().expect("P-256 keys encode");
        der.as_ref().to_vec()
    }
}

impl fmt::Debug for CellKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CellKey({:?})", self.spki)
    }
}

/// Who this cell is and where it unlocks, from instance metadata (untrusted) and the
/// image (the release).
#[derive(Debug, Clone)]
pub struct BootConfig {
    pub env: EnvId,
    pub subenv: SubenvId,
    pub verifier: String,
    pub release: ReleaseId,
    pub instance_id: u64,
    pub zone: Zone,
    /// The project's number, for receipts.
    pub project: String,
    pub deadline: Duration,
    /// The control plane's cell channel (`https://host:port`); none runs the cell on
    /// its own.
    pub control_plane: Option<String>,
    /// How long after its unlock the cell ends: the pool's cap, at most 48 hours.
    pub cap: Duration,
    /// When the policy's templates are fetched.
    pub prepull: Prepull,
}

/// When a cell fetches the templates its policy bundle lists (boot step 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prepull {
    /// Before the cell reports ready (metadata `clovelly-prepull=boot`).
    AtBoot,
    /// On first use by a sandbox: the default since phase 4 criterion 2 found that
    /// pre-pulling a 2 GB template at boot added 10.4 s to boot-to-ready, over its 10 s
    /// bound (run 20261028-023456).
    OnFirstUse,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error(transparent)]
    Metadata(#[from] metadata::MetadataError),
    #[error("metadata {0} is missing")]
    Missing(&'static str),
    #[error("metadata {0} is malformed: {1}")]
    Malformed(&'static str, String),
    #[error("reading {RELEASE_PATH}: {0}")]
    Release(std::io::Error),
}

impl BootConfig {
    /// Reads `clovelly-env`, `clovelly-subenv`, `clovelly-verifier` and the optional
    /// `clovelly-unlock-timeout` (seconds), `clovelly-control-plane`, `clovelly-cell-cap` (seconds)
    /// and `clovelly-prepull` (`boot` or `first-use`) attributes, and the instance's id, zone and project.
    pub fn from_metadata() -> Result<Self, ConfigError> {
        let need = |name: &'static str| -> Result<String, ConfigError> {
            Ok(metadata::attribute(name)?.ok_or(ConfigError::Missing(name))?.trim().to_owned())
        };
        let parse = |name: &'static str, v: &str| ConfigError::Malformed(name, v.to_owned());
        let env = need("clovelly-env")?;
        let subenv = need("clovelly-subenv")?;
        let id = metadata::get("instance/id")?.ok_or(ConfigError::Missing("instance/id"))?;
        let zone = metadata::get("instance/zone")?.ok_or(ConfigError::Missing("instance/zone"))?;
        let zone = zone.rsplit('/').next().unwrap_or_default().to_owned();
        let release = std::fs::read_to_string(RELEASE_PATH).map_err(ConfigError::Release)?;
        let deadline = match metadata::attribute("clovelly-unlock-timeout")? {
            Some(s) => Duration::from_secs(s.trim().parse().map_err(|_| parse("clovelly-unlock-timeout", &s))?),
            None => UNLOCK_DEADLINE,
        };
        // Untrusted, like all metadata: a wrong cap only recycles the cell early or at
        // 48 hours, and the lease bounds key exposure whatever the cap.
        let cap = match metadata::attribute("clovelly-cell-cap")? {
            Some(s) => Duration::from_secs(s.trim().parse().map_err(|_| parse("clovelly-cell-cap", &s))?),
            None => MAX_CELL_CAP,
        }
        .min(MAX_CELL_CAP);
        let project = metadata::get("project/numeric-project-id")?.unwrap_or_default();
        // Untrusted: either value only moves when a template's fetch is paid for.
        let prepull = match metadata::attribute("clovelly-prepull")?.as_deref().map(str::trim) {
            Some("boot") => Prepull::AtBoot,
            None | Some("first-use") => Prepull::OnFirstUse,
            Some(other) => return Err(parse("clovelly-prepull", other)),
        };
        Ok(Self {
            env: env.parse().map_err(|_| parse("clovelly-env", &env))?,
            subenv: subenv.parse().map_err(|_| parse("clovelly-subenv", &subenv))?,
            verifier: need("clovelly-verifier")?,
            release: release.trim().parse().map_err(|_| parse("release", &release))?,
            instance_id: id.trim().parse().map_err(|_| parse("instance/id", &id))?,
            zone: zone.parse().map_err(|_| parse("instance/zone", &zone))?,
            project: project.trim().to_owned(),
            deadline,
            control_plane: metadata::attribute("clovelly-control-plane")?.map(|s| s.trim().to_owned()),
            cap,
            prepull,
        })
    }
}

/// How an unlock attempt failed at the verifier.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ApiError {
    /// The verifier refused the evidence with this check number. Final.
    #[error("verifier refused: check {0}")]
    Refused(u8),
    /// The verifier could not be reached or could not decide. Retried.
    #[error("verifier unavailable: {0}")]
    Unavailable(String),
}

/// What the verifier returned for an accepted unlock.
#[derive(Debug, Clone)]
pub struct Granted {
    pub cell_cert: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub policy_bundle: Vec<u8>,
    pub policy_sig: String,
    /// The release's valid_until, Unix seconds.
    pub release_valid_until: u64,
    /// The customer's policy public key (PEM).
    pub policy_key: String,
}

/// The verifier's API as the cell uses it. [`crate::grpc::GrpcVerifier`] in
/// production; fakes in tests.
pub trait VerifierApi {
    fn nonce(&mut self, env: &EnvId) -> impl Future<Output = Result<Nonce, ApiError>> + Send;
    fn unlock(&mut self, evidence: &Evidence) -> impl Future<Output = Result<Granted, ApiError>> + Send;
}

/// Asks the TD for a quote over `report_data` (blocking configfs I/O).
pub trait Quoter {
    fn quote(&self, report_data: &ReportData) -> Result<Vec<u8>, String>;
}

/// The TD's own quote provider.
pub struct TsmQuoter;

impl Quoter for TsmQuoter {
    fn quote(&self, report_data: &ReportData) -> Result<Vec<u8>, String> {
        tsm::quote(report_data).map(|r| r.quote).map_err(|e| e.to_string())
    }
}

/// One lease: an unlocked cell's certificate and secrets. The DEK is wiped when this is
/// dropped, at renewal (replaced by the next lease's), revocation or cell end.
#[derive(Debug)]
pub struct Unlocked {
    pub cell_cert: Vec<u8>,
    /// Shared with the credential release while the lease holds; wiped when the last
    /// holder drops it (the lease ends and the agent's terms let go).
    pub dek: Arc<Dek>,
    pub policy_bundle: Vec<u8>,
    pub policy_sig: String,
    /// The customer's policy public key (PEM) the verifier sent.
    pub policy_key: String,
    pub evidence: Evidence,
    /// When the unlock succeeded.
    pub at: SystemTime,
    /// The certificate's notAfter: the lease ends here.
    pub expires: SystemTime,
    /// The release's valid_until.
    pub valid_until: SystemTime,
}

/// Why the cell did not unlock.
#[derive(Debug, thiserror::Error)]
pub enum UnlockFailure {
    #[error("verifier refused: check {0}")]
    Refused(u8, Box<Evidence>),
    #[error("no unlock within {0:?}; last error: {1}")]
    Deadline(Duration, String),
    #[error("quote: {0}")]
    Quote(String),
    #[error("the verifier's DEK does not open with this cell's key: {0}")]
    Dek(#[from] dek::DekError),
    #[error("the cell certificate does not parse: {0}")]
    Cert(String),
}

/// Steps 3 to 6: nonce, quote, `Unlock`, DEK unwrap. Retries an unavailable verifier
/// with backoff for up to `deadline`; a refusal or a bad wrap ends it.
pub async fn unlock(
    cfg: &BootConfig,
    key: &CellKey,
    api: &mut impl VerifierApi,
    quoter: &impl Quoter,
    ccel: (&[u8], &[u8]),
    deadline: Duration,
) -> Result<Unlocked, UnlockFailure> {
    let started = tokio::time::Instant::now();
    let mut backoff = Duration::from_millis(500);
    loop {
        let err = match attempt(cfg, key, api, quoter, ccel).await {
            Ok(u) => return Ok(u),
            Err(Attempt::Final(f)) => return Err(f),
            Err(Attempt::Retry(e)) => e,
        };
        if started.elapsed() + backoff > deadline {
            return Err(UnlockFailure::Deadline(deadline, err));
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(10));
    }
}

enum Attempt {
    Final(UnlockFailure),
    Retry(String),
}

async fn attempt(
    cfg: &BootConfig,
    key: &CellKey,
    api: &mut impl VerifierApi,
    quoter: &impl Quoter,
    (table, log): (&[u8], &[u8]),
) -> Result<Unlocked, Attempt> {
    let retry = |e: ApiError| match e {
        ApiError::Unavailable(m) => Attempt::Retry(m),
        ApiError::Refused(n) => Attempt::Retry(format!("unexpected refusal {n} for a nonce")),
    };
    let nonce = api.nonce(&cfg.env).await.map_err(retry)?;
    let rd = evidence::report_data(&cfg.env, key.spki(), &nonce);
    let quote = quoter
        .quote(&rd)
        .map_err(|e| Attempt::Final(UnlockFailure::Quote(e)))?;
    let ev = Evidence {
        quote,
        ccel_table: table.to_vec(),
        ccel_log: log.to_vec(),
        env: cfg.env.clone(),
        subenv: cfg.subenv.clone(),
        release: cfg.release.clone(),
        spki: key.spki().clone(),
        nonce,
        instance_id: cfg.instance_id,
        zone: cfg.zone.clone(),
    };
    let granted = match api.unlock(&ev).await {
        Ok(g) => g,
        Err(ApiError::Refused(n)) => {
            return Err(Attempt::Final(UnlockFailure::Refused(n, Box::new(ev))));
        }
        Err(ApiError::Unavailable(m)) => return Err(Attempt::Retry(m)),
    };
    let expires = not_after(&granted.cell_cert).map_err(|e| Attempt::Final(UnlockFailure::Cert(e)))?;
    let dek = key
        .unwrap_dek(&granted.wrapped_dek, &cfg.env, &cfg.subenv)
        .map_err(|e| Attempt::Final(e.into()))?;
    Ok(Unlocked {
        cell_cert: granted.cell_cert,
        dek: Arc::new(dek),
        policy_bundle: granted.policy_bundle,
        policy_sig: granted.policy_sig,
        policy_key: granted.policy_key,
        evidence: ev,
        at: SystemTime::now(),
        expires,
        valid_until: UNIX_EPOCH + Duration::from_secs(granted.release_valid_until),
    })
}

/// A DER certificate's notAfter.
pub fn not_after(cert: &[u8]) -> Result<SystemTime, String> {
    use der::Decode;
    let cert = x509_cert::Certificate::from_der(cert).map_err(|e| e.to_string())?;
    Ok(cert.tbs_certificate().validity().not_after.to_system_time())
}

/// Seconds since the epoch.
pub fn unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A CCEL with Secure Boot on and the given `.cmdline` contents, and its table.
    pub(crate) fn ccel(secure_boot: u8, cmdline: &[u8]) -> (Vec<u8>, Vec<u8>, [Measurement; 4]) {
        fn event(mr: u32, ty: u32, digest: &Measurement, data: &[u8]) -> Vec<u8> {
            let mut e = Vec::new();
            e.extend_from_slice(&mr.to_le_bytes());
            e.extend_from_slice(&ty.to_le_bytes());
            e.extend_from_slice(&1u32.to_le_bytes());
            e.extend_from_slice(&0x000cu16.to_le_bytes());
            e.extend_from_slice(&digest.0);
            e.extend_from_slice(&(data.len() as u32).to_le_bytes());
            e.extend_from_slice(data);
            e
        }
        let mut spec = b"Spec ID Event03\0".to_vec();
        spec.extend_from_slice(&[0, 0, 0, 0, 0, 2, 0, 2]);
        spec.extend_from_slice(&1u32.to_le_bytes());
        spec.extend_from_slice(&0x000cu16.to_le_bytes());
        spec.extend_from_slice(&48u16.to_le_bytes());
        spec.push(0);
        let mut log = Vec::new();
        log.extend_from_slice(&1u32.to_le_bytes());
        log.extend_from_slice(&3u32.to_le_bytes());
        log.extend_from_slice(&[0; 20]);
        log.extend_from_slice(&(spec.len() as u32).to_le_bytes());
        log.extend_from_slice(&spec);

        // SecureBoot variable: EFI global GUID, name length 10, data length 1.
        let mut var = vec![
            0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c,
        ];
        var.extend_from_slice(&10u64.to_le_bytes());
        var.extend_from_slice(&1u64.to_le_bytes());
        for u in "SecureBoot".encode_utf16() {
            var.extend_from_slice(&u.to_le_bytes());
        }
        var.push(secure_boot);
        let sb = Measurement::sha384(&var);
        // As systemd-stub logs it: the name, UTF-16LE with its NUL, as event data.
        let tag: Vec<u8> = ".cmdline\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let (name, contents) = (Measurement::sha384(b".cmdline\0"), Measurement::sha384(cmdline));
        log.extend(event(1, 0x8000_0001, &sb, &var));
        log.extend(event(3, 0xd, &name, &tag));
        log.extend(event(3, 0xd, &contents, &tag));
        let rtmrs = [
            Measurement::ZERO.extend(&sb),
            Measurement::ZERO,
            Measurement::ZERO.extend(&name).extend(&contents),
            Measurement::ZERO,
        ];
        let mut t = vec![0u8; 56];
        t[0..4].copy_from_slice(b"CCEL");
        t[4..8].copy_from_slice(&56u32.to_le_bytes());
        t[36] = 2;
        t[40..48].copy_from_slice(&(log.len() as u64).to_le_bytes());
        let sum = t.iter().fold(0u8, |s, b| s.wrapping_add(*b));
        t[9] = 0u8.wrapping_sub(sum);
        (t, log, rtmrs)
    }

    const HASH: &str = "135fba3bce9b5ad6c25f3290c41b9b13209301eb77cb7b3a33ac315b65da8a17";

    fn cmdline() -> String {
        format!("console=ttyS0 clovelly.roothash={HASH} panic=-1")
    }

    #[test]
    fn integrity_passes_for_a_measured_matching_boot() {
        let (t, l, r) = ccel(1, cmdline().as_bytes());
        let ok = check_integrity(&t, &l, &r, &format!("{}\n", cmdline()), || Ok(HASH.into())).unwrap();
        assert_eq!(ok.root_hash, HASH);
    }

    /// Criterion 9: the command line's root hash differs from the mounted root's.
    #[test]
    fn refuses_a_root_hash_mismatch() {
        let (t, l, r) = ccel(1, cmdline().as_bytes());
        let err = check_integrity(&t, &l, &r, &cmdline(), || Ok("00".repeat(32))).unwrap_err();
        assert!(matches!(err, Refusal::RootHashMismatch { .. }), "{err}");
    }

    /// Criterion 14: Secure Boot off, or a command line other than the measured one.
    #[test]
    fn refuses_secure_boot_off_and_unmeasured_command_lines() {
        let (t, l, r) = ccel(0, cmdline().as_bytes());
        let err = check_integrity(&t, &l, &r, &cmdline(), || Ok(HASH.into())).unwrap_err();
        assert!(matches!(err, Refusal::SecureBootOff), "{err}");

        let (t, l, r) = ccel(1, cmdline().as_bytes());
        let altered = cmdline().replace("panic=-1", "panic=0");
        let err = check_integrity(&t, &l, &r, &altered, || Ok(HASH.into())).unwrap_err();
        assert!(matches!(err, Refusal::CmdlineNotMeasured { .. }), "{err}");
    }

    #[test]
    fn refuses_a_log_that_does_not_replay() {
        let (t, l, mut r) = ccel(1, cmdline().as_bytes());
        r[2] = Measurement([1; 48]);
        let err = check_integrity(&t, &l, &r, &cmdline(), || Ok(HASH.into())).unwrap_err();
        assert!(matches!(err, Refusal::Replay(_)), "{err}");
    }

    /// Criterion 10: on every exit path of the unlock, no freed heap block still holds
    /// the DEK or the cell's private scalar.
    mod zeroised {
        use super::super::*;
        use crate::guard;
        use crate::lease::tests::{FakeQuoter, Scripted, cfg, granted, random, scalar};
        use common::dek::Dek;

        fn run(key: &CellKey, reply: Result<Granted, ApiError>, deadline: Duration) -> Result<Unlocked, UnlockFailure> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            let mut api = Scripted {
                replies: vec![reply],
                calls: Default::default(),
            };
            rt.block_on(unlock(&cfg(), key, &mut api, &FakeQuoter, (b"t", b"l"), deadline))
        }

        /// The control: the guard sees a secret freed unwiped, and not a wiped one.
        #[test]
        fn the_guard_catches_an_unwiped_free() {
            let secret = random();
            let w = guard::watch(&secret);
            drop(std::hint::black_box(secret.to_vec()));
            assert_eq!(w.leaks(), 1);
            let mut v = secret.to_vec();
            dek::wipe(&mut v);
            drop(v);
            assert_eq!(w.leaks(), 1);
        }

        #[test]
        fn unlocked_then_cell_end() {
            let key = CellKey::generate();
            let (dek_bytes, k) = (random(), scalar(&key));
            let (wd, wk) = (guard::watch(&dek_bytes), guard::watch(&k));
            let unlocked = run(&key, granted(&key, dek_bytes), Duration::from_secs(5)).unwrap();
            assert_eq!(unlocked.dek.as_bytes(), &dek_bytes);
            let mut der = key.private_sec1_der(); // as the listener does
            dek::wipe(&mut der);
            drop(unlocked);
            drop(key);
            assert_eq!((wd.leaks(), wk.leaks()), (0, 0));
        }

        #[test]
        fn refused_by_the_verifier() {
            let key = CellKey::generate();
            let wk = guard::watch(&scalar(&key));
            let err = run(&key, Err(ApiError::Refused(6)), Duration::from_secs(5)).unwrap_err();
            assert!(matches!(err, UnlockFailure::Refused(6, _)));
            drop(key);
            assert_eq!(wk.leaks(), 0);
        }

        #[test]
        fn verifier_unreachable_until_the_deadline() {
            let key = CellKey::generate();
            let wk = guard::watch(&scalar(&key));
            let err = run(&key, Err(ApiError::Unavailable("down".into())), Duration::from_secs(1)).unwrap_err();
            assert!(matches!(err, UnlockFailure::Deadline(..)));
            drop(key);
            assert_eq!(wk.leaks(), 0);
        }

        #[test]
        fn a_wrap_for_another_key_or_subenv_does_not_open() {
            let key = CellKey::generate();
            let other = CellKey::generate();
            let dek_bytes = random();
            let (wd, wk) = (guard::watch(&dek_bytes), guard::watch(&scalar(&key)));
            let c = cfg();
            for (to, subenv) in [(other.spki(), c.subenv.clone()), (key.spki(), "bank-b".parse().unwrap())] {
                let mut g = granted(&key, [0; 32]).unwrap();
                g.wrapped_dek = dek::wrap(&Dek::from_bytes(dek_bytes), to, &c.env, &subenv).unwrap();
                let err = run(&key, Ok(g), Duration::from_secs(5)).unwrap_err();
                assert!(matches!(err, UnlockFailure::Dek(_)), "{err}");
            }
            drop(key);
            assert_eq!((wd.leaks(), wk.leaks()), (0, 0));
        }
    }
}
