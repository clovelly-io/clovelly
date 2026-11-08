//! The cell's reports to the control plane (SPEC.md "Telemetry"): exactly the fixed set,
//! every 10 seconds and at once when the drain state changes, over TLS to the control
//! plane's internal address, verified against the control-plane CA baked into the
//! image. Nothing else leaves the cell this way.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use common::proto::control::cell_channel_client::CellChannelClient;
use common::proto::control::{CellReport, DrainState};
use common::sandbox::CpuShare;
use serde_json::json;
use tokio::sync::watch;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};

use crate::agent::status;
use crate::boot::{self, BootConfig};
use crate::cgroup;
use crate::lease::SharedTerms;
use crate::sandbox::Sandboxes;

/// How often the cell reports.
pub const INTERVAL: Duration = Duration::from_secs(10);
/// The name the control plane's cell-channel certificate carries.
pub const CONTROL_PLANE_NAME: &str = "control.clovelly.internal";

/// What the reports read.
pub struct Reported {
    pub sandboxes: Arc<Sandboxes>,
    pub terms: Arc<SharedTerms>,
    pub drain: watch::Receiver<DrainState>,
    /// Serving and reachable: the forwarding rule's address is routed to the cell.
    pub ready: Arc<AtomicBool>,
    /// The cell's sharing factor, fixed at the unlock; the unreserved CPU already counts it.
    pub cpu_share: CpuShare,
}

#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("control plane URL: {0}")]
    Uri(#[from] tonic::codegen::http::uri::InvalidUri),
    #[error(transparent)]
    Transport(#[from] tonic::transport::Error),
}

/// A lazily connected client for the control plane at `url`, trusting only `ca_pem`.
pub fn client(url: &str, ca_pem: &[u8]) -> Result<CellChannelClient<Channel>, ReportError> {
    let channel = Channel::from_shared(url.to_owned())?
        .tls_config(
            ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(ca_pem))
                .domain_name(CONTROL_PLANE_NAME),
        )?
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(5))
        .connect_lazy();
    Ok(CellChannelClient::new(channel))
}

/// The aggregate CPU of all sandboxes since the previous call, in thousandths of a
/// vCPU.
struct CpuMeter {
    last: Option<(tokio::time::Instant, u64)>,
}

impl CpuMeter {
    fn sample(&mut self, usec: u64) -> u32 {
        let now = tokio::time::Instant::now();
        let millis = self.last.map_or(0, |(at, prev)| {
            let wall = now.duration_since(at).as_micros().max(1);
            u32::try_from(u128::from(usec.saturating_sub(prev)) * 1000 / wall).unwrap_or(u32::MAX)
        });
        self.last = Some((now, usec));
        millis
    }
}

fn report(cfg: &BootConfig, r: &Reported, cpu: &mut CpuMeter) -> CellReport {
    let snap = r.sandboxes.snapshot();
    let (usec, memory) = cgroup::usage().unwrap_or((0, 0));
    CellReport {
        instance_id: cfg.instance_id,
        zone: cfg.zone.to_string(),
        ready: r.ready.load(Ordering::Relaxed),
        unreserved_cpu_halves: snap.unreserved.cpu.0,
        unreserved_memory_gib: snap.unreserved.memory.0,
        sandbox_count: snap.count,
        cpu_in_use_millis: cpu.sample(usec),
        memory_in_use_bytes: memory,
        lease_expiry_unix: boot::unix(r.terms.expires()),
        proxy_connections: r.sandboxes.proxy_connections(),
        drain_state: (*r.drain.borrow()).into(),
        release_id: cfg.release.to_string(),
        egress_bytes: r.sandboxes.egress_bytes(),
        cpu_share: r.cpu_share.get(),
    }
}

/// Reports every [`INTERVAL`] and whenever the drain state changes, until the drain
/// state is `Recycle` and that report has been delivered (or tried for a minute).
pub async fn run(cfg: BootConfig, mut client: CellChannelClient<Channel>, mut r: Reported) {
    let mut cpu = CpuMeter { last: None };
    let mut tick = tokio::time::interval(INTERVAL);
    let mut recycle_tries = 0;
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            changed = r.drain.changed() => if changed.is_err() { return },
        }
        let rep = report(&cfg, &r, &mut cpu);
        let recycle = rep.drain_state == i32::from(DrainState::Recycle);
        match client.report(rep).await {
            Ok(_) if recycle => return,
            Ok(_) => {}
            Err(e) => status("report-failed", json!({ "error": e.message() })),
        }
        if recycle {
            recycle_tries += 1;
            if recycle_tries >= 6 {
                return;
            }
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_meter_reports_thousandths_of_a_vcpu() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        rt.block_on(async {
            let mut m = CpuMeter { last: None };
            assert_eq!(m.sample(1_000_000), 0);
            tokio::time::advance(Duration::from_secs(10)).await;
            // 15 CPU-seconds in 10 s: 1.5 vCPU.
            assert_eq!(m.sample(16_000_000), 1500);
        });
    }
}
