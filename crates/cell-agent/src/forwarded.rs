//! Accepting traffic for the cell's forwarding rule (SPEC.md "Reaching a cell").
//!
//! A forwarding rule to a target instance delivers packets still addressed to the rule's
//! IP. Google's guest agent normally routes such addresses to the host; the image has no
//! guest agent, so the cell agent does this one thing itself: every 10 seconds it reads
//! the instance's forwarded IPs from metadata and adds a local route for each new one
//! (`ip route replace local IP dev eth0 table local`).
//!
//! Metadata is untrusted: a wrong address only makes the cell accept packets for an
//! address it does not own, and every connection still has to complete TLS with the
//! cell's key.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::json;

use crate::agent::status;
use crate::metadata;

const PATH: &str = "instance/network-interfaces/0/forwarded-ips/?recursive=true&alt=json";

/// The forwarded IPv4 addresses in a metadata answer (a JSON array of strings).
fn parse(body: &str) -> Vec<Ipv4Addr> {
    serde_json::from_str::<Vec<String>>(body)
        .unwrap_or_default()
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect()
}

/// Keeps routing the instance's forwarded IPs to this host, forever. `routed_any` is set
/// once one is: until then nobody can reach the cell, so it does not report ready. Each
/// is also one of the cell's own addresses, which the egress proxy never connects to:
/// each new one goes to `own`, for the proxy's supervisor.
pub async fn keep_routes(routed_any: Arc<AtomicBool>, own: Option<tokio::sync::mpsc::UnboundedSender<Ipv4Addr>>) {
    let mut routed = BTreeSet::new();
    loop {
        let body = tokio::task::spawn_blocking(|| metadata::get(PATH)).await;
        if let Ok(Ok(Some(body))) = body {
            for ip in parse(&body) {
                if routed.contains(&ip) {
                    continue;
                }
                let out = tokio::process::Command::new("ip")
                    .args(["route", "replace", "local"])
                    .arg(ip.to_string())
                    .args(["dev", "eth0", "table", "local"])
                    .output()
                    .await;
                match out {
                    Ok(o) if o.status.success() => {
                        routed.insert(ip);
                        if let Some(own) = &own {
                            let _ = own.send(ip);
                        }
                        routed_any.store(true, Ordering::Relaxed);
                        status("forwarded-ip", json!({ "ip": ip.to_string() }));
                    }
                    Ok(o) => status(
                        "forwarded-ip-failed",
                        json!({ "ip": ip.to_string(), "error": String::from_utf8_lossy(&o.stderr).trim() }),
                    ),
                    Err(e) => status("forwarded-ip-failed", json!({ "ip": ip.to_string(), "error": e.to_string() })),
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_forwarded_ips() {
        assert_eq!(super::parse(r#"["136.65.196.105","10.0.0.1"]"#).len(), 2);
        assert!(super::parse("[]").is_empty());
        assert!(super::parse("not json").is_empty());
        assert!(super::parse(r#"["::1","x"]"#).is_empty());
    }
}
