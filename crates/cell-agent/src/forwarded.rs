//! Accepting traffic for a test VM's forwarding rule: the test destination and the
//! impostor (phases 3 and 4) are reached through one. Cells have none since phase 12:
//! clients reach them through their region's relay at their internal address.
//!
//! A forwarding rule to a target instance delivers packets still addressed to the rule's
//! IP. Google's guest agent normally routes such addresses to the host; the image has no
//! guest agent, so the agent does this one thing itself: every 10 seconds it reads the
//! instance's forwarded IPs from metadata and adds a local route for each new one
//! (`ip route replace local IP dev eth0 table local`).
//!
//! Metadata is untrusted: a wrong address only makes the VM accept packets for an
//! address it does not own.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
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

/// Keeps routing the instance's forwarded IPs to this host, forever.
pub async fn keep_routes() {
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
