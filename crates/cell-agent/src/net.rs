//! Sandbox networking (SPEC.md decision 6): each sandbox runs under `runsc
//! --network=sandbox` in its own network namespace, whose only interface is one end of a
//! veth pair and whose default route is the other end, the sandbox's gateway, in the
//! agent's namespace. nftables there redirects the sandbox's TCP 443 and 80 and its DNS
//! to the egress proxy and drops or resets everything else, so the proxy is the only
//! way out.
//!
//! ```text
//! sandbox netns cs<n>                     cell (agent's namespace)
//!   eth0 172.31.a.b+2/30 ── veth ──  cv<n> 172.31.a.b+1/30 (gateway)
//!   default via the gateway                tcp 443 → :15443, tcp 80 → :15080,
//!   /etc/resolv.conf: the gateway          udp 53 to 172.31/16 → :15053,
//!                                          tcp 3128 (CONNECT) accepted, the rest
//!                                          reset (TCP) or dropped; nothing forwarded
//! ```
//!
//! Slots are /30s in 172.31.0.0/16 (16,384 of them), outside the VPC's 10.128.0.0/9.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Mutex;

use egress_proxy::Ports;

/// Sandbox subnets are carved from this /16.
pub const SUBNET: (u8, u8) = (172, 31);
/// How many /30 slots the /16 holds.
pub const SLOTS: u16 = 16_384;
/// The per-CPU input backlog (`net.core.netdev_max_backlog`; the kernel's default is
/// 1000 packets). Every sandbox's veth delivers into it, and a full cell's netstacks
/// bursting at once overflow the default (phase 3's throughput diagnosis).
pub const NETDEV_BACKLOG: u32 = 30_000;
/// The veth MTU. Matches gve's (1460) as phase 0's benchmark did; the throughput
/// diagnosis (phase 3 criterion 8) measures the alternatives.
pub const MTU: u32 = 1460;

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("no free sandbox network slot")]
    Exhausted,
    #[error("`{command}`: {detail}")]
    Command { command: String, detail: String },
}

/// One sandbox's /30: its gateway, its address and its namespace and veth names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Slot(u16);

impl Slot {
    fn base(self) -> u32 {
        (u32::from(SUBNET.0) << 24) | (u32::from(SUBNET.1) << 16) | (u32::from(self.0) * 4)
    }

    /// The host end of the veth: the sandbox's gateway, DNS server and CONNECT proxy.
    pub fn gateway(self) -> Ipv4Addr {
        Ipv4Addr::from(self.base() + 1)
    }

    /// The sandbox's own address, by which the proxy knows it.
    pub fn address(self) -> Ipv4Addr {
        Ipv4Addr::from(self.base() + 2)
    }

    pub fn netns(self) -> String {
        format!("cs{}", self.0)
    }

    pub fn veth(self) -> String {
        format!("cv{}", self.0)
    }

    /// Where `ip netns` keeps the namespace (the OCI spec's network namespace path).
    pub fn netns_path(self) -> PathBuf {
        PathBuf::from("/run/netns").join(self.netns())
    }

    /// The sandbox's `/etc/resolv.conf`.
    pub fn resolv_conf(self) -> String {
        format!("nameserver {}\noptions timeout:2 attempts:2\n", self.gateway())
    }
}

/// The free slots.
pub struct Slots(Mutex<BTreeSet<u16>>);

impl Default for Slots {
    fn default() -> Self {
        Self(Mutex::new((0..SLOTS).collect()))
    }
}

impl Slots {
    pub fn take(&self) -> Result<Slot, NetError> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).pop_first().map(Slot).ok_or(NetError::Exhausted)
    }

    pub fn give_back(&self, slot: Slot) {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).insert(slot.0);
    }
}

async fn run(args: &[String]) -> Result<(), NetError> {
    let out = tokio::process::Command::new(&args[0])
        .args(&args[1..])
        .output()
        .await
        .map_err(|e| NetError::Command {
            command: args.join(" "),
            detail: e.to_string(),
        })?;
    if out.status.success() {
        return Ok(());
    }
    Err(NetError::Command {
        command: args.join(" "),
        detail: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
    })
}

fn words(s: &str) -> Vec<String> {
    s.split_whitespace().map(str::to_owned).collect()
}

/// The commands that build `slot`'s namespace and veth pair.
pub fn create_commands(slot: Slot, mtu: u32) -> Vec<Vec<String>> {
    let (ns, veth, gw, addr) = (slot.netns(), slot.veth(), slot.gateway(), slot.address());
    [
        format!("ip netns add {ns}"),
        format!("ip link add {veth} mtu {mtu} type veth peer name eth0 mtu {mtu} netns {ns}"),
        format!("ip addr add {gw}/30 dev {veth}"),
        format!("ip link set {veth} up"),
        format!("ip -n {ns} addr add {addr}/30 dev eth0"),
        format!("ip -n {ns} link set eth0 up"),
        format!("ip -n {ns} link set lo up"),
        format!("ip -n {ns} route add default via {gw}"),
    ]
    .iter()
    .map(|c| words(c))
    .collect()
}

/// Builds `slot`'s namespace; on failure removes what was made.
pub async fn create(slot: Slot, mtu: u32) -> Result<(), NetError> {
    for c in create_commands(slot, mtu) {
        if let Err(e) = run(&c).await {
            destroy(slot).await;
            return Err(e);
        }
    }
    Ok(())
}

/// Removes `slot`'s namespace (and with it both veth ends). Best effort.
pub async fn destroy(slot: Slot) {
    let _ = run(&words(&format!("ip netns del {}", slot.netns()))).await;
    let _ = run(&words(&format!("ip link del {}", slot.veth()))).await;
}

/// The cell's nftables ruleset for `ports`.
pub fn ruleset(ports: Ports) -> String {
    let Ports { tls, http, dns, connect } = ports;
    let (a, b) = SUBNET;
    format!(
        r#"table inet clovelly_egress {{
  chain prerouting {{
    type nat hook prerouting priority dstnat; policy accept;
    iifname "cv*" tcp dport 443 redirect to :{tls}
    iifname "cv*" tcp dport 80 redirect to :{http}
    iifname "cv*" ip daddr {a}.{b}.0.0/16 udp dport 53 redirect to :{dns}
  }}
  chain input {{
    type filter hook input priority filter; policy accept;
    iifname "cv*" meta nfproto ipv6 drop
    iifname "cv*" tcp dport {{ {tls}, {http}, {connect} }} accept
    iifname "cv*" udp dport {dns} accept
    iifname "cv*" meta l4proto tcp reject with tcp reset
    iifname "cv*" drop
    tcp dport {{ {tls}, {http}, {connect} }} drop
    udp dport {dns} drop
  }}
  chain forward {{
    type filter hook forward priority filter; policy accept;
    iifname "cv*" meta l4proto tcp reject with tcp reset
    iifname "cv*" drop
    oifname "cv*" drop
  }}
}}
"#
    )
}

/// Cell-wide setup at serve time: strict reverse-path filtering (a sandbox cannot
/// send as another sandbox's address), the input backlog and the ruleset.
pub async fn setup_cell(ports: Ports) -> Result<(), NetError> {
    for key in ["all", "default"] {
        run(&words(&format!("sysctl -w net.ipv4.conf.{key}.rp_filter=1"))).await?;
    }
    run(&words(&format!("sysctl -w net.core.netdev_max_backlog={NETDEV_BACKLOG}"))).await?;
    let mut child = tokio::process::Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| NetError::Command {
            command: "nft -f -".into(),
            detail: e.to_string(),
        })?;
    {
        use tokio::io::AsyncWriteExt;
        let mut stdin = child.stdin.take().expect("stdin is piped");
        stdin.write_all(ruleset(ports).as_bytes()).await.map_err(|e| NetError::Command {
            command: "nft -f -".into(),
            detail: e.to_string(),
        })?;
    }
    let out = child.wait_with_output().await.map_err(|e| NetError::Command {
        command: "nft -f -".into(),
        detail: e.to_string(),
    })?;
    if !out.status.success() {
        return Err(NetError::Command {
            command: "nft -f -".into(),
            detail: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_disjoint_slash_30s() {
        let (s0, s1, last) = (Slot(0), Slot(1), Slot(SLOTS - 1));
        assert_eq!((s0.gateway(), s0.address()), ("172.31.0.1".parse().unwrap(), "172.31.0.2".parse().unwrap()));
        assert_eq!((s1.gateway(), s1.address()), ("172.31.0.5".parse().unwrap(), "172.31.0.6".parse().unwrap()));
        assert_eq!(last.address(), "172.31.255.254".parse::<Ipv4Addr>().unwrap());
        assert_eq!(s1.resolv_conf().lines().next(), Some("nameserver 172.31.0.5"));
        let slots = Slots::default();
        let (a, b) = (slots.take().unwrap(), slots.take().unwrap());
        assert_ne!(a, b);
        slots.give_back(a);
        assert_eq!(slots.take().unwrap(), a);
    }

    #[test]
    fn commands_and_ruleset_name_the_slot_and_ports() {
        let c = create_commands(Slot(7), 1460);
        assert_eq!(c[1].join(" "), "ip link add cv7 mtu 1460 type veth peer name eth0 mtu 1460 netns cs7");
        assert_eq!(c[7].join(" "), "ip -n cs7 route add default via 172.31.0.29");
        let r = ruleset(Ports::CELL);
        assert!(r.contains("tcp dport 443 redirect to :15443"));
        assert!(r.contains("ip daddr 172.31.0.0/16 udp dport 53 redirect to :15053"));
        assert!(r.contains("tcp dport { 15443, 15080, 3128 } accept"));
    }
}
