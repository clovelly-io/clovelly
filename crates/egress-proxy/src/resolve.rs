//! Name resolution for the proxy and its sandbox DNS responder: DNS-over-TLS to the
//! policy's resolvers (the image's pinned set by default), with a small cache, and the
//! address guard that keeps every connection the proxy makes on the public internet.
//!
//! The guard refuses private, loopback, link-local (the metadata server), shared,
//! multicast, reserved and documentation addresses, and the cell's own forwarded
//! addresses, whatever a policy or a DNS answer says: a sandbox can reach neither the
//! cell agent, the control plane, the metadata server nor another sandbox through the
//! proxy.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use common::bundle::{HostName, Resolver};
use rustls::ClientConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::dns;
use crate::tls;

const TIMEOUT: Duration = Duration::from_secs(5);
const NEGATIVE_TTL: Duration = Duration::from_secs(30);
const MIN_TTL: u32 = 5;
const MAX_TTL: u32 = 300;

/// Which addresses the proxy may connect to.
#[derive(Debug, Default)]
pub struct Guard {
    /// Addresses allowed although not public (the throughput harness's destination VM
    /// only; production cells have none).
    exempt: Vec<Ipv4Addr>,
    /// The cell's own public addresses (its forwarding rules), never a destination.
    own: RwLock<Vec<Ipv4Addr>>,
}

/// Whether `ip` is a public unicast address.
pub fn is_public(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || o[0] == 0
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10, shared address space
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24, protocol assignments
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15, benchmarking
        || o[0] >= 240) // reserved
}

impl Guard {
    /// The production guard: public addresses only.
    pub fn public() -> Self {
        Self::default()
    }

    /// Public addresses and `exempt` (tests and the throughput harness).
    pub fn with_exempt(exempt: Vec<Ipv4Addr>) -> Self {
        Self {
            exempt,
            own: RwLock::default(),
        }
    }

    /// Adds one of the cell's own addresses.
    pub fn add_own(&self, ip: Ipv4Addr) {
        let mut own = self.own.write().unwrap_or_else(|p| p.into_inner());
        if !own.contains(&ip) {
            own.push(ip);
        }
    }

    pub fn permits(&self, ip: Ipv4Addr) -> bool {
        if self.exempt.contains(&ip) {
            return true;
        }
        is_public(ip) && !self.own.read().unwrap_or_else(|p| p.into_inner()).contains(&ip)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    #[error("no such name")]
    NoSuchName,
    #[error("resolution failed: {0}")]
    Failed(String),
}

#[derive(Clone)]
struct Entry {
    result: Result<Vec<Ipv4Addr>, ResolveError>,
    until: Instant,
}

/// The DoT client and its cache.
pub struct Dns {
    tls: Arc<ClientConfig>,
    /// Resolver addresses pass the same guard as every other connection.
    guard: Arc<Guard>,
    /// Fixed answers (tests); production cells have none.
    hosts: HashMap<HostName, Vec<Ipv4Addr>>,
    cache: Mutex<HashMap<HostName, Entry>>,
}

impl Dns {
    pub fn new(roots: Arc<rustls::RootCertStore>, guard: Arc<Guard>, hosts: HashMap<HostName, Vec<Ipv4Addr>>) -> Result<Self, tls::TlsError> {
        Ok(Self {
            tls: tls::client_config(roots, &[])?,
            guard,
            hosts,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// `name`'s IPv4 addresses, from the cache or the first resolver that answers.
    pub async fn lookup(&self, name: &HostName, resolvers: &[Resolver]) -> Result<Vec<Ipv4Addr>, ResolveError> {
        if let Some(ips) = self.hosts.get(name) {
            return Ok(ips.clone());
        }
        if let Some(e) = self.cache.lock().unwrap_or_else(|p| p.into_inner()).get(name)
            && e.until > Instant::now()
        {
            return e.result.clone();
        }
        let mut last = ResolveError::Failed("no resolvers".into());
        for r in resolvers {
            if !self.guard.permits(r.ip) {
                last = ResolveError::Failed(format!("{}: {} is not a public address", r.name, r.ip));
                continue;
            }
            match tokio::time::timeout(TIMEOUT, query(&self.tls, r, name)).await {
                Ok(Ok(answer)) => {
                    let (result, ttl) = match answer.rcode {
                        dns::NXDOMAIN => (Err(ResolveError::NoSuchName), NEGATIVE_TTL),
                        dns::NOERROR if answer.addresses.is_empty() => (Err(ResolveError::NoSuchName), NEGATIVE_TTL),
                        dns::NOERROR => {
                            let ttl = answer.addresses.iter().map(|a| a.1).min().unwrap_or(MIN_TTL).clamp(MIN_TTL, MAX_TTL);
                            let mut ips: Vec<Ipv4Addr> = answer.addresses.iter().map(|a| a.0).collect();
                            ips.dedup();
                            (Ok(ips), Duration::from_secs(u64::from(ttl)))
                        }
                        rcode => {
                            last = ResolveError::Failed(format!("{} answered rcode {rcode}", r.name));
                            continue;
                        }
                    };
                    self.cache.lock().unwrap_or_else(|p| p.into_inner()).insert(
                        name.clone(),
                        Entry {
                            result: result.clone(),
                            until: Instant::now() + ttl,
                        },
                    );
                    return result;
                }
                Ok(Err(e)) => last = ResolveError::Failed(format!("{}: {e}", r.name)),
                Err(_) => last = ResolveError::Failed(format!("{}: timed out", r.name)),
            }
        }
        Err(last)
    }
}

/// One DNS-over-TLS query (RFC 7858): a fresh connection, one length-prefixed message.
async fn query(tls: &Arc<ClientConfig>, r: &Resolver, name: &HostName) -> Result<dns::Answer, String> {
    let mut id = [0u8; 2];
    aws_lc_rs::rand::fill(&mut id).map_err(|_| "no randomness".to_owned())?;
    let id = u16::from_be_bytes(id);
    let q = dns::query(id, name.as_str()).map_err(|e| e.to_string())?;
    let tcp = TcpStream::connect(SocketAddr::from((r.ip, 853))).await.map_err(|e| e.to_string())?;
    let server = tls::server_name(&common::bundle::Host::Name(r.name.clone()));
    let mut s = TlsConnector::from(Arc::clone(tls))
        .connect(server, tcp)
        .await
        .map_err(|e| e.to_string())?;
    let mut msg = Vec::with_capacity(q.len() + 2);
    msg.extend_from_slice(&u16::try_from(q.len()).map_err(|_| "query too long")?.to_be_bytes());
    msg.extend_from_slice(&q);
    s.write_all(&msg).await.map_err(|e| e.to_string())?;
    let mut len = [0u8; 2];
    s.read_exact(&mut len).await.map_err(|e| e.to_string())?;
    let mut answer = vec![0u8; usize::from(u16::from_be_bytes(len))];
    s.read_exact(&mut answer).await.map_err(|e| e.to_string())?;
    dns::parse_answer(&answer, id, name.as_str()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_addresses_pass_the_guard() {
        let g = Guard::public();
        for blocked in [
            "169.254.169.254",
            "10.128.0.2",
            "172.31.0.2",
            "192.168.1.1",
            "127.0.0.1",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "240.0.0.1",
        ] {
            assert!(!g.permits(blocked.parse().unwrap()), "{blocked}");
        }
        for public in ["1.1.1.1", "34.120.0.1", "8.8.8.8"] {
            assert!(g.permits(public.parse().unwrap()), "{public}");
        }
        g.add_own("34.120.0.1".parse().unwrap());
        assert!(!g.permits("34.120.0.1".parse().unwrap()), "the cell's own forwarding address");
        assert!(Guard::with_exempt(vec!["10.128.0.9".parse().unwrap()]).permits("10.128.0.9".parse().unwrap()));
    }

    /// A policy's resolver passes the guard like any destination: the proxy never
    /// connects to a private one.
    #[tokio::test]
    async fn private_resolvers_are_not_queried() {
        let dns = Dns::new(Arc::new(rustls::RootCertStore::empty()), Arc::new(Guard::public()), HashMap::new()).unwrap();
        let resolver = Resolver { name: "dns.internal".parse().unwrap(), ip: "10.128.0.2".parse().unwrap() };
        let r = dns.lookup(&"example.com".parse().unwrap(), &[resolver]).await;
        assert!(matches!(&r, Err(ResolveError::Failed(e)) if e.contains("not a public address")), "{r:?}");
    }
}
