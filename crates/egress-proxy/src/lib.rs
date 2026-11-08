//! The egress proxy (SPEC.md "The egress proxy"): the only way out of a sandbox.
//!
//! It runs as its own process, `egress-proxy`, which shares no memory with the cell
//! key or the DEKs. The cell agent starts it through a [`Supervisor`], which feeds it
//! over its stdin and stdout ([`ipc`]), keeps each sandbox's egress log, and restarts
//! it with the same in-cell CA when it dies. Inside that process one [`Proxy`] serves
//! every sandbox (tests also run a [`Proxy`] in their own process).
//!
//! Each sandbox's network namespace routes to a veth whose host end is the sandbox's
//! gateway; nftables redirects the sandbox's TCP 443 and 80 and its DNS to the proxy's
//! ports, and the proxy also listens for CONNECT. The proxy tells sandboxes apart by
//! source address: each sandbox's address is registered with its policy (the bundle in
//! force when it was created, never changed after) and its released credentials, and
//! unregistered at the end, which ends its connections and wipes its credentials.
//!
//! ```ignore
//! let sup = Supervisor::start(SupervisorConfig { bin, roots_pem, cell: "cell-1".into(), network: Network::default(), status }).await?;
//! sup.register(sandbox_ip, id, policy, credentials).await?;
//! // ... the sandbox runs ...
//! let log = sup.unregister(sandbox_ip).await; // its egress log, hash and gaps
//! ```
//!
//! The proxy never stores a request or response body: HTTP/1.1 heads are parsed one at
//! a time, HTTP/2 headers one stream at a time, and bodies stream through. Its egress log records, per connection, the host, port, result
//! (`allowed`, `wildcard`, `passthrough`, `denied`, `error`), byte counts and the
//! credential substituted, and per refused DNS name a `denied` line.

mod adapter;
mod conn;
mod dns;
mod http;
mod http2;
pub mod ipc;
pub mod process;
mod resolve;
mod sni;
mod supervisor;
mod tls;

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use aws_lc_rs::digest;
use common::bundle::{HostName, Policy};
use common::cred::{Binding, CredName, Secret};
use common::ids::SandboxId;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;

pub use conn::Line;
pub use resolve::{Guard, is_public};
pub use supervisor::{Network, StatusFn, Supervisor, SupervisorConfig, SupervisorError};
pub use tls::{CaKey, CellCa, TlsError};

/// The proxy's ports on the cell (nftables redirects to the first three of these).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ports {
    /// Sandbox TCP 443.
    pub tls: u16,
    /// Sandbox TCP 80.
    pub http: u16,
    /// Sandbox UDP 53.
    pub dns: u16,
    /// The CONNECT endpoint, on the sandbox's gateway address.
    pub connect: u16,
}

impl Ports {
    pub const CELL: Ports = Ports {
        tls: 15443,
        http: 15080,
        dns: 15053,
        connect: 3128,
    };
}

/// What a proxy is built from.
pub struct Config {
    /// The public roots (PEM) destinations and resolvers must chain to.
    pub roots_pem: String,
    /// Shared with whoever learns the cell's own addresses ([`Guard::add_own`]).
    pub guard: Arc<Guard>,
    pub ports: Ports,
    /// Names the in-cell CA (the instance id).
    pub cell: String,
    /// Fixed name-to-address answers that bypass DNS (tests); production cells have
    /// none.
    pub hosts: HashMap<HostName, Vec<Ipv4Addr>>,
}

/// The proxy's sockets, bound by [`Listeners::bind`] or by a caller.
pub struct Listeners {
    pub tls: TcpListener,
    pub http: TcpListener,
    pub connect: TcpListener,
    pub dns: UdpSocket,
}

impl Listeners {
    /// Binds `ports` on `ip`; a port of 0 picks a free one ([`Listeners::ports`] says
    /// which).
    pub async fn bind(ip: Ipv4Addr, ports: Ports) -> std::io::Result<Self> {
        Ok(Self {
            tls: TcpListener::bind((ip, ports.tls)).await?,
            http: TcpListener::bind((ip, ports.http)).await?,
            connect: TcpListener::bind((ip, ports.connect)).await?,
            dns: UdpSocket::bind((ip, ports.dns)).await?,
        })
    }

    /// The ports bound.
    pub fn ports(&self) -> std::io::Result<Ports> {
        Ok(Ports {
            tls: self.tls.local_addr()?.port(),
            http: self.http.local_addr()?.port(),
            dns: self.dns.local_addr()?.port(),
            connect: self.connect.local_addr()?.port(),
        })
    }
}

/// A credential released to a sandbox: what it is bound to and its secret.
pub struct Credential {
    pub binding: Binding,
    pub secret: Secret,
}

/// The lines logged for one sandbox. All lines are hashed; the first
/// [`EgressLog::KEEP`] are kept.
pub(crate) struct EgressLog {
    lines: Vec<String>,
    count: u64,
    hash: digest::Context,
}

impl EgressLog {
    const KEEP: usize = 10_000;

    pub(crate) fn new() -> Self {
        Self {
            lines: Vec::new(),
            count: 0,
            hash: digest::Context::new(&digest::SHA256),
        }
    }

    /// Appends one line (JSON, without its newline).
    pub(crate) fn push(&mut self, json: String) {
        self.hash.update(json.as_bytes());
        self.hash.update(b"\n");
        self.count += 1;
        if self.lines.len() < Self::KEEP {
            self.lines.push(json);
        }
    }

    pub(crate) fn snapshot(&self, gaps: Vec<Gap>) -> LogSnapshot {
        LogSnapshot {
            lines: self.lines.clone(),
            count: self.count,
            sha256: common::hex(self.hash.clone().finish().as_ref()),
            gaps,
        }
    }
}

/// A stretch when a sandbox had no egress: from the moment the proxy process died to
/// the moment a new one held the sandbox (or the sandbox ended first). Connections open
/// when it died were reset; new ones were refused until `to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gap {
    pub from: SystemTime,
    pub to: SystemTime,
}

/// A sandbox's egress log as it stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSnapshot {
    /// The kept lines (JSON).
    pub lines: Vec<String>,
    /// Every line logged, kept or not.
    pub count: u64,
    /// SHA-256 (hex) over every line, each followed by `\n`.
    pub sha256: String,
    /// When the sandbox had no egress because the proxy process had died (oldest
    /// first; always empty for a [`Proxy`] in the caller's own process).
    pub gaps: Vec<Gap>,
}

/// Where a sandbox's log lines go.
enum Lines {
    /// Kept and hashed here.
    Kept(Mutex<EgressLog>),
    /// Handed, as JSON, to whoever started the proxy process, which keeps them.
    Sent(Box<dyn Fn(String) + Send + Sync>),
}

/// One sandbox, as the proxy knows it.
pub struct SandboxEgress {
    pub sandbox: SandboxId,
    /// The bundle in force when the sandbox was created.
    pub policy: Arc<Policy>,
    pub credentials: HashMap<CredName, Credential>,
    lines: Lines,
    cancel: watch::Sender<bool>,
}

impl SandboxEgress {
    /// A sandbox whose log the proxy keeps ([`Proxy::log`], [`Proxy::unregister`]).
    pub fn new(sandbox: SandboxId, policy: Arc<Policy>, credentials: HashMap<CredName, Credential>) -> Self {
        Self::with_lines(sandbox, policy, credentials, Lines::Kept(Mutex::new(EgressLog::new())))
    }

    /// A sandbox whose log lines are handed to `send` as they are recorded, each as
    /// JSON (the proxy process sends them to the agent, which keeps the log).
    pub fn streamed(
        sandbox: SandboxId,
        policy: Arc<Policy>,
        credentials: HashMap<CredName, Credential>,
        send: impl Fn(String) + Send + Sync + 'static,
    ) -> Self {
        Self::with_lines(sandbox, policy, credentials, Lines::Sent(Box::new(send)))
    }

    fn with_lines(sandbox: SandboxId, policy: Arc<Policy>, credentials: HashMap<CredName, Credential>, lines: Lines) -> Self {
        Self {
            sandbox,
            policy,
            credentials,
            lines,
            cancel: watch::Sender::new(false),
        }
    }

    fn record(&self, line: Line) {
        let json = serde_json::to_string(&line.finish()).expect("a log line always serialises");
        match &self.lines {
            Lines::Kept(log) => log.lock().unwrap_or_else(|p| p.into_inner()).push(json),
            Lines::Sent(send) => send(json),
        }
    }

    /// The log so far; `None` for a [`SandboxEgress::streamed`] sandbox, whose log is
    /// kept elsewhere.
    pub fn log(&self) -> Option<LogSnapshot> {
        match &self.lines {
            Lines::Kept(log) => Some(log.lock().unwrap_or_else(|p| p.into_inner()).snapshot(Vec::new())),
            Lines::Sent(_) => None,
        }
    }
}

pub(crate) struct Shared {
    ca: tls::CellCa,
    client_tls: Arc<rustls::ClientConfig>,
    dns: resolve::Dns,
    guard: Arc<Guard>,
    ports: Ports,
    sandboxes: RwLock<HashMap<Ipv4Addr, Arc<SandboxEgress>>>,
    connections: AtomicU32,
    /// Bytes written toward destinations since this proxy started ([`conn::Metered`]).
    egress_bytes: Arc<AtomicU64>,
}

impl Shared {
    fn sandbox(&self, ip: Ipv4Addr) -> Option<Arc<SandboxEgress>> {
        self.sandboxes.read().unwrap_or_else(|p| p.into_inner()).get(&ip).cloned()
    }
}

/// Counts an open connection for telemetry while it lives.
struct Open<'a>(&'a AtomicU32);

impl<'a> Open<'a> {
    fn new(c: &'a AtomicU32) -> Self {
        c.fetch_add(1, Ordering::Relaxed);
        Self(c)
    }
}

impl Drop for Open<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The egress proxy. Cheap to clone.
#[derive(Clone)]
pub struct Proxy {
    shared: Arc<Shared>,
}

#[derive(Debug, Clone, Copy)]
enum Kind {
    Tls,
    Http,
    Connect,
}

impl Kind {
    fn proto(self) -> &'static str {
        match self {
            Kind::Tls => "tls",
            Kind::Http => "http",
            Kind::Connect => "connect",
        }
    }
}

impl Proxy {
    /// A proxy with a fresh in-cell CA.
    pub fn new(cfg: Config) -> Result<Self, TlsError> {
        let ca = tls::CellCa::generate(&cfg.cell)?;
        Self::with_ca(cfg, ca)
    }

    /// A proxy presenting certificates from `ca` (the agent's CA, in the proxy process).
    pub fn with_ca(cfg: Config, ca: CellCa) -> Result<Self, TlsError> {
        let roots = tls::roots(&cfg.roots_pem)?;
        Ok(Self {
            shared: Arc::new(Shared {
                ca,
                client_tls: tls::client_config(Arc::clone(&roots), &[b"http/1.1"])?,
                dns: resolve::Dns::new(roots, Arc::clone(&cfg.guard), cfg.hosts)?,
                guard: cfg.guard,
                ports: cfg.ports,
                sandboxes: RwLock::new(HashMap::new()),
                connections: AtomicU32::new(0),
                egress_bytes: Arc::new(AtomicU64::new(0)),
            }),
        })
    }

    /// The in-cell CA certificate (PEM) sandboxes trust.
    pub fn ca_pem(&self) -> String {
        self.shared.ca.pem()
    }

    pub fn guard(&self) -> &Guard {
        &self.shared.guard
    }

    pub fn ports(&self) -> Ports {
        self.shared.ports
    }

    /// Connections open now (the telemetry's proxy connection count).
    pub fn connections(&self) -> u32 {
        self.shared.connections.load(Ordering::Relaxed)
    }

    /// Bytes sent toward destinations, for every sandbox, since this proxy started (SPEC.md
    /// phase 10's egress meter). Traffic of the proxy's own (its DoT lookups) is not in it.
    pub fn egress_bytes(&self) -> u64 {
        self.shared.egress_bytes.load(Ordering::Relaxed)
    }

    /// Binds the configured ports on every address and serves until a listener
    /// fails. Restarting it (after a failure) keeps the CA.
    pub async fn serve(&self) -> std::io::Result<()> {
        self.serve_on(Listeners::bind(Ipv4Addr::UNSPECIFIED, self.shared.ports).await?).await
    }
    /// Serves on sockets the caller bound.
    pub async fn serve_on(&self, l: Listeners) -> std::io::Result<()> {
        tokio::try_join!(
            self.accept(l.tls, Kind::Tls),
            self.accept(l.http, Kind::Http),
            self.accept(l.connect, Kind::Connect),
            self.answer(Arc::new(l.dns)),
        )?;
        Ok(())
    }

    async fn accept(&self, listener: TcpListener, kind: Kind) -> std::io::Result<()> {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(a) => a,
                // Out of descriptors and the like: back off, keep serving.
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let egress = match peer {
                SocketAddr::V4(v4) => self.shared.sandbox(*v4.ip()),
                SocketAddr::V6(_) => None,
            };
            let Some(egress) = egress else {
                let _ = stream.set_zero_linger();
                continue;
            };
            let _ = stream.set_nodelay(true);
            let dialled = original_destination(&stream);
            let shared = Arc::clone(&self.shared);
            tokio::spawn(async move {
                let _open = Open::new(&shared.connections);
                let mut cancel = egress.cancel.subscribe();
                let mut line = Line::new(kind.proto(), dialled);
                let work = async {
                    match kind {
                        Kind::Tls => conn::tls(&shared, &egress, stream, &mut line).await,
                        Kind::Http => conn::http(&shared, &egress, stream, &mut line).await,
                        Kind::Connect => conn::connect(&shared, &egress, stream, &mut line).await,
                    }
                };
                let ended = tokio::select! {
                    () = work => false,
                    _ = cancel.wait_for(|c| *c) => true,
                };
                if ended && line.reason.is_none() {
                    line.reason = Some("the sandbox ended".into());
                }
                egress.record(line);
            });
        }
    }

    async fn answer(&self, socket: Arc<UdpSocket>) -> std::io::Result<()> {
        let mut buf = vec![0u8; 1500];
        loop {
            let (n, peer) = socket.recv_from(&mut buf).await?;
            let SocketAddr::V4(peer) = peer else { continue };
            let Some(egress) = self.shared.sandbox(*peer.ip()) else { continue };
            let (shared, socket, query) = (Arc::clone(&self.shared), Arc::clone(&socket), buf[..n].to_vec());
            tokio::spawn(async move {
                let (reply, line) = conn::dns(&shared, &egress, &query).await;
                if let Some(line) = line {
                    egress.record(line);
                }
                if let Some(reply) = reply {
                    let _ = socket.send_to(&reply, SocketAddr::V4(peer)).await;
                }
            });
        }
    }

    /// Starts serving a sandbox at `ip`.
    pub fn register(&self, ip: Ipv4Addr, egress: SandboxEgress) -> Arc<SandboxEgress> {
        let e = Arc::new(egress);
        self.shared
            .sandboxes
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .insert(ip, Arc::clone(&e));
        e
    }

    /// The egress log of the sandbox at `ip`, while it is registered (and its log is
    /// kept here).
    pub fn log(&self, ip: Ipv4Addr) -> Option<LogSnapshot> {
        self.shared.sandbox(ip).and_then(|e| e.log())
    }

    /// Stops serving the sandbox at `ip`: ends its connections, waits (up to 5 s) until
    /// nothing else holds it (every connection has recorded its line), and drops it,
    /// wiping its credentials. Returns its log, if it is kept here.
    pub async fn unregister(&self, ip: Ipv4Addr) -> Option<LogSnapshot> {
        drained(self.end(ip)?).await
    }

    /// The first half of [`Proxy::unregister`], done at once: stops serving the sandbox
    /// at `ip` and ends its connections. Finish with [`drained`].
    pub(crate) fn end(&self, ip: Ipv4Addr) -> Option<Arc<SandboxEgress>> {
        let e = self.shared.sandboxes.write().unwrap_or_else(|p| p.into_inner()).remove(&ip)?;
        e.cancel.send_replace(true);
        Some(e)
    }
}

/// Waits (up to 5 s) until nothing but `e` holds an ended sandbox, then drops it,
/// wiping its credentials; returns its log, if it is kept here.
pub(crate) async fn drained(e: Arc<SandboxEgress>) -> Option<LogSnapshot> {
    for _ in 0..500 {
        if Arc::strong_count(&e) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let log = e.log();
    drop(e);
    log
}

/// Where a redirected connection was going (`SO_ORIGINAL_DST`), for the log.
#[cfg(target_os = "linux")]
fn original_destination(s: &TcpStream) -> Option<SocketAddrV4> {
    let a = nix::sys::socket::getsockopt(s, nix::sys::socket::sockopt::OriginalDst).ok()?;
    Some(SocketAddrV4::new(
        Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)),
        u16::from_be(a.sin_port),
    ))
}

#[cfg(not(target_os = "linux"))]
fn original_destination(_: &TcpStream) -> Option<SocketAddrV4> {
    None
}

/// Helpers for tests of the proxy, here and in the cell agent: a signed policy,
/// destinations that record what they receive (HTTP/1.1, and HTTP/2 over TLS from a
/// test CA the proxy trusts), and clients through the CONNECT endpoint.
#[doc(hidden)]
pub mod testing {
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};

    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
    use bytes::Bytes;
    use common::bundle::Policy;
    use common::evidence::Spki;
    use common::jws::{self, TrustedKey};
    use common::sandbox::{CpuHalves, MemoryGib, Size};
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyUsagePurpose};
    use rustls::crypto::aws_lc_rs as provider;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use crate::{Config, Guard, Listeners, Ports, Proxy, tls};

    /// The HTTP/2 test destination's gRPC-style bidirectional echo.
    pub const ECHO: &str = "/clovelly.test.Echo/Stream";

    /// A root CA for test destinations: give [`TestCa::pem`] to the proxy as its public
    /// roots and serve with [`TestCa::server_config`].
    pub struct TestCa {
        issuer: Issuer<'static, rcgen::KeyPair>,
        cert: CertificateDer<'static>,
    }

    impl Default for TestCa {
        fn default() -> Self {
            Self::new()
        }
    }

    impl TestCa {
        pub fn new() -> Self {
            let key = rcgen::KeyPair::generate().expect("a test key");
            let mut p = CertificateParams::new(Vec::<String>::new()).expect("params");
            p.distinguished_name.push(DnType::CommonName, "clovelly test roots");
            p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
            let cert = p.self_signed(&key).expect("a test root").der().clone();
            Self { issuer: Issuer::new(p, key), cert }
        }

        pub fn pem(&self) -> String {
            common::b64::pem("CERTIFICATE", &self.cert)
        }

        /// A server configuration with a certificate for `name`, negotiating `alpn`.
        pub fn server_config(&self, name: &str, alpn: &[&[u8]]) -> Arc<rustls::ServerConfig> {
            let key = rcgen::KeyPair::generate().expect("a test key");
            let cert = CertificateParams::new(vec![name.to_owned()])
                .and_then(|p| p.signed_by(&key, &self.issuer))
                .expect("a test certificate");
            let mut c = rustls::ServerConfig::builder_with_provider(Arc::new(provider::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("TLS versions")
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone(), self.cert.clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
                )
                .expect("a server configuration");
            c.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
            Arc::new(c)
        }
    }

    /// A policy for env `staging`, sub-environment `a`, with these destinations
    /// (JSON array), signed and verified.
    pub fn policy(destinations: &str) -> Arc<Policy> {
        let kp = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).expect("P-256 key");
        let key = TrustedKey::from_spki(Spki::from_der(kp.public_key().as_der().expect("SPKI").as_ref()).expect("SPKI"));
        let now = SystemTime::now();
        let expires = now.duration_since(SystemTime::UNIX_EPOCH).expect("after 1970").as_secs() + 3600;
        let bundle = format!(r#"{{"v":1,"env":"staging","subenv":"a","version":1,"expires":{expires},"destinations":{destinations}}}"#);
        let sig = kp.sign(&SystemRandom::new(), jws::signing_input(bundle.as_bytes()).as_bytes()).expect("sign");
        let sig = jws::assemble(bundle.as_bytes(), sig.as_ref(), true).expect("JWS");
        let placeable = Size::new(CpuHalves(14), MemoryGib(27));
        Arc::new(Policy::verify(bundle.as_bytes(), &sig, &key, &"staging".parse().expect("id"), &"a".parse().expect("id"), now, placeable).expect("valid policy"))
    }

    /// A proxy on ephemeral loopback ports that may connect to 127.0.0.1 and resolves
    /// `names` there; returns it and its CONNECT address.
    pub async fn proxy(names: &[&str]) -> (Proxy, SocketAddr) {
        proxy_trusting(names, &TestCa::new().pem()).await
    }

    /// [`proxy`] with `roots_pem` as its public roots.
    pub async fn proxy_trusting(names: &[&str], roots_pem: &str) -> (Proxy, SocketAddr) {
        let hosts: HashMap<_, _> = names.iter().map(|n| (n.parse().expect("name"), vec![Ipv4Addr::LOCALHOST])).collect();
        let proxy = Proxy::new(Config {
            roots_pem: roots_pem.to_owned(),
            guard: Arc::new(Guard::with_exempt(vec![Ipv4Addr::LOCALHOST])),
            ports: Ports::CELL,
            cell: "test".into(),
            hosts,
        })
        .expect("proxy");
        let bind = || TcpListener::bind((Ipv4Addr::LOCALHOST, 0));
        let l = Listeners {
            tls: bind().await.expect("bind"),
            http: bind().await.expect("bind"),
            connect: bind().await.expect("bind"),
            dns: UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("bind"),
        };
        let connect = l.connect.local_addr().expect("address");
        let p = proxy.clone();
        tokio::spawn(async move { p.serve_on(l).await });
        (proxy, connect)
    }

    /// A destination on loopback that records each request head and answers 200.
    pub async fn destination() -> (u16, Arc<Mutex<Vec<String>>>) {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("bind");
        let port = l.local_addr().expect("address").port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let seen = Arc::clone(&s2);
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    while let Ok(n) = s.read(&mut chunk).await {
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head: Vec<u8> = buf.drain(..end + 4).collect();
                            seen.lock().expect("lock").push(String::from_utf8_lossy(&head).into_owned());
                            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
                        }
                    }
                });
            }
        });
        (port, seen)
    }

    /// One request's headers as the HTTP/2 destination saw them, `:authority` and
    /// `:path` first.
    pub type Seen = Arc<Mutex<Vec<Vec<(String, String)>>>>;

    /// An HTTP/2 destination over TLS on loopback with a certificate for `name` from
    /// `ca`. It records every request's headers; at [`ECHO`] it answers at once, echoes
    /// each DATA frame and ends with trailers `grpc-status: 0` and `clovelly-echoed: <bytes>`;
    /// anything else gets 200 and `ok`.
    pub async fn h2_destination(ca: &TestCa, name: &str) -> (u16, Seen) {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("bind");
        let port = l.local_addr().expect("address").port();
        let acceptor = TlsAcceptor::from(ca.server_config(name, &[b"h2", b"http/1.1"]));
        let seen: Seen = Arc::default();
        let s2 = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let (acceptor, seen) = (acceptor.clone(), Arc::clone(&s2));
                tokio::spawn(async move {
                    let Ok(s) = acceptor.accept(s).await else { return };
                    if s.get_ref().1.alpn_protocol() != Some(b"h2") {
                        return;
                    }
                    let Ok(mut conn) = h2::server::handshake(s).await else { return };
                    while let Some(Ok((req, respond))) = conn.accept().await {
                        let mut headers = vec![
                            (":authority".to_owned(), req.uri().authority().map(|a| a.to_string()).unwrap_or_default()),
                            (":path".to_owned(), req.uri().path().to_owned()),
                        ];
                        headers.extend(req.headers().iter().map(|(n, v)| (n.to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned())));
                        seen.lock().expect("lock").push(headers);
                        tokio::spawn(answer(req, respond));
                    }
                });
            }
        });
        (port, seen)
    }

    async fn answer(req: ::http::Request<h2::RecvStream>, mut respond: h2::server::SendResponse<Bytes>) {
        let echo = req.uri().path() == ECHO;
        let mut body = req.into_body();
        let ok = ::http::Response::builder().status(200).body(()).expect("a response");
        let Ok(mut send) = respond.send_response(ok, false) else { return };
        if !echo {
            let _ = send.send_data(Bytes::from_static(b"ok"), true);
            return;
        }
        let mut echoed = 0;
        while let Some(Ok(chunk)) = body.data().await {
            let _ = body.flow_control().release_capacity(chunk.len());
            echoed += chunk.len();
            if send.send_data(chunk, false).is_err() {
                return;
            }
        }
        let mut trailers = ::http::HeaderMap::new();
        trailers.insert("grpc-status", ::http::HeaderValue::from_static("0"));
        trailers.insert("clovelly-echoed", echoed.into());
        let _ = send.send_trailers(trailers);
    }

    /// CONNECTs through the proxy to `target` and starts TLS trusting `ca_pem` (the
    /// in-cell CA), offering `alpn`.
    pub async fn tls_through(
        connect: SocketAddr,
        target: &str,
        ca_pem: &str,
        alpn: &[&[u8]],
    ) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let mut s = TcpStream::connect(connect).await?;
        s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes()).await?;
        let mut answer = Vec::new();
        while !answer.ends_with(b"\r\n\r\n") {
            let mut b = [0u8; 1];
            if s.read(&mut b).await? == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            answer.push(b[0]);
        }
        if !answer.starts_with(b"HTTP/1.1 200") {
            return Err(std::io::Error::other(String::from_utf8_lossy(&answer).into_owned()));
        }
        let roots = tls::roots(ca_pem).map_err(std::io::Error::other)?;
        let config = tls::client_config(roots, alpn).map_err(std::io::Error::other)?;
        let host = target.rsplit_once(':').map_or(target, |(h, _)| h);
        let name = ServerName::try_from(host.to_owned()).map_err(std::io::Error::other)?;
        TlsConnector::from(config).connect(name, s).await
    }

    /// An HTTP/2 client through the CONNECT endpoint to `target`, trusting `ca_pem`.
    pub async fn h2_through(connect: SocketAddr, target: &str, ca_pem: &str) -> std::io::Result<h2::client::SendRequest<Bytes>> {
        let tls = tls_through(connect, target, ca_pem, &[b"h2"]).await?;
        let (sender, conn) = h2::client::handshake(tls).await.map_err(std::io::Error::other)?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(sender)
    }

    /// CONNECTs through the proxy to `target` and sends `request`; returns what came
    /// back (the CONNECT answer and the response), or an error if the proxy reset.
    pub async fn through(connect: SocketAddr, target: &str, request: &str) -> std::io::Result<String> {
        let mut s = TcpStream::connect(connect).await?;
        s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes()).await?;
        let mut answer = vec![0u8; 256];
        let n = s.read(&mut answer).await?;
        let mut out = String::from_utf8_lossy(&answer[..n]).into_owned();
        if !out.starts_with("HTTP/1.1 200") {
            return Ok(out);
        }
        s.write_all(request.as_bytes()).await?;
        let mut rest = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut rest)).await;
        out.push_str(&String::from_utf8_lossy(&rest));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::cred::AdapterType;

    fn credential(name: &str, dest: &str, secret: &str) -> (CredName, Credential) {
        let name: CredName = name.parse().unwrap();
        let binding = Binding {
            name: name.clone(),
            adapter: AdapterType::Bearer,
            destination: dest.parse().unwrap(),
        };
        (name, Credential { binding, secret: Secret::copy_from(secret.as_bytes()).unwrap() })
    }

    /// Criterion 1, end to end on loopback: the placeholder reaches the destination as
    /// the real credential; a request naming another host, and a destination outside
    /// the policy, are refused and logged.
    #[tokio::test]
    async fn a_placeholder_arrives_as_the_credential_and_refusals_are_logged() {
        let (proxy, connect) = testing::proxy(&["dest.test"]).await;
        let (port, seen) = testing::destination().await;
        let policy = testing::policy(&format!(
            r#"[{{"host":"dest.test","port":{port},"adapter":{{"type":"bearer","credential":"svc"}}}}]"#
        ));
        let id = SandboxId::generate();
        proxy.register(Ipv4Addr::LOCALHOST, SandboxEgress::new(id, policy, HashMap::from([credential("svc", "dest.test", "REAL-SECRET")])));

        let target = format!("dest.test:{port}");
        let got = testing::through(connect, &target, &format!("GET /x HTTP/1.1\r\nHost: {target}\r\nAuthorization: Bearer clovelly://cred/svc\r\nConnection: close\r\n\r\n"))
            .await
            .unwrap();
        assert!(got.contains("200 OK") && got.ends_with("ok"), "{got}");
        let heads = seen.lock().unwrap().clone();
        assert!(heads[0].contains("Authorization: Bearer REAL-SECRET\r\n"), "{heads:?}");

        let misdirected = testing::through(connect, &target, "GET / HTTP/1.1\r\nHost: other.test\r\n\r\n").await;
        assert!(misdirected.is_err() || !misdirected.unwrap().contains("ok"));
        let denied = testing::through(connect, "elsewhere.test:443", "").await.unwrap();
        assert!(denied.starts_with("HTTP/1.1 403"), "{denied}");

        tokio::time::sleep(Duration::from_millis(100)).await;
        let log = proxy.unregister(Ipv4Addr::LOCALHOST).await.unwrap();
        let results: Vec<serde_json::Value> = log.lines.iter().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert!(results.iter().any(|l| l["result"] == "allowed" && l["credential"] == "svc"), "{results:?}");
        assert!(results.iter().any(|l| l["result"] == "denied" && l["host"] == "elsewhere.test"), "{results:?}");
        assert!(results.iter().any(|l| l["result"] == "denied" && l["reason"].as_str().unwrap_or("").contains("other.test")), "{results:?}");
        assert!(!log.lines.iter().any(|l| l.contains("REAL-SECRET")), "the log holds no secret");
        assert_eq!(log.count as usize, log.lines.len());
        assert_eq!(log.sha256.len(), 64);
    }

    /// A CONNECT to port 443 must carry TLS, and an upgrade is refused where path rules
    /// apply: neither may put a credential in the clear or step around the rules.
    #[tokio::test]
    async fn plain_text_to_443_and_upgrades_past_path_rules_are_refused() {
        let (proxy, connect) = testing::proxy(&["dest.test"]).await;
        let (port, seen) = testing::destination().await;
        let policy = testing::policy(&format!(
            r#"[{{"host":"dest.test","port":443}},{{"host":"dest.test","port":{port},"paths":["/v1/"]}}]"#
        ));
        proxy.register(Ipv4Addr::LOCALHOST, SandboxEgress::new(SandboxId::generate(), policy, HashMap::new()));
        let plain = testing::through(connect, "dest.test:443", "GET / HTTP/1.1\r\nHost: dest.test\r\n\r\n").await;
        assert!(plain.map_or(true, |s| !s.contains("ok")));
        let target = format!("dest.test:{port}");
        let upgrade = testing::through(
            connect,
            &target,
            &format!("GET /v1/ws HTTP/1.1\r\nHost: {target}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"),
        )
        .await;
        assert!(upgrade.map_or(true, |s| !s.ends_with("ok")));
        assert!(seen.lock().unwrap().is_empty(), "nothing reached the destination");
        let log = proxy.unregister(Ipv4Addr::LOCALHOST).await.unwrap();
        assert_eq!(log.lines.iter().filter(|l| l.contains(r#""result":"denied""#)).count(), 2, "{:?}", log.lines);
    }

    /// An upgrade the destination declines ends the connection after its answer, so a
    /// later request (here one naming another host) never reaches it unchecked; an
    /// upgrade after another request is refused; one the destination accepts (101)
    /// becomes a byte tunnel.
    #[tokio::test]
    async fn only_an_accepted_upgrade_becomes_a_tunnel() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (proxy, connect) = testing::proxy(&["dest.test", "ws.test"]).await;
        let (port, seen) = testing::destination().await;
        // A destination that switches protocols, then echoes.
        let l = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let ws_port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let (mut buf, mut have) = (vec![0u8; 4096], Vec::new());
            let end = loop {
                if let Some(i) = have.windows(4).position(|w| w == b"\r\n\r\n") {
                    break i + 4;
                }
                let n = s.read(&mut buf).await.unwrap();
                have.extend_from_slice(&buf[..n]);
            };
            s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n").await.unwrap();
            s.write_all(&have[end..]).await.unwrap();
            while let Ok(n @ 1..) = s.read(&mut buf).await {
                s.write_all(&buf[..n]).await.unwrap();
            }
        });
        let policy = testing::policy(&format!(r#"[{{"host":"dest.test","port":{port}}},{{"host":"ws.test","port":{ws_port}}}]"#));
        proxy.register(Ipv4Addr::LOCALHOST, SandboxEgress::new(SandboxId::generate(), policy, HashMap::new()));

        let target = format!("dest.test:{port}");
        let upgrade = |t: &str| format!("GET /ws HTTP/1.1\r\nHost: {t}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n");
        let declined = testing::through(connect, &target, &format!("{}GET / HTTP/1.1\r\nHost: other.test\r\n\r\n", upgrade(&target)))
            .await
            .unwrap();
        assert!(declined.ends_with("ok"), "{declined}");
        let heads = seen.lock().unwrap().clone();
        assert_eq!(heads.len(), 1, "only the upgrade request arrived: {heads:?}");

        // A refusal drops both connections at once, so whether `/a` is seen is a race;
        // the upgrade after it must never arrive.
        let _ = testing::through(connect, &target, &format!("GET /a HTTP/1.1\r\nHost: {target}\r\n\r\n{}", upgrade(&target))).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let heads = seen.lock().unwrap().clone();
        assert!(heads[1..].iter().all(|h| h.starts_with("GET /a ")), "{heads:?}");

        let ws = format!("ws.test:{ws_port}");
        let tunnel = testing::through(connect, &ws, &format!("{}PING", upgrade(&ws))).await.unwrap();
        assert!(tunnel.contains(" 101 ") && tunnel.ends_with("PING"), "{tunnel}");

        let log = proxy.unregister(Ipv4Addr::LOCALHOST).await.unwrap();
        assert!(log.lines.iter().any(|l| l.contains("first request")), "{:?}", log.lines);
    }

    /// Criterion 13: under `*` a connection is logged `wildcard` and nothing is
    /// substituted, even for a credential bound to that very host.
    #[tokio::test]
    async fn wildcard_destinations_substitute_nothing() {
        let (proxy, connect) = testing::proxy(&["dest.test"]).await;
        let (port, seen) = testing::destination().await;
        let policy = testing::policy(&format!(r#"[{{"host":"*","port":{port}}}]"#));
        let id = SandboxId::generate();
        proxy.register(Ipv4Addr::LOCALHOST, SandboxEgress::new(id, policy, HashMap::from([credential("svc", "dest.test", "REAL-SECRET")])));
        let target = format!("dest.test:{port}");
        let got = testing::through(connect, &target, &format!("GET / HTTP/1.1\r\nHost: {target}\r\nAuthorization: Bearer clovelly://cred/svc\r\nConnection: close\r\n\r\n"))
            .await
            .unwrap();
        assert!(got.ends_with("ok"), "{got}");
        assert!(seen.lock().unwrap()[0].contains("Bearer clovelly://cred/svc\r\n"));
        let log = proxy.unregister(Ipv4Addr::LOCALHOST).await.unwrap();
        assert!(log.lines[0].contains(r#""result":"wildcard""#) && !log.lines[0].contains("credential"), "{:?}", log.lines);
    }

    /// Phase 10 criterion 2, on loopback: a request with a body of known size counts every
    /// byte that reached the destination, exactly, and nothing of the larger response or of
    /// a refused destination.
    #[tokio::test]
    async fn the_egress_meter_counts_what_leaves_toward_destinations() {
        use std::sync::atomic::AtomicU64;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (proxy, connect) = testing::proxy(&["sink.test"]).await;
        // A destination that counts every byte it receives, reads one request with its
        // body, and answers with two megabytes.
        let l = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = l.local_addr().unwrap().port();
        let received = Arc::new(AtomicU64::new(0));
        let r2 = Arc::clone(&received);
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = vec![0u8; 65536];
            let want = loop {
                let n = s.read(&mut chunk).await.unwrap();
                buf.extend_from_slice(&chunk[..n]);
                if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..end]).to_lowercase();
                    let len: usize = head.lines().find_map(|l| l.strip_prefix("content-length: ")).unwrap().trim().parse().unwrap();
                    break end + 4 + len;
                }
            };
            while buf.len() < want {
                let n = s.read(&mut chunk).await.unwrap();
                buf.extend_from_slice(&chunk[..n]);
            }
            r2.store(buf.len() as u64, Ordering::SeqCst);
            let body = vec![b'r'; 2 << 20];
            let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await;
            let _ = s.write_all(&body).await;
        });
        let policy = testing::policy(&format!(r#"[{{"host":"sink.test","port":{port}}}]"#));
        proxy.register(Ipv4Addr::LOCALHOST, SandboxEgress::new(SandboxId::generate(), policy, HashMap::new()));
        assert_eq!(proxy.egress_bytes(), 0);

        let body = "a".repeat(1_000_000);
        let target = format!("sink.test:{port}");
        let request = format!("POST /up HTTP/1.1\r\nHost: {target}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        let got = testing::through(connect, &target, &request).await.unwrap();
        assert!(got.contains("200 OK"), "{}", &got[..got.len().min(200)]);
        let denied = testing::through(connect, "elsewhere.test:443", "").await.unwrap();
        assert!(denied.starts_with("HTTP/1.1 403"), "{denied}");

        let sent = proxy.egress_bytes();
        assert_eq!(sent, received.load(Ordering::SeqCst), "the meter counts exactly what reached the destination");
        let off = sent.abs_diff(1_000_000) as f64 / 1_000_000.0;
        assert!(off < 0.01, "{sent} bytes for a 1,000,000-byte body");
        proxy.unregister(Ipv4Addr::LOCALHOST).await.unwrap();
        assert_eq!(proxy.egress_bytes(), sent, "the count is the proxy's, not the sandbox's: it outlives it");
    }
}
