//! One sandbox connection through the proxy, from its first bytes to its log line.
//!
//! - TLS (intercepted port 443): the ClientHello's server name picks the destination.
//!   Denied: TCP reset. Passthrough: the ClientHello and everything after are relayed
//!   untouched. Otherwise TLS is terminated with a certificate from the in-cell CA and
//!   the requests inside are relayed over the proxy's own TLS to the destination. A
//!   sandbox that offers HTTP/2 (ALPN `h2`) has its offer made to the destination
//!   first, and its TLS then negotiates exactly what the destination chose: HTTP/2 on
//!   both sides is relayed stream by stream ([`crate::http2`]), anything else as
//!   HTTP/1.1.
//! - HTTP (intercepted port 80): the first request's Host header picks the destination.
//! - CONNECT (port 3128 on the sandbox's gateway): the CONNECT target picks it, then the
//!   tunnel is handled as TLS or HTTP by its first byte.
//! - DNS (intercepted UDP 53): names the policy allows are resolved over DoT; any other
//!   gets NXDOMAIN and a log line.
//!
//! Every request on an inspected connection must name the connection's host in its Host
//! header or HTTP/2 `:authority` (so a request cannot be steered to another virtual
//! host on the same address),
//! pass the destination's path rules, and is rewritten by the destination's adapter
//! when it carries the adapter's placeholder. The proxy only ever connects to the host
//! the policy allowed, resolved by itself, never to the address the sandbox dialled.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use common::bundle::{Adapter, Destination, Host, Verdict};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::http::{self, BufIn, Framing};
use crate::resolve::ResolveError;
use crate::{Credential, SandboxEgress, Shared, adapter, dns, http2, sni, tls};

/// ALPN protocol names the proxy can inspect.
const H2: &[u8] = b"h2";
const HTTP11: &[u8] = b"http/1.1";

/// How long the proxy waits for a connection's first bytes (ClientHello, request head
/// or CONNECT).
const FIRST_BYTES: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// After the sandbox has closed its side, how long responses may still arrive.
const DRAIN: Duration = Duration::from_secs(60);

/// One egress log line: a connection or a refused DNS question. No request or response
/// content, only where, how much and what the policy said.
#[derive(Debug, Clone, Serialize)]
pub struct Line {
    pub at_ms: u64,
    pub proto: &'static str,
    pub host: String,
    pub port: u16,
    /// The address the sandbox dialled (informational; never connected to).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dialled: Option<String>,
    /// `allowed` (a named destination), `wildcard`, `passthrough`, `denied` or `error`.
    pub result: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The credential substituted into at least one request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    pub requests: u32,
    pub up: u64,
    pub down: u64,
    pub ms: u64,
    #[serde(skip)]
    started: Option<Instant>,
}

impl Line {
    pub(crate) fn new(proto: &'static str, dialled: Option<SocketAddrV4>) -> Self {
        Self {
            at_ms: SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64),
            proto,
            host: String::new(),
            port: dialled.map_or(0, |d| d.port()),
            dialled: dialled.map(|d| d.to_string()),
            result: "error",
            reason: None,
            credential: None,
            requests: 0,
            up: 0,
            down: 0,
            ms: 0,
            started: Some(Instant::now()),
        }
    }

    pub(crate) fn deny(&mut self, why: impl Into<String>) {
        self.result = "denied";
        self.reason = Some(why.into());
    }

    pub(crate) fn error(&mut self, why: impl Into<String>) {
        self.result = "error";
        self.reason = Some(why.into());
    }

    /// Stamps the duration; called once the connection is over.
    pub fn finish(mut self) -> Self {
        self.ms = self.started.take().map_or(0, |s| s.elapsed().as_millis() as u64);
        self
    }
}

/// The log result for an allowed verdict.
fn result_of(v: Verdict<'_>) -> &'static str {
    match v {
        Verdict::Named(d) | Verdict::Wildcard(d) if d.is_passthrough() => "passthrough",
        Verdict::Wildcard(_) => "wildcard",
        Verdict::Named(_) => "allowed",
        Verdict::Denied => "denied",
    }
}

/// Ends a connection with a TCP reset.
fn reset(s: TcpStream) {
    let _ = s.set_zero_linger();
    drop(s);
}

/// A stream that first yields bytes already read from it.
pub(crate) struct Prefixed<S> {
    prefix: Vec<u8>,
    at: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    pub(crate) fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self { prefix, at: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.at < self.prefix.len() {
            let n = (self.prefix.len() - self.at).min(buf.remaining());
            let at = self.at;
            buf.put_slice(&self.prefix[at..at + n]);
            self.at += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Relays bytes both ways until both directions end (a passthrough destination), adding
/// the bytes each way to `line` even when one side resets.
async fn splice(client: TcpStream, upstream: TcpStream, line: &mut Line) {
    async fn one_way(mut r: impl AsyncRead + Unpin, mut w: impl AsyncWrite + Unpin) -> (u64, Option<String>) {
        let mut buf = vec![0u8; http::BUF];
        let mut n = 0u64;
        loop {
            match r.read(&mut buf).await {
                Ok(0) => {
                    let _ = w.shutdown().await;
                    return (n, None);
                }
                Ok(k) => {
                    if let Err(e) = w.write_all(&buf[..k]).await {
                        return (n, Some(e.to_string()));
                    }
                    n += k as u64;
                }
                Err(e) => {
                    let _ = w.shutdown().await;
                    return (n, Some(e.to_string()));
                }
            }
        }
    }
    let (cr, cw) = client.into_split();
    let (ur, uw) = upstream.into_split();
    let ((up, e1), (down, e2)) = tokio::join!(one_way(cr, uw), one_way(ur, cw));
    line.up += up;
    line.down += down;
    if let Some(e) = e1.or(e2) {
        line.reason = Some(e);
    }
}

/// Connects to `host:port`, resolved by the proxy and only to addresses the guard
/// permits.
async fn upstream(shared: &Shared, egress: &SandboxEgress, host: &Host, port: u16) -> Result<TcpStream, String> {
    let ips: Vec<Ipv4Addr> = match host {
        Host::Ip(ip) => vec![*ip],
        Host::Name(n) => match shared.dns.lookup(n, &egress.policy.resolvers()).await {
            Ok(ips) => ips,
            Err(ResolveError::NoSuchName) => return Err("no such name".into()),
            Err(e) => return Err(e.to_string()),
        },
    };
    let permitted: Vec<Ipv4Addr> = ips.into_iter().filter(|ip| shared.guard.permits(*ip)).collect();
    if permitted.is_empty() {
        return Err("no public address".into());
    }
    let mut last = String::new();
    for ip in permitted {
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(SocketAddr::from((ip, port)))).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                return Ok(s);
            }
            Ok(Err(e)) => last = format!("{ip}: {e}"),
            Err(_) => last = format!("{ip}: connect timed out"),
        }
    }
    Err(last)
}

/// What a ClientHello asked for: its server name and the protocols it offers.
struct Asked {
    sni: Option<String>,
    alpn: Vec<Vec<u8>>,
}

/// Reads until `buf` holds a whole ClientHello.
async fn read_hello<S: AsyncRead + Unpin>(s: &mut S, buf: &mut Vec<u8>) -> Result<Asked, &'static str> {
    let mut chunk = [0u8; 4096];
    loop {
        match sni::parse(buf) {
            sni::Hello::Complete { sni, alpn } => return Ok(Asked { sni, alpn }),
            sni::Hello::NotTls => return Err("not a TLS ClientHello"),
            sni::Hello::Incomplete => {}
        }
        let n = s.read(&mut chunk).await.map_err(|_| "read failed")?;
        if n == 0 {
            return Err("closed before a ClientHello");
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Intercepted port 443.
pub(crate) async fn tls(shared: &Shared, egress: &Arc<SandboxEgress>, mut client: TcpStream, line: &mut Line) {
    line.port = 443;
    let mut hello = Vec::with_capacity(2048);
    let Asked { sni, alpn } = match tokio::time::timeout(FIRST_BYTES, read_hello(&mut client, &mut hello)).await {
        Ok(Ok(asked)) => asked,
        Ok(Err(why)) => {
            reset(client);
            return line.deny(why);
        }
        Err(_) => {
            reset(client);
            return line.deny("no ClientHello in time");
        }
    };
    let Some(Ok(host)) = sni.as_deref().map(str::parse::<Host>) else {
        line.host = sni.unwrap_or_default();
        reset(client);
        return line.deny("no usable server name");
    };
    line.host = host.to_string();
    tls_to(shared, egress, client, (hello, alpn), host, 443, line).await;
}

/// A TLS stream (its ClientHello already read into `hello`, offering `alpn`) to
/// `host:port`.
async fn tls_to(
    shared: &Shared,
    egress: &Arc<SandboxEgress>,
    client: TcpStream,
    (hello, alpn): (Vec<u8>, Vec<Vec<u8>>),
    host: Host,
    port: u16,
    line: &mut Line,
) {
    let verdict = egress.policy.decide(&host, port);
    let Some(dest) = verdict.destination() else {
        reset(client);
        return line.deny("not in policy");
    };
    line.result = result_of(verdict);
    let mut up = match upstream(shared, egress, &host, port).await {
        Ok(s) => s,
        Err(e) => {
            reset(client);
            return line.error(e);
        }
    };
    if dest.is_passthrough() {
        if up.write_all(&hello).await.is_err() {
            return line.error("destination closed");
        }
        line.up = hello.len() as u64;
        drop(hello);
        splice(client, up, line).await;
        return;
    }
    let route = Route { dest, verdict, host: &host, port };
    // The protocols the proxy can inspect, in the sandbox's order.
    let offered: Vec<&[u8]> = alpn.iter().map(Vec::as_slice).filter(|p| *p == H2 || *p == HTTP11).collect();
    if !offered.contains(&H2) {
        let config = match shared.ca.server_config(&host, Some(HTTP11)) {
            Ok(c) => c,
            Err(e) => return line.error(e.to_string()),
        };
        let client = match TlsAcceptor::from(config).accept(Prefixed::new(hello, client)).await {
            Ok(s) => s,
            Err(e) => return line.error(format!("sandbox TLS: {e}")),
        };
        let up = match TlsConnector::from(Arc::clone(&shared.client_tls)).connect(tls::server_name(&host), up).await {
            Ok(s) => s,
            Err(e) => return line.error(format!("destination TLS: {e}")),
        };
        return relay(egress, &route, client, up, &[], line).await;
    }
    // HTTP/2 offered: the destination chooses first, and the sandbox gets its choice.
    let mut offer = (*shared.client_tls).clone();
    offer.alpn_protocols = offered.iter().map(|p| p.to_vec()).collect();
    let up = match TlsConnector::from(Arc::new(offer)).connect(tls::server_name(&host), up).await {
        Ok(s) => s,
        Err(e) => {
            reset(client);
            return line.error(format!("destination TLS: {e}"));
        }
    };
    let chosen = up.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    let config = match shared.ca.server_config(&host, chosen.as_deref()) {
        Ok(c) => c,
        Err(e) => return line.error(e.to_string()),
    };
    let client = match TlsAcceptor::from(config).accept(Prefixed::new(hello, client)).await {
        Ok(s) => s,
        Err(e) => return line.error(format!("sandbox TLS: {e}")),
    };
    if chosen.as_deref() == Some(H2) {
        let conn = http2::Conn::new(Arc::clone(egress), dest.clone(), &host, port, substitution(egress, &route).map(|(a, _)| a.clone()));
        http2::relay(conn, client, up, line).await;
    } else {
        relay(egress, &route, client, up, &[], line).await;
    }
}

/// Intercepted port 80.
pub(crate) async fn http(shared: &Shared, egress: &Arc<SandboxEgress>, mut client: TcpStream, line: &mut Line) {
    line.port = 80;
    let first = {
        let mut cin = BufIn::new(&mut client, &[]);
        match tokio::time::timeout(FIRST_BYTES, cin.head()).await {
            Ok(Ok(Some(head))) => {
                let mut all = head;
                all.extend_from_slice(cin.data());
                all
            }
            _ => {
                drop(cin);
                reset(client);
                return line.deny("no request head");
            }
        }
    };
    let host = http::head_end(&first)
        .and_then(|end| http::parse(&first[..end]).ok())
        .and_then(|r| {
            let h = r.host();
            let name = h.rsplit_once(':').map_or(h, |(n, _)| n);
            name.parse::<Host>().ok()
        });
    let Some(host) = host else {
        reset(client);
        return line.deny("no usable Host header");
    };
    line.host = host.to_string();
    plain_to(shared, egress, client, first, host, 80, line).await;
}

/// A plain HTTP stream (its first bytes already read into `first`) to `host:port`.
async fn plain_to(
    shared: &Shared,
    egress: &SandboxEgress,
    client: TcpStream,
    first: Vec<u8>,
    host: Host,
    port: u16,
    line: &mut Line,
) {
    let verdict = egress.policy.decide(&host, port);
    let Some(dest) = verdict.destination() else {
        reset(client);
        return line.deny("not in policy");
    };
    line.result = result_of(verdict);
    let mut up = match upstream(shared, egress, &host, port).await {
        Ok(s) => s,
        Err(e) => {
            reset(client);
            return line.error(e);
        }
    };
    if dest.is_passthrough() {
        if up.write_all(&first).await.is_err() {
            return line.error("destination closed");
        }
        line.up = first.len() as u64;
        splice(client, up, line).await;
        return;
    }
    let route = Route { dest, verdict, host: &host, port };
    relay(egress, &route, client, up, &first, line).await;
}

/// The explicit CONNECT endpoint.
pub(crate) async fn connect(shared: &Shared, egress: &Arc<SandboxEgress>, mut client: TcpStream, line: &mut Line) {
    let (head, mut rest) = {
        let mut cin = BufIn::new(&mut client, &[]);
        match tokio::time::timeout(FIRST_BYTES, cin.head()).await {
            Ok(Ok(Some(head))) => (head, cin.data().to_vec()),
            _ => {
                drop(cin);
                reset(client);
                return line.deny("no CONNECT request");
            }
        }
    };
    let target = std::str::from_utf8(&head)
        .ok()
        .and_then(|h| h.lines().next())
        .and_then(|l| match l.split(' ').collect::<Vec<_>>().as_slice() {
            ["CONNECT", authority, "HTTP/1.1" | "HTTP/1.0"] => authority.rsplit_once(':').map(|(h, p)| (h.to_owned(), p.to_owned())),
            _ => None,
        })
        .and_then(|(h, p)| Some((h.parse::<Host>().ok()?, p.parse::<u16>().ok()?)));
    let Some((host, port)) = target else {
        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n").await;
        return line.deny("not a CONNECT request");
    };
    line.host = host.to_string();
    line.port = port;
    if egress.policy.decide(&host, port) == Verdict::Denied {
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").await;
        return line.deny("not in policy");
    }
    if client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.is_err() {
        return line.error("sandbox closed");
    }
    if rest.is_empty() {
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout(FIRST_BYTES, client.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => rest.extend_from_slice(&chunk[..n]),
            _ => return line.deny("nothing sent through the tunnel"),
        }
    }
    if rest[0] == 22 {
        match tokio::time::timeout(FIRST_BYTES, read_hello(&mut client, &mut rest)).await {
            Ok(Ok(Asked { sni, alpn })) => {
                // The ClientHello must not name another host than the CONNECT did.
                if let Some(s) = sni
                    && s.parse::<Host>().ok().as_ref() != Some(&host)
                {
                    reset(client);
                    return line.deny(format!("ClientHello names {s}, not the CONNECT host"));
                }
                tls_to(shared, egress, client, (rest, alpn), host, port, line).await;
            }
            _ => {
                reset(client);
                line.deny("no ClientHello in the tunnel");
            }
        }
    } else if port == 443 {
        // Port 443 carries TLS; plain HTTP there would put a substituted credential on the
        // wire in the clear.
        reset(client);
        line.deny("plain HTTP through a CONNECT to port 443");
    } else {
        plain_to(shared, egress, client, rest, host, port, line).await;
    }
}

/// Why a relay stopped early.
enum Stop {
    Denied(String),
    Io(String),
}

impl From<std::io::Error> for Stop {
    fn from(e: std::io::Error) -> Self {
        Stop::Io(e.to_string())
    }
}

/// Where an inspected connection goes and what the policy said about it.
struct Route<'a> {
    dest: &'a Destination,
    verdict: Verdict<'a>,
    host: &'a Host,
    port: u16,
}

/// The adapter and credential to substitute on a route: only for a named destination,
/// with its own adapter and a credential released for exactly that destination and
/// adapter type.
fn substitution<'a>(egress: &'a SandboxEgress, route: &Route<'a>) -> Option<(&'a Adapter, &'a Credential)> {
    match (route.verdict, route.dest.adapter(), route.host) {
        (Verdict::Named(_), Some(a), Host::Name(h)) => egress
            .credentials
            .get(&a.credential)
            .filter(|c| &c.binding.destination == h && c.binding.adapter == a.kind.kind())
            .map(|c| (a, c)),
        _ => None,
    }
}

/// Relays requests and responses on an inspected connection: every request head is
/// checked and, for a destination with an adapter, rewritten; bodies and responses are
/// streamed. An upgrade must be the connection's first request, and the connection
/// becomes a byte tunnel only once the destination answers 101; a declined upgrade
/// ends the connection after its response, so no later request goes unchecked.
async fn relay<C, U>(egress: &SandboxEgress, route: &Route<'_>, client: C, upstream: U, already: &[u8], line: &mut Line)
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let Route { dest, host, port, .. } = *route;
    let (cr, cw) = tokio::io::split(client);
    let (ur, mut uw) = tokio::io::split(upstream);
    let mut cin = BufIn::new(cr, already);
    let host_text = host.to_string();
    let substitution = substitution(egress, route);
    let (mut requests, mut up, mut substituted) = (0u32, 0u64, false);
    // Tells the receiving side, once the first request is read, whether it asks to
    // upgrade, and if so where to say whether the destination switched protocols.
    let (first, first_rx) = tokio::sync::oneshot::channel::<Option<tokio::sync::oneshot::Sender<bool>>>();
    let (outcome, down) = {
    let sending = async {
        let mut first = Some(first);
        let mut switched = None;
        loop {
            let Some(head) = cin.head().await? else { break };
            let req = http::parse(&head).map_err(|e| Stop::Denied(e.to_string()))?;
            if !http::host_matches(req.host(), &host_text, port) {
                return Err(Stop::Denied(format!("Host {:?} is not {host_text}", req.host())));
            }
            if !dest.allows_path(req.path()) {
                return Err(Stop::Denied(format!("path {:?} is not allowed", req.path())));
            }
            // After an upgrade the connection is relayed as bytes, so later requests would
            // not be checked: refused where path rules apply.
            if req.upgrade && !dest.paths.is_empty() {
                return Err(Stop::Denied("an upgrade would bypass the destination's path rules".into()));
            }
            // Only the first response can be told apart without parsing responses.
            if req.upgrade && requests > 0 {
                return Err(Stop::Denied("an upgrade must be the connection's first request".into()));
            }
            if let Some(first) = first.take() {
                let answer = req.upgrade.then(|| {
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    switched = Some(rx);
                    tx
                });
                let _ = first.send(answer);
            }
            match substitution {
                Some((a, c)) => {
                    let rewritten = adapter::rewrite(&req, a, &c.secret);
                    uw.write_all(rewritten.head.as_slice()).await?;
                    up += rewritten.head.len() as u64;
                    substituted |= rewritten.substituted;
                }
                None => {
                    uw.write_all(&head).await?;
                    up += head.len() as u64;
                }
            }
            requests += 1;
            up += match req.framing {
                Framing::None => 0,
                Framing::Length(n) => cin.copy_exact(n, &mut uw).await?,
                Framing::Chunked => cin.copy_chunked(&mut uw).await?,
            };
            if req.upgrade {
                if let Some(rx) = switched.take()
                    && rx.await.unwrap_or(false)
                {
                    up += cin.copy_rest(&mut uw).await?;
                }
                break;
            }
        }
        let _ = uw.shutdown().await;
        Ok::<(), Stop>(())
    };
    let receiving = async move {
        match first_rx.await {
            Ok(Some(switched)) => http::pump_upgrade(ur, cw, switched).await,
            _ => http::pump(ur, cw).await,
        }
    };
    tokio::pin!(sending, receiving);
    let mut down = 0;
    let outcome = tokio::select! {
        r = &mut sending => match r {
            // The sandbox is done sending; let the last responses arrive.
            Ok(()) => match tokio::time::timeout(DRAIN, &mut receiving).await {
                Ok(Ok(n)) => { down = n; Ok(()) }
                Ok(Err(e)) => Err(Stop::Io(e.to_string())),
                Err(_) => Ok(()),
            },
            Err(e) => Err(e),
        },
        r = &mut receiving => {
            down = *r.as_ref().unwrap_or(&0);
            Ok(())
        }
    };
    (outcome, down)
    };
    line.requests = requests;
    line.up = up;
    line.down = down;
    if substituted && let Some((a, _)) = substitution {
        line.credential = Some(a.credential.to_string());
    }
    match outcome {
        Ok(()) => {}
        Err(Stop::Denied(why)) => {
            line.result = "denied";
            line.reason = Some(why);
        }
        Err(Stop::Io(why)) => line.reason = Some(why),
    }
}

/// One DNS question from a sandbox: the answer to send back and, for a refused name,
/// a log line.
pub(crate) async fn dns(shared: &Shared, egress: &SandboxEgress, query: &[u8]) -> (Option<Vec<u8>>, Option<Line>) {
    let Ok(q) = dns::parse_query(query) else { return (None, None) };
    let allowed = q
        .name
        .parse()
        .ok()
        .filter(|name| egress.policy.resolves(name));
    let Some(name) = allowed else {
        let mut line = Line::new("dns", None);
        line.host = q.name.to_ascii_lowercase();
        line.port = 53;
        line.deny("name not in policy");
        return (Some(dns::answer(query, &q, dns::NXDOMAIN, &[])), Some(line));
    };
    if q.qclass != dns::CLASS_IN {
        return (Some(dns::answer(query, &q, dns::REFUSED, &[])), None);
    }
    if q.qtype != dns::TYPE_A {
        // IPv4 only: other types for an allowed name have no data.
        return (Some(dns::answer(query, &q, dns::NOERROR, &[])), None);
    }
    match shared.dns.lookup(&name, &egress.policy.resolvers()).await {
        Ok(ips) => {
            let records: Vec<(Ipv4Addr, u32)> = ips.into_iter().filter(|ip| shared.guard.permits(*ip)).map(|ip| (ip, 30)).collect();
            if records.is_empty() {
                let mut line = Line::new("dns", None);
                line.host = name.to_string();
                line.port = 53;
                line.deny("no public address");
                return (Some(dns::answer(query, &q, dns::NXDOMAIN, &[])), Some(line));
            }
            (Some(dns::answer(query, &q, dns::NOERROR, &records)), None)
        }
        Err(ResolveError::NoSuchName) => (Some(dns::answer(query, &q, dns::NXDOMAIN, &[])), None),
        Err(_) => (Some(dns::answer(query, &q, dns::SERVFAIL, &[])), None),
    }
}
