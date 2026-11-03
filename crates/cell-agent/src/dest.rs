//! `cell-agent dest` (test image, role `dest`): the header-logging test destination we
//! control (phase 3), reached through its own forwarding rule so cells' requests arrive
//! from Cloud NAT. It serves HTTP on :80 and the same over TLS on :443 with a
//! self-signed certificate for `dest.clovelly.test`, `*.sslip.io` and `*.nip.io` (the
//! pinning client's destination, and on test cells one the proxy trusts). On :443 it
//! speaks HTTP/2 to clients that offer `h2` (phase 4).
//!
//! Every request is logged to stdout (serial) as `CLOVELLY-DEST {json}`: the scheme
//! (`http`, `https`, or `h2` for HTTP/2 over TLS), the peer address, method, target,
//! Host (`:authority` on HTTP/2), the credential-bearing headers (`Authorization`,
//! `X-Api-Key`) verbatim, since only test credentials are sent here, and the request's
//! `X-Clovelly-Tag`, by which a test finds its own request. Bodies are counted, never
//! logged, and responses never repeat a header value; they say only whether the request
//! carried a placeholder (`x-clovelly-received: placeholder`), something else (`other`) or
//! nothing (`none`).
//!
//! On HTTP/2, [`ECHO`] is a gRPC-style bidirectional echo: each request DATA frame comes
//! back as a response DATA frame, then trailers `grpc-status: 0` and `clovelly-echoed:
//! <bytes>`; any other request is answered 200 with the summary, once its body has
//! ended (when it is logged, with its size).
//!
//! HTTP/1.1 paths: `/sink` reads the body and answers its size (the throughput benchmark);
//! `/hold` answers and keeps the connection open; `/count` answers how many connections
//! are open now (the concurrent-connection check); `/netstat` answers this VM's
//! receive-side TCP counters ([`bench::TCPEXT`], so the benchmark can tell spurious
//! retransmissions from lost segments); anything else answers the `x-clovelly-received`
//! summary.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;
use bytes::Bytes;
use h2::RecvStream;
use h2::server::SendResponse;
use rcgen::{CertificateParams, KeyPair};
use rustls::ServerConfig;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use aws_lc_rs::digest;

use crate::bench;

static OPEN: AtomicU64 = AtomicU64::new(0);

/// The names in the TLS certificate: the job reaches the destination as
/// `<ip-dashed>.sslip.io` (or `.nip.io`); the pinning client pins the certificate.
const NAMES: [&str; 3] = ["dest.clovelly.test", "*.sslip.io", "*.nip.io"];

/// The HTTP/2 bidirectional echo.
pub const ECHO: &str = "/clovelly.test.Echo/Stream";

pub async fn run() -> anyhow::Result<()> {
    tokio::spawn(crate::forwarded::keep_routes(Default::default(), Default::default()));
    let (cert, acceptor) = certificate()?;
    let fingerprint = common::hex(digest::digest(&digest::SHA256, &cert).as_ref());
    println!(
        "CLOVELLY-DEST-CERT {}",
        json!({ "sha256": fingerprint, "pem": common::b64::pem("CERTIFICATE", &cert) })
    );
    let plain = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 80)).await.context(":80")?;
    let secure = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 443)).await.context(":443")?;
    println!("CLOVELLY-DEST-READY");
    tokio::try_join!(accept_tls(secure, acceptor), accept_plain(plain))?;
    Ok(())
}

/// A fresh self-signed end-entity certificate for [`NAMES`] (DER), and a TLS acceptor
/// presenting it that negotiates HTTP/2 or HTTP/1.1.
fn certificate() -> anyhow::Result<(Vec<u8>, TlsAcceptor)> {
    let key = KeyPair::generate()?;
    let cert = CertificateParams::new(NAMES.map(str::to_owned).to_vec())?.self_signed(&key)?;
    let mut tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())))?;
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok((cert.der().to_vec(), TlsAcceptor::from(Arc::new(tls))))
}

async fn accept_tls(listener: TcpListener, acceptor: TlsAcceptor) -> anyhow::Result<()> {
    loop {
        let (s, peer) = listener.accept().await.context("accept :443")?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let Ok(s) = acceptor.accept(s).await else { return };
            if s.get_ref().1.alpn_protocol() == Some(b"h2") {
                serve_h2(s, peer).await;
            } else {
                serve(s, peer, "https").await;
            }
        });
    }
}

async fn accept_plain(listener: TcpListener) -> anyhow::Result<()> {
    loop {
        let (s, peer) = listener.accept().await.context("accept :80")?;
        let _ = s.set_nodelay(true);
        tokio::spawn(serve(s, peer, "http"));
    }
}

/// Connections open now, counted for `/count`.
struct Open;

impl Open {
    fn new() -> Self {
        OPEN.fetch_add(1, Ordering::Relaxed);
        Self
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        OPEN.fetch_sub(1, Ordering::Relaxed);
    }
}

/// What a request carried: a placeholder (in a credential header or the target),
/// another credential, or none.
fn received(auth: Option<&str>, api_key: Option<&str>, target: &str) -> &'static str {
    if [auth, api_key, Some(target)].iter().flatten().any(|v| v.contains("clovelly://cred/") || v.contains("clovelly%3A%2F%2Fcred")) {
        "placeholder"
    } else if auth.is_some() || api_key.is_some() {
        "other"
    } else {
        "none"
    }
}

/// One request, as logged.
struct Logged<'a> {
    scheme: &'a str,
    peer: SocketAddr,
    method: &'a str,
    target: &'a str,
    host: Option<String>,
    authorization: Option<&'a str>,
    x_api_key: Option<&'a str>,
    tag: Option<&'a str>,
    body_bytes: u64,
}

impl Logged<'_> {
    fn print(&self) {
        println!(
            "CLOVELLY-DEST {}",
            json!({ "scheme": self.scheme, "peer": self.peer.ip().to_string(), "method": self.method, "target": self.target,
                    "host": self.host, "authorization": self.authorization, "x_api_key": self.x_api_key, "tag": self.tag,
                    "received": received(self.authorization, self.x_api_key, self.target), "body_bytes": self.body_bytes })
        );
    }
}

/// Serves one HTTP/2 connection's streams until it closes.
async fn serve_h2<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(s: S, peer: SocketAddr) {
    let _open = Open::new();
    let Ok(mut conn) = h2::server::handshake(s).await else { return };
    while let Some(Ok((req, respond))) = conn.accept().await {
        tokio::spawn(answer_h2(req, respond, peer));
    }
}

/// One HTTP/2 request: logged once its body has ended; [`ECHO`] echoes it frame by
/// frame and ends with trailers, anything else gets the summary.
async fn answer_h2(req: ::http::Request<RecvStream>, mut respond: SendResponse<Bytes>, peer: SocketAddr) {
    let (head, mut body) = req.into_parts();
    let header = |name: &str| head.headers.get(name).and_then(|v| v.to_str().ok());
    let target = head.uri.path_and_query().map_or("/", |p| p.as_str());
    let echo = head.uri.path() == ECHO;
    let (auth, api_key) = (header("authorization"), header("x-api-key"));
    let summary = received(auth, api_key, target);
    let Ok(response) = ::http::Response::builder()
        .status(200)
        .header("content-type", if echo { "application/grpc" } else { "application/json" })
        .header("x-clovelly-received", summary)
        .body(())
    else {
        return;
    };
    let Ok(mut send) = respond.send_response(response, false) else { return };
    let mut bytes = 0u64;
    while let Some(chunk) = body.data().await {
        let Ok(chunk) = chunk else { return };
        let _ = body.flow_control().release_capacity(chunk.len());
        bytes += chunk.len() as u64;
        if echo && send.send_data(chunk, false).is_err() {
            return;
        }
    }
    Logged {
        scheme: "h2",
        peer,
        method: head.method.as_str(),
        target,
        host: head.uri.authority().map(|a| a.to_string()).or_else(|| header("host").map(str::to_owned)),
        authorization: auth,
        x_api_key: api_key,
        tag: header("x-clovelly-tag"),
        body_bytes: bytes,
    }
    .print();
    if echo {
        let mut trailers = ::http::HeaderMap::new();
        trailers.insert("grpc-status", ::http::HeaderValue::from_static("0"));
        trailers.insert("clovelly-echoed", bytes.into());
        let _ = send.send_trailers(trailers);
    } else {
        let _ = send.send_data(Bytes::from(json!({ "received": summary }).to_string()), true);
    }
}

/// Serves one connection's requests until it closes.
async fn serve<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, peer: SocketAddr, scheme: &str) {
    let _open = Open::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut have = 0;
    loop {
        // Read a head.
        let end = loop {
            if let Some(i) = buf[..have].windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            if have == buf.len() {
                return;
            }
            match s.read(&mut buf[have..]).await {
                Ok(0) | Err(_) => return,
                Ok(n) => have += n,
            }
        };
        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap_or_default().to_owned();
        let mut parts = request_line.split(' ');
        let (method, target) = (parts.next().unwrap_or_default().to_owned(), parts.next().unwrap_or_default().to_owned());
        let header = |name: &str| {
            head.split("\r\n")
                .skip(1)
                .filter_map(|l| l.split_once(':'))
                .find(|(n, _)| n.trim().eq_ignore_ascii_case(name))
                .map(|(_, v)| v.trim().to_owned())
        };
        let length: u64 = header("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
        let close = request_line.ends_with("HTTP/1.0")
            || header("connection").is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")));
        let (auth, api_key) = (header("authorization"), header("x-api-key"));
        let received = received(auth.as_deref(), api_key.as_deref(), &target);
        // Drain the body: what is buffered, then the rest.
        buf.copy_within(end..have, 0);
        have -= end;
        let mut left = length;
        let from_buffer = (have as u64).min(left);
        buf.copy_within(from_buffer as usize..have, 0);
        have -= from_buffer as usize;
        left -= from_buffer;
        let started = std::time::Instant::now();
        while left > 0 {
            match s.read(&mut buf[..]).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    let used = (n as u64).min(left);
                    left -= used;
                    if (used as usize) < n {
                        buf.copy_within(used as usize..n, 0);
                        have = n - used as usize;
                    }
                }
            }
        }
        let path = target.split('?').next().unwrap_or_default();
        if !["/sink", "/hold", "/count", "/netstat"].contains(&path) {
            let tag = header("x-clovelly-tag");
            Logged {
                scheme,
                peer,
                method: &method,
                target: &target,
                host: header("host"),
                authorization: auth.as_deref(),
                x_api_key: api_key.as_deref(),
                tag: tag.as_deref(),
                body_bytes: length,
            }
            .print();
        }
        let body = match path {
            "/sink" => json!({ "bytes": length, "ms": started.elapsed().as_millis() as u64 }).to_string(),
            "/count" => json!({ "open": OPEN.load(Ordering::Relaxed) }).to_string(),
            "/netstat" => json!(bench::tcpext()).to_string(),
            "/hold" => "held".to_owned(),
            _ => json!({ "received": received }).to_string(),
        };
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nx-clovelly-received: {received}\r\nContent-Length: {}\r\n{}\r\n{body}",
            body.len(),
            if close { "Connection: close\r\n" } else { "" }
        );
        if s.write_all(resp.as_bytes()).await.is_err() || close {
            let _ = s.shutdown().await;
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h2client::{self, Options};

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|a| (*a).to_owned()).collect()
    }

    /// Criterion 14's destination: to a client that offers `h2` it speaks HTTP/2, the
    /// bidirectional echo returns every frame and ends with its trailers, and the
    /// certificate verifies, as a trusted root, for the names the job uses.
    #[tokio::test]
    async fn h2_echo_returns_every_frame_and_the_trailers() {
        let (cert, acceptor) = certificate().unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(accept_tls(listener, acceptor));
        let roots = || {
            let mut r = rustls::RootCertStore::empty();
            r.add(rustls::pki_types::CertificateDer::from(cert.clone())).unwrap();
            r
        };
        let url = format!("https://10-0-0-1.sslip.io:{}{ECHO}", addr.port());
        let echo = Options::parse(&args(&[
            "--url", &url, "--header", "authorization: Bearer clovelly://cred/svc", "--header", "x-clovelly-tag: t1", "--bidi", "4", "--bytes", "3000",
        ]))
        .unwrap();
        let out = h2client::exchange(&echo, roots(), addr).await.unwrap();
        assert_eq!((out.status, out.sent, out.received), (200, 12_000, 12_000));
        assert_eq!((out.trailers["grpc-status"].as_str(), out.trailers["clovelly-echoed"].as_str()), ("0", "12000"));
        assert_eq!(out.headers["x-clovelly-received"], "placeholder");

        let url = format!("https://dest.clovelly.test:{}/v1/models", addr.port());
        let get = Options::parse(&args(&["--url", &url])).unwrap();
        let out = h2client::exchange(&get, roots(), addr).await.unwrap();
        assert_eq!((out.status, out.headers["x-clovelly-received"].as_str()), (200, "none"));
        assert!(out.received > 0 && out.trailers.is_empty());
    }
}
