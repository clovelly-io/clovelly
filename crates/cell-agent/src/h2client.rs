//! `cell-agent h2-client` (test image, run inside a sandbox): one HTTP/2 request over
//! TLS, for the phase 4 job's HTTP/2 substitution checks (a gRPC-style bidirectional
//! stream to the test destination, `GET /v1/models` to OpenAI).
//!
//! ```text
//! cell-agent h2-client --url https://HOST[:PORT]/PATH [--header 'name: value']...
//!                      [--bidi N] [--bytes B]
//! ```
//!
//! It trusts the CA file named by `SSL_CERT_FILE` (the sandbox's trust store, which
//! holds the in-cell CA), else `/etc/ssl/certs/ca-certificates.crt`; resolves the host
//! with the system resolver (the proxy's, in a sandbox); and requires the server to
//! negotiate ALPN `h2`. Without `--bidi` it sends a GET; with `--bidi N` a POST whose
//! body is N DATA frames of B bytes (default 1024), sent while the response is read.
//! It prints one JSON line:
//!
//! ```text
//! {"alpn":"h2","status":200,"headers":{...},"trailers":{...},"sent":N*B,"received":..,"ms":..}
//! ```
//!
//! Exit codes: 0 for a 2xx status, 2 for any other status (the line is still printed),
//! 1 if the exchange failed (TLS, ALPN, a reset stream).

use std::collections::BTreeMap;
use std::future::poll_fn;
use std::net::{SocketAddr, ToSocketAddrs};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, bail};
use bytes::Bytes;
use h2::SendStream;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, ServerName};
use serde_json::json;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// The trust store when `SSL_CERT_FILE` is not set.
const DEFAULT_ROOTS: &str = "/etc/ssl/certs/ca-certificates.crt";

/// What to send.
#[derive(Debug, PartialEq, Eq)]
pub struct Options {
    pub uri: ::http::Uri,
    pub headers: Vec<(::http::HeaderName, ::http::HeaderValue)>,
    pub body: Body,
    /// `--connect IP`: the address to dial, when the caller resolved the host itself
    /// (this binary is static, and glibc's resolver needs shared NSS modules).
    pub connect: Option<std::net::Ipv4Addr>,
}

/// The request body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Body {
    /// A GET with no body.
    None,
    /// A POST streaming `frames` DATA frames of `bytes` bytes while the response is read.
    Bidi { frames: u32, bytes: usize },
}

impl Options {
    pub fn parse(args: &[String]) -> anyhow::Result<Self> {
        let (mut url, mut headers, mut frames, mut bytes, mut connect) = (None, Vec::new(), None, 1024usize, None);
        let mut it = args.iter();
        while let Some(flag) = it.next() {
            let value = it.next().with_context(|| format!("{flag} needs a value"))?;
            match flag.as_str() {
                "--url" => url = Some(value),
                "--header" => {
                    let (name, v) = value.split_once(':').with_context(|| format!("--header {value:?} is not 'name: value'"))?;
                    headers.push((
                        ::http::HeaderName::from_bytes(name.trim().as_bytes()).with_context(|| format!("header name {name:?}"))?,
                        ::http::HeaderValue::from_str(v.trim()).with_context(|| format!("header value for {name}"))?,
                    ));
                }
                "--bidi" => frames = Some(value.parse().with_context(|| format!("--bidi {value:?}"))?),
                "--bytes" => bytes = value.parse().with_context(|| format!("--bytes {value:?}"))?,
                "--connect" => connect = Some(value.parse().with_context(|| format!("--connect {value:?}"))?),
                other => bail!("unknown flag {other:?}; expected --url, --header, --bidi, --bytes or --connect"),
            }
        }
        let uri: ::http::Uri = url.context("--url is required")?.parse().context("--url")?;
        if uri.scheme() != Some(&::http::uri::Scheme::HTTPS) || uri.host().is_none() {
            bail!("--url must be https://HOST[:PORT]/PATH");
        }
        let body = frames.map_or(Body::None, |frames| Body::Bidi { frames, bytes });
        Ok(Self { uri, headers, body, connect })
    }

    fn host(&self) -> &str {
        self.uri.host().expect("checked when parsed")
    }

    fn port(&self) -> u16 {
        self.uri.port_u16().unwrap_or(443)
    }
}

/// What came back.
#[derive(Debug)]
pub struct Outcome {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub trailers: BTreeMap<String, String>,
    pub sent: u64,
    pub received: u64,
}

/// `cell-agent h2-client ARGS`.
pub fn run(args: &[String]) -> anyhow::Result<ExitCode> {
    let opts = Options::parse(args)?;
    let path = std::env::var("SSL_CERT_FILE").unwrap_or_else(|_| DEFAULT_ROOTS.to_owned());
    let roots = roots(&std::fs::read_to_string(&path).with_context(|| path.clone())?).with_context(|| path.clone())?;
    let addr = match opts.connect {
        Some(ip) => SocketAddr::from((ip, opts.port())),
        None => (opts.host(), opts.port())
            .to_socket_addrs()
            .with_context(|| format!("resolving {}", opts.host()))?
            .find(SocketAddr::is_ipv4)
            .with_context(|| format!("{} has no IPv4 address", opts.host()))?,
    };
    let started = Instant::now();
    let outcome = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(exchange(&opts, roots, addr))?;
    println!(
        "{}",
        json!({ "alpn": "h2", "status": outcome.status, "headers": outcome.headers, "trailers": outcome.trailers,
                "sent": outcome.sent, "received": outcome.received, "ms": started.elapsed().as_millis() as u64 })
    );
    Ok(if (200..300).contains(&outcome.status) { ExitCode::SUCCESS } else { ExitCode::from(2) })
}

/// The certificates in a PEM bundle.
fn roots(pem: &str) -> anyhow::Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    let (added, _) = store.add_parsable_certificates(common::b64::pem_blocks(pem, "CERTIFICATE")?.into_iter().map(CertificateDer::from));
    if added == 0 {
        bail!("no certificates");
    }
    Ok(store)
}

/// Connects to `addr`, requires `h2`, and makes the request `opts` describes.
pub async fn exchange(opts: &Options, roots: RootCertStore, addr: SocketAddr) -> anyhow::Result<Outcome> {
    let mut tls = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let tcp = TcpStream::connect(addr).await.with_context(|| format!("connecting to {addr}"))?;
    let name = ServerName::try_from(opts.host().to_owned())?;
    let stream = TlsConnector::from(Arc::new(tls)).connect(name, tcp).await.context("TLS")?;
    let alpn = stream.get_ref().1.alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned());
    if alpn.as_deref() != Some("h2") {
        bail!("the server did not negotiate h2 (ALPN {alpn:?})");
    }
    let (sender, connection) = h2::client::handshake(stream).await.context("HTTP/2 handshake")?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut sender = sender.ready().await.context("HTTP/2 connection")?;
    let method = match opts.body {
        Body::None => ::http::Method::GET,
        Body::Bidi { .. } => ::http::Method::POST,
    };
    let mut req = ::http::Request::builder().method(method).uri(opts.uri.clone()).body(())?;
    for (name, value) in &opts.headers {
        req.headers_mut().append(name.clone(), value.clone());
    }
    let (response, mut body) = sender.send_request(req, opts.body == Body::None)?;
    let upload = async {
        let Body::Bidi { frames, bytes } = opts.body else { return Ok(0) };
        let frame = Bytes::from(vec![b'x'; bytes]);
        for _ in 0..frames {
            send(&mut body, frame.clone()).await?;
        }
        body.send_data(Bytes::new(), true)?;
        anyhow::Ok(u64::from(frames) * bytes as u64)
    };
    let download = async {
        let response = response.await.context("response")?;
        let status = response.status().as_u16();
        let headers = map(response.headers());
        let mut from = response.into_body();
        let mut received = 0u64;
        while let Some(chunk) = from.data().await {
            let chunk = chunk.context("response body")?;
            from.flow_control().release_capacity(chunk.len())?;
            received += chunk.len() as u64;
        }
        let trailers = from.trailers().await.context("trailers")?.as_ref().map(map).unwrap_or_default();
        anyhow::Ok((status, headers, trailers, received))
    };
    let (sent, (status, headers, trailers, received)) = tokio::try_join!(upload, download)?;
    Ok(Outcome { status, headers, trailers, sent, received })
}

/// Sends `chunk` as the stream's window allows.
async fn send(to: &mut SendStream<Bytes>, mut chunk: Bytes) -> anyhow::Result<()> {
    while !chunk.is_empty() {
        to.reserve_capacity(chunk.len());
        let mut capacity = to.capacity();
        while capacity == 0 {
            capacity = match poll_fn(|cx| to.poll_capacity(cx)).await {
                Some(n) => n?,
                None => bail!("the stream closed"),
            };
        }
        to.send_data(chunk.split_to(capacity.min(chunk.len())), false)?;
    }
    Ok(())
}

/// Headers as name to value, repeated names joined with ", ".
fn map(headers: &::http::HeaderMap) -> BTreeMap<String, String> {
    let mut out = BTreeMap::<String, String>::new();
    for (name, value) in headers {
        let value = String::from_utf8_lossy(value.as_bytes());
        out.entry(name.to_string())
            .and_modify(|v| {
                v.push_str(", ");
                v.push_str(&value);
            })
            .or_insert_with(|| value.into_owned());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|a| (*a).to_owned()).collect()
    }

    #[test]
    fn h2_client_options_parse() {
        let o = Options::parse(&args(&["--url", "https://api.openai.com/v1/models", "--header", "authorization: Bearer clovelly://cred/openai"])).unwrap();
        assert_eq!((o.host(), o.port(), o.body), ("api.openai.com", 443, Body::None));
        assert_eq!(o.headers[0].1, "Bearer clovelly://cred/openai");
        let o = Options::parse(&args(&["--url", "https://d.sslip.io:8443/clovelly.test.Echo/Stream", "--bidi", "5", "--bytes", "100"])).unwrap();
        assert_eq!((o.port(), o.body), (8443, Body::Bidi { frames: 5, bytes: 100 }));
        for bad in [&["--url", "http://h/"][..], &["--bidi", "2"], &["--url", "https://h/", "--header", "novalue"], &["--url"]] {
            assert!(Options::parse(&args(bad)).is_err(), "{bad:?}");
        }
    }
}
