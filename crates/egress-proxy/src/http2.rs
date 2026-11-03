//! HTTP/2 inspection (SPEC.md "Inspection covers HTTP/1.1 and HTTP/2"): a sandbox
//! connection that negotiated `h2` with a destination that did too is relayed with
//! `h2` on both sides, stream by stream.
//!
//! Each request stream must name the connection's host in `:authority` (and in `host`,
//! if it also sends one), pass the destination's path rules on `:path`, and is
//! rewritten by the destination's adapter ([`adapter::rewrite_h2`]); nothing else is
//! changed. Then the request's DATA frames and trailers go one way and the response's
//! headers, DATA frames and trailers the other, as they come: capacity is released to
//! the sender only once the other side has accepted the bytes, so flow control holds
//! end to end and no body is buffered beyond the streams' windows. A refused stream is
//! reset (`REFUSED_STREAM` for a policy refusal, `PROTOCOL_ERROR` for a malformed
//! request) and the connection's log line says why; a reset on one side is passed to
//! the other.
//!
//! The connection's log line counts the requests relayed and the DATA bytes each way,
//! and names the credential if any stream had it substituted.

use std::future::poll_fn;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use bytes::Bytes;
use common::bundle::{Adapter, Destination, Host};
use h2::client::SendRequest;
use h2::server::SendResponse;
use h2::{Reason, RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinSet;

use crate::conn::Line;
use crate::{Credential, SandboxEgress, adapter, http as http1};

/// The most concurrent streams the proxy accepts on one sandbox connection.
const MAX_STREAMS: u32 = 256;

/// One inspected HTTP/2 connection: what every stream is checked against, and the
/// connection's counts.
pub(crate) struct Conn {
    egress: Arc<SandboxEgress>,
    dest: Destination,
    host: String,
    port: u16,
    /// The adapter to apply: a named destination's, with a credential released for it.
    substitution: Option<Adapter>,
    requests: AtomicU32,
    up: AtomicU64,
    down: AtomicU64,
    substituted: AtomicBool,
    /// Why the first refused stream was refused.
    refused: Mutex<Option<String>>,
}

impl Conn {
    pub(crate) fn new(egress: Arc<SandboxEgress>, dest: Destination, host: &Host, port: u16, substitution: Option<Adapter>) -> Self {
        Self {
            egress,
            dest,
            host: host.to_string(),
            port,
            substitution,
            requests: AtomicU32::new(0),
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            substituted: AtomicBool::new(false),
            refused: Mutex::new(None),
        }
    }

    fn credential(&self) -> Option<(&Adapter, &Credential)> {
        let a = self.substitution.as_ref()?;
        Some((a, self.egress.credentials.get(&a.credential)?))
    }

    /// Checks a request's method, authority and path against the connection.
    fn check(&self, parts: &::http::request::Parts) -> Result<(), Refusal> {
        if parts.method == ::http::Method::CONNECT {
            return Err(Refusal::Malformed("a CONNECT stream would tunnel past inspection".into()));
        }
        let Some(authority) = parts.uri.authority() else {
            return Err(Refusal::Malformed("no :authority".into()));
        };
        if !http1::host_matches(authority.as_str(), &self.host, self.port) {
            return Err(Refusal::Policy(format!(":authority {:?} is not {}", authority.as_str(), self.host)));
        }
        for h in parts.headers.get_all(::http::header::HOST) {
            if !h.to_str().is_ok_and(|v| http1::host_matches(v, &self.host, self.port)) {
                return Err(Refusal::Policy(format!("host {h:?} is not {}", self.host)));
            }
        }
        let path = parts.uri.path();
        http1::check_path(path).map_err(|e| Refusal::Policy(e.to_string()))?;
        if !self.dest.allows_path(path) {
            return Err(Refusal::Policy(format!("path {path:?} is not allowed")));
        }
        Ok(())
    }

    fn refuse(&self, mut respond: SendResponse<Bytes>, why: Refusal) {
        let (reason, text) = match why {
            Refusal::Policy(t) => (Reason::REFUSED_STREAM, t),
            Refusal::Malformed(t) => (Reason::PROTOCOL_ERROR, t),
        };
        respond.send_reset(reason);
        self.refused.lock().unwrap_or_else(|p| p.into_inner()).get_or_insert(text);
    }
}

/// Why a stream was not relayed.
enum Refusal {
    /// The policy does not allow it.
    Policy(String),
    /// The request is not one the proxy relays.
    Malformed(String),
}

/// Relays an HTTP/2 connection from the sandbox (`client`) to the destination
/// (`upstream`) until the sandbox's side closes, then fills in `line`. If the relay is
/// dropped first (the sandbox ended), `line` still gets the counts so far.
pub(crate) async fn relay<C, U>(conn: Conn, client: C, upstream: U, line: &mut Line)
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut fill = Fill { line, conn: Arc::new(conn), outcome: Ok(()) };
    fill.outcome = serve(&fill.conn, client, upstream).await;
}

/// Writes a connection's counts and outcome into its log line when the relay ends,
/// however it ends.
struct Fill<'a> {
    line: &'a mut Line,
    conn: Arc<Conn>,
    outcome: Result<(), String>,
}

impl Drop for Fill<'_> {
    fn drop(&mut self) {
        let (line, conn) = (&mut *self.line, &self.conn);
        line.requests = conn.requests.load(Ordering::Relaxed);
        line.up = conn.up.load(Ordering::Relaxed);
        line.down = conn.down.load(Ordering::Relaxed);
        if conn.substituted.load(Ordering::Relaxed)
            && let Some(a) = &conn.substitution
        {
            line.credential = Some(a.credential.to_string());
        }
        if let Some(why) = conn.refused.lock().unwrap_or_else(|p| p.into_inner()).take() {
            line.deny(why);
        } else if let Err(why) = &self.outcome {
            line.reason = Some(why.clone());
        }
    }
}

/// Accepts the sandbox's streams and drives both connections; every stream task ends
/// with it.
async fn serve<C, U>(conn: &Arc<Conn>, client: C, upstream: U) -> Result<(), String>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut server = h2::server::Builder::new()
        .max_concurrent_streams(MAX_STREAMS)
        .handshake::<_, Bytes>(client)
        .await
        .map_err(|e| format!("sandbox HTTP/2: {e}"))?;
    let (sender, connection) = h2::client::handshake(upstream).await.map_err(|e| format!("destination HTTP/2: {e}"))?;
    let mut connection = std::pin::pin!(connection);
    let mut upstream_open = true;
    let mut upstream_error = None;
    let mut streams = JoinSet::new();
    let outcome = loop {
        tokio::select! {
            r = &mut connection, if upstream_open => {
                // The destination is gone: tell the sandbox to open no more streams.
                upstream_open = false;
                upstream_error = r.err().map(|e| format!("destination HTTP/2: {e}"));
                server.graceful_shutdown();
            }
            next = server.accept() => match next {
                Some(Ok((req, respond))) => {
                    streams.spawn(stream(Arc::clone(conn), sender.clone(), req, respond));
                }
                Some(Err(e)) => break Err(format!("sandbox HTTP/2: {e}")),
                None => break Ok(()),
            },
            Some(_) = streams.join_next(), if !streams.is_empty() => {}
        }
    };
    outcome.and(upstream_error.map_or(Ok(()), Err))
}

/// How one direction of a stream ended early.
enum Ended {
    /// The side it comes from reset the stream or failed; the reason to pass on.
    From(Reason),
    /// The side it goes to reset the stream.
    To(Reason),
}

fn reason(e: &h2::Error) -> Reason {
    e.reason().unwrap_or(Reason::CANCEL)
}

/// Why `to` stopped taking data, if it was reset; checked without waiting.
fn reset_reason(to: &mut SendStream<Bytes>) -> Reason {
    match to.poll_reset(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(Ok(r)) => r,
        _ => Reason::CANCEL,
    }
}

/// Sends `chunk` on `to` as its window allows.
async fn send(to: &mut SendStream<Bytes>, mut chunk: Bytes) -> Result<(), Ended> {
    while !chunk.is_empty() {
        to.reserve_capacity(chunk.len());
        let mut capacity = to.capacity();
        while capacity == 0 {
            capacity = match poll_fn(|cx| to.poll_capacity(cx)).await {
                Some(Ok(n)) => n,
                Some(Err(e)) => return Err(Ended::To(reason(&e))),
                None => return Err(Ended::To(reset_reason(to))),
            };
        }
        let piece = chunk.split_to(capacity.min(chunk.len()));
        to.send_data(piece, false).map_err(|e| Ended::To(reason(&e)))?;
    }
    Ok(())
}

/// Relays one direction of a stream: DATA as it arrives, then the trailers or the end
/// of the stream. `from`'s capacity is released only once `to` has taken the bytes.
/// A failure on `from` resets `to` at once; one on `to` is returned for the caller to
/// pass back.
async fn pipe(from: &mut RecvStream, to: &mut SendStream<Bytes>, count: &AtomicU64) -> Result<(), Ended> {
    let result = async {
        loop {
            let next = tokio::select! {
                d = from.data() => d,
                r = poll_fn(|cx| to.poll_reset(cx)) => return Err(Ended::To(r.map_or(Reason::CANCEL, |r| r))),
            };
            let Some(chunk) = next else { break };
            let chunk = chunk.map_err(|e| Ended::From(reason(&e)))?;
            let n = chunk.len();
            send(to, chunk).await?;
            from.flow_control().release_capacity(n).map_err(|e| Ended::From(reason(&e)))?;
            count.fetch_add(n as u64, Ordering::Relaxed);
        }
        match from.trailers().await {
            Ok(Some(trailers)) => to.send_trailers(trailers).map_err(|e| Ended::To(reason(&e))),
            Ok(None) => to.send_data(Bytes::new(), true).map_err(|e| Ended::To(reason(&e))),
            Err(e) => Err(Ended::From(reason(&e))),
        }
    }
    .await;
    if let Err(Ended::From(r)) = &result {
        to.send_reset(*r);
    }
    result
}

/// One request stream from the sandbox: checked, rewritten and relayed both ways.
async fn stream(conn: Arc<Conn>, sender: SendRequest<Bytes>, req: ::http::Request<RecvStream>, mut respond: SendResponse<Bytes>) {
    let (mut parts, mut from_sandbox) = req.into_parts();
    if let Err(why) = conn.check(&parts) {
        return conn.refuse(respond, why);
    }
    if let Some((a, c)) = conn.credential() {
        match adapter::rewrite_h2(&mut parts, a, &c.secret) {
            Ok(true) => conn.substituted.store(true, Ordering::Relaxed),
            Ok(false) => {}
            Err(e) => return conn.refuse(respond, Refusal::Malformed(e.to_string())),
        }
    }
    let end = from_sandbox.is_end_stream();
    let Ok(mut sender) = sender.ready().await else {
        return respond.send_reset(Reason::REFUSED_STREAM);
    };
    let (response, mut to_dest) = match sender.send_request(::http::Request::from_parts(parts, ()), end) {
        Ok(r) => r,
        Err(e) => return respond.send_reset(e.reason().unwrap_or(Reason::REFUSED_STREAM)),
    };
    conn.requests.fetch_add(1, Ordering::Relaxed);
    let upload = async {
        if end { Ok(()) } else { pipe(&mut from_sandbox, &mut to_dest, &conn.up).await }
    };
    let download = async {
        let resp = match response.await {
            Ok(r) => r,
            Err(e) => {
                respond.send_reset(reason(&e));
                return Err(Ended::From(reason(&e)));
            }
        };
        let (head, mut from_dest) = resp.into_parts();
        let end = from_dest.is_end_stream();
        let mut to_sandbox = match respond.send_response(::http::Response::from_parts(head, ()), end) {
            Ok(s) => s,
            Err(e) => return Err(Ended::To(reason(&e))),
        };
        if end { Ok(()) } else { pipe(&mut from_dest, &mut to_sandbox, &conn.down).await }
    };
    let (up, down) = tokio::join!(upload, download);
    // A side that stopped taking data is passed on to the other side, if the direction
    // that would have told it had already finished.
    if let Err(Ended::To(r)) = down {
        to_dest.send_reset(r);
    }
    if let Err(Ended::To(r)) = up {
        respond.send_reset(r);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use super::*;
    use crate::testing;
    use common::cred::{AdapterType, Binding, CredName, Secret};
    use common::ids::SandboxId;

    fn credential(name: &str, dest: &str, secret: &str) -> (CredName, Credential) {
        let name: CredName = name.parse().unwrap();
        let binding = Binding { name: name.clone(), adapter: AdapterType::Bearer, destination: dest.parse().unwrap() };
        (name, Credential { binding, secret: Secret::copy_from(secret.as_bytes()).unwrap() })
    }

    fn request(target: &str, path: &str, auth: &str, end: bool) -> (::http::Request<()>, bool) {
        let req = ::http::Request::builder()
            .method("POST")
            .uri(format!("https://{target}{path}"))
            .header("authorization", auth)
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(())
            .unwrap();
        (req, end)
    }

    /// Criterion 14, in process: a bidirectional stream to an HTTP/2 destination keeps
    /// every DATA frame both ways and the trailers, `authorization` arrives as the real
    /// secret, a stream naming another `:authority` is reset before it reaches the
    /// destination, and a wildcard destination gets the placeholder unchanged.
    #[tokio::test]
    async fn http2_streams_are_relayed_with_substituted_headers() {
        let ca = testing::TestCa::new();
        let (proxy, connect) = testing::proxy_trusting(&["grpc.test"], &ca.pem()).await;
        let (port, seen) = testing::h2_destination(&ca, "grpc.test").await;
        let policy = testing::policy(&format!(
            r#"[{{"host":"grpc.test","port":{port},"adapter":{{"type":"bearer","credential":"svc"}}}}]"#
        ));
        proxy.register(Ipv4Addr::LOCALHOST, SandboxEgress::new(SandboxId::generate(), policy, HashMap::from([credential("svc", "grpc.test", "REAL-SECRET")])));
        let target = format!("grpc.test:{port}");
        let mut client = testing::h2_through(connect, &target, &proxy.ca_pem()).await.unwrap();

        let (req, end) = request(&target, testing::ECHO, "Bearer clovelly://cred/svc", false);
        client = client.ready().await.unwrap();
        let (response, mut body) = client.send_request(req, end).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), 200);
        let mut echoes = response.into_body();
        for frame in ["one", "two", "three"] {
            body.send_data(Bytes::from(frame), false).unwrap();
            let echoed = echoes.data().await.unwrap().unwrap();
            echoes.flow_control().release_capacity(echoed.len()).unwrap();
            assert_eq!(echoed, frame, "each frame comes back before the next is sent");
        }
        body.send_data(Bytes::new(), true).unwrap();
        assert!(echoes.data().await.is_none());
        let trailers = echoes.trailers().await.unwrap().unwrap();
        assert_eq!(trailers["grpc-status"], "0");
        assert_eq!(trailers["clovelly-echoed"], "11");
        let first = seen.lock().unwrap()[0].clone();
        assert!(first.contains(&("authorization".into(), "Bearer REAL-SECRET".into())), "{first:?}");

        let (req, end) = request("other.test", "/x", "Bearer clovelly://cred/svc", true);
        client = client.ready().await.unwrap();
        let (refused, _) = client.send_request(req, end).unwrap();
        let e = refused.await.unwrap_err();
        assert_eq!(e.reason(), Some(Reason::REFUSED_STREAM), "{e}");
        assert_eq!(seen.lock().unwrap().len(), 1, "the misdirected stream never arrived");

        drop(client);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let log = proxy.unregister(Ipv4Addr::LOCALHOST).await.unwrap();
        let line: serde_json::Value = serde_json::from_str(&log.lines[0]).unwrap();
        assert_eq!((&line["credential"], &line["requests"], &line["up"], &line["down"]), (&"svc".into(), &1.into(), &11.into(), &11.into()), "{line}");
        assert!(line["reason"].as_str().unwrap().contains("other.test"), "{line}");
        assert!(!log.lines[0].contains("REAL-SECRET"));

        // A wildcard destination: the placeholder arrives as it was sent.
        let policy = testing::policy(&format!(r#"[{{"host":"*","port":{port}}}]"#));
        proxy.register(Ipv4Addr::LOCALHOST, SandboxEgress::new(SandboxId::generate(), policy, HashMap::from([credential("svc", "grpc.test", "REAL-SECRET")])));
        let client = testing::h2_through(connect, &target, &proxy.ca_pem()).await.unwrap();
        let (req, end) = request(&target, "/v1/models", "Bearer clovelly://cred/svc", true);
        let mut client = client.ready().await.unwrap();
        let (response, _) = client.send_request(req, end).unwrap();
        assert_eq!(response.await.unwrap().status(), 200);
        let last = seen.lock().unwrap().last().cloned().unwrap();
        assert!(last.contains(&("authorization".into(), "Bearer clovelly://cred/svc".into())), "{last:?}");
        drop(client);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let log = proxy.unregister(Ipv4Addr::LOCALHOST).await.unwrap();
        assert!(log.lines[0].contains(r#""result":"wildcard""#) && !log.lines[0].contains("credential"), "{:?}", log.lines);
    }

    /// A sandbox that offers only HTTP/1.1 keeps the HTTP/1.1 path, even to a
    /// destination that speaks HTTP/2.
    #[tokio::test]
    async fn an_http1_offer_stays_http1() {
        let ca = testing::TestCa::new();
        let (proxy, connect) = testing::proxy_trusting(&["grpc.test"], &ca.pem()).await;
        let (port, _) = testing::h2_destination(&ca, "grpc.test").await;
        let policy = testing::policy(&format!(r#"[{{"host":"grpc.test","port":{port}}}]"#));
        proxy.register(Ipv4Addr::LOCALHOST, SandboxEgress::new(SandboxId::generate(), policy, HashMap::new()));
        let tls = testing::tls_through(connect, &format!("grpc.test:{port}"), &proxy.ca_pem(), &[b"http/1.1"]).await.unwrap();
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
    }
}
