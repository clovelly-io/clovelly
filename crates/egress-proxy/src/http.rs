//! HTTP/1.1 requests as the proxy relays them (RFC 9112): request heads are parsed and
//! checked one by one so each can be matched to the destination and rewritten; bodies
//! are streamed through with their framing (Content-Length or chunked), never stored.
//!
//! The parser refuses what could make the proxy and the destination disagree about where
//! a request ends or where it goes: both Transfer-Encoding and Content-Length, unequal
//! Content-Lengths, obsolete line folding, bare LF, a missing or repeated Host, an
//! absolute-form target, and paths that are not normalised (`..`, `.`, encoded `.` or
//! `/`, backslashes).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The largest request head the proxy reads.
pub const MAX_HEAD: usize = 64 * 1024;
/// The read buffer for bodies.
pub const BUF: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpError {
    #[error("request head over 64 KiB")]
    HeadTooLarge,
    #[error("malformed request: {0}")]
    Malformed(&'static str),
    #[error("request target {0:?} is not origin-form")]
    Target(String),
    #[error("path {0:?} is not normalised")]
    Path(String),
    #[error("the request has no single Host header")]
    Host,
    #[error("chunked body is malformed")]
    Chunk,
}

/// How a request's body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    None,
    Length(u64),
    Chunked,
}

/// One header, borrowed from the head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header<'a> {
    pub name: &'a str,
    pub value: &'a [u8],
}

/// A parsed request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
    pub method: &'a str,
    pub target: &'a str,
    pub version: &'a str,
    pub headers: Vec<Header<'a>>,
    pub framing: Framing,
    /// `Connection: upgrade` with an `Upgrade` header: after this request the
    /// connection carries another protocol and is relayed as bytes.
    pub upgrade: bool,
}

/// The index just past the head's terminating blank line, if `buf` holds it.
pub fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Parses a head (through its blank line).
pub fn parse(head: &[u8]) -> Result<Request<'_>, HttpError> {
    let text = head.strip_suffix(b"\r\n\r\n").ok_or(HttpError::Malformed("no blank line"))?;
    if text.contains(&b'\n') && text.windows(2).filter(|w| w == b"\r\n").count() != text.iter().filter(|b| **b == b'\n').count() {
        return Err(HttpError::Malformed("bare LF"));
    }
    let mut lines = text.split(|b| *b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let line = std::str::from_utf8(lines.next().unwrap_or_default()).map_err(|_| HttpError::Malformed("request line"))?;
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(HttpError::Malformed("request line"));
    };
    if !token(method) || method == "CONNECT" || !matches!(version, "HTTP/1.1" | "HTTP/1.0") {
        return Err(HttpError::Malformed("method or version"));
    }
    if !(target.starts_with('/') || (target == "*" && method == "OPTIONS")) {
        return Err(HttpError::Target(target.to_owned()));
    }
    if target.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(HttpError::Target(target.to_owned()));
    }
    let mut headers = Vec::new();
    for l in lines {
        if l.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
            return Err(HttpError::Malformed("obsolete line folding"));
        }
        let colon = l.iter().position(|b| *b == b':').ok_or(HttpError::Malformed("header without a colon"))?;
        let name = std::str::from_utf8(&l[..colon]).map_err(|_| HttpError::Malformed("header name"))?;
        if !token(name) {
            return Err(HttpError::Malformed("header name"));
        }
        let value = l[colon + 1..].trim_ascii();
        if value.iter().any(|b| *b == 0 || *b == b'\r') {
            return Err(HttpError::Malformed("header value"));
        }
        headers.push(Header { name, value });
    }
    fn named<'h, 'a>(headers: &'h [Header<'a>], n: &'static str) -> impl Iterator<Item = &'h Header<'a>> {
        headers.iter().filter(move |h| h.name.eq_ignore_ascii_case(n))
    }
    let all = |n: &'static str| named(&headers, n);
    let te: Vec<&[u8]> = all("transfer-encoding").map(|h| h.value).collect();
    let cl: Vec<&[u8]> = all("content-length").map(|h| h.value).collect();
    let framing = match (te.is_empty(), cl.as_slice()) {
        (false, []) => {
            let last = te.last().and_then(|v| v.rsplit(|b| *b == b',').next()).map(<[u8]>::trim_ascii);
            if !last.is_some_and(|c| c.eq_ignore_ascii_case(b"chunked")) {
                return Err(HttpError::Malformed("transfer-encoding without chunked last"));
            }
            Framing::Chunked
        }
        (false, _) => return Err(HttpError::Malformed("both transfer-encoding and content-length")),
        (true, []) => Framing::None,
        (true, [first, rest @ ..]) => {
            if rest.iter().any(|v| v != first) {
                return Err(HttpError::Malformed("conflicting content-length"));
            }
            let n = std::str::from_utf8(first)
                .ok()
                .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|s| s.parse().ok())
                .ok_or(HttpError::Malformed("content-length"))?;
            if n == 0 { Framing::None } else { Framing::Length(n) }
        }
    };
    let upgrade = all("connection").any(|h| h.value.split(|b| *b == b',').any(|t| t.trim_ascii().eq_ignore_ascii_case(b"upgrade")))
        && all("upgrade").next().is_some();
    let req = Request {
        method,
        target,
        version,
        headers,
        framing,
        upgrade,
    };
    if all_hosts(&req).count() != 1 {
        return Err(HttpError::Host);
    }
    check_path(req.path())?;
    Ok(req)
}

fn all_hosts<'r, 'a>(r: &'r Request<'a>) -> impl Iterator<Item = &'r Header<'a>> {
    r.headers.iter().filter(|h| h.name.eq_ignore_ascii_case("host"))
}

impl Request<'_> {
    /// The Host header's value.
    pub fn host(&self) -> &str {
        all_hosts(self)
            .next()
            .and_then(|h| std::str::from_utf8(h.value).ok())
            .unwrap_or_default()
    }

    /// The target's path (before any `?`).
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or_default()
    }
}

/// Whether a Host header value names `host` (and `port`, if it carries one).
pub fn host_matches(value: &str, host: &str, port: u16) -> bool {
    let (name, p) = match value.rsplit_once(':') {
        Some((n, p)) if !n.contains(':') => (n, Some(p)),
        _ => (value, None),
    };
    let name = name.strip_suffix('.').unwrap_or(name);
    name.eq_ignore_ascii_case(host) && p.is_none_or(|p| p.parse() == Ok(port))
}

/// Refuses a path that is not normalised (`..`, `.`, encoded `.` or `/`, backslashes).
pub fn check_path(path: &str) -> Result<(), HttpError> {
    let lower = path.to_ascii_lowercase();
    let bad = path.contains('\\')
        || lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || path.split('/').any(|seg| seg == "." || seg == "..");
    if bad { Err(HttpError::Path(path.to_owned())) } else { Ok(()) }
}

/// A read half with a buffer, for reading heads, chunk lines and bodies.
pub struct BufIn<R> {
    r: R,
    buf: Vec<u8>,
    start: usize,
    end: usize,
}

impl<R: AsyncRead + Unpin> BufIn<R> {
    /// Reads from `r`, starting with `already` (bytes read before, such as a
    /// ClientHello's or a CONNECT's leftovers).
    pub fn new(r: R, already: &[u8]) -> Self {
        let mut buf = vec![0u8; BUF.max(already.len())];
        buf[..already.len()].copy_from_slice(already);
        Self {
            r,
            buf,
            start: 0,
            end: already.len(),
        }
    }

    pub fn data(&self) -> &[u8] {
        &self.buf[self.start..self.end]
    }

    pub fn consume(&mut self, n: usize) {
        self.start += n;
    }

    /// Reads more; `Ok(0)` at end of stream.
    pub async fn fill(&mut self) -> std::io::Result<usize> {
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        } else if self.end == self.buf.len() {
            self.buf.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        if self.end == self.buf.len() {
            self.buf.resize((self.buf.len() * 2).min(MAX_HEAD + BUF), 0);
            if self.end == self.buf.len() {
                return Err(std::io::Error::other(HttpError::HeadTooLarge));
            }
        }
        let n = self.r.read(&mut self.buf[self.end..]).await?;
        self.end += n;
        Ok(n)
    }

    /// The next request head (owned), or `None` at a clean end of stream.
    pub async fn head(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(end) = head_end(self.data()) {
                let head = self.data()[..end].to_vec();
                self.consume(end);
                return Ok(Some(head));
            }
            if self.data().len() > MAX_HEAD {
                return Err(std::io::Error::other(HttpError::HeadTooLarge));
            }
            if self.fill().await? == 0 {
                return if self.data().is_empty() {
                    Ok(None)
                } else {
                    Err(std::io::ErrorKind::UnexpectedEof.into())
                };
            }
        }
    }

    /// Copies exactly `n` bytes to `w`.
    pub async fn copy_exact<W: AsyncWrite + Unpin>(&mut self, mut n: u64, w: &mut W) -> std::io::Result<u64> {
        let total = n;
        while n > 0 {
            if self.data().is_empty() && self.fill().await? == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            let take = self.data().len().min(usize::try_from(n).unwrap_or(usize::MAX));
            w.write_all(&self.data()[..take]).await?;
            self.consume(take);
            n -= take as u64;
        }
        Ok(total)
    }

    /// One CRLF-terminated line (with its CRLF), at most 4 KiB.
    async fn line(&mut self) -> std::io::Result<Vec<u8>> {
        loop {
            if let Some(i) = self.data().windows(2).position(|w| w == b"\r\n") {
                let line = self.data()[..i + 2].to_vec();
                self.consume(i + 2);
                return Ok(line);
            }
            if self.data().len() > 4096 {
                return Err(std::io::Error::other(HttpError::Chunk));
            }
            if self.fill().await? == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
        }
    }

    /// Copies a chunked body (chunks, the last chunk and trailers) to `w` as it is.
    pub async fn copy_chunked<W: AsyncWrite + Unpin>(&mut self, w: &mut W) -> std::io::Result<u64> {
        let mut total = 0;
        loop {
            let line = self.line().await?;
            let size_text = line[..line.len() - 2].split(|b| *b == b';').next().unwrap_or_default().trim_ascii();
            let size = std::str::from_utf8(size_text)
                .ok()
                // from_str_radix would also take a leading `+`, which a destination refuses.
                .filter(|s| !s.is_empty() && s.len() <= 16 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                .and_then(|s| u64::from_str_radix(s, 16).ok())
                .ok_or_else(|| std::io::Error::other(HttpError::Chunk))?;
            w.write_all(&line).await?;
            total += line.len() as u64;
            if size == 0 {
                // Trailers, then the blank line.
                loop {
                    let t = self.line().await?;
                    w.write_all(&t).await?;
                    total += t.len() as u64;
                    if t == b"\r\n" {
                        return Ok(total);
                    }
                }
            }
            total += self.copy_exact(size, w).await?;
            let crlf = self.line().await?;
            if crlf != b"\r\n" {
                return Err(std::io::Error::other(HttpError::Chunk));
            }
            w.write_all(&crlf).await?;
            total += 2;
        }
    }

    /// Copies whatever is buffered and then the rest of the stream to `w`.
    pub async fn copy_rest<W: AsyncWrite + Unpin>(&mut self, w: &mut W) -> std::io::Result<u64> {
        let mut total = 0;
        loop {
            if !self.data().is_empty() {
                w.write_all(self.data()).await?;
                total += self.data().len() as u64;
                let n = self.data().len();
                self.consume(n);
            }
            if self.fill().await? == 0 {
                return Ok(total);
            }
        }
    }
}

/// The status that settles an upgrade request, from the start of the response stream:
/// the first head that is not an interim 1xx response (101 is final). `None` until
/// that head is complete.
pub fn upgrade_answer(prefix: &[u8]) -> Result<Option<u16>, HttpError> {
    let mut rest = prefix;
    loop {
        let Some(end) = rest.windows(4).position(|w| w == b"\r\n\r\n") else {
            return if prefix.len() > MAX_HEAD { Err(HttpError::HeadTooLarge) } else { Ok(None) };
        };
        // `HTTP/1.1 101 Switching Protocols`
        let status = rest
            .get(9..12)
            .filter(|_| rest.starts_with(b"HTTP/1.") && end >= 12)
            .and_then(|s| std::str::from_utf8(s).ok())
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or(HttpError::Malformed("response status line"))?;
        if (100..200).contains(&status) && status != 101 {
            rest = &rest[end + 4..];
            continue;
        }
        return Ok(Some(status));
    }
}

/// [`pump`] for the response to an upgrade request: says on `accepted` whether the
/// destination switched protocols (101) as soon as its answer has arrived, and false if
/// the stream ends or is malformed first. Everything is forwarded as it arrives.
pub async fn pump_upgrade<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut r: R,
    mut w: W,
    accepted: tokio::sync::oneshot::Sender<bool>,
) -> std::io::Result<u64> {
    let mut buf = vec![0u8; BUF];
    let mut total = 0;
    let mut seen = Vec::new();
    let mut accepted = Some(accepted);
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            let _ = w.shutdown().await;
            return Ok(total);
        }
        w.write_all(&buf[..n]).await?;
        total += n as u64;
        if let Some(tx) = accepted.take() {
            seen.extend_from_slice(&buf[..n]);
            match upgrade_answer(&seen) {
                Ok(None) => accepted = Some(tx),
                Ok(Some(status)) => {
                    let _ = tx.send(status == 101);
                }
                Err(_) => {
                    let _ = tx.send(false);
                }
            }
        }
    }
}

/// Copies `r` to `w` until end of stream, then shuts `w` down; returns the bytes.
pub async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(mut r: R, mut w: W) -> std::io::Result<u64> {
    let mut buf = vec![0u8; BUF];
    let mut total = 0;
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            let _ = w.shutdown().await;
            return Ok(total);
        }
        w.write_all(&buf[..n]).await?;
        total += n as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<Request<'_>, HttpError> {
        parse(s.as_bytes())
    }

    #[test]
    fn heads_parse_with_their_framing() {
        let r = p("POST /v1/x?a=1 HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 5\r\n\r\n").unwrap();
        assert_eq!((r.method, r.path(), r.host(), r.framing), ("POST", "/v1/x", "api.example.com", Framing::Length(5)));
        let r = p("POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip, chunked\r\n\r\n").unwrap();
        assert_eq!(r.framing, Framing::Chunked);
        let r = p("GET /ws HTTP/1.1\r\nHost: h\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n").unwrap();
        assert!(r.upgrade && r.framing == Framing::None);
    }

    #[test]
    fn ambiguous_or_misdirected_requests_are_refused() {
        for bad in [
            "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: -1\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: h\r\n folded\r\n\r\n",
            "GET / HTTP/1.1\nHost: h\r\n\r\n",
            "GET / HTTP/1.1\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
            "GET http://evil.example/ HTTP/1.1\r\nHost: h\r\n\r\n",
            "CONNECT h:443 HTTP/1.1\r\nHost: h\r\n\r\n",
            "GET /v1/../admin HTTP/1.1\r\nHost: h\r\n\r\n",
            "GET /v1/%2e%2e/admin HTTP/1.1\r\nHost: h\r\n\r\n",
            "GET /v1%2Fadmin HTTP/1.1\r\nHost: h\r\n\r\n",
            "PRI * HTTP/2.0\r\n\r\n",
        ] {
            assert!(p(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn host_headers_match_the_connection() {
        assert!(host_matches("API.example.com", "api.example.com", 443));
        assert!(host_matches("api.example.com:443", "api.example.com", 443));
        assert!(!host_matches("api.example.com:8443", "api.example.com", 443));
        assert!(!host_matches("evil.example.com", "api.example.com", 443));
        assert!(host_matches("203.0.113.5:80", "203.0.113.5", 80));
    }

    #[test]
    fn upgrades_are_settled_by_the_first_final_response() {
        assert_eq!(upgrade_answer(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n\x81\x00"), Ok(Some(101)));
        assert_eq!(upgrade_answer(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 101 OK\r\n\r\n"), Ok(Some(101)));
        assert_eq!(upgrade_answer(b"HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\n\r\n"), Ok(Some(200)));
        assert_eq!(upgrade_answer(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), Ok(Some(200)));
        assert_eq!(upgrade_answer(b"HTTP/1.1 101 Switching"), Ok(None));
        assert_eq!(upgrade_answer(b"HTTP/1.1 100 Continue\r\n\r\n"), Ok(None));
        assert!(upgrade_answer(b"garbage\r\n\r\n").is_err());
    }

    #[tokio::test]
    async fn chunk_sizes_are_hex_digits_only() {
        for bad in [&b"+a\r\n0123456789\r\n0\r\n\r\n"[..], b"-0\r\n\r\n", b" \r\n\r\n"] {
            let mut out = Vec::new();
            assert!(BufIn::new(bad, &[]).copy_chunked(&mut out).await.is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[tokio::test]
    async fn bodies_stream_with_their_framing() {
        let input = b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n0\r\nT: 1\r\n\r\nGET / HTTP/1.1\r\nHost: h\r\n\r\n";
        let mut b = BufIn::new(&input[..], &[]);
        let head = b.head().await.unwrap().unwrap();
        assert_eq!(parse(&head).unwrap().framing, Framing::Chunked);
        let mut out = Vec::new();
        b.copy_chunked(&mut out).await.unwrap();
        assert_eq!(out, b"3;x=y\r\nabc\r\n0\r\nT: 1\r\n\r\n");
        let next = b.head().await.unwrap().unwrap();
        assert_eq!(next, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n");
        assert!(b.head().await.unwrap().is_none());

        let mut b = BufIn::new(&b"hello world"[..], b"xx");
        let mut out = Vec::new();
        assert_eq!(b.copy_exact(7, &mut out).await.unwrap(), 7);
        assert_eq!(out, b"xxhello");
    }
}
