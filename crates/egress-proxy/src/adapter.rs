//! Credential adapters (SPEC.md "Credential substitution"): a request head for a
//! destination with an adapter is rewritten so the placeholder `clovelly://cred/<name>` in
//! the header or query parameter the policy names becomes the real secret.
//!
//! - bearer: every placeholder in the named header's value is replaced.
//! - basic: `Authorization: Basic <base64(user:pass)>` is decoded, placeholders in it
//!   replaced and the value re-encoded.
//! - query: in the named query parameter, a placeholder (raw or percent-encoded) is
//!   replaced and the value percent-encoded.
//!
//! The rewritten head is built into one [`SecretBuf`] of exactly its final size, and the
//! intermediate values that hold the secret are [`SecretBuf`]s too, so the secret is
//! never copied into a block that is freed without being wiped.
//!
//! On HTTP/2 the same adapters rewrite one stream's headers ([`rewrite_h2`], the
//! HTTP/2 header adapter): each rewritten header value, and a rewritten `:path`, is a
//! [`SecretBuf`] behind a [`Bytes`] that wipes it when the last reference goes, and
//! header values are marked sensitive so HPACK encodes them as never indexed (no
//! dynamic table on either side keeps them). Two copies are h2's and cannot be wiped:
//! the HPACK-encoded header block in h2's write buffer, and `:path`, which h2 copies
//! into its own pseudo-header value. TLS then encrypts from rustls's buffers, as it does
//! for HTTP/1.1.

use bytes::Bytes;
use common::bundle::{Adapter, AdapterKind};
use common::cred::{Secret, SecretBuf, find_placeholders};

use crate::http::Request;

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    /// HTTP/2 header values exclude control characters that HTTP/1.1 relays.
    #[error("the substituted value is not a valid HTTP/2 header value")]
    HeaderValue(#[from] ::http::header::InvalidHeaderValue),
    #[error("the substituted path is not a valid request path")]
    Path(#[from] ::http::uri::InvalidUri),
    #[error("the substituted request URI is invalid")]
    Uri(#[from] ::http::uri::InvalidUriParts),
}

/// A rewritten head and whether any placeholder was replaced.
pub struct Rewritten {
    pub head: SecretBuf,
    pub substituted: bool,
}

/// Bytes of the output: borrowed plain bytes, the secret, or an owned secret value.
enum Piece<'a> {
    Plain(&'a [u8]),
    Owned(SecretBuf),
}

impl Piece<'_> {
    fn len(&self) -> usize {
        match self {
            Piece::Plain(b) => b.len(),
            Piece::Owned(b) => b.len(),
        }
    }
}

/// Splices `secret` over every placeholder for the adapter's credential in `value`.
fn splice<'a>(value: &'a [u8], at: &[usize], placeholder_len: usize, secret: &'a [u8]) -> Vec<Piece<'a>> {
    let mut out = Vec::with_capacity(at.len() * 2 + 1);
    let mut from = 0;
    for &i in at {
        out.push(Piece::Plain(&value[from..i]));
        out.push(Piece::Plain(secret));
        from = i + placeholder_len;
    }
    out.push(Piece::Plain(&value[from..]));
    out
}

fn collect(pieces: &[Piece<'_>]) -> SecretBuf {
    let mut buf = SecretBuf::with_capacity(pieces.iter().map(Piece::len).sum());
    for p in pieces {
        match p {
            Piece::Plain(b) => buf.extend(b),
            Piece::Owned(b) => buf.extend(b.as_slice()),
        }
    }
    buf
}

/// Rewrites `req` for `adapter` with `secret`. A request with no placeholder for the
/// adapter's credential comes back unchanged (`substituted` false).
pub fn rewrite(req: &Request<'_>, adapter: &Adapter, secret: &Secret) -> Rewritten {
    let placeholder = adapter.credential.placeholder();
    let mut substituted = false;
    let mut target: Vec<Piece<'_>> = vec![Piece::Plain(req.target.as_bytes())];
    if let AdapterKind::Query { param } = &adapter.kind
        && let Some(t) = rewrite_query(req.target, param, &adapter.credential, secret)
    {
        target = t;
        substituted = true;
    }
    let mut pieces: Vec<Piece<'_>> = vec![Piece::Plain(req.method.as_bytes()), Piece::Plain(b" ")];
    pieces.append(&mut target);
    pieces.extend([Piece::Plain(b" "), Piece::Plain(req.version.as_bytes()), Piece::Plain(b"\r\n")]);
    for h in &req.headers {
        pieces.extend([Piece::Plain(h.name.as_bytes()), Piece::Plain(b": ")]);
        let value: Option<Vec<Piece<'_>>> = match &adapter.kind {
            AdapterKind::Bearer { header } if h.name.eq_ignore_ascii_case(header.as_str()) => {
                let at = find_placeholders(h.value, &adapter.credential);
                (!at.is_empty()).then(|| splice(h.value, &at, placeholder.len(), secret.expose()))
            }
            AdapterKind::Basic if h.name.eq_ignore_ascii_case("authorization") => {
                rewrite_basic(h.value, adapter, secret).map(|v| vec![Piece::Plain(b"Basic "), Piece::Owned(v)])
            }
            _ => None,
        };
        match value {
            Some(mut v) => {
                substituted = true;
                pieces.append(&mut v);
            }
            None => pieces.push(Piece::Plain(h.value)),
        }
        pieces.push(Piece::Plain(b"\r\n"));
    }
    pieces.push(Piece::Plain(b"\r\n"));
    Rewritten {
        head: collect(&pieces),
        substituted,
    }
}

/// `Basic <b64>` with a placeholder inside the decoded `user:pass`, re-encoded with the
/// secret; `None` if the value is not that.
fn rewrite_basic(value: &[u8], adapter: &Adapter, secret: &Secret) -> Option<SecretBuf> {
    let scheme = value.get(..6)?;
    if !scheme.eq_ignore_ascii_case(b"basic ") {
        return None;
    }
    let decoded = common::b64::decode(std::str::from_utf8(&value[6..]).ok()?.trim()).ok()?;
    let at = find_placeholders(&decoded, &adapter.credential);
    if at.is_empty() {
        return None;
    }
    let plain = collect(&splice(&decoded, &at, adapter.credential.placeholder().len(), secret.expose()));
    Some(base64(plain.as_slice()))
}

/// Standard base64 with padding, into a buffer of exactly the encoded size.
fn base64(input: &[u8]) -> SecretBuf {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = SecretBuf::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        let mut quad = [b'='; 4];
        for (i, q) in quad.iter_mut().enumerate().take(chunk.len() + 1) {
            *q = ALPHABET[(n >> (18 - 6 * i) & 63) as usize];
        }
        out.extend(&quad);
    }
    out
}

/// A secret-bearing buffer as the owner of a [`Bytes`]: wiped when the last reference
/// is dropped.
struct Wiped(SecretBuf);

impl AsRef<[u8]> for Wiped {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

fn wiped(buf: SecretBuf) -> Bytes {
    Bytes::from_owner(Wiped(buf))
}

/// A header value that holds a secret: wiped on drop, never indexed by HPACK.
fn sensitive(buf: SecretBuf) -> Result<::http::HeaderValue, AdapterError> {
    let mut v = ::http::HeaderValue::from_maybe_shared(wiped(buf))?;
    v.set_sensitive(true);
    Ok(v)
}

/// The HTTP/2 header adapter: rewrites one request's headers (bearer: the named header;
/// basic: `authorization`) or its `:path` (query) for `adapter` with `secret`, as
/// [`rewrite`] does for an HTTP/1.1 head. Returns whether a placeholder was replaced;
/// a request without one is left untouched.
pub fn rewrite_h2(parts: &mut ::http::request::Parts, adapter: &Adapter, secret: &Secret) -> Result<bool, AdapterError> {
    let placeholder = adapter.credential.placeholder();
    let mut substituted = false;
    match &adapter.kind {
        AdapterKind::Bearer { header } => {
            // Bundle header names are lower-case tokens, so this always parses.
            let Ok(name) = ::http::HeaderName::from_bytes(header.as_str().as_bytes()) else { return Ok(false) };
            if let ::http::header::Entry::Occupied(mut e) = parts.headers.entry(name) {
                for v in e.iter_mut() {
                    let at = find_placeholders(v.as_bytes(), &adapter.credential);
                    if at.is_empty() {
                        continue;
                    }
                    let new = sensitive(collect(&splice(v.as_bytes(), &at, placeholder.len(), secret.expose())))?;
                    *v = new;
                    substituted = true;
                }
            }
        }
        AdapterKind::Basic => {
            if let ::http::header::Entry::Occupied(mut e) = parts.headers.entry(::http::header::AUTHORIZATION) {
                for v in e.iter_mut() {
                    let Some(pair) = rewrite_basic(v.as_bytes(), adapter, secret) else { continue };
                    *v = sensitive(collect(&[Piece::Plain(b"Basic "), Piece::Owned(pair)]))?;
                    substituted = true;
                }
            }
        }
        AdapterKind::Query { param } => {
            let rewritten = parts
                .uri
                .path_and_query()
                .and_then(|pq| rewrite_query(pq.as_str(), param, &adapter.credential, secret))
                .map(|pieces| collect(&pieces));
            if let Some(buf) = rewritten {
                let mut uri = std::mem::take(&mut parts.uri).into_parts();
                uri.path_and_query = Some(::http::uri::PathAndQuery::from_maybe_shared(wiped(buf))?);
                parts.uri = ::http::Uri::from_parts(uri)?;
                substituted = true;
            }
        }
    }
    Ok(substituted)
}

fn unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-._~".contains(&b)
}

/// Percent-decodes a query value; `None` if it has a bad escape.
fn percent_decode(v: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(v.len());
    let mut i = 0;
    while i < v.len() {
        if v[i] == b'%' {
            let hex = std::str::from_utf8(v.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(v[i]);
            i += 1;
        }
    }
    Some(out)
}

/// Percent-encodes everything but unreserved bytes, into a buffer of exactly that size.
fn percent_encode(v: &[u8]) -> SecretBuf {
    let mut out = SecretBuf::with_capacity(v.iter().map(|b| if unreserved(*b) { 1 } else { 3 }).sum());
    for &b in v {
        if unreserved(b) {
            out.extend(&[b]);
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            out.extend(&[b'%', HEX[usize::from(b >> 4)], HEX[usize::from(b & 15)]]);
        }
    }
    out
}

/// The target with the placeholder in `param` replaced, or `None` if there is none.
fn rewrite_query<'a>(target: &'a str, param: &str, name: &common::cred::CredName, secret: &'a Secret) -> Option<Vec<Piece<'a>>> {
    let (path, query) = target.split_once('?')?;
    let mut pieces = vec![Piece::Plain(path.as_bytes()), Piece::Plain(b"?")];
    let mut changed = false;
    for (i, pair) in query.split('&').enumerate() {
        if i > 0 {
            pieces.push(Piece::Plain(b"&"));
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let decoded = (key == param).then(|| percent_decode(value.as_bytes())).flatten();
        let at = decoded.as_deref().map(|d| find_placeholders(d, name)).unwrap_or_default();
        match decoded {
            Some(d) if key == param && !at.is_empty() => {
                let plain = collect(&splice(&d, &at, name.placeholder().len(), secret.expose()));
                pieces.extend([Piece::Plain(key.as_bytes()), Piece::Plain(b"="), Piece::Owned(percent_encode(plain.as_slice()))]);
                changed = true;
            }
            _ => pieces.push(Piece::Plain(pair.as_bytes())),
        }
    }
    changed.then_some(pieces)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::parse;
    use common::bundle::HeaderName;

    fn adapter(kind: AdapterKind) -> Adapter {
        Adapter {
            kind,
            credential: "svc".parse().unwrap(),
        }
    }

    fn secret(s: &str) -> Secret {
        Secret::copy_from(s.as_bytes()).unwrap()
    }

    fn run(head: &str, a: &Adapter, s: &str) -> (String, bool) {
        let req = parse(head.as_bytes()).unwrap();
        let r = rewrite(&req, a, &secret(s));
        (String::from_utf8(r.head.as_slice().to_vec()).unwrap(), r.substituted)
    }

    /// Criterion 1: the bearer adapter replaces the placeholder in the named header
    /// only, and leaves other credentials' placeholders alone.
    #[test]
    fn bearer_adapter_rewrites_the_named_header() {
        let a = adapter(AdapterKind::Bearer { header: "authorization".parse::<HeaderName>().unwrap() });
        let (out, sub) = run(
            "GET /v1/models HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer clovelly://cred/svc\r\nX-Other: clovelly://cred/svc\r\n\r\n",
            &a,
            "sk-REAL",
        );
        assert!(sub);
        assert_eq!(
            out,
            "GET /v1/models HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer sk-REAL\r\nX-Other: clovelly://cred/svc\r\n\r\n"
        );
        let (out, sub) = run("GET / HTTP/1.1\r\nHost: h\r\nauthorization: Bearer clovelly://cred/svc2\r\n\r\n", &a, "sk-REAL");
        assert!(!sub && out.contains("clovelly://cred/svc2"), "another credential's placeholder is left alone");
        let x = adapter(AdapterKind::Bearer { header: "x-api-key".parse().unwrap() });
        let (out, _) = run("GET / HTTP/1.1\r\nHost: h\r\nX-API-Key: clovelly://cred/svc\r\n\r\n", &x, "k1");
        assert!(out.contains("X-API-Key: k1\r\n"));
    }

    /// Criterion 1: the basic adapter decodes `user:pass`, substitutes and re-encodes.
    #[test]
    fn basic_adapter_rewrites_inside_the_encoded_pair() {
        let a = adapter(AdapterKind::Basic);
        let pair = common::b64::encode(b"alice:clovelly://cred/svc");
        let (out, sub) = run(&format!("GET / HTTP/1.1\r\nHost: h\r\nAuthorization: Basic {pair}\r\n\r\n"), &a, "s3cr3t!");
        assert!(sub);
        let enc = out.split("Authorization: Basic ").nth(1).unwrap().split("\r\n").next().unwrap();
        assert_eq!(common::b64::decode(enc).unwrap(), b"alice:s3cr3t!");
        for n in 1..=5 {
            let s = "x".repeat(n);
            assert_eq!(base64(s.as_bytes()).as_slice(), common::b64::encode(s.as_bytes()).as_bytes());
        }
        let (_, sub) = run("GET / HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer clovelly://cred/svc\r\n\r\n", &a, "x");
        assert!(!sub, "a bearer value is not touched by the basic adapter");
    }

    /// Criterion 1: the query adapter replaces a raw or percent-encoded placeholder in
    /// the named parameter and percent-encodes the secret.
    #[test]
    fn query_adapter_rewrites_the_named_parameter() {
        let a = adapter(AdapterKind::Query { param: "key".into() });
        let (out, sub) = run("GET /maps?q=1&key=clovelly%3A%2F%2Fcred%2Fsvc&z=clovelly%3A%2F%2Fcred%2Fsvc HTTP/1.1\r\nHost: h\r\n\r\n", &a, "a b/c");
        assert!(sub);
        assert!(out.starts_with("GET /maps?q=1&key=a%20b%2Fc&z=clovelly%3A%2F%2Fcred%2Fsvc HTTP/1.1\r\n"), "{out}");
        let (out, sub) = run("GET /maps?key=clovelly://cred/svc HTTP/1.1\r\nHost: h\r\n\r\n", &a, "AIza-9");
        assert!(sub && out.starts_with("GET /maps?key=AIza-9 HTTP/1.1"), "{out}");
        let (_, sub) = run("GET /maps?key=plain HTTP/1.1\r\nHost: h\r\n\r\n", &a, "x");
        assert!(!sub);
    }

    fn h2_request(uri: &str, headers: &[(&str, &str)]) -> ::http::request::Parts {
        let mut b = ::http::Request::builder().method("POST").uri(uri);
        for (n, v) in headers {
            b = b.header(*n, *v);
        }
        b.body(()).unwrap().into_parts().0
    }

    /// Criterion 14: on HTTP/2 the bearer adapter rewrites the named header's values,
    /// the basic adapter the encoded pair in `authorization`, and the query adapter the
    /// parameter in `:path`; rewritten header values are sensitive (never indexed by
    /// HPACK) and other headers, and other credentials' placeholders, are untouched.
    #[test]
    fn h2_header_adapter_rewrites_bearer_basic_and_query() {
        let bearer = adapter(AdapterKind::Bearer { header: "authorization".parse::<HeaderName>().unwrap() });
        let mut p = h2_request(
            "https://grpc.example.com/clovelly.test.Echo/Stream",
            &[("authorization", "Bearer clovelly://cred/svc"), ("x-other", "clovelly://cred/svc"), ("content-type", "application/grpc")],
        );
        assert!(rewrite_h2(&mut p, &bearer, &secret("sk-REAL")).unwrap());
        assert_eq!(p.headers["authorization"], "Bearer sk-REAL");
        assert!(p.headers["authorization"].is_sensitive());
        assert_eq!(p.headers["x-other"], "clovelly://cred/svc");
        assert!(!p.headers["content-type"].is_sensitive());
        let mut other = h2_request("https://h/", &[("authorization", "Bearer clovelly://cred/svc2")]);
        assert!(!rewrite_h2(&mut other, &bearer, &secret("sk-REAL")).unwrap(), "another credential's placeholder");
        assert_eq!(other.headers["authorization"], "Bearer clovelly://cred/svc2");

        let basic = adapter(AdapterKind::Basic);
        let pair = common::b64::encode(b"alice:clovelly://cred/svc");
        let mut p = h2_request("https://h/", &[("authorization", &format!("Basic {pair}"))]);
        assert!(rewrite_h2(&mut p, &basic, &secret("s3cr3t!")).unwrap());
        let v = p.headers["authorization"].to_str().unwrap().strip_prefix("Basic ").unwrap().to_owned();
        assert_eq!(common::b64::decode(&v).unwrap(), b"alice:s3cr3t!");
        assert!(p.headers["authorization"].is_sensitive());

        let query = adapter(AdapterKind::Query { param: "key".into() });
        let mut p = h2_request("https://maps.example.com/v1/geo?q=1&key=clovelly%3A%2F%2Fcred%2Fsvc", &[]);
        assert!(rewrite_h2(&mut p, &query, &secret("a b/c")).unwrap());
        assert_eq!(p.uri.path_and_query().unwrap().as_str(), "/v1/geo?q=1&key=a%20b%2Fc");
        assert_eq!(p.uri.authority().unwrap().as_str(), "maps.example.com", "only the path changes");
        let mut none = h2_request("https://h/v1/geo?key=plain", &[]);
        assert!(!rewrite_h2(&mut none, &query, &secret("x")).unwrap());

        // A secret HTTP/1.1 would relay but an HTTP/2 header value cannot hold.
        let mut p = h2_request("https://h/", &[("authorization", "Bearer clovelly://cred/svc")]);
        assert!(rewrite_h2(&mut p, &bearer, &secret("a\u{1}b")).is_err());
    }
}
