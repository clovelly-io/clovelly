//! Reads the server name and the offered application protocols (ALPN) from a TLS
//! ClientHello without terminating TLS, so the proxy can decide (deny, relay untouched,
//! or terminate, and whether to speak HTTP/2) before answering, and can replay the
//! exact bytes to the destination for a `passthrough` destination.

/// The most ClientHello bytes the proxy buffers before deciding.
pub const MAX_HELLO: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hello {
    /// More bytes are needed.
    Incomplete,
    /// Not a TLS ClientHello (or malformed, or too large).
    NotTls,
    /// A whole ClientHello: its server name, if it sent one, and the protocols it
    /// offers in its order (empty without ALPN).
    Complete { sni: Option<String>, alpn: Vec<Vec<u8>> },
}

/// Inspects the start of a connection.
pub fn parse(buf: &[u8]) -> Hello {
    // Reassemble the handshake message from consecutive handshake records.
    let mut hs = Vec::new();
    let mut at = 0;
    loop {
        let Some(header) = buf.get(at..at + 5) else { return incomplete(buf) };
        if header[0] != 22 || header[1] != 3 {
            return Hello::NotTls;
        }
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let Some(body) = buf.get(at + 5..at + 5 + len) else { return incomplete(buf) };
        hs.extend_from_slice(body);
        at += 5 + len;
        if hs.len() >= 4 {
            if hs[0] != 1 {
                return Hello::NotTls;
            }
            let need = 4 + (usize::from(hs[1]) << 16 | usize::from(hs[2]) << 8 | usize::from(hs[3]));
            if need > MAX_HELLO {
                return Hello::NotTls;
            }
            if hs.len() >= need {
                return match extensions(&hs[4..need]) {
                    Some((sni, alpn)) => Hello::Complete { sni, alpn },
                    None => Hello::NotTls,
                };
            }
        }
    }
}

fn incomplete(buf: &[u8]) -> Hello {
    if buf.len() > MAX_HELLO { Hello::NotTls } else { Hello::Incomplete }
}

/// The server_name and ALPN extensions of a ClientHello body; `None` if the body is
/// malformed.
fn extensions(b: &[u8]) -> Option<(Option<String>, Vec<Vec<u8>>)> {
    let mut r = Reader { b, at: 0 };
    r.skip(2 + 32)?; // legacy_version, random
    let n = usize::from(r.u8()?);
    r.skip(n)?; // session id
    let n = usize::from(r.u16()?);
    r.skip(n)?; // cipher suites
    let n = usize::from(r.u8()?);
    r.skip(n)?; // compression methods
    let (mut sni, mut alpn) = (None, Vec::new());
    if r.at == b.len() {
        return Some((sni, alpn)); // no extensions
    }
    let ext_len = usize::from(r.u16()?);
    let end = r.at + ext_len;
    if end > b.len() {
        return None;
    }
    while r.at < end {
        let (kind, len) = (r.u16()?, usize::from(r.u16()?));
        let mut ext = Reader { b: r.take(len)?, at: 0 };
        match kind {
            // server_name_list: a list of (name_type, name); the first host_name counts.
            0 => {
                let list = ext.vec16()?;
                let mut names = Reader { b: list, at: 0 };
                while names.at < list.len() {
                    let (name_type, n) = (names.u8()?, usize::from(names.u16()?));
                    let name = names.take(n)?;
                    if name_type == 0 && sni.is_none() {
                        sni = std::str::from_utf8(name).ok().map(str::to_owned);
                    }
                }
            }
            // application_layer_protocol_negotiation: a list of non-empty names.
            16 => {
                let list = ext.vec16()?;
                let mut protocols = Reader { b: list, at: 0 };
                while protocols.at < list.len() {
                    let n = usize::from(protocols.u8()?);
                    if n == 0 {
                        return None;
                    }
                    alpn.push(protocols.take(n)?.to_vec());
                }
            }
            _ => {}
        }
    }
    Some((sni, alpn))
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.at..self.at + n)?;
        self.at += n;
        Some(s)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    /// A vector with a two-byte length.
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal ClientHello record naming `sni` (or none), split into records of at
    /// most `record` bytes.
    pub(crate) fn hello(sni: Option<&str>, record: usize) -> Vec<u8> {
        hello_offering(sni, &[], record)
    }

    /// [`hello`] offering the ALPN protocols `alpn` (none if empty).
    pub(crate) fn hello_offering(sni: Option<&str>, alpn: &[&[u8]], record: usize) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        let mut ext = Vec::new();
        if let Some(name) = sni {
            let n = name.len() as u16;
            ext.extend_from_slice(&[0, 0]);
            ext.extend_from_slice(&(n + 5).to_be_bytes());
            ext.extend_from_slice(&(n + 3).to_be_bytes());
            ext.push(0);
            ext.extend_from_slice(&n.to_be_bytes());
            ext.extend_from_slice(name.as_bytes());
        }
        if !alpn.is_empty() {
            let list: Vec<u8> = alpn.iter().flat_map(|p| std::iter::once(p.len() as u8).chain(p.iter().copied())).collect();
            ext.extend_from_slice(&[0, 16]);
            ext.extend_from_slice(&(list.len() as u16 + 2).to_be_bytes());
            ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
            ext.extend_from_slice(&list);
        }
        ext.extend_from_slice(&[0, 43, 0, 3, 2, 3, 4]); // supported_versions
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![1, 0, 0, 0];
        hs[2] = (body.len() >> 8) as u8;
        hs[3] = body.len() as u8;
        hs.extend_from_slice(&body);
        hs.chunks(record)
            .flat_map(|c| {
                let mut r = vec![22, 3, 1];
                r.extend_from_slice(&(c.len() as u16).to_be_bytes());
                r.extend_from_slice(c);
                r
            })
            .collect()
    }

    #[test]
    fn finds_the_server_name_across_records_and_partial_reads() {
        let h = hello(Some("api.openai.com"), 4096);
        assert_eq!(parse(&h), Hello::Complete { sni: Some("api.openai.com".into()), alpn: vec![] });
        for cut in [0, 3, 5, 20, h.len() - 1] {
            assert_eq!(parse(&h[..cut]), Hello::Incomplete, "{cut}");
        }
        let split = hello(Some("example.com"), 16);
        assert_eq!(parse(&split), Hello::Complete { sni: Some("example.com".into()), alpn: vec![] });
        assert_eq!(parse(&hello(None, 4096)), Hello::Complete { sni: None, alpn: vec![] });
    }

    /// HTTP/2 inspection starts here: the protocols a sandbox offers, in its order,
    /// whichever side of the server name they come.
    #[test]
    fn finds_the_offered_protocols() {
        let h = hello_offering(Some("grpc.example.com"), &[b"h2", b"http/1.1"], 4096);
        assert_eq!(
            parse(&h),
            Hello::Complete { sni: Some("grpc.example.com".into()), alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()] }
        );
        assert_eq!(parse(&hello_offering(None, &[b"h2"], 32)), Hello::Complete { sni: None, alpn: vec![b"h2".to_vec()] });
        let mut empty_name = hello_offering(Some("a.example"), &[b"h2"], 4096);
        let at = empty_name.windows(3).rposition(|w| w == [2, b'h', b'2']).unwrap();
        empty_name[at] = 0;
        assert_eq!(parse(&empty_name), Hello::NotTls, "a zero-length protocol name is malformed");
    }

    #[test]
    fn other_protocols_are_not_tls() {
        assert_eq!(parse(b"GET / HTTP/1.1\r\n"), Hello::NotTls);
        assert_eq!(parse(&[22, 3, 1, 0, 4, 2, 0, 0, 0]), Hello::NotTls, "a ServerHello");
    }
}
