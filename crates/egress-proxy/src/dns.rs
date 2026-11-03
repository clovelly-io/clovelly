//! The DNS wire format (RFC 1035), as much as the sandbox resolver and the DNS-over-TLS
//! client need: one-question queries, answers with A records and CNAME chains, and
//! name compression when reading.

use std::net::Ipv4Addr;

pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const CLASS_IN: u16 = 1;

pub const NOERROR: u8 = 0;
pub const SERVFAIL: u8 = 2;
pub const NXDOMAIN: u8 = 3;
pub const REFUSED: u8 = 5;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    #[error("DNS message truncated")]
    Truncated,
    #[error("DNS message is not a query with one question")]
    NotAQuery,
    #[error("DNS name is malformed")]
    BadName,
    #[error("DNS answer does not match the query")]
    Mismatch,
}

/// A query's single question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub id: u16,
    /// Recursion desired, echoed in the answer.
    pub rd: bool,
    /// The name as asked, dotted, without a trailing dot.
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// Where the question ends in the query (the answer repeats `query[12..end]`).
    pub end: usize,
}

fn u16_at(m: &[u8], i: usize) -> Result<u16, DnsError> {
    m.get(i..i + 2).map(|b| u16::from_be_bytes([b[0], b[1]])).ok_or(DnsError::Truncated)
}

fn u32_at(m: &[u8], i: usize) -> Result<u32, DnsError> {
    m.get(i..i + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or(DnsError::Truncated)
}

/// Reads the name at `at`, following compression pointers; returns it and where the
/// name ends in place (after the first pointer, if any).
fn read_name(m: &[u8], mut at: usize) -> Result<(String, usize), DnsError> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *m.get(at).ok_or(DnsError::Truncated)?;
        match len {
            0 => {
                return Ok((labels.join("."), end.unwrap_or(at + 1)));
            }
            l if l & 0xc0 == 0xc0 => {
                jumps += 1;
                if jumps > 16 {
                    return Err(DnsError::BadName);
                }
                end.get_or_insert(at + 2);
                at = usize::from(u16_at(m, at)? & 0x3fff);
            }
            l if l & 0xc0 == 0 => {
                let l = usize::from(l);
                let label = m.get(at + 1..at + 1 + l).ok_or(DnsError::Truncated)?;
                labels.push(String::from_utf8(label.to_vec()).map_err(|_| DnsError::BadName)?);
                if labels.iter().map(|l| l.len() + 1).sum::<usize>() > 255 {
                    return Err(DnsError::BadName);
                }
                at += 1 + l;
            }
            _ => return Err(DnsError::BadName),
        }
    }
}

fn write_name(out: &mut Vec<u8>, name: &str) -> Result<(), DnsError> {
    for label in name.split('.').filter(|l| !l.is_empty()) {
        let len = u8::try_from(label.len()).map_err(|_| DnsError::BadName)?;
        if len > 63 {
            return Err(DnsError::BadName);
        }
        out.push(len);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// Parses a query with exactly one question.
pub fn parse_query(m: &[u8]) -> Result<Question, DnsError> {
    let id = u16_at(m, 0)?;
    let flags = u16_at(m, 2)?;
    let qdcount = u16_at(m, 4)?;
    // QR must be 0 (a query) and the opcode QUERY.
    if flags & 0x8000 != 0 || (flags >> 11) & 0xf != 0 || qdcount != 1 {
        return Err(DnsError::NotAQuery);
    }
    let (name, at) = read_name(m, 12)?;
    Ok(Question {
        id,
        rd: flags & 0x0100 != 0,
        name,
        qtype: u16_at(m, at)?,
        qclass: u16_at(m, at + 2)?,
        end: at + 4,
    })
}

/// The answer to `query` (whose question is `q`): `rcode` and A records for the
/// question's name.
pub fn answer(query: &[u8], q: &Question, rcode: u8, records: &[(Ipv4Addr, u32)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(q.end + records.len() * 16);
    out.extend_from_slice(&q.id.to_be_bytes());
    // QR, RD as asked, RA.
    let flags: u16 = 0x8000 | if q.rd { 0x0100 } else { 0 } | 0x0080 | u16::from(rcode & 0xf);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&u16::try_from(records.len()).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&query[12..q.end]);
    for (ip, ttl) in records {
        // A pointer to the question's name at offset 12.
        out.extend_from_slice(&[0xc0, 12]);
        out.extend_from_slice(&TYPE_A.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&ip.octets());
    }
    out
}

/// A query for `name`'s A records (recursion desired).
pub fn query(id: u16, name: &str) -> Result<Vec<u8>, DnsError> {
    let mut out = Vec::with_capacity(name.len() + 18);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    write_name(&mut out, name)?;
    out.extend_from_slice(&TYPE_A.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

/// What a resolver answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub rcode: u8,
    /// A records for the name or the CNAME chain from it, with their TTLs.
    pub addresses: Vec<(Ipv4Addr, u32)>,
}

/// Reads a resolver's answer to our query `id` for `name`.
pub fn parse_answer(m: &[u8], id: u16, name: &str) -> Result<Answer, DnsError> {
    if u16_at(m, 0)? != id {
        return Err(DnsError::Mismatch);
    }
    let flags = u16_at(m, 2)?;
    if flags & 0x8000 == 0 {
        return Err(DnsError::Mismatch);
    }
    let (qd, an) = (u16_at(m, 4)?, u16_at(m, 6)?);
    let mut at = 12;
    for _ in 0..qd {
        let (q, end) = read_name(m, at)?;
        if !q.eq_ignore_ascii_case(name) {
            return Err(DnsError::Mismatch);
        }
        at = end + 4;
    }
    let mut chain = vec![name.to_ascii_lowercase()];
    let mut addresses = Vec::new();
    for _ in 0..an {
        let (owner, end) = read_name(m, at)?;
        let (rtype, class, ttl, len) = (u16_at(m, end)?, u16_at(m, end + 2)?, u32_at(m, end + 4)?, u16_at(m, end + 8)?);
        let data = end + 10;
        let rdata = m.get(data..data + usize::from(len)).ok_or(DnsError::Truncated)?;
        let owner = owner.to_ascii_lowercase();
        if class == CLASS_IN && chain.contains(&owner) {
            match rtype {
                TYPE_CNAME => chain.push(read_name(m, data)?.0.to_ascii_lowercase()),
                TYPE_A if rdata.len() == 4 => {
                    addresses.push((Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]), ttl));
                }
                _ => {}
            }
        }
        at = data + usize::from(len);
    }
    Ok(Answer {
        rcode: (flags & 0xf) as u8,
        addresses,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_query_round_trips_into_an_answer() {
        let q = query(0x1234, "API.example.com").unwrap();
        let parsed = parse_query(&q).unwrap();
        assert_eq!((parsed.id, parsed.name.as_str(), parsed.qtype, parsed.rd), (0x1234, "API.example.com", TYPE_A, true));
        let a = answer(&q, &parsed, NOERROR, &[(Ipv4Addr::new(192, 0, 2, 7), 30)]);
        let got = parse_answer(&a, 0x1234, "api.example.com").unwrap();
        assert_eq!(got, Answer { rcode: NOERROR, addresses: vec![(Ipv4Addr::new(192, 0, 2, 7), 30)] });
        let nx = answer(&q, &parsed, NXDOMAIN, &[]);
        assert_eq!(parse_answer(&nx, 0x1234, "api.example.com").unwrap().rcode, NXDOMAIN);
        assert_eq!(parse_answer(&nx, 0x9999, "api.example.com"), Err(DnsError::Mismatch));
    }

    #[test]
    fn answers_follow_cname_chains_and_compression() {
        // www.example.com CNAME edge.example.net; edge.example.net A 198.51.100.1;
        // other.example.org A 203.0.113.1 (not in the chain).
        let mut m = query(7, "www.example.com").unwrap();
        m[2] = 0x81;
        m[3] = 0x80;
        m[7] = 3;
        let cname_target = m.len() + 12;
        m.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 18]);
        m.extend_from_slice(b"\x04edge\x07example\x03net\x00");
        m.extend_from_slice(&[0xc0, cname_target as u8, 0, 1, 0, 1, 0, 0, 0, 20, 0, 4, 198, 51, 100, 1]);
        m.extend_from_slice(b"\x05other\x07example\x03org\x00");
        m.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 20, 0, 4, 203, 0, 113, 1]);
        let got = parse_answer(&m, 7, "www.example.com").unwrap();
        assert_eq!(got.addresses, vec![(Ipv4Addr::new(198, 51, 100, 1), 20)]);
    }

    #[test]
    fn malformed_queries_are_refused() {
        assert_eq!(parse_query(&[0; 5]), Err(DnsError::Truncated));
        let mut q = query(1, "a.b").unwrap();
        q[2] |= 0x80;
        assert_eq!(parse_query(&q), Err(DnsError::NotAQuery));
        let mut loop_ptr = query(1, "a").unwrap();
        loop_ptr.truncate(12);
        loop_ptr.extend_from_slice(&[0xc0, 12]);
        assert_eq!(parse_query(&loop_ptr), Err(DnsError::BadName));
    }
}
