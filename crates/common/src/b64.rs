//! Base64 (RFC 4648), standard and URL-safe alphabets, and PEM armour.
//!
//! JWS needs unpadded base64url; Cloud KMS's JSON API and PEM use padded standard
//! base64. Small enough to keep here rather than add a crate.

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Base64Error {
    #[error("byte {0:#04x} at offset {1} is not in the base64 alphabet")]
    BadByte(u8, usize),
    #[error("base64 input has a dangling final character")]
    BadLength,
}

/// Padded standard base64.
pub fn encode(bytes: &[u8]) -> String {
    encode_with(bytes, STANDARD, true)
}

/// Unpadded base64url, as JWS uses.
pub fn encode_url(bytes: &[u8]) -> String {
    encode_with(bytes, URL_SAFE, false)
}

/// Decodes standard base64; padding is optional.
pub fn decode(text: &str) -> Result<Vec<u8>, Base64Error> {
    decode_with(text, STANDARD)
}

/// Decodes base64url; padding is optional.
pub fn decode_url(text: &str) -> Result<Vec<u8>, Base64Error> {
    decode_with(text, URL_SAFE)
}

/// PEM armour: `-----BEGIN {label}-----`, base64 in 64-column lines, `-----END`.
pub fn pem(label: &str, der: &[u8]) -> String {
    let body = encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// The DER inside every PEM block labelled `label`, in order.
pub fn pem_blocks(text: &str, label: &str) -> Result<Vec<Vec<u8>>, Base64Error> {
    let (begin, end) = (
        format!("-----BEGIN {label}-----"),
        format!("-----END {label}-----"),
    );
    let mut blocks = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(&begin) {
        let after = &rest[start + begin.len()..];
        let Some(stop) = after.find(&end) else { break };
        let body: String = after[..stop].split_whitespace().collect();
        blocks.push(decode(&body)?);
        rest = &after[stop + end.len()..];
    }
    Ok(blocks)
}

fn encode_with(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        let chars = chunk.len() + 1;
        for i in 0..4 {
            if i < chars {
                out.push(char::from(alphabet[(n >> (18 - 6 * i) & 0x3f) as usize]));
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

fn decode_with(text: &str, alphabet: &[u8; 64]) -> Result<Vec<u8>, Base64Error> {
    let trimmed = text.trim_end_matches('=');
    let mut out = Vec::with_capacity(trimmed.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for (i, &b) in trimmed.as_bytes().iter().enumerate() {
        let v = alphabet
            .iter()
            .position(|&a| a == b)
            .ok_or(Base64Error::BadByte(b, i))?;
        acc = acc << 6 | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if trimmed.len() % 4 == 1 {
        return Err(Base64Error::BadLength);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        let cases = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, coded) in cases {
            assert_eq!(encode(plain.as_bytes()), coded);
            assert_eq!(decode(coded).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn url_safe_is_unpadded_and_uses_its_alphabet() {
        assert_eq!(encode_url(&[0xfb, 0xff]), "-_8");
        assert_eq!(decode_url("-_8").unwrap(), vec![0xfb, 0xff]);
        assert_eq!(decode("-_8"), Err(Base64Error::BadByte(b'-', 0)));
        assert_eq!(decode("Zm9vY"), Err(Base64Error::BadLength));
    }

    #[test]
    fn pem_round_trips() {
        let der: Vec<u8> = (0..=255).collect();
        let text = pem("CERTIFICATE", &der);
        assert!(text.lines().all(|l| l.len() <= 64));
        let twice = format!("{text}junk\n{text}");
        assert_eq!(pem_blocks(&twice, "CERTIFICATE").unwrap(), vec![der.clone(), der]);
        assert!(pem_blocks(&text, "PUBLIC KEY").unwrap().is_empty());
    }
}
