//! JSON Canonicalization Scheme (RFC 8785) for the documents we sign: receipts.
//!
//! Object members are sorted by the UTF-16 code units of their names, strings use the
//! shortest escapes, there is no whitespace, and numbers are integers. Receipts carry
//! no fractions, so a non-integral number is refused rather than formatted with
//! ECMAScript's float rules.
//!
//! ```
//! let v = serde_json::json!({ "b": 1, "a": [true, null, "x\n"] });
//! assert_eq!(common::jcs::canonical(&v).unwrap(), br#"{"a":[true,null,"x\n"],"b":1}"#);
//! ```

use serde_json::Value;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JcsError {
    #[error("number {0} is not an integer between -(2^53 - 1) and 2^53 - 1")]
    Number(String),
}

/// The largest integer an IEEE double holds exactly (RFC 8785 serialises numbers as
/// doubles, so larger integers would not round-trip).
const MAX_SAFE: u64 = (1 << 53) - 1;

/// The canonical bytes of `value`.
pub fn canonical(value: &Value) -> Result<Vec<u8>, JcsError> {
    let mut out = Vec::new();
    write(value, &mut out)?;
    Ok(out)
}

fn write(value: &Value, out: &mut Vec<u8>) -> Result<(), JcsError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Number(n) => {
            let text = match (n.as_u64(), n.as_i64()) {
                (Some(u), _) if u <= MAX_SAFE => u.to_string(),
                (None, Some(i)) if i.unsigned_abs() <= MAX_SAFE => i.to_string(),
                _ => return Err(JcsError::Number(n.to_string())),
            };
            out.extend_from_slice(text.as_bytes());
        }
        Value::String(s) => string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut members: Vec<(Vec<u16>, &String, &Value)> =
                map.iter().map(|(k, v)| (k.encode_utf16().collect(), k, v)).collect();
            members.sort_by(|a, b| a.0.cmp(&b.0));
            out.push(b'{');
            for (i, (_, k, v)) in members.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                string(k, out);
                out.push(b':');
                write(v, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes()),
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// RFC 8785 §3.2.3's sorting example: names compare by UTF-16 code units, so the
    /// astral character (a surrogate pair, 0xD83D...) sorts before U+FB33.
    #[test]
    fn members_sort_by_utf16_code_units() {
        let v: Value = serde_json::from_str(
            r#"{"€":"Euro Sign","\r":"Carriage Return","דּ":"Hebrew Letter Dalet With Dagesh","1":"One","😀":"Emoji: Grinning Face","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis"}"#,
        )
        .unwrap();
        let want = "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\"\u{f6}\":\"Latin Small Letter O With Diaeresis\",\"\u{20ac}\":\"Euro Sign\",\"\u{1f600}\":\"Emoji: Grinning Face\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}";
        assert_eq!(String::from_utf8(canonical(&v).unwrap()).unwrap(), want);
    }

    #[test]
    fn strings_take_the_shortest_escapes() {
        let v = json!("\u{1}\u{8}\t\n\u{c}\r\"\\/é\u{7f}");
        assert_eq!(canonical(&v).unwrap(), "\"\\u0001\\b\\t\\n\\f\\r\\\"\\\\/é\u{7f}\"".as_bytes());
    }

    #[test]
    fn integers_only() {
        assert_eq!(canonical(&json!([0, -1, 9007199254740991u64])).unwrap(), b"[0,-1,9007199254740991]");
        assert!(canonical(&json!(1.5)).is_err());
        assert!(canonical(&json!(9007199254740992u64)).is_err());
    }

    #[test]
    fn whitespace_and_order_do_not_matter() {
        let a: Value = serde_json::from_str("{ \"z\" : [1, 2], \"a\": {\"y\": null, \"b\": false} }").unwrap();
        let b = json!({"a": {"b": false, "y": null}, "z": [1, 2]});
        assert_eq!(canonical(&a).unwrap(), canonical(&b).unwrap());
        assert_eq!(canonical(&a).unwrap(), br#"{"a":{"b":false,"y":null},"z":[1,2]}"#);
    }
}
