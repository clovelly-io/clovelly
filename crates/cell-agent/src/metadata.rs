//! The GCE metadata server, which is untrusted: what it says only decides where the
//! cell asks to be unlocked and what it claims about itself. The verifier checks every
//! claim against the quote.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const SERVER: &str = "169.254.169.254:80";

#[derive(Debug, thiserror::Error)]
pub enum MetadataError {
    #[error("metadata {path}: {source}")]
    Io { path: String, source: io::Error },
    #[error("metadata {path}: HTTP status line {status:?}")]
    Status { path: String, status: String },
}

/// GETs `computeMetadata/v1/<path>`; `Ok(None)` when the server answers 404.
pub fn get(path: &str) -> Result<Option<String>, MetadataError> {
    let io_err = |source| MetadataError::Io {
        path: path.to_owned(),
        source,
    };
    let mut s = TcpStream::connect(SERVER).map_err(io_err)?;
    s.set_read_timeout(Some(Duration::from_secs(10))).map_err(io_err)?;
    write!(
        s,
        "GET /computeMetadata/v1/{path} HTTP/1.1\r\nHost: metadata.google.internal\r\n\
         Metadata-Flavor: Google\r\nConnection: close\r\n\r\n"
    )
    .map_err(io_err)?;
    let mut resp = String::new();
    s.read_to_string(&mut resp).map_err(io_err)?;
    let (head, body) = resp.split_once("\r\n\r\n").unwrap_or((&resp, ""));
    let status = head.lines().next().unwrap_or_default();
    match status.split_whitespace().nth(1) {
        Some("200") => Ok(Some(body.to_owned())),
        Some("404") => Ok(None),
        _ => Err(MetadataError::Status {
            path: path.to_owned(),
            status: status.to_owned(),
        }),
    }
}

/// An instance attribute (`instance/attributes/<name>`).
pub fn attribute(name: &str) -> Result<Option<String>, MetadataError> {
    get(&format!("instance/attributes/{name}"))
}
