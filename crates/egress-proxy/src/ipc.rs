//! The local channel between the cell agent and the egress proxy process (SPEC.md "The
//! egress proxy is its own process"): the proxy's stdin and stdout, pipes only the
//! agent holds. Each message is one frame:
//!
//! ```text
//! u32 header length | u32 secret length | header (JSON) | secret bytes
//! ```
//!
//! with lengths big-endian. The header is a small JSON object ([`ToProxy`] or
//! [`FromProxy`]). The secret part carries key material, the in-cell CA's key or a
//! sandbox's credential secrets, and never passes through serde_json: the agent writes
//! it straight from its own wiped buffers, and the proxy reads it into one buffer of
//! exactly its size ([`Blob`]) that is wiped when dropped.
//!
//! Agent to proxy: [`ToProxy::Hello`] (first, once), then [`ToProxy::AddOwn`],
//! [`ToProxy::Register`] and [`ToProxy::Unregister`]. Proxy to agent:
//! [`FromProxy::Ready`] (the answer to Hello), [`FromProxy::Registered`] or
//! [`FromProxy::Refused`] (to Register), [`FromProxy::Log`] for every log line,
//! [`FromProxy::Unregistered`] (to Unregister, after the sandbox's connections have
//! ended and their lines were sent) and [`FromProxy::Connections`] every second.
//!
//! Nothing in the protocol carries a DEK, the cell key or anything derived from them:
//! the proxy process holds only the CA key, the policies, and the credentials released
//! to the sandboxes it serves.

use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;

use common::cred::AdapterType;
use common::sandbox::{CpuHalves, MemoryGib, Size};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::Ports;

/// The largest header: a policy bundle (base64) and a sandbox's credential names.
pub const MAX_HEADER: usize = 4 << 20;
/// The largest secret part: a CA key, or a sandbox's credentials (16 KiB each).
pub const MAX_SECRET: usize = 1 << 20;

#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("channel: {0}")]
    Io(#[from] std::io::Error),
    #[error("the channel ended inside a frame")]
    Truncated,
    #[error("frame header of {0} bytes is over the limit")]
    HeaderTooLarge(usize),
    #[error("frame secret of {0} bytes is over the limit")]
    SecretTooLarge(usize),
    #[error("frame header: {0}")]
    Json(#[from] serde_json::Error),
}

/// From the agent to the proxy process.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ToProxy {
    /// The first message: what the proxy is built from. Secret: the in-cell CA's
    /// private key, PKCS#8 DER.
    Hello {
        /// Names the in-cell CA (the instance id).
        cell: String,
        /// The CA certificate, DER, base64.
        ca_cert: String,
        /// The public roots (PEM) destinations and resolvers must chain to.
        roots_pem: String,
        /// The address to listen on (every address on a cell).
        listen: Ipv4Addr,
        /// The ports to bind; 0 picks a free one (tests).
        ports: Ports,
        /// Fixed name-to-address answers (tests); none on a cell.
        hosts: HashMap<String, Vec<Ipv4Addr>>,
        /// Addresses allowed although not public (tests); none on a cell.
        exempt: Vec<Ipv4Addr>,
    },
    /// One of the cell's own addresses, never a destination.
    AddOwn { ip: Ipv4Addr },
    /// Serve a sandbox at `ip`. Secret: its credentials' secrets, concatenated in
    /// `credentials` order.
    Register {
        ip: Ipv4Addr,
        sandbox: String,
        /// The policy bundle as the agent verified it, base64.
        bundle: String,
        /// The agent's `limits.max` for the policy.
        ceiling: Ceiling,
        credentials: Vec<WireCredential>,
    },
    /// Stop serving the sandbox at `ip`, ending its connections and wiping its
    /// credentials.
    Unregister { ip: Ipv4Addr, sandbox: String },
}

/// A sandbox size on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ceiling {
    pub cpu_halves: u32,
    pub memory_gib: u32,
}

impl From<Size> for Ceiling {
    fn from(s: Size) -> Self {
        Self { cpu_halves: s.cpu.0, memory_gib: s.memory.0 }
    }
}

impl From<Ceiling> for Size {
    fn from(c: Ceiling) -> Self {
        Size::new(CpuHalves(c.cpu_halves), MemoryGib(c.memory_gib))
    }
}

/// A released credential's binding and where its secret is in the frame's secret part.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireCredential {
    pub name: String,
    pub adapter: AdapterType,
    pub destination: String,
    /// Its secret's length; secrets follow one another in this list's order.
    pub len: usize,
}

/// From the proxy process to the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FromProxy {
    /// Serving, on these ports (the ones bound, where Hello asked for 0).
    Ready { ports: Ports },
    /// The sandbox at `ip` is served. Every answer names the sandbox it is about, so
    /// one that comes late is never taken for a later sandbox at the same address.
    Registered { ip: Ipv4Addr, sandbox: String },
    /// The sandbox at `ip` could not be registered.
    Refused { ip: Ipv4Addr, sandbox: String, reason: String },
    /// One egress log line (JSON) of the sandbox at `ip`.
    Log { ip: Ipv4Addr, sandbox: String, line: String },
    /// The sandbox at `ip` is no longer served and every line of it has been sent.
    Unregistered { ip: Ipv4Addr, sandbox: String },
    /// Connections open now.
    Connections { count: u32 },
}

/// A frame's secret part: exactly its size, never reallocated, wiped on drop.
pub struct Blob(pub(crate) Box<[u8]>);

impl Blob {
    fn zeroed(n: usize) -> Self {
        Self(vec![0u8; n].into_boxed_slice())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for Blob {
    fn drop(&mut self) {
        common::dek::wipe(&mut self.0);
    }
}

impl fmt::Debug for Blob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Blob({} bytes)", self.0.len())
    }
}

/// Writes one frame: `header` as JSON, then `secret` (empty for most messages)
/// straight from the caller's buffer.
pub async fn write<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, header: &T, secret: &[u8]) -> Result<(), IpcError> {
    let json = serde_json::to_vec(header)?;
    if json.len() > MAX_HEADER {
        return Err(IpcError::HeaderTooLarge(json.len()));
    }
    if secret.len() > MAX_SECRET {
        return Err(IpcError::SecretTooLarge(secret.len()));
    }
    let mut head = Vec::with_capacity(8 + json.len());
    head.extend_from_slice(&u32::try_from(json.len()).map_err(|_| IpcError::HeaderTooLarge(json.len()))?.to_be_bytes());
    head.extend_from_slice(&u32::try_from(secret.len()).map_err(|_| IpcError::SecretTooLarge(secret.len()))?.to_be_bytes());
    head.extend_from_slice(&json);
    w.write_all(&head).await?;
    if !secret.is_empty() {
        w.write_all(secret).await?;
    }
    w.flush().await?;
    Ok(())
}

/// Reads one frame; `None` at a clean end of the channel (before a frame starts). Not
/// cancel-safe: a frame half read is lost.
pub async fn read<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> Result<Option<(T, Blob)>, IpcError> {
    let mut lengths = [0u8; 8];
    let mut have = 0;
    while have < lengths.len() {
        match r.read(&mut lengths[have..]).await? {
            0 if have == 0 => return Ok(None),
            0 => return Err(IpcError::Truncated),
            n => have += n,
        }
    }
    let [h0, h1, h2, h3, s0, s1, s2, s3] = lengths;
    let header_len = u32::from_be_bytes([h0, h1, h2, h3]) as usize;
    let secret_len = u32::from_be_bytes([s0, s1, s2, s3]) as usize;
    if header_len > MAX_HEADER {
        return Err(IpcError::HeaderTooLarge(header_len));
    }
    if secret_len > MAX_SECRET {
        return Err(IpcError::SecretTooLarge(secret_len));
    }
    let mut header = vec![0u8; header_len];
    exact(r, &mut header).await?;
    let mut secret = Blob::zeroed(secret_len);
    exact(r, &mut secret.0).await?;
    Ok(Some((serde_json::from_slice(&header)?, secret)))
}

async fn exact<R: AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> Result<(), IpcError> {
    match r.read_exact(buf).await {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(IpcError::Truncated),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello() -> ToProxy {
        ToProxy::Hello {
            cell: "cell-1".into(),
            ca_cert: "AAAA".into(),
            roots_pem: String::new(),
            listen: Ipv4Addr::UNSPECIFIED,
            ports: Ports::CELL,
            hosts: HashMap::new(),
            exempt: Vec::new(),
        }
    }

    /// A frame's secret part comes back byte for byte, outside the JSON header, and
    /// frames follow one another on the channel.
    #[tokio::test]
    async fn frames_round_trip_with_their_secret_part() {
        let mut wire = Vec::new();
        write(&mut wire, &hello(), b"\x00KEY\xffmaterial").await.unwrap();
        write(&mut wire, &FromProxy::Connections { count: 7 }, &[]).await.unwrap();
        assert!(wire.windows(13).any(|w| w == b"\x00KEY\xffmaterial"), "raw, not JSON-escaped");
        let mut r = wire.as_slice();
        let (msg, secret) = read::<_, ToProxy>(&mut r).await.unwrap().unwrap();
        assert!(matches!(msg, ToProxy::Hello { ref cell, ports: Ports::CELL, .. } if cell == "cell-1"));
        assert_eq!(secret.as_slice(), b"\x00KEY\xffmaterial");
        let (msg, secret) = read::<_, FromProxy>(&mut r).await.unwrap().unwrap();
        assert_eq!((msg, secret.len()), (FromProxy::Connections { count: 7 }, 0));
        assert!(read::<_, FromProxy>(&mut r).await.unwrap().is_none(), "a clean end");
    }

    /// A channel that ends inside a frame, and a frame over the limits, are refused.
    #[tokio::test]
    async fn truncated_and_oversized_frames_are_refused() {
        let mut wire = Vec::new();
        write(&mut wire, &hello(), b"secret").await.unwrap();
        for cut in [1, 7, 8, 20, wire.len() - 1] {
            let mut r = &wire[..cut];
            assert!(matches!(read::<_, ToProxy>(&mut r).await, Err(IpcError::Truncated)), "cut at {cut}");
        }
        let mut big = Vec::new();
        big.extend_from_slice(&(MAX_HEADER as u32 + 1).to_be_bytes());
        big.extend_from_slice(&0u32.to_be_bytes());
        assert!(matches!(read::<_, ToProxy>(&mut big.as_slice()).await, Err(IpcError::HeaderTooLarge(_))));
        let mut big = Vec::new();
        big.extend_from_slice(&2u32.to_be_bytes());
        big.extend_from_slice(&(MAX_SECRET as u32 + 1).to_be_bytes());
        assert!(matches!(read::<_, ToProxy>(&mut big.as_slice()).await, Err(IpcError::SecretTooLarge(_))));
        assert!(matches!(write(&mut Vec::new(), &hello(), &vec![0; MAX_SECRET + 1]).await, Err(IpcError::SecretTooLarge(_))));
    }
}
