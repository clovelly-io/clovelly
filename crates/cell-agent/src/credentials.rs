//! Credentials at sandbox start (SPEC.md "Credential substitution"): the cell fetches
//! the sealed credentials its policy's adapters name from the control plane (ciphertext
//! only), opens them under the sub-environment DEK and hands them to the egress proxy
//! for the new sandbox. A credential is released only for the destination and adapter
//! type it was sealed for, and only if the policy uses it there.
//!
//! A credential that is not stored is not released (requests carry the placeholder,
//! which the destination refuses); one that does not open, which only tampering
//! explains, refuses the create.

use std::collections::HashMap;
use std::sync::Arc;

use common::bundle::{HostName, Policy};
use common::cred::{self, AdapterType, CredError, CredName, Sealed};
use common::dek::Dek;
use common::ids::{EnvId, SubenvId, Zone};
use common::proto::control::FetchCredentialsRequest;
use common::proto::control::cell_channel_client::CellChannelClient;
use egress_proxy::Credential;
use serde_json::json;
use tonic::transport::Channel;

use crate::agent::status;

#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("the policy names credentials but this cell has no control plane to fetch them from")]
    NoControlPlane,
    #[error("the lease has no DEK")]
    NoKey,
    #[error("fetching credentials: {0}")]
    Fetch(String),
    #[error("credential {name}: {source}")]
    Open { name: String, source: CredError },
}

/// What a sandbox is given: the credentials, and their names for its receipt.
#[derive(Default)]
pub struct Released {
    pub credentials: HashMap<CredName, Credential>,
    pub names: Vec<String>,
}

/// Fetches sealed credentials for this cell's sub-environment.
pub struct Store {
    pub client: Option<CellChannelClient<Channel>>,
    pub instance_id: u64,
    pub zone: Zone,
    pub env: EnvId,
    pub subenv: SubenvId,
}

impl Store {
    /// The credentials `policy` uses, opened with `dek`.
    pub async fn release(&self, policy: &Policy, dek: Option<Arc<Dek>>) -> Result<Released, CredentialError> {
        let wanted = policy.credentials();
        if wanted.is_empty() {
            return Ok(Released::default());
        }
        let dek = dek.ok_or(CredentialError::NoKey)?;
        let mut client = self.client.clone().ok_or(CredentialError::NoControlPlane)?;
        let mut names: Vec<String> = wanted.iter().map(|(n, _, _)| n.to_string()).collect();
        names.dedup();
        let resp = client
            .fetch_credentials(FetchCredentialsRequest {
                instance_id: self.instance_id,
                zone: self.zone.to_string(),
                names,
            })
            .await
            .map_err(|s| CredentialError::Fetch(format!("{:?}: {}", s.code(), s.message())))?
            .into_inner();
        let sealed = resp.credentials.into_iter().map(|c| (c.name, c.sealed)).collect();
        open_all(&dek, &self.env, &self.subenv, &wanted, sealed)
    }
}

/// Opens each sealed credential and keeps those whose binding the policy uses.
pub fn open_all(
    dek: &Dek,
    env: &EnvId,
    subenv: &SubenvId,
    wanted: &[(CredName, HostName, AdapterType)],
    sealed: Vec<(String, Vec<u8>)>,
) -> Result<Released, CredentialError> {
    let mut out = Released::default();
    for (name, bytes) in sealed {
        let open_err = |source| CredentialError::Open { name: name.clone(), source };
        let s = Sealed::from_json(&bytes).map_err(open_err)?;
        let (binding, secret) = cred::open(dek, env, subenv, &s).map_err(open_err)?;
        let used = wanted
            .iter()
            .any(|(n, h, a)| *n == binding.name && *h == binding.destination && *a == binding.adapter);
        if binding.name.as_str() != name || !used {
            status(
                "credential-not-released",
                json!({ "name": name, "destination": binding.destination.as_str(), "adapter": binding.adapter.as_str(),
                        "why": "the policy does not use it for that destination and adapter" }),
            );
            continue;
        }
        out.names.push(name);
        out.credentials.insert(binding.name.clone(), Credential { binding, secret });
    }
    out.names.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard;
    use common::cred::Binding;
    use common::ids::SandboxId;
    use egress_proxy::{SandboxEgress, testing};
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn ids() -> (EnvId, SubenvId) {
        ("staging".parse().unwrap(), "a".parse().unwrap())
    }

    fn seal(dek: &Dek, name: &str, dest: &str, adapter: AdapterType, secret: &[u8]) -> (String, Vec<u8>) {
        let (env, sub) = ids();
        let b = Binding {
            name: name.parse().unwrap(),
            adapter,
            destination: dest.parse().unwrap(),
        };
        (name.to_owned(), cred::seal(dek, &env, &sub, &b, secret).unwrap().to_json())
    }

    fn wanted(name: &str, dest: &str) -> Vec<(CredName, HostName, AdapterType)> {
        vec![(name.parse().unwrap(), dest.parse().unwrap(), AdapterType::Bearer)]
    }

    #[test]
    fn only_credentials_bound_as_the_policy_uses_them_are_released() {
        let (env, sub) = ids();
        let dek = Dek::from_bytes([9; 32]);
        let w = wanted("svc", "api.example.com");
        let ok = seal(&dek, "svc", "api.example.com", AdapterType::Bearer, b"k");
        assert_eq!(open_all(&dek, &env, &sub, &w, vec![ok.clone()]).unwrap().names, vec!["svc"]);
        let elsewhere = seal(&dek, "svc", "evil.example.com", AdapterType::Bearer, b"k");
        assert!(open_all(&dek, &env, &sub, &w, vec![elsewhere]).unwrap().credentials.is_empty());
        let retyped = seal(&dek, "svc", "api.example.com", AdapterType::Query, b"k");
        assert!(open_all(&dek, &env, &sub, &w, vec![retyped]).unwrap().credentials.is_empty());
        let mut tampered = ok;
        tampered.1 = String::from_utf8(tampered.1).unwrap().replace("\"ciphertext\":\"", "\"ciphertext\":\"AA").into_bytes();
        assert!(matches!(open_all(&dek, &env, &sub, &w, vec![tampered]), Err(CredentialError::Open { .. })));
        let other_dek = Dek::from_bytes([8; 32]);
        let wrong_key = seal(&other_dek, "svc", "api.example.com", AdapterType::Bearer, b"k");
        assert!(open_all(&dek, &env, &sub, &w, vec![wrong_key]).is_err());
    }

    /// A destination that reports whether a request carried the 32-byte secret whose
    /// SHA-256 is `want`. It holds only the hash and reads into one buffer that it
    /// wipes, so the test's own copies are not counted as leaks.
    async fn destination(want: [u8; 32]) -> (u16, tokio::sync::oneshot::Receiver<bool>) {
        let sha = |w: &[u8]| aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, w);
        let l = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let mut n = 0;
            while !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                let r = s.read(&mut buf[n..]).await.unwrap();
                if r == 0 {
                    break;
                }
                n += r;
            }
            let seen = buf[..n].windows(32).any(|w| sha(w).as_ref() == want);
            common::dek::wipe(&mut buf);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
            let _ = tx.send(seen);
        });
        (port, rx)
    }

    /// Criterion 12: a real credential is zeroised at sandbox end. Under the guard
    /// allocator, a credential sealed, fetched, opened, substituted into a request by
    /// the proxy and released at the sandbox's end leaves no freed block holding it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn credentials_are_zeroised_at_sandbox_end_under_the_guard_allocator() {
        let mut raw = [0u8; 16];
        aws_lc_rs::rand::fill(&mut raw).unwrap();
        let secret: [u8; 32] = common::hex(&raw).into_bytes().try_into().unwrap();
        let w = guard::watch(&secret);
        let (env, sub) = ids();
        let dek = Dek::from_bytes([5; 32]);

        let (proxy, connect) = testing::proxy(&["dest.test"]).await;
        let want: [u8; 32] = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &secret).as_ref().try_into().unwrap();
        let (port, seen) = destination(want).await;
        let policy = testing::policy(&format!(
            r#"[{{"host":"dest.test","port":{port},"adapter":{{"type":"bearer","credential":"svc"}}}}]"#
        ));
        let sealed = seal(&dek, "svc", "dest.test", AdapterType::Bearer, &secret);
        let released = open_all(&dek, &env, &sub, &policy.credentials(), vec![sealed]).unwrap();
        assert_eq!(released.names, vec!["svc"]);
        proxy.register(Ipv4Addr::LOCALHOST, SandboxEgress::new(SandboxId::generate(), policy, released.credentials));

        let target = format!("dest.test:{port}");
        let answer = testing::through(
            connect,
            &target,
            &format!("GET / HTTP/1.1\r\nHost: {target}\r\nAuthorization: Bearer clovelly://cred/svc\r\n\r\n"),
        )
        .await
        .unwrap();
        assert!(answer.contains("200 OK"), "{answer}");
        assert!(seen.await.unwrap(), "the destination received the real credential");

        let log = proxy.unregister(Ipv4Addr::LOCALHOST).await.unwrap();
        assert!(log.lines.iter().any(|l| l.contains(r#""credential":"svc""#)), "{:?}", log.lines);
        drop(dek);
        assert_eq!(w.leaks(), 0, "no freed block held the credential");
    }
}
