//! `cell-agent impostor` (test image only): a cell that has not been verified for the
//! environment, for phase 2 criterion 2. It serves TLS on the cell API port with the
//! right name, `<subenv>.<env>.cells.clovelly.internal`, under a certificate that is
//! either self-signed or issued by another environment's CA, and logs, per connection,
//! how the handshake ended and how many bytes the client sent after it. An SDK that
//! refuses the certificate leaves `app_bytes` at 0.

use std::sync::Arc;
use std::time::Duration;

use common::cellcert::{self, CellCertInfo};
use rcgen::{BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::json;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::agent::status;
use crate::listener;

/// Which certificate the impostor presents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    SelfSigned,
    OtherCa,
}

impl std::str::FromStr for Mode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        match s {
            "self-signed" => Ok(Mode::SelfSigned),
            "other-ca" => Ok(Mode::OtherCa),
            other => anyhow::bail!("unknown impostor mode {other:?}; expected self-signed or other-ca"),
        }
    }
}

/// A certificate chain and key for `name` (`<subenv>.<env>.cells.clovelly.internal`).
fn certificate(mode: Mode, name: &str) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let (subenv, env) = name
        .strip_suffix(".cells.clovelly.internal")
        .and_then(|rest| rest.split_once('.'))
        .ok_or_else(|| anyhow::anyhow!("{name:?} is not <subenv>.<env>.cells.clovelly.internal"))?;
    let info = CellCertInfo {
        quote_sha256: [0; 32],
        env: env.parse()?,
        subenv: subenv.parse()?,
        release: "clovelly-impostor".parse()?,
    };
    let mut leaf = CertificateParams::new(vec![name.to_owned()])?;
    leaf.distinguished_name.push(DnType::CommonName, name);
    leaf.custom_extensions = vec![CustomExtension::from_oid_content(&cellcert::OID_ARCS, info.to_der())];
    let leaf_key = KeyPair::generate()?;
    let chain = match mode {
        Mode::SelfSigned => vec![leaf.self_signed(&leaf_key)?.der().clone()],
        Mode::OtherCa => {
            let mut ca = CertificateParams::default();
            ca.distinguished_name.push(DnType::CommonName, "clovelly other environment CA");
            ca.distinguished_name.push(DnType::OrganizationName, "clovelly");
            ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
            let ca_key = KeyPair::generate()?;
            let ca_der = ca.self_signed(&ca_key)?.der().clone();
            let issuer = Issuer::new(ca, ca_key);
            vec![leaf.signed_by(&leaf_key, &issuer)?.der().clone(), ca_der]
        }
    };
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    Ok((chain, key))
}

/// Serves on the cell API port until killed.
pub async fn run(mode: Mode, name: &str) -> anyhow::Result<()> {
    let (chain, key) = certificate(mode, name)?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    tokio::spawn(crate::forwarded::keep_routes(Default::default(), Default::default()));
    let listener = TcpListener::bind(("0.0.0.0", listener::PORT)).await?;
    status("impostor-serving", json!({ "mode": format!("{mode:?}"), "name": name }));
    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let handshake = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await;
            let (outcome, app_bytes) = match handshake {
                Err(_) => ("timeout".to_owned(), 0),
                Ok(Err(e)) => (format!("failed: {e}"), 0),
                Ok(Ok(mut tls)) => {
                    // Count what the client sends once it has accepted us.
                    let mut buf = vec![0u8; 64 * 1024];
                    let mut total = 0usize;
                    while let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf)).await {
                        if n == 0 {
                            break;
                        }
                        total += n;
                    }
                    ("completed".to_owned(), total)
                }
            };
            println!(
                "CLOVELLY-IMPOSTOR {}",
                json!({ "peer": peer.to_string(), "handshake": outcome, "app_bytes": app_bytes })
            );
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificates_name_the_cell_and_carry_the_extension() {
        for mode in [Mode::SelfSigned, Mode::OtherCa] {
            let (chain, _) = certificate(mode, "a.staging.cells.clovelly.internal").unwrap();
            assert_eq!(chain.len(), if mode == Mode::SelfSigned { 1 } else { 2 });
        }
        assert!(certificate(Mode::SelfSigned, "nope").is_err());
    }
}
