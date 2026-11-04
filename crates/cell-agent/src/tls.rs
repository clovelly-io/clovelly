//! TLS for the cell API: the cell certificate, swapped in place at each lease renewal
//! so connections and streams survive it, and, for `Drain` only, an optional client
//! certificate from the control-plane CA baked into the image.

use std::fmt;
use std::io;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivateSec1KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert, ServerConfig, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_stream::wrappers::ReceiverStream;

use crate::boot::CellKey;

/// How long a client has to finish its handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("TLS: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("control-plane CA: {0}")]
    ClientCa(#[from] rustls::server::VerifierBuilderError),
}

/// The certificate the listener presents; [`CertSwap::swap`] replaces it for new
/// handshakes without touching established connections.
pub struct CertSwap(RwLock<Arc<CertifiedKey>>);

fn certified(cert: &[u8], key: &CellKey) -> Result<CertifiedKey, TlsError> {
    let mut der = key.private_sec1_der();
    let signing = rustls::crypto::aws_lc_rs::sign::any_ecdsa_type(&PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(
        der.as_slice(),
    )));
    common::dek::wipe(&mut der);
    Ok(CertifiedKey::new(vec![CertificateDer::from(cert.to_vec())], signing?))
}

impl CertSwap {
    pub fn new(cert: &[u8], key: &CellKey) -> Result<Arc<Self>, TlsError> {
        Ok(Arc::new(Self(RwLock::new(Arc::new(certified(cert, key)?)))))
    }

    /// Presents `cert` (for the same key) from the next handshake on.
    pub fn swap(&self, cert: &[u8], key: &CellKey) -> Result<(), TlsError> {
        let next = Arc::new(certified(cert, key)?);
        *self.0.write().unwrap_or_else(|p| p.into_inner()) = next;
        Ok(())
    }
}

impl fmt::Debug for CertSwap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CertSwap(..)")
    }
}

impl ResolvesServerCert for CertSwap {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0.read().unwrap_or_else(|p| p.into_inner())))
    }
}

/// A TLS 1.2/1.3 server config offering HTTP/2. With `client_cas` (DER; the image bakes
/// two while the control-plane CA rotates), a client may present a certificate from one
/// of them; one that presents any other certificate fails the handshake, and one that
/// presents none is served as anonymous.
pub fn server_config(certs: Arc<CertSwap>, client_cas: &[Vec<u8>]) -> Result<ServerConfig, TlsError> {
    let builder = ServerConfig::builder();
    let builder = if client_cas.is_empty() {
        builder.with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        for ca in client_cas {
            roots.add(CertificateDer::from(ca.clone()))?;
        }
        builder.with_client_cert_verifier(
            WebPkiClientVerifier::builder(Arc::new(roots))
                .allow_unauthenticated()
                .build()?,
        )
    };
    let mut config = builder.with_cert_resolver(certs);
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

/// Accepts connections on `listener` and completes their handshakes concurrently,
/// yielding each established stream (for tonic's `serve_with_incoming`). A failed
/// handshake is dropped: the client refused us, or we it.
pub fn incoming(
    listener: TcpListener,
    config: Arc<ServerConfig>,
) -> ReceiverStream<Result<TlsStream<TcpStream>, io::Error>> {
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(config);
        loop {
            let tcp = match listener.accept().await {
                Ok((tcp, _)) => tcp,
                Err(_) => {
                    // Out of file descriptors and the like: back off, keep serving.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let _ = tcp.set_nodelay(true);
            let (acceptor, tx) = (acceptor.clone(), tx.clone());
            tokio::spawn(async move {
                if let Ok(Ok(tls)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                    let _ = tx.send(Ok(tls)).await;
                }
            });
        }
    });
    ReceiverStream::new(rx)
}
