//! Where the verifier gets the evidence it does not receive from the cell: Intel's
//! collateral (check 1 to 3), Google's host registry (check 7) and Google's firmware
//! endorsements (check 5).
//!
//! [`Sources`] is the injectable seam SPEC.md names; [`HttpSources`] is production,
//! with an optional cache. The corpus tests serve recorded or crafted files instead.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;

use common::tdx::Measurement;

pub use crate::qvl::Collateral;

/// A source could not be reached or answered with something unusable. Not a check
/// failure: the cell retries.
#[derive(Debug, thiserror::Error)]
#[error("{what}: {source}")]
pub struct SourceError {
    pub what: &'static str,
    #[source]
    pub source: Box<dyn std::error::Error + Send + Sync>,
}

impl SourceError {
    fn new(what: &'static str, source: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self {
            what,
            source: source.into(),
        }
    }
}

/// The verifier's external inputs.
pub trait Sources: Send + Sync {
    /// Intel's TCB info, QE identity and CRLs for a platform, by FMSPC (hex) and PCK
    /// CA (`platform` or `processor`). Each quote carries its own PCK chain.
    fn collateral(
        &self,
        fmspc: &str,
        ca: &str,
        now: u64,
    ) -> impl Future<Output = Result<Collateral, SourceError>> + Send;

    /// Whether Google's confidential-host-registry lists `ppid` (32 hex digits).
    fn host_registered(&self, ppid: &str, now: u64) -> impl Future<Output = Result<bool, SourceError>> + Send;

    /// Google's serialized launch endorsement for `mrtd`, or `None` when there is none.
    fn endorsement(
        &self,
        mrtd: &Measurement,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, SourceError>> + Send;
}

const HOST_REGISTRY: &str = "https://storage.googleapis.com/confidential-host-registry";
/// Intel PCS, API v4.
const PCS: &str = "https://api.trustedservices.intel.com";
/// The Intel SGX root CA's CRL distribution point (PCS has no endpoint for it).
const ROOT_CA_CRL: &str = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der";

/// Intel PCS and Google's public buckets over HTTPS. With a cache lifetime of zero
/// every unlock fetches everything ("cold").
pub struct HttpSources {
    http: reqwest::Client,
    endorsements_url: String,
    cache_secs: u64,
    collateral: Mutex<HashMap<(String, String), Collateral>>,
    registered: Mutex<HashMap<String, u64>>,
    endorsements: Mutex<HashMap<Measurement, Vec<u8>>>,
}

impl HttpSources {
    pub fn new(endorsements_url: &str, cache_secs: u64) -> Result<Self, SourceError> {
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|e| SourceError::new("HTTP client", e))?,
            endorsements_url: endorsements_url.to_owned(),
            cache_secs,
            collateral: Mutex::default(),
            registered: Mutex::default(),
            endorsements: Mutex::default(),
        })
    }

    fn fresh(&self, at: u64, now: u64) -> bool {
        now.saturating_sub(at) < self.cache_secs
    }

    /// GETs `url`, requiring success, and returns the body and the issuer chain in
    /// header `chain` (URL-encoded PEM) as DER certificates.
    async fn get_signed(
        &self,
        what: &'static str,
        url: &str,
        chain: &str,
    ) -> Result<(Vec<u8>, Vec<Vec<u8>>), SourceError> {
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| SourceError::new(what, e))?;
        let pem = resp
            .headers()
            .get(chain)
            .and_then(|v| v.to_str().ok())
            .and_then(percent_decode)
            .ok_or_else(|| SourceError::new(what, format!("no {chain} header")))?;
        let certs = common::b64::pem_blocks(&pem, "CERTIFICATE").map_err(|e| SourceError::new(what, e))?;
        let body = resp.bytes().await.map_err(|e| SourceError::new(what, e))?;
        Ok((body.to_vec(), certs))
    }

    async fn fetch_collateral(&self, fmspc: &str, ca: &str, now: u64) -> Result<Collateral, SourceError> {
        let text = |what: &'static str, b: Vec<u8>| {
            String::from_utf8(b).map_err(|e| SourceError::new(what, e))
        };
        let tcb_url = format!("{PCS}/tdx/certification/v4/tcb?fmspc={fmspc}");
        let qe_url = format!("{PCS}/tdx/certification/v4/qe/identity");
        let crl_url = format!("{PCS}/sgx/certification/v4/pckcrl?ca={ca}&encoding=der");
        let (tcb, qe, pck_crl, root_crl) = tokio::try_join!(
            self.get_signed("TCB info", &tcb_url, "TCB-Info-Issuer-Chain"),
            self.get_signed("QE identity", &qe_url, "SGX-Enclave-Identity-Issuer-Chain"),
            self.get_signed("PCK CRL", &crl_url, "SGX-PCK-CRL-Issuer-Chain"),
            self.get("root CA CRL", ROOT_CA_CRL),
        )?;
        Ok(Collateral {
            tcb_info: text("TCB info", tcb.0)?,
            tcb_info_chain: tcb.1,
            qe_identity: text("QE identity", qe.0)?,
            qe_identity_chain: qe.1,
            pck_crl: pck_crl.0,
            root_ca_crl: root_crl.ok_or_else(|| SourceError::new("root CA CRL", "not found"))?,
            fetched_at: now,
        })
    }

    async fn get(&self, what: &'static str, url: &str) -> Result<Option<Vec<u8>>, SourceError> {
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| SourceError::new(what, e))?;
        match resp.status().as_u16() {
            404 => Ok(None),
            _ => {
                let resp = resp.error_for_status().map_err(|e| SourceError::new(what, e))?;
                let body = resp.bytes().await.map_err(|e| SourceError::new(what, e))?;
                Ok(Some(body.to_vec()))
            }
        }
    }
}

/// Locks a cache map. Every write is one insert, so a poisoned lock is consistent.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Sources for HttpSources {
    async fn collateral(&self, fmspc: &str, ca: &str, now: u64) -> Result<Collateral, SourceError> {
        let key = (fmspc.to_owned(), ca.to_owned());
        if let Some(c) = lock(&self.collateral).get(&key).filter(|c| self.fresh(c.fetched_at, now)) {
            return Ok(c.clone());
        }
        let c = self.fetch_collateral(fmspc, ca, now).await?;
        lock(&self.collateral).insert(key, c.clone());
        Ok(c)
    }

    async fn host_registered(&self, ppid: &str, now: u64) -> Result<bool, SourceError> {
        if lock(&self.registered).get(ppid).is_some_and(|&at| self.fresh(at, now)) {
            return Ok(true);
        }
        let found = self
            .get("host registry", &format!("{HOST_REGISTRY}/{ppid}"))
            .await?
            .is_some();
        if found {
            lock(&self.registered).insert(ppid.to_owned(), now);
        }
        Ok(found)
    }

    async fn endorsement(&self, mrtd: &Measurement) -> Result<Option<Vec<u8>>, SourceError> {
        if self.cache_secs > 0
            && let Some(e) = lock(&self.endorsements).get(mrtd)
        {
            return Ok(Some(e.clone()));
        }
        let url = format!("{}{mrtd}.binarypb", self.endorsements_url);
        let found = self.get("Google endorsement", &url).await?;
        if let Some(e) = &found {
            lock(&self.endorsements).insert(*mrtd, e.clone());
        }
        Ok(found)
    }
}

/// Decodes `%XX` escapes (Intel sends issuer chains URL-encoded in headers).
fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            out.push(u8::from_str_radix(s.get(i + 1..i + 3)?, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    #[test]
    fn percent_decoding() {
        assert_eq!(
            super::percent_decode("-----BEGIN%20CERT%0A-----").as_deref(),
            Some("-----BEGIN CERT\n-----")
        );
        assert_eq!(super::percent_decode("%4"), None);
    }
}
