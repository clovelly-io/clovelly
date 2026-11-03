//! Ciphertext in Cloud Storage (templates and volumes): the control plane names where
//! the cell's sub-environment keeps its objects (`GetStorage`), and the cell reads and
//! writes them itself with its VM's service-account token from the metadata server.
//!
//! Neither the location nor the token is a security input: every object is ciphertext
//! or authenticated under keys only an unlocked cell of the sub-environment holds, so a
//! wrong location or a swapped object fails to open; it never yields plaintext.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::proto::control::GetStorageRequest;
use common::proto::control::cell_channel_client::CellChannelClient;
use serde::Deserialize;
use tokio::sync::OnceCell;
use tonic::transport::Channel;

const STORAGE: &str = "https://storage.googleapis.com";
const TOKEN: &str = "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token";

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("this cell has no control plane to ask where its ciphertext is")]
    NoControlPlane,
    #[error("GetStorage: {0}")]
    Locate(String),
    #[error("HTTP: {0}")]
    Http(#[from] reqwest::Error),
    #[error("{what}: HTTP {status}: {body}")]
    Status { what: String, status: u16, body: String },
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

/// One sub-environment's objects: `gs://<bucket>/<prefix>/<name>`.
pub struct Storage {
    http: reqwest::Client,
    bucket: String,
    prefix: String,
    token: Mutex<Option<(String, Instant)>>,
}

/// Object names hold only `a-z 0-9 - _ . /`; the JSON API wants `/` escaped.
fn encode(name: &str) -> String {
    name.replace('/', "%2F")
}

impl Storage {
    pub fn new(bucket: String, prefix: String) -> Result<Self, StorageError> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(300))
            .build()?;
        Ok(Self { http, bucket, prefix, token: Mutex::new(None) })
    }

    /// The full object name of `name`.
    pub fn object(&self, name: &str) -> String {
        format!("{}/{name}", self.prefix)
    }

    async fn bearer(&self) -> Result<String, StorageError> {
        if let Some((t, until)) = self.token.lock().unwrap_or_else(|p| p.into_inner()).as_ref()
            && Instant::now() < *until
        {
            return Ok(t.clone());
        }
        let r: TokenResponse = self
            .http
            .get(TOKEN)
            .header("Metadata-Flavor", "Google")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let until = Instant::now() + Duration::from_secs(r.expires_in.saturating_sub(60));
        *self.token.lock().unwrap_or_else(|p| p.into_inner()) = Some((r.access_token.clone(), until));
        Ok(r.access_token)
    }

    async fn fail(what: String, resp: reqwest::Response) -> StorageError {
        let status = resp.status().as_u16();
        StorageError::Status { what, status, body: resp.text().await.unwrap_or_default() }
    }

    async fn open(&self, name: &str) -> Result<Option<reqwest::Response>, StorageError> {
        let url = format!("{STORAGE}/storage/v1/b/{}/o/{}", self.bucket, encode(&self.object(name)));
        let resp = self.http.get(url).query(&[("alt", "media")]).bearer_auth(self.bearer().await?).send().await?;
        match resp.status() {
            reqwest::StatusCode::NOT_FOUND => Ok(None),
            s if s.is_success() => Ok(Some(resp)),
            _ => Err(Self::fail(format!("get {name}"), resp).await),
        }
    }

    /// Reads an object; `Ok(None)` if there is none.
    pub async fn get(&self, name: &str) -> Result<Option<Vec<u8>>, StorageError> {
        match self.open(name).await? {
            Some(resp) => Ok(Some(resp.bytes().await?.to_vec())),
            None => Ok(None),
        }
    }

    /// Streams an object to `each` as it arrives; `Ok(false)` if there is none.
    pub async fn get_each<E>(&self, name: &str, mut each: impl FnMut(&[u8]) -> Result<(), E>) -> Result<Result<bool, E>, StorageError> {
        let Some(mut resp) = self.open(name).await? else { return Ok(Ok(false)) };
        while let Some(chunk) = resp.chunk().await? {
            if let Err(e) = each(&chunk) {
                return Ok(Err(e));
            }
        }
        Ok(Ok(true))
    }

    /// Writes an object, replacing any of the same name; with `only_new`, only if none
    /// exists (returns false then).
    pub async fn put(&self, name: &str, bytes: Vec<u8>, only_new: bool) -> Result<bool, StorageError> {
        let url = format!("{STORAGE}/upload/storage/v1/b/{}/o", self.bucket);
        let object = self.object(name);
        let mut query = vec![("uploadType", "media"), ("name", object.as_str())];
        if only_new {
            query.push(("ifGenerationMatch", "0"));
        }
        let resp = self
            .http
            .post(url)
            .query(&query)
            .bearer_auth(self.bearer().await?)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(bytes)
            .send()
            .await?;
        match resp.status() {
            reqwest::StatusCode::PRECONDITION_FAILED if only_new => Ok(false),
            s if s.is_success() => Ok(true),
            _ => Err(Self::fail(format!("put {name}"), resp).await),
        }
    }

    /// Deletes an object; a missing one is not an error.
    pub async fn delete(&self, name: &str) -> Result<(), StorageError> {
        let url = format!("{STORAGE}/storage/v1/b/{}/o/{}", self.bucket, encode(&self.object(name)));
        let resp = self.http.delete(url).bearer_auth(self.bearer().await?).send().await?;
        match resp.status() {
            reqwest::StatusCode::NOT_FOUND => Ok(()),
            s if s.is_success() => Ok(()),
            _ => Err(Self::fail(format!("delete {name}"), resp).await),
        }
    }
}

/// Finds the cell's [`Storage`] through the control plane once, on first use.
pub struct Locator {
    pub client: Option<CellChannelClient<Channel>>,
    pub instance_id: u64,
    pub zone: String,
    storage: OnceCell<Arc<Storage>>,
}

impl Locator {
    pub fn new(client: Option<CellChannelClient<Channel>>, instance_id: u64, zone: String) -> Self {
        Self { client, instance_id, zone, storage: OnceCell::new() }
    }

    pub async fn storage(&self) -> Result<Arc<Storage>, StorageError> {
        self.storage
            .get_or_try_init(|| async {
                let mut client = self.client.clone().ok_or(StorageError::NoControlPlane)?;
                let s = client
                    .get_storage(GetStorageRequest { instance_id: self.instance_id, zone: self.zone.clone() })
                    .await
                    .map_err(|s| StorageError::Locate(format!("{:?}: {}", s.code(), s.message())))?
                    .into_inner();
                Ok(Arc::new(Storage::new(s.bucket, s.prefix)?))
            })
            .await
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn object_names_are_prefixed_and_escaped() {
        let s = super::Storage::new("b".into(), "ciphertext/run/staging/a".into()).unwrap();
        assert_eq!(s.object("templates/x/meta.json"), "ciphertext/run/staging/a/templates/x/meta.json");
        assert_eq!(super::encode(&s.object("v/k.json")), "ciphertext%2Frun%2Fstaging%2Fa%2Fv%2Fk.json");
    }
}
