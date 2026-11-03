//! The verifier's gRPC API over TLS, as the cell calls it.

use std::time::Duration;

use common::evidence::{Evidence, Nonce};
use common::ids::EnvId;
use common::proto::verifier::verifier_client::VerifierClient;
use common::ids::SubenvId;
use common::proto::verifier::{AppendReceiptRequest, GetCaRequest, GetNonceRequest, GetPolicyRequest, LogRecord, UnlockRequest};
use tonic::transport::{Channel, ClientTlsConfig};

use crate::boot::{ApiError, Granted, VerifierApi};

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("verifier URL: {0}")]
    Uri(#[from] tonic::codegen::http::uri::InvalidUri),
    #[error(transparent)]
    Transport(#[from] tonic::transport::Error),
}

/// A lazily connected client: connection trouble surfaces per call, as
/// [`ApiError::Unavailable`], so the boot loop retries it.
#[derive(Clone)]
pub struct GrpcVerifier {
    client: VerifierClient<Channel>,
}

impl GrpcVerifier {
    /// `url` is the verifier's HTTPS URL; its certificate must chain to a system root.
    /// Call it inside a Tokio runtime (`block_on` or `Runtime::enter`): the channel
    /// spawns its worker task there, and panics without one.
    pub fn new(url: &str) -> Result<Self, ConnectError> {
        let channel = Channel::from_shared(url.to_owned())?
            .tls_config(ClientTlsConfig::new().with_native_roots())?
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .connect_lazy();
        Ok(Self {
            client: VerifierClient::new(channel),
        })
    }

    /// The environment CA certificate (DER).
    pub async fn ca(&mut self, env: &EnvId) -> Result<Vec<u8>, ApiError> {
        let resp = self
            .client
            .get_ca(GetCaRequest {
                env_id: env.to_string(),
            })
            .await
            .map_err(classify)?;
        Ok(resp.into_inner().ca_cert)
    }
}

/// `PERMISSION_DENIED` with "check N" is a refusal; anything else may pass.
fn classify(s: tonic::Status) -> ApiError {
    if s.code() == tonic::Code::PermissionDenied
        && let Some(n) = s.message().strip_prefix("check ").and_then(|n| n.parse().ok())
    {
        return ApiError::Refused(n);
    }
    ApiError::Unavailable(format!("{:?}: {}", s.code(), s.message()))
}

impl VerifierApi for GrpcVerifier {
    async fn nonce(&mut self, env: &EnvId) -> Result<Nonce, ApiError> {
        let resp = self
            .client
            .get_nonce(GetNonceRequest {
                env_id: env.to_string(),
            })
            .await
            .map_err(classify)?;
        Nonce::try_from(resp.into_inner().nonce.as_slice())
            .map_err(|e| ApiError::Unavailable(e.to_string()))
    }

    async fn unlock(&mut self, evidence: &Evidence) -> Result<Granted, ApiError> {
        let resp = self
            .client
            .unlock(UnlockRequest {
                evidence: Some(evidence.into()),
            })
            .await
            .map_err(classify)?
            .into_inner();
        Ok(Granted {
            cell_cert: resp.cell_cert,
            wrapped_dek: resp.wrapped_env_dek,
            policy_bundle: resp.policy_bundle,
            policy_sig: resp.policy_sig,
            release_valid_until: resp.release_valid_until,
            policy_key: resp.policy_key,
        })
    }
}

impl GrpcVerifier {
    /// The sub-environment's current policy bundle and its detached JWS.
    pub async fn policy(&mut self, env: &EnvId, subenv: &SubenvId) -> Result<(Vec<u8>, String), ApiError> {
        let r = self
            .client
            .get_policy(GetPolicyRequest {
                env_id: env.to_string(),
                subenv_id: subenv.to_string(),
            })
            .await
            .map_err(classify)?
            .into_inner();
        Ok((r.policy_bundle, r.policy_sig))
    }
}

impl GrpcVerifier {
    /// Appends records to the customer's receipt log; the error is for the cell's log.
    pub async fn append_receipts(&mut self, records: Vec<LogRecord>) -> Result<(), String> {
        self.client
            .append_receipt(AppendReceiptRequest { records })
            .await
            .map(|_| ())
            .map_err(|s| format!("{:?}: {}", s.code(), s.message()))
    }
}
