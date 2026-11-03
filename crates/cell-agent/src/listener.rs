//! The cell API listener's port and its gRPC health service (boot step 6). The agent
//! serves both with the cell API over TLS with the certificate the verifier issued.

use common::proto::health::health_check_response::ServingStatus;
use common::proto::health::health_server::Health;
use common::proto::health::{HealthCheckRequest, HealthCheckResponse};
use tonic::{Request, Response, Status};

/// The port the cell API listens on.
pub const PORT: u16 = 443;

/// The gRPC health service: serving whenever the listener is up.
pub struct Serving;

#[tonic::async_trait]
impl Health for Serving {
    async fn check(&self, _: Request<HealthCheckRequest>) -> Result<Response<HealthCheckResponse>, Status> {
        Ok(Response::new(HealthCheckResponse {
            status: ServingStatus::Serving.into(),
        }))
    }
}
