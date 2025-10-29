use candid::Principal;
use ic_agent::agent::CallResponse;
use ic_agent::{Agent, AgentError};

/// A canister that can serve a HTTP request.
#[derive(Debug, Clone)]
pub struct HttpRequestCanister<'agent> {
    agent: &'agent Agent,
    canister_id: Principal,
}

impl<'agent> HttpRequestCanister<'agent> {
    /// Create an instance of a `HttpRequestCanister` interface pointing to the specified Canister ID.
    pub fn create(agent: &'agent Agent, canister_id: Principal) -> Self {
        Self { agent, canister_id }
    }

    pub fn canister_id(&self) -> Principal {
        self.canister_id
    }

    pub async fn http_request<'canister: 'agent>(
        &'canister self,
        envelope_bytes: Vec<u8>,
    ) -> Result<Vec<u8>, AgentError> {
        self.agent
            .query_signed(self.canister_id, envelope_bytes)
            .await
    }

    /// Performs a HTTP request over an update call. Unlike query calls, update calls must pass consensus
    /// and therefore cannot be tampered with by a malicious node.
    /// `T` and `C` are the `token` and `callback` types for the `streaming_strategy`.
    pub async fn http_request_update<'canister: 'agent>(
        &'canister self,
        envelope_bytes: Vec<u8>,
    ) -> Result<Vec<u8>, AgentError> {
        let response = self
            .agent
            .update_signed(self.canister_id, envelope_bytes)
            .await?;

        match response {
            CallResponse::Response(response) => Ok(response),
            CallResponse::Poll(_) => Err(AgentError::InvalidReplicaStatus),
        }
    }
}
