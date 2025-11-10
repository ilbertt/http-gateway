use std::borrow::Cow;

use candid::Principal;
use ic_agent::agent::{CallResponse, Envelope, EnvelopeContent};
use ic_agent::hash_tree::Label;
use ic_agent::{Agent, AgentError, RequestId};

use crate::protocol::http::HttpProcessingError;

const HTTP_REQUEST_QUERY_METHOD_NAME: &str = "http_request_v2";
const HTTP_REQUEST_UPDATE_METHOD_NAME: &str = "http_request_update_v2";

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
        envelope: Envelope<'_>,
    ) -> Result<Vec<u8>, AgentError> {
        let envelope_bytes = envelope.encode_bytes();

        self.agent
            .query_signed(self.canister_id, envelope_bytes)
            .await
    }

    /// Performs a HTTP request over an update call. Unlike query calls, update calls must pass consensus
    /// and therefore cannot be tampered with by a malicious node.
    /// `T` and `C` are the `token` and `callback` types for the `streaming_strategy`.
    pub async fn http_request_update<'canister: 'agent>(
        &'canister self,
        call_envelope: Envelope<'_>,
        read_state_envelope: Option<Envelope<'_>>,
    ) -> Result<Vec<u8>, AgentError> {
        let envelope_bytes = call_envelope.encode_bytes();

        let response = self
            .agent
            .update_signed(self.canister_id, envelope_bytes)
            .await?;

        match response {
            CallResponse::Response(response) => Ok(response),
            CallResponse::Poll(_) => match read_state_envelope {
                Some(envelope) => {
                    let read_state_envelope_bytes = envelope.encode_bytes();

                    // TODO: verify certificate
                    let (response, _) = self
                        .agent
                        .wait_signed(
                            &call_envelope.content.to_request_id(),
                            self.canister_id,
                            read_state_envelope_bytes,
                        )
                        .await?;

                    Ok(response)
                }
                None => {
                    return Err(AgentError::TimeoutWaitingForResponse());
                }
            },
        }
    }
}

/// Construct the CBOR-encoded envelope for non-authenticated query requests
pub fn construct_query_envelope<'a>(
    canister_id: Principal,
    binary_request: Vec<u8>,
) -> Result<Envelope<'a>, HttpProcessingError> {
    use std::time::{SystemTime, UNIX_EPOCH};

    // For non-authenticated requests, use anonymous sender and set expiry
    let ingress_expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| HttpProcessingError::InvalidHeaderValue(e.to_string()))?
        .as_nanos() as u64
        + 300_000_000_000; // 5 minutes from now

    // Create the EnvelopeContent::Query variant for non-authenticated requests
    let content = EnvelopeContent::Query {
        nonce: None,
        ingress_expiry,
        sender: Principal::anonymous(),
        canister_id,
        method_name: HTTP_REQUEST_QUERY_METHOD_NAME.to_string(),
        arg: binary_request,
    };

    // Create the Envelope without signature (anonymous)
    let envelope = Envelope {
        content: Cow::Owned(content),
        sender_pubkey: None,
        sender_sig: None,
        sender_delegation: None,
    };

    Ok(envelope)
}

/// Construct the CBOR-encoded envelope for non-authenticated update requests (Call)
pub fn construct_update_envelope<'a>(
    canister_id: Principal,
    binary_request: Vec<u8>,
) -> Result<Envelope<'a>, HttpProcessingError> {
    use std::time::{SystemTime, UNIX_EPOCH};

    // For non-authenticated requests, use anonymous sender and set expiry
    let ingress_expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| HttpProcessingError::InvalidHeaderValue(e.to_string()))?
        .as_nanos() as u64
        + 300_000_000_000; // 5 minutes from now

    // Create the EnvelopeContent::Call variant for non-authenticated update requests
    let content = EnvelopeContent::Call {
        nonce: None,
        ingress_expiry,
        sender: Principal::anonymous(),
        canister_id,
        method_name: HTTP_REQUEST_UPDATE_METHOD_NAME.to_string(),
        arg: binary_request,
    };

    // Create the Envelope without signature (anonymous)
    let envelope = Envelope {
        content: Cow::Owned(content),
        sender_pubkey: None,
        sender_sig: None,
        sender_delegation: None,
    };

    Ok(envelope)
}

pub fn construct_read_state_envelope<'a>(
    request_id: RequestId,
) -> Result<Envelope<'a>, HttpProcessingError> {
    use std::time::{SystemTime, UNIX_EPOCH};

    // For non-authenticated requests, use anonymous sender and set expiry
    let ingress_expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| HttpProcessingError::InvalidHeaderValue(e.to_string()))?
        .as_nanos() as u64
        + 300_000_000_000; // 5 minutes from now

    let paths = vec![vec![
        Label::from_bytes(b"request_state"),
        request_id.signable().into(),
    ]];

    let content = EnvelopeContent::ReadState {
        ingress_expiry,
        sender: Principal::anonymous(),
        paths,
    };

    let envelope = Envelope {
        content: Cow::Owned(content),
        sender_pubkey: None,
        sender_sig: None,
        sender_delegation: None,
    };

    Ok(envelope)
}
