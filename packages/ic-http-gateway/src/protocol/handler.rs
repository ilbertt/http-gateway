use crate::protocol::canister::HttpRequestCanister;
use crate::protocol::http::{
    binary_to_http_response, construct_authenticated_envelope, construct_query_envelope,
    has_auth_headers, http_request_to_binary, http_request_to_binary_all_headers,
    parse_include_headers,
};
use crate::protocol::signature::Signature;
use crate::{
    CanisterRequest, CanisterResponse, HttpGatewayResponse, HttpGatewayResponseBody,
    HttpGatewayResponseMetadata,
};
use candid::Principal;
use http::{Response, StatusCode};
use http_body_util::Full;
use ic_agent::{
    agent::{RejectCode, RejectResponse},
    Agent, AgentError,
};

fn create_err_response(status_code: StatusCode, msg: &str) -> CanisterResponse {
    let mut response = Response::new(HttpGatewayResponseBody::Right(Full::from(
        msg.as_bytes().to_vec(),
    )));
    *response.status_mut() = status_code;

    response
}

pub async fn process_request(
    agent: &Agent,
    request: CanisterRequest,
    canister_id: Principal,
    _skip_verification: bool,
) -> HttpGatewayResponse {
    let canister = HttpRequestCanister::create(agent, canister_id);

    // Check if request has authentication headers
    if has_auth_headers(&request) {
        // Authenticated flow: use signed update call with filtered headers
        process_authenticated_request(&canister, request).await
    } else {
        // Non-authenticated flow: use anonymous query call with all headers
        process_query_request(&canister, request).await
    }
}

/// Process an authenticated request with signature verification
async fn process_authenticated_request(
    canister: &HttpRequestCanister<'_>,
    request: CanisterRequest,
) -> HttpGatewayResponse {
    // Parse signatures from headers
    let signature = match Signature::from_headers(request.headers()) {
        Ok(sig) => sig,
        Err(e) => {
            return HttpGatewayResponse {
                canister_response: create_err_response(
                    StatusCode::BAD_REQUEST,
                    &format!("Failed to parse signatures: {}", e),
                ),
                metadata: HttpGatewayResponseMetadata {
                    upgraded_to_update_call: false,
                    response_verification_version: None,
                    internal_error: None,
                },
            };
        }
    };

    // Parse include headers
    let include_headers = match parse_include_headers(&request) {
        Ok(headers) => headers,
        Err(e) => {
            return HttpGatewayResponse {
                canister_response: create_err_response(
                    StatusCode::BAD_REQUEST,
                    &format!("Failed to parse include headers: {}", e),
                ),
                metadata: HttpGatewayResponseMetadata {
                    upgraded_to_update_call: false,
                    response_verification_version: None,
                    internal_error: None,
                },
            };
        }
    };

    // Convert filtered HTTP request to binary representation
    let binary_request = match http_request_to_binary(&request, &include_headers) {
        Ok(binary) => binary,
        Err(e) => {
            return HttpGatewayResponse {
                canister_response: create_err_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Failed to convert request to binary: {}", e),
                ),
                metadata: HttpGatewayResponseMetadata {
                    upgraded_to_update_call: false,
                    response_verification_version: None,
                    internal_error: None,
                },
            };
        }
    };

    // Get the primary signature data (call signature for Call variant, query for Query variant)
    let signature_data = signature.primary();

    // Construct the authenticated envelope with signature information
    let envelope_bytes = match construct_authenticated_envelope(signature_data, binary_request) {
        Ok(bytes) => bytes,
        Err(e) => {
            return HttpGatewayResponse {
                canister_response: create_err_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Failed to construct authenticated envelope: {}", e),
                ),
                metadata: HttpGatewayResponseMetadata {
                    upgraded_to_update_call: false,
                    response_verification_version: None,
                    internal_error: None,
                },
            };
        }
    };

    // Send the signed envelope to the replica via update call
    let response_bytes = match canister.http_request_update(envelope_bytes).await {
        Ok(bytes) => bytes,
        Err(e) => {
            println!("http_request_update error: {:?}", e);
            return HttpGatewayResponse {
                canister_response: handle_agent_error(&e),
                metadata: HttpGatewayResponseMetadata {
                    upgraded_to_update_call: true,
                    response_verification_version: None,
                    internal_error: Some(e.into()),
                },
            };
        }
    };

    // Parse the binary response back to HTTP response
    let canister_response = match binary_to_http_response(&response_bytes) {
        Ok(response) => response,
        Err(e) => {
            return HttpGatewayResponse {
                canister_response: create_err_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Failed to parse binary response: {}", e),
                ),
                metadata: HttpGatewayResponseMetadata {
                    upgraded_to_update_call: true,
                    response_verification_version: None,
                    internal_error: None,
                },
            };
        }
    };

    HttpGatewayResponse {
        canister_response,
        metadata: HttpGatewayResponseMetadata {
            upgraded_to_update_call: true,
            response_verification_version: None,
            internal_error: None,
        },
    }
}

/// Process a non-authenticated query request
async fn process_query_request(
    canister: &HttpRequestCanister<'_>,
    request: CanisterRequest,
) -> HttpGatewayResponse {
    // Convert HTTP request to binary representation (include all headers)
    let binary_request = match http_request_to_binary_all_headers(&request) {
        Ok(binary) => binary,
        Err(e) => {
            return HttpGatewayResponse {
                canister_response: create_err_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Failed to convert request to binary: {}", e),
                ),
                metadata: HttpGatewayResponseMetadata {
                    upgraded_to_update_call: false,
                    response_verification_version: None,
                    internal_error: None,
                },
            };
        }
    };

    // Construct the anonymous query envelope
    let envelope_bytes = match construct_query_envelope(canister.canister_id(), binary_request) {
        Ok(bytes) => bytes,
        Err(e) => {
            return HttpGatewayResponse {
                canister_response: create_err_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Failed to construct query envelope: {}", e),
                ),
                metadata: HttpGatewayResponseMetadata {
                    upgraded_to_update_call: false,
                    response_verification_version: None,
                    internal_error: None,
                },
            };
        }
    };

    // Send the anonymous envelope to the replica via query call
    let response_bytes = match canister.http_request(envelope_bytes).await {
        Ok(bytes) => bytes,
        Err(e) => {
            return HttpGatewayResponse {
                canister_response: handle_agent_error(&e),
                metadata: HttpGatewayResponseMetadata {
                    upgraded_to_update_call: false,
                    response_verification_version: None,
                    internal_error: Some(e.into()),
                },
            };
        }
    };

    // Parse the binary response back to HTTP response
    let canister_response = match binary_to_http_response(&response_bytes) {
        Ok(response) => response,
        Err(e) => {
            return HttpGatewayResponse {
                canister_response: create_err_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Failed to parse binary response: {}", e),
                ),
                metadata: HttpGatewayResponseMetadata {
                    upgraded_to_update_call: false,
                    response_verification_version: None,
                    internal_error: None,
                },
            };
        }
    };

    // TODO: validate the response certification

    HttpGatewayResponse {
        canister_response,
        metadata: HttpGatewayResponseMetadata {
            upgraded_to_update_call: false,
            response_verification_version: None,
            internal_error: None,
        },
    }
}

fn handle_agent_error(error: &AgentError) -> CanisterResponse {
    match error {
        // Turn all `DestinationInvalid`s into 404
        AgentError::CertifiedReject {
            reject:
                RejectResponse {
                    reject_code: RejectCode::DestinationInvalid,
                    reject_message,
                    ..
                },
            ..
        } => create_err_response(StatusCode::NOT_FOUND, reject_message),

        // If the result is a Replica error, returns the 500 code and message. There is no information
        // leak here because a user could use `dfx` to get the same reply.
        AgentError::CertifiedReject { reject, .. } => create_err_response(
            StatusCode::BAD_GATEWAY,
            &format!(
                "Replica Error: reject code {:?}, message {}, error code {:?}",
                reject.reject_code, reject.reject_message, reject.error_code,
            ),
        ),

        AgentError::UncertifiedReject {
            reject:
                RejectResponse {
                    reject_code: RejectCode::DestinationInvalid,
                    reject_message,
                    ..
                },
            ..
        } => create_err_response(StatusCode::NOT_FOUND, reject_message),

        // If the result is a Replica error, returns the 500 code and message. There is no information
        // leak here because a user could use `dfx` to get the same reply.
        AgentError::UncertifiedReject { reject, .. } => create_err_response(
            StatusCode::BAD_GATEWAY,
            &format!(
                "Replica Error: reject code {:?}, message {}, error code {:?}",
                reject.reject_code, reject.reject_message, reject.error_code,
            ),
        ),

        AgentError::ResponseSizeExceededLimit() => create_err_response(
            StatusCode::INSUFFICIENT_STORAGE,
            "Response size exceeds limit",
        ),

        AgentError::HttpError(payload) => match StatusCode::from_u16(payload.status) {
            Ok(status) => create_err_response(status, &format!("{:?}", payload)),
            Err(_) => create_err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Received invalid status code {:?}", payload),
            ),
        },

        // Handle all other errors
        _ => create_err_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Internal Server Error: {:?}", error),
        ),
    }
}
