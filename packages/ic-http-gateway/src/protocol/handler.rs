use crate::protocol::canister::{
    construct_query_envelope, construct_read_state_envelope, construct_update_envelope,
    HttpRequestCanister,
};
use crate::protocol::http::{
    binary_to_certification_http_response, binary_to_http_response,
    canister_request_to_http_request, construct_authenticated_call_envelope,
    construct_authenticated_query_envelope, construct_authenticated_read_state_envelope,
    has_signature_headers, http_request_to_binary, http_request_to_binary_all_headers,
    parse_include_headers,
};
use crate::protocol::signature::Signature;
use crate::protocol::validate::validate;
use crate::{
    CanisterRequest, CanisterResponse, HttpGatewayResponse, HttpGatewayResponseBody,
    HttpGatewayResponseMetadata, CACHE_HEADER_NAME,
};
use candid::Principal;
use http::{Method, Response, StatusCode};
use http_body_util::Full;
use ic_agent::{
    agent::{RejectCode, RejectResponse},
    Agent, AgentError,
};

/// Execute a query call and process the response with verification
async fn execute_query_call<'a>(
    canister: &HttpRequestCanister<'_>,
    agent: &Agent,
    canister_id: &Principal,
    request: &CanisterRequest,
    envelope: ic_agent::agent::Envelope<'a>,
    include_headers: &[String],
    skip_verification: bool,
) -> HttpGatewayResponse {
    // Send the envelope to the replica via query call
    let response_bytes = match canister.http_request(envelope).await {
        Ok(bytes) => bytes,
        Err(e) => {
            return create_gateway_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Query call failed: {}", e),
                false,
                Some(e.into()),
            );
        }
    };

    // Verify response and apply header filtering
    match verify_and_process_response(
        agent,
        canister_id,
        request,
        include_headers,
        &response_bytes,
        skip_verification,
        false, // is_update_call = false for query requests
    ) {
        Ok((canister_response, response_verification_version)) => HttpGatewayResponse {
            canister_response,
            metadata: HttpGatewayResponseMetadata {
                upgraded_to_update_call: false,
                response_verification_version,
                internal_error: None,
            },
        },
        Err(response) => response,
    }
}

/// Execute an update call and process the response
async fn execute_update_call<'a>(
    canister: &HttpRequestCanister<'_>,
    agent: Option<&Agent>,
    canister_id: Option<&Principal>,
    request: Option<&CanisterRequest>,
    call_envelope: ic_agent::agent::Envelope<'a>,
    read_state_envelope: Option<ic_agent::agent::Envelope<'a>>,
    include_headers: Option<&[String]>,
    skip_verification: bool,
) -> HttpGatewayResponse {
    // Send the envelope to the replica via update call
    let response_bytes = match canister
        .http_request_update(call_envelope, read_state_envelope)
        .await
    {
        Ok(bytes) => bytes,
        Err(e) => {
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

    // If we have verification parameters, verify the response
    if let (Some(agent), Some(canister_id), Some(request), Some(include_headers)) =
        (agent, canister_id, request, include_headers)
    {
        match verify_and_process_response(
            agent,
            canister_id,
            request,
            include_headers,
            &response_bytes,
            skip_verification,
            true, // is_update_call = true
        ) {
            Ok((canister_response, response_verification_version)) => HttpGatewayResponse {
                canister_response,
                metadata: HttpGatewayResponseMetadata {
                    upgraded_to_update_call: true,
                    response_verification_version,
                    internal_error: None,
                },
            },
            Err(response) => response,
        }
    } else {
        // No verification for anonymous update calls
        let canister_response = match binary_to_http_response(&response_bytes) {
            Ok(response) => response,
            Err(e) => {
                return create_gateway_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to parse binary response: {}", e),
                    true,
                    None,
                );
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
}

/// Verify response and apply header filtering based on verification version
/// This is used by both authenticated and non-authenticated query requests
fn verify_and_process_response(
    agent: &Agent,
    canister_id: &Principal,
    request: &CanisterRequest,
    include_headers: &[String],
    response_bytes: &[u8],
    skip_verification: bool,
    is_update_call: bool,
) -> Result<(CanisterResponse, Option<u16>), HttpGatewayResponse> {
    // There is no need to verify the response if the request was upgraded to an update call.
    let validation_info = if !is_update_call {
        // Convert request to HttpRequest for verification
        let http_request = match canister_request_to_http_request(request, include_headers) {
            Ok(req) => req,
            Err(e) => {
                return Err(HttpGatewayResponse {
                    canister_response: create_canister_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!("Failed to convert request for verification: {}", e),
                    ),
                    metadata: HttpGatewayResponseMetadata {
                        upgraded_to_update_call: is_update_call,
                        response_verification_version: None,
                        internal_error: None,
                    },
                });
            }
        };

        // Convert binary response to HttpResponse for verification
        let http_response = match binary_to_certification_http_response(response_bytes) {
            Ok(resp) => resp,
            Err(e) => {
                return Err(HttpGatewayResponse {
                    canister_response: create_canister_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!("Failed to convert response for verification: {}", e),
                    ),
                    metadata: HttpGatewayResponseMetadata {
                        upgraded_to_update_call: is_update_call,
                        response_verification_version: None,
                        internal_error: None,
                    },
                });
            }
        };

        // Validate the response
        match validate(
            agent,
            canister_id,
            http_request,
            http_response,
            skip_verification,
        ) {
            Err(e) => {
                return Err(HttpGatewayResponse {
                    canister_response: create_canister_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!("Response verification failed: {}", e),
                    ),
                    metadata: HttpGatewayResponseMetadata {
                        upgraded_to_update_call: is_update_call,
                        response_verification_version: None,
                        internal_error: Some(e),
                    },
                });
            }
            Ok(validation_info) => validation_info,
        }
    } else {
        None
    };

    let response_verification_version = validation_info.as_ref().map(|e| e.verification_version);

    // Parse the binary response back to HTTP response
    let mut canister_response = match binary_to_http_response(response_bytes) {
        Ok(response) => response,
        Err(e) => {
            return Err(HttpGatewayResponse {
                canister_response: create_canister_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Failed to parse binary response: {}", e),
                ),
                metadata: HttpGatewayResponseMetadata {
                    upgraded_to_update_call: is_update_call,
                    response_verification_version,
                    internal_error: None,
                },
            });
        }
    };

    // Apply header filtering based on verification version
    if let Some(validation_info) = &validation_info {
        if validation_info.verification_version < 2 {
            // Status codes are not certified in v1, reject known dangerous status codes
            let status = canister_response.status();
            if status.as_u16() >= 300 && status.as_u16() < 400 {
                return Err(HttpGatewayResponse {
                    canister_response: create_canister_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Response verification v1 does not allow redirects",
                    ),
                    metadata: HttpGatewayResponseMetadata {
                        upgraded_to_update_call: is_update_call,
                        response_verification_version,
                        internal_error: None,
                    },
                });
            }

            // Headers are also not certified in v1, filter known dangerous headers
            canister_response.headers_mut().remove(CACHE_HEADER_NAME);
        } else {
            // V2+: Replace headers with certified headers if available
            if let Some(certified_http_response) = &validation_info.response {
                // Clear all headers and add only certified ones
                let headers = canister_response.headers_mut();
                headers.clear();
                for (name, value) in &certified_http_response.headers {
                    if let (Ok(header_name), Ok(header_value)) = (
                        name.parse::<http::HeaderName>(),
                        value.parse::<http::HeaderValue>(),
                    ) {
                        headers.insert(header_name, header_value);
                    }
                }
            }
        }
    } else {
        // If there is no validation info, that means we've skipped verification,
        // this should only happen for raw domains.
        return Err(HttpGatewayResponse {
            canister_response: create_canister_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Skipping response verification for raw domains is not allowed",
            ),
            metadata: HttpGatewayResponseMetadata {
                upgraded_to_update_call: is_update_call,
                response_verification_version,
                internal_error: None,
            },
        });
    }

    Ok((canister_response, response_verification_version))
}

pub async fn process_request(
    agent: &Agent,
    request: CanisterRequest,
    canister_id: Principal,
    skip_verification: bool,
) -> HttpGatewayResponse {
    let canister = HttpRequestCanister::create(agent, canister_id);

    // First, check if request has signature headers
    if has_signature_headers(&request) {
        // Authenticated flow: parse signature to determine query vs update
        process_authenticated_request(&canister, agent, request, canister_id, skip_verification)
            .await
    } else {
        // Non-authenticated flow: use HTTP method to determine query vs update
        // GET -> query call, otherwise -> update call
        if request.method() == Method::GET {
            process_non_auth_query_request(
                &canister,
                agent,
                request,
                canister_id,
                skip_verification,
            )
            .await
        } else {
            process_non_auth_update_request(&canister, request).await
        }
    }
}

/// Process an authenticated request with signature verification
/// Determines query vs update based on signature type (Signature::Query -> query, Signature::Call -> update)
async fn process_authenticated_request(
    canister: &HttpRequestCanister<'_>,
    agent: &Agent,
    request: CanisterRequest,
    canister_id: Principal,
    skip_verification: bool,
) -> HttpGatewayResponse {
    // Parse signatures from headers
    let signature = match Signature::from_headers(request.headers()) {
        Ok(sig) => sig,
        Err(e) => {
            return create_gateway_error_response(
                StatusCode::BAD_REQUEST,
                format!("Failed to parse signatures: {}", e),
                false,
                None,
            );
        }
    };

    // Parse include headers
    let include_headers = match parse_include_headers(&request) {
        Ok(headers) => headers,
        Err(e) => {
            return create_gateway_error_response(
                StatusCode::BAD_REQUEST,
                format!("Failed to parse include headers: {}", e),
                false,
                None,
            );
        }
    };

    // Convert filtered HTTP request to binary representation
    let binary_request = match http_request_to_binary(&request, &include_headers) {
        Ok(binary) => binary,
        Err(e) => {
            return create_gateway_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to convert request to binary: {}", e),
                false,
                None,
            );
        }
    };

    // Determine call type based on signature variant
    match &signature {
        Signature::Query { query } => {
            // Authenticated query: use query envelope and query call
            let envelope_bytes = match construct_authenticated_query_envelope(query, binary_request)
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    return create_gateway_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to construct authenticated query envelope: {}", e),
                        false,
                        None,
                    );
                }
            };

            execute_query_call(
                canister,
                agent,
                &canister_id,
                &request,
                envelope_bytes,
                &include_headers,
                skip_verification,
            )
            .await
        }
        Signature::Call {
            call, read_state, ..
        } => {
            // Authenticated update: use call envelope and update call
            let call_envelope = match construct_authenticated_call_envelope(call, binary_request) {
                Ok(envelope) => envelope,
                Err(e) => {
                    return create_gateway_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to construct authenticated envelope: {}", e),
                        true,
                        None,
                    );
                }
            };

            let read_state_envelope = if let Some(read_state) = read_state {
                match construct_authenticated_read_state_envelope(
                    read_state,
                    call_envelope.content.to_request_id(),
                ) {
                    Ok(envelope) => Some(envelope),
                    Err(e) => {
                        return create_gateway_error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!(
                                "Failed to construct authenticated read state envelope: {}",
                                e
                            ),
                            true,
                            None,
                        );
                    }
                }
            } else {
                None
            };

            execute_update_call(
                canister,
                Some(agent),
                Some(&canister_id),
                Some(&request),
                call_envelope,
                read_state_envelope,
                Some(&include_headers),
                skip_verification,
            )
            .await
        }
    }
}

/// Process a non-authenticated query request (GET requests)
async fn process_non_auth_query_request(
    canister: &HttpRequestCanister<'_>,
    agent: &Agent,
    request: CanisterRequest,
    canister_id: Principal,
    skip_verification: bool,
) -> HttpGatewayResponse {
    // Get all headers for non-authenticated requests
    let include_headers: Vec<String> = request
        .headers()
        .keys()
        .map(|k| k.as_str().to_lowercase())
        .collect();

    // Convert HTTP request to binary representation (include all headers)
    let binary_request = match http_request_to_binary_all_headers(&request) {
        Ok(binary) => binary,
        Err(e) => {
            return create_gateway_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to convert request to binary: {}", e),
                false,
                None,
            );
        }
    };

    // Construct the anonymous query envelope
    let query_envelope = match construct_query_envelope(canister.canister_id(), binary_request) {
        Ok(envelope) => envelope,
        Err(e) => {
            return create_gateway_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to construct query envelope: {}", e),
                false,
                None,
            );
        }
    };

    execute_query_call(
        canister,
        agent,
        &canister_id,
        &request,
        query_envelope,
        &include_headers,
        skip_verification,
    )
    .await
}

/// Process a non-authenticated update request (non-GET requests)
async fn process_non_auth_update_request(
    canister: &HttpRequestCanister<'_>,
    request: CanisterRequest,
) -> HttpGatewayResponse {
    // Convert HTTP request to binary representation (include all headers)
    let binary_request = match http_request_to_binary_all_headers(&request) {
        Ok(binary) => binary,
        Err(e) => {
            return create_gateway_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to convert request to binary: {}", e),
                true,
                None,
            );
        }
    };

    // Construct the anonymous update envelope
    let call_envelope = match construct_update_envelope(canister.canister_id(), binary_request) {
        Ok(envelope) => envelope,
        Err(e) => {
            return create_gateway_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to construct update envelope: {}", e),
                true,
                None,
            );
        }
    };

    let read_state_envelope =
        match construct_read_state_envelope(call_envelope.content.to_request_id()) {
            Ok(envelope) => Some(envelope),
            Err(e) => {
                return create_gateway_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to construct read state envelope: {}", e),
                    true,
                    None,
                );
            }
        };

    execute_update_call(
        canister,
        None, // No verification for anonymous update calls
        None,
        None,
        call_envelope,
        read_state_envelope,
        None,
        false,
    )
    .await
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
        } => create_canister_error_response(StatusCode::NOT_FOUND, reject_message),

        // If the result is a Replica error, returns the 500 code and message. There is no information
        // leak here because a user could use `dfx` to get the same reply.
        AgentError::CertifiedReject { reject, .. } => create_canister_error_response(
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
        } => create_canister_error_response(StatusCode::NOT_FOUND, reject_message),

        // If the result is a Replica error, returns the 500 code and message. There is no information
        // leak here because a user could use `dfx` to get the same reply.
        AgentError::UncertifiedReject { reject, .. } => create_canister_error_response(
            StatusCode::BAD_GATEWAY,
            &format!(
                "Replica Error: reject code {:?}, message {}, error code {:?}",
                reject.reject_code, reject.reject_message, reject.error_code,
            ),
        ),

        AgentError::ResponseSizeExceededLimit() => create_canister_error_response(
            StatusCode::INSUFFICIENT_STORAGE,
            "Response size exceeds limit",
        ),

        AgentError::HttpError(payload) => match StatusCode::from_u16(payload.status) {
            Ok(status) => create_canister_error_response(status, &format!("{:?}", payload)),
            Err(_) => create_canister_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Received invalid status code {:?}", payload),
            ),
        },

        // Handle all other errors
        _ => create_canister_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Internal Server Error: {:?}", error),
        ),
    }
}

fn create_canister_error_response(status_code: StatusCode, msg: &str) -> CanisterResponse {
    let mut response = Response::new(HttpGatewayResponseBody::Right(Full::from(
        msg.as_bytes().to_vec(),
    )));
    *response.status_mut() = status_code;

    response
}

fn create_gateway_error_response(
    status_code: StatusCode,
    message: String,
    upgraded_to_update_call: bool,
    internal_error: Option<crate::HttpGatewayError>,
) -> HttpGatewayResponse {
    HttpGatewayResponse {
        canister_response: create_canister_error_response(status_code, &message),
        metadata: HttpGatewayResponseMetadata {
            upgraded_to_update_call,
            response_verification_version: None,
            internal_error,
        },
    }
}
