use crate::{CanisterRequest, CanisterResponse, HttpGatewayResponseBody};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64, Engine};
use candid::Principal;
use http::{HeaderName, HeaderValue, Response, StatusCode};
use http_body_util::Full;
use ic_agent::agent::{Envelope, EnvelopeContent};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::io::Cursor;

/// Custom header names used in the protocol
pub const IC_INCLUDE_HEADERS: &str = "x-ic-include-headers";
pub const SIGNATURE: &str = "signature";
pub const SIGNATURE_INPUT: &str = "signature-input";
pub const SIGNATURE_KEY: &str = "signature-key";

const IC_INCLUDE_HEADERS_SEPARATOR: char = ',';

/// Errors that can occur during HTTP processing
#[derive(Debug)]
pub enum HttpProcessingError {
    MissingHeader(&'static str),
    InvalidHeaderValue(String),
    Base64DecodeError(String),
    JsonParseError(String),
    BhttpEncodeError(String),
    BhttpDecodeError(String),
}

impl std::fmt::Display for HttpProcessingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingHeader(header) => write!(f, "Missing required header: {}", header),
            Self::InvalidHeaderValue(msg) => write!(f, "Invalid header value: {}", msg),
            Self::Base64DecodeError(msg) => write!(f, "Base64 decode error: {}", msg),
            Self::JsonParseError(msg) => write!(f, "JSON parse error: {}", msg),
            Self::BhttpEncodeError(msg) => write!(f, "Binary HTTP encode error: {}", msg),
            Self::BhttpDecodeError(msg) => write!(f, "Binary HTTP decode error: {}", msg),
        }
    }
}

impl std::error::Error for HttpProcessingError {}

/// The signature key structure from the client
#[derive(Debug, Deserialize, Serialize)]
pub struct SignatureKey {
    #[serde(rename = "pubKey")]
    pub pub_key: String,
}

/// Parsed authentication headers from the incoming request
#[derive(Debug)]
pub struct AuthHeaders {
    pub sender_sig: Vec<u8>,
    pub sender_pubkey: Vec<u8>,
    pub signature_input: SignatureInputData,
    pub include_headers: Vec<String>,
}

/// Parsed signature input data
#[derive(Debug)]
pub struct SignatureInputData {
    pub canister_id: Principal,
    pub method_name: String,
    pub sender: Principal,
    pub ingress_expiry: u64,
    pub nonce: Option<Vec<u8>>,
}

/// Check if the request has authentication headers
pub fn has_auth_headers(request: &CanisterRequest) -> bool {
    request.headers().contains_key(SIGNATURE)
        && request.headers().contains_key(SIGNATURE_INPUT)
        && request.headers().contains_key(SIGNATURE_KEY)
        && request.headers().contains_key(IC_INCLUDE_HEADERS)
}

/// Helper function to extract base64 value from structured field format: "sig=:base64value:"
fn extract_structured_field_base64(header_value: &str) -> Result<Vec<u8>, HttpProcessingError> {
    // Expected format: "sig=:base64value:"
    let value = header_value
        .strip_prefix("sig=:")
        .and_then(|s| s.strip_suffix(':'))
        .ok_or_else(|| {
            HttpProcessingError::InvalidHeaderValue(format!(
                "Expected format 'sig=:value:', got: {}",
                header_value
            ))
        })?;

    BASE64
        .decode(value)
        .map_err(|e| HttpProcessingError::Base64DecodeError(e.to_string()))
}

/// Helper function to extract value from structured field format: "sig=value"
fn extract_structured_field_value(header_value: &str) -> Result<&str, HttpProcessingError> {
    // Expected format: "sig=value"
    header_value.strip_prefix("sig=").ok_or_else(|| {
        HttpProcessingError::InvalidHeaderValue(format!(
            "Expected format 'sig=value', got: {}",
            header_value
        ))
    })
}

/// Parse authentication headers from the incoming HTTP request
pub fn parse_auth_headers(request: &CanisterRequest) -> Result<AuthHeaders, HttpProcessingError> {
    // Parse IC-Include-Headers
    let include_headers_str = request
        .headers()
        .get(IC_INCLUDE_HEADERS)
        .ok_or(HttpProcessingError::MissingHeader(IC_INCLUDE_HEADERS))?
        .to_str()
        .map_err(|e| HttpProcessingError::InvalidHeaderValue(e.to_string()))?;

    let include_headers: Vec<String> = include_headers_str
        .split(IC_INCLUDE_HEADERS_SEPARATOR)
        .map(|s| s.trim().to_lowercase())
        .collect();

    // Parse Signature header: format is "sig=:base64signature:"
    let signature_str = request
        .headers()
        .get(SIGNATURE)
        .ok_or(HttpProcessingError::MissingHeader(SIGNATURE))?
        .to_str()
        .map_err(|e| HttpProcessingError::InvalidHeaderValue(e.to_string()))?;

    let sender_sig = extract_structured_field_base64(signature_str)?;

    // Parse Signature-Key header: format is "sig=:base64json:"
    let signature_key_str = request
        .headers()
        .get(SIGNATURE_KEY)
        .ok_or(HttpProcessingError::MissingHeader(SIGNATURE_KEY))?
        .to_str()
        .map_err(|e| HttpProcessingError::InvalidHeaderValue(e.to_string()))?;

    let signature_key_json = extract_structured_field_base64(signature_key_str)?;

    let signature_key: SignatureKey = serde_json::from_slice(&signature_key_json)
        .map_err(|e| HttpProcessingError::JsonParseError(e.to_string()))?;

    let sender_pubkey = BASE64
        .decode(&signature_key.pub_key)
        .map_err(|e| HttpProcessingError::Base64DecodeError(e.to_string()))?;

    // Parse Signature-Input header: format is "sig=semicolon-separated-pairs"
    let signature_input_header = request
        .headers()
        .get(SIGNATURE_INPUT)
        .ok_or(HttpProcessingError::MissingHeader(SIGNATURE_INPUT))?
        .to_str()
        .map_err(|e| HttpProcessingError::InvalidHeaderValue(e.to_string()))?;

    let signature_input_str = extract_structured_field_value(signature_input_header)?;

    let mut canister_id: Option<Principal> = None;
    let mut method_name: Option<String> = None;
    let mut sender: Option<Principal> = None;
    let mut ingress_expiry: Option<u64> = None;
    let mut nonce: Option<Vec<u8>> = None;

    for pair in signature_input_str.split(';') {
        let pair = pair.trim();
        if let Some((key, value)) = pair.split_once('=') {
            let key = key.trim();
            let value = value.trim();

            match key {
                "canister_id" => {
                    canister_id = Some(
                        Principal::from_text(value)
                            .map_err(|e| HttpProcessingError::InvalidHeaderValue(e.to_string()))?,
                    );
                }
                "method_name" => {
                    method_name = Some(value.to_string());
                }
                "sender" => {
                    sender = Some(
                        Principal::from_text(value)
                            .map_err(|e| HttpProcessingError::InvalidHeaderValue(e.to_string()))?,
                    );
                }
                "ingress_expiry" => {
                    ingress_expiry = Some(
                        value
                            .parse::<u64>()
                            .map_err(|e| HttpProcessingError::InvalidHeaderValue(e.to_string()))?,
                    );
                }
                "nonce" => {
                    // Nonce might be sent as base64 or as a number
                    nonce = Some(
                        BASE64
                            .decode(value)
                            .or_else(|_| {
                                // If not base64, try parsing as a number
                                value
                                    .parse::<u64>()
                                    .map(|n| n.to_be_bytes().to_vec())
                                    .map_err(|_| base64::DecodeError::InvalidLength(value.len()))
                            })
                            .map_err(|e| HttpProcessingError::Base64DecodeError(e.to_string()))?,
                    );
                }
                _ => {} // Ignore unknown fields
            }
        }
    }

    let signature_input = SignatureInputData {
        canister_id: canister_id.ok_or(HttpProcessingError::MissingHeader(
            "canister_id in signature-input",
        ))?,
        method_name: method_name.ok_or(HttpProcessingError::MissingHeader(
            "method_name in signature-input",
        ))?,
        sender: sender.ok_or(HttpProcessingError::MissingHeader(
            "sender in signature-input",
        ))?,
        ingress_expiry: ingress_expiry.ok_or(HttpProcessingError::MissingHeader(
            "ingress_expiry in signature-input",
        ))?,
        nonce,
    };

    Ok(AuthHeaders {
        sender_sig,
        sender_pubkey,
        signature_input,
        include_headers,
    })
}

/// Convert HTTP request to binary representation using bhttp (for non-authenticated requests, includes all headers)
pub fn http_request_to_binary_all_headers(
    request: &CanisterRequest,
) -> Result<Vec<u8>, HttpProcessingError> {
    // Get all headers as lowercase for non-authenticated requests
    let include_headers: Vec<String> = request
        .headers()
        .keys()
        .map(|k| k.as_str().to_lowercase())
        .collect();

    http_request_to_binary(request, &include_headers)
}

/// Convert HTTP request to binary representation using bhttp with filtered headers
pub fn http_request_to_binary(
    request: &CanisterRequest,
    include_headers: &[String],
) -> Result<Vec<u8>, HttpProcessingError> {
    use bhttp::{Message, Mode};

    // Build the parameters for Message::request
    let method = request.method().as_str().as_bytes().to_vec();
    let scheme = request
        .uri()
        .scheme_str()
        .unwrap_or("http")
        .as_bytes()
        .to_vec();
    let authority = request
        .uri()
        .authority()
        .map(|a| a.as_str().as_bytes().to_vec())
        .unwrap_or_else(|| {
            "lqy7q-dh777-77777-aaaaq-cai.localhost:4943"
                .as_bytes()
                .to_vec()
        });
    let path = request
        .uri()
        .path_and_query()
        .map(|p| p.as_str().as_bytes().to_vec())
        .unwrap_or_else(|| b"/".to_vec());

    // Create the bhttp message
    let mut message = Message::request(method, scheme, authority, path);

    // Filter headers based on include_headers list and collect them
    let mut filtered_headers: Vec<(&HeaderName, &HeaderValue)> = request
        .headers()
        .iter()
        .filter(|(name, _)| {
            let header_name_lower = name.as_str().to_lowercase();
            include_headers.contains(&header_name_lower)
        })
        .collect();

    // Sort headers lexicographically by name (case-insensitive)
    filtered_headers.sort_by(|a, b| {
        a.0.as_str()
            .to_lowercase()
            .cmp(&b.0.as_str().to_lowercase())
    });

    // Add sorted headers to the message
    for (name, value) in filtered_headers {
        message.put_header(name.as_str().as_bytes().to_vec(), value.as_bytes().to_vec());
    }

    // Add the request body
    message.write_content(request.body());

    // Encode to binary format (known-length mode)
    let mut encoded = Vec::new();
    message
        .write_bhttp(Mode::KnownLength, &mut encoded)
        .map_err(|e| HttpProcessingError::BhttpEncodeError(e.to_string()))?;

    Ok(encoded)
}

/// Parse binary HTTP response back to CanisterResponse
pub fn binary_to_http_response(binary: &[u8]) -> Result<CanisterResponse, HttpProcessingError> {
    use bhttp::{ControlData, Message};

    // Decode the bhttp message
    let mut cursor = Cursor::new(binary);
    let message = Message::read_bhttp(&mut cursor)
        .map_err(|e| HttpProcessingError::BhttpDecodeError(e.to_string()))?;

    // Extract status code from control data
    let status_code = match message.control() {
        ControlData::Response(status) => StatusCode::from_u16((*status).into())
            .map_err(|e| HttpProcessingError::BhttpDecodeError(e.to_string()))?,
        _ => {
            return Err(HttpProcessingError::BhttpDecodeError(
                "Expected response control data, got request".to_string(),
            ))
        }
    };

    // Build HTTP response
    let mut response = Response::new(HttpGatewayResponseBody::Right(Full::from(
        message.content().to_vec(),
    )));
    *response.status_mut() = status_code;

    // Add headers
    for field in message.header().fields().iter() {
        let name = HeaderName::from_bytes(field.name())
            .map_err(|e| HttpProcessingError::BhttpDecodeError(e.to_string()))?;
        let value = HeaderValue::from_bytes(field.value())
            .map_err(|e| HttpProcessingError::BhttpDecodeError(e.to_string()))?;
        response.headers_mut().insert(name, value);
    }

    Ok(response)
}

/// Construct the CBOR-encoded envelope for authenticated requests
pub fn construct_authenticated_envelope(
    auth_headers: &AuthHeaders,
    binary_request: Vec<u8>,
) -> Result<Vec<u8>, HttpProcessingError> {
    // Create the EnvelopeContent::Call variant
    let content = EnvelopeContent::Call {
        nonce: auth_headers.signature_input.nonce.clone(),
        ingress_expiry: auth_headers.signature_input.ingress_expiry,
        sender: auth_headers.signature_input.sender,
        canister_id: auth_headers.signature_input.canister_id,
        method_name: auth_headers.signature_input.method_name.clone(),
        arg: binary_request,
    };

    // Create the Envelope with signature
    let envelope = Envelope {
        content: Cow::Owned(content),
        sender_pubkey: Some(auth_headers.sender_pubkey.clone()),
        sender_sig: Some(auth_headers.sender_sig.clone()),
        sender_delegation: None, // TODO: Support delegation chains from Internet Identity
    };

    // Use ic-agent's encode_bytes method to properly CBOR-encode the envelope
    Ok(envelope.encode_bytes())
}

/// Construct the CBOR-encoded envelope for non-authenticated query requests
pub fn construct_query_envelope(
    canister_id: Principal,
    binary_request: Vec<u8>,
) -> Result<Vec<u8>, HttpProcessingError> {
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
        method_name: "http_request".to_string(),
        arg: binary_request,
    };

    // Create the Envelope without signature (anonymous)
    let envelope = Envelope {
        content: Cow::Owned(content),
        sender_pubkey: None,
        sender_sig: None,
        sender_delegation: None,
    };

    // Use ic-agent's encode_bytes method to properly CBOR-encode the envelope
    Ok(envelope.encode_bytes())
}
