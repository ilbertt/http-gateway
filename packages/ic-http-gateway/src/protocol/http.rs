use crate::protocol::signature::{
    SignatureData, SignatureInputData, SIGNATURE_HEADER_NAME, SIGNATURE_INPUT_HEADER_NAME,
    SIGNATURE_KEY_HEADER_NAME,
};
use crate::{CanisterRequest, CanisterResponse, HttpGatewayResponseBody};
use candid::Principal;
use http::{HeaderName, HeaderValue, Response, StatusCode};
use http_body_util::Full;
use ic_agent::agent::{Envelope, EnvelopeContent};
use ic_agent::hash_tree::Label;
use ic_agent::RequestId;
use std::borrow::Cow;
use std::io::Cursor;

/// Custom header names used in the protocol
const IC_INCLUDE_HEADERS: &str = "ic-include-headers";

const IC_INCLUDE_HEADERS_SEPARATOR: char = ',';

/// Errors that can occur during HTTP processing
#[derive(Debug)]
#[allow(dead_code)]
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

/// Check if the request has authentication headers
pub fn has_auth_headers(request: &CanisterRequest) -> bool {
    request.headers().contains_key(SIGNATURE_HEADER_NAME)
        && request.headers().contains_key(SIGNATURE_INPUT_HEADER_NAME)
        && request.headers().contains_key(SIGNATURE_KEY_HEADER_NAME)
        && request.headers().contains_key(IC_INCLUDE_HEADERS)
}

/// Parse the IC-Include-Headers header value
pub fn parse_include_headers(
    request: &CanisterRequest,
) -> Result<Vec<String>, HttpProcessingError> {
    let include_headers_str = request
        .headers()
        .get(IC_INCLUDE_HEADERS)
        .ok_or(HttpProcessingError::MissingHeader(IC_INCLUDE_HEADERS))?
        .to_str()
        .map_err(|e| HttpProcessingError::InvalidHeaderValue(e.to_string()))?;

    Ok(include_headers_str
        .split(IC_INCLUDE_HEADERS_SEPARATOR)
        .map(|s| s.trim().to_lowercase())
        .collect())
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

/// Construct the CBOR-encoded envelope for authenticated update requests (Call)
pub fn construct_authenticated_call_envelope(
    signature_data: &'_ SignatureData,
    binary_request: Vec<u8>,
) -> Result<Envelope<'_>, HttpProcessingError> {
    let SignatureInputData::Call {
        canister_id,
        method_name,
        sender,
        ingress_expiry,
        nonce,
    } = signature_data.signature_input.clone()
    else {
        return Err(HttpProcessingError::InvalidHeaderValue(
            "Signature input must be a call".to_string(),
        ));
    };

    // Create the EnvelopeContent::Call variant
    let content = EnvelopeContent::Call {
        canister_id,
        method_name,
        sender,
        ingress_expiry,
        nonce,
        arg: binary_request,
    };

    // Create the Envelope with signature
    let envelope = Envelope {
        content: Cow::Owned(content),
        sender_pubkey: Some(signature_data.sender_pubkey.clone()),
        sender_sig: Some(signature_data.sender_sig.clone()),
        sender_delegation: None, // TODO: Support delegation chains from Internet Identity
    };

    Ok(envelope)
}

/// Construct the CBOR-encoded envelope for authenticated read_state requests (ReadState)
pub fn construct_authenticated_read_state_envelope(
    signature_data: &'_ SignatureData,
    request_id: RequestId,
) -> Result<Envelope<'_>, HttpProcessingError> {
    let SignatureInputData::ReadState {
        ingress_expiry,
        sender,
        nonce: _, // Not used in the read_state envelope
    } = signature_data.signature_input.clone()
    else {
        return Err(HttpProcessingError::InvalidHeaderValue(
            "Signature input must be a read_state".to_string(),
        ));
    };

    let paths = vec![vec![
        Label::from_bytes(b"request_state"),
        request_id.signable().into(),
    ]];

    // Create the EnvelopeContent::ReadState variant
    let content = EnvelopeContent::ReadState {
        ingress_expiry,
        sender,
        paths,
    };

    // Create the Envelope with signature
    let envelope = Envelope {
        content: Cow::Owned(content),
        sender_pubkey: Some(signature_data.sender_pubkey.clone()),
        sender_sig: Some(signature_data.sender_sig.clone()),
        sender_delegation: None, // TODO: Support delegation chains from Internet Identity
    };

    Ok(envelope)
}

/// Construct the CBOR-encoded envelope for authenticated query requests (Query)
pub fn construct_authenticated_query_envelope(
    signature_data: &'_ SignatureData,
    binary_request: Vec<u8>,
) -> Result<Envelope<'_>, HttpProcessingError> {
    // Extract fields from SignatureInputData::Query variant
    let SignatureInputData::Query {
        canister_id,
        method_name,
        sender,
        ingress_expiry,
        nonce,
    } = signature_data.signature_input.clone()
    else {
        return Err(HttpProcessingError::InvalidHeaderValue(
            "Signature input must be a query".to_string(),
        ));
    };

    // Create the EnvelopeContent::Query variant
    let content = EnvelopeContent::Query {
        nonce,
        ingress_expiry,
        sender,
        canister_id,
        method_name,
        arg: binary_request,
    };

    // Create the Envelope with signature
    let envelope = Envelope {
        content: Cow::Owned(content),
        sender_pubkey: Some(signature_data.sender_pubkey.clone()),
        sender_sig: Some(signature_data.sender_sig.clone()),
        sender_delegation: None, // TODO: Support delegation chains from Internet Identity
    };

    Ok(envelope)
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
        method_name: "http_request_update".to_string(),
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
