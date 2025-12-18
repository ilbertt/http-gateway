use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64, Engine};
use candid::Principal;
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Custom header names used in the signature protocol
pub const SIGNATURE_HEADER_NAME: &str = "signature";
pub const SIGNATURE_INPUT_HEADER_NAME: &str = "signature-input";
pub const SIGNATURE_KEY_HEADER_NAME: &str = "signature-key";

const SIGNATURES_SEPARATOR: char = ',';
const SIGNATURE_INPUTS_SEPARATOR: char = ';';
const SIGNATURE_INPUT_VALUE_START_DELIMITER: char = '(';
const SIGNATURE_INPUT_VALUE_END_DELIMITER: char = ')';
const SIGNATURE_INPUT_PARAMETERS_SEPARATOR: char = ';';
const SIGNATURE_INPUT_KEY_VALUE_SEPARATOR: char = '=';
const SIGNATURE_INPUT_INCLUDE_HEADERS_SEPARATOR: char = ',';

/// Errors that can occur during signature parsing
#[derive(Debug)]
pub enum SignatureParseError {
    MissingHeader(&'static str),
    InvalidHeaderValue(String),
    Base64DecodeError(String),
    JsonParseError(String),
    InvalidSignatureName(String),
    MissingRequiredSignature(String),
}

impl std::fmt::Display for SignatureParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingHeader(header) => write!(f, "Missing required header: {}", header),
            Self::InvalidHeaderValue(msg) => write!(f, "Invalid header value: {}", msg),
            Self::Base64DecodeError(msg) => write!(f, "Base64 decode error: {}", msg),
            Self::JsonParseError(msg) => write!(f, "JSON parse error: {}", msg),
            Self::InvalidSignatureName(name) => write!(f, "Invalid signature name: {}", name),
            Self::MissingRequiredSignature(name) => {
                write!(f, "Missing required signature: {}", name)
            }
        }
    }
}

impl std::error::Error for SignatureParseError {}

/// The signature key structure from the client
#[derive(Debug, Deserialize, Serialize)]
struct SignatureKey {
    #[serde(rename = "pubKey")]
    pub_key: String,
}

/// Parsed signature input data
#[derive(Debug, Clone)]
pub enum SignatureInputData {
    Call {
        canister_id: Principal,
        method_name: String,
        sender: Principal,
        ingress_expiry: u64,
        nonce: Option<Vec<u8>>,
        include_headers: Vec<String>,
    },
    ReadState {
        ingress_expiry: u64,
        sender: Principal,
        #[allow(dead_code)]
        nonce: Option<Vec<u8>>, // Not used in the read_state envelope
    },
    Query {
        canister_id: Principal,
        method_name: String,
        sender: Principal,
        ingress_expiry: u64,
        nonce: Option<Vec<u8>>,
        include_headers: Vec<String>,
    },
}

impl SignatureInputData {
    pub fn call_from_str(value: &str) -> Result<Self, SignatureParseError> {
        let mut canister_id = None;
        let mut method_name = None;
        let mut sender = None;
        let mut ingress_expiry = None;
        let mut nonce = None;
        let mut include_headers = None;

        for pair in value.split(SIGNATURE_INPUT_PARAMETERS_SEPARATOR) {
            let pair = pair.trim();
            if let Some((key, value)) = pair.split_once(SIGNATURE_INPUT_KEY_VALUE_SEPARATOR) {
                let key = key.trim();
                let value = value.trim();

                match key {
                    "request_type" => {
                        if value != "call" {
                            return Err(SignatureParseError::InvalidHeaderValue(
                                "request_type must be 'call'".to_string(),
                            ));
                        }
                    }
                    "canister_id" => {
                        canister_id =
                            Some(Principal::from_text(value).map_err(|e| {
                                SignatureParseError::InvalidHeaderValue(e.to_string())
                            })?);
                    }
                    "method_name" => {
                        method_name = Some(value.to_string());
                    }
                    "sender" => {
                        sender =
                            Some(Principal::from_text(value).map_err(|e| {
                                SignatureParseError::InvalidHeaderValue(e.to_string())
                            })?);
                    }
                    "ingress_expiry" => {
                        ingress_expiry =
                            Some(value.parse::<u64>().map_err(|e| {
                                SignatureParseError::InvalidHeaderValue(e.to_string())
                            })?);
                    }
                    "nonce" => {
                        nonce = Some(
                            BASE64
                                .decode(value)
                                .or_else(|_| {
                                    value
                                        .parse::<u64>()
                                        .map(|n| n.to_be_bytes().to_vec())
                                        .map_err(|_| {
                                            base64::DecodeError::InvalidLength(value.len())
                                        })
                                })
                                .map_err(|e| {
                                    SignatureParseError::Base64DecodeError(e.to_string())
                                })?,
                        );
                    }
                    "include_headers" => {
                        include_headers = Some(
                            value
                                .split(SIGNATURE_INPUT_INCLUDE_HEADERS_SEPARATOR)
                                .map(|s| s.trim().to_lowercase())
                                .collect(),
                        );
                    }
                    _ => {} // Ignore unknown fields
                }
            }
        }

        let signature_input = SignatureInputData::Call {
            canister_id: canister_id.ok_or(SignatureParseError::MissingHeader(
                "canister_id in signature-input",
            ))?,
            method_name: method_name.ok_or(SignatureParseError::MissingHeader(
                "method_name in signature-input",
            ))?,
            sender: sender.ok_or(SignatureParseError::MissingHeader(
                "sender in signature-input",
            ))?,
            ingress_expiry: ingress_expiry.ok_or(SignatureParseError::MissingHeader(
                "ingress_expiry in signature-input",
            ))?,
            nonce,
            include_headers: include_headers.ok_or(SignatureParseError::MissingHeader(
                "include_headers in signature-input",
            ))?,
        };

        Ok(signature_input)
    }

    pub fn read_state_from_str(value: &str) -> Result<Self, SignatureParseError> {
        let mut ingress_expiry = None;
        let mut sender = None;
        let mut nonce = None;

        for pair in value.split(SIGNATURE_INPUT_PARAMETERS_SEPARATOR) {
            let pair = pair.trim();
            if let Some((key, value)) = pair.split_once(SIGNATURE_INPUT_KEY_VALUE_SEPARATOR) {
                let key = key.trim();
                let value = value.trim();

                match key {
                    "request_type" => {
                        if value != "read_state" {
                            return Err(SignatureParseError::InvalidHeaderValue(
                                "request_type must be 'read_state'".to_string(),
                            ));
                        }
                    }
                    "ingress_expiry" => {
                        ingress_expiry =
                            Some(value.parse::<u64>().map_err(|e| {
                                SignatureParseError::InvalidHeaderValue(e.to_string())
                            })?);
                    }
                    "sender" => {
                        sender =
                            Some(Principal::from_text(value).map_err(|e| {
                                SignatureParseError::InvalidHeaderValue(e.to_string())
                            })?);
                    }
                    "nonce" => {
                        nonce = Some(
                            BASE64
                                .decode(value)
                                .or_else(|_| {
                                    value
                                        .parse::<u64>()
                                        .map(|n| n.to_be_bytes().to_vec())
                                        .map_err(|_| {
                                            base64::DecodeError::InvalidLength(value.len())
                                        })
                                })
                                .map_err(|e| {
                                    SignatureParseError::Base64DecodeError(e.to_string())
                                })?,
                        );
                    }
                    _ => {} // Ignore unknown fields
                }
            }
        }

        let signature_input = SignatureInputData::ReadState {
            ingress_expiry: ingress_expiry.ok_or(SignatureParseError::MissingHeader(
                "ingress_expiry in signature-input",
            ))?,
            sender: sender.ok_or(SignatureParseError::MissingHeader(
                "sender in signature-input",
            ))?,
            nonce,
        };

        Ok(signature_input)
    }

    pub fn query_from_str(value: &str) -> Result<Self, SignatureParseError> {
        let mut canister_id = None;
        let mut method_name = None;
        let mut sender = None;
        let mut ingress_expiry = None;
        let mut nonce = None;
        let mut include_headers = None;

        for pair in value.split(SIGNATURE_INPUT_PARAMETERS_SEPARATOR) {
            let pair = pair.trim();
            if let Some((key, value)) = pair.split_once(SIGNATURE_INPUT_KEY_VALUE_SEPARATOR) {
                let key = key.trim();
                let value = value.trim();

                match key {
                    "request_type" => {
                        if value != "query" {
                            return Err(SignatureParseError::InvalidHeaderValue(
                                "request_type must be 'query'".to_string(),
                            ));
                        }
                    }
                    "canister_id" => {
                        canister_id =
                            Some(Principal::from_text(value).map_err(|e| {
                                SignatureParseError::InvalidHeaderValue(e.to_string())
                            })?);
                    }
                    "method_name" => {
                        method_name = Some(value.to_string());
                    }
                    "sender" => {
                        sender =
                            Some(Principal::from_text(value).map_err(|e| {
                                SignatureParseError::InvalidHeaderValue(e.to_string())
                            })?);
                    }
                    "ingress_expiry" => {
                        ingress_expiry =
                            Some(value.parse::<u64>().map_err(|e| {
                                SignatureParseError::InvalidHeaderValue(e.to_string())
                            })?);
                    }
                    "nonce" => {
                        nonce = Some(
                            BASE64
                                .decode(value)
                                .or_else(|_| {
                                    value
                                        .parse::<u64>()
                                        .map(|n| n.to_be_bytes().to_vec())
                                        .map_err(|_| {
                                            base64::DecodeError::InvalidLength(value.len())
                                        })
                                })
                                .map_err(|e| {
                                    SignatureParseError::Base64DecodeError(e.to_string())
                                })?,
                        );
                    }
                    "include_headers" => {
                        include_headers = Some(
                            value
                                .split(SIGNATURE_INPUT_INCLUDE_HEADERS_SEPARATOR)
                                .map(|s| s.trim().to_lowercase())
                                .collect(),
                        );
                    }
                    _ => {} // Ignore unknown fields
                }
            }
        }

        let signature_input = SignatureInputData::Query {
            canister_id: canister_id.ok_or(SignatureParseError::MissingHeader(
                "canister_id in signature-input",
            ))?,
            method_name: method_name.ok_or(SignatureParseError::MissingHeader(
                "method_name in signature-input",
            ))?,
            sender: sender.ok_or(SignatureParseError::MissingHeader(
                "sender in signature-input",
            ))?,
            ingress_expiry: ingress_expiry.ok_or(SignatureParseError::MissingHeader(
                "ingress_expiry in signature-input",
            ))?,
            nonce,
            include_headers: include_headers.ok_or(SignatureParseError::MissingHeader(
                "include_headers in signature-input",
            ))?,
        };

        Ok(signature_input)
    }

    pub fn include_headers(&self) -> Result<&[String], String> {
        match self {
            SignatureInputData::Call {
                include_headers, ..
            } => Ok(include_headers),
            SignatureInputData::Query {
                include_headers, ..
            } => Ok(include_headers),
            SignatureInputData::ReadState { .. } => {
                Err("ReadState does not have include_headers".to_string())
            }
        }
    }
}

/// Data for a single signature
#[derive(Debug, Clone)]
pub struct SignatureData {
    pub sender_sig: Vec<u8>,
    pub sender_pubkey: Vec<u8>,
    pub signature_input: SignatureInputData,
}

/// Signature enum representing the different signature types
#[derive(Debug, Clone)]
pub enum Signature {
    Call {
        call: SignatureData,
        read_state: Option<SignatureData>,
    },
    Query {
        query: SignatureData,
    },
}

impl Signature {
    /// Parse signatures from HTTP headers
    pub fn from_headers(headers: &HeaderMap) -> Result<Self, SignatureParseError> {
        // Parse all three headers
        let signature_str = headers
            .get(SIGNATURE_HEADER_NAME)
            .ok_or(SignatureParseError::MissingHeader(SIGNATURE_HEADER_NAME))?
            .to_str()
            .map_err(|e| SignatureParseError::InvalidHeaderValue(e.to_string()))?;

        let signature_input_str = headers
            .get(SIGNATURE_INPUT_HEADER_NAME)
            .ok_or(SignatureParseError::MissingHeader(
                SIGNATURE_INPUT_HEADER_NAME,
            ))?
            .to_str()
            .map_err(|e| SignatureParseError::InvalidHeaderValue(e.to_string()))?;

        let signature_key_str = headers
            .get(SIGNATURE_KEY_HEADER_NAME)
            .ok_or(SignatureParseError::MissingHeader(
                SIGNATURE_KEY_HEADER_NAME,
            ))?
            .to_str()
            .map_err(|e| SignatureParseError::InvalidHeaderValue(e.to_string()))?;

        // Parse each header into HashMaps
        let signatures = parse_signature_header(signature_str)?;
        let signature_inputs = parse_signature_input_header(signature_input_str)?;
        let signature_keys = parse_signature_key_header(signature_key_str)?;

        // Determine signature type based on what's present
        if signatures.contains_key("sig_call") {
            // Call signature - sig_read_state is optional, sig_query must not be present
            if signatures.contains_key("sig_query") {
                return Err(SignatureParseError::InvalidHeaderValue(
                    "sig_call and sig_query cannot both be present".to_string(),
                ));
            }

            let call =
                build_signature_data("sig_call", &signatures, &signature_inputs, &signature_keys)?;
            let read_state = if signatures.contains_key("sig_read_state") {
                Some(build_signature_data(
                    "sig_read_state",
                    &signatures,
                    &signature_inputs,
                    &signature_keys,
                )?)
            } else {
                None
            };

            Ok(Signature::Call { call, read_state })
        } else if signatures.contains_key("sig_query") {
            // Query signature - no other signatures should be present
            if signatures.len() > 1 {
                return Err(SignatureParseError::InvalidHeaderValue(
                    "sig_query must be the only signature present".to_string(),
                ));
            }

            let query =
                build_signature_data("sig_query", &signatures, &signature_inputs, &signature_keys)?;
            Ok(Signature::Query { query })
        } else {
            Err(SignatureParseError::MissingRequiredSignature(
                "Expected 'sig_call' or 'sig_query'".to_string(),
            ))
        }
    }
}

/// Build SignatureData for a given signature name from the parsed header maps
fn build_signature_data(
    sig_name: &str,
    signatures: &HashMap<String, Vec<u8>>,
    signature_inputs: &HashMap<String, String>,
    signature_keys: &HashMap<String, Vec<u8>>,
) -> Result<SignatureData, SignatureParseError> {
    let sender_sig = signatures
        .get(sig_name)
        .ok_or_else(|| {
            SignatureParseError::MissingRequiredSignature(format!(
                "Missing '{}' in Signature header",
                sig_name
            ))
        })?
        .clone();

    let signature_input_str = signature_inputs
        .get(sig_name)
        .ok_or_else(|| {
            SignatureParseError::MissingRequiredSignature(format!(
                "Missing '{}' in Signature-Input header",
                sig_name
            ))
        })?
        .clone();

    let signature_input = match sig_name {
        "sig_call" => SignatureInputData::call_from_str(&signature_input_str)?,
        "sig_read_state" => SignatureInputData::read_state_from_str(&signature_input_str)?,
        "sig_query" => SignatureInputData::query_from_str(&signature_input_str)?,
        _ => {
            return Err(SignatureParseError::InvalidSignatureName(
                sig_name.to_string(),
            ))
        }
    };

    let sender_pubkey = signature_keys
        .get(sig_name)
        .ok_or_else(|| {
            SignatureParseError::MissingRequiredSignature(format!(
                "Missing '{}' in Signature-Key header",
                sig_name
            ))
        })?
        .clone();

    Ok(SignatureData {
        sender_sig,
        sender_pubkey,
        signature_input,
    })
}

/// Parse all signatures from the Signature header
/// Format: <sig_name>=:<sig_bytes_base64_encoded>:,<sig_name>=:<sig_bytes_base64_encoded>:,...
fn parse_signature_header(
    header_value: &str,
) -> Result<HashMap<String, Vec<u8>>, SignatureParseError> {
    let mut signatures = HashMap::new();

    for entry in header_value.split(SIGNATURES_SEPARATOR) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }

        // Find the '=:' separator to extract sig_name
        if let Some(eq_colon_pos) = entry.find("=:") {
            let sig_name = entry[..eq_colon_pos].trim().to_string();
            let rest = &entry[eq_colon_pos + 2..];

            // Validate sig_name
            if !matches!(
                sig_name.as_str(),
                "sig_call" | "sig_read_state" | "sig_query"
            ) {
                return Err(SignatureParseError::InvalidSignatureName(sig_name));
            }

            // Extract base64 value between =: and final :
            let value = rest.strip_suffix(':').ok_or_else(|| {
                SignatureParseError::InvalidHeaderValue(format!(
                    "Expected format '<sig_name>=:<value>:', got: {}",
                    entry
                ))
            })?;

            let decoded = BASE64
                .decode(value)
                .map_err(|e| SignatureParseError::Base64DecodeError(e.to_string()))?;

            signatures.insert(sig_name, decoded);
        } else {
            return Err(SignatureParseError::InvalidHeaderValue(format!(
                "Invalid signature entry format, expected '<sig_name>=:<value>:', got: {}",
                entry
            )));
        }
    }

    if signatures.is_empty() {
        return Err(SignatureParseError::InvalidHeaderValue(
            "No signatures found in Signature header".to_string(),
        ));
    }

    Ok(signatures)
}

/// Parse all signature inputs from the Signature-Input header
/// Format: <sig_name>=(<key>=<value>;<key>=<value>;...);<sig_name>=(<key>=<value>;<key>=<value>;...);...
fn parse_signature_input_header(
    header_value: &str,
) -> Result<HashMap<String, String>, SignatureParseError> {
    let mut signature_inputs = HashMap::new();
    let inputs_separator =
        format!("{SIGNATURE_INPUT_VALUE_END_DELIMITER}{SIGNATURE_INPUTS_SEPARATOR}");
    let key_value_separator =
        format!("{SIGNATURE_INPUT_KEY_VALUE_SEPARATOR}{SIGNATURE_INPUT_VALUE_START_DELIMITER}");
    let key_value_separator_len = key_value_separator.len();

    // Split at ');' which is the end of an input and the start of the next input
    for entry in header_value.split(&inputs_separator) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }

        // Find the first '=(' to extract sig_name and its value
        if let Some(sep_pos) = entry.find(&key_value_separator) {
            let sig_name = entry[..sep_pos].trim().to_string();
            let signature_input_value = entry[sep_pos + key_value_separator_len..]
                .trim_end_matches(SIGNATURE_INPUT_VALUE_END_DELIMITER)
                .to_string();

            signature_inputs.insert(sig_name, signature_input_value);
        } else {
            return Err(SignatureParseError::InvalidHeaderValue(format!(
                "Invalid signature-input entry format, expected '<sig_name>=<params>', got: {}",
                entry
            )));
        }
    }

    if signature_inputs.is_empty() {
        return Err(SignatureParseError::InvalidHeaderValue(
            "No signature inputs found in Signature-Input header".to_string(),
        ));
    }

    Ok(signature_inputs)
}

/// Parse all signature keys from the Signature-Key header
/// Format: <sig_name>=:<base64({ pubKey: <base64_bytes> })>:,<sig_name>=:<base64({ pubKey: <base64_bytes> })>:,...
fn parse_signature_key_header(
    header_value: &str,
) -> Result<HashMap<String, Vec<u8>>, SignatureParseError> {
    let mut signature_keys = HashMap::new();

    for entry in header_value.split(SIGNATURES_SEPARATOR) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }

        // Find the '=:' separator to extract sig_name
        if let Some(eq_colon_pos) = entry.find("=:") {
            let sig_name = entry[..eq_colon_pos].trim().to_string();
            let rest = &entry[eq_colon_pos + 2..];

            // Extract base64 value between =: and final :
            let value = rest.strip_suffix(':').ok_or_else(|| {
                SignatureParseError::InvalidHeaderValue(format!(
                    "Expected format '<sig_name>=:<value>:', got: {}",
                    entry
                ))
            })?;

            let signature_key_json = BASE64
                .decode(value)
                .map_err(|e| SignatureParseError::Base64DecodeError(e.to_string()))?;

            let signature_key: SignatureKey = serde_json::from_slice(&signature_key_json)
                .map_err(|e| SignatureParseError::JsonParseError(e.to_string()))?;

            let sender_pubkey = BASE64
                .decode(&signature_key.pub_key)
                .map_err(|e| SignatureParseError::Base64DecodeError(e.to_string()))?;

            signature_keys.insert(sig_name, sender_pubkey);
        } else {
            return Err(SignatureParseError::InvalidHeaderValue(format!(
                "Invalid signature-key entry format, expected '<sig_name>=:<value>:', got: {}",
                entry
            )));
        }
    }

    if signature_keys.is_empty() {
        return Err(SignatureParseError::InvalidHeaderValue(
            "No signature keys found in Signature-Key header".to_string(),
        ));
    }

    Ok(signature_keys)
}
