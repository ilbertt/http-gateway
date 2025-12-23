use candid::Principal;
use serde::{Deserialize, Serialize};

use super::base64::deserialize_base64_string_to_bytes;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DelegationChain {
    #[serde(
        rename = "pubKey",
        deserialize_with = "deserialize_base64_string_to_bytes"
    )]
    pub pub_key: Vec<u8>,
    pub delegations: Vec<SignedDelegation>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedDelegation {
    delegation: Delegation,
    #[serde(deserialize_with = "deserialize_base64_string_to_bytes")]
    sig: Vec<u8>,
}

impl From<SignedDelegation> for ic_agent::identity::SignedDelegation {
    fn from(signed_delegation: SignedDelegation) -> Self {
        Self {
            delegation: signed_delegation.delegation.into(),
            signature: signed_delegation.sig,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Delegation {
    #[serde(
        rename = "pubKey",
        deserialize_with = "deserialize_base64_string_to_bytes"
    )]
    pub pub_key: Vec<u8>,
    #[serde(deserialize_with = "parse_u64")]
    pub expiration: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub targets: Option<Vec<Principal>>,
}

impl From<Delegation> for ic_agent::identity::Delegation {
    fn from(delegation: Delegation) -> Self {
        Self {
            pubkey: delegation.pub_key,
            expiration: delegation.expiration,
            targets: delegation.targets,
        }
    }
}

fn parse_u64<'de, T, D>(de: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Display,
{
    Ok(String::deserialize(de)?
        .parse()
        .map_err(serde::de::Error::custom)?)
}
