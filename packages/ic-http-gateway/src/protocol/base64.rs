use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Deserializer};

pub(crate) fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| {
            input
                .parse::<u64>()
                .map(|n| n.to_be_bytes().to_vec())
                .map_err(|_| base64::DecodeError::InvalidLength(input.len()))
        })
        .map_err(|e| e.to_string())
}

/// Deserializes a base64 encoded JSON field to a byte vector.
pub(crate) fn deserialize_base64_string_to_bytes<'de, D>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct HexBytesVisitor;

    impl<'de> serde::de::Visitor<'de> for HexBytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a hex string representing bytes")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            // Convert hex string to bytes
            let bytes = base64_decode(v).map_err(|_| E::custom("Invalid base64 string"))?;
            Ok(bytes)
        }

        fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            // Also handle direct byte arrays
            Deserialize::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))
        }
    }

    deserializer.deserialize_any(HexBytesVisitor)
}
