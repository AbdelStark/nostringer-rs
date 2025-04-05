use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use k256::elliptic_curve::{sec1::ToEncodedPoint, PrimeField};
use k256::Scalar;
use serde::{Deserialize, Serialize};
use serde_cbor::Error as CborError;
use thiserror::Error;

// Access KeyImage through the public type
use crate::types::KeyImage;
use crate::types::{BlsagSignatureBinary, RingSignatureBinary};
use std::convert::TryFrom;

// Define the prefix and version for our serialization format
const SIGNATURE_PREFIX: &str = "ring";
const SIGNATURE_VERSION: char = 'A';

/// Represents the data structure used for CBOR serialization.
/// Uses single-character keys for compactness.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct SerializedSignatureData {
    /// Signature variant: "sag" or "blsag"
    #[serde(rename = "v")]
    variant: String,
    /// c0 challenge scalar (32 bytes)
    #[serde(with = "serde_bytes")]
    #[serde(rename = "c")]
    c0: Vec<u8>,
    /// s response scalars (array of 32-byte scalars)
    #[serde(rename = "s")]
    s: Vec<Vec<u8>>,
    /// Key image (33 bytes compressed point, optional, only for blsag)
    #[serde(rename = "i", skip_serializing_if = "Option::is_none", default)]
    key_image: Option<Vec<u8>>,
    /// Linkability flag (optional, only for blsag with local linkability)
    #[serde(rename = "l", skip_serializing_if = "Option::is_none", default)]
    linkability_flag: Option<Vec<u8>>,
}

/// Errors related to compact signature serialization and deserialization
#[derive(Debug, PartialEq, Eq, Error)]
pub enum SerializationError {
    #[error("Invalid prefix, expected 'ringA'")]
    InvalidPrefix,

    #[error("Base64 decoding failed: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("CBOR decoding failed: {0}")]
    CborDecode(String),

    #[error("Invalid CBOR structure (expected array with 3 or 4 elements)")]
    InvalidStructure(String),

    #[error("Invalid signature variant tag: {0}")]
    InvalidVariantTag(u8),

    #[error("Unexpected key image found for SAG signature")]
    UnexpectedKeyImage,

    #[error("Key image missing for BLSAG signature")]
    MissingKeyImage,

    #[error("Failed to convert data during deserialization: {0}")]
    DataConversion(String),

    #[error("CBOR encoding failed: {0}")]
    CborEncode(String),
}

impl From<CborError> for SerializationError {
    fn from(e: CborError) -> Self {
        // Distinguish between serialization and deserialization errors if possible
        // For now, categorizing based on context might be needed, or just use a generic message
        SerializationError::CborDecode(e.to_string()) // Assume deserialization for now
    }
}

// Manually convert from elliptic_curve Error to SerializationError
impl From<k256::elliptic_curve::Error> for SerializationError {
    fn from(e: k256::elliptic_curve::Error) -> Self {
        SerializationError::DataConversion(e.to_string())
    }
}

/// Represents either a SAG or BLSAG signature in a compact, serializable format.
#[derive(Debug, PartialEq, Clone)]
pub enum CompactSignature {
    Sag(RingSignatureBinary),
    Blsag(BlsagSignatureBinary, KeyImage),
}

impl CompactSignature {
    /// Serialize the compact signature to the `ringA...` format string.
    pub fn serialize(&self) -> Result<String, SerializationError> {
        let data: SerializedSignatureData = self.try_into()?;
        let cbor_bytes =
            serde_cbor::to_vec(&data).map_err(|e| SerializationError::CborEncode(e.to_string()))?;
        let base64_encoded = URL_SAFE_NO_PAD.encode(&cbor_bytes);
        Ok(format!(
            "{}{}{}",
            SIGNATURE_PREFIX, SIGNATURE_VERSION, base64_encoded
        ))
    }

    /// Deserialize a compact signature from the `ringA...` format string.
    pub fn deserialize(encoded: &str) -> Result<Self, SerializationError> {
        let prefix = format!("{}{}", SIGNATURE_PREFIX, SIGNATURE_VERSION);
        if !encoded.starts_with(&prefix) {
            return Err(SerializationError::InvalidPrefix);
        }

        let base64_data = &encoded[prefix.len()..];
        let cbor_bytes = URL_SAFE_NO_PAD.decode(base64_data)?;
        let data: SerializedSignatureData = serde_cbor::from_slice(&cbor_bytes)
            .map_err(|e| SerializationError::CborDecode(e.to_string()))?;

        Self::try_from(data)
    }

    /// Returns the signature variant ("sag" or "blsag").
    pub fn variant(&self) -> &'static str {
        match self {
            CompactSignature::Sag(_) => "sag",
            CompactSignature::Blsag(_, _) => "blsag",
        }
    }
}

// --- Conversions ---

impl TryFrom<&CompactSignature> for SerializedSignatureData {
    type Error = SerializationError;

    fn try_from(value: &CompactSignature) -> Result<Self, Self::Error> {
        match value {
            CompactSignature::Sag(sig) => {
                if sig.s.is_empty() {
                    return Err(SerializationError::DataConversion(
                        "Invalid signature format: empty s values".to_string(),
                    ));
                }
                Ok(SerializedSignatureData {
                    variant: "sag".to_string(),
                    c0: sig.c0.to_bytes().to_vec(),
                    s: sig.s.iter().map(|s| s.to_bytes().to_vec()).collect(),
                    key_image: None,
                    linkability_flag: None, // No key image for SAG
                })
            }
            CompactSignature::Blsag(sig, key_image) => {
                if sig.s.is_empty() {
                    return Err(SerializationError::DataConversion(
                        "Invalid signature format: empty s values".to_string(),
                    ));
                }
                let key_image_bytes = key_image
                    .as_point()
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec();
                if key_image_bytes.len() != 33 {
                    return Err(SerializationError::DataConversion(
                        "Key image must be 33 bytes".to_string(),
                    ));
                }
                Ok(SerializedSignatureData {
                    variant: "blsag".to_string(),
                    c0: sig.c0.to_bytes().to_vec(),
                    s: sig.s.iter().map(|s| s.to_bytes().to_vec()).collect(),
                    key_image: Some(key_image_bytes),
                    linkability_flag: sig.linkability_flag.clone(),
                })
            }
        }
    }
}

impl TryFrom<SerializedSignatureData> for CompactSignature {
    type Error = SerializationError;

    fn try_from(data: SerializedSignatureData) -> Result<Self, Self::Error> {
        // Validate c0 length
        if data.c0.len() != 32 {
            return Err(SerializationError::DataConversion(
                "c0 must be 32 bytes".to_string(),
            ));
        }
        let c0_bytes: [u8; 32] = data.c0.try_into().map_err(|e: Vec<u8>| {
            SerializationError::DataConversion(format!(
                "Incorrect length for c0: expected 32, got {}",
                e.len()
            ))
        })?;
        let c0_opt = Scalar::from_repr_vartime(c0_bytes.into());
        if c0_opt.is_none() {
            return Err(SerializationError::DataConversion(
                "Invalid scalar value for c0".into(),
            ));
        }
        let c0 = c0_opt.unwrap();

        // Validate and convert s scalars
        let mut s_scalars = Vec::with_capacity(data.s.len());
        for s_bytes_vec in data.s {
            if s_bytes_vec.len() != 32 {
                return Err(SerializationError::DataConversion(
                    "Each s must be 32 bytes".to_string(),
                ));
            }
            let s_bytes: [u8; 32] = s_bytes_vec.try_into().map_err(|e: Vec<u8>| {
                SerializationError::DataConversion(format!(
                    "Incorrect length for s: expected 32, got {}",
                    e.len()
                ))
            })?;
            let s_opt = Scalar::from_repr_vartime(s_bytes.into());
            if s_opt.is_none() {
                return Err(SerializationError::DataConversion(
                    "Invalid scalar value for s".into(),
                ));
            }
            s_scalars.push(s_opt.unwrap());
        }

        match data.variant.as_str() {
            "sag" => {
                if data.key_image.is_some() {
                    return Err(SerializationError::UnexpectedKeyImage);
                }
                let sig = RingSignatureBinary { c0, s: s_scalars };
                Ok(CompactSignature::Sag(sig))
            }
            "blsag" => {
                let key_image_bytes = data.key_image.ok_or(SerializationError::MissingKeyImage)?;
                if key_image_bytes.len() != 33 {
                    return Err(SerializationError::DataConversion(
                        "Key image must be 33 bytes".to_string(),
                    ));
                }

                // Convert bytes back to ProjectivePoint using a different approach
                let key_image_point = match k256::PublicKey::from_sec1_bytes(&key_image_bytes) {
                    Ok(pk) => pk.to_projective(),
                    Err(e) => {
                        return Err(SerializationError::DataConversion(format!(
                            "Invalid key image: {}",
                            e
                        )))
                    }
                };

                let sig = BlsagSignatureBinary {
                    c0,
                    s: s_scalars,
                    linkability_flag: data.linkability_flag,
                };
                let key_image = KeyImage(key_image_point);
                Ok(CompactSignature::Blsag(sig, key_image))
            }
            _ => Err(SerializationError::InvalidVariantTag(
                data.variant.chars().next().unwrap() as u8,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blsag::sign_blsag_binary;
    use crate::keys::generate_keypair_hex;
    use crate::sag::sign_binary as sag_sign_binary;
    use crate::types::hex_to_scalar;
    use crate::utils::hex_to_point;
    use k256::ProjectivePoint;
    use rand::rngs::OsRng;

    #[test]
    fn test_sag_serialization_deserialization() {
        let kp1 = generate_keypair_hex("compressed");
        let kp2 = generate_keypair_hex("compressed");
        let ring_hex = vec![kp1.public_key_hex, kp2.public_key_hex.clone()];
        let ring_points: Vec<ProjectivePoint> =
            ring_hex.iter().map(|h| hex_to_point(h).unwrap()).collect();
        let signer_priv = hex_to_scalar(&kp2.private_key_hex).unwrap();
        let message = b"test message for sag";

        let original_sig = sag_sign_binary(message, &signer_priv, &ring_points, OsRng).unwrap();
        let compact_sig = CompactSignature::Sag(original_sig.clone());

        let serialized = compact_sig.serialize().unwrap();
        println!("Serialized SAG: {}", serialized);
        assert!(serialized.starts_with("ringA"));

        let deserialized = CompactSignature::deserialize(&serialized).unwrap();

        assert_eq!(compact_sig, deserialized);
        match deserialized {
            CompactSignature::Sag(deserialized_sig) => {
                // Compare fields directly for Scalar (impl PartialEq)
                assert_eq!(original_sig.c0, deserialized_sig.c0);
                assert_eq!(original_sig.s, deserialized_sig.s);
            }
            _ => panic!("Deserialized into wrong variant"),
        }
    }

    #[test]
    fn test_blsag_serialization_deserialization() {
        let kp1 = generate_keypair_hex("compressed");
        let kp2 = generate_keypair_hex("compressed");
        let ring_hex = vec![kp1.public_key_hex, kp2.public_key_hex.clone()];
        let ring_points: Vec<ProjectivePoint> =
            ring_hex.iter().map(|h| hex_to_point(h).unwrap()).collect();
        let signer_priv = hex_to_scalar(&kp2.private_key_hex).unwrap();
        let message = b"test message for blsag";
        let linkability_flag: Option<&[u8]> = None;

        let (original_sig, original_key_image) =
            sign_blsag_binary(message, &signer_priv, &ring_points, &linkability_flag).unwrap();
        let compact_sig = CompactSignature::Blsag(original_sig.clone(), original_key_image.clone());

        let serialized = compact_sig.serialize().unwrap();
        println!("Serialized BLSAG: {}", serialized);
        assert!(serialized.starts_with("ringA"));

        let deserialized = CompactSignature::deserialize(&serialized).unwrap();
        assert_eq!(compact_sig, deserialized);

        match deserialized {
            CompactSignature::Blsag(deserialized_sig, deserialized_key_image) => {
                assert_eq!(original_sig.c0, deserialized_sig.c0);
                assert_eq!(original_sig.s, deserialized_sig.s);
                assert_eq!(original_key_image, deserialized_key_image); // KeyImage derives PartialEq
            }
            _ => panic!("Deserialized into wrong variant"),
        }
    }

    #[test]
    fn test_blsag_serialization_deserialization_with_linkability_flag() {
        let kp1 = generate_keypair_hex("compressed");
        let kp2 = generate_keypair_hex("compressed");
        let ring_hex = vec![kp1.public_key_hex, kp2.public_key_hex.clone()];
        let ring_points: Vec<ProjectivePoint> =
            ring_hex.iter().map(|h| hex_to_point(h).unwrap()).collect();
        let signer_priv = hex_to_scalar(&kp2.private_key_hex).unwrap();
        let message = b"test message for blsag";
        let linkability_flag: Option<&[u8]> = Some(b"linkability flag");

        let (original_sig, original_key_image) =
            sign_blsag_binary(message, &signer_priv, &ring_points, &linkability_flag).unwrap();
        let compact_sig = CompactSignature::Blsag(original_sig.clone(), original_key_image.clone());

        let serialized = compact_sig.serialize().unwrap();
        println!("Serialized BLSAG: {}", serialized);
        assert!(serialized.starts_with("ringA"));

        let deserialized = CompactSignature::deserialize(&serialized).unwrap();
        assert_eq!(compact_sig, deserialized);

        match deserialized {
            CompactSignature::Blsag(deserialized_sig, deserialized_key_image) => {
                assert_eq!(original_sig.c0, deserialized_sig.c0);
                assert_eq!(original_sig.s, deserialized_sig.s);
                assert_eq!(original_key_image, deserialized_key_image); // KeyImage derives PartialEq
            }
            _ => panic!("Deserialized into wrong variant"),
        }
    }

    #[test]
    fn test_invalid_prefix() {
        let invalid_encoded = "rngA....";
        let result = CompactSignature::deserialize(invalid_encoded);
        assert!(matches!(result, Err(SerializationError::InvalidPrefix)));
    }

    #[test]
    fn test_invalid_base64() {
        let invalid_encoded = "ringA***";
        let result = CompactSignature::deserialize(invalid_encoded);
        assert!(matches!(result, Err(SerializationError::Base64Decode(_))));
    }

    #[test]
    fn test_invalid_cbor() {
        // Valid base64 but invalid CBOR (e.g., just random bytes)
        let invalid_cbor_base64 = URL_SAFE_NO_PAD.encode(&[0x01, 0x02, 0x03]);
        let invalid_encoded = format!("ringA{}", invalid_cbor_base64);
        let result = CompactSignature::deserialize(&invalid_encoded);
        assert!(matches!(result, Err(SerializationError::CborDecode(_))));
    }

    #[test]
    fn test_invalid_cbor_structure() {
        // Correct CBOR, but wrong structure (e.g., not an array)
        let invalid_structure_cbor = serde_cbor::to_vec(&"just a string").unwrap();
        let invalid_structure_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&invalid_structure_cbor);
        let result = CompactSignature::deserialize(&format!("ringA{}", invalid_structure_b64));
        // Deserialization into SerializedSignatureData fails first
        assert!(
            matches!(result, Err(SerializationError::CborDecode(_))),
            "Expected CborDecode for wrong structure"
        );

        // Correct CBOR array, but wrong number of elements
        let invalid_element_count_cbor = serde_cbor::to_vec(&[1, 2]).unwrap(); // Expecting 3 or 4 elements
        let invalid_element_count_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&invalid_element_count_cbor);
        let result_count =
            CompactSignature::deserialize(&format!("ringA{}", invalid_element_count_b64));
        // Also fails during deserialization into SerializedSignatureData
        assert!(
            matches!(result_count, Err(SerializationError::CborDecode(_))),
            "Expected CborDecode for wrong element count"
        );
    }

    #[test]
    fn test_invalid_variant_tag() {
        // Correct CBOR structure, but invalid variant tag (e.g., 3 instead of 0 or 1)
        // We need to craft the SerializedSignatureData manually for this
        let data = SerializedSignatureData {
            variant: "invalid_variant_3".to_string(), // Invalid variant string
            c0: vec![0u8; 32],
            s: vec![vec![0u8; 32]],
            key_image: None,
            linkability_flag: None,
        };
        let invalid_variant_cbor = serde_cbor::to_vec(&data).unwrap();
        let invalid_variant_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&invalid_variant_cbor);
        let result = CompactSignature::deserialize(&format!("ringA{}", invalid_variant_b64));
        // The error occurs during the final match statement in TryFrom<SerializedSignatureData>
        // We expect the first byte of the invalid variant string here
        assert!(
            matches!(result, Err(SerializationError::InvalidVariantTag(b'i'))),
            "Expected InvalidVariantTag error"
        );
    }

    #[test]
    fn test_key_image_mismatch() {
        // Test SAG signature with unexpected key image
        let sag_data_with_ki = SerializedSignatureData {
            variant: "sag".to_string(),
            c0: vec![0u8; 32],
            s: vec![vec![0u8; 32]],
            key_image: Some(vec![2u8; 33]), // Unexpected KI for SAG
            linkability_flag: None,
        };
        let unexpected_ki_cbor = serde_cbor::to_vec(&sag_data_with_ki).unwrap();
        let unexpected_ki_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&unexpected_ki_cbor);
        let result_sag = CompactSignature::deserialize(&format!("ringA{}", unexpected_ki_b64));
        assert!(
            matches!(result_sag, Err(SerializationError::UnexpectedKeyImage)),
            "Expected UnexpectedKeyImage error for SAG"
        );

        // Test BLSAG signature missing key image
        let blsag_data_no_ki = SerializedSignatureData {
            variant: "blsag".to_string(),
            c0: vec![0u8; 32],
            s: vec![vec![0u8; 32]],
            key_image: None, // Missing KI for BLSAG
            linkability_flag: None,
        };
        let missing_ki_cbor = serde_cbor::to_vec(&blsag_data_no_ki).unwrap();
        let missing_ki_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&missing_ki_cbor);
        let result_blsag = CompactSignature::deserialize(&format!("ringA{}", missing_ki_b64));
        assert!(
            matches!(result_blsag, Err(SerializationError::MissingKeyImage)),
            "Expected MissingKeyImage error for BLSAG"
        );
    }

    // Potential tests for invalid CBOR types within the structure (e.g., string where bytes expected)
    // These are harder to craft manually but might be caught by CborDecode or InvalidStructure
}
