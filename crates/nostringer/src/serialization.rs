use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use k256::elliptic_curve::{sec1::ToEncodedPoint, PrimeField};
use k256::Scalar;
use serde::{Deserialize, Serialize};
use serde_cbor::Error as CborError;

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
}

/// Errors that can occur during signature serialization or deserialization.
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum SerializationError {
    #[error("CBOR serialization error: {0}")]
    CborSerialization(String),
    #[error("CBOR deserialization error: {0}")]
    CborDeserialization(String),
    #[error("Base64 decoding error: {0}")]
    Base64Decoding(#[from] base64::DecodeError),
    #[error("Invalid prefix: expected '{SIGNATURE_PREFIX}{SIGNATURE_VERSION}', got '{0}'")]
    InvalidPrefix(String),
    #[error("Invalid signature variant: '{0}'")]
    InvalidVariant(String),
    #[error("Invalid data length: {0}")]
    InvalidLength(String),
    #[error("Missing key image for BLSAG signature")]
    MissingKeyImage,
    #[error("Unexpected key image found for SAG signature")]
    UnexpectedKeyImage,
    #[error("SEC1 encoding error: {0}")]
    Sec1Error(String),
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<CborError> for SerializationError {
    fn from(e: CborError) -> Self {
        // Distinguish between serialization and deserialization errors if possible
        // For now, categorizing based on context might be needed, or just use a generic message
        SerializationError::CborDeserialization(e.to_string()) // Assume deserialization for now
    }
}

// Manually convert from elliptic_curve Error to SerializationError
impl From<k256::elliptic_curve::Error> for SerializationError {
    fn from(e: k256::elliptic_curve::Error) -> Self {
        SerializationError::Sec1Error(e.to_string())
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
        let cbor_bytes = serde_cbor::to_vec(&data)
            .map_err(|e| SerializationError::CborSerialization(e.to_string()))?;
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
            return Err(SerializationError::InvalidPrefix(
                encoded
                    .split_at(prefix.len().min(encoded.len()))
                    .0
                    .to_string(),
            ));
        }

        let base64_data = &encoded[prefix.len()..];
        let cbor_bytes = URL_SAFE_NO_PAD.decode(base64_data)?;
        let data: SerializedSignatureData = serde_cbor::from_slice(&cbor_bytes)
            .map_err(|e| SerializationError::CborDeserialization(e.to_string()))?;

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
                    return Err(SerializationError::InternalError(
                        "Invalid signature format: empty s values".to_string(),
                    ));
                }
                Ok(SerializedSignatureData {
                    variant: "sag".to_string(),
                    c0: sig.c0.to_bytes().to_vec(),
                    s: sig.s.iter().map(|s| s.to_bytes().to_vec()).collect(),
                    key_image: None,
                })
            }
            CompactSignature::Blsag(sig, key_image) => {
                if sig.s.is_empty() {
                    return Err(SerializationError::InternalError(
                        "Invalid signature format: empty s values".to_string(),
                    ));
                }
                let key_image_bytes = key_image
                    .as_point()
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec();
                if key_image_bytes.len() != 33 {
                    return Err(SerializationError::InvalidLength(
                        "Key image must be 33 bytes".to_string(),
                    ));
                }
                Ok(SerializedSignatureData {
                    variant: "blsag".to_string(),
                    c0: sig.c0.to_bytes().to_vec(),
                    s: sig.s.iter().map(|s| s.to_bytes().to_vec()).collect(),
                    key_image: Some(key_image_bytes),
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
            return Err(SerializationError::InvalidLength(
                "c0 must be 32 bytes".to_string(),
            ));
        }
        let c0_bytes: [u8; 32] = data
            .c0
            .try_into()
            .map_err(|_| SerializationError::InvalidLength("c0 conversion failed".to_string()))?;
        let c0_opt = Scalar::from_repr_vartime(c0_bytes.into());
        if c0_opt.is_none().into() {
            return Err(SerializationError::InternalError(
                "Invalid scalar value for c0".into(),
            ));
        }
        let c0 = c0_opt.unwrap();

        // Validate and convert s scalars
        let mut s_scalars = Vec::with_capacity(data.s.len());
        for s_bytes_vec in data.s {
            if s_bytes_vec.len() != 32 {
                return Err(SerializationError::InvalidLength(
                    "Each s must be 32 bytes".to_string(),
                ));
            }
            let s_bytes: [u8; 32] = s_bytes_vec.try_into().map_err(|_| {
                SerializationError::InvalidLength("s conversion failed".to_string())
            })?;
            let s_opt = Scalar::from_repr_vartime(s_bytes.into());
            if s_opt.is_none().into() {
                return Err(SerializationError::InternalError(
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
                    return Err(SerializationError::InvalidLength(
                        "Key image must be 33 bytes".to_string(),
                    ));
                }

                // Convert bytes back to ProjectivePoint using a different approach
                let key_image_point = match k256::PublicKey::from_sec1_bytes(&key_image_bytes) {
                    Ok(pk) => pk.to_projective(),
                    Err(e) => {
                        return Err(SerializationError::InternalError(format!(
                            "Invalid key image: {}",
                            e
                        )))
                    }
                };

                let sig = BlsagSignatureBinary { c0, s: s_scalars };
                let key_image = KeyImage(key_image_point);
                Ok(CompactSignature::Blsag(sig, key_image))
            }
            _ => Err(SerializationError::InvalidVariant(data.variant)),
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

        let (original_sig, original_key_image) =
            sign_blsag_binary(message, &signer_priv, &ring_points).unwrap();
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
        assert!(matches!(result, Err(SerializationError::InvalidPrefix(_))));
    }

    #[test]
    fn test_invalid_base64() {
        let invalid_encoded = "ringA***";
        let result = CompactSignature::deserialize(invalid_encoded);
        assert!(matches!(result, Err(SerializationError::Base64Decoding(_))));
    }

    #[test]
    fn test_invalid_cbor() {
        // Valid base64 but invalid CBOR (e.g., just random bytes)
        let invalid_cbor_base64 = URL_SAFE_NO_PAD.encode(&[0x01, 0x02, 0x03]);
        let invalid_encoded = format!("ringA{}", invalid_cbor_base64);
        let result = CompactSignature::deserialize(&invalid_encoded);
        assert!(matches!(
            result,
            Err(SerializationError::CborDeserialization(_))
        ));
    }

    #[test]
    fn test_missing_key_image_blsag() {
        // Create valid BLSAG data but omit key image during serialization
        let data = SerializedSignatureData {
            variant: "blsag".to_string(),
            c0: vec![0u8; 32],
            s: vec![vec![0u8; 32]],
            key_image: None, // Omit key image
        };
        let cbor_bytes = serde_cbor::to_vec(&data).unwrap();
        let base64_encoded = URL_SAFE_NO_PAD.encode(&cbor_bytes);
        let encoded = format!("ringA{}", base64_encoded);

        let result = CompactSignature::deserialize(&encoded);
        assert_eq!(result, Err(SerializationError::MissingKeyImage));
    }

    #[test]
    fn test_unexpected_key_image_sag() {
        // Create valid SAG data but include a key image
        let data = SerializedSignatureData {
            variant: "sag".to_string(),
            c0: vec![0u8; 32],
            s: vec![vec![0u8; 32]],
            key_image: Some(vec![2u8; 33]), // Add unexpected key image
        };
        let cbor_bytes = serde_cbor::to_vec(&data).unwrap();
        let base64_encoded = URL_SAFE_NO_PAD.encode(&cbor_bytes);
        let encoded = format!("ringA{}", base64_encoded);

        let result = CompactSignature::deserialize(&encoded);
        assert_eq!(result, Err(SerializationError::UnexpectedKeyImage));
    }
}
