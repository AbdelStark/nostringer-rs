use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{ProjectivePoint, Scalar};
use thiserror::Error;
// Optional: Add serde imports gated by feature
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::utils::hex_to_point;

/// Defines the type of ring signature to create
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureVariant {
    /// Standard Spontaneous Anonymous Group (SAG) signature
    /// Provides unlinkability (no way to tell if two signatures came from the same signer)
    Sag,

    /// Back's Linkable Spontaneous Anonymous Group (BLSAG) signature
    /// Produces a key image that allows detecting when the same key signs multiple times
    /// Still preserves anonymity (doesn't reveal which specific ring member is the signer)
    Blsag,
}

/// Errors that can occur during ring signature operations
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    /// Error in hexadecimal decoding
    #[error("Hex decoding failed: {0}")]
    HexDecode(#[from] hex::FromHexError),

    /// Error in private key format or validation
    #[error("Invalid private key format: {0}")]
    PrivateKeyFormat(String),

    /// Error in secret key format (e.g., invalid nsec)
    #[error("Invalid secret key format: {0}")]
    SecretKeyFormat(String),

    /// Error in public key format or validation
    #[error("Invalid public key format: {0}")]
    PublicKeyFormat(String),

    /// Error when a scalar value is outside the valid range for the curve
    #[error("Invalid scalar encoding (>= curve order N)")]
    InvalidScalarEncoding,

    /// Error from the underlying secp256k1 elliptic curve operations
    #[error("Secp256k1 curve error: {0}")]
    Secp256k1(#[from] k256::elliptic_curve::Error),

    /// Error when the ring does not have enough members
    #[error("Ring must have at least 2 members, got {0}")]
    RingTooSmall(usize),

    /// Error when the signer's public key is not in the ring
    #[error("Signer's public key (or its negation) not found in the ring")]
    SignerNotInRing,

    /// Error during signature verification
    #[error("Signature verification failed (internal calculation mismatch)")]
    VerificationFailed,

    /// Error in the format of a signature
    #[error("Invalid signature format (e.g., incorrect number of 's' values)")]
    InvalidSignatureFormat,

    /// Error during hashing operations
    #[error("Hashing error: {0}")]
    HashingError(String),

    /// Error during point decompression
    #[error("Point decompression error: {0}")]
    PointDecompression(String),

    /// Serialization error from the serialization module
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Error during key format conversion (e.g., bech32 encoding/decoding)
    #[error("Nostr key error: {0}")]
    NostrKeyError(#[from] nostr::key::Error),
}

/// A ring signature consisting of an initial commitment value c0 and a vector of s values
///
/// This structure represents a ring signature in the SAG (Spontaneous Anonymous Group)
/// scheme, where:
/// - `c0` is the initial commitment scalar value encoded as a hex string
/// - `s` is a vector of scalar values (one for each ring member) encoded as hex strings
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RingSignature {
    /// The initial commitment scalar value (c₀) encoded as a hex string
    pub c0: String,
    /// Vector of scalar values (one for each ring member) encoded as hex strings
    pub s: Vec<String>,
}

/// A ring signature consisting of an initial commitment value c0 and a vector of s values
/// with binary representation for better performance
///
/// This structure is the optimized binary version of RingSignature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingSignatureBinary {
    /// The initial commitment scalar value (c₀) as a Scalar
    pub c0: Scalar,
    /// Vector of scalar values (one for each ring member) as Scalar objects
    pub s: Vec<Scalar>,
}

/// A key pair with both private and public keys in binary format for optimized operations
#[derive(Debug, Clone)]
pub struct KeyPair {
    /// Private key as a Scalar
    pub private_key: Scalar,
    /// Public key as a ProjectivePoint
    pub public_key: ProjectivePoint,
}

/// A key pair with both private and public keys in hexadecimal format
///
/// This structure holds a key pair for use in ring signatures:
/// - `private_key_hex` is the secret key scalar encoded as a hex string
/// - `public_key_hex` is the public key point encoded as a hex string in the
///   format specified during generation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct KeyPairHex {
    /// Private key (scalar) encoded as a hexadecimal string
    pub private_key_hex: String,
    /// Public key (curve point) encoded as a hexadecimal string
    pub public_key_hex: String,
}

/// Converts RingSignatureBinary to RingSignature (binary to hex)
impl From<&RingSignatureBinary> for RingSignature {
    fn from(binary: &RingSignatureBinary) -> Self {
        RingSignature {
            c0: scalar_to_hex(&binary.c0),
            s: binary.s.iter().map(scalar_to_hex).collect(),
        }
    }
}

/// Attempts to convert RingSignature to RingSignatureBinary (hex to binary)
impl TryFrom<&RingSignature> for RingSignatureBinary {
    type Error = Error;

    fn try_from(sig: &RingSignature) -> Result<Self, Self::Error> {
        let c0 = hex_to_scalar(&sig.c0)?;
        let s = sig
            .s
            .iter()
            .map(|s_hex| hex_to_scalar(s_hex))
            .collect::<Result<Vec<Scalar>, Error>>()?;

        Ok(RingSignatureBinary { c0, s })
    }
}

/// Represents the Key Image (`I = k * Hp(P)`) used in linkable ring signatures (bLSAG).
/// It is unique per private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))] // Add serde if needed for hex version
pub struct KeyImage(
    #[cfg_attr(
        feature = "serde",
        serde(with = "k256::elliptic_curve::serde::ProjectivePoint")
    )] // Use k256 serde helper if needed
    pub  ProjectivePoint,
);

impl KeyImage {
    /// Returns the inner ProjectivePoint.
    pub fn as_point(&self) -> &ProjectivePoint {
        &self.0
    }

    /// Creates a KeyImage from a ProjectivePoint.
    /// Note: Does not guarantee the point was correctly derived.
    pub fn from_point(point: ProjectivePoint) -> Self {
        KeyImage(point)
    }

    /// Returns the compressed hex representation of the key image.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0.to_encoded_point(true).as_bytes())
    }

    /// Attempts to create a KeyImage from a compressed hex string.
    /// Validates that the point is on the curve.
    pub fn from_hex(hex_str: &str) -> Result<Self, Error> {
        let point = hex_to_point(hex_str)?; // hex_to_point already validates
        Ok(KeyImage(point))
    }
}

/// Binary representation of a bLSAG signature (linkable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlsagSignatureBinary {
    /// The initial commitment scalar value (c₀).
    pub c0: Scalar,
    /// Vector of response scalars (s_i).
    pub s: Vec<Scalar>,
}

/// Hex representation of a bLSAG signature (linkable).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BlsagSignature {
    /// The initial commitment scalar value (c₀) encoded as hex.
    pub c0: String,
    /// Vector of response scalars (s_i) encoded as hex.
    pub s: Vec<String>,
}

// --- Conversions for bLSAG Signatures ---

impl From<&BlsagSignatureBinary> for BlsagSignature {
    fn from(binary: &BlsagSignatureBinary) -> Self {
        BlsagSignature {
            c0: scalar_to_hex(&binary.c0),
            s: binary.s.iter().map(scalar_to_hex).collect(),
        }
    }
}

impl TryFrom<&BlsagSignature> for BlsagSignatureBinary {
    type Error = Error;
    fn try_from(sig: &BlsagSignature) -> Result<Self, Self::Error> {
        let c0 = hex_to_scalar(&sig.c0)?;
        let s = sig
            .s
            .iter()
            .map(|s_hex| hex_to_scalar(s_hex))
            .collect::<Result<Vec<Scalar>, Error>>()?;
        Ok(BlsagSignatureBinary { c0, s })
    }
}

/// Converts a scalar value to a hexadecimal string
///
/// # Arguments
/// * `scalar` - The scalar value to convert
///
/// # Returns
/// The scalar encoded as a lowercase hex string without prefix
pub(crate) fn scalar_to_hex(scalar: &Scalar) -> String {
    // Scalar::to_bytes returns FieldBytes, which can be converted to slice
    hex::encode(scalar.to_bytes().as_slice())
}

/// Converts a hexadecimal string to a scalar value
///
/// # Arguments
/// * `hex_str` - The hex string to convert (with or without "0x" prefix)
///
/// # Returns
/// * `Ok(Scalar)` - The scalar value
/// * `Err(Error)` - If the hex string is invalid or the value is not a valid scalar
///
/// # Errors
/// Returns an error if:
/// * The hex string is invalid
/// * The resulting value is not a valid scalar (>= curve order)
pub fn hex_to_scalar(hex_str: &str) -> Result<Scalar, Error> {
    // Get normalized hex without 0x prefix and all lowercase
    let hex_str = normalize_hex(hex_str)?;

    // Pad to 64 characters if shorter
    let padded_hex = if hex_str.len() < 64 {
        format!("{:0>64}", hex_str)
    } else {
        hex_str
    };
    if padded_hex.len() != 64 {
        return Err(Error::PrivateKeyFormat(format!(
            "Hex len {} != 64",
            padded_hex.len()
        )));
    }

    // Decode hex to bytes
    let bytes = hex::decode(&padded_hex)?;
    let field_bytes = k256::FieldBytes::from_slice(&bytes);

    // Convert bytes to scalar
    let maybe_scalar = Scalar::from_repr_vartime(*field_bytes); // Deref FieldBytes to GenericArray

    if let Some(scalar) = maybe_scalar {
        Ok(scalar)
    } else {
        Err(Error::InvalidScalarEncoding)
    }
}

/// Normalizes a hexadecimal string by removing prefixes and converting to lowercase
///
/// # Arguments
/// * `hex_str` - The hex string to normalize, with or without "0x" prefix
///
/// # Returns
/// * `Ok(String)` - The normalized hex string (lowercase, no prefix)
/// * `Err(Error)` - If the string contains non-hex characters
///
/// # Errors
/// Returns PublicKeyFormat error if any non-hex characters are found
pub(crate) fn normalize_hex(hex_str: &str) -> Result<String, Error> {
    let lower = hex_str
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_lowercase();
    if lower.chars().any(|c| !c.is_ascii_hexdigit()) {
        // Return HexDecode error if non-hex chars are found
        return Err(Error::HexDecode(hex::FromHexError::InvalidHexCharacter {
            c: lower
                .chars()
                .find(|c| !c.is_ascii_hexdigit())
                .unwrap_or('?'), // Find first invalid char
            index: lower
                .chars()
                .position(|c| !c.is_ascii_hexdigit())
                .unwrap_or(0),
        }));
    }
    Ok(lower)
}

#[cfg(test)]
mod tests {
    use super::*; // Import items from parent module (types.rs)
    use crate::utils::random_non_zero_scalar;
    use rand::rngs::OsRng;

    #[test]
    fn test_hex_scalar_conversion() {
        // Generate a random non-zero scalar
        let non_zero_scalar = random_non_zero_scalar(OsRng);
        let scalar: Scalar = *non_zero_scalar; // Dereference NonZeroScalar to get Scalar
        let hex = scalar_to_hex(&scalar);
        assert_eq!(hex.len(), 64, "Hex string should be 64 chars");

        let recovered_scalar = hex_to_scalar(&hex).expect("Hex to scalar conversion failed");
        assert_eq!(scalar, recovered_scalar, "Scalar round trip failed");

        // Test with "0x" prefix
        let hex_with_prefix = format!("0x{}", hex);
        let recovered_scalar_prefix =
            hex_to_scalar(&hex_with_prefix).expect("Hex with prefix failed");
        assert_eq!(
            scalar, recovered_scalar_prefix,
            "Scalar with prefix round trip failed"
        );

        // Test with short hex (should pad)
        let short_hex = "1a2b3c";
        let expected_padded_hex =
            "00000000000000000000000000000000000000000000000000000000001a2b3c";
        let expected_scalar = hex_to_scalar(expected_padded_hex).unwrap();
        let scalar_from_short = hex_to_scalar(short_hex).unwrap();
        assert_eq!(
            scalar_from_short, expected_scalar,
            "Short hex padding failed"
        );
    }

    #[test]
    fn test_hex_scalar_invalid() {
        // Invalid characters
        let result_invalid_char =
            hex_to_scalar("gggga6e49bdb6829e72ab7332de72cd6756c10e40eec0a202797a6e3c399a27b");
        assert!(
            matches!(result_invalid_char, Err(Error::HexDecode(_))),
            "Incorrect error for invalid hex chars"
        );

        // Invalid length (too long) - Use a string that is actually 66 chars long
        let too_long_normalized =
            "a6e49bdb6829e72ab7332de72cd6756c10e40eec0a202797a6e3c399a27bffaabb"; // Now 66 chars
        assert_eq!(too_long_normalized.len(), 66);
        let result_too_long = hex_to_scalar(too_long_normalized);
        assert!(
            matches!(result_too_long, Err(Error::PrivateKeyFormat(_))),
            "Incorrect error for invalid hex length (too long)"
        );

        // Value >= curve order N (specifically N itself)
        let curve_order_n_hex = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
        let result_too_large = hex_to_scalar(curve_order_n_hex);
        assert!(
            matches!(result_too_large, Err(Error::InvalidScalarEncoding)),
            "Incorrect error for value >= curve order"
        );
    }

    #[test]
    fn test_key_image_hex_conversion() -> Result<(), Error> {
        // Create a dummy point for KeyImage
        let point = ProjectivePoint::GENERATOR * Scalar::from(123u64);
        let key_image = KeyImage::from_point(point);

        let hex = key_image.to_hex();
        assert_eq!(
            hex.len(),
            66,
            "KeyImage hex should be 66 chars (compressed)"
        );
        assert!(
            hex.starts_with("02") || hex.starts_with("03"),
            "KeyImage hex should start with 02 or 03"
        );

        let recovered_key_image = KeyImage::from_hex(&hex)?;
        assert_eq!(key_image, recovered_key_image, "KeyImage round trip failed");

        Ok(())
    }

    #[test]
    fn test_key_image_invalid_hex() {
        assert!(
            matches!(KeyImage::from_hex("invalid"), Err(Error::HexDecode(_))),
            "Incorrect error for invalid hex chars in KeyImage"
        );
        // Invalid prefix (04 is uncompressed, KeyImage expects compressed 02/03)
        // hex_to_point handles this, returning PublicKeyFormat error
        assert!(
            matches!(
                KeyImage::from_hex(
                    "04abababababababababababababababababababababababababababababababab"
                ),
                Err(Error::PublicKeyFormat(_))
            ),
            "Incorrect error for invalid prefix in KeyImage"
        );
        // Hex representing point not on curve (hard to construct easily, relies on underlying check)
    }

    #[test]
    fn test_ring_signature_conversion() -> Result<(), Error> {
        let binary_sig = RingSignatureBinary {
            c0: Scalar::from(1u64),
            s: vec![Scalar::from(2u64), Scalar::from(3u64)],
        };

        let hex_sig: RingSignature = (&binary_sig).into();
        assert_eq!(hex_sig.c0, scalar_to_hex(&Scalar::from(1u64)));
        assert_eq!(hex_sig.s[0], scalar_to_hex(&Scalar::from(2u64)));
        assert_eq!(hex_sig.s[1], scalar_to_hex(&Scalar::from(3u64)));

        let recovered_binary: RingSignatureBinary = (&hex_sig).try_into()?;
        assert_eq!(
            binary_sig, recovered_binary,
            "RingSignature conversion round trip failed"
        );

        Ok(())
    }

    #[test]
    fn test_blsag_signature_conversion() -> Result<(), Error> {
        let binary_sig = BlsagSignatureBinary {
            c0: Scalar::from(4u64),
            s: vec![Scalar::from(5u64), Scalar::from(6u64)],
        };

        let hex_sig: BlsagSignature = (&binary_sig).into();
        assert_eq!(hex_sig.c0, scalar_to_hex(&Scalar::from(4u64)));
        assert_eq!(hex_sig.s[0], scalar_to_hex(&Scalar::from(5u64)));
        assert_eq!(hex_sig.s[1], scalar_to_hex(&Scalar::from(6u64)));

        let recovered_binary: BlsagSignatureBinary = (&hex_sig).try_into()?;
        assert_eq!(
            binary_sig, recovered_binary,
            "BlsagSignature conversion round trip failed"
        );

        Ok(())
    }
}
