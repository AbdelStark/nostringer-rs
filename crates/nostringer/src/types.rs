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
        return Err(Error::PublicKeyFormat(format!(
            "Non-hex characters found: {}",
            hex_str
        )));
    }
    Ok(lower)
}
