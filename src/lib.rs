//! # Nostringer Ring Signatures (Rust)
//!
//! A Rust implementation of the ring signature scheme in the
//! [nostringer](https://github.com/AbdelStark/nostringer) TypeScript library.
//!
//! This library provides functions to sign and verify messages using a
//! Spontaneous Anonymous Group (SAG)-like ring signature scheme over the
//! secp256k1 curve. It aims for compatibility with the original TS implementation.
//!
//! ## Usage
//!
//! ```rust
//! use nostringer::{sign, verify, generate_keypair_hex, RingSignature};
//! use k256::SecretKey;
//! use std::collections::HashMap; // Example, not needed for basic usage
//!
//! fn main() -> Result<(), nostringer::Error> {
//!     // 1. Setup: Generate keys for the ring members
//!     let keypair1 = generate_keypair_hex("xonly"); // Use "xonly", "compressed", or "uncompressed"
//!     let keypair2 = generate_keypair_hex("xonly");
//!     let keypair3 = generate_keypair_hex("xonly");
//!
//!     let ring_pubkeys_hex = vec![
//!         keypair1.public_key_hex.clone(),
//!         keypair2.public_key_hex.clone(),
//!         keypair3.public_key_hex.clone(),
//!     ];
//!
//!     // 2. Define the message to be signed
//!     let message = b"This is a secret message to the group.";
//!
//!     // 3. Signer (keypair2) signs the message
//!     let signature = sign(
//!         message,
//!         &keypair2.private_key_hex,
//!         &ring_pubkeys_hex,
//!     )?;
//!
//!     println!("Generated Signature:");
//!     println!(" c0: {}", signature.c0);
//!     println!(" s: {:?}", signature.s);
//!
//!     // 4. Verification: Anyone can verify the signature against the ring
//!     let is_valid = verify(
//!         &signature,
//!         message,
//!         &ring_pubkeys_hex,
//!     )?;
//!
//!     println!("Signature valid: {}", is_valid);
//!     assert!(is_valid);
//!
//!     // 5. Tamper test: Verification should fail if the message changes
//!     let tampered_message = b"This is a different message.";
//!     let is_tampered_valid = verify(
//!         &signature,
//!         tampered_message,
//!         &ring_pubkeys_hex,
//!     )?;
//!     println!("Tampered signature valid: {}", is_tampered_valid);
//!     assert!(!is_tampered_valid);
//!
//!     Ok(())
//! }
//! ```

use k256::elliptic_curve::{
    PrimeField,
    ops::Reduce,
    point::AffineCoordinates,
    rand_core::{self},
    sec1::ToEncodedPoint,
};
use k256::{NonZeroScalar, ProjectivePoint, PublicKey, Scalar, SecretKey, U256};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use subtle::{ConditionallySelectable, ConstantTimeEq};
use thiserror::Error;

// Optional: Add serde imports gated by feature
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The generator point G for the secp256k1 curve
const GENERATOR: ProjectivePoint = ProjectivePoint::GENERATOR;

/// Errors that can occur during ring signature operations
#[derive(Error, Debug)]
pub enum Error {
    /// Error in hexadecimal decoding
    #[error("Hex decoding failed: {0}")]
    HexDecode(#[from] hex::FromHexError),

    /// Error in private key format or validation
    #[error("Invalid private key format: {0}")]
    PrivateKeyFormat(String),

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

/// Creates a ring signature for a message using the provided private key and ring of public keys
///
/// This function implements the core ring signature algorithm:
/// 1. Finds the signer's position in the ring
/// 2. Generates random scalars for all other ring members
/// 3. Computes the signature components in a cyclic manner
/// 4. Completes the ring using the signer's private key
///
/// # Arguments
/// * `message` - The message to sign as a byte array
/// * `private_key_hex` - The signer's private key as a hex string
/// * `ring_pubkeys_hex` - The public keys of all ring members as hex strings
///
/// # Returns
/// * `Ok(RingSignature)` - The generated ring signature
/// * `Err(Error)` - If any step in the signature generation fails
///
/// # Errors
/// Returns an error if:
/// * The ring has fewer than 2 members
/// * The private key format is invalid
/// * The signer's public key is not in the ring
/// * Any cryptographic operation fails
pub fn sign(
    message: &[u8],
    private_key_hex: &str,
    ring_pubkeys_hex: &[String],
) -> Result<RingSignature, Error> {
    let ring_size = ring_pubkeys_hex.len();
    if ring_size < 2 {
        return Err(Error::RingTooSmall(ring_size));
    }

    // Convert private key from hex to scalar
    let d = hex_to_scalar(private_key_hex)?;
    if d == Scalar::ZERO {
        return Err(Error::PrivateKeyFormat(
            "Private key scalar cannot be zero".into(),
        ));
    }
    let _d_nonzero =
        NonZeroScalar::new(d).expect("d was checked non-zero, NonZeroScalar::new must succeed");

    // Convert all public keys to curve points
    let ring_points: Vec<ProjectivePoint> = ring_pubkeys_hex
        .iter()
        .map(|pubkey_str| hex_to_point(pubkey_str))
        .collect::<Result<_, _>>()?;

    // Compute the signer's public key point in both normal and negated form
    let my_point = GENERATOR * d;
    let flipped_d = d.negate();
    let flipped_point = GENERATOR * flipped_d;

    // Find the signer's position in the ring
    let mut signer_index: Option<usize> = None;
    let mut used_d = d;
    for (i, p) in ring_points.iter().enumerate() {
        if p == &my_point {
            signer_index = Some(i);
            used_d = d;
            break;
        }
        if p == &flipped_point {
            signer_index = Some(i);
            used_d = flipped_d;
            break;
        }
    }
    let signer_index = signer_index.ok_or(Error::SignerNotInRing)?;

    // Initialize vectors for the signature components
    let mut r_scalars = vec![Scalar::ZERO; ring_size];
    let mut c_scalars = vec![Scalar::ZERO; ring_size];
    let os_rng = OsRng;

    // Generate a random scalar alpha and compute alpha*G
    let alpha_nonzero = random_non_zero_scalar(os_rng);
    let alpha = *alpha_nonzero.as_ref();
    let alpha_g = GENERATOR * alpha;

    // Start the ring signature process at the position after the signer
    let start_index = (signer_index + 1) % ring_size;
    c_scalars[start_index] = hash_to_scalar(message, ring_pubkeys_hex, &alpha_g)?;

    // Generate random components for each member and build the ring
    let mut current_index = start_index;
    while current_index != signer_index {
        // Random scalar for this ring member
        let r_nonzero = random_non_zero_scalar(os_rng);
        r_scalars[current_index] = *r_nonzero.as_ref();

        // Compute the ring link: x_i = r_i*G + c_i*P_i
        let xi = (GENERATOR * r_scalars[current_index])
            + (ring_points[current_index] * c_scalars[current_index]);

        // Hash to get the next challenge
        let next_index = (current_index + 1) % ring_size;
        c_scalars[next_index] = hash_to_scalar(message, ring_pubkeys_hex, &xi)?;
        current_index = next_index;
    }

    // Complete the ring by computing the signer's s value
    r_scalars[signer_index] = alpha - (c_scalars[signer_index] * used_d);

    // Convert to hex format and return the signature
    Ok(RingSignature {
        c0: scalar_to_hex(&c_scalars[0]),
        s: r_scalars.iter().map(scalar_to_hex).collect(),
    })
}

/// Verifies a ring signature against a message and a ring of public keys
///
/// This function implements the ring signature verification algorithm:
/// 1. Converts all components from hex to their scalar/point representations
/// 2. Recomputes the ring links using the signature components
/// 3. Checks if the ring closes properly (c₀ = c_n)
///
/// # Arguments
/// * `signature` - The ring signature to verify
/// * `message` - The message that was signed
/// * `ring_pubkeys_hex` - The public keys of all ring members as hex strings
///
/// # Returns
/// * `Ok(bool)` - Whether the signature is valid
/// * `Err(Error)` - If any step in the verification process fails
///
/// # Errors
/// Returns an error if:
/// * The signature format is invalid
/// * Any hex conversion fails
/// * Any cryptographic operation fails
pub fn verify(
    signature: &RingSignature,
    message: &[u8],
    ring_pubkeys_hex: &[String],
) -> Result<bool, Error> {
    let ring_size = ring_pubkeys_hex.len();
    if ring_size == 0 {
        return Ok(false);
    }
    if signature.s.len() != ring_size {
        return Err(Error::InvalidSignatureFormat);
    }

    // Convert c0 from hex to scalar
    let c0_scalar = hex_to_scalar(&signature.c0)?;

    // Convert all s values from hex to scalars
    let r_scalars: Vec<Scalar> = signature
        .s
        .iter()
        .map(|s_hex| hex_to_scalar(s_hex))
        .collect::<Result<_, _>>()?;

    // Convert all public keys to curve points
    let ring_points: Vec<ProjectivePoint> = ring_pubkeys_hex
        .iter()
        .map(|pubkey_str| hex_to_point(pubkey_str))
        .collect::<Result<_, _>>()?;

    // Verify the ring by recomputing each link
    let mut current_c = c0_scalar;
    for i in 0..ring_size {
        // Compute x_i = s_i*G + c_i*P_i
        let xi = (GENERATOR * r_scalars[i]) + (ring_points[i] * current_c);
        // Hash to get the next challenge
        current_c = hash_to_scalar(message, ring_pubkeys_hex, &xi)?;
    }

    // Check if the ring closes (c_n == c₀)
    let is_valid = current_c.ct_eq(&c0_scalar);
    Ok(is_valid.into())
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
fn normalize_hex(hex_str: &str) -> Result<String, Error> {
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

/// Converts a scalar value to a hexadecimal string
///
/// # Arguments
/// * `scalar` - The scalar value to convert
///
/// # Returns
/// The scalar encoded as a lowercase hex string without prefix
fn scalar_to_hex(scalar: &Scalar) -> String {
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
fn hex_to_scalar(hex_str: &str) -> Result<Scalar, Error> {
    // Pad to 64 characters if shorter
    let padded_hex = if hex_str.len() < 64 {
        format!("{:0>64}", hex_str)
    } else {
        hex_str.to_string()
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
    let maybe_scalar = Scalar::from_repr(*field_bytes); // Deref FieldBytes to GenericArray

    if maybe_scalar.is_some().into() {
        Ok(maybe_scalar.unwrap())
    } else {
        Err(Error::InvalidScalarEncoding)
    }
}

/// Converts a hexadecimal public key string to a curve point
///
/// Supports multiple formats:
/// - 64 hex chars: x-coordinate only (xonly)
/// - 66 hex chars: compressed format (02/03 prefix + x-coordinate)
/// - 130 hex chars: uncompressed format (04 prefix + x-coordinate + y-coordinate)
///
/// # Arguments
/// * `pubkey_hex` - The public key as a hex string
///
/// # Returns
/// * `Ok(ProjectivePoint)` - The public key as a curve point
/// * `Err(Error)` - If the format is invalid or the point is not on the curve
///
/// # Errors
/// Returns an error if:
/// * The hex string length is invalid
/// * The format prefix is invalid
/// * The point is not on the curve
fn hex_to_point(pubkey_hex: &str) -> Result<ProjectivePoint, Error> {
    let hex_norm = normalize_hex(pubkey_hex)?;
    let point_bytes = match hex_norm.len() {
        // x-coordinate only, assume 02 prefix (even y)
        64 => hex::decode(format!("02{}", hex_norm))?,

        // Compressed format (02/03 prefix + x-coordinate)
        66 => {
            if !hex_norm.starts_with("02") && !hex_norm.starts_with("03") {
                return Err(Error::PublicKeyFormat(format!(
                    "Invalid prefix: {}",
                    &hex_norm[..2]
                )));
            }
            hex::decode(&hex_norm)?
        }

        // Uncompressed format (04 prefix + x-coordinate + y-coordinate)
        130 => {
            if !hex_norm.starts_with("04") {
                return Err(Error::PublicKeyFormat(format!(
                    "Invalid prefix: {}",
                    &hex_norm[..2]
                )));
            }
            hex::decode(&hex_norm)?
        }

        // Invalid length
        _ => {
            return Err(Error::PublicKeyFormat(format!(
                "Invalid length: {}",
                hex_norm.len()
            )));
        }
    };

    // Parse the SEC1 formatted bytes to a public key
    let public_key = PublicKey::from_sec1_bytes(&point_bytes)
        .map_err(|e| Error::PublicKeyFormat(format!("SEC1 parse error: {}", e)))?;

    // Convert to projective representation
    Ok(public_key.to_projective())
}

/// Generates a non-zero random scalar using the provided random number generator
///
/// # Arguments
/// * `rng` - A cryptographically secure random number generator
///
/// # Returns
/// A non-zero scalar value from the Secp256k1 field
fn random_non_zero_scalar(
    mut rng: impl rand_core::RngCore + rand_core::CryptoRng,
) -> NonZeroScalar {
    NonZeroScalar::random(&mut rng)
}

/// Hashes a message, ring public keys, and an ephemeral point to a scalar value
///
/// This is a key part of the ring signature scheme, creating challenges from message content.
/// The function computes SHA256(message || pubkeys || ephemeral_point) and converts the
/// result to a scalar, ensuring it's non-zero.
///
/// # Arguments
/// * `message` - The message being signed or verified
/// * `ring_pubkeys_hex` - All public keys in the ring as hex strings
/// * `ephemeral_point` - An ephemeral curve point (part of the ring computation)
///
/// # Returns
/// * `Ok(Scalar)` - The resulting scalar (guaranteed non-zero)
/// * `Err(Error)` - If any part of the hashing process fails
///
/// # Errors
/// Returns an error if normalizing or decoding any public key fails
fn hash_to_scalar(
    message: &[u8],
    ring_pubkeys_hex: &[String],
    ephemeral_point: &ProjectivePoint,
) -> Result<Scalar, Error> {
    // Initialize hasher
    let mut hasher = Sha256::new();

    // Hash the message
    hasher.update(message);

    // Hash all public keys in the ring
    for pk_hex in ring_pubkeys_hex {
        let norm_hex = normalize_hex(pk_hex)?;
        let pk_bytes = hex::decode(&norm_hex)?;
        hasher.update(&pk_bytes);
    }

    // Hash the ephemeral point (in compressed format)
    let ephemeral_compressed = ephemeral_point.to_encoded_point(true);
    hasher.update(ephemeral_compressed.as_bytes());

    // Finalize hash
    let hash_result = hasher.finalize();

    // Convert hash to a scalar
    let hash_uint = U256::from_be_slice(&hash_result);
    let scalar = Scalar::reduce(hash_uint);

    // Ensure result is non-zero (use Scalar::ONE if zero)
    let is_zero = scalar.ct_eq(&Scalar::ZERO);
    Ok(Scalar::conditional_select(&scalar, &Scalar::ONE, is_zero))
}

/// Generates a keypair with private and public keys in hexadecimal format
///
/// # Arguments
/// * `format` - The format for the public key:
///   * "xonly" - X coordinate only (32 bytes)
///   * "compressed" - Compressed format with prefix (33 bytes)
///   * "uncompressed" - Uncompressed format with prefix (65 bytes)
///
/// # Returns
/// A KeyPairHex with private and public keys in the specified format
pub fn generate_keypair_hex(format: &str) -> KeyPairHex {
    // Generate a random non-zero scalar
    let os_rng = OsRng;
    let secret_scalar_nonzero = random_non_zero_scalar(os_rng);
    let secret_key = SecretKey::from(secret_scalar_nonzero);
    let secret_scalar = *secret_scalar_nonzero.as_ref();
    let private_key_hex = scalar_to_hex(&secret_scalar);

    // Compute the public key
    let public_key = secret_key.public_key();
    let mut point = public_key.to_projective();

    // Format the public key according to the requested format
    let public_key_hex = match format {
        "xonly" => {
            // Ensure Y coordinate is even (x-only format for BIP340 compatibility)
            let affine = point.to_affine();
            let y_is_odd = affine.y_is_odd();

            // If Y is odd, negate the point to get the even Y variant
            if y_is_odd.into() {
                let flipped_scalar = secret_scalar.negate();
                point = GENERATOR * flipped_scalar;
            }
            let final_affine = point.to_affine();
            hex::encode(final_affine.x().as_slice())
        }
        // Standard SEC1 formats
        "uncompressed" => hex::encode(point.to_encoded_point(false).as_bytes()),
        "compressed" => hex::encode(point.to_encoded_point(true).as_bytes()),
        // Default to compressed format
        _ => hex::encode(point.to_encoded_point(true).as_bytes()),
    };

    KeyPairHex {
        private_key_hex,
        public_key_hex,
    }
}

/// Generates multiple keypairs in the specified format
///
/// # Arguments
/// * `count` - The number of keypairs to generate
/// * `format` - The format for the public keys (see `generate_keypair_hex`)
///
/// # Returns
/// A vector of KeyPairHex structures
pub fn generate_keypairs(count: usize, format: &str) -> Vec<KeyPairHex> {
    (0..count).map(|_| generate_keypair_hex(format)).collect()
}

/// Extracts the public keys from a slice of keypairs
///
/// # Arguments
/// * `keypairs` - A slice of KeyPairHex structures
///
/// # Returns
/// A vector containing only the public keys as strings
pub fn get_public_keys(keypairs: &[KeyPairHex]) -> Vec<String> {
    keypairs
        .iter()
        .map(|kp| kp.public_key_hex.clone())
        .collect()
}
