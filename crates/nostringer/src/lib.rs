//! # Nostringer Ring Signatures (Rust)
//!
//! A Rust implementation of Ring signatures (SAG, BLSAG) for Nostr.
//!
//! This library provides functions to sign and verify messages using a
//! Spontaneous Anonymous Group (SAG)-like or Back's Linkable Spontaneous Anonymous Group (bLSAG) ring signature scheme over the
//! secp256k1 curve.
//!
//! ## Modules
//!
//! - `sag`: Implements the original Spontaneous Anonymous Group (SAG) ring signature.
//! - `blsag`: Implements the Back's Linkable Spontaneous Anonymous Group (bLSAG) ring signature.
//! - `types`: Defines common types like keys, signatures, and errors.
//! - `utils`: Provides utility functions for hashing, conversions, etc.
//! - `wasm`: Contains bindings for WebAssembly usage.
//! - `keys`: Contains key-related functions.
//! - `serialization`: Implements compact signature serialization.
//!
//! ## Usage
//!
//! ```rust
//! use nostringer::{sag, types::KeyPairHex, keys::generate_keypair_hex};
//! use std::collections::HashMap; // Example, not needed for basic usage
//!
//! fn main() -> Result<(), nostringer::types::Error> {
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
//!     // 3. Signer (keypair2) signs the message using SAG
//!     let signature = sag::sign(
//!         message,
//!         &keypair2.private_key_hex,
//!         &ring_pubkeys_hex,
//!     )?;
//!
//!     println!("Generated SAG Signature:");
//!     println!(" c0: {}", signature.c0);
//!     println!(" s: {:?}", signature.s);
//!
//!     // 4. Verification: Anyone can verify the signature against the ring
//!     let is_valid = sag::verify(
//!         &signature,
//!         message,
//!         &ring_pubkeys_hex,
//!     )?;
//!
//!     println!("Signature valid: {}", is_valid);
//!     assert!(is_valid);
//!
//!     Ok(())
//! }
//! ```

pub mod blsag;
pub mod keys;
pub mod sag;
pub mod serialization;
pub mod types;
pub mod utils;
#[cfg(feature = "wasm")]
pub mod wasm;

// Re-export core types for convenience
pub use types::{Error, KeyPair, KeyPairHex, RingSignature, RingSignatureBinary};

// Re-export serialization types and functions
pub use serialization::{CompactSignature, SerializationError};

pub use types::hex_to_scalar; // Re-export hex_to_scalar
                              // Re-export key-related functions
pub use keys::{generate_keypair_hex, generate_keypairs, get_public_keys};

// Add a conversion from SerializationError to Error
impl From<SerializationError> for Error {
    fn from(err: SerializationError) -> Self {
        Error::Serialization(err.to_string())
    }
}

// --- New Top-Level Compact API ---

/// Creates a compact, serialized SAG ring signature (`ringA...` format).
///
/// Uses the optimized binary signing internally and then serializes the result.
///
/// # Arguments
/// * `message` - The message to sign as a byte array.
/// * `private_key_hex` - The signer's private key as a hex string.
/// * `ring_pubkeys_hex` - The public keys of all ring members as hex strings.
///
/// # Returns
/// * `Ok(String)` - The compact serialized signature string.
/// * `Err(Error)` - If signing or serialization fails.
pub fn sign_compact_sag(
    message: &[u8],
    private_key_hex: &str,
    ring_pubkeys_hex: &[String],
) -> Result<String, Error> {
    // Convert hex inputs to binary types needed for signing
    let private_key = hex_to_scalar(private_key_hex)?;
    let ring_pubkeys: Vec<k256::ProjectivePoint> = ring_pubkeys_hex
        .iter()
        .map(|pubkey_str| utils::hex_to_point(pubkey_str))
        .collect::<Result<_, _>>()?;

    // Perform the binary signing
    let binary_signature =
        sag::sign_binary(message, &private_key, &ring_pubkeys, rand::rngs::OsRng)?;

    // Wrap in CompactSignature and serialize
    let compact_sig = CompactSignature::Sag(binary_signature);
    compact_sig
        .serialize()
        .map_err(|e| Error::Serialization(e.to_string()))
}

/// Creates a compact, serialized bLSAG ring signature (`ringA...` format).
///
/// Uses the optimized binary signing internally and then serializes the result.
///
/// # Arguments
/// * `message` - The message to sign as a byte array.
/// * `private_key_hex` - The signer's private key as a hex string.
/// * `ring_pubkeys_hex` - The public keys of all ring members as hex strings.
///
/// # Returns
/// * `Ok(String)` - The compact serialized signature string.
/// * `Err(Error)` - If signing or serialization fails.
pub fn sign_compact_blsag(
    message: &[u8],
    private_key_hex: &str,
    ring_pubkeys_hex: &[String],
) -> Result<String, Error> {
    // Convert hex inputs to binary types
    let private_key = hex_to_scalar(private_key_hex)?;
    let ring_pubkeys: Vec<k256::ProjectivePoint> = ring_pubkeys_hex
        .iter()
        .map(|pubkey_str| utils::hex_to_point(pubkey_str))
        .collect::<Result<_, _>>()?;

    // Perform binary signing
    let (binary_sig, key_image) = blsag::sign_blsag_binary(message, &private_key, &ring_pubkeys)?;

    // Wrap and serialize
    let compact_sig = CompactSignature::Blsag(binary_sig, key_image);
    compact_sig
        .serialize()
        .map_err(|e| Error::Serialization(e.to_string()))
}

/// Verifies a compact, serialized ring signature (`ringA...` format).
///
/// Deserializes the signature and then uses the optimized binary verification.
///
/// # Arguments
/// * `compact_signature` - The `ringA...` formatted signature string.
/// * `message` - The message that was supposedly signed.
/// * `ring_pubkeys_hex` - The public keys of all ring members as hex strings.
///
/// # Returns
/// * `Ok(bool)` - Whether the signature is valid for the given message and ring.
/// * `Err(Error)` - If deserialization or verification fails.
pub fn verify_compact(
    compact_signature: &str,
    message: &[u8],
    ring_pubkeys_hex: &[String],
) -> Result<bool, Error> {
    // Deserialize the compact signature string
    let compact_sig = CompactSignature::deserialize(compact_signature)
        .map_err(|e| Error::Serialization(e.to_string()))?;

    // Convert hex pubkeys to binary points
    let ring_pubkeys: Vec<k256::ProjectivePoint> = ring_pubkeys_hex
        .iter()
        .map(|pubkey_str| utils::hex_to_point(pubkey_str))
        .collect::<Result<_, _>>()?;

    // Call the appropriate binary verification function
    match compact_sig {
        CompactSignature::Sag(binary_sig) => {
            sag::verify_binary(&binary_sig, message, &ring_pubkeys)
        }
        CompactSignature::Blsag(binary_sig, key_image) => {
            // For BLSAG, we need the key image from the deserialized data
            blsag::verify_blsag_binary(&binary_sig, &key_image, message, &ring_pubkeys)
        }
    }
}
