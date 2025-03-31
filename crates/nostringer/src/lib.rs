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
//! use nostringer::{sign, verify, SignatureVariant, types::KeyPairHex, keys::generate_keypair_hex};
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
//!     // 3. Signer (keypair2) signs the message using the default SAG signature variant
//!     let signature = sign(
//!         message,
//!         &keypair2.private_key_hex,
//!         &ring_pubkeys_hex,
//!         SignatureVariant::Sag,
//!     )?;
//!
//!     println!("Generated Compact Signature: {}", signature);
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
pub use types::{Error, KeyPair, KeyPairHex, RingSignature, RingSignatureBinary, SignatureVariant};

// Re-export serialization types and functions
pub use serialization::{CompactSignature, SerializationError};

pub use types::hex_to_scalar;

pub use keys::{generate_keypair_hex, generate_keypairs, get_public_keys};

// Add a conversion from SerializationError to Error
impl From<SerializationError> for Error {
    fn from(err: SerializationError) -> Self {
        Error::Serialization(err.to_string())
    }
}

/// Signs a message with a ring signature in compact format.
///
/// This is the main signing function that creates a compact, serialized ring signature.
/// By default, it uses the SAG variant, but you can specify BLSAG for linkable signatures.
///
/// # Arguments
/// * `message` - The message to sign as a byte array
/// * `private_key_hex` - The signer's private key as a hex string
/// * `ring_pubkeys_hex` - The public keys of all ring members (including the signer) as hex strings
/// * `variant` - The signature variant to use (SAG or BLSAG)
///
/// # Returns
/// * `Ok(String)` - The compact serialized signature string (ringA... format)
/// * `Err(Error)` - If signing or serialization fails
///
/// # Example
///
/// ```
/// use nostringer::{sign, verify, SignatureVariant, generate_keypair_hex};
///
/// // Setup: Generate keys and create a ring
/// let keypair1 = generate_keypair_hex("xonly");
/// let keypair2 = generate_keypair_hex("xonly");
/// let ring = vec![keypair1.public_key_hex.clone(), keypair2.public_key_hex.clone()];
///
/// // Sign with SAG (default, unlinkable)
/// let message = b"This is a secret message";
/// let signature = sign(message, &keypair1.private_key_hex, &ring, SignatureVariant::Sag)?;
///
/// // Verify
/// let is_valid = verify(&signature, message, &ring)?;
/// assert!(is_valid);
/// # Ok::<(), nostringer::Error>(())
/// ```
pub fn sign(
    message: &[u8],
    private_key_hex: &str,
    ring_pubkeys_hex: &[String],
    variant: SignatureVariant,
) -> Result<String, Error> {
    match variant {
        SignatureVariant::Sag => sign_compact_sag(message, private_key_hex, ring_pubkeys_hex),
        SignatureVariant::Blsag => sign_compact_blsag(message, private_key_hex, ring_pubkeys_hex),
    }
}

/// Verifies a compact ring signature.
///
/// This function automatically detects whether the signature is SAG or BLSAG
/// based on the compact signature format, and verifies it accordingly.
///
/// # Arguments
/// * `compact_signature` - The compact signature string (ringA... format)
/// * `message` - The message that was supposedly signed
/// * `ring_pubkeys_hex` - The public keys of all ring members as hex strings
///
/// # Returns
/// * `Ok(bool)` - Whether the signature is valid for the given message and ring
/// * `Err(Error)` - If verification fails due to invalid format or other errors
///
/// # Example
///
/// ```
/// use nostringer::{sign, verify, SignatureVariant, generate_keypair_hex};
///
/// // Setup: Generate keys and create a ring
/// let keypair1 = generate_keypair_hex("xonly");
/// let keypair2 = generate_keypair_hex("xonly");
/// let ring = vec![keypair1.public_key_hex.clone(), keypair2.public_key_hex.clone()];
///
/// // Sign a message
/// let message = b"This is a secret message";
/// let signature = sign(message, &keypair1.private_key_hex, &ring, SignatureVariant::Sag)?;
///
/// // Verify the signature
/// let is_valid = verify(&signature, message, &ring)?;
/// assert!(is_valid);
/// # Ok::<(), nostringer::Error>(())
/// ```
pub fn verify(
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
    verify(compact_signature, message, ring_pubkeys_hex)
}
