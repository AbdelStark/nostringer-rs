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
/// * `private_key_input` - The signer's private key as a hex string or nsec string
/// * `ring_pubkeys_input` - The public keys of all ring members (including the signer) as hex or npub strings
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
/// use nostr::prelude::{Keys, ToBech32};
///
/// // Setup: Generate keys and create a ring
/// let keypair1 = Keys::generate();
/// let keypair2 = Keys::generate();
/// let nsec1 = keypair1.secret_key().to_bech32().expect("SecretKey to_bech32 should not fail");
/// let npub1 = keypair1.public_key().to_bech32().expect("PublicKey to_bech32 is infallible");
/// let npub2 = keypair2.public_key().to_bech32().expect("PublicKey to_bech32 is infallible");
/// let ring = vec![npub1, npub2];
///
/// // Sign with SAG (default, unlinkable) using nsec
/// let message = b"This is a secret message";
/// let signature = sign(message, &nsec1, &ring, SignatureVariant::Sag)?;
///
/// // Verify using npub keys
/// let is_valid = verify(&signature, message, &ring)?;
/// assert!(is_valid);
/// # Ok::<(), nostringer::Error>(())
/// ```
pub fn sign(
    message: &[u8],
    private_key_input: &str,
    ring_pubkeys_input: &[String],
    variant: SignatureVariant,
) -> Result<String, Error> {
    match variant {
        SignatureVariant::Sag => sign_compact_sag(message, private_key_input, ring_pubkeys_input),
        SignatureVariant::Blsag | SignatureVariant::BlsagWithFlag(_) => {
            sign_compact_blsag(message, private_key_input, ring_pubkeys_input, &variant)
        }
    }
}

/// Verifies a compact ring signature.
///
/// This function automatically detects whether the signature is SAG or BLSAG
/// based on the compact signature format, and verifies it accordingly.
/// It accepts public keys in hex or npub format.
///
/// # Arguments
/// * `compact_signature` - The compact signature string (ringA... format)
/// * `message` - The message that was supposedly signed
/// * `ring_pubkeys_input` - The public keys of all ring members as hex or npub strings
///
/// # Returns
/// * `Ok(bool)` - Whether the signature is valid for the given message and ring
/// * `Err(Error)` - If verification fails due to invalid format or other errors
///
/// # Example
///
/// ```
/// use nostringer::{sign, verify, SignatureVariant, generate_keypair_hex};
/// use nostr::prelude::{Keys, ToBech32};
///
/// // Setup: Generate keys and create a ring
/// let keypair1 = Keys::generate();
/// let keypair2 = Keys::generate();
/// let nsec1 = keypair1.secret_key().to_bech32().expect("SecretKey to_bech32 should not fail");
/// let npub1 = keypair1.public_key().to_bech32().expect("PublicKey to_bech32 is infallible");
/// let npub2 = keypair2.public_key().to_bech32().expect("PublicKey to_bech32 is infallible");
/// let ring_npub = vec![npub1, npub2];
/// let ring_hex = vec![keypair1.public_key().to_hex(), keypair2.public_key().to_hex()];
///
/// // Sign a message using hex keys
/// let message = b"This is a secret message";
/// let signature = sign(message, &keypair1.secret_key().to_secret_hex(), &ring_hex, SignatureVariant::Sag)?;
///
/// // Verify the signature using npub keys
/// let is_valid = verify(&signature, message, &ring_npub)?;
/// assert!(is_valid);
/// # Ok::<(), nostringer::Error>(())
/// ```
pub fn verify(
    compact_signature: &str,
    message: &[u8],
    ring_pubkeys_input: &[String],
) -> Result<bool, Error> {
    // Deserialize the compact signature string
    let compact_sig = CompactSignature::deserialize(compact_signature)
        .map_err(|e| Error::Serialization(e.to_string()))?;

    // Convert input pubkeys (hex or npub) to binary points
    let ring_pubkeys: Vec<k256::ProjectivePoint> = ring_pubkeys_input
        .iter()
        .map(|pubkey_str| utils::parse_public_key(pubkey_str))
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
/// Accepts keys in hex, npub, or nsec format.
///
/// # Arguments
/// * `message` - The message to sign as a byte array.
/// * `private_key_input` - The signer's private key as a hex or nsec string.
/// * `ring_pubkeys_input` - The public keys of all ring members as hex or npub strings.
///
/// # Returns
/// * `Ok(String)` - The compact serialized signature string.
/// * `Err(Error)` - If signing or serialization fails.
pub fn sign_compact_sag(
    message: &[u8],
    private_key_input: &str,
    ring_pubkeys_input: &[String],
) -> Result<String, Error> {
    // Parse the private key (hex or nsec)
    let private_key = utils::parse_secret_key(private_key_input)?;

    // Parse the public keys (hex or npub)
    let ring_pubkeys: Vec<k256::ProjectivePoint> = ring_pubkeys_input
        .iter()
        .map(|pubkey_str| utils::parse_public_key(pubkey_str))
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
/// Accepts keys in hex, npub, or nsec format.
///
/// # Arguments
/// * `message` - The message to sign as a byte array.
/// * `private_key_input` - The signer's private key as a hex or nsec string.
/// * `ring_pubkeys_input` - The public keys of all ring members as hex or npub strings.
///
/// # Returns
/// * `Ok(String)` - The compact serialized signature string.
/// * `Err(Error)` - If signing or serialization fails.
pub fn sign_compact_blsag(
    message: &[u8],
    private_key_input: &str,
    ring_pubkeys_input: &[String],
    signature_variant: &SignatureVariant,
) -> Result<String, Error> {
    // Parse the private key (hex or nsec)
    let private_key = utils::parse_secret_key(private_key_input)?;

    // Parse the public keys (hex or npub)
    let ring_pubkeys: Vec<k256::ProjectivePoint> = ring_pubkeys_input
        .iter()
        .map(|pubkey_str| utils::parse_public_key(pubkey_str))
        .collect::<Result<_, _>>()?;

    let linkability_flag = match signature_variant {
        SignatureVariant::BlsagWithFlag(flag) => Some(flag.as_bytes()),
        _ => None,
    };

    // Perform binary signing
    let (binary_sig, key_image) =
        blsag::sign_blsag_binary(message, &private_key, &ring_pubkeys, &linkability_flag)?;

    // Wrap and serialize
    let compact_sig = CompactSignature::Blsag(binary_sig, key_image);
    compact_sig
        .serialize()
        .map_err(|e| Error::Serialization(e.to_string()))
}

/// Verifies a compact, serialized ring signature (`ringA...` format).
///
/// Deserializes the signature and then uses the optimized binary verification.
/// Accepts public keys in hex or npub format.
///
/// # Arguments
/// * `compact_signature` - The `ringA...` formatted signature string.
/// * `message` - The message that was supposedly signed.
/// * `ring_pubkeys_input` - The public keys of all ring members as hex or npub strings.
///
/// # Returns
/// * `Ok(bool)` - Whether the signature is valid for the given message and ring.
/// * `Err(Error)` - If deserialization or verification fails.
pub fn verify_compact(
    compact_signature: &str,
    message: &[u8],
    ring_pubkeys_input: &[String],
) -> Result<bool, Error> {
    // This function now just delegates to verify, which handles the parsing.
    verify(compact_signature, message, ring_pubkeys_input)
}

#[cfg(test)]
mod bech32_tests {
    use super::*; // Import items from parent module (lib.rs)
    use nostr::prelude::{Keys, ToBech32};

    #[test]
    fn test_sign_verify_sag_with_bech32() -> Result<(), Error> {
        let keypair1 = Keys::generate();
        let keypair2 = Keys::generate();
        let keypair3 = Keys::generate();

        // Get the secret key as nsec
        let nsec2 = keypair2
            .secret_key()
            .to_bech32()
            .expect("SecretKey to_bech32 should not fail");

        // Get public keys as npub
        let npub1 = keypair1
            .public_key()
            .to_bech32()
            .expect("PublicKey to_bech32 is infallible");
        let npub2 = keypair2
            .public_key()
            .to_bech32()
            .expect("PublicKey to_bech32 is infallible");
        let npub3 = keypair3
            .public_key()
            .to_bech32()
            .expect("PublicKey to_bech32 is infallible");

        let ring = vec![npub1, npub2.clone(), npub3];
        let message = b"test message sag bech32";

        // Sign using nsec2
        let signature = sign(message, &nsec2, &ring, SignatureVariant::Sag)?;

        // Verify using npub keys
        let is_valid = verify(&signature, message, &ring)?;
        assert!(is_valid, "SAG signature should be valid with npub keys");

        // Verify with one hex key mixed in
        let ring_mixed = vec![
            keypair1.public_key().to_hex(),
            npub2,
            keypair3.public_key().to_hex(),
        ];
        let is_valid_mixed = verify(&signature, message, &ring_mixed)?;
        assert!(
            is_valid_mixed,
            "SAG signature should be valid with mixed hex/npub keys"
        );

        Ok(())
    }

    #[test]
    fn test_sign_verify_blsag_with_bech32() -> Result<(), Error> {
        let keypair1 = Keys::generate();
        let keypair2 = Keys::generate();

        // Get the secret key as nsec
        let nsec1 = keypair1
            .secret_key()
            .to_bech32()
            .expect("SecretKey to_bech32 should not fail");

        // Get public keys as npub
        let npub1 = keypair1
            .public_key()
            .to_bech32()
            .expect("PublicKey to_bech32 is infallible");
        let npub2 = keypair2
            .public_key()
            .to_bech32()
            .expect("PublicKey to_bech32 is infallible");

        let ring = vec![npub1.clone(), npub2];
        let message = b"test message blsag bech32";

        // Sign using nsec1
        let signature = sign(message, &nsec1, &ring, SignatureVariant::Blsag)?;

        // Verify using npub keys
        let is_valid = verify(&signature, message, &ring)?;
        assert!(is_valid, "BLSAG signature should be valid with npub keys");

        // Verify with hex keys
        let ring_hex = vec![
            keypair1.public_key().to_hex(),
            keypair2.public_key().to_hex(),
        ];
        let is_valid_hex = verify(&signature, message, &ring_hex)?;
        assert!(
            is_valid_hex,
            "BLSAG signature should be valid when verifying with hex keys"
        );

        Ok(())
    }

    #[test]
    fn test_sign_with_hex_verify_with_bech32() -> Result<(), Error> {
        let keypair1 = Keys::generate();
        let keypair2 = Keys::generate();

        // Get the secret key as hex
        let sec1_hex = keypair1.secret_key().to_secret_hex();

        let pub1_hex = keypair1.public_key().to_hex();
        let pub2_hex = keypair2.public_key().to_hex();

        let pub1_npub = keypair1
            .public_key()
            .to_bech32()
            .expect("PublicKey to_bech32 is infallible");
        let pub2_npub = keypair2
            .public_key()
            .to_bech32()
            .expect("PublicKey to_bech32 is infallible");

        let ring_hex = vec![pub1_hex, pub2_hex];
        let ring_npub = vec![pub1_npub, pub2_npub];
        let message = b"sign hex verify bech32";

        // Sign using hex secret key and hex ring
        let signature = sign(message, &sec1_hex, &ring_hex, SignatureVariant::Sag)?;

        // Verify using npub ring
        let is_valid = verify(&signature, message, &ring_npub)?;
        assert!(
            is_valid,
            "Should be able to verify with npub keys a signature made with hex keys"
        );

        Ok(())
    }

    #[test]
    fn test_invalid_nsec_input() -> Result<(), Error> {
        let keypair1 = Keys::generate();
        let keypair2 = Keys::generate();
        let npub1 = keypair1
            .public_key()
            .to_bech32()
            .expect("PublicKey to_bech32 is infallible");
        let npub2 = keypair2
            .public_key()
            .to_bech32()
            .expect("PublicKey to_bech32 is infallible");
        let ring = vec![npub1, npub2];
        let message = b"invalid nsec test";

        let invalid_nsec = "nsec1invalid";
        let result = sign(message, invalid_nsec, &ring, SignatureVariant::Sag);
        assert!(
            matches!(result, Err(Error::SecretKeyFormat(_))),
            "Should fail with SecretKeyFormat error"
        );

        let invalid_hex_nsec = "deadbeef"; // Short invalid hex
        let result_hex = sign(message, invalid_hex_nsec, &ring, SignatureVariant::Sag);
        // The actual error could be either PrivateKeyFormat or HexDecode depending on implementation
        assert!(result_hex.is_err(), "Should fail with invalid hex format");

        Ok(())
    }

    #[test]
    fn test_invalid_npub_input() -> Result<(), Error> {
        // First create some valid keys
        let keypair1 = Keys::generate();
        let keypair2 = Keys::generate();
        let valid_npub1 = keypair1
            .public_key()
            .to_bech32()
            .expect("PublicKey to_bech32 is infallible");
        let valid_npub2 = keypair2
            .public_key()
            .to_bech32()
            .expect("PublicKey to_bech32 is infallible");
        let nsec1 = keypair1
            .secret_key()
            .to_bech32()
            .expect("SecretKey to_bech32 should not fail");

        let message = b"invalid npub test";

        // Create rings with both valid and invalid npubs to avoid RingTooSmall error
        let invalid_npub = "npub1invalid";
        let ring_invalid = vec![valid_npub1.clone(), invalid_npub.to_string()];

        // Test signing with invalid npub in ring
        let result_sign = sign(message, &nsec1, &ring_invalid, SignatureVariant::Sag);
        assert!(
            matches!(result_sign, Err(Error::PublicKeyFormat(_))),
            "Signing should fail with invalid npub"
        );

        // Test verifying with invalid npub in ring
        let invalid_hex_npub = "deadbeef"; // Obviously not valid npub
        let ring_invalid_hex = vec![valid_npub2.clone(), invalid_hex_npub.to_string()];

        // Create a valid signature first
        let valid_ring = vec![valid_npub1.clone(), valid_npub2.clone()];
        let valid_sig = sign(b"temp", &nsec1, &valid_ring, SignatureVariant::Sag)?;

        let result_verify_bech32 = verify(&valid_sig, b"temp", &ring_invalid);
        assert!(
            matches!(result_verify_bech32, Err(Error::PublicKeyFormat(_))),
            "Verify should fail with invalid npub"
        );

        let result_verify_hex = verify(&valid_sig, b"temp", &ring_invalid_hex);
        assert!(
            matches!(result_verify_hex, Err(Error::PublicKeyFormat(_))),
            "Verify should fail with invalid hex as npub"
        );

        Ok(())
    }
}
