//! # Nostringer Ring Signatures (Rust)
//!
//! A Rust implementation of the ring signature scheme in the
//! [nostringer](https://github.com/AbdelStark/nostringer) TypeScript library.
//!
//! This library provides functions to sign and verify messages using a
//! Spontaneous Anonymous Group (SAG)-like ring signature scheme over the
//! secp256k1 curve. It aims for compatibility with the original TS implementation.
//!
//! ## Optimized API
//!
//! This library provides two sets of APIs:
//! - Hex-encoded interfaces (`sign`, `verify`, `sign_with_hex`, `verify_with_hex`) that work with hex strings
//! - Binary interfaces (`sign_binary`, `verify_binary`) that work directly with scalar and curve point types
//!   for improved performance
//!
//! For maximum performance in Rust applications, prefer the binary interfaces when possible.
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
//!
//! ## Binary API Example (more efficient)
//!
//! ```rust,no_run
//! use nostringer::{sign_binary, verify_binary, KeyPair, RingSignatureBinary, Error};
//! use k256::{Scalar, ProjectivePoint};
//!
//! // Assuming you have raw binary keys available:
//! fn example_binary_api(
//!     private_key: &Scalar,
//!     ring_pubkeys: &[ProjectivePoint],
//!     message: &[u8]
//! ) -> Result<(), Error> {
//!     // Sign using binary API (more efficient)
//!     let binary_signature = sign_binary(message, private_key, ring_pubkeys)?;
//!
//!     // Verify using binary API (more efficient)
//!     let is_valid = verify_binary(&binary_signature, message, ring_pubkeys)?;
//!     assert!(is_valid);
//!
//!     Ok(())
//! }
//! ```

pub mod types;
pub mod utils;
#[cfg(feature = "wasm")]
pub mod wasm;

use k256::elliptic_curve::{ops::Reduce, point::AffineCoordinates, sec1::ToEncodedPoint, Group};
use k256::{NonZeroScalar, ProjectivePoint, PublicKey, Scalar, SecretKey, U256};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use subtle::{ConditionallySelectable, ConstantTimeEq};
// Export types from the types module
pub use types::{Error, KeyPair, KeyPairHex, RingSignature, RingSignatureBinary};
// Use internal functions from types module
use types::{
    hex_to_scalar, normalize_hex, scalar_to_hex, BlsagSignature, BlsagSignatureBinary, KeyImage,
};
use utils::{hex_to_point, random_non_zero_scalar};

/// The generator point G for the secp256k1 curve
const GENERATOR: ProjectivePoint = ProjectivePoint::GENERATOR;

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
    // Use sign_with_hex instead, which is now the hex wrapper
    sign_with_hex(message, private_key_hex, ring_pubkeys_hex)
}

/// Creates a ring signature using hex-encoded inputs (wrapper for sign_binary)
///
/// This function is a wrapper around sign_binary, handling hex conversions.
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
/// Same as sign_binary, plus:
/// * Errors from hex decoding
pub fn sign_with_hex(
    message: &[u8],
    private_key_hex: &str,
    ring_pubkeys_hex: &[String],
) -> Result<RingSignature, Error> {
    // Convert inputs from hex
    let private_key = hex_to_scalar(private_key_hex)?;
    let ring_pubkeys: Vec<ProjectivePoint> = ring_pubkeys_hex
        .iter()
        .map(|pubkey_str| hex_to_point(pubkey_str))
        .collect::<Result<_, _>>()?;

    // Call the binary version
    let binary_signature = sign_binary(message, &private_key, &ring_pubkeys)?;

    // Convert the binary signature to hex format
    Ok(RingSignature::from(&binary_signature))
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
    // Use verify_with_hex instead, which is now the hex wrapper
    verify_with_hex(signature, message, ring_pubkeys_hex)
}

/// Verifies a ring signature using hex-encoded inputs (wrapper for verify_binary)
///
/// This function is a wrapper around verify_binary, handling hex conversions.
///
/// # Arguments
/// * `signature` - The hex-encoded ring signature to verify
/// * `message` - The message that was signed
/// * `ring_pubkeys_hex` - The public keys of all ring members as hex strings
///
/// # Returns
/// * `Ok(bool)` - Whether the signature is valid
/// * `Err(Error)` - If any step in the verification process fails
///
/// # Errors
/// Same as verify_binary, plus:
/// * Errors from hex decoding
pub fn verify_with_hex(
    signature: &RingSignature,
    message: &[u8],
    ring_pubkeys_hex: &[String],
) -> Result<bool, Error> {
    // Convert inputs from hex
    let binary_signature = RingSignatureBinary::try_from(signature)?;
    let ring_pubkeys: Vec<ProjectivePoint> = ring_pubkeys_hex
        .iter()
        .map(|pubkey_str| hex_to_point(pubkey_str))
        .collect::<Result<_, _>>()?;

    // Call the binary version
    verify_binary(&binary_signature, message, &ring_pubkeys)
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

/// Creates a bLSAG signature (linkable) using binary inputs.
///
/// Returns the signature and the key image. The key image can be used to detect
/// if the same private key signed multiple messages.
///
/// # Arguments
/// * `message` - The message bytes (`&[u8]`) to sign.
/// * `private_key` - The signer's private key as a `Scalar`.
/// * `ring_pubkeys` - A slice of `ProjectivePoint` representing the ring members.
///
/// # Returns
/// * `Ok((BlsagSignatureBinary, KeyImage))` - The binary signature and the key image.
/// * `Err(Error)` - If signing fails.
pub fn sign_blsag_binary(
    message: &[u8],
    private_key: &Scalar,
    ring_pubkeys: &[ProjectivePoint],
) -> Result<(BlsagSignatureBinary, KeyImage), Error> {
    let ring_size = ring_pubkeys.len();
    if ring_size < 2 {
        return Err(Error::RingTooSmall(ring_size));
    }
    if *private_key == Scalar::ZERO {
        return Err(Error::PrivateKeyFormat(
            "Private key scalar cannot be zero".into(),
        ));
    }

    let d = *private_key;
    let _d_nonzero = NonZeroScalar::new(d).expect("d checked non-zero");

    // Find signer index and key variant used
    let my_point = GENERATOR * d;
    let flipped_d = d.negate();
    let flipped_point = GENERATOR * flipped_d;
    let mut signer_index: Option<usize> = None;
    let mut used_d = d; // The actual scalar corresponding to the pubkey found in the ring

    for (i, p) in ring_pubkeys.iter().enumerate() {
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
    let p_signer = &ring_pubkeys[signer_index]; // Signer's public key point in the ring

    // --- bLSAG Specific ---
    // 1. Calculate Key Image
    let hp_p_signer = hash_to_point(p_signer)?;
    let key_image_point = hp_p_signer * used_d; // I = used_d * Hp(P_signer)
    let key_image = KeyImage(key_image_point);

    // --- Standard Ring Calculation (adapted for bLSAG hashing) ---
    let mut r_scalars = vec![Scalar::ZERO; ring_size]; // Responses 's'
    let mut c_scalars = vec![Scalar::ZERO; ring_size]; // Challenges 'c'
    let os_rng = OsRng;

    let alpha_nonzero = random_non_zero_scalar(os_rng);
    let alpha = *alpha_nonzero.as_ref();

    // Calculate initial commitments L0, L1 for challenge hash
    let l0_start = GENERATOR * alpha;
    let l1_start = hp_p_signer * alpha; // Use signer's hashed pubkey

    // Calculate initial challenge c[start_index]
    let start_index = (signer_index + 1) % ring_size;
    c_scalars[start_index] = hash_for_blsag_challenge(message, &l0_start, &l1_start)?;

    // Iterate through non-signers
    let mut current_index = start_index;
    while current_index != signer_index {
        let r_nonzero = random_non_zero_scalar(os_rng);
        r_scalars[current_index] = *r_nonzero.as_ref();

        let p_i = &ring_pubkeys[current_index];
        let hp_p_i = hash_to_point(p_i)?;

        // Calculate commitments L0, L1 for this index's challenge hash
        // Li0 = r_i * G + c_i * P_i
        let li0 = (GENERATOR * r_scalars[current_index]) + (*p_i * c_scalars[current_index]);
        // Li1 = r_i * Hp(P_i) + c_i * I
        let li1 =
            (hp_p_i * r_scalars[current_index]) + (key_image_point * c_scalars[current_index]);

        // Calculate next challenge
        let next_index = (current_index + 1) % ring_size;
        c_scalars[next_index] = hash_for_blsag_challenge(message, &li0, &li1)?;

        current_index = next_index;
    }

    // Calculate signer's response
    r_scalars[signer_index] = alpha - (c_scalars[signer_index] * used_d);

    // Construct signature
    let signature = BlsagSignatureBinary {
        c0: c_scalars[0],
        s: r_scalars,
    };

    Ok((signature, key_image))
}

/// Verifies a bLSAG signature (linkable) using binary inputs.
///
/// Checks the signature validity and that the key image is valid.
///
/// # Arguments
/// * `signature` - The binary `BlsagSignatureBinary` to verify.
/// * `key_image` - The `KeyImage` associated with the signature.
/// * `message` - The message bytes (`&[u8]`).
/// * `ring_pubkeys` - A slice of `ProjectivePoint` representing the ring.
///
/// # Returns
/// * `Ok(bool)` - `true` if the signature and key image are valid, `false` otherwise.
/// * `Err(Error)` - If verification fails due to errors.
pub fn verify_blsag_binary(
    signature: &BlsagSignatureBinary,
    key_image: &KeyImage,
    message: &[u8],
    ring_pubkeys: &[ProjectivePoint],
) -> Result<bool, Error> {
    let ring_size = ring_pubkeys.len();
    if ring_size == 0 {
        return Ok(false);
    } // Ring cannot be empty
    if signature.s.len() != ring_size {
        return Err(Error::InvalidSignatureFormat);
    }

    let key_image_point = key_image.as_point();

    // --- bLSAG Specific ---
    // 1. Validate Key Image
    // Check it's not identity
    if key_image_point.is_identity().into() {
        return Ok(false);
    }
    // Check it's in the prime-order subgroup (torsion-free)
    // Commenting this out for now as it does not build.
    // TODO: Fix this
    // if !(*key_image_point).is_torsion_free() {
    //     return Ok(false);
    // }
    // Note: This check prevents certain attacks like small subgroup attacks.

    // --- Standard Ring Verification (adapted for bLSAG hashing) ---
    let c0_scalar = signature.c0;
    let r_scalars = &signature.s;
    // Temporary array to store recalculated challenges
    let mut c_recalculated = vec![Scalar::ZERO; ring_size];

    // Start loop with c = c0
    let mut current_c = c0_scalar;

    for i in 0..ring_size {
        let p_i = &ring_pubkeys[i];
        let hp_p_i = hash_to_point(p_i)?;

        // Recalculate L0, L1 for this index
        // Li0 = r_i * G + c_i * P_i
        let li0 = (GENERATOR * r_scalars[i]) + (*p_i * current_c);
        // Li1 = r_i * Hp(P_i) + c_i * I
        let li1 = (hp_p_i * r_scalars[i]) + (*key_image_point * current_c);

        // Calculate the next challenge based on recalculated L0, L1
        let next_c = hash_for_blsag_challenge(message, &li0, &li1)?;

        // Store it for the check *after* the loop finishes,
        // and use it as input for the *next* iteration.
        let next_index = (i + 1) % ring_size;
        if next_index == 0 {
            // Store the final calculation which should match c0
            c_recalculated[0] = next_c;
        } else {
            c_recalculated[next_index] = next_c; // Store intermediate challenges if needed for debugging
        }
        current_c = next_c; // Use newly calculated c for the next iteration
    }

    // Final Check: Does the recalculated c0 match the original?
    // We compare the final `current_c` value after the loop with the input `c0_scalar`.
    let is_valid = current_c.ct_eq(&c0_scalar);

    Ok(is_valid.into())
}

/// Hashes a public key point to another point on the curve (`Hp` function).
/// Uses SHA-256 and try-and-increment to find a valid point.
fn hash_to_point(pubkey: &ProjectivePoint) -> Result<ProjectivePoint, Error> {
    if pubkey.is_identity().into() {
        // Hashing the identity point is usually undefined or undesirable
        return Err(Error::PublicKeyFormat("Cannot hash identity point".into()));
    }
    let compressed_pubkey = pubkey.to_encoded_point(true); // 33 bytes
    let mut hasher = Sha256::new();
    hasher.update(compressed_pubkey.as_bytes());
    // Use a domain separator for hashing to a point vs hashing for challenges
    hasher.update(b"NostringerHp"); // Simple domain separation
    let mut hash = hasher.finalize(); // GenericArray<u8, 32>

    let mut counter: u32 = 0;
    // Limit attempts to prevent potential infinite loops in edge cases
    const MAX_TRIES: u32 = 1000;

    loop {
        if counter >= MAX_TRIES {
            return Err(Error::HashingError(format!(
                "Failed to hash to point after {} tries",
                MAX_TRIES
            )));
        }

        // Treat hash as x-coordinate candidate
        let mut potential_point_bytes = [0u8; 33];
        potential_point_bytes[1..].copy_from_slice(&hash);

        // Try even Y (0x02 prefix)
        potential_point_bytes[0] = 0x02;
        if let Ok(pk) = PublicKey::from_sec1_bytes(&potential_point_bytes) {
            // Check if the resulting point is identity (should be avoided)
            let point = pk.to_projective();
            if !bool::from(point.is_identity()) {
                return Ok(point);
            }
        }

        // Try odd Y (0x03 prefix)
        potential_point_bytes[0] = 0x03;
        if let Ok(pk) = PublicKey::from_sec1_bytes(&potential_point_bytes) {
            // Check if the resulting point is identity
            let point = pk.to_projective();
            if !bool::from(point.is_identity()) {
                return Ok(point);
            }
        }

        // If both failed or resulted in identity, update hash: hash = SHA256(hash || counter)
        let mut rehasher = Sha256::new();
        rehasher.update(hash);
        rehasher.update(counter.to_be_bytes());
        hash = rehasher.finalize();
        counter += 1;
    }
}

/// Hashes message and two points to create a bLSAG challenge scalar.
/// H = SHA256(domain_sep || msg || compressed_p1 || compressed_p2)
fn hash_for_blsag_challenge(
    message: &[u8],
    p1: &ProjectivePoint,
    p2: &ProjectivePoint,
) -> Result<Scalar, Error> {
    let mut hasher = Sha256::new();
    // Domain separation from regular SAG hash and Hp hash
    hasher.update(b"NostringerBlsagChallenge");
    hasher.update(message);
    hasher.update(p1.to_encoded_point(true).as_bytes());
    hasher.update(p2.to_encoded_point(true).as_bytes());

    let hash_result = hasher.finalize();
    let hash_uint = U256::from_be_slice(&hash_result);
    let scalar = Scalar::reduce(hash_uint);

    let is_zero = scalar.ct_eq(&Scalar::ZERO);
    Ok(Scalar::conditional_select(&scalar, &Scalar::ONE, is_zero))
}

/// Creates a bLSAG signature (linkable) using hex inputs.
///
/// Returns the hex-encoded signature and the hex-encoded key image.
pub fn sign_blsag_hex(
    message: &[u8],
    private_key_hex: &str,
    ring_pubkeys_hex: &[String],
) -> Result<(BlsagSignature, String), Error> {
    let private_key = hex_to_scalar(private_key_hex)?;
    let ring_pubkeys: Vec<ProjectivePoint> = ring_pubkeys_hex
        .iter()
        .map(|s| hex_to_point(s))
        .collect::<Result<Vec<_>, _>>()?;

    let (binary_sig, key_image) = sign_blsag_binary(message, &private_key, &ring_pubkeys)?;

    Ok((BlsagSignature::from(&binary_sig), key_image.to_hex()))
}

/// Verifies a bLSAG signature (linkable) using hex inputs.
pub fn verify_blsag_hex(
    signature_hex: &BlsagSignature,
    key_image_hex: &str,
    message: &[u8],
    ring_pubkeys_hex: &[String],
) -> Result<bool, Error> {
    let binary_sig = BlsagSignatureBinary::try_from(signature_hex)?;
    let key_image = KeyImage::from_hex(key_image_hex)?;
    let ring_pubkeys: Vec<ProjectivePoint> = ring_pubkeys_hex
        .iter()
        .map(|s| hex_to_point(s))
        .collect::<Result<Vec<_>, _>>()?;

    verify_blsag_binary(&binary_sig, &key_image, message, &ring_pubkeys)
}

// --- Add Key Image comparison utility ---
/// Compares two KeyImages for equality.
/// If two different valid bLSAG signatures have the same KeyImage,
/// they were produced by the same private key.
pub fn key_images_match(image1: &KeyImage, image2: &KeyImage) -> bool {
    image1 == image2 // Relies on PartialEq derived for KeyImage
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

/// Creates a ring signature for a message using the provided binary private key and ring of public keys
///
/// This function is the optimized binary version of the sign function, avoiding hex conversions.
///
/// # Arguments
/// * `message` - The message to sign as a byte array
/// * `private_key` - The signer's private key as a Scalar
/// * `ring_pubkeys` - The public keys of all ring members as ProjectivePoints
///
/// # Returns
/// * `Ok(RingSignatureBinary)` - The generated ring signature in binary format
/// * `Err(Error)` - If any step in the signature generation fails
///
/// # Errors
/// Returns an error if:
/// * The ring has fewer than 2 members
/// * The signer's public key is not in the ring
/// * Any cryptographic operation fails
pub fn sign_binary(
    message: &[u8],
    private_key: &Scalar,
    ring_pubkeys: &[ProjectivePoint],
) -> Result<RingSignatureBinary, Error> {
    let ring_size = ring_pubkeys.len();
    if ring_size < 2 {
        return Err(Error::RingTooSmall(ring_size));
    }

    if *private_key == Scalar::ZERO {
        return Err(Error::PrivateKeyFormat(
            "Private key scalar cannot be zero".into(),
        ));
    }

    let d = *private_key;
    let _d_nonzero =
        NonZeroScalar::new(d).expect("d was checked non-zero, NonZeroScalar::new must succeed");

    // Compute the signer's public key point in both normal and negated form
    let my_point = GENERATOR * d;
    let flipped_d = d.negate();
    let flipped_point = GENERATOR * flipped_d;

    // Find the signer's position in the ring
    let mut signer_index: Option<usize> = None;
    let mut used_d = d;
    for (i, p) in ring_pubkeys.iter().enumerate() {
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

    // Convert public keys to hex for hashing
    // This is a necessary temporary step as the hash_to_scalar function uses hex strings
    // A future improvement would be to optimize hash_to_scalar to work with binary directly
    let ring_pubkeys_hex: Vec<String> = ring_pubkeys
        .iter()
        .map(|point| hex::encode(point.to_encoded_point(true).as_bytes()))
        .collect();

    c_scalars[start_index] = hash_to_scalar(message, &ring_pubkeys_hex, &alpha_g)?;

    // Generate random components for each member and build the ring
    let mut current_index = start_index;
    while current_index != signer_index {
        // Random scalar for this ring member
        let r_nonzero = random_non_zero_scalar(os_rng);
        r_scalars[current_index] = *r_nonzero.as_ref();

        // Compute the ring link: x_i = r_i*G + c_i*P_i
        let xi = (GENERATOR * r_scalars[current_index])
            + (ring_pubkeys[current_index] * c_scalars[current_index]);

        // Hash to get the next challenge
        let next_index = (current_index + 1) % ring_size;
        c_scalars[next_index] = hash_to_scalar(message, &ring_pubkeys_hex, &xi)?;
        current_index = next_index;
    }

    // Complete the ring by computing the signer's s value
    r_scalars[signer_index] = alpha - (c_scalars[signer_index] * used_d);

    // Return the binary signature
    Ok(RingSignatureBinary {
        c0: c_scalars[0],
        s: r_scalars,
    })
}

/// Verifies a ring signature against a message and a ring of public keys
///
/// This function is the optimized binary version of the verify function, avoiding hex conversions.
///
/// # Arguments
/// * `signature` - The binary ring signature to verify
/// * `message` - The message that was signed
/// * `ring_pubkeys` - The public keys of all ring members as ProjectivePoints
///
/// # Returns
/// * `Ok(bool)` - Whether the signature is valid
/// * `Err(Error)` - If any step in the verification process fails
///
/// # Errors
/// Returns an error if:
/// * The signature format is invalid
/// * Any cryptographic operation fails
pub fn verify_binary(
    signature: &RingSignatureBinary,
    message: &[u8],
    ring_pubkeys: &[ProjectivePoint],
) -> Result<bool, Error> {
    let ring_size = ring_pubkeys.len();
    if ring_size == 0 {
        return Ok(false);
    }
    if signature.s.len() != ring_size {
        return Err(Error::InvalidSignatureFormat);
    }

    // Get reference to the components directly
    let c0_scalar = signature.c0;
    let r_scalars = &signature.s;

    // Convert public keys to hex for hashing
    // This is a necessary temporary step as the hash_to_scalar function uses hex strings
    let ring_pubkeys_hex: Vec<String> = ring_pubkeys
        .iter()
        .map(|point| hex::encode(point.to_encoded_point(true).as_bytes()))
        .collect();

    // Verify the ring by recomputing each link
    let mut current_c = c0_scalar;
    for i in 0..ring_size {
        // Compute x_i = s_i*G + c_i*P_i
        let xi = (GENERATOR * r_scalars[i]) + (ring_pubkeys[i] * current_c);
        // Hash to get the next challenge
        current_c = hash_to_scalar(message, &ring_pubkeys_hex, &xi)?;
    }

    // Check if the ring closes (c_n == c₀)
    let is_valid = current_c.ct_eq(&c0_scalar);
    Ok(is_valid.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ... existing test code ...

    #[test]
    fn test_binary_api() {
        // Generate keypairs
        let keypair1 = generate_keypair_hex("xonly");
        let keypair2 = generate_keypair_hex("xonly");
        let keypair3 = generate_keypair_hex("xonly");

        // Convert to binary
        let _private_key1 = hex_to_scalar(&keypair1.private_key_hex).unwrap();
        let private_key2 = hex_to_scalar(&keypair2.private_key_hex).unwrap();
        let _private_key3 = hex_to_scalar(&keypair3.private_key_hex).unwrap();

        let pubkey1 = hex_to_point(&keypair1.public_key_hex).unwrap();
        let pubkey2 = hex_to_point(&keypair2.public_key_hex).unwrap();
        let pubkey3 = hex_to_point(&keypair3.public_key_hex).unwrap();

        let ring_binary = vec![pubkey1, pubkey2, pubkey3];
        let ring_hex = vec![
            keypair1.public_key_hex.clone(),
            keypair2.public_key_hex.clone(),
            keypair3.public_key_hex.clone(),
        ];

        let message = b"Test message for binary API";

        // Sign with binary API
        let binary_sig = sign_binary(message, &private_key2, &ring_binary).unwrap();

        // Verify with binary API
        let binary_verify = verify_binary(&binary_sig, message, &ring_binary).unwrap();
        assert!(binary_verify, "Binary verification should succeed");

        // Tampered message should fail
        let tampered = b"Tampered message";
        let tampered_verify = verify_binary(&binary_sig, tampered, &ring_binary).unwrap();
        assert!(
            !tampered_verify,
            "Verification with tampered message should fail"
        );

        // Test conversion between hex and binary signatures
        let hex_sig = RingSignature::from(&binary_sig);
        let binary_sig2 = RingSignatureBinary::try_from(&hex_sig).unwrap();

        // Verify the converted signature
        let verify_after_conversion = verify_binary(&binary_sig2, message, &ring_binary).unwrap();
        assert!(
            verify_after_conversion,
            "Verification after conversion should succeed"
        );

        // Test hex API with the same inputs
        let hex_sig_direct = sign(message, &keypair2.private_key_hex, &ring_hex).unwrap();
        let hex_verify = verify(&hex_sig_direct, message, &ring_hex).unwrap();
        assert!(hex_verify, "Hex verification should succeed");
    }
}
