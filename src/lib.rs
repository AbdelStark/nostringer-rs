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

// --- Constants ---
const GENERATOR: ProjectivePoint = ProjectivePoint::GENERATOR;

// --- Error Type ---
#[derive(Error, Debug)]
pub enum Error {
    #[error("Hex decoding failed: {0}")]
    HexDecode(#[from] hex::FromHexError),
    #[error("Invalid private key format: {0}")]
    PrivateKeyFormat(String),
    #[error("Invalid public key format: {0}")]
    PublicKeyFormat(String),
    #[error("Invalid scalar encoding (>= curve order N)")]
    InvalidScalarEncoding,
    #[error("Secp256k1 curve error: {0}")]
    Secp256k1(#[from] k256::elliptic_curve::Error),
    #[error("Ring must have at least 2 members, got {0}")]
    RingTooSmall(usize),
    #[error("Signer's public key (or its negation) not found in the ring")]
    SignerNotInRing,
    #[error("Signature verification failed (internal calculation mismatch)")]
    VerificationFailed,
    #[error("Invalid signature format (e.g., incorrect number of 's' values)")]
    InvalidSignatureFormat,
    #[error("Hashing error: {0}")]
    HashingError(String),
}

// --- Structs ---
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RingSignature {
    pub c0: String,
    pub s: Vec<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct KeyPairHex {
    pub private_key_hex: String,
    pub public_key_hex: String,
}

// --- Core Functions ---

pub fn sign(
    message: &[u8],
    private_key_hex: &str,
    ring_pubkeys_hex: &[String],
) -> Result<RingSignature, Error> {
    let ring_size = ring_pubkeys_hex.len();
    if ring_size < 2 {
        return Err(Error::RingTooSmall(ring_size));
    }

    let d = hex_to_scalar(private_key_hex)?;
    if d == Scalar::ZERO {
        return Err(Error::PrivateKeyFormat(
            "Private key scalar cannot be zero".into(),
        ));
    }
    let _d_nonzero =
        NonZeroScalar::new(d).expect("d was checked non-zero, NonZeroScalar::new must succeed");

    // FIX: Use closure in map
    let ring_points: Vec<ProjectivePoint> = ring_pubkeys_hex
        .iter()
        .map(|pubkey_str| hex_to_point(pubkey_str)) // Closure fixes type mismatch
        .collect::<Result<_, _>>()?;

    let my_point = GENERATOR * d;
    let flipped_d = d.negate();
    let flipped_point = GENERATOR * flipped_d;

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

    let mut r_scalars = vec![Scalar::ZERO; ring_size];
    let mut c_scalars = vec![Scalar::ZERO; ring_size];
    let os_rng = OsRng;

    let alpha_nonzero = random_non_zero_scalar(os_rng);
    let alpha = *alpha_nonzero.as_ref();
    let alpha_g = GENERATOR * alpha;

    let start_index = (signer_index + 1) % ring_size;
    c_scalars[start_index] = hash_to_scalar(message, ring_pubkeys_hex, &alpha_g)?;

    let mut current_index = start_index;
    while current_index != signer_index {
        let r_nonzero = random_non_zero_scalar(os_rng);
        r_scalars[current_index] = *r_nonzero.as_ref();
        let xi = (GENERATOR * r_scalars[current_index])
            + (ring_points[current_index] * c_scalars[current_index]);
        let next_index = (current_index + 1) % ring_size;
        c_scalars[next_index] = hash_to_scalar(message, ring_pubkeys_hex, &xi)?;
        current_index = next_index;
    }

    r_scalars[signer_index] = alpha - (c_scalars[signer_index] * used_d);

    Ok(RingSignature {
        c0: scalar_to_hex(&c_scalars[0]),
        s: r_scalars.iter().map(scalar_to_hex).collect(),
    })
}

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

    let c0_scalar = hex_to_scalar(&signature.c0)?;

    let r_scalars: Vec<Scalar> = signature
        .s
        .iter()
        .map(|s_hex| hex_to_scalar(s_hex)) // Closure fixes type mismatch
        .collect::<Result<_, _>>()?;

    let ring_points: Vec<ProjectivePoint> = ring_pubkeys_hex
        .iter()
        .map(|pubkey_str| hex_to_point(pubkey_str)) // Closure fixes type mismatch
        .collect::<Result<_, _>>()?;

    let mut current_c = c0_scalar;
    for i in 0..ring_size {
        let xi = (GENERATOR * r_scalars[i]) + (ring_points[i] * current_c);
        current_c = hash_to_scalar(message, ring_pubkeys_hex, &xi)?;
    }

    let is_valid = current_c.ct_eq(&c0_scalar);
    Ok(is_valid.into())
}

// --- Helper Functions ---

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

fn scalar_to_hex(scalar: &Scalar) -> String {
    // Scalar::to_bytes returns FieldBytes, which can be converted to slice
    hex::encode(scalar.to_bytes().as_slice())
}

fn hex_to_scalar(hex_str: &str) -> Result<Scalar, Error> {
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

    let bytes = hex::decode(&padded_hex)?;
    let field_bytes = k256::FieldBytes::from_slice(&bytes);

    let maybe_scalar = Scalar::from_repr(*field_bytes); // Deref FieldBytes to GenericArray

    if maybe_scalar.is_some().into() {
        Ok(maybe_scalar.unwrap())
    } else {
        Err(Error::InvalidScalarEncoding)
    }
}

fn hex_to_point(pubkey_hex: &str) -> Result<ProjectivePoint, Error> {
    let hex_norm = normalize_hex(pubkey_hex)?;
    let point_bytes = match hex_norm.len() {
        64 => hex::decode(format!("02{}", hex_norm))?,
        66 => {
            if !hex_norm.starts_with("02") && !hex_norm.starts_with("03") {
                return Err(Error::PublicKeyFormat(format!(
                    "Invalid prefix: {}",
                    &hex_norm[..2]
                )));
            }
            hex::decode(&hex_norm)?
        }
        130 => {
            if !hex_norm.starts_with("04") {
                return Err(Error::PublicKeyFormat(format!(
                    "Invalid prefix: {}",
                    &hex_norm[..2]
                )));
            }
            hex::decode(&hex_norm)?
        }
        _ => {
            return Err(Error::PublicKeyFormat(format!(
                "Invalid length: {}",
                hex_norm.len()
            )));
        }
    };

    let public_key = PublicKey::from_sec1_bytes(&point_bytes)
        .map_err(|e| Error::PublicKeyFormat(format!("SEC1 parse error: {}", e)))?;

    Ok(public_key.to_projective())
}

fn random_non_zero_scalar(
    mut rng: impl rand_core::RngCore + rand_core::CryptoRng,
) -> NonZeroScalar {
    NonZeroScalar::random(&mut rng)
}

fn hash_to_scalar(
    message: &[u8],
    ring_pubkeys_hex: &[String],
    ephemeral_point: &ProjectivePoint,
) -> Result<Scalar, Error> {
    let mut hasher = Sha256::new();
    hasher.update(message);
    for pk_hex in ring_pubkeys_hex {
        let norm_hex = normalize_hex(pk_hex)?;
        let pk_bytes = hex::decode(&norm_hex)?;
        hasher.update(&pk_bytes);
    }
    let ephemeral_compressed = ephemeral_point.to_encoded_point(true); // Uses ToEncodedPoint trait
    hasher.update(ephemeral_compressed.as_bytes());
    let hash_result = hasher.finalize();

    let hash_uint = U256::from_be_slice(&hash_result);
    let scalar = Scalar::reduce(hash_uint);

    let is_zero = scalar.ct_eq(&Scalar::ZERO);
    Ok(Scalar::conditional_select(&scalar, &Scalar::ONE, is_zero))
}

pub fn generate_keypair_hex(format: &str) -> KeyPairHex {
    let os_rng = OsRng;
    let secret_scalar_nonzero = random_non_zero_scalar(os_rng);
    let secret_key = SecretKey::from(secret_scalar_nonzero); // Use from NonZeroScalar
    let secret_scalar = *secret_scalar_nonzero.as_ref();
    let private_key_hex = scalar_to_hex(&secret_scalar);

    let public_key = secret_key.public_key();
    let mut point = public_key.to_projective();

    let public_key_hex = match format {
        "xonly" => {
            // Requires AffineCoordinates trait in scope
            let affine = point.to_affine();
            let y_is_odd = affine.y_is_odd(); // Use trait method

            if y_is_odd.into() {
                let flipped_scalar = secret_scalar.negate();
                point = GENERATOR * flipped_scalar;
            }
            let final_affine = point.to_affine();
            hex::encode(final_affine.x().as_slice()) // Use trait method .x() -> FieldBytes -> slice
        }
        // These use ToEncodedPoint trait
        "uncompressed" => hex::encode(point.to_encoded_point(false).as_bytes()),
        "compressed" => hex::encode(point.to_encoded_point(true).as_bytes()),
        // Default to compressed
        _ => hex::encode(point.to_encoded_point(true).as_bytes()),
    };

    KeyPairHex {
        private_key_hex,
        public_key_hex,
    }
}

// Helper to generate multiple keys easily
pub fn generate_keypairs(count: usize, format: &str) -> Vec<KeyPairHex> {
    (0..count).map(|_| generate_keypair_hex(format)).collect()
}

// Helper to extract public keys
pub fn get_public_keys(keypairs: &[KeyPairHex]) -> Vec<String> {
    keypairs
        .iter()
        .map(|kp| kp.public_key_hex.clone())
        .collect()
}
