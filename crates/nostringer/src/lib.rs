//! # Nostringer Ring Signatures (Rust)
//!
//! A Rust implementation of the ring signature scheme in the
//! [nostringer](https://github.com/AbdelStark/nostringer) TypeScript library.
//!
//! This library provides functions to sign and verify messages using a
//! Spontaneous Anonymous Group (SAG)-like ring signature scheme over the
//! secp256k1 curve. It aims for compatibility with the original TS implementation.
//!
//! ## Modules
//!
//! - `sag`: Implements the original Spontaneous Anonymous Group (SAG) ring signature.
//! - `blsag`: Implements the Back's Linkable Spontaneous Anonymous Group (bLSAG) ring signature.
//! - `types`: Defines common types like keys, signatures, and errors.
//! - `utils`: Provides utility functions for hashing, conversions, etc.
//! - `wasm`: Contains bindings for WebAssembly usage.
//! - `keys`: Contains key-related functions.
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
pub mod types;
pub mod utils;
#[cfg(feature = "wasm")]
pub mod wasm;

// Re-export core types for convenience
pub use types::{Error, KeyPair, KeyPairHex, RingSignature, RingSignatureBinary};

pub use types::hex_to_scalar; // Re-export hex_to_scalar
                              // Re-export key-related functions
pub use keys::{generate_keypair_hex, generate_keypairs, get_public_keys};
