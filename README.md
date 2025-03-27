# nostringer-rs

<div align="center">

![Build Status](https://img.shields.io/github/actions/workflow/status/abdelstark/nostringer-rs/rust.yml?branch=main)
![Crates.io](https://img.shields.io/crates/v/nostringer-rs)
![License](https://img.shields.io/crates/l/nostringer-rs)
![Rust Version](https://img.shields.io/badge/rust-stable-orange)

**A Rust library for creating and verifying ring signatures using the secp256k1 cryptographic curve**

</div>

## Overview

`nostringer-rs` is a Rust implementation of ring signatures for the secp256k1 curve. It allows members of a group to create signatures that:

- Can be verified against a set of public keys
- Do not reveal which specific key was used to create the signature
- Guarantee that only a member of the group could have created the signature

This library is built on top of the `secp256k1` and `hashes` crates, providing a simple API for creating and verifying both ring signatures and standard ECDSA signatures.

## Features

- **SAG Ring Signatures**: Create and verify Spontaneous Anonymous Group (SAG) ring signatures
- **ECDSA Signatures**: Standard ECDSA signature creation and verification
- **Secure by default**: Built on the widely-used and audited secp256k1 implementation
- **Simple API**: Easy-to-use functions for all cryptographic operations

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
nostringer-rs = "0.1.0"
```

## Usage

### Standard ECDSA Signatures

```rust
use nostringer_rs::{sign, verify};
use secp256k1::SecretKey;

fn main() {
    // Example secret key and public key
    let seckey = [
        // 32 bytes of secret key
        59, 148, 11, 85, 134, 130, 61, 253, 2, 174, 59, 70, 27, 180, 51, 107, 
        94, 203, 174, 253, 102, 39, 170, 146, 46, 252, 4, 143, 236, 12, 136, 28,
    ];
    let pubkey = [
        // 33 bytes of public key (compressed format)
        2, 29, 21, 35, 7, 198, 183, 43, 14, 208, 65, 139, 14, 112, 205, 128, 
        231, 245, 41, 91, 141, 134, 245, 114, 45, 63, 82, 19, 251, 210, 57, 79, 54,
    ];
    
    // Message to sign
    let msg = b"This is some message";
    
    // Create a signature
    let signature = sign(msg, seckey).unwrap();
    let signature_bytes = signature.serialize_compact();
    
    // Verify the signature
    let is_valid = verify(msg, signature_bytes, pubkey).unwrap();
    assert!(is_valid);
}
```

### Ring Signatures

```rust
use nostringer_rs::{ring_sign, RingSignature};
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use rand_core::{OsRng, RngCore};

fn main() {
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    
    // Generate keys for a 3-member ring
    let mut secret_keys = Vec::with_capacity(3);
    let mut public_keys = Vec::with_capacity(3);
    
    for _ in 0..3 {
        let mut key_bytes = [0u8; 32];
        rng.fill_bytes(&mut key_bytes);
        
        let secret_key = SecretKey::from_slice(&key_bytes).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        
        secret_keys.push(secret_key);
        public_keys.push(public_key);
    }
    
    // Message to sign
    let message = b"Test ring signature message";
    
    // Create a ring signature with the first key
    let ring_signature = ring_sign(message, &secret_keys[0], &public_keys).unwrap();
    
    // Verify the ring signature
    let is_valid = ring_signature.verify(message, &public_keys).unwrap();
    
    // Note: The verifier cannot determine which key was used to create the signature
}
```

## Security Notes

- Ring signatures provide anonymity within the group of public keys, but do not hide the group itself
- Always use cryptographically secure random number generators for key generation
- The library applies best practices for cryptographic operations, but has not undergone a formal security audit
- For production use, please review and test thoroughly

## Development

### Building

```
cargo build
```

### Testing

```
cargo test
```

### Benchmarking

```
cargo bench
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
