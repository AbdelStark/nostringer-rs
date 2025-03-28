<div align="center">

<a href="https://github.com/AbdelStark/nostringer-rs/actions/workflows/rust.yml"><img alt="GitHub Workflow Status" src="https://img.shields.io/github/actions/workflow/status/AbdelStark/nostringer-rs/rust.yml?style=for-the-badge&label=CI" height=30></a>
<a href="https://crates.io/crates/nostringer"><img alt="Crates.io" src="https://img.shields.io/crates/v/nostringer.svg?style=for-the-badge&label=crates.io" height=30></a>
<a href="https://docs.rs/nostringer"><img alt="Docs.rs" src="https://docs.rs/nostringer/badge.svg?style=for-the-badge&label=docs.rs" height=30></a>
<a href="https://github.com/AbdelStark/nostringer-rs/blob/main/LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge" height=30></a>
<a href="https://github.com/nostr-protocol/nostr"> <img alt="Nostr" src="https://img.shields.io/badge/Nostr-8E44AD?style=for-the-badge" height=30></a>
<img alt="Rust Version" src="https://img.shields.io/badge/rust-stable-orange.svg?style=for-the-badge&logo=rust" height=30>

</div>

# Nostringer Ring Signatures (Rust)

<div align="center">
  <img src="https://raw.githubusercontent.com/AbdelStark/nostringer/main/assets/img/nostringer.png" alt="Nostringer Logo" width="250">

  <h3>
    <a href="https://nostringer.starknetonbitcoin.com/">
      TS LIVE DEMO
    </a>
    <span> | </span>
    <a href="https://github.com/AbdelStark/nostringer-rs">
      RUST REPO
    </a>
    <span> | </span>
    <a href="https://github.com/AbdelStark/nostringer-rs/tree/main/examples">
      EXAMPLES
    </a>
  </h3>
</div>

A **blazing fast** Rust implementation of the **unlinkable ring signature** scheme in the [nostringer](https://github.com/AbdelStark/nostringer) TypeScript library.

Built using pure Rust crypto crates, this library allows a signer to prove membership in a group of Nostr accounts (defined by their public keys) without revealing which specific account produced the signature. It uses a Spontaneous Anonymous Group (SAG)-like algorithm compatible with secp256k1 keys used in Nostr.

Nostringer is largely inspired by [Monero's Ring Signatures](https://www.getmonero.org/library/Zero-to-Monero-2-0-0.pdf) using Spontaneous Anonymous Group signatures (SAG), and [beritani/ring-signatures](https://github.com/beritani/ring-signatures) implementation of ring signatures using the elliptic curve Ed25519 and Keccak for hashing.

## Table of Contents

- [Nostringer Ring Signatures (Rust)](#nostringer-ring-signatures-rust)
  - [Table of Contents](#table-of-contents)
  - [Disclaimer](#disclaimer)
  - [Problem Statement](#problem-statement)
  - [Key Features](#key-features)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Optimized Binary API](#optimized-binary-api)
  - [Examples](#examples)
  - [Benchmarks](#benchmarks)
    - [Performance Results](#performance-results)
  - [API Reference](#api-reference)
    - [`sign(message: &[u8], private_key_hex: &str, ring_pubkeys_hex: &[String]) -> Result<RingSignature, Error>`](#signmessage-u8-private_key_hex-str-ring_pubkeys_hex-string---resultringsignature-error)
    - [`verify(signature: &RingSignature, message: &[u8], ring_pubkeys_hex: &[String]) -> Result<bool, Error>`](#verifysignature-ringsignature-message-u8-ring_pubkeys_hex-string---resultbool-error)
    - [`sign_binary(message: &[u8], private_key: &Scalar, ring_pubkeys: &[ProjectivePoint]) -> Result<RingSignatureBinary, Error>`](#sign_binarymessage-u8-private_key-scalar-ring_pubkeys-projectivepoint---resultringsignaturebinary-error)
    - [`verify_binary(signature: &RingSignatureBinary, message: &[u8], ring_pubkeys: &[ProjectivePoint]) -> Result<bool, Error>`](#verify_binarysignature-ringsignaturebinary-message-u8-ring_pubkeys-projectivepoint---resultbool-error)
    - [`sign_with_hex(message: &[u8], private_key_hex: &str, ring_pubkeys_hex: &[String]) -> Result<RingSignature, Error>`](#sign_with_hexmessage-u8-private_key_hex-str-ring_pubkeys_hex-string---resultringsignature-error)
    - [`verify_with_hex(signature: &RingSignature, message: &[u8], ring_pubkeys_hex: &[String]) -> Result<bool, Error>`](#verify_with_hexsignature-ringsignature-message-u8-ring_pubkeys_hex-string---resultbool-error)
    - [`generate_keypair_hex(format: &str) -> KeyPairHex`](#generate_keypair_hexformat-str---keypairhex)
    - [`RingSignature` Struct](#ringsignature-struct)
    - [`RingSignatureBinary` Struct](#ringsignaturebinary-struct)
    - [`KeyPairHex` Struct](#keypairhex-struct)
    - [`KeyPair` Struct](#keypair-struct)
    - [`Error` Enum](#error-enum)
  - [Signature Size](#signature-size)
  - [Security Considerations](#security-considerations)
  - [License](#license)
  - [References](#references)

## Disclaimer

> **This code is highly experimental.**
> The original author is not a cryptographer, and this Rust port, while aiming for compatibility and correctness using standard libraries, **has not been audited or formally verified.**
> Use for educational exploration **at your own risk.** Production usage is **strongly discouraged** until thorough security reviews and testing are performed by qualified individuals.

## Problem Statement

In many scenarios, you want to prove that "someone among these N credentials produced this signature," but you do **not** want to reveal _which_ credential or identity. For instance, you might have a set of recognized Nostr pubkeys (e.g., moderators, DAO members, authorized reviewers) who are allowed to perform certain actions, but you want them to remain anonymous within that set when doing so.

A **ring signature** solves this by letting an individual sign a message _on behalf of the group_ (the ring). A verifier can confirm the message originated from **one** of the public keys in the ring, without learning the specific signer's identity.

## Key Features

- **Unlinkable**: Signatures hide the signer's identity. Two signatures from the same signer cannot be linked cryptographically.
- **Fast**: Implemented in Rust, leveraging efficient and audited cryptographic primitives from the RustCrypto ecosystem (`k256`, `sha2`).
- **Optimized API**: Provides both hex-string based API and a more efficient binary API that avoids serialization/deserialization overhead.
- **Nostr Key Compatibility**: Directly supports standard Nostr key formats (hex strings):
  - 32-byte (64-hex) x-only public keys.
  - 33-byte (66-hex) compressed public keys.
  - 65-byte (130-hex) uncompressed public keys.
  - 32-byte (64-hex) private keys.
- **Easy to Use**: Simple `sign`, `verify`, and `generate_keypair_hex` functions.
- **Minimal Dependencies**: Relies on well-maintained RustCrypto crates.
- **No Trusted Setup**: The scheme does not require any special setup ceremony.

## Installation

Add this crate to your `Cargo.toml` dependencies:

```toml
[dependencies]
nostringer = "0.1.0" # Replace with the latest version from crates.io
```

_(Note: You might need other crates like `hex` or `rand` in your own project depending on how you handle keys and messages.)_

## Usage

```rust
use nostringer::{sign, verify, generate_keypair_hex, RingSignature, Error};

fn main() -> Result<(), Error> {
    // 1. Setup: Generate keys for the ring members
    // Keys can be x-only, compressed, or uncompressed hex strings
    let keypair1 = generate_keypair_hex("xonly");
    let keypair2 = generate_keypair_hex("compressed");
    let keypair3 = generate_keypair_hex("xonly");

    let ring_pubkeys_hex: Vec<String> = vec![
        keypair1.public_key_hex.clone(),
        keypair2.public_key_hex.clone(), // Signer's key must be included
        keypair3.public_key_hex.clone(),
    ];

    // 2. Define the message to be signed (as bytes)
    let message = b"This is a secret message to the group.";

    // 3. Signer (keypair2) signs the message using their private key
    println!("Signing message...");
    let signature = sign(
        message,
        &keypair2.private_key_hex, // Signer's private key hex
        &ring_pubkeys_hex,         // The full ring of public keys
    )?;

    println!("Generated Signature:");
    println!(" c0: {}", signature.c0);
    println!(" s: {:?}", signature.s);

    // 4. Verification: Anyone can verify the signature against the ring and message
    println!("\nVerifying signature...");
    let is_valid = verify(
        &signature,
        message,
        &ring_pubkeys_hex, // Must use the exact same ring (order matters for hashing)
    )?;

    println!("Signature valid: {}", is_valid);
    assert!(is_valid);

    // 5. Tamper test: Verification should fail if the message changes
    println!("\nVerifying with tampered message...");
    let tampered_message = b"This is a different message.";
    let is_tampered_valid = verify(
        &signature,
        tampered_message,
        &ring_pubkeys_hex,
    )?;
    println!("Tampered signature valid: {}", is_tampered_valid);
    assert!(!is_tampered_valid);

    Ok(())
}
```

### Optimized Binary API

For applications requiring maximum performance, we provide a binary API that works directly with the native types, avoiding hex conversion overhead:

```rust
use nostringer::{sign_binary, verify_binary, KeyPair, RingSignatureBinary, Error};
use k256::{Scalar, ProjectivePoint};

fn main() -> Result<(), Error> {
    // Assuming you have raw binary keys available:
    // (You'd normally get these from elsewhere in your app)
    let private_key = /* Scalar value */;
    let ring_pubkeys = /* Vec<ProjectivePoint> */;
    let message = b"This is a secret message to the group.";
    
    // Sign using binary API (more efficient)
    let binary_signature = sign_binary(message, &private_key, &ring_pubkeys)?;
    
    // Verify using binary API (more efficient)
    let is_valid = verify_binary(&binary_signature, message, &ring_pubkeys)?;
    println!("Signature valid: {}", is_valid);
    
    Ok(())
}
```

## Examples

The repository includes several examples that demonstrate different aspects of the library:

1. **Basic Signing** (`examples/basic_signing.rs`): Demonstrates the core signing and verification functionality.

   ```bash
   cargo run --example basic_signing
   ```

2. **Key Formats** (`examples/key_formats.rs`): Shows how to work with different key formats (x-only, compressed, uncompressed) and create larger rings.

   ```bash
   cargo run --example key_formats
   ```

3. **Error Handling** (`examples/error_handling.rs`): Demonstrates proper error handling for common error scenarios.

   ```bash
   cargo run --example error_handling
   ```

These examples provide practical demonstrations of how to use the library in real-world scenarios and handle various edge cases.

## Benchmarks

The library includes comprehensive benchmarks using the Criterion framework for different ring sizes and operations. You can run these benchmarks yourself with:

```bash
cargo bench
```

For detailed information on running and interpreting benchmarks, see [BENCHMARKS.md](BENCHMARKS.md).

The repository also includes a GitHub Actions workflow that automatically runs benchmarks on each push and pull request, with the HTML report available as an artifact in the workflow run.

### Performance Results

Below is a summary of the benchmark results, showing median execution times for each operation with different ring sizes:

| Operation       | Ring Size   | Execution Time |
| --------------- | ----------- | -------------- |
| **Sign**        | 2 members   | 204.75 µs      |
| **Sign**        | 10 members  | 897.76 µs      |
| **Sign**        | 100 members | 13.31 ms       |
| **Verify**      | 2 members   | 166.83 µs      |
| **Verify**      | 10 members  | 847.23 µs      |
| **Verify**      | 100 members | 12.71 ms       |
| **Sign+Verify** | 2 members   | 370.41 µs      |
| **Sign+Verify** | 10 members  | 1.76 ms        |
| **Sign+Verify** | 100 members | 25.02 ms       |

Benchmarking Environment:

- **Model:** MacBook Pro (Identifier: `MacBookPro18,2`)
- **CPU:** Apple M1 Max
- **Cores:** 10
- **RAM:** 64 GB
- **Architecture:** `arm64`
- **Operating System:** macOS 14.7 (Build `23H124`)

## API Reference

### `sign(message: &[u8], private_key_hex: &str, ring_pubkeys_hex: &[String]) -> Result<RingSignature, Error>`

Signs a message using the SAG-like ring signature scheme. This function is a wrapper around the more efficient `sign_binary` that handles hex conversion.

- **`message`**: The message bytes (`&[u8]`) to sign.
- **`private_key_hex`**: The signer's private key as a 64-character hex string.
- **`ring_pubkeys_hex`**: A slice of public key hex strings representing the ring members. The signer's corresponding public key (or the key corresponding to the _negated_ private key) **must** be present in this ring. The order of keys matters for verification.
- **Returns**: A `Result` containing the `RingSignature` on success, or an `Error` on failure (e.g., signer not in ring, invalid keys, ring too small).

### `verify(signature: &RingSignature, message: &[u8], ring_pubkeys_hex: &[String]) -> Result<bool, Error>`

Verifies a ring signature against a message and the ring of public keys. This function is a wrapper around the more efficient `verify_binary` that handles hex conversion.

- **`signature`**: A reference to the `RingSignature` object (`{ c0, s }`).
- **`message`**: The original message bytes (`&[u8]`) that were allegedly signed.
- **`ring_pubkeys_hex`**: A slice of public key hex strings representing the ring. **Must** be identical (including order) to the ring used during signing.
- **Returns**: A `Result` containing `true` if the signature is valid for the message and ring, or `false` if it's invalid. Returns an `Error` if inputs are malformed (e.g., wrong signature length, invalid hex).

### `sign_binary(message: &[u8], private_key: &Scalar, ring_pubkeys: &[ProjectivePoint]) -> Result<RingSignatureBinary, Error>`

Optimized version of sign that works directly with binary types, avoiding hex conversion overhead.

- **`message`**: The message bytes (`&[u8]`) to sign.
- **`private_key`**: The signer's private key as a `k256::Scalar`.
- **`ring_pubkeys`**: A slice of public keys as `k256::ProjectivePoint` representing the ring members.
- **Returns**: A `Result` containing the `RingSignatureBinary` on success, or an `Error` on failure.

### `verify_binary(signature: &RingSignatureBinary, message: &[u8], ring_pubkeys: &[ProjectivePoint]) -> Result<bool, Error>`

Optimized version of verify that works directly with binary types, avoiding hex conversion overhead.

- **`signature`**: A reference to the `RingSignatureBinary` object.
- **`message`**: The original message bytes (`&[u8]`) that were allegedly signed.
- **`ring_pubkeys`**: A slice of public keys as `k256::ProjectivePoint` representing the ring.
- **Returns**: A `Result` containing `true` if the signature is valid, or `false` if it's invalid.

### `sign_with_hex(message: &[u8], private_key_hex: &str, ring_pubkeys_hex: &[String]) -> Result<RingSignature, Error>`

Alias for the original `sign` function, provided for clarity. Handles hex conversion internally.

### `verify_with_hex(signature: &RingSignature, message: &[u8], ring_pubkeys_hex: &[String]) -> Result<bool, Error>`

Alias for the original `verify` function, provided for clarity. Handles hex conversion internally.

### `generate_keypair_hex(format: &str) -> KeyPairHex`

Generates a new random secp256k1 key pair.

- **`format`**: A string slice specifying the desired public key format:
  - `"xonly"`: 64-hex (32 bytes), guaranteed even-Y point.
  - `"compressed"`: 66-hex (33 bytes), starts with `02` or `03`.
  - `"uncompressed"`: 130-hex (65 bytes), starts with `04`.
  - Defaults to `"compressed"` if an unrecognized format is provided.
- **Returns**: A `KeyPairHex` struct containing `private_key_hex` (String) and `public_key_hex` (String).
  _Note: The returned `private_key_hex` is the original randomly generated scalar, even if internal negation was required to produce an even-Y public key for the `"xonly"` format._

### `RingSignature` Struct

```rust
pub struct RingSignature {
  pub c0: String, // Initial challenge scalar (64-char hex)
  pub s: Vec<String>, // Array of response scalars (64-char hex strings)
}
```

### `RingSignatureBinary` Struct

```rust
pub struct RingSignatureBinary {
  pub c0: Scalar, // Initial challenge scalar in binary form
  pub s: Vec<Scalar>, // Array of response scalars in binary form
}
```

### `KeyPairHex` Struct

```rust
pub struct KeyPairHex {
  pub private_key_hex: String, // 64-char hex
  pub public_key_hex: String,  // Hex format depends on generation option
}
```

### `KeyPair` Struct

```rust
pub struct KeyPair {
  pub private_key: Scalar,
  pub public_key: ProjectivePoint,
}
```

### `Error` Enum

An enum representing possible errors during signing or verification, such as invalid key formats, signer not found in the ring, ring too small, hex decoding errors, or internal cryptographic errors.

## Signature Size

The size of the generated ring signature depends directly on the number of members (`n`) in the ring. It consists of:

- One initial challenge (`c0`) scalar (32 bytes binary / 64 hex chars).
- `n` response scalars (`s` array) (each 32 bytes binary / 64 hex chars).

The total **binary size** follows the formula:
`Size (bytes) = 32 * (n + 1)`

This means the signature size grows **linearly** with the ring size. A larger ring provides more anonymity but results in a larger signature.

## Security Considerations

- **Anonymity Set**: The level of anonymity depends on the size (`n`) and plausibility of the chosen ring members. Ensure the ring containskeys that could _realistically_ be the signer in the given context.
- **No Trusted Setup**: This scheme does not require any trusted setup procedure.
- **Unlinkability**: Signatures produced by the same signer for different messages (using the same or different rings) should be cryptographically unlinkable.
- **No Traceability**: This specific SAG implementation does not produce linkability tags (like key images used in Monero's MLSAG/CLSAG) which would allow detecting if the _same key_ was used to sign twice within _different_ rings for the _same_ message. This enhances privacy but means double-spending prevention requires other mechanisms if used for voting/claiming.
- **Implementation Security**: This library relies on the correctness of the underlying `k256` crate. While `k256` is well-regarded, this specific ring signature implementation has **not** been independently audited.

## License

This project is licensed under the [MIT License](LICENSE).

## References

- [Linkable Spontaneous Anonymous Group Signature for Ad Hoc Groups](https://eprint.iacr.org/2004/027.pdf) - (Joseph Liu et al., 2004) – basis of LSAG.
- [Beritani, ring-signatures JS library](https://github.com/beritani/ring-signatures) – Ed25519 ring signature implementation (SAG, bLSAG, MLSAG, CLSAG)​.
- [Blockstream Elements rust-secp256k1-zkp library](https://github.com/BlockstreamResearch/rust-secp256k1-zkp) – Whitelist Ring Signature in libsecp256k1-zkp (C code exposed via Rust)​.
- [Zero to Monero 2.0 – Chapter 3, ring signature algorithms](https://www.getmonero.org/library/Zero-to-Monero-2-0-0.pdf).
- [Cronokirby Blog – On Monero's Ring Signatures](https://cronokirby.com/posts/2022/03/on-moneros-ring-signatures), explains Schnorr ring signatures in detail​.

---

Built with love by [AbdelStark](https://github.com/AbdelStark) 🧡

Feel free to follow me on Nostr if you'd like, using my public key:

```text
npub1hr6v96g0phtxwys4x0tm3khawuuykz6s28uzwtj5j0zc7lunu99snw2e29
```

Or just **scan this QR code** to find me:

![Nostr Public Key QR Code](https://hackmd.io/_uploads/SkAvwlYYC.png)
