<div align="center">

<a href="https://github.com/AbdelStark/nostringer-rs/actions/workflows/rust.yml"><img alt="GitHub Workflow Status" src="https://img.shields.io/github/actions/workflow/status/AbdelStark/nostringer-rs/rust.yml?style=for-the-badge&label=CI" height=30></a>
<a href="https://crates.io/crates/nostringer"><img alt="Crates.io" src="https://img.shields.io/crates/v/nostringer.svg?style=for-the-badge&label=crates.io" height=30></a>
<a href="https://docs.rs/nostringer"><img alt="Docs.rs" src="https://docs.rs/nostringer/badge.svg?style=for-the-badge&label=docs.rs" height=30></a>
<a href="https://github.com/AbdelStark/nostringer-rs/blob/main/LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge" height=30></a>
<a href="https://bitcoin.org/"> <img alt="Bitcoin" src="https://img.shields.io/badge/Bitcoin-FF9900?style=for-the-badge&logo=bitcoin&logoColor=white" height=30></a>
<a href="https://www.getmonero.org/"> <img alt="Monero" src="https://img.shields.io/badge/Monero-000?style=for-the-badge&logo=monero&logoColor=white" height=30></a>
<a href="https://github.com/nostr-protocol/nostr"> <img alt="Nostr" src="https://img.shields.io/badge/Nostr-8E44AD?style=for-the-badge" height=30></a>

</div>

# Nostringer Ring Signatures (Rust)

<div align="center">
  <img src="https://raw.githubusercontent.com/AbdelStark/nostringer/main/assets/img/nostringer.png" alt="Nostringer Logo" width="250">

  <h3>
   <a href="https://github.com/AbdelStark/nostringer-rs/ROADMAP.md">
      ROADMAP
    </a>
   <span> | </span>
    <a href="https://nostringer.starknetonbitcoin.com/">
      LIVE DEMO
    </a>
    <span> | </span>
    <a href="https://docs.rs/nostringer/latest/nostringer/">
      RUST DOC
    </a>
    <span> | </span>
    <a href="https://github.com/AbdelStark/nostringer-rs/tree/main/crates/nostringer/examples">
      EXAMPLES
    </a>
  </h3>
</div>

A **blazing fast** Rust implementation of the Nostringer **unlinkable ring signature** scheme for Nostr, compatible with the [nostringer](https://github.com/AbdelStark/nostringer) TypeScript library.

Built using pure Rust crypto crates, this library allows a signer to prove membership in a group of Nostr accounts (defined by their public keys) without revealing which specific account produced the signature. It uses a Spontaneous Anonymous Group (SAG)-like algorithm compatible with secp256k1 keys used in Nostr.

Nostringer is largely inspired by [Monero's Ring Signatures](https://www.getmonero.org/library/Zero-to-Monero-2-0-0.pdf) using Spontaneous Anonymous Group signatures (SAG), and [beritani/ring-signatures](https://github.com/beritani/ring-signatures) implementation of ring signatures using the elliptic curve Ed25519 and Keccak for hashing.

## Table of Contents

- [Nostringer Ring Signatures (Rust)](#nostringer-ring-signatures-rust)
  - [Table of Contents](#table-of-contents)
  - [Problem Statement](#problem-statement)
  - [Roadmap](#roadmap)
  - [Key Features](#key-features)
  - [Signature Variants](#signature-variants)
    - [SAG (Spontaneous Anonymous Group)](#sag-spontaneous-anonymous-group)
    - [BLSAG (Back's Linkable Spontaneous Anonymous Group)](#blsag-backs-linkable-spontaneous-anonymous-group)
  - [SAG vs. bLSAG Trade-offs](#sag-vs-blsag-trade-offs)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Optimized Binary API](#optimized-binary-api)
    - [WebAssembly Usage](#webassembly-usage)
      - [Building for WASM](#building-for-wasm)
  - [Examples](#examples)
  - [Benchmarks](#benchmarks)
    - [Performance Results](#performance-results)
  - [API Reference](#api-reference)
  - [Signature Size](#signature-size)
  - [Security Considerations](#security-considerations)
  - [Disclaimer](#disclaimer)
  - [License](#license)
  - [References](#references)

## Problem Statement

In many scenarios, you want to prove that "someone among these N credentials produced this signature," but you do **not** want to reveal _which_ credential or identity. For instance, you might have a set of recognized Nostr pubkeys (e.g., moderators, DAO members, authorized reviewers) who are allowed to perform certain actions, but you want them to remain anonymous within that set when doing so.

A **ring signature** solves this by letting an individual sign a message _on behalf of the group_ (the ring). A verifier can confirm the message originated from **one** of the public keys in the ring, without learning the specific signer's identity.

## Roadmap

Check [ROADMAP.md](ROADMAP.md) for the detailed project roadmap, including completed and upcoming milestones.

## Key Features

- **Unlinkable**: Signatures hide the signer's identity. Two signatures from the same signer cannot be linked cryptographically.
- **Linkable Option**: The BLSAG variant provides linkability through key images to detect when the same key is used multiple times, while still preserving anonymity within the ring.
- **Fast**: Implemented in Rust, leveraging efficient and audited cryptographic primitives from the RustCrypto ecosystem (`k256`, `sha2`).
- **Optimized API**: Provides both hex-string based API and a more efficient binary API that avoids serialization/deserialization overhead.
- **WebAssembly Support**: Use the library directly in web browsers and other WASM environments.
- **Nostr Key Compatibility**: Directly supports standard Nostr key formats (hex strings):
  - 32-byte (64-hex) x-only public keys.
  - 33-byte (66-hex) compressed public keys.
  - 65-byte (130-hex) uncompressed public keys.
  - 32-byte (64-hex) private keys.
- **Easy to Use**: Simple `sign`, `verify`, and `generate_keypair_hex` functions.
- **Minimal Dependencies**: Relies on well-maintained RustCrypto crates.
- **No Trusted Setup**: The scheme does not require any special setup ceremony.

## Signature Variants

The library offers two main variants of ring signatures:

### SAG (Spontaneous Anonymous Group)

The default variant that provides:

- Complete unlinkability (no way to tell if two signatures came from the same signer)
- Maximum privacy within the ring
- Suitable for anonymous voting, whistleblowing, or any scenario requiring maximum privacy

### BLSAG (Back's Linkable Spontaneous Anonymous Group)

A linkable variant that:

- Produces a key image along with the signature to enable linkability
- Can detect when the same key signs multiple times (via the key image)
- Still doesn't reveal which specific ring member signed (preserves anonymity within the ring)
- Suitable for preventing double-spending, duplicate voting, or tracking usage of a credential
- Similar to the linkable ring signature scheme used in Monero

Choose the variant that best suits your privacy and security requirements.

## SAG vs. bLSAG Trade-offs

This library implements both a basic SAG-like ring signature and the bLSAG (Back's Linkable Spontaneous Anonymous Group) variant. They offer different properties with corresponding performance characteristics:

**Functionality:**

- **SAG (e.g., `sign`, `verify`, `sign_binary`, `verify_binary`):**
  - Provides **Anonymity**: Hides which ring member produced the signature. The verifier only knows the signature came from _someone_ in the specified ring.
  - Provides **Unlinkability**: Signatures produced by the same signer (for different messages or using different rings) cannot be cryptographically linked back to that signer or to each other.
- **bLSAG (e.g., `sign_blsag_binary`, `verify_blsag_binary`):**
  - Provides **Anonymity**: Same as SAG.
  - Provides **Linkability**: Introduces a **Key Image** (`I`) which is unique and deterministic for each private key (`I = sk * H_p(PK)`). If the same private key is used to create multiple bLSAG signatures (even with different rings or messages), they will all produce the _same_ key image. This allows detection of multiple signatures from the same (anonymous) source, useful for preventing double-voting or double-spending in anonymous contexts. Signatures from _different_ private keys will produce _different_ key images.

**Signature Size:**

- **SAG Signature (`c0`, `s`):** Contains `n + 1` scalars (where `n` is the ring size).
  - Binary Size: `32 * (n + 1)` bytes.
- **bLSAG Signature (`c0`, `s`) + Key Image (`I`):** Contains `n + 1` scalars _plus_ one key image (a curve point).
  - Binary Size: `[32 * (n + 1)]` bytes (signature) + `33` bytes (compressed key image) = `32n + 65` bytes.
- **Comparison:** bLSAG signatures require transmitting the additional key image alongside the `c0` and `s` values, making them slightly larger (a constant overhead of 33 bytes compared to SAG when using compressed points).

**Performance (Signing & Verification Speed):**

The computational cost is dominated by elliptic curve scalar multiplications and hashing operations.

- **Elliptic Curve Operations:**
  - **SAG:** Roughly `2n` point multiplications per sign/verify operation in the main loop (`s*G + c*P`).
  - **bLSAG:** Roughly `4n` point multiplications per sign/verify operation in the main loop (`s*G + c*P` and `s*Hp(P) + c*I`). It also includes the key image calculation (`sk * Hp(PK)`) during signing and a key image validity check (subgroup check via `is_torsion_free`) during verification.
- **Hashing:** -**SAG:** Uses one type of hash function (`hash_to_scalar`) involving the message, ring keys (hex strings in current implementation), and one point. This hash is computed `n` times per operation.
  - **bLSAG:** Requires an additional `hash_to_point` operation (hashing a public key to a point) for each ring member (`n` times per operation). It uses a different challenge hash function (`hash_for_blsag_challenge`) involving the message and two points, also computed `n` times per operation.
- **Comparison:** bLSAG signing and verification involve approximately twice the number of core point multiplications and additional hashing steps (`hash_to_point`). Therefore, bLSAG operations are expected to be noticeably **slower** than their SAG counterparts. We will provide detailed benchmarks to quantify this difference.

**Summary Table:**

| Feature         | SAG                  | bLSAG                         | Trade-off Summary                     |
| :-------------- | :------------------- | :---------------------------- | :------------------------------------ |
| **Linkability** | No (Unlinkable)      | Yes (Via Key Image)           | bLSAG adds same-signer detection.     |
| **Size**        | `32(n+1)` bytes      | `32n + 65` bytes              | bLSAG is slightly larger (+33 bytes). |
| **Speed**       | Faster (`~2n` mults) | Slower (`~4n` mults + extras) | bLSAG is computationally heavier.     |

**When to Choose:**

- Choose **SAG** if simple anonymity and unlinkability are sufficient, and maximum performance or minimum signature size are priorities.
- Choose **bLSAG** if you **need** the ability to detect if the same anonymous signer has signed multiple times (e.g., voting, unique claims), and can accept the slightly larger signature size and increased computation time.

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

### WebAssembly Usage

Nostringer can be compiled to WebAssembly, allowing you to use it directly in web browsers and other WASM environments:

```javascript
// Import the WASM module
import init, {
  wasm_generate_keypair,
  wasm_sign,
  wasm_verify,
  wasm_sign_blsag,
  wasm_verify_blsag,
  wasm_key_images_match,
} from "./nostringer.js";

// Initialize the WASM module
async function main() {
  await init();

  // Generate keypairs for the ring
  const keypair1 = wasm_generate_keypair("xonly");
  const keypair2 = wasm_generate_keypair("xonly");
  const keypair3 = wasm_generate_keypair("xonly");

  const ringPubkeys = [
    keypair1.public_key_hex(),
    keypair2.public_key_hex(),
    keypair3.public_key_hex(),
  ];

  // Sign a message with one of the keys
  const message = new TextEncoder().encode(
    "This is a secret message to the group.",
  );
  const signature = wasm_sign(message, keypair2.private_key_hex(), ringPubkeys);

  // Verify the signature
  const isValid = wasm_verify(signature, message, ringPubkeys);
  console.log("Signature valid:", isValid);
}

main();
```

#### Building for WASM

To compile Nostringer for WebAssembly:

```bash
# Install wasm-pack if you don't have it
cargo install wasm-pack

# Build the WASM module
wasm-pack build --target web --features wasm

# For bundlers like webpack
wasm-pack build --target bundler --features wasm

# For Node.js
wasm-pack build --target nodejs --features wasm
```

See the [WebAssembly example](https://github.com/AbdelStark/nostringer-rs/tree/main/crates/nostringer/examples/web/basic_wasm) for a complete demonstration of using Nostringer in a web browser.

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

3. **BLSAG Linkability** (`examples/blsag_linkability.rs`): Demonstrates the linkable BLSAG variant and how to detect when the same key is used for multiple signatures.

   ```bash
   cargo run --example blsag_linkability
   ```

4. **Error Handling** (`examples/error_handling.rs`): Demonstrates proper error handling for common error scenarios.

   ```bash
   cargo run --example error_handling
   ```

5. **WebAssembly** (`examples/web/basic_wasm`): A web-based example showing how to use the library in a browser via WebAssembly.

   ```bash
   # Build the WASM module
   wasm-pack build crates/nostringer --target web --out-dir examples/web/basic_wasm/pkg --features wasm

   # Serve the example (using Python's built-in server)
   cd crates/nostringer/examples/web/basic_wasm
   python -m http.server
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

Check the [Rust API Docs](https://docs.rs/nostringer/latest/nostringer/) for detailed API reference and usage examples.

## Signature Size

The size of the generated ring signature depends directly on the number of members (`n`) in the ring. It consists of:

- One initial challenge (`c0`) scalar (32 bytes binary / 64 hex chars).
- `n` response scalars (`s` array) (each 32 bytes binary / 64 hex chars).

The total **binary size** follows the formula:
`Size (bytes) = 32 * (n + 1)`

This means the signature size grows **linearly** with the ring size. A larger ring provides more anonymity but results in a larger signature.

## Security Considerations

- **Anonymity Set**: The level of anonymity depends on the size (`n`) and plausibility of the chosen ring members. Ensure the ring contains keys that could _realistically_ be the signer in the given context.
- **No Trusted Setup**: This scheme does not require any trusted setup procedure.
- **Unlinkability vs. Linkability**:
  - **SAG**: The default SAG implementation provides complete unlinkability. Signatures produced by the same signer for different messages (using the same or different rings) are cryptographically unlinkable.
  - **BLSAG**: The BLSAG variant intentionally provides linkability through key images. These key images allow detecting when the same key signed multiple messages, while still preserving anonymity (not revealing which specific ring member is the signer).
- **Implementation Security**: This library relies on the correctness of the underlying `k256` crate. While `k256` is well-regarded, this specific ring signature implementation has **not** been independently audited.

## Disclaimer

> **This code is highly experimental.**
> The original author is not a cryptographer, and this Rust port, while aiming for compatibility and correctness using standard libraries, **has not been audited or formally verified.**
> Use for educational exploration **at your own risk.** Production usage is **strongly discouraged** until thorough security reviews and testing are performed by qualified individuals.

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
