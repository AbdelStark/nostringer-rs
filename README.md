# Nostringer Ring Signatures (Rust)

<div align="center">
  <img src="https://raw.githubusercontent.com/AbdelStark/nostringer/main/assets/img/nostringer.png" alt="Nostringer Logo" width="250">

  <p>
    <a href="https://github.com/AbdelStark/nostringer-rs/actions/workflows/rust.yml"><img alt="GitHub Workflow Status" src="https://img.shields.io/github/actions/workflow/status/AbdelStark/nostringer-rs/rust.yml?style=for-the-badge&label=CI" height=30></a>
    <a href="https://crates.io/crates/nostringer"><img alt="Crates.io" src="https://img.shields.io/crates/v/nostringer.svg?style=for-the-badge&label=crates.io" height=30></a>
    <a href="https://docs.rs/nostringer"><img alt="Docs.rs" src="https://docs.rs/nostringer/badge.svg?style=for-the-badge&label=docs.rs" height=30></a>
    <a href="https://github.com/AbdelStark/nostringer-rs/blob/main/LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge" height=30></a>
  </p>
</div>

A Rust workspace containing libraries and tools for **unlinkable ring signatures** with secp256k1 keys.

## Workspace Structure

This repository is organized as a Rust workspace with the following components:

### Core Library

The `nostringer` crate is a **blazing fast** Rust implementation of the unlinkable ring signature scheme originally developed in TypeScript. It provides:

- Highly optimized binary and hex-string APIs
- Full compatibility with Nostr key formats
- Comprehensive error handling and type safety
- Optional serde support for serialization

```bash
# Add to your project
cargo add nostringer
```

[Read more about the core library →](crates/nostringer/README.md)

### Command-line Interface

The `nostringer_cli` crate provides a user-friendly CLI for working with ring signatures:

- Generate keypairs in various formats
- Sign messages with ring signatures
- Verify ring signatures
- Run demos and examples

```bash
# Install the CLI
cargo install --path crates/nostringer_cli
```

[Read more about the CLI →](crates/nostringer_cli/README.md)

## Quick Start

```rust
use nostringer::{sign, verify, generate_keypair_hex};

// Generate keys for ring members
let keypair1 = generate_keypair_hex("xonly");
let keypair2 = generate_keypair_hex("xonly");
let keypair3 = generate_keypair_hex("xonly");

let ring = vec![
    keypair1.public_key_hex.clone(), 
    keypair2.public_key_hex.clone(),
    keypair3.public_key_hex.clone(),
];

// Sign a message (keypair2 is the actual signer)
let message = b"This is a secret message.";
let signature = sign(message, &keypair2.private_key_hex, &ring)?;

// Anyone can verify the signature came from someone in the ring
let is_valid = verify(&signature, message, &ring)?;
assert!(is_valid);
```

## Use Case: Anonymous Group Proof

Ring signatures allow a member of a group to sign a message without revealing exactly who signed it.

Possible applications:
- Anonymous voting within a DAO or organization
- Whistleblower protection
- Privacy-preserving identity proofs
- Anonymous approvals or endorsements

## Performance

The library provides excellent performance even with large rings:

| Operation     | Ring Size   | Time    |
| ------------- | ----------- | ------- |
| Sign + Verify | 2 members   | 370 µs  |
| Sign + Verify | 10 members  | 1.76 ms |
| Sign + Verify | 100 members | 25 ms   |

See [BENCHMARKS.md](BENCHMARKS.md) for detailed benchmarking information.

## For Developers

### Building

```bash
# Build all components
cargo build

# Run tests
cargo test

# Run benchmarks
cargo bench
```

### Contributor Guidelines

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the [MIT License](LICENSE)

---

Built with ❤️ by [AbdelStark](https://github.com/AbdelStark)

```
npub1hr6v96g0phtxwys4x0tm3khawuuykz6s28uzwtj5j0zc7lunu99snw2e29
```
