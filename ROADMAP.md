# Project Roadmap: Nostringer Ring Signatures for Nostr

This roadmap outlines the planned development stages for the Rust implementation of Nostringer ring signatures.

## Phase 0: Core Implementation (Completed)

- [x] Implement basic SAG (Spontaneous Anonymous Group) ring signatures (`sign_binary`, `verify_binary`).
- [x] Implement hex-based wrappers (`sign`, `verify`).
- [x] Implement bLSAG (Back's Linkable Spontaneous Anonymous Group) signatures (`sign_blsag_binary`, `verify_blsag_binary`) including Key Image generation and validation.
- [x] Implement hex-based wrappers for bLSAG (`sign_blsag_hex`, `verify_blsag_hex`).
- [x] Add utility for Key Image comparison (`key_images_match`).
- [x] Add key generation helpers (`generate_keypair_hex`, etc.).
- [x] Establish initial test suite for round trips and basic validation.
- [x] Add basic WASM support for core signing/verification functions.

## Phase 1: Stabilization & Nostr Integration (Target: v0.2.x / v0.3.x)

**Goal:** Ensure robustness, compatibility with the Nostr ecosystem (specifically `rust-nostr`), and refine existing features.

**Tasks:**

### Testing & Compatibility

- [ ] **E2E Cross-Compatibility Tests:** Finalize and automate robust end-to-end tests verifying signatures between this Rust library and various Nostr libraries.
- [ ] **`rust-nostr` Key Compatibility:** Rigorously test that keys generated and managed by the `rust-nostr` crate (`Keys`, `PublicKey`, `SecretKey`) work seamlessly with `nostringer-ring`'s hex and binary APIs, covering different key formats (x-only, compressed).
- [ ] **`rust-nostr` Event Signing Test:** Create examples/tests demonstrating signing the canonical serialization of `rust-nostr` `Event` JSON arrays using both SAG and bLSAG. Verify these signatures.
- [ ] **Expand Unit Tests:** Add tests for edge cases (e.g., ring size limits, specific key values, invalid inputs) for both SAG and bLSAG.

### Refinement & Optimization

- [ ] **Optimize Binary APIs:** Investigate refactoring hashing functions (`hash_to_scalar`, `hash_for_blsag_challenge`, `hash_to_point`) to accept binary inputs (`&[ProjectivePoint]`) directly, potentially eliminating intermediate hex conversions within `sign_*_binary`/`verify_*_binary` for significant performance gains.
- [ ] **Error Handling:** Review `Error` enum variants for clarity and specificity. Ensure errors propagate helpfully.
- [ ] **Benchmarking:** Perform and document benchmarks comparing SAG vs. bLSAG signing and verification speeds for various ring sizes. Compare Rust vs. WASM performance.

### WASM

- [ ] **Robust Bindings:** Review and solidify WASM function exports (`wasm-bindgen` setup).
- [ ] **JS/TS Examples:** Provide clear, runnable examples showing how to use the generated WASM package from JavaScript/TypeScript.

## Phase 2: Serialization Standard & Usability (Target: v0.4.x / v0.5.x)

**Goal:** Define and implement a standard, compact format for transmitting signatures, making them practical for use cases like Nostr events. Improve overall usability.

**Tasks:**

### Define Standard Signature Format

- [ ] Research trade-offs (size, complexity, ecosystem compatibility) between CBOR+Base64URL, JSON+Base64, concatenated hex+Base64, etc.
- [ ] Consider adopting a [Cashu like NUT-00 V4 tokens format](https://github.com/cashubtc/nuts/blob/main/00.md#v4-tokens)
  - Define concise CBOR representation for `BlsagSignature` + `KeyImage` (and `RingSignature`). Use byte strings for scalars, points, key image. Use short keys (e.g., `c`, `s`, `i`).
  - Implement `serde_cbor` serialization/deserialization.
  - Implement Base64 URL Safe encoding/decoding (using `base64` crate's `URL_SAFE_NO_PAD` engine).
  - Define distinct prefixes (e.g., `nring1sag_`, `nring1blsag_`) to identify signature type and version.

### Implement Serialization API

- [ ] Add `to_standard_format(&self) -> String` methods to `RingSignatureBinary` / `BlsagSignatureBinary` (+ `KeyImage`).
- [ ] Add `from_standard_format(s: &str) -> Result<Self, Error>` methods or standalone functions.
- [ ] **Documentation:** Clearly specify the chosen serialization format in the README with examples.
- [ ] **WASM:** Expose the standard format serialization/deserialization functions via WASM.
- [ ] **API Review:** Refine public API based on integration testing feedback for better ergonomics.

## Phase 3: Nostr Ecosystem & Future Research (Target: v0.6.x / v1.0)

**Goal:** Specify, discuss with Nostr devs, explore advanced features, and ensure long-term stability and security.

**Tasks:**

- [ ] **NIP Proposal:** Based on the standardized format, consider drafting or contributing to a Nostr Improvement Proposal (NIP) for ring signatures on Nostr.
- [ ] **Security Audit:** Seek review/audit from external cryptographers or security experts (Crucial before widespread adoption or a 1.0 release).
- [ ] **Performance (Advanced):** Explore more advanced optimizations:
  - Batch verification (investigate feasibility for SAG/bLSAG).
  - Alternative `hash_to_point` methods (e.g., SWU via `k256`'s `hash2curve` feature) if try-and-increment proves too slow or problematic.
- [ ] **Alternative Schemes?:** Research MLSAG/CLSAG from Monero – assess complexity vs. benefits (e.g., smaller multi-signatures) in the Nostr context. Implement only if a strong use case emerges.
- [ ] **Documentation & Examples:** Create more extensive documentation, tutorials, and real-world usage examples (e.g., anonymous polling on Nostr, private group access).

## Ongoing Tasks

- [ ] **Dependency Updates:** Keep `k256`, `rust-nostr` (for testing), and other dependencies up-to-date.
- [ ] **CI/Testing:** Maintain and enhance the CI pipeline and test coverage.
- [ ] **Issue Tracking:** Address bugs and feature requests reported by users.
- [ ] **Community:** Engage with potential users and the Nostr developer community.
