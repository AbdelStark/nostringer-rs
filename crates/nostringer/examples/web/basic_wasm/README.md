# Nostringer WebAssembly Example

This example demonstrates how to use the Nostringer library in a web browser via WebAssembly (WASM).

## Prerequisites

- [Rust](https://www.rust-lang.org/) (latest stable)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/) - Install with `cargo install wasm-pack`
- A web server for local development (e.g., [Python's http.server](https://docs.python.org/3/library/http.server.html) or [Node's http-server](https://www.npmjs.com/package/http-server))

## Building the WASM Module

From the root of the project, run:

```bash
# Build the WASM module in release mode
wasm-pack build crates/nostringer --target web --out-dir examples/web/basic_wasm/pkg --features wasm

# Alternatively, for development with more debugging info:
wasm-pack build crates/nostringer --target web --out-dir examples/web/basic_wasm/pkg --features wasm --dev
```

## Running the Example

After building the WASM module, you can serve the example locally:

```bash
# Using Python's built-in HTTP server
cd crates/nostringer/examples/web/basic_wasm
python -m http.server

# Or using Node's http-server (if installed)
cd crates/nostringer/examples/web/basic_wasm
http-server
```

Then open your browser and navigate to:
- For Python: http://localhost:8000
- For http-server: http://localhost:8080

## Example Features

This example demonstrates:

1. **SAG Ring Signatures (Unlinkable):**
   - Generating keypairs for a ring
   - Signing a message with one of the ring members
   - Verifying the signature against the ring
   - Testing signature validity with a tampered message

2. **BLSAG Ring Signatures (Linkable):**
   - Generating keypairs for a ring
   - Signing multiple messages with the same key
   - Verifying signatures
   - Demonstrating linkability by comparing key images

## Integration into Your Own Web Application

To use Nostringer in your own web application:

1. Build the WASM module as described above.
2. Copy the generated files from the `pkg` directory to your web project.
3. Import the WASM module in your JavaScript:

```javascript
import init, {
  wasm_generate_keypair,
  wasm_sign,
  wasm_verify,
  wasm_sign_blsag,
  wasm_verify_blsag,
  wasm_key_images_match
} from './path/to/nostringer.js';

// Initialize the WASM module
async function start() {
  await init();
  
  // Now you can use the functions
  const keypair = wasm_generate_keypair("xonly");
  console.log("Generated keypair:", keypair.public_key_hex());
  
  // For signing and verification, use arrays to pass the ring public keys
  const ring = [pubkey1, pubkey2, pubkey3];
  
  // Sign a message
  const message = new TextEncoder().encode("Your message here");
  const signature = wasm_sign(message, privateKey, ring);
  
  // Verify a signature
  const isValid = wasm_verify(signature, message, ring);
}

start();
```

## Available WASM Functions

- `wasm_generate_keypair(format: string)`: Generates a keypair with the specified format ("xonly", "compressed", or "uncompressed")
- `wasm_sign(message: Uint8Array, privateKeyHex: string, ringPubkeysHex: string[])`: Signs a message with SAG
- `wasm_verify(signature: WasmRingSignature, message: Uint8Array, ringPubkeysHex: string[])`: Verifies a SAG signature
- `wasm_sign_blsag(message: Uint8Array, privateKeyHex: string, ringPubkeysHex: string[])`: Signs a message with BLSAG (linkable)
- `wasm_verify_blsag(signature: WasmBlsagSignature, message: Uint8Array, ringPubkeysHex: string[])`: Verifies a BLSAG signature
- `wasm_key_images_match(keyImage1: string, keyImage2: string)`: Checks if two key images match (same signer)

## Performance Considerations

- The WebAssembly version uses hex-encoded strings for compatibility, which is less efficient than the native binary API.
- For large rings or performance-critical applications, consider offloading heavy cryptographic operations to a server using the native Rust library. 