#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

// Re-export the core types and functions needed for WASM
#[cfg(feature = "wasm")]
use crate::{
    // Group imports for clarity
    blsag::{key_images_match, sign_blsag_hex, verify_blsag_hex},
    keys::generate_keypair_hex,
    sag::{sign, verify},
    sign_compact_blsag,
    sign_compact_sag,
    verify_compact,
    CompactSignature,
};

/// Set up panic hook for better error messages in WASM
#[cfg(feature = "wasm")]
pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function to get better error messages if a panic occurs.
    console_error_panic_hook::set_once();
}

// ------------------ WASM API ------------------

/// WASM-compatible version of the RingSignature struct
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct WasmRingSignature {
    c0: String,
    s: Box<[JsValue]>,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl WasmRingSignature {
    /// Creates a new RingSignature from components
    #[wasm_bindgen(constructor)]
    pub fn new(c0: String, s: Box<[JsValue]>) -> WasmRingSignature {
        WasmRingSignature { c0, s }
    }

    /// Gets the c0 value
    #[wasm_bindgen(getter)]
    pub fn c0(&self) -> String {
        self.c0.clone()
    }

    /// Gets the s values
    #[wasm_bindgen(getter)]
    pub fn s(&self) -> Box<[JsValue]> {
        self.s.clone()
    }
}

/// WASM-compatible version of the BlsagSignature struct
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct WasmBlsagSignature {
    c0: String,
    s: Box<[JsValue]>,
    key_image: String,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl WasmBlsagSignature {
    /// Creates a new BlsagSignature from components
    #[wasm_bindgen(constructor)]
    pub fn new(c0: String, s: Box<[JsValue]>, key_image: String) -> WasmBlsagSignature {
        WasmBlsagSignature { c0, s, key_image }
    }

    /// Gets the c0 value
    #[wasm_bindgen(getter)]
    pub fn c0(&self) -> String {
        self.c0.clone()
    }

    /// Gets the s values
    #[wasm_bindgen(getter)]
    pub fn s(&self) -> Box<[JsValue]> {
        self.s.clone()
    }

    /// Gets the key image
    #[wasm_bindgen(getter)]
    pub fn key_image(&self) -> String {
        self.key_image.clone()
    }
}

/// WASM-compatible version of the KeyPairHex struct
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct WasmKeyPair {
    private_key_hex: String,
    public_key_hex: String,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl WasmKeyPair {
    /// Creates a new KeyPair from components
    #[wasm_bindgen(constructor)]
    pub fn new(private_key_hex: String, public_key_hex: String) -> WasmKeyPair {
        WasmKeyPair {
            private_key_hex,
            public_key_hex,
        }
    }

    /// Gets the private key hex
    #[wasm_bindgen(getter)]
    pub fn private_key_hex(&self) -> String {
        self.private_key_hex.clone()
    }

    /// Gets the public key hex
    #[wasm_bindgen(getter)]
    pub fn public_key_hex(&self) -> String {
        self.public_key_hex.clone()
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen(start)]
pub fn start() {
    set_panic_hook();
}

/// Generate a new keypair with the specified format
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_generate_keypair(format: &str) -> Result<WasmKeyPair, JsValue> {
    let keypair = generate_keypair_hex(format);
    Ok(WasmKeyPair {
        private_key_hex: keypair.private_key_hex,
        public_key_hex: keypair.public_key_hex,
    })
}

/// Sign a message using a ring signature
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_sign(
    message: &[u8],
    private_key_hex: &str,
    ring_pubkeys: Box<[JsValue]>,
) -> Result<WasmRingSignature, JsValue> {
    // Convert JsValue array to Vec<String>
    let ring_pubkeys_vec: Vec<String> = ring_pubkeys
        .iter()
        .map(|v| {
            v.as_string()
                .ok_or_else(|| JsValue::from_str("Invalid public key"))
        })
        .collect::<Result<Vec<String>, JsValue>>()?;

    // Call the Rust function
    let signature = sign(message, private_key_hex, &ring_pubkeys_vec)
        .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;

    // Convert s values to JsValue array
    let s_values: Vec<JsValue> = signature.s.iter().map(|s| JsValue::from_str(s)).collect();

    Ok(WasmRingSignature {
        c0: signature.c0,
        s: s_values.into_boxed_slice(),
    })
}

/// Verify a ring signature
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_verify(
    signature: &WasmRingSignature,
    message: &[u8],
    ring_pubkeys: Box<[JsValue]>,
) -> Result<bool, JsValue> {
    // Convert JsValue array to Vec<String>
    let ring_pubkeys_vec: Vec<String> = ring_pubkeys
        .iter()
        .map(|v| {
            v.as_string()
                .ok_or_else(|| JsValue::from_str("Invalid public key"))
        })
        .collect::<Result<Vec<String>, JsValue>>()?;

    // Convert WasmRingSignature to RingSignature
    let s_values: Vec<String> = signature
        .s
        .iter()
        .map(|v| {
            v.as_string()
                .ok_or_else(|| JsValue::from_str("Invalid s value"))
        })
        .collect::<Result<Vec<String>, JsValue>>()?;

    let rust_signature = crate::RingSignature {
        c0: signature.c0.clone(),
        s: s_values,
    };

    // Call the Rust function
    let result = verify(&rust_signature, message, &ring_pubkeys_vec)
        .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;

    Ok(result)
}

/// Sign a message using a BLSAG signature (linkable)
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_sign_blsag(
    message: &[u8],
    private_key_hex: &str,
    ring_pubkeys: Box<[JsValue]>,
) -> Result<WasmBlsagSignature, JsValue> {
    // Convert JsValue array to Vec<String>
    let ring_pubkeys_vec: Vec<String> = ring_pubkeys
        .iter()
        .map(|v| {
            v.as_string()
                .ok_or_else(|| JsValue::from_str("Invalid public key"))
        })
        .collect::<Result<Vec<String>, JsValue>>()?;

    // Call the Rust function
    let (signature, key_image) = sign_blsag_hex(message, private_key_hex, &ring_pubkeys_vec)
        .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;

    // Convert s values to JsValue array
    let s_values: Vec<JsValue> = signature.s.iter().map(|s| JsValue::from_str(s)).collect();

    Ok(WasmBlsagSignature {
        c0: signature.c0,
        s: s_values.into_boxed_slice(),
        key_image,
    })
}

/// Verify a BLSAG signature (linkable)
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_verify_blsag(
    signature: &WasmBlsagSignature,
    message: &[u8],
    ring_pubkeys: Box<[JsValue]>,
) -> Result<bool, JsValue> {
    // Convert JsValue array to Vec<String>
    let ring_pubkeys_vec: Vec<String> = ring_pubkeys
        .iter()
        .map(|v| {
            v.as_string()
                .ok_or_else(|| JsValue::from_str("Invalid public key"))
        })
        .collect::<Result<Vec<String>, JsValue>>()?;

    // Convert WasmBlsagSignature to BlsagSignature
    let s_values: Vec<String> = signature
        .s
        .iter()
        .map(|v| {
            v.as_string()
                .ok_or_else(|| JsValue::from_str("Invalid s value"))
        })
        .collect::<Result<Vec<String>, JsValue>>()?;

    let rust_signature = crate::types::BlsagSignature {
        c0: signature.c0.clone(),
        s: s_values,
    };

    // Call the Rust function
    let result = verify_blsag_hex(
        &rust_signature,
        &signature.key_image,
        message,
        &ring_pubkeys_vec,
    )
    .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;

    Ok(result)
}

/// Check if two key images match (same signer)
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_key_images_match(image1: &str, image2: &str) -> Result<bool, JsValue> {
    // Parse key images
    let ki1 = crate::types::KeyImage::from_hex(image1)
        .map_err(|e| JsValue::from_str(&format!("Error parsing key image 1: {}", e)))?;
    let ki2 = crate::types::KeyImage::from_hex(image2)
        .map_err(|e| JsValue::from_str(&format!("Error parsing key image 2: {}", e)))?;

    // Compare key images
    Ok(key_images_match(&ki1, &ki2))
}

// --- Compact Signature API ---

/// Sign a message using the compact SAG format, resulting in a 'ringA' prefixed string
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_sign_compact_sag(
    message: &[u8],
    private_key_hex: &str,
    ring_pubkeys: Box<[JsValue]>,
) -> Result<String, JsValue> {
    // Convert JsValue array to Vec<String>
    let ring_pubkeys_vec: Vec<String> = ring_pubkeys
        .iter()
        .map(|v| {
            v.as_string()
                .ok_or_else(|| JsValue::from_str("Invalid public key"))
        })
        .collect::<Result<Vec<String>, JsValue>>()?;

    // Call the Rust compact signature function
    sign_compact_sag(message, private_key_hex, &ring_pubkeys_vec)
        .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))
}

/// Sign a message using the compact BLSAG format, resulting in a 'ringA' prefixed string
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_sign_compact_blsag(
    message: &[u8],
    private_key_hex: &str,
    ring_pubkeys: Box<[JsValue]>,
) -> Result<String, JsValue> {
    // Convert JsValue array to Vec<String>
    let ring_pubkeys_vec: Vec<String> = ring_pubkeys
        .iter()
        .map(|v| {
            v.as_string()
                .ok_or_else(|| JsValue::from_str("Invalid public key"))
        })
        .collect::<Result<Vec<String>, JsValue>>()?;

    // Call the Rust compact signature function
    sign_compact_blsag(message, private_key_hex, &ring_pubkeys_vec)
        .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))
}

/// Verify a compact signature (both SAG and BLSAG types)
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_verify_compact(
    compact_signature: &str,
    message: &[u8],
    ring_pubkeys: Box<[JsValue]>,
) -> Result<bool, JsValue> {
    // Convert JsValue array to Vec<String>
    let ring_pubkeys_vec: Vec<String> = ring_pubkeys
        .iter()
        .map(|v| {
            v.as_string()
                .ok_or_else(|| JsValue::from_str("Invalid public key"))
        })
        .collect::<Result<Vec<String>, JsValue>>()?;

    // Call the Rust verify function
    verify_compact(compact_signature, message, &ring_pubkeys_vec)
        .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))
}

/// Get details about a compact signature (variant and size)
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_get_compact_signature_info(compact_signature: &str) -> Result<JsValue, JsValue> {
    // Deserialize the compact signature
    let compact_sig = CompactSignature::deserialize(compact_signature)
        .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;

    // Extract info
    let variant = compact_sig.variant();
    let size = compact_signature.len();

    // Create a JavaScript object with the info
    let info = js_sys::Object::new();
    js_sys::Reflect::set(
        &info,
        &JsValue::from_str("variant"),
        &JsValue::from_str(variant),
    )
    .map_err(|_| JsValue::from_str("Failed to set variant"))?;
    js_sys::Reflect::set(
        &info,
        &JsValue::from_str("size"),
        &JsValue::from_f64(size as f64),
    )
    .map_err(|_| JsValue::from_str("Failed to set size"))?;

    Ok(info.into())
}

/// Deserializes a compact SAG signature string to a WasmRingSignature
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_deserialize_compact_sag(compact_signature: &str) -> Result<WasmRingSignature, JsValue> {
    // Deserialize the compact signature
    let compact_sig = CompactSignature::deserialize(compact_signature)
        .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;

    // Ensure it's the correct type
    match compact_sig {
        CompactSignature::Sag(binary_sig) => {
            // Convert s values to JsValue array using proper hex conversion for Scalar
            let s_values: Vec<JsValue> = binary_sig
                .s
                .iter()
                .map(|s| {
                    let bytes_array = s.to_bytes();
                    let bytes: &[u8] = bytes_array.as_ref();
                    JsValue::from_str(&hex::encode(bytes))
                })
                .collect();

            let c0_bytes_array = binary_sig.c0.to_bytes();
            let c0_bytes: &[u8] = c0_bytes_array.as_ref();

            Ok(WasmRingSignature {
                c0: hex::encode(c0_bytes),
                s: s_values.into_boxed_slice(),
            })
        }
        _ => Err(JsValue::from_str("Error: Not a SAG signature")),
    }
}

/// Deserializes a compact BLSAG signature string to a WasmBlsagSignature
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_deserialize_compact_blsag(
    compact_signature: &str,
) -> Result<WasmBlsagSignature, JsValue> {
    // Deserialize the compact signature
    let compact_sig = CompactSignature::deserialize(compact_signature)
        .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;

    // Ensure it's the correct type
    match compact_sig {
        CompactSignature::Blsag(binary_sig, key_image) => {
            // Convert s values to JsValue array using proper hex conversion for Scalar
            let s_values: Vec<JsValue> = binary_sig
                .s
                .iter()
                .map(|s| {
                    let bytes_array = s.to_bytes();
                    let bytes: &[u8] = bytes_array.as_ref();
                    JsValue::from_str(&hex::encode(bytes))
                })
                .collect();

            let c0_bytes_array = binary_sig.c0.to_bytes();
            let c0_bytes: &[u8] = c0_bytes_array.as_ref();

            Ok(WasmBlsagSignature {
                c0: hex::encode(c0_bytes),
                s: s_values.into_boxed_slice(),
                key_image: key_image.to_hex(),
            })
        }
        _ => Err(JsValue::from_str("Error: Not a BLSAG signature")),
    }
}

/// Attempts to deserialize a compact signature string to either type
/// Returns information about the signature type and an optional error
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_detect_compact_signature_type(compact_signature: &str) -> Result<JsValue, JsValue> {
    // Attempt to deserialize
    let compact_sig = CompactSignature::deserialize(compact_signature)
        .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;

    // Create a JavaScript object with the info
    let info = js_sys::Object::new();

    match compact_sig {
        CompactSignature::Sag(_) => {
            js_sys::Reflect::set(&info, &JsValue::from_str("type"), &JsValue::from_str("sag"))
                .map_err(|_| JsValue::from_str("Failed to set type"))?;
        }
        CompactSignature::Blsag(_, _) => {
            js_sys::Reflect::set(
                &info,
                &JsValue::from_str("type"),
                &JsValue::from_str("blsag"),
            )
            .map_err(|_| JsValue::from_str("Failed to set type"))?;
        }
    }

    Ok(info.into())
}

/// Serializes a WasmRingSignature to a compact signature string
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_serialize_ring_signature(signature: &WasmRingSignature) -> Result<String, JsValue> {
    // Convert JsValue s values to Vec<String>
    let s_values: Vec<String> = signature
        .s
        .iter()
        .map(|v| {
            v.as_string()
                .ok_or_else(|| JsValue::from_str("Invalid s value"))
        })
        .collect::<Result<Vec<String>, JsValue>>()?;

    // Convert to RingSignatureBinary
    let c0_scalar = crate::types::hex_to_scalar(&signature.c0)
        .map_err(|e| JsValue::from_str(&format!("Error parsing c0: {}", e)))?;

    // Convert s values to scalars
    let s_scalars = s_values
        .iter()
        .map(|s| crate::types::hex_to_scalar(s))
        .collect::<Result<Vec<k256::Scalar>, _>>()
        .map_err(|e| JsValue::from_str(&format!("Error parsing s values: {}", e)))?;

    let binary_signature = crate::types::RingSignatureBinary {
        c0: c0_scalar,
        s: s_scalars,
    };

    // Create compact signature and serialize
    let compact_sig = CompactSignature::Sag(binary_signature);
    compact_sig
        .serialize()
        .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))
}

/// Serializes a WasmBlsagSignature to a compact signature string
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_serialize_blsag_signature(signature: &WasmBlsagSignature) -> Result<String, JsValue> {
    // Convert JsValue s values to Vec<String>
    let s_values: Vec<String> = signature
        .s
        .iter()
        .map(|v| {
            v.as_string()
                .ok_or_else(|| JsValue::from_str("Invalid s value"))
        })
        .collect::<Result<Vec<String>, JsValue>>()?;

    // Convert to binary types
    let c0_scalar = crate::types::hex_to_scalar(&signature.c0)
        .map_err(|e| JsValue::from_str(&format!("Error parsing c0: {}", e)))?;

    // Convert s values to scalars
    let s_scalars = s_values
        .iter()
        .map(|s| crate::types::hex_to_scalar(s))
        .collect::<Result<Vec<k256::Scalar>, _>>()
        .map_err(|e| JsValue::from_str(&format!("Error parsing s values: {}", e)))?;

    // Using BlsagSignatureBinary (same as RingSignatureBinary)
    let binary_signature = crate::types::BlsagSignatureBinary {
        c0: c0_scalar,
        s: s_scalars,
    };

    // Parse key image
    let key_image = crate::types::KeyImage::from_hex(&signature.key_image)
        .map_err(|e| JsValue::from_str(&format!("Error parsing key image: {}", e)))?;

    // Create compact signature and serialize
    let compact_sig = CompactSignature::Blsag(binary_signature, key_image);
    compact_sig
        .serialize()
        .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))
}

// ====== Tests for WASM Serialization/Deserialization ======

#[cfg(all(test, feature = "wasm"))]
mod tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn test_deserialize_serialize_sag() {
        // Generate a keypair and create a signature
        let keypair = generate_keypair_hex("xonly");
        let ring_pubkeys = vec![keypair.public_key_hex.clone()];
        let message = b"test message";

        // Create a compact signature
        let compact_sig = sign_compact_sag(message, &keypair.private_key_hex, &ring_pubkeys)
            .expect("Should sign successfully");

        // Deserialize to WASM type
        let wasm_sig =
            wasm_deserialize_compact_sag(&compact_sig).expect("Should deserialize successfully");

        // Serialize back to compact
        let recompact_sig =
            wasm_serialize_ring_signature(&wasm_sig).expect("Should serialize successfully");

        // Verify the round-trip
        let verification = verify_compact(&recompact_sig, message, &ring_pubkeys)
            .expect("Should verify successfully");
        assert!(verification, "Round-trip signature should verify");
    }

    #[wasm_bindgen_test]
    fn test_deserialize_serialize_blsag() {
        // Generate a keypair and create a signature
        let keypair = generate_keypair_hex("xonly");
        let ring_pubkeys = vec![keypair.public_key_hex.clone()];
        let message = b"test message";

        // Create a compact signature
        let compact_sig = sign_compact_blsag(message, &keypair.private_key_hex, &ring_pubkeys)
            .expect("Should sign successfully");

        // Deserialize to WASM type
        let wasm_sig =
            wasm_deserialize_compact_blsag(&compact_sig).expect("Should deserialize successfully");

        // Serialize back to compact
        let recompact_sig =
            wasm_serialize_blsag_signature(&wasm_sig).expect("Should serialize successfully");

        // Verify the round-trip
        let verification = verify_compact(&recompact_sig, message, &ring_pubkeys)
            .expect("Should verify successfully");
        assert!(verification, "Round-trip signature should verify");
    }

    #[wasm_bindgen_test]
    fn test_detect_signature_type() {
        // Generate a keypair for testing
        let keypair = generate_keypair_hex("xonly");
        let ring_pubkeys = vec![keypair.public_key_hex.clone()];
        let message = b"test message";

        // Create both types of signatures
        let sag_sig = sign_compact_sag(message, &keypair.private_key_hex, &ring_pubkeys)
            .expect("Should sign SAG successfully");
        let blsag_sig = sign_compact_blsag(message, &keypair.private_key_hex, &ring_pubkeys)
            .expect("Should sign BLSAG successfully");

        // Test detection
        let sag_info =
            wasm_detect_compact_signature_type(&sag_sig).expect("Should detect SAG type");
        let blsag_info =
            wasm_detect_compact_signature_type(&blsag_sig).expect("Should detect BLSAG type");

        // We would verify the type information here,
        // but this requires JavaScript interaction which we can't do in a pure Rust test
        // This test just ensures no panic or error occurs
    }
}
