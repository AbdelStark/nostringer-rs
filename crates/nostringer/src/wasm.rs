#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

// Re-export the core types and functions needed for WASM
#[cfg(feature = "wasm")]
use crate::{
    // Group imports for clarity
    blsag::{key_images_match, sign_blsag_hex, verify_blsag_hex},
    keys::generate_keypair_hex,
    sag::{sign, verify},
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
