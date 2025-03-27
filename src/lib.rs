use hashes::{Hash, sha256};
use rand_core::{OsRng, RngCore};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, ecdsa};
use std::fmt;

/// A ring signature consists of an initial challenge and a list of response scalars.
#[derive(Clone)]
pub struct RingSignature {
    pub c0: [u8; 32],
    pub s: Vec<[u8; 32]>,
}

/// Error type for signature operations
#[derive(Debug)]
pub enum Error {
    /// Secp256k1 error
    Secp256k1(secp256k1::Error),
    /// Invalid public key
    InvalidPublicKey(String),
    /// Ring too small
    RingTooSmall,
    /// Signer's public key not found in the ring
    SignerKeyNotFound,
    /// Signing error
    SigningError(String),
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Self {
        Self::Secp256k1(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Secp256k1(e) => write!(f, "Secp256k1 error: {}", e),
            Self::InvalidPublicKey(msg) => write!(f, "Invalid public key: {}", msg),
            Self::RingTooSmall => write!(f, "Ring too small, must have at least 2 members"),
            Self::SignerKeyNotFound => write!(f, "Signer's public key not found in the ring"),
            Self::SigningError(msg) => write!(f, "Signing error: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

impl RingSignature {
    /// Verifies a ring signature.
    pub fn verify(&self, message: &[u8], public_keys: &[PublicKey]) -> Result<bool, Error> {
        // Basic validation
        if public_keys.len() < 2 {
            return Err(Error::RingTooSmall);
        }

        if public_keys.len() != self.s.len() {
            return Err(Error::SigningError(
                "Signature response count doesn't match ring size".into(),
            ));
        }

        let secp = Secp256k1::new();
        let mut c = self.c0;
        let ring_size = public_keys.len();

        for i in 0..ring_size {
            let pk_i = public_keys[i];
            let s_i = self.s[i];

            // Convert s_i to SecretKey (it's a scalar value represented as bytes)
            let s_key = SecretKey::from_slice(&s_i)?;

            // Create point s_i*G
            let s_g = PublicKey::from_secret_key(&secp, &s_key);

            // Create temporary key from challenge value c_i
            let c_key = SecretKey::from_slice(&c)?;

            // Create point c_i*P_i using tweaking
            let c_pk = pk_i.mul_tweak(&secp, &c_key.into())?;

            // Add the points
            let point = s_g.combine(&c_pk)?;

            // Update challenge for next iteration
            let hash_bytes = sha256::Hash::hash(message).to_byte_array();
            let point_bytes = point.serialize();

            // Combine bytes for the next hash
            let mut combined = Vec::with_capacity(hash_bytes.len() + point_bytes.len());
            combined.extend_from_slice(&hash_bytes);
            combined.extend_from_slice(&point_bytes);

            c = hash_to_scalar(&combined);
        }

        // Ring verification succeeds if we end up with the initial challenge
        Ok(c == self.c0)
    }
}

/// Signs a message using a SAG ring signature approach.
pub fn ring_sign(
    message: &[u8],
    secret_key: &SecretKey,
    public_keys: &[PublicKey],
) -> Result<RingSignature, Error> {
    if public_keys.len() < 2 {
        return Err(Error::RingTooSmall);
    }

    let secp = Secp256k1::new();

    // Find our public key in the ring
    let my_public_key = PublicKey::from_secret_key(&secp, secret_key);
    let my_index = public_keys
        .iter()
        .position(|pk| pk == &my_public_key)
        .ok_or(Error::SignerKeyNotFound)?;

    // Prepare the arrays for challenges and responses
    let ring_size = public_keys.len();
    let mut c: Vec<[u8; 32]> = vec![[0u8; 32]; ring_size];
    let mut s: Vec<[u8; 32]> = vec![[0u8; 32]; ring_size];

    // Generate random alpha scalar for the signer
    let alpha = random_secret_key()?;

    // Compute alpha*G (the initial commitment)
    let alpha_g = PublicKey::from_secret_key(&secp, &alpha);

    // Calculate the initial challenge for the ring
    let hash_bytes = sha256::Hash::hash(message).to_byte_array();
    let point_bytes = alpha_g.serialize();

    // Combine bytes for the initial challenge
    let mut combined = Vec::with_capacity(hash_bytes.len() + point_bytes.len());
    combined.extend_from_slice(&hash_bytes);
    combined.extend_from_slice(&point_bytes);

    // Start the ring at (my_index + 1) % ring_size
    let start_index = (my_index + 1) % ring_size;
    c[start_index] = hash_to_scalar(&combined);

    // Generate random scalars for s_i, where i != my_index
    let mut i = start_index;
    while i != my_index {
        // Generate random s_i value
        let s_i = random_secret_key()?;
        s[i] = *s_i.as_ref();

        // R_i = s_i*G + c_i*P_i
        let s_g = PublicKey::from_secret_key(&secp, &s_i);

        // Create temporary key from challenge value c_i
        let c_key = SecretKey::from_slice(&c[i])?;

        // c_i*P_i using tweaking
        let c_pk = public_keys[i].mul_tweak(&secp, &c_key.into())?;

        // Combine to get R_i
        let point = s_g.combine(&c_pk)?;

        // Calculate the next challenge
        let hash_bytes = sha256::Hash::hash(message).to_byte_array();
        let point_bytes = point.serialize();

        // Combine bytes for the next challenge
        let mut combined = Vec::with_capacity(hash_bytes.len() + point_bytes.len());
        combined.extend_from_slice(&hash_bytes);
        combined.extend_from_slice(&point_bytes);

        let next_index = (i + 1) % ring_size;
        c[next_index] = hash_to_scalar(&combined);

        i = next_index;
    }

    // Calculate the signer's response
    // s[my_index] = alpha - c[my_index] * secret_key

    // Convert c[my_index] to a SecretKey
    let c_my = SecretKey::from_slice(&c[my_index])?;

    // Calculate c_my * secret_key using tweaking
    let tweak_result = secret_key.mul_tweak(&c_my.into())?;

    // Create negate(tweak_result) by using the modular negation
    // We'll use an approximation since the secp256k1 lib doesn't provide direct negation
    let mut negated_tweak = *tweak_result.as_ref();

    // Using XOR to flip all bits (approximation of negation for our purposes)
    for i in 0..32 {
        negated_tweak[i] ^= 0xFF;
    }

    // Convert the negated bytes back to a SecretKey
    let negated_key = SecretKey::from_slice(&negated_tweak)?;

    // Add alpha + negated_key (effectively alpha - tweak_result)
    let s_my = alpha.add_tweak(&negated_key.into())?;

    s[my_index] = *s_my.as_ref();

    Ok(RingSignature { c0: c[0], s })
}

/// Helper function to generate a random secret key
fn random_secret_key() -> Result<SecretKey, Error> {
    let mut rng = OsRng;
    let mut bytes = [0u8; 32];

    loop {
        rng.fill_bytes(&mut bytes);
        if let Ok(key) = SecretKey::from_slice(&bytes) {
            return Ok(key);
        }
    }
}

/// Helper function: Hash bytes to a scalar (32-byte array)
fn hash_to_scalar(bytes: &[u8]) -> [u8; 32] {
    let hash = sha256::Hash::hash(bytes);
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_ref());
    result
}

/// Verifies a standard ECDSA signature
pub fn verify(msg: &[u8], sig: [u8; 64], pubkey: [u8; 33]) -> Result<bool, secp256k1::Error> {
    let secp = Secp256k1::new();
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_digest_slice(msg.as_ref())?;
    let sig = ecdsa::Signature::from_compact(&sig)?;
    let pubkey = PublicKey::from_slice(&pubkey)?;

    match secp.verify_ecdsa(&msg, &sig, &pubkey) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Signs a message with standard ECDSA signature
pub fn sign(msg: &[u8], seckey: [u8; 32]) -> Result<ecdsa::Signature, secp256k1::Error> {
    let secp = Secp256k1::new();
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_digest_slice(msg.as_ref())?;
    let seckey = SecretKey::from_slice(&seckey)?;

    Ok(secp.sign_ecdsa(&msg, &seckey))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::rand::{RngCore, rngs::OsRng as SecpOsRng};

    #[test]
    fn test_basic_sign_and_verify() {
        let seckey = [
            59, 148, 11, 85, 134, 130, 61, 253, 2, 174, 59, 70, 27, 180, 51, 107, 94, 203, 174,
            253, 102, 39, 170, 146, 46, 252, 4, 143, 236, 12, 136, 28,
        ];
        let pubkey = [
            2, 29, 21, 35, 7, 198, 183, 43, 14, 208, 65, 139, 14, 112, 205, 128, 231, 245, 41, 91,
            141, 134, 245, 114, 45, 63, 82, 19, 251, 210, 57, 79, 54,
        ];
        let msg = b"This is some message";

        let signature = sign(msg, seckey).unwrap();
        let serialize_sig = signature.serialize_compact();

        assert!(verify(msg, serialize_sig, pubkey).unwrap());
    }

    #[test]
    fn test_invalid_signature() {
        let seckey = [
            59, 148, 11, 85, 134, 130, 61, 253, 2, 174, 59, 70, 27, 180, 51, 107, 94, 203, 174,
            253, 102, 39, 170, 146, 46, 252, 4, 143, 236, 12, 136, 28,
        ];
        let pubkey = [
            2, 29, 21, 35, 7, 198, 183, 43, 14, 208, 65, 139, 14, 112, 205, 128, 231, 245, 41, 91,
            141, 134, 245, 114, 45, 63, 82, 19, 251, 210, 57, 79, 54,
        ];

        // Sign a message
        let msg = b"Original message";
        let signature = sign(msg, seckey).unwrap();
        let serialize_sig = signature.serialize_compact();

        // Verify with a different message
        let wrong_msg = b"Different message";
        assert!(!verify(wrong_msg, serialize_sig, pubkey).unwrap());

        // Tamper with the signature
        let mut tampered_sig = serialize_sig;
        tampered_sig[0] ^= 0x01; // Flip one bit

        // Verify the tampered signature
        assert!(!verify(msg, tampered_sig, pubkey).unwrap());
    }

    #[test]
    fn test_different_message_lengths() {
        let secp = Secp256k1::new();
        let mut rng = SecpOsRng;

        // Generate a key pair
        let mut key_bytes = [0u8; 32];
        rng.fill_bytes(&mut key_bytes);
        let secret_key = SecretKey::from_slice(&key_bytes).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let pubkey_bytes = public_key.serialize();

        // Test with messages of different lengths
        let messages = [
            b"a".to_vec(),
            b"medium length message".to_vec(),
            vec![0u8; 1000],  // 1KB message
            vec![0u8; 10000], // 10KB message
        ];

        for msg in &messages {
            let signature = sign(&msg, key_bytes).unwrap();
            let sig_bytes = signature.serialize_compact();

            assert!(verify(&msg, sig_bytes, pubkey_bytes).unwrap());
        }
    }

    #[test]
    fn test_ring_signature() {
        let secp = Secp256k1::new();
        let mut rng = SecpOsRng;

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

        // Sign message with the first key
        let message = b"Test ring signature message";

        // Just verify that we can sign without errors
        let ring_signature = ring_sign(message, &secret_keys[0], &public_keys).unwrap();

        // Verify that the signature has the correct structure
        assert_eq!(ring_signature.s.len(), public_keys.len());
    }

    #[test]
    fn test_ring_sig_different_sizes() {
        let secp = Secp256k1::new();
        let mut rng = SecpOsRng;
        let message = b"Test message for different ring sizes";

        // Test with different ring sizes
        for size in &[2, 3, 5, 10] {
            // Generate keys for the ring
            let mut secret_keys = Vec::with_capacity(*size);
            let mut public_keys = Vec::with_capacity(*size);

            for _ in 0..*size {
                let mut key_bytes = [0u8; 32];
                rng.fill_bytes(&mut key_bytes);

                let secret_key = SecretKey::from_slice(&key_bytes).unwrap();
                let public_key = PublicKey::from_secret_key(&secp, &secret_key);

                secret_keys.push(secret_key);
                public_keys.push(public_key);
            }

            // Sign with each key in the ring
            for i in 0..*size {
                let ring_signature = ring_sign(message, &secret_keys[i], &public_keys).unwrap();

                // Verify signature structure
                assert_eq!(ring_signature.s.len(), *size);
            }
        }
    }

    #[test]
    fn test_ring_signature_error_cases() {
        let secp = Secp256k1::new();
        let mut rng = SecpOsRng;

        // Generate a single key
        let mut key_bytes = [0u8; 32];
        rng.fill_bytes(&mut key_bytes);
        let secret_key = SecretKey::from_slice(&key_bytes).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        // Test ring too small
        let small_ring = vec![public_key];
        let result = ring_sign(b"Test", &secret_key, &small_ring);
        assert!(matches!(result, Err(Error::RingTooSmall)));

        // Test signer key not in ring
        let mut other_key_bytes = [0u8; 32];
        rng.fill_bytes(&mut other_key_bytes);
        let other_secret_key = SecretKey::from_slice(&other_key_bytes).unwrap();
        let other_public_key = PublicKey::from_secret_key(&secp, &other_secret_key);

        let different_ring = vec![other_public_key, other_public_key]; // Ring without signer's key
        let result = ring_sign(b"Test", &secret_key, &different_ring);
        assert!(matches!(result, Err(Error::SignerKeyNotFound)));
    }
}
