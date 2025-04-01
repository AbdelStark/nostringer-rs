use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar, SecretKey};
use rand::rngs::OsRng;

// Assuming types and utils are siblings
use crate::types::{scalar_to_hex, KeyPairHex};
use crate::utils::random_non_zero_scalar;

/// The generator point G for the secp256k1 curve
const GENERATOR: ProjectivePoint = ProjectivePoint::GENERATOR;

/// Generates a keypair with private and public keys in hexadecimal format
///
/// # Arguments
/// * `format` - The format for the public key:
///   * "xonly" - X coordinate only (32 bytes), even Y assumed.
///   * "compressed" - Compressed format with prefix (33 bytes)
///   * "uncompressed" - Uncompressed format with prefix (65 bytes)
///
/// # Returns
/// A KeyPairHex with private and public keys in the specified format
pub fn generate_keypair_hex(format: &str) -> KeyPairHex {
    // Generate a random non-zero scalar
    let os_rng = OsRng;
    let secret_scalar_nonzero = random_non_zero_scalar(os_rng);
    let secret_key = SecretKey::from(secret_scalar_nonzero);
    let secret_scalar: Scalar = *secret_scalar_nonzero.as_ref(); // Explicit type annotation
    let private_key_hex = scalar_to_hex(&secret_scalar);

    // Compute the public key
    let public_key = secret_key.public_key();
    let mut point = public_key.to_projective();

    // Format the public key according to the requested format
    let public_key_hex = match format {
        "xonly" => {
            // Ensure Y coordinate is even (x-only format for BIP340 compatibility)
            let affine = point.to_affine();
            let y_is_odd = affine.y_is_odd();

            // If Y is odd, negate the scalar and recompute point to get the even Y variant
            // We return the original private key hex, but the pubkey corresponds to the potentially flipped scalar
            if y_is_odd.into() {
                let flipped_scalar = secret_scalar.negate();
                point = GENERATOR * flipped_scalar;
            }
            let final_affine = point.to_affine();
            hex::encode(final_affine.x().as_slice())
        }
        // Standard SEC1 formats
        "uncompressed" => hex::encode(point.to_encoded_point(false).as_bytes()),
        "compressed" => hex::encode(point.to_encoded_point(true).as_bytes()),
        // Default to compressed format
        _ => hex::encode(point.to_encoded_point(true).as_bytes()),
    };

    KeyPairHex {
        private_key_hex,
        public_key_hex,
    }
}

/// Generates multiple keypairs in the specified format
///
/// # Arguments
/// * `count` - The number of keypairs to generate
/// * `format` - The format for the public keys (see `generate_keypair_hex`)
///
/// # Returns
/// A vector of KeyPairHex structures
pub fn generate_keypairs(count: usize, format: &str) -> Vec<KeyPairHex> {
    (0..count).map(|_| generate_keypair_hex(format)).collect()
}

/// Extracts the public keys from a slice of keypairs
///
/// # Arguments
/// * `keypairs` - A slice of KeyPairHex structures
///
/// # Returns
/// A vector containing only the public keys as strings
pub fn get_public_keys(keypairs: &[KeyPairHex]) -> Vec<String> {
    keypairs
        .iter()
        .map(|kp| kp.public_key_hex.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*; // Import items from parent module (keys.rs)
    use crate::types::hex_to_scalar;
    use crate::utils::hex_to_point;
    use k256::ProjectivePoint;

    #[test]
    fn test_generate_keypair_hex_formats() {
        // Compressed
        let kp_comp = generate_keypair_hex("compressed");
        assert_eq!(kp_comp.private_key_hex.len(), 64);
        assert_eq!(kp_comp.public_key_hex.len(), 66);
        assert!(
            kp_comp.public_key_hex.starts_with("02") || kp_comp.public_key_hex.starts_with("03")
        );
        // Verify keys match
        let sk = hex_to_scalar(&kp_comp.private_key_hex).unwrap();
        let pk = hex_to_point(&kp_comp.public_key_hex).unwrap();
        assert_eq!(ProjectivePoint::GENERATOR * sk, pk);

        // Uncompressed
        let kp_uncomp = generate_keypair_hex("uncompressed");
        assert_eq!(kp_uncomp.private_key_hex.len(), 64);
        assert_eq!(kp_uncomp.public_key_hex.len(), 130);
        assert!(kp_uncomp.public_key_hex.starts_with("04"));
        let sk = hex_to_scalar(&kp_uncomp.private_key_hex).unwrap();
        let pk = hex_to_point(&kp_uncomp.public_key_hex).unwrap();
        assert_eq!(ProjectivePoint::GENERATOR * sk, pk);

        // XOnly
        let kp_xonly = generate_keypair_hex("xonly");
        assert_eq!(kp_xonly.private_key_hex.len(), 64);
        assert_eq!(kp_xonly.public_key_hex.len(), 64);
        let pk = hex_to_point(&kp_xonly.public_key_hex).unwrap(); // hex_to_point assumes even Y for 64 len

        // If original Y was odd, generate_keypair_hex flips the scalar internally
        // So, the point derived from the *returned* public key should always have even Y
        assert!(
            !bool::from(pk.to_affine().y_is_odd()),
            "xonly pubkey should correspond to even Y"
        );

        // Invalid format (defaults to compressed)
        let kp_invalid = generate_keypair_hex("invalid");
        assert_eq!(kp_invalid.public_key_hex.len(), 66);
        assert!(
            kp_invalid.public_key_hex.starts_with("02")
                || kp_invalid.public_key_hex.starts_with("03")
        );
    }

    #[test]
    fn test_generate_keypairs() {
        let count = 5;
        let keypairs = generate_keypairs(count, "xonly");
        assert_eq!(keypairs.len(), count);
        for kp in keypairs {
            assert_eq!(kp.private_key_hex.len(), 64);
            assert_eq!(kp.public_key_hex.len(), 64);
        }
    }

    #[test]
    fn test_get_public_keys() {
        let keypairs = generate_keypairs(3, "compressed");
        let pubkeys = get_public_keys(&keypairs);
        assert_eq!(pubkeys.len(), 3);
        assert_eq!(pubkeys[0], keypairs[0].public_key_hex);
        assert_eq!(pubkeys[1], keypairs[1].public_key_hex);
        assert_eq!(pubkeys[2], keypairs[2].public_key_hex);
    }
}
