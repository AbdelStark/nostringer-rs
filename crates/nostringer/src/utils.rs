use k256::elliptic_curve::PrimeField;
use k256::{NonZeroScalar, ProjectivePoint, PublicKey, Scalar};
use nostr::prelude::FromBech32;
use rand::{CryptoRng, RngCore};

use crate::types::{normalize_hex, Error};

/// Converts a hexadecimal public key string to a curve point
///
/// Supports multiple formats:
/// - 64 hex chars: x-coordinate only (xonly)
/// - 66 hex chars: compressed format (02/03 prefix + x-coordinate)
/// - 130 hex chars: uncompressed format (04 prefix + x-coordinate + y-coordinate)
///
/// # Arguments
/// * `pubkey_hex` - The public key as a hex string
///
/// # Returns
/// * `Ok(ProjectivePoint)` - The public key as a curve point
/// * `Err(Error)` - If the format is invalid or the point is not on the curve
///
/// # Errors
/// Returns an error if:
/// * The hex string length is invalid
/// * The format prefix is invalid
/// * The point is not on the curve
pub fn hex_to_point(pubkey_hex: &str) -> Result<ProjectivePoint, Error> {
    let hex_norm = normalize_hex(pubkey_hex)?;
    let point_bytes = match hex_norm.len() {
        // x-coordinate only, assume 02 prefix (even y)
        64 => hex::decode(format!("02{}", hex_norm))?,

        // Compressed format (02/03 prefix + x-coordinate)
        66 => {
            if !hex_norm.starts_with("02") && !hex_norm.starts_with("03") {
                return Err(Error::PublicKeyFormat(format!(
                    "Invalid prefix: {}",
                    &hex_norm[..2]
                )));
            }
            hex::decode(&hex_norm)?
        }

        // Uncompressed format (04 prefix + x-coordinate + y-coordinate)
        130 => {
            if !hex_norm.starts_with("04") {
                return Err(Error::PublicKeyFormat(format!(
                    "Invalid prefix: {}",
                    &hex_norm[..2]
                )));
            }
            hex::decode(&hex_norm)?
        }

        // Invalid length
        _ => {
            return Err(Error::PublicKeyFormat(format!(
                "Invalid length: {}",
                hex_norm.len()
            )));
        }
    };

    // Parse the SEC1 formatted bytes to a public key
    let public_key = PublicKey::from_sec1_bytes(&point_bytes)
        .map_err(|e| Error::PublicKeyFormat(format!("SEC1 parse error: {}", e)))?;

    // Convert to projective representation
    Ok(public_key.to_projective())
}

/// Generates a non-zero random scalar using the provided random number generator
///
/// # Arguments
/// * `rng` - A cryptographically secure random number generator
///
/// # Returns
/// A non-zero scalar value from the Secp256k1 field
pub fn random_non_zero_scalar(mut rng: impl RngCore + CryptoRng) -> NonZeroScalar {
    NonZeroScalar::random(&mut rng)
}

/// Parses a secret key string (nsec or hex) into a k256 Scalar.
///
/// # Arguments
/// * `key_input` - The secret key string (nsec1... or hex format).
///
/// # Returns
/// * `Ok(Scalar)` - The secret key as a scalar.
/// * `Err(Error)` - If parsing fails.
pub fn parse_secret_key(key_input: &str) -> Result<Scalar, Error> {
    if key_input.starts_with("nsec1") {
        let sk = nostr::SecretKey::from_bech32(key_input)
            .map_err(|e| Error::SecretKeyFormat(format!("Bech32 parse error: {}", e)))?;
        // Convert [u8; 32] -> FieldBytes -> Option<Scalar>
        let field_bytes = k256::FieldBytes::from(sk.to_secret_bytes());
        let maybe_scalar = Scalar::from_repr_vartime(field_bytes);
        if let Some(scalar) = maybe_scalar {
            Ok(scalar)
        } else {
            // This case should be rare for valid keys but handles potential edge cases
            Err(Error::InvalidScalarEncoding)
        }
    } else {
        // Fallback to hex parsing
        crate::types::hex_to_scalar(key_input)
    }
}

/// Parses a public key string (npub or hex) into a k256 ProjectivePoint.
///
/// # Arguments
/// * `key_input` - The public key string (npub1... or hex format).
///
/// # Returns
/// * `Ok(ProjectivePoint)` - The public key as a curve point.
/// * `Err(Error)` - If parsing fails.
pub fn parse_public_key(key_input: &str) -> Result<ProjectivePoint, Error> {
    if key_input.starts_with("npub1") {
        let pk = nostr::PublicKey::from_bech32(key_input)
            .map_err(|e| Error::PublicKeyFormat(format!("Bech32 parse error: {}", e)))?;
        // nostr::PublicKey stores the x-only key. We need the full ProjectivePoint.
        // k256::PublicKey::from_x_only cannot recover the full point reliably without context.
        // Let's convert nostr::PublicKey -> hex -> k256::PublicKey -> ProjectivePoint
        let hex_pk = pk.to_hex();
        hex_to_point(&hex_pk) // Use existing hex parser which handles xonly/compressed/uncompressed
    } else {
        // Fallback to hex parsing
        hex_to_point(key_input)
    }
}

#[cfg(test)]
mod tests {
    use super::*; // Import items from parent module (utils.rs)
    use k256::elliptic_curve::sec1::ToEncodedPoint; // Import trait for to_encoded_point
    use k256::SecretKey;
    use nostr::prelude::{Keys, ToBech32};

    #[test]
    fn test_parse_secret_key_valid() -> Result<(), Error> {
        // Generate keys using nostr
        let keys = Keys::generate();
        let nsec = keys.secret_key().to_bech32().unwrap();
        let hex_sk = keys.secret_key().to_secret_hex();

        // Expected k256::Scalar
        let expected_scalar =
            Scalar::from_repr_vartime(k256::FieldBytes::from(keys.secret_key().to_secret_bytes()))
                .unwrap();

        // Test nsec
        let scalar_from_nsec = parse_secret_key(&nsec)?;
        assert_eq!(scalar_from_nsec, expected_scalar, "Parsing nsec failed");

        // Test hex
        let scalar_from_hex = parse_secret_key(&hex_sk)?;
        assert_eq!(
            scalar_from_hex, expected_scalar,
            "Parsing hex secret key failed"
        );

        Ok(())
    }

    #[test]
    fn test_parse_secret_key_invalid() {
        // Invalid nsec prefix (doesn't start with nsec1) - Falls back to hex parsing, fails HexDecode
        assert!(
            matches!(parse_secret_key("nsec2..."), Err(Error::HexDecode(_))),
            "Incorrect error for invalid nsec prefix (should be HexDecode)"
        );
        // Invalid nsec checksum/format
        assert!(
            matches!(
                parse_secret_key("nsec1qwertyuiopasdfghjklzxcvbnm1234567890abcdefgh"),
                Err(Error::SecretKeyFormat(_))
            ),
            "Incorrect error for invalid nsec format"
        );
        // Invalid hex length (too short) - Falls back to hex_to_scalar, gets padded, should succeed
        assert!(
            parse_secret_key("deadbeef").is_ok(),
            "Short valid hex ('deadbeef') should succeed after padding"
        );
        // Invalid hex characters
        assert!(
            matches!(
                parse_secret_key(
                    "gggga6e49bdb6829e72ab7332de72cd6756c10e40eec0a202797a6e3c399a27b"
                ),
                Err(Error::HexDecode(_))
            ),
            "Incorrect error for invalid hex chars"
        );
    }

    #[test]
    fn test_parse_public_key_valid() -> Result<(), Error> {
        // Generate keys using nostr
        let keys = Keys::generate();
        let npub = keys.public_key().to_bech32().unwrap();
        let hex_pk_xonly = keys.public_key().to_hex(); // xonly format used by nostr

        // Expected k256::ProjectivePoint derived consistently with the parse_public_key logic
        // i.e., start from the xonly hex representation
        let expected_point = hex_to_point(&hex_pk_xonly)?;

        // Test npub -> parse_public_key
        let point_from_npub = parse_public_key(&npub)?;
        assert_eq!(
            point_from_npub, expected_point,
            "Parsing npub resulted in unexpected point"
        );

        // Test hex (xonly) -> parse_public_key
        let point_from_hex = parse_public_key(&hex_pk_xonly)?;
        assert_eq!(
            point_from_hex, expected_point,
            "Parsing hex public key (xonly) failed"
        );

        // Test hex (compressed) -> parse_public_key
        let k256_sk =
            SecretKey::from_bytes(&k256::FieldBytes::from(keys.secret_key().to_secret_bytes()))?;
        let full_point = k256_sk.public_key().to_projective(); // Get the potentially non-even Y point
        let hex_pk_compressed = hex::encode(full_point.to_encoded_point(true).as_bytes());
        let point_from_compressed = parse_public_key(&hex_pk_compressed)?;
        // Comparing with the full_point here is correct because hex_to_point handles compressed format correctly
        assert_eq!(
            point_from_compressed, full_point,
            "Parsing hex public key (compressed) failed"
        );

        // Test hex (uncompressed) -> parse_public_key
        let hex_pk_uncompressed = hex::encode(full_point.to_encoded_point(false).as_bytes());
        let point_from_uncompressed = parse_public_key(&hex_pk_uncompressed)?;
        assert_eq!(
            point_from_uncompressed, full_point,
            "Parsing hex public key (uncompressed) failed"
        );

        Ok(())
    }

    #[test]
    fn test_parse_public_key_invalid() {
        // Invalid npub prefix (doesn't start with npub1) - Falls back to hex parsing, fails HexDecode
        assert!(
            matches!(parse_public_key("npub2..."), Err(Error::HexDecode(_))),
            "Incorrect error for invalid npub prefix (should be HexDecode)"
        );
        // Invalid npub checksum/format
        assert!(
            matches!(
                parse_public_key("npub1qwertyuiopasdfghjklzxcvbnm1234567890abcdefgh"),
                Err(Error::PublicKeyFormat(_))
            ),
            "Incorrect error for invalid npub format"
        );
        // Invalid hex length (neither 64, 66, nor 130)
        assert!(
            matches!(parse_public_key("deadbeef"), Err(Error::PublicKeyFormat(_))),
            "Incorrect error for invalid hex length"
        );
        // Invalid hex characters
        assert!(
            matches!(
                parse_public_key(
                    "gggga6e49bdb6829e72ab7332de72cd6756c10e40eec0a202797a6e3c399a27b"
                ),
                Err(Error::HexDecode(_))
            ),
            "Incorrect error for invalid hex chars"
        );
        // Invalid hex prefix (not 02, 03, or 04 for compressed/uncompressed)
        assert!(
            matches!(
                parse_public_key("05a6e49bdb6829e72ab7332de72cd6756c10e40eec0a202797a6e3c399a27b"),
                Err(Error::PublicKeyFormat(_))
            ),
            "Incorrect error for invalid hex prefix"
        );
    }
}
