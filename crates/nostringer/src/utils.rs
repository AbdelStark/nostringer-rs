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
