use crate::types::Error;
use k256::{elliptic_curve::rand_core, NonZeroScalar, ProjectivePoint, PublicKey};

use crate::normalize_hex;

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
pub fn random_non_zero_scalar(
    mut rng: impl rand_core::RngCore + rand_core::CryptoRng,
) -> NonZeroScalar {
    NonZeroScalar::random(&mut rng)
}
