use k256::elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint, Group};
use k256::{NonZeroScalar, ProjectivePoint, PublicKey, Scalar, U256};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use subtle::{ConditionallySelectable, ConstantTimeEq};

use crate::types::{hex_to_scalar, BlsagSignature, BlsagSignatureBinary, Error, KeyImage};
use crate::utils::{hex_to_point, random_non_zero_scalar};

/// The generator point G for the secp256k1 curve
const GENERATOR: ProjectivePoint = ProjectivePoint::GENERATOR;

// --- Hex API ---

/// Creates a bLSAG signature (linkable) using hex inputs.
///
/// Returns the hex-encoded signature and the hex-encoded key image.
pub fn sign_blsag_hex(
    message: &[u8],
    private_key_hex: &str,
    ring_pubkeys_hex: &[String],
) -> Result<(BlsagSignature, String), Error> {
    let private_key = hex_to_scalar(private_key_hex)?;
    let ring_pubkeys: Vec<ProjectivePoint> = ring_pubkeys_hex
        .iter()
        .map(|s| hex_to_point(s))
        .collect::<Result<Vec<_>, _>>()?;

    let (binary_sig, key_image) = sign_blsag_binary(message, &private_key, &ring_pubkeys)?;

    Ok((BlsagSignature::from(&binary_sig), key_image.to_hex()))
}

/// Verifies a bLSAG signature (linkable) using hex inputs.
pub fn verify_blsag_hex(
    signature_hex: &BlsagSignature,
    key_image_hex: &str,
    message: &[u8],
    ring_pubkeys_hex: &[String],
) -> Result<bool, Error> {
    let binary_sig = BlsagSignatureBinary::try_from(signature_hex)?;
    let key_image = KeyImage::from_hex(key_image_hex)?;
    let ring_pubkeys: Vec<ProjectivePoint> = ring_pubkeys_hex
        .iter()
        .map(|s| hex_to_point(s))
        .collect::<Result<Vec<_>, _>>()?;

    verify_blsag_binary(&binary_sig, &key_image, message, &ring_pubkeys)
}

// --- Binary API ---

/// Creates a bLSAG signature (linkable) using binary inputs.
///
/// Returns the signature and the key image. The key image can be used to detect
/// if the same private key signed multiple messages.
///
/// # Arguments
/// * `message` - The message bytes (`&[u8]`) to sign.
/// * `private_key` - The signer's private key as a `Scalar`.
/// * `ring_pubkeys` - A slice of `ProjectivePoint` representing the ring members.
///
/// # Returns
/// * `Ok((BlsagSignatureBinary, KeyImage))` - The binary signature and the key image.
/// * `Err(Error)` - If signing fails.
pub fn sign_blsag_binary(
    message: &[u8],
    private_key: &Scalar,
    ring_pubkeys: &[ProjectivePoint],
) -> Result<(BlsagSignatureBinary, KeyImage), Error> {
    let ring_size = ring_pubkeys.len();
    if ring_size < 2 {
        return Err(Error::RingTooSmall(ring_size));
    }
    if *private_key == Scalar::ZERO {
        return Err(Error::PrivateKeyFormat(
            "Private key scalar cannot be zero".into(),
        ));
    }

    let d = *private_key;
    let _d_nonzero = NonZeroScalar::new(d).expect("d checked non-zero");

    // Find signer index and key variant used
    let my_point = GENERATOR * d;
    let flipped_d = d.negate();
    let flipped_point = GENERATOR * flipped_d;
    let mut signer_index: Option<usize> = None;
    let mut used_d = d; // The actual scalar corresponding to the pubkey found in the ring

    for (i, p) in ring_pubkeys.iter().enumerate() {
        if p == &my_point {
            signer_index = Some(i);
            used_d = d;
            break;
        }
        if p == &flipped_point {
            signer_index = Some(i);
            used_d = flipped_d;
            break;
        }
    }
    let signer_index = signer_index.ok_or(Error::SignerNotInRing)?;
    let p_signer = &ring_pubkeys[signer_index]; // Signer's public key point in the ring

    // --- bLSAG Specific ---
    // 1. Calculate Key Image
    let hp_p_signer = hash_to_point(p_signer)?;
    let key_image_point = hp_p_signer * used_d; // I = used_d * Hp(P_signer)
    let key_image = KeyImage(key_image_point);

    // --- Standard Ring Calculation (adapted for bLSAG hashing) ---
    let mut r_scalars = vec![Scalar::ZERO; ring_size]; // Responses 's'
    let mut c_scalars = vec![Scalar::ZERO; ring_size]; // Challenges 'c'
    let os_rng = OsRng;

    let alpha_nonzero = random_non_zero_scalar(os_rng);
    let alpha = *alpha_nonzero.as_ref();

    // Calculate initial commitments L0, L1 for challenge hash
    let l0_start = GENERATOR * alpha;
    let l1_start = hp_p_signer * alpha; // Use signer's hashed pubkey

    // Calculate initial challenge c[start_index]
    let start_index = (signer_index + 1) % ring_size;
    c_scalars[start_index] = hash_for_blsag_challenge(message, &l0_start, &l1_start)?;

    // Iterate through non-signers
    let mut current_index = start_index;
    while current_index != signer_index {
        let r_nonzero = random_non_zero_scalar(os_rng);
        r_scalars[current_index] = *r_nonzero.as_ref();

        let p_i = &ring_pubkeys[current_index];
        let hp_p_i = hash_to_point(p_i)?;

        // Calculate commitments L0, L1 for this index's challenge hash
        // Li0 = r_i * G + c_i * P_i
        let li0 = (GENERATOR * r_scalars[current_index]) + (*p_i * c_scalars[current_index]);
        // Li1 = r_i * Hp(P_i) + c_i * I
        let li1 =
            (hp_p_i * r_scalars[current_index]) + (key_image_point * c_scalars[current_index]);

        // Calculate next challenge
        let next_index = (current_index + 1) % ring_size;
        c_scalars[next_index] = hash_for_blsag_challenge(message, &li0, &li1)?;

        current_index = next_index;
    }

    // Calculate signer's response
    r_scalars[signer_index] = alpha - (c_scalars[signer_index] * used_d);

    // Construct signature
    let signature = BlsagSignatureBinary {
        c0: c_scalars[0],
        s: r_scalars,
    };

    Ok((signature, key_image))
}

/// Verifies a bLSAG signature (linkable) using binary inputs.
///
/// Checks the signature validity and that the key image is valid.
///
/// # Arguments
/// * `signature` - The binary `BlsagSignatureBinary` to verify.
/// * `key_image` - The `KeyImage` associated with the signature.
/// * `message` - The message bytes (`&[u8]`).
/// * `ring_pubkeys` - A slice of `ProjectivePoint` representing the ring.
///
/// # Returns
/// * `Ok(bool)` - `true` if the signature and key image are valid, `false` otherwise.
/// * `Err(Error)` - If verification fails due to errors.
pub fn verify_blsag_binary(
    signature: &BlsagSignatureBinary,
    key_image: &KeyImage,
    message: &[u8],
    ring_pubkeys: &[ProjectivePoint],
) -> Result<bool, Error> {
    let ring_size = ring_pubkeys.len();
    if ring_size == 0 {
        return Ok(false);
    } // Ring cannot be empty
    if signature.s.len() != ring_size {
        return Err(Error::InvalidSignatureFormat);
    }

    let key_image_point = key_image.as_point();

    // --- bLSAG Specific ---
    // 1. Validate Key Image
    // Check it's not identity
    if key_image_point.is_identity().into() {
        return Ok(false);
    }
    // Check it's in the prime-order subgroup (torsion-free)
    // TODO: Re-enable this check once k256 v0.14 is potentially released with this fix
    // or find a workaround.
    // Current k256 doesn't expose is_torsion_free directly on ProjectivePoint.
    // We might need to convert to Affine and check there, or wait for library updates.
    // if !(*key_image_point).is_torsion_free() {
    //     return Ok(false);
    // }

    // --- Standard Ring Verification (adapted for bLSAG hashing) ---
    let c0_scalar = signature.c0;
    let r_scalars = &signature.s;
    // Temporary array to store recalculated challenges
    let mut c_recalculated = vec![Scalar::ZERO; ring_size];

    // Start loop with c = c0
    let mut current_c = c0_scalar;

    for i in 0..ring_size {
        let p_i = &ring_pubkeys[i];
        let hp_p_i = hash_to_point(p_i)?;

        // Recalculate L0, L1 for this index
        // Li0 = r_i * G + c_i * P_i
        let li0 = (GENERATOR * r_scalars[i]) + (*p_i * current_c);
        // Li1 = r_i * Hp(P_i) + c_i * I
        let li1 = (hp_p_i * r_scalars[i]) + (*key_image_point * current_c);

        // Calculate the next challenge based on recalculated L0, L1
        let next_c = hash_for_blsag_challenge(message, &li0, &li1)?;

        // Store it for the check *after* the loop finishes,
        // and use it as input for the *next* iteration.
        let next_index = (i + 1) % ring_size;
        if next_index == 0 {
            // Store the final calculation which should match c0
            c_recalculated[0] = next_c;
        } else {
            // Store intermediate challenges if needed for debugging
            // c_recalculated[next_index] = next_c;
        }
        current_c = next_c; // Use newly calculated c for the next iteration
    }

    // Final Check: Does the recalculated c0 match the original?
    // We compare the final `current_c` value after the loop with the input `c0_scalar`.
    let is_valid = current_c.ct_eq(&c0_scalar);

    Ok(is_valid.into())
}

/// Compares two KeyImages for equality.
/// If two different valid bLSAG signatures have the same KeyImage,
/// they were produced by the same private key.
pub fn key_images_match(image1: &KeyImage, image2: &KeyImage) -> bool {
    image1 == image2 // Relies on PartialEq derived for KeyImage
}

// --- Hashing ---

/// Hashes a public key point to another point on the curve (`Hp` function).
/// Uses SHA-256 and try-and-increment to find a valid point.
fn hash_to_point(pubkey: &ProjectivePoint) -> Result<ProjectivePoint, Error> {
    if pubkey.is_identity().into() {
        // Hashing the identity point is usually undefined or undesirable
        return Err(Error::PublicKeyFormat("Cannot hash identity point".into()));
    }
    let compressed_pubkey = pubkey.to_encoded_point(true); // 33 bytes
    let mut hasher = Sha256::new();
    hasher.update(compressed_pubkey.as_bytes());
    // Use a domain separator for hashing to a point vs hashing for challenges
    hasher.update(b"NostringerHp"); // Simple domain separation
    let mut hash = hasher.finalize(); // GenericArray<u8, 32>

    let mut counter: u32 = 0;
    // Limit attempts to prevent potential infinite loops in edge cases
    const MAX_TRIES: u32 = 1000;

    loop {
        if counter >= MAX_TRIES {
            return Err(Error::HashingError(format!(
                "Failed to hash to point after {} tries",
                MAX_TRIES
            )));
        }

        // Treat hash as x-coordinate candidate
        let mut potential_point_bytes = [0u8; 33];
        potential_point_bytes[1..].copy_from_slice(&hash);

        // Try even Y (0x02 prefix)
        potential_point_bytes[0] = 0x02;
        if let Ok(pk) = PublicKey::from_sec1_bytes(&potential_point_bytes) {
            // Check if the resulting point is identity (should be avoided)
            let point = pk.to_projective();
            if !bool::from(point.is_identity()) {
                return Ok(point);
            }
        }

        // Try odd Y (0x03 prefix)
        potential_point_bytes[0] = 0x03;
        if let Ok(pk) = PublicKey::from_sec1_bytes(&potential_point_bytes) {
            // Check if the resulting point is identity
            let point = pk.to_projective();
            if !bool::from(point.is_identity()) {
                return Ok(point);
            }
        }

        // If both failed or resulted in identity, update hash: hash = SHA256(hash || counter)
        let mut rehasher = Sha256::new();
        rehasher.update(hash);
        rehasher.update(counter.to_be_bytes());
        hash = rehasher.finalize();
        counter += 1;
    }
}

/// Hashes message and two points to create a bLSAG challenge scalar.
/// H = SHA256(domain_sep || msg || compressed_p1 || compressed_p2)
fn hash_for_blsag_challenge(
    message: &[u8],
    p1: &ProjectivePoint,
    p2: &ProjectivePoint,
) -> Result<Scalar, Error> {
    let mut hasher = Sha256::new();
    // Domain separation from regular SAG hash and Hp hash
    hasher.update(b"NostringerBlsagChallenge");
    hasher.update(message);
    hasher.update(p1.to_encoded_point(true).as_bytes());
    hasher.update(p2.to_encoded_point(true).as_bytes());

    let hash_result = hasher.finalize();
    let hash_uint = U256::from_be_slice(&hash_result);
    let scalar = Scalar::reduce(hash_uint);

    let is_zero = scalar.ct_eq(&Scalar::ZERO);
    Ok(Scalar::conditional_select(&scalar, &Scalar::ONE, is_zero))
}
