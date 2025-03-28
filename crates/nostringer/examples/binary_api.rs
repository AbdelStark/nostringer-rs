use hex;
use k256::{elliptic_curve::PrimeField, ProjectivePoint, PublicKey, Scalar};
use nostringer::{generate_keypair_hex, sign_binary, verify_binary, Error};

fn main() -> Result<(), Error> {
    println!("Demonstrating the optimized binary API for nostringer");

    // Define ring size (larger ring shows more performance difference)
    let ring_size = 20;
    println!("Using a ring size of {} members", ring_size);

    // 1. Setup: Generate keys for ring members
    println!("Generating keypairs...");
    let mut keypairs_hex = Vec::with_capacity(ring_size);
    let mut ring_pubkeys_hex = Vec::with_capacity(ring_size);

    for _ in 0..ring_size {
        let keypair = generate_keypair_hex("xonly");
        ring_pubkeys_hex.push(keypair.public_key_hex.clone());
        keypairs_hex.push(keypair);
    }

    // Select signer as middle member
    let signer_idx = ring_size / 2;

    // 2. Convert to binary format (in a real app, you might already have binary keys)
    println!("Converting to binary format...");
    let private_key_signer = hex_to_scalar(&keypairs_hex[signer_idx].private_key_hex)?;

    let mut ring_pubkeys_binary = Vec::with_capacity(ring_size);
    for keypair in &keypairs_hex {
        let pubkey = hex_to_point(&keypair.public_key_hex)?;
        ring_pubkeys_binary.push(pubkey);
    }

    // 3. Define message to be signed
    let message = b"This message was signed using the optimized binary API";

    // 4. Signer signs message using binary API
    println!("Signing message with binary API...");
    let start = std::time::Instant::now();
    let binary_signature = sign_binary(message, &private_key_signer, &ring_pubkeys_binary)?;
    let binary_sign_time = start.elapsed();

    println!("Binary signature generated in: {:?}", binary_sign_time);

    // 5. Verify the signature using binary API
    println!("\nVerifying signature with binary API...");
    let start = std::time::Instant::now();
    let is_valid = verify_binary(&binary_signature, message, &ring_pubkeys_binary)?;
    let binary_verify_time = start.elapsed();

    println!("Binary verification completed in: {:?}", binary_verify_time);
    println!("Binary signature valid: {}", is_valid);

    // 6. Compare with hex API (using the original APIs)
    compare_with_hex_api(
        message,
        &keypairs_hex[signer_idx],
        &ring_pubkeys_hex,
        binary_sign_time,
        binary_verify_time,
    )?;

    // 7. Tamper test
    println!("\nVerifying with tampered message...");
    let tampered_message = b"This is a different message that should fail verification";
    let is_tampered_valid =
        verify_binary(&binary_signature, tampered_message, &ring_pubkeys_binary)?;
    println!(
        "Tampered signature valid: {} (should be false)",
        is_tampered_valid
    );
    assert!(!is_tampered_valid);

    Ok(())
}

// Helper functions for converting hex strings to binary format
fn hex_to_scalar(hex_str: &str) -> Result<Scalar, Error> {
    // Pad to 64 characters if shorter
    let padded_hex = if hex_str.len() < 64 {
        format!("{:0>64}", hex_str)
    } else {
        hex_str.to_string()
    };

    if padded_hex.len() != 64 {
        return Err(Error::PrivateKeyFormat(format!(
            "Hex len {} != 64",
            padded_hex.len()
        )));
    }

    // Decode hex to bytes
    let bytes = hex::decode(&padded_hex).map_err(|e| Error::HexDecode(e))?;
    let field_bytes = k256::FieldBytes::from_slice(&bytes);

    // Convert bytes to scalar using the PrimeField trait method
    let maybe_scalar = Scalar::from_repr_vartime(*field_bytes);

    if maybe_scalar.is_some().into() {
        Ok(maybe_scalar.unwrap())
    } else {
        Err(Error::InvalidScalarEncoding)
    }
}

fn hex_to_point(pubkey_hex: &str) -> Result<ProjectivePoint, Error> {
    // Normalize hex (remove 0x prefix if present)
    let hex_norm = if pubkey_hex.starts_with("0x") {
        &pubkey_hex[2..]
    } else {
        pubkey_hex
    };

    let point_bytes = match hex_norm.len() {
        // x-coordinate only, assume 02 prefix (even y)
        64 => hex::decode(format!("02{}", hex_norm)).map_err(|e| Error::HexDecode(e))?,

        // Compressed format (02/03 prefix + x-coordinate)
        66 => {
            if !hex_norm.starts_with("02") && !hex_norm.starts_with("03") {
                return Err(Error::PublicKeyFormat(format!(
                    "Invalid prefix: {}",
                    &hex_norm[..2]
                )));
            }
            hex::decode(hex_norm).map_err(|e| Error::HexDecode(e))?
        }

        // Uncompressed format (04 prefix + x-coordinate + y-coordinate)
        130 => {
            if !hex_norm.starts_with("04") {
                return Err(Error::PublicKeyFormat(format!(
                    "Invalid prefix: {}",
                    &hex_norm[..2]
                )));
            }
            hex::decode(hex_norm).map_err(|e| Error::HexDecode(e))?
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

// Function to compare with original hex API
fn compare_with_hex_api(
    message: &[u8],
    signer: &nostringer::KeyPairHex,
    ring_pubkeys: &[String],
    binary_sign_time: std::time::Duration,
    binary_verify_time: std::time::Duration,
) -> Result<(), Error> {
    println!("\nComparing with hex string API:");

    // Measure time for hex API
    let start = std::time::Instant::now();
    let hex_signature = nostringer::sign(message, &signer.private_key_hex, ring_pubkeys)?;
    let hex_sign_time = start.elapsed();

    println!("Hex signature generated in: {:?}", hex_sign_time);

    let start = std::time::Instant::now();
    let is_valid = nostringer::verify(&hex_signature, message, ring_pubkeys)?;
    let hex_verify_time = start.elapsed();

    println!("Hex verification completed in: {:?}", hex_verify_time);
    println!("Hex signature valid: {}", is_valid);

    // Calculate and show performance improvement
    let sign_speedup =
        hex_sign_time.as_micros() as f64 / std::cmp::max(1, binary_sign_time.as_micros()) as f64;

    let verify_speedup = hex_verify_time.as_micros() as f64
        / std::cmp::max(1, binary_verify_time.as_micros()) as f64;

    println!("\n📊 Performance comparison:");
    println!(
        "→ Signing: Binary API is {:.2}x faster than hex API",
        sign_speedup
    );
    println!(
        "→ Verification: Binary API is {:.2}x faster than hex API",
        verify_speedup
    );

    Ok(())
}
