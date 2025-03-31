use nostringer::{
    keys::generate_keypair_hex, sag, sign_compact_sag, verify_compact, CompactSignature, Error,
    RingSignature, RingSignatureBinary,
};

fn main() -> Result<(), nostringer::Error> {
    println!("=== Format Conversion Between Hex and Compact Signatures ===\n");

    // Generate keys for a ring
    println!("Creating ring keys...");
    let keypair1 = generate_keypair_hex("xonly");
    let keypair2 = generate_keypair_hex("xonly"); // Our signer
    let keypair3 = generate_keypair_hex("xonly");

    let ring_pubkeys_hex = vec![
        keypair1.public_key_hex.clone(),
        keypair2.public_key_hex.clone(),
        keypair3.public_key_hex.clone(),
    ];

    let message = b"Message to sign with different formats";
    println!("Message: \"{}\"", String::from_utf8_lossy(message));

    // ===== Method 1: Original Hex Format =====
    println!("\n== Method 1: Original Hex Format ==");

    // Sign using the original hex API
    let hex_signature = sag::sign(message, &keypair2.private_key_hex, &ring_pubkeys_hex)?;

    println!("Original hex signature:");
    println!("c0: {}", hex_signature.c0);
    println!("s[0]: {}", hex_signature.s[0]);
    println!("...");
    println!(
        "Size: {} bytes (total of all hex strings)",
        hex_signature.c0.len() + hex_signature.s.iter().map(|s| s.len()).sum::<usize>()
    );

    // ===== Method 2: Compact Format =====
    println!("\n== Method 2: Compact Format ==");

    // Sign using the compact API
    let compact_signature =
        sign_compact_sag(message, &keypair2.private_key_hex, &ring_pubkeys_hex)?;

    println!("Compact signature:");
    println!("{}", compact_signature);
    println!("Size: {} bytes", compact_signature.len());

    // ===== Converting Between Formats =====
    println!("\n== Converting Between Formats ==");

    // 1. Hex Format -> Binary Format -> Compact Format
    println!("Original Hex -> Binary -> Compact:");

    // First convert hex to binary
    let binary_sig = RingSignatureBinary::try_from(&hex_signature)?;

    // Then wrap in CompactSignature and serialize
    let compact_from_hex = CompactSignature::Sag(binary_sig)
        .serialize()
        .map_err(|e| Error::Serialization(e.to_string()))?;

    println!("{}", compact_from_hex);

    // 2. Compact Format -> Binary Format -> Hex Format
    println!("\nCompact -> Binary -> Hex:");

    // First deserialize compact to binary
    let deserialized = CompactSignature::deserialize(&compact_signature)
        .map_err(|e| Error::Serialization(e.to_string()))?;

    match deserialized {
        CompactSignature::Sag(binary_sig) => {
            // Then convert binary to hex
            let hex_from_compact = RingSignature::from(&binary_sig);

            println!("c0: {}", hex_from_compact.c0);
            println!("s[0]: {}", hex_from_compact.s[0]);
            println!("...");
        }
        CompactSignature::Blsag(_, _) => {
            println!("Unexpected BLSAG signature type");
        }
    }

    // ===== Verify Both Formats =====
    println!("\n== Verifying Both Formats ==");

    // Verify original hex format
    let hex_valid = sag::verify(&hex_signature, message, &ring_pubkeys_hex)?;
    println!("Hex signature valid: {}", hex_valid);

    // Verify compact format
    let compact_valid = verify_compact(&compact_signature, message, &ring_pubkeys_hex)?;
    println!("Compact signature valid: {}", compact_valid);

    // Verify converted formats
    let converted_hex_valid = verify_compact(&compact_from_hex, message, &ring_pubkeys_hex)?;
    println!("Hex->Compact signature valid: {}", converted_hex_valid);

    println!("\nSuccessfully demonstrated format conversion!");
    Ok(())
}
