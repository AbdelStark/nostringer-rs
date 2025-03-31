use nostringer::{
    keys::generate_keypair_hex,
    sign_compact_blsag,
    sign_compact_sag,
    verify_compact,
    CompactSignature, // Re-exported from serialization
};

fn main() -> Result<(), nostringer::Error> {
    println!("=== Nostringer Compact Signatures Example ===\n");

    // ===== Generate keys =====
    println!("Creating a ring of 3 keypairs...");
    let keypair1 = generate_keypair_hex("xonly"); // The first ring member
    let keypair2 = generate_keypair_hex("xonly"); // Will be our signer
    let keypair3 = generate_keypair_hex("xonly"); // The third ring member

    // Create a ring from the public keys
    let ring_pubkeys_hex = vec![
        keypair1.public_key_hex.clone(),
        keypair2.public_key_hex.clone(),
        keypair3.public_key_hex.clone(),
    ];

    println!("Ring pubkeys:");
    for (i, pubkey) in ring_pubkeys_hex.iter().enumerate() {
        println!("  {}: {:.10}...", i + 1, pubkey);
    }
    println!();

    // ===== SAG (Unlinkable Ring Signature) =====
    println!("\n=== SAG (Unlinkable) Compact Signature ===");
    let message = b"This is a test message for SAG signature";

    // Sign with the compact API
    println!("Signing message: \"{}\"", String::from_utf8_lossy(message));
    let compact_sig_sag = sign_compact_sag(
        message,
        &keypair2.private_key_hex, // keypair2 is our signer
        &ring_pubkeys_hex,
    )?;

    // Display the compact signature
    println!("Compact SAG signature (ringA format):");
    println!("{}", compact_sig_sag);

    // Verify the SAG signature
    let is_valid = verify_compact(&compact_sig_sag, message, &ring_pubkeys_hex)?;
    println!("Signature valid: {}", is_valid);

    // Verify with a tampered message
    let tampered_message = b"This is a TAMPERED message!";
    let is_valid_tampered = verify_compact(&compact_sig_sag, tampered_message, &ring_pubkeys_hex)?;
    println!(
        "Signature valid with tampered message: {}",
        is_valid_tampered
    );
    assert!(
        !is_valid_tampered,
        "Signature validation should fail with tampered message"
    );

    // ===== BLSAG (Linkable Ring Signature) =====
    println!("\n=== BLSAG (Linkable) Compact Signature ===");
    let message2 = b"This is a test message for BLSAG signature";

    // Sign with the compact BLSAG API
    println!("Signing message: \"{}\"", String::from_utf8_lossy(message2));
    let compact_sig_blsag = sign_compact_blsag(
        message2,
        &keypair2.private_key_hex, // Same signer as before
        &ring_pubkeys_hex,
    )?;

    // Display the compact signature
    println!("Compact BLSAG signature (ringA format):");
    println!("{}", compact_sig_blsag);

    // Verify the BLSAG signature
    let is_valid_blsag = verify_compact(&compact_sig_blsag, message2, &ring_pubkeys_hex)?;
    println!("Signature valid: {}", is_valid_blsag);

    // Manually deserialize to show variant and internal information
    println!("\n=== Understanding Compact Signatures ===");

    // Let's deserialize both signatures to examine their contents
    let deserialized_sag = CompactSignature::deserialize(&compact_sig_sag)
        .map_err(|e| nostringer::Error::Serialization(e.to_string()))?;

    let deserialized_blsag = CompactSignature::deserialize(&compact_sig_blsag)
        .map_err(|e| nostringer::Error::Serialization(e.to_string()))?;

    println!("SAG signature variant: {}", deserialized_sag.variant());
    println!("BLSAG signature variant: {}", deserialized_blsag.variant());

    // Show size difference
    println!("\nSignature size comparison:");
    println!("SAG size: {} bytes", compact_sig_sag.len());
    println!("BLSAG size: {} bytes", compact_sig_blsag.len());

    // BLSAG contains key image which adds size but enables linkability

    println!("\nSuccessfully demonstrated compact signatures!");
    Ok(())
}
