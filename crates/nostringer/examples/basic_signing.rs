use nostringer::{generate_keypair_hex, sign, types::Error, verify, SignatureVariant};

fn main() -> Result<(), Error> {
    // Generate three keypairs for our example
    let keypair1 = generate_keypair_hex("xonly");
    let keypair2 = generate_keypair_hex("xonly");
    let keypair3 = generate_keypair_hex("xonly");

    println!("Generated 3 keypairs for the ring:");
    println!("1: {}", keypair1.public_key_hex);
    println!("2: {}", keypair2.public_key_hex);
    println!("3: {}", keypair3.public_key_hex);

    // Create a ring of public keys
    let ring_pubkeys_hex = vec![
        keypair1.public_key_hex.clone(),
        keypair2.public_key_hex.clone(), // keypair2 will be our signer
        keypair3.public_key_hex.clone(),
    ];

    // The message we want to sign
    let message = b"This is a message signed by one of the ring members.";
    println!(
        "\nMessage to sign: \"{}\"",
        String::from_utf8_lossy(message)
    );

    // Sign the message using keypair2's private key with SAG variant
    println!("\nSigning message using keypair2 (using SAG variant)...");
    let compact_signature = sign(
        message,
        &keypair2.private_key_hex,
        &ring_pubkeys_hex,
        SignatureVariant::Sag,
    )?;

    // Print the compact signature
    println!("\nGenerated compact signature:");
    println!("{}", compact_signature);

    // Verify the signature
    println!("\nVerifying signature...");
    let is_valid = verify(&compact_signature, message, &ring_pubkeys_hex)?;

    println!("Signature valid: {}", is_valid);
    assert!(is_valid);

    // Create a BLSAG signature for comparison
    println!("\nCreating a BLSAG signature for comparison...");
    let blsag_signature = sign(
        message,
        &keypair2.private_key_hex,
        &ring_pubkeys_hex,
        SignatureVariant::Blsag,
    )?;

    println!("BLSAG signature:");
    println!("{}", blsag_signature);

    // Verify the BLSAG signature
    println!("\nVerifying BLSAG signature...");
    let is_blsag_valid = verify(&blsag_signature, message, &ring_pubkeys_hex)?;
    println!("BLSAG signature valid: {}", is_blsag_valid);
    assert!(is_blsag_valid);

    // Try to verify with a different message
    let different_message = b"This is a different message that wasn't signed.";
    println!("\nVerifying with a different message...");
    let is_different_valid = verify(&compact_signature, different_message, &ring_pubkeys_hex)?;

    println!(
        "Different message signature valid: {} (expected: false)",
        is_different_valid
    );
    assert!(!is_different_valid);

    println!("\nExample completed successfully!");
    Ok(())
}
