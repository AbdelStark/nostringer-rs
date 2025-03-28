use nostringer::{Error, generate_keypair_hex, sign, verify};

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

    // Sign the message using keypair2's private key
    println!("\nSigning message using keypair2...");
    let signature = sign(message, &keypair2.private_key_hex, &ring_pubkeys_hex)?;

    // Print the signature
    println!("\nGenerated signature:");
    println!("c0: {}", signature.c0);
    println!("s values:");
    for (i, s) in signature.s.iter().enumerate() {
        println!("  s[{}]: {}", i, s);
    }

    // Verify the signature
    println!("\nVerifying signature...");
    let is_valid = verify(&signature, message, &ring_pubkeys_hex)?;

    println!("Signature valid: {}", is_valid);
    assert!(is_valid);

    // Try to verify with a different message
    let different_message = b"This is a different message that wasn't signed.";
    println!("\nVerifying with a different message...");
    let is_different_valid = verify(&signature, different_message, &ring_pubkeys_hex)?;

    println!(
        "Different message signature valid: {} (expected: false)",
        is_different_valid
    );
    assert!(!is_different_valid);

    println!("\nExample completed successfully!");
    Ok(())
}
