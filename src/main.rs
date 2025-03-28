use nostr::prelude::*;
use nostringer::{Error, generate_keypair_hex, sign, verify};

fn main() -> Result<(), Error> {
    // 1. Setup: Generate keys for the ring members
    // Keys can be x-only, compressed, or uncompressed hex strings
    let keypair1 = generate_keypair_hex("xonly");
    let keypair2 = generate_keypair_hex("compressed");
    let keypair3 = generate_keypair_hex("xonly");

    let ring_pubkeys_hex: Vec<String> = vec![
        keypair1.public_key_hex.clone(),
        keypair2.public_key_hex.clone(), // Signer's key must be included
        keypair3.public_key_hex.clone(),
    ];

    // 2. Define the message to be signed (as bytes)
    let message = b"This is a secret message to the group.";

    // 3. Signer (keypair2) signs the message using their private key
    println!("Signing message...");
    let signature = sign(
        message,
        &keypair2.private_key_hex, // Signer's private key hex
        &ring_pubkeys_hex,         // The full ring of public keys
    )?;

    println!("Generated Signature:");
    println!(" c0: {}", signature.c0);
    println!(" s: {:?}", signature.s);

    // 4. Verification: Anyone can verify the signature against the ring and message
    println!("\nVerifying signature...");
    let is_valid = verify(
        &signature,
        message,
        &ring_pubkeys_hex, // Must use the exact same ring (order matters for hashing)
    )?;

    println!("Signature valid: {}", is_valid);
    assert!(is_valid);

    // 5. Tamper test: Verification should fail if the message changes
    println!("\nVerifying with tampered message...");
    let tampered_message = b"This is a different message.";
    let is_tampered_valid = verify(&signature, tampered_message, &ring_pubkeys_hex)?;
    println!("Tampered signature valid: {}", is_tampered_valid);
    assert!(!is_tampered_valid);

    Ok(())
}
