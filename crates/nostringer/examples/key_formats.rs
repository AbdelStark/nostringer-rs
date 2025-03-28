use nostringer::{generate_keypair_hex, generate_keypairs, get_public_keys, sign, verify, Error};

fn main() -> Result<(), Error> {
    println!("Nostringer Key Format Example");
    println!("============================\n");

    // Generate keys in different formats
    println!("Generating keys in different formats:");
    let xonly_key = generate_keypair_hex("xonly");
    let compressed_key = generate_keypair_hex("compressed");
    let uncompressed_key = generate_keypair_hex("uncompressed");

    println!("X-only public key (64 hex chars):");
    println!("  {}", xonly_key.public_key_hex);
    println!("  Length: {} chars\n", xonly_key.public_key_hex.len());

    println!("Compressed public key (66 hex chars, starts with 02 or 03):");
    println!("  {}", compressed_key.public_key_hex);
    println!("  Length: {} chars\n", compressed_key.public_key_hex.len());

    println!("Uncompressed public key (130 hex chars, starts with 04):");
    println!("  {}", uncompressed_key.public_key_hex);
    println!(
        "  Length: {} chars\n",
        uncompressed_key.public_key_hex.len()
    );

    // Create a larger ring with mixed key formats
    println!("Creating a larger ring with mixed key formats...");

    // Generate 5 additional keys in compressed format
    let additional_keys = generate_keypairs(5, "compressed");

    // Our ring will consist of all the keys
    let mixed_ring = vec![
        xonly_key.public_key_hex.clone(),
        compressed_key.public_key_hex.clone(),
        uncompressed_key.public_key_hex.clone(),
    ];

    // Add the additional keys to the ring
    let mut full_ring = mixed_ring.clone();
    full_ring.extend(get_public_keys(&additional_keys));

    println!("Ring size: {} members\n", full_ring.len());

    // Message to sign
    let message = b"This message demonstrates using different key formats in a ring.";
    println!("Message: \"{}\"", String::from_utf8_lossy(message));

    // Choose a signer - we'll use the uncompressed key for this example
    println!("\nSigning with the uncompressed key...");
    let signature = sign(message, &uncompressed_key.private_key_hex, &full_ring)?;

    println!(
        "Signature size: {} bytes (c0 + {} s values)",
        32 + 32 * signature.s.len(), // Each scalar is 32 bytes
        signature.s.len()
    );

    // Verify the signature
    println!("\nVerifying the signature...");
    let is_valid = verify(&signature, message, &full_ring)?;
    println!("Signature valid: {}", is_valid);

    // Show that the signature hides which specific key was the signer
    println!("\nThe verifier knows the signature came from one of these keys:");
    for (i, key) in full_ring.iter().enumerate() {
        // Show just a preview of each key for readability
        let key_preview = if key.len() > 10 {
            format!("{}...{}", &key[0..5], &key[key.len() - 5..])
        } else {
            key.clone()
        };
        println!("  {}: {}", i + 1, key_preview);
    }
    println!("\nBut they cannot determine which one was the actual signer!");

    Ok(())
}
