use nostringer::{
    generate_keypair_hex,
    sag::{sign, verify},
    types::{Error, RingSignature},
};
use std::time::Instant;

fn main() {
    println!("Nostringer Error Handling Example");
    println!("===============================\n");

    // Run each error scenario and report results
    println!("Testing various error scenarios:\n");

    // Scenario 1: Ring too small
    match test_ring_too_small() {
        Ok(_) => println!("❌ Failed: Expected error for ring too small"),
        Err(e) => println!("✅ Success: Caught error for ring too small: {}", e),
    }

    // Scenario 2: Signer not in ring
    match test_signer_not_in_ring() {
        Ok(_) => println!("❌ Failed: Expected error for signer not in ring"),
        Err(e) => println!("✅ Success: Caught error for signer not in ring: {}", e),
    }

    // Scenario 3: Invalid signature format
    match test_invalid_signature_format() {
        Ok(_) => println!("❌ Failed: Expected error for invalid signature format"),
        Err(e) => println!(
            "✅ Success: Caught error for invalid signature format: {}",
            e
        ),
    }

    // Scenario 4: Invalid private key
    match test_invalid_private_key() {
        Ok(_) => println!("❌ Failed: Expected error for invalid private key"),
        Err(e) => println!("✅ Success: Caught error for invalid private key: {}", e),
    }

    // Scenario 5: Invalid public key
    match test_invalid_public_key() {
        Ok(_) => println!("❌ Failed: Expected error for invalid public key"),
        Err(e) => println!("✅ Success: Caught error for invalid public key: {}", e),
    }

    println!("\nAll error handling tests completed successfully!");
}

// Scenario 1: Ring too small (< 2 members)
fn test_ring_too_small() -> Result<(), Error> {
    let keypair = generate_keypair_hex("xonly");
    let ring = vec![keypair.public_key_hex.clone()]; // Only 1 member

    let message = b"This should fail because the ring is too small.";
    let start = Instant::now();
    let result = sign(message, &keypair.private_key_hex, &ring);
    let elapsed = start.elapsed();

    println!("Ring too small test took {:?}", elapsed);
    result.map(|_| ())
}

// Scenario 2: Signer not in ring
fn test_signer_not_in_ring() -> Result<(), Error> {
    // Generate three keypairs
    let keypair1 = generate_keypair_hex("xonly");
    let keypair2 = generate_keypair_hex("xonly");
    let keypair3 = generate_keypair_hex("xonly");

    // Create a ring WITHOUT keypair1
    let ring = vec![
        keypair2.public_key_hex.clone(),
        keypair3.public_key_hex.clone(),
    ];

    // Try to sign with keypair1 (not in the ring)
    let message = b"This should fail because the signer is not in the ring.";
    let start = Instant::now();
    let result = sign(message, &keypair1.private_key_hex, &ring);
    let elapsed = start.elapsed();

    println!("Signer not in ring test took {:?}", elapsed);
    result.map(|_| ())
}

// Scenario 3: Invalid signature format
fn test_invalid_signature_format() -> Result<(), Error> {
    let keypair1 = generate_keypair_hex("xonly");
    let keypair2 = generate_keypair_hex("xonly");

    let ring = vec![
        keypair1.public_key_hex.clone(),
        keypair2.public_key_hex.clone(),
    ];

    // Create an invalid signature with mismatched sizes
    let invalid_signature = RingSignature {
        c0: "deadbeef".repeat(8),      // 64 characters
        s: vec!["deadbeef".repeat(8)], // Only 1 s value for 2 ring members
    };

    let message = b"This should fail because signature doesn't match ring size.";
    let start = Instant::now();
    let result = verify(&invalid_signature, message, &ring);
    let elapsed = start.elapsed();

    println!("Invalid signature format test took {:?}", elapsed);
    result.map(|_| ())
}

// Scenario 4: Invalid private key
fn test_invalid_private_key() -> Result<(), Error> {
    let keypair1 = generate_keypair_hex("xonly");
    let keypair2 = generate_keypair_hex("xonly");

    let ring = vec![
        keypair1.public_key_hex.clone(),
        keypair2.public_key_hex.clone(),
    ];

    // Create an invalid private key
    let invalid_private_key = "not-a-hex-key";

    let message = b"This should fail because private key is invalid.";
    let start = Instant::now();
    let result = sign(message, invalid_private_key, &ring);
    let elapsed = start.elapsed();

    println!("Invalid private key test took {:?}", elapsed);
    result.map(|_| ())
}

// Scenario 5: Invalid public key
fn test_invalid_public_key() -> Result<(), Error> {
    let keypair = generate_keypair_hex("xonly");

    // Create a ring with an invalid public key
    let ring = vec![
        keypair.public_key_hex.clone(),
        "01234567".repeat(8), // Valid hex but invalid point
    ];

    let message = b"This should fail because there's an invalid public key in the ring.";
    let start = Instant::now();
    let result = sign(message, &keypair.private_key_hex, &ring);
    let elapsed = start.elapsed();

    println!("Invalid public key test took {:?}", elapsed);
    result.map(|_| ())
}
