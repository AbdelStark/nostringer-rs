use nostringer::{
    generate_keypair_hex,
    sag::{sign_binary, verify_binary},
    types::{hex_to_scalar, Error},
    utils::hex_to_point,
};

fn main() -> Result<(), Error> {
    println!("--- Binary API Demonstration ---");

    // 1. Generate keys
    let keypair1 = generate_keypair_hex("xonly");
    let keypair2 = generate_keypair_hex("compressed");
    let keypair3 = generate_keypair_hex("uncompressed");

    // 2. Convert keys to binary format for the binary API
    let signer = &keypair2; // Choose signer
    let signer_privkey = hex_to_scalar(&signer.private_key_hex)?;
    let ring_pubkeys_binary = vec![
        hex_to_point(&keypair1.public_key_hex)?,
        hex_to_point(&keypair2.public_key_hex)?,
        hex_to_point(&keypair3.public_key_hex)?,
    ];

    // 3. Define message
    let message = b"Message for binary API";

    // 4. Sign using the binary API
    println!("Signing with binary API...");
    let mut rng = rand::rngs::OsRng;
    let binary_signature = sign_binary(message, &signer_privkey, &ring_pubkeys_binary, &mut rng)?;
    println!(" Binary Signature c0: {:?}", binary_signature.c0);
    println!(" Binary Signature s: {:?} values", binary_signature.s.len());

    // 5. Verify using the binary API
    println!("Verifying with binary API...");
    let is_binary_valid = verify_binary(&binary_signature, message, &ring_pubkeys_binary)?;
    assert!(is_binary_valid, "Binary API verification failed!");
    println!(" Binary API verification successful.");

    // 6. Tamper test (binary)
    let tampered_message = b"Tampered binary message";
    let is_tampered_valid_binary =
        verify_binary(&binary_signature, tampered_message, &ring_pubkeys_binary)?;
    assert!(
        !is_tampered_valid_binary,
        "Binary API should fail verification for tampered message"
    );
    println!(" Binary API tampered verification correctly failed.");

    Ok(())
}
