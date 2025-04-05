use colored::Colorize;
use nostringer::{
    blsag::{key_images_match, sign_blsag_hex, verify_blsag_hex},
    generate_keypairs, get_public_keys,
    types::{Error, KeyImage},
};

fn main() -> Result<(), Error> {
    println!(
        "{}",
        "NOSTRINGER BLSAG EXAMPLE: Linkable Ring Signatures"
            .bold()
            .green()
    );
    println!(
        "{}",
        "This example demonstrates the linkability property of bLSAG.".italic()
    );
    println!("{}", "Unlike regular SAG signatures, bLSAG signatures can detect if the same signer created multiple signatures.".italic());
    println!();

    // 1. Generate a ring of public keys
    println!("{}", "1. Setting up the ring".bold());
    let ring_size = 5;
    println!("   Generating a ring with {} members...", ring_size);

    let keypairs = generate_keypairs(ring_size, "xonly");
    let ring_pubkeys = get_public_keys(&keypairs);

    // Print the ring members
    for (i, pubkey) in ring_pubkeys.iter().enumerate() {
        let shortened = format!("{}...{}", &pubkey[0..8], &pubkey[pubkey.len() - 8..]);
        println!("   Ring Member {}: {}", i + 1, shortened.cyan());
    }

    // 2. Choose signer (member 3) for both signatures
    let signer_index = 2; // 0-based index
    let signer_keypair = &keypairs[signer_index];
    println!("\n{}", "2. Selecting a signer".bold());
    println!("   Selected Ring Member {} as the signer", signer_index + 1);
    println!("   Note: Other ring members cannot tell which member is signing!");

    // 3. Create a linkability flag specific to our context (optional)
    let linkability_flag = None;
    println!("\n{}", "3. Linkability flag".bold());
    println!(
        "   In this example, we are using the global linkability. For real-world applications,"
    );
    println!("   you can create a linkability flag specific to your context.");
    println!("   (see the blsag_local_linkability.rs example)");

    // 4. Sign two different messages with the same key
    println!(
        "\n{}",
        "4. Signing two different messages with the same private key".bold()
    );

    let message1 = b"First vote: Approve proposal A";
    println!(
        "   First message: {}",
        std::str::from_utf8(message1).unwrap().green()
    );

    let (signature1, key_image1_hex) = sign_blsag_hex(
        message1,
        &signer_keypair.private_key_hex,
        &ring_pubkeys,
        &linkability_flag,
    )?;

    let key_image1 = KeyImage::from_hex(&key_image1_hex)?;
    println!(
        "   Signature created with key image: {}",
        key_image1_hex[0..16].bright_magenta()
    );

    // Verify first signature
    let is_valid1 = verify_blsag_hex(&signature1, &key_image1_hex, message1, &ring_pubkeys)?;
    println!(
        "   Verification result: {}",
        if is_valid1 {
            "Valid ✓".green()
        } else {
            "Invalid ✗".red()
        }
    );

    // Sign second message
    let message2 = b"Second vote: Approve proposal B";
    println!(
        "\n   Second message: {}",
        std::str::from_utf8(message2).unwrap().green()
    );

    let (signature2, key_image2_hex) = sign_blsag_hex(
        message2,
        &signer_keypair.private_key_hex,
        &ring_pubkeys,
        &linkability_flag,
    )?;

    let key_image2 = KeyImage::from_hex(&key_image2_hex)?;
    println!(
        "   Signature created with key image: {}",
        key_image2_hex[0..16].bright_magenta()
    );

    // Verify second signature
    let is_valid2 = verify_blsag_hex(&signature2, &key_image2_hex, message2, &ring_pubkeys)?;
    println!(
        "   Verification result: {}",
        if is_valid2 {
            "Valid ✓".green()
        } else {
            "Invalid ✗".red()
        }
    );

    // 5. Sign a third message with a different ring member
    println!(
        "\n{}",
        "5. Signing a third message with a DIFFERENT private key".bold()
    );

    let different_signer_index = 4; // Use a different member
    let different_signer = &keypairs[different_signer_index];

    let message3 = b"Third vote: Approve proposal C";
    println!(
        "   Third message: {}",
        std::str::from_utf8(message3).unwrap().green()
    );
    println!("   Signing with Ring Member {}", different_signer_index + 1);

    let (signature3, key_image3_hex) = sign_blsag_hex(
        message3,
        &different_signer.private_key_hex,
        &ring_pubkeys,
        &linkability_flag,
    )?;

    let key_image3 = KeyImage::from_hex(&key_image3_hex)?;
    println!(
        "   Signature created with key image: {}",
        key_image3_hex[0..16].bright_magenta()
    );

    // Verify third signature
    let is_valid3 = verify_blsag_hex(&signature3, &key_image3_hex, message3, &ring_pubkeys)?;
    println!(
        "   Verification result: {}",
        if is_valid3 {
            "Valid ✓".green()
        } else {
            "Invalid ✗".red()
        }
    );

    // 6. Compare key images to detect same signer
    println!(
        "\n{}",
        "6. Detecting same signer through key image comparison".bold()
    );

    let same_key_used_1_2 = key_images_match(&key_image1, &key_image2);
    let same_key_used_1_3 = key_images_match(&key_image1, &key_image3);

    println!(
        "   Are signatures 1 and 2 from the same key? {}",
        if same_key_used_1_2 {
            "YES ✓".green().bold()
        } else {
            "NO ✗".red()
        }
    );
    println!(
        "   Are signatures 1 and 3 from the same key? {}",
        if same_key_used_1_3 {
            "YES ✓".green()
        } else {
            "NO ✗".red().bold()
        }
    );

    // Explain the results
    println!("\n{}", "RESULTS EXPLAINED:".bold());
    println!("   In bLSAG (Back's Linkable Spontaneous Anonymous Group), each signer produces");
    println!("   a unique key image derived from their private key. This key image is the same");
    println!(
        "   for all signatures produced by the same key, regardless of the message or the ring."
    );
    println!("");
    println!("   This allows detecting when the same key signs multiple messages, without");
    println!("   revealing which specific key in the ring is the signer.");
    println!("");
    println!("   Use cases include preventing double-voting, double-spending, or enforcing");
    println!("   one-time use credentials, while maintaining anonymity within the group.");

    Ok(())
}
