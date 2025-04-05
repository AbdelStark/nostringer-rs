use colored::Colorize;
use nostringer::{
    blsag::{key_images_match, sign_blsag_hex, verify_blsag_hex},
    generate_keypairs, get_public_keys,
    types::{Error, KeyImage},
};

fn main() -> Result<(), Error> {
    println!(
        "{}",
        "NOSTRINGER BLSAG EXAMPLE: Locally Linkable Ring Signatures"
            .bold()
            .green()
    );
    println!(
        "{}",
        "This example demonstrates the impact of different linkability flags for bLSAG.".italic()
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
    let linkability_flag = Some("blsag_local_linkability_example".to_string());
    println!("\n{}", "3. Creating a linkability flag (optional)".bold());
    println!(
        "   Linkability flag: {}",
        linkability_flag
            .clone()
            .unwrap_or("None".to_string())
            .bright_blue()
    );

    // 4. Sign two different messages with the same key
    println!(
        "\n{}",
        "4. Signing the same message with the same private key and different linkability flags"
            .bold()
    );

    let message = b"Stay safe, Stay anon !";
    println!(
        "   Signed message: {}",
        std::str::from_utf8(message).unwrap().green()
    );

    let (signature1, key_image1_hex) = sign_blsag_hex(
        message,
        &signer_keypair.private_key_hex,
        &ring_pubkeys,
        &linkability_flag, // Linkability flag for local linkability
    )?;

    let key_image1 = KeyImage::from_hex(&key_image1_hex)?;
    println!(
        "   Signature 1 created with key image: {}",
        key_image1_hex[0..16].bright_magenta()
    );

    // Verify first signature
    let is_valid1 = verify_blsag_hex(&signature1, &key_image1_hex, message, &ring_pubkeys)?;
    println!(
        "   Verification result: {}",
        if is_valid1 {
            "Valid ✓".green()
        } else {
            "Invalid ✗".red()
        }
    );

    // Sign second message
    let (signature2, key_image2_hex) = sign_blsag_hex(
        message,
        &signer_keypair.private_key_hex,
        &ring_pubkeys,
        &None, // No linkability flag
    )?;

    let key_image2 = KeyImage::from_hex(&key_image2_hex)?;
    println!(
        "   Signature created with key image: {}",
        key_image2_hex[0..16].bright_magenta()
    );

    // Verify second signature
    let is_valid2 = verify_blsag_hex(&signature2, &key_image2_hex, message, &ring_pubkeys)?;
    println!(
        "   Verification result: {}",
        if is_valid2 {
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

    let are_key_images_1_and_2_different = if key_images_match(&key_image1, &key_image2) {
        "No ✗".red()
    } else {
        "Yes ✓".green()
    };
    println!(
        "   Are key images 1 and 2 different? {}",
        are_key_images_1_and_2_different
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
