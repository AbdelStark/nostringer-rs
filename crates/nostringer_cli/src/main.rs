use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use nostr::prelude::{Keys, ToBech32};
use nostringer::{
    blsag::{key_images_match, sign_blsag_hex, verify_blsag_hex},
    generate_keypair_hex, generate_keypairs, get_public_keys, sag,
    types::{KeyImage, KeyPairHex},
    CompactSignature, SignatureVariant,
};

/// Command-line interface for the nostringer ring signature library
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new keypair
    Generate {
        /// The format for the public key
        /// Options: 'xonly' (default), 'compressed', 'uncompressed'
        #[arg(short, long, default_value = "xonly")]
        format: String,

        /// Optional: File path to save the keys to (as JSON)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Sign a message using a ring signature
    Sign {
        /// The message to sign (as a string)
        #[arg(short, long)]
        message: String,

        /// The signer's private key (hex string)
        #[arg(short, long)]
        private_key: String,

        /// A comma-separated list of public keys in the ring
        #[arg(short, long)]
        ring: String,

        /// Optional: Signature variant to use (sag or blsag, default: sag)
        #[arg(short, long, default_value = "sag")]
        variant: String,

        /// Optional: The linkability flag to use (default: None) (only works with variant = "blsag")
        #[arg(short, long)]
        linkability_flag: Option<String>,

        /// Optional: File path to save the signature to
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Verify a ring signature
    Verify {
        /// The message that was signed (as a string)
        #[arg(short, long)]
        message: String,

        /// The compact signature (ringA... format)
        #[arg(short, long)]
        signature: String,

        /// A comma-separated list of public keys in the ring
        #[arg(short, long)]
        ring: String,
    },

    /// Run a complete demo of the ring signature process
    Demo,

    /// Run a demo of the linkable bLSAG ring signature variant
    BlsagDemo,

    /// Run a demo of compact signature format (both SAG and BLSAG)
    CompactSignDemo,

    /// Run a demo with a large ring of 100 members
    BigRingDemo,

    /// Run a demo of nostringer integrated with Nostr keys (npub/nsec)
    NostrDemo,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Generate { format, output } => {
            let keypair = generate_keypair_hex(format);
            display_keypair(&keypair);

            if let Some(output_path) = output {
                save_keypair(&keypair, output_path)?;
                println!(
                    "\n{} Keys saved to {}",
                    "✓".green().bold(),
                    output_path.display().to_string().cyan()
                );
            }
        }

        Commands::Sign {
            message,
            private_key,
            ring,
            variant,
            linkability_flag,
            output,
        } => {
            let ring_pubkeys = parse_keys_list(ring)?;

            // Parse the signature variant
            let sig_variant = match variant.to_lowercase().as_str() {
                "sag" => {
                    // Linkability flag is not applicable for SAG signatures
                    if linkability_flag.is_some() {
                        return Err(anyhow!(
                            "Linkability flag is not supported for SAG variant."
                        ));
                    }

                    SignatureVariant::Sag
                }
                "blsag" => match linkability_flag {
                    // If a non empty linkability flag is provided, use it
                    Some(flag) if !flag.is_empty() => {
                        SignatureVariant::BlsagWithFlag(flag.to_string())
                    }
                    _ => SignatureVariant::Blsag,
                },
                _ => {
                    return Err(anyhow!(
                        "Invalid signature variant: {}. Use 'sag' or 'blsag'.",
                        variant
                    ))
                }
            };

            match sig_variant {
                SignatureVariant::BlsagWithFlag(_) => {
                    println!(
                        "Signing with BLSAG variant and linkability flag: '{}'...",
                        linkability_flag.clone().unwrap_or(String::new())
                    );
                }
                _ => {
                    println!("Signing with {} variant...", variant.to_uppercase());
                }
            }

            let compact_signature =
                nostringer::sign(message.as_bytes(), private_key, &ring_pubkeys, sig_variant)
                    .context("Failed to create signature")?;

            println!("\n{}", "Compact Signature (ringA format):".bold());
            println!("{}", compact_signature.bright_magenta());

            // Verify the signature
            let is_valid =
                nostringer::verify(&compact_signature, message.as_bytes(), &ring_pubkeys)
                    .context("Failed to verify signature")?;

            if is_valid {
                println!("\n{} {}", "✓".green().bold(), "Signature is valid!".green());
            } else {
                println!("\n{} {}", "✗".red().bold(), "Signature is invalid!".red());
            }

            if let Some(output_path) = output {
                fs::write(output_path, compact_signature.as_bytes()).with_context(|| {
                    format!("Failed to write signature to {}", output_path.display())
                })?;
                println!(
                    "\n{} Signature saved to {}",
                    "✓".green().bold(),
                    output_path.display().to_string().cyan()
                );
            }
        }

        Commands::Verify {
            message,
            signature,
            ring,
        } => {
            let ring_pubkeys = parse_keys_list(ring)?;

            println!("Verifying signature: {}", signature.bright_magenta());

            let is_valid = nostringer::verify(signature, message.as_bytes(), &ring_pubkeys)
                .context("Failed to verify signature")?;

            if is_valid {
                println!("\n{} {}", "✓".green().bold(), "Signature is valid!".green());
            } else {
                println!("\n{} {}", "✗".red().bold(), "Signature is invalid!".red());
            }

            // Try to get the signature variant for informational purposes
            match CompactSignature::deserialize(signature) {
                Ok(compact_sig) => {
                    let linkability_level: Option<String> = match &compact_sig {
                        CompactSignature::Blsag(binary_blsag, _) => binary_blsag
                            .linkability_flag
                            .as_ref()
                            .map(|linkability_flag| {
                                String::from_utf8_lossy(linkability_flag).to_string()
                            }),
                        _ => None,
                    };
                    println!(
                        "Signature variant: {} {}",
                        compact_sig.variant().to_uppercase().cyan(),
                        linkability_level
                            .map(|flag| format!("(linkability flag: '{}')", flag.yellow()))
                            .unwrap_or_default()
                    );
                }
                Err(_) => {
                    println!("Could not determine signature variant");
                }
            }
        }

        Commands::Demo => {
            run_demo()?;
        }

        Commands::BlsagDemo => {
            run_blsag_demo()?;
        }

        Commands::CompactSignDemo => {
            run_compact_sign_demo()?;
        }

        Commands::BigRingDemo => {
            run_big_ring_demo()?;
        }

        Commands::NostrDemo => {
            run_nostr_demo()?;
        }
    }

    Ok(())
}

/// Run an end-to-end demo of the ring signature process
fn run_demo() -> Result<()> {
    println!(
        "\n{}",
        "=== NOSTRINGER RING SIGNATURE DEMO ===".bold().green()
    );
    println!(
        "{}",
        "This demo will take you through a complete ring signature process.".italic()
    );

    println!(
        "\n{}",
        "1. Generating keypairs for the ring members...".bold()
    );
    let keypair1 = generate_keypair_hex("xonly");
    let keypair2 = generate_keypair_hex("xonly");
    let keypair3 = generate_keypair_hex("xonly");

    println!("Ring Member 1 (xonly):");
    println!("  Private Key: {}", keypair1.private_key_hex.yellow());
    println!("  Public Key:  {}", keypair1.public_key_hex.cyan());

    println!("\nRing Member 2 (xonly):");
    println!("  Private Key: {}", keypair2.private_key_hex.yellow());
    println!("  Public Key:  {}", keypair2.public_key_hex.cyan());

    println!("\nRing Member 3 (xonly):");
    println!("  Private Key: {}", keypair3.private_key_hex.yellow());
    println!("  Public Key:  {}", keypair3.public_key_hex.cyan());

    let ring_pubkeys = vec![
        keypair1.public_key_hex.clone(),
        keypair2.public_key_hex.clone(),
        keypair3.public_key_hex.clone(),
    ];

    println!("\n{}", "2. Creating a message to sign...".bold());
    let message = "This is a secret message from one of the ring members.";
    println!("Message: {}", message.green());

    println!(
        "\n{}",
        "3. Signing the message using Ring Member 2's private key...".bold()
    );
    println!("Selected signer: Ring Member 2");

    let compact_signature = nostringer::sign(
        message.as_bytes(),
        &keypair2.private_key_hex,
        &ring_pubkeys,
        SignatureVariant::Sag,
    )
    .context("Failed to create signature")?;

    println!("\nGenerated Compact Signature (ringA format):");
    println!("{}", compact_signature.bright_magenta());

    println!("\n{}", "4. Verifying the signature...".bold());
    println!("Can we verify who signed it? No, just that it was someone in the ring.");

    let is_valid = nostringer::verify(&compact_signature, message.as_bytes(), &ring_pubkeys)
        .context("Failed to verify signature")?;

    if is_valid {
        println!(
            "\n{} {}",
            "✓".green().bold(),
            "Signature is valid!".green().bold()
        );
        println!("This proves that one of the ring members signed the message,");
        println!("but there's no way to determine which one.");
    } else {
        println!(
            "\n{} {}",
            "✗".red().bold(),
            "Signature verification failed!".red().bold()
        );
    }

    println!("\n{}", "5. Testing with a tampered message...".bold());
    let tampered_message = "This is a tampered message that wasn't signed.";
    println!("Tampered message: {}", tampered_message.red());

    let is_tampered_valid = nostringer::verify(
        &compact_signature,
        tampered_message.as_bytes(),
        &ring_pubkeys,
    )
    .context("Failed to verify tampered signature")?;

    if !is_tampered_valid {
        println!(
            "\n{} {}",
            "✓".green().bold(),
            "Tampered message correctly rejected!".green().bold()
        );
        println!("This shows that the signature is bound to the original message.");
    } else {
        println!(
            "\n{} {}",
            "✗".red().bold(),
            "Tampered message was incorrectly verified!".red().bold()
        );
    }

    // Now we will simulate compromising the ring and adding a new unauthorized member
    let non_ring_member_keypair = generate_keypair_hex("xonly");
    let compromised_ring = vec![
        keypair1.public_key_hex.clone(),
        keypair2.public_key_hex.clone(),
        keypair3.public_key_hex.clone(),
        non_ring_member_keypair.public_key_hex.clone(),
    ];

    // We sign the message again with the compromised ring
    println!(
        "\n{}",
        "6. Signing the message with the compromised ring...".bold()
    );
    let compromised_signature = nostringer::sign(
        message.as_bytes(),
        &non_ring_member_keypair.private_key_hex,
        &compromised_ring,
        SignatureVariant::Sag,
    )
    .context("Failed to create compromised signature")?;

    println!(
        "\n{}",
        "7. Verifying the signature with the original ring (should fail)".bold()
    );
    let error_thrown =
        nostringer::verify(&compromised_signature, message.as_bytes(), &ring_pubkeys).is_err();

    if error_thrown {
        println!(
            "\n{} {}",
            "✓".green().bold(),
            "Compromised signature was correctly rejected!"
                .bold()
                .green()
        );
        println!("This shows that the signature is bound to the original ring members.");
    } else {
        println!(
            "\n{} {}",
            "✗".red().bold(),
            "Compromised signature was incorrectly verified!"
                .bold()
                .red()
        );
    }

    println!("\n{}", "=== DEMO COMPLETE ===".bold().green());
    Ok(())
}

/// Run a demo of the bLSAG (Back's Linkable Spontaneous Anonymous Group) signature scheme
fn run_blsag_demo() -> Result<()> {
    println!(
        "\n{}",
        "=== NOSTRINGER BLSAG (LINKABLE) RING SIGNATURE DEMO ==="
            .bold()
            .green()
    );
    println!(
        "{}",
        "This demo shows how bLSAG signatures can be linked when signed by the same key.".italic()
    );

    println!(
        "\n{}",
        "1. Generating keypairs for 5 ring members...".bold()
    );
    let keypairs = generate_keypairs(5, "xonly");
    let ring_pubkeys = get_public_keys(&keypairs);

    // Display ring members
    for (i, pubkey) in ring_pubkeys.iter().enumerate() {
        let short_key = format!("{}...{}", &pubkey[0..8], &pubkey[pubkey.len() - 8..]);
        println!("Ring Member {}: {}", i + 1, short_key.cyan());
    }

    println!("\n{}", "2. Selecting Ring Member 3 as our signer.".bold());
    let signer_index = 2; // 0-based index for the third member
    let signer = &keypairs[signer_index];

    println!(
        "\n{}",
        "3. Creating and signing two different messages.".bold()
    );

    // First message and signature
    let message1 = "Vote for Proposal #1: Increase community budget";
    println!("\nFirst message: {}", message1.green());

    let (signature1, key_image1_hex) = sign_blsag_hex(
        message1.as_bytes(),
        &signer.private_key_hex,
        &ring_pubkeys,
        &None,
    )
    .context("Failed to create first signature")?;

    println!(
        "Created signature with key image: {}",
        key_image1_hex[0..16].bright_magenta()
    );

    // Verify first signature
    let is_valid1 = verify_blsag_hex(
        &signature1,
        &key_image1_hex,
        message1.as_bytes(),
        &ring_pubkeys,
    )
    .context("Failed to verify first signature")?;

    println!(
        "Verification result: {}",
        if is_valid1 {
            "Valid ✓".green().bold()
        } else {
            "Invalid ✗".red().bold()
        }
    );

    // Parse key image for comparison
    let key_image1 = KeyImage::from_hex(&key_image1_hex)?;

    // Second message and signature (with the same signer)
    let message2 = "Vote for Proposal #2: Fund development team";
    println!("\nSecond message: {}", message2.green());

    let (signature2, key_image2_hex) = sign_blsag_hex(
        message2.as_bytes(),
        &signer.private_key_hex,
        &ring_pubkeys,
        &None,
    )
    .context("Failed to create second signature")?;

    println!(
        "Created signature with key image: {}",
        key_image2_hex[0..16].bright_magenta()
    );

    // Verify second signature
    let is_valid2 = verify_blsag_hex(
        &signature2,
        &key_image2_hex,
        message2.as_bytes(),
        &ring_pubkeys,
    )
    .context("Failed to verify second signature")?;

    println!(
        "Verification result: {}",
        if is_valid2 {
            "Valid ✓".green().bold()
        } else {
            "Invalid ✗".red().bold()
        }
    );

    // Parse key image for comparison
    let key_image2 = KeyImage::from_hex(&key_image2_hex)?;

    // Third message with a different signer
    println!(
        "\n{}",
        "4. Creating one more signature with a different ring member.".bold()
    );

    let different_signer_index = 4; // The fifth ring member
    let different_signer = &keypairs[different_signer_index];

    let message3 = "Vote for Proposal #3: Update governance rules";
    println!("\nThird message: {}", message3.green());
    println!("Signing with Ring Member {}", different_signer_index + 1);

    let (signature3, key_image3_hex) = sign_blsag_hex(
        message3.as_bytes(),
        &different_signer.private_key_hex,
        &ring_pubkeys,
        &None,
    )
    .context("Failed to create third signature")?;

    println!(
        "Created signature with key image: {}",
        key_image3_hex[0..16].bright_magenta()
    );

    // Verify third signature
    let is_valid3 = verify_blsag_hex(
        &signature3,
        &key_image3_hex,
        message3.as_bytes(),
        &ring_pubkeys,
    )
    .context("Failed to verify third signature")?;

    println!(
        "Verification result: {}",
        if is_valid3 {
            "Valid ✓".green().bold()
        } else {
            "Invalid ✗".red().bold()
        }
    );

    // Parse key image for comparison
    let key_image3 = KeyImage::from_hex(&key_image3_hex)?;

    // Compare key images to detect linkability
    println!(
        "\n{}",
        "5. Detecting signature linkability through key images.".bold()
    );

    let same_signer_1_2 = key_images_match(&key_image1, &key_image2);
    let same_signer_1_3 = key_images_match(&key_image1, &key_image3);

    println!(
        "Are signatures 1 and 2 from the same signer? {}",
        if same_signer_1_2 {
            "YES ✓".green().bold()
        } else {
            "NO ✗".red().bold()
        }
    );

    println!(
        "Are signatures 1 and 3 from the same signer? {}",
        if same_signer_1_3 {
            "YES ✓".green().bold()
        } else {
            "NO ✗".red().bold()
        }
    );

    // Explanation of bLSAG vs regular SAG
    println!(
        "\n{}",
        "UNDERSTANDING BLSAG VS REGULAR SAG:".bold().yellow()
    );
    println!("1. Regular SAG signatures are completely unlinkable");
    println!("   - No way to tell if two signatures came from the same signer");
    println!("   - Provides maximum privacy within the ring");
    println!();
    println!("2. bLSAG signatures are linkable but still anonymous");
    println!("   - Can detect when the same key signs multiple times (through key images)");
    println!("   - Still doesn't reveal which specific ring member signed");
    println!("   - Useful for preventing double-spending or duplicate voting");
    println!("   - The key image is unique to the private key but doesn't expose it");
    println!();
    println!("3. Both variants provide:");
    println!("   - Ring signature verification (proving a member of the ring signed)");
    println!("   - Anonymity (hiding which specific member signed)");
    println!("   - Spontaneous group creation (no coordinator needed)");

    println!("\n{}", "=== BLSAG DEMO COMPLETE ===".bold().green());
    Ok(())
}

fn display_keypair(keypair: &KeyPairHex) {
    println!("\n{}", "Generated Keypair:".bold());
    println!("  Private Key: {}", keypair.private_key_hex.yellow());
    println!("  Public Key:  {}", keypair.public_key_hex.cyan());
}

fn save_keypair(keypair: &KeyPairHex, path: &Path) -> Result<()> {
    let json = serde_json::json!({
        "private_key": keypair.private_key_hex,
        "public_key": keypair.public_key_hex,
    });
    let content =
        serde_json::to_string_pretty(&json).context("Failed to serialize keypair to JSON")?;
    fs::write(path, content).with_context(|| format!("Failed to write to {}", path.display()))?;
    Ok(())
}

/// Run a demo of the compact signature format (ringA...) for both SAG and BLSAG
fn run_compact_sign_demo() -> Result<()> {
    println!(
        "\n{}",
        "=== NOSTRINGER COMPACT SIGNATURE DEMO ===".bold().green()
    );
    println!(
        "{}",
        "This demo demonstrates the compact signature format (ringA...) for both SAG and BLSAG variants."
            .italic()
    );

    println!(
        "\n{}",
        "1. Generating keypairs for the ring members...".bold()
    );
    let keypair1 = generate_keypair_hex("xonly");
    let keypair2 = generate_keypair_hex("xonly");
    let keypair3 = generate_keypair_hex("xonly");

    println!("Ring Member 1 (xonly):");
    println!("  Public Key:  {}", keypair1.public_key_hex.cyan());

    println!("\nRing Member 2 (xonly):");
    println!("  Public Key:  {}", keypair2.public_key_hex.cyan());

    println!("\nRing Member 3 (xonly):");
    println!("  Public Key:  {}", keypair3.public_key_hex.cyan());

    let ring_pubkeys = vec![
        keypair1.public_key_hex.clone(),
        keypair2.public_key_hex.clone(),
        keypair3.public_key_hex.clone(),
    ];

    // ==========
    // SAG COMPACT
    // ==========

    println!("\n{}", "2. Creating an SAG compact signature...".bold());
    let message = "This is a message signed with SAG compact format.";
    println!("Message: {}", message.green());

    println!("Signing with Ring Member 2's private key...");
    let compact_sig_sag =
        nostringer::sign_compact_sag(message.as_bytes(), &keypair2.private_key_hex, &ring_pubkeys)
            .context("Failed to create SAG compact signature")?;

    println!("\nCompact SAG signature (ringA format):");
    println!("{}", compact_sig_sag.bright_magenta());

    // Verify the signature
    println!("\n{}", "3. Verifying the SAG compact signature...".bold());
    let is_valid = nostringer::verify_compact(&compact_sig_sag, message.as_bytes(), &ring_pubkeys)
        .context("Failed to verify SAG compact signature")?;

    if is_valid {
        println!(
            "{} {}",
            "✓".green().bold(),
            "SAG compact signature is valid!".green().bold()
        );
    } else {
        println!(
            "{} {}",
            "✗".red().bold(),
            "SAG compact signature is invalid!".red().bold()
        );
    }

    // Test with a tampered message
    let tampered_message = "This is a tampered message!";
    println!(
        "\nTesting with tampered message: {}",
        tampered_message.red()
    );

    let is_tampered_valid =
        nostringer::verify_compact(&compact_sig_sag, tampered_message.as_bytes(), &ring_pubkeys)
            .context("Failed to verify tampered SAG compact signature")?;

    if !is_tampered_valid {
        println!(
            "{} {}",
            "✓".green().bold(),
            "Tampered message correctly rejected!".green().bold()
        );
    } else {
        println!(
            "{} {}",
            "✗".red().bold(),
            "Tampered message was incorrectly verified!".red().bold()
        );
    }

    // ==========
    // BLSAG COMPACT
    // ==========

    println!("\n{}", "4. Creating a BLSAG compact signature...".bold());
    let message2 = "This is a message signed with BLSAG compact format.";
    println!("Message: {}", message2.green());

    println!("Signing with Ring Member 2's private key (same signer)...");
    let compact_sig_blsag = nostringer::sign_compact_blsag(
        message2.as_bytes(),
        &keypair2.private_key_hex,
        &ring_pubkeys,
        &SignatureVariant::Blsag,
    )
    .context("Failed to create BLSAG compact signature")?;

    println!("\nCompact BLSAG signature (ringA format):");
    println!("{}", compact_sig_blsag.bright_magenta());

    // Verify the BLSAG signature
    println!("\n{}", "5. Verifying the BLSAG compact signature...".bold());
    let is_valid_blsag =
        nostringer::verify_compact(&compact_sig_blsag, message2.as_bytes(), &ring_pubkeys)
            .context("Failed to verify BLSAG compact signature")?;

    if is_valid_blsag {
        println!(
            "{} {}",
            "✓".green().bold(),
            "BLSAG compact signature is valid!".green().bold()
        );
    } else {
        println!(
            "{} {}",
            "✗".red().bold(),
            "BLSAG compact signature is invalid!".red().bold()
        );
    }

    // ==========
    // SIGNATURE ANALYSIS
    // ==========

    println!("\n{}", "6. Analyzing compact signatures...".bold());
    println!("Deserializing signatures to examine their contents...");

    // Use nostringer functions to deserialize
    let deserialized_sag = CompactSignature::deserialize(&compact_sig_sag)
        .map_err(|e| anyhow!("Deserialization error: {}", e))?;

    let deserialized_blsag = CompactSignature::deserialize(&compact_sig_blsag)
        .map_err(|e| anyhow!("Deserialization error: {}", e))?;

    println!(
        "\nSAG signature variant: {}",
        deserialized_sag.variant().cyan()
    );
    println!(
        "BLSAG signature variant: {}",
        deserialized_blsag.variant().cyan()
    );

    // Show size difference
    println!("\nSignature size comparison:");
    println!("SAG size: {} bytes", compact_sig_sag.len());
    println!("BLSAG size: {} bytes", compact_sig_blsag.len());
    println!(
        "Size difference: {} bytes",
        compact_sig_blsag.len() - compact_sig_sag.len()
    );

    // ==========
    // EXPLANATION
    // ==========

    println!("\n{}", "ABOUT COMPACT SIGNATURES:".bold().yellow());
    println!("1. The 'ringA...' format is a compact representation using:");
    println!("   - CBOR binary serialization (smaller than JSON)");
    println!("   - Base64url encoding (URL-safe, no padding)");
    println!("   - Internal binary representation (not hex strings)");

    println!("\n2. Benefits of compact format:");
    println!("   - Significantly smaller signature size");
    println!("   - Better for transmission over networks");
    println!("   - Single, unified verification function");
    println!("   - Self-contained (includes signature variant)");

    println!("\n3. Format details:");
    println!("   - Prefix: 'ringA' identifies the format and version");
    println!("   - Payload: Base64url-encoded CBOR data containing:");
    println!("     * Signature variant (sag/blsag)");
    println!("     * c0 challenge value");
    println!("     * Response scalars (s values)");
    println!("     * Key image (for BLSAG only)");

    println!(
        "\n{}",
        "=== COMPACT SIGNATURE DEMO COMPLETE ===".bold().green()
    );
    Ok(())
}

/// Run a demo with a large ring of 100 members
fn run_big_ring_demo() -> Result<()> {
    println!(
        "\n{}",
        "=== NOSTRINGER BIG RING DEMO (100 MEMBERS) ==="
            .bold()
            .green()
    );
    println!(
        "{}",
        "This demo will show how ring signatures perform with a large anonymity set.".italic()
    );

    // Start timing
    let start_time = std::time::Instant::now();

    println!(
        "\n{}",
        "1. Generating 100 keypairs for the ring members...".bold()
    );

    // Use the generate_keypairs helper function to create 100 keypairs
    let keypairs = generate_keypairs(100, "xonly");
    let ring_pubkeys = get_public_keys(&keypairs);

    let generation_time = start_time.elapsed();
    println!("Generated 100 keypairs in {:.2?}", generation_time);

    // Pick a random signer from the ring (between 0 and 99)
    let signer_index = rand::random::<usize>() % 100;
    let signer_keypair = &keypairs[signer_index];

    println!(
        "\n{}",
        "2. Selected a random ring member as the signer...".bold()
    );
    println!("Signer is member #{}", signer_index + 1);
    println!(
        "Public key (first 8 chars): {}",
        &signer_keypair.public_key_hex[0..8]
    );

    println!("\n{}", "3. Creating a message to sign...".bold());
    let message = "This is a message signed by one of 100 ring members.";
    println!("Message: {}", message.green());

    // Measure SAG signing time
    println!(
        "\n{}",
        "4. Signing the message with SAG (unlinkable) signature...".bold()
    );
    let sag_start = std::time::Instant::now();

    let sag_signature = sag::sign(
        message.as_bytes(),
        &signer_keypair.private_key_hex,
        &ring_pubkeys,
    )
    .context("Failed to create SAG signature")?;

    let sag_sign_time = sag_start.elapsed();
    println!("SAG signing completed in {:.2?}", sag_sign_time);

    // Measure SAG verification time
    println!("\n{}", "5. Verifying the SAG signature...".bold());
    let sag_verify_start = std::time::Instant::now();

    let is_sag_valid = sag::verify(&sag_signature, message.as_bytes(), &ring_pubkeys)
        .context("Failed to verify SAG signature")?;

    let sag_verify_time = sag_verify_start.elapsed();
    println!("SAG verification completed in {:.2?}", sag_verify_time);

    if is_sag_valid {
        println!(
            "{} {}",
            "✓".green().bold(),
            "SAG Signature valid!".green().bold()
        );
    } else {
        println!(
            "{} {}",
            "✗".red().bold(),
            "SAG Signature invalid!".red().bold()
        );
    }

    // Measure BLSAG signing time
    println!(
        "\n{}",
        "6. Signing the message with BLSAG (linkable) signature...".bold()
    );
    let blsag_start = std::time::Instant::now();

    let (blsag_signature, key_image) = sign_blsag_hex(
        message.as_bytes(),
        &signer_keypair.private_key_hex,
        &ring_pubkeys,
        &None,
    )
    .context("Failed to create BLSAG signature")?;

    let blsag_sign_time = blsag_start.elapsed();
    println!("BLSAG signing completed in {:.2?}", blsag_sign_time);

    // Measure BLSAG verification time
    println!("\n{}", "7. Verifying the BLSAG signature...".bold());
    let blsag_verify_start = std::time::Instant::now();

    let is_blsag_valid = verify_blsag_hex(
        &blsag_signature,
        &key_image,
        message.as_bytes(),
        &ring_pubkeys,
    )
    .context("Failed to verify BLSAG signature")?;

    let blsag_verify_time = blsag_verify_start.elapsed();
    println!("BLSAG verification completed in {:.2?}", blsag_verify_time);

    if is_blsag_valid {
        println!(
            "{} {}",
            "✓".green().bold(),
            "BLSAG Signature valid!".green().bold()
        );
    } else {
        println!(
            "{} {}",
            "✗".red().bold(),
            "BLSAG Signature invalid!".red().bold()
        );
    }

    // Measure compact signing time
    println!("\n{}", "8. Signing with compact signature format...".bold());
    let compact_start = std::time::Instant::now();

    // Using compact signature API
    let compact_sig = nostringer::sign_compact_sag(
        message.as_bytes(),
        &signer_keypair.private_key_hex,
        &ring_pubkeys,
    )
    .context("Failed to create compact signature")?;

    let compact_sign_time = compact_start.elapsed();
    println!("Compact signing completed in {:.2?}", compact_sign_time);

    // Measure compact verification time
    println!("\n{}", "9. Verifying the compact signature...".bold());
    let compact_verify_start = std::time::Instant::now();

    let is_compact_valid =
        nostringer::verify_compact(&compact_sig, message.as_bytes(), &ring_pubkeys)
            .context("Failed to verify compact signature")?;

    let compact_verify_time = compact_verify_start.elapsed();
    println!(
        "Compact verification completed in {:.2?}",
        compact_verify_time
    );

    // Display the compact signature compact format
    println!("\n{}", "Compact signature:".bold());
    println!("{}", compact_sig.bright_magenta());

    if is_compact_valid {
        println!(
            "{} {}",
            "✓".green().bold(),
            "Compact Signature valid!".green().bold()
        );
    } else {
        println!(
            "{} {}",
            "✗".red().bold(),
            "Compact Signature invalid!".red().bold()
        );
    }

    // Signature sizes
    println!("\n{}", "10. Analyzing signature sizes...".bold());
    let sag_size = sag_signature.s.len() * 64 + sag_signature.c0.len();
    let blsag_size = blsag_signature.s.len() * 64 + blsag_signature.c0.len() + key_image.len();
    let compact_size = compact_sig.len();

    println!("SAG signature size: {} bytes", sag_size);
    println!("BLSAG signature size: {} bytes", blsag_size);
    println!("Compact signature size: {} bytes", compact_size);

    // Convert durations to milliseconds for consistent display
    let sag_sign_ms = sag_sign_time.as_millis();
    let sag_verify_ms = sag_verify_time.as_millis();
    let blsag_sign_ms = blsag_sign_time.as_millis();
    let blsag_verify_ms = blsag_verify_time.as_millis();
    let compact_sign_ms = compact_sign_time.as_millis();
    let compact_verify_ms = compact_verify_time.as_millis();

    // Performance summary
    println!("\n{}", "PERFORMANCE SUMMARY:".bold().yellow());
    println!("┌─────────────┬────────────┬────────────┬────────────┐");
    println!("│ Operation   │ Time (ms)  │ Size (bytes)│ vs SAG (%) │");
    println!("├─────────────┼────────────┼────────────┼────────────┤");
    println!(
        "│ SAG Sign    │ {:<10} │ {:<10} │ {:<10} │",
        sag_sign_ms, sag_size, "100%"
    );
    println!(
        "│ SAG Verify  │ {:<10} │ {:<10} │ {:<10} │",
        sag_verify_ms, "", "100%"
    );

    // Calculate percentage relative to SAG
    let blsag_sign_percent = (blsag_sign_ms as f64 / sag_sign_ms as f64 * 100.0).round();
    let blsag_verify_percent = (blsag_verify_ms as f64 / sag_verify_ms as f64 * 100.0).round();
    let compact_sign_percent = (compact_sign_ms as f64 / sag_sign_ms as f64 * 100.0).round();
    let compact_verify_percent = (compact_verify_ms as f64 / sag_verify_ms as f64 * 100.0).round();

    println!(
        "│ BLSAG Sign  │ {:<10} │ {:<10} │ {:<9.0}% │",
        blsag_sign_ms, blsag_size, blsag_sign_percent
    );
    println!(
        "│ BLSAG Verify│ {:<10} │ {:<10} │ {:<9.0}% │",
        blsag_verify_ms, "", blsag_verify_percent
    );
    println!(
        "│ Compact Sign│ {:<10} │ {:<10} │ {:<9.0}% │",
        compact_sign_ms, compact_size, compact_sign_percent
    );
    println!(
        "│ Compact Ver.│ {:<10} │ {:<10} │ {:<9.0}% │",
        compact_verify_ms, "", compact_verify_percent
    );
    println!("└─────────────┴────────────┴────────────┴────────────┘");

    println!("\n{}", "=== BIG RING DEMO COMPLETE ===".bold().green());
    Ok(())
}

/// Run a demo of nostringer integrated with Nostr keys (npub/nsec format)
fn run_nostr_demo() -> Result<()> {
    println!(
        "\n{}",
        "=== NOSTRINGER WITH NOSTR INTEGRATION DEMO ==="
            .bold()
            .green()
    );
    println!(
        "{}",
        "This demo shows how to use nostringer with Nostr keys in npub/nsec format.".italic()
    );

    println!(
        "\n{}",
        "1. Generating Nostr keys for ring members...".bold()
    );

    // Generate 3 Nostr keys
    let nostr_key1 = Keys::generate();
    let nostr_key2 = Keys::generate();
    let nostr_key3 = Keys::generate();

    // Display Ring Member 1 keys in both formats
    println!("Ring Member 1:");
    println!(
        "  Public Key (hex): {}",
        nostr_key1.public_key().to_hex().cyan()
    );
    println!(
        "  Public Key (npub): {}",
        nostr_key1
            .public_key()
            .to_bech32()
            .expect("Public key to_bech32 should not fail")
            .cyan()
    );
    println!(
        "  Secret Key (hex): {}",
        nostr_key1.secret_key().to_secret_hex().yellow()
    );
    println!(
        "  Secret Key (nsec): {}",
        nostr_key1
            .secret_key()
            .to_bech32()
            .expect("Secret key to_bech32 should not fail")
            .yellow()
    );

    // Display Ring Member 2 keys in both formats
    println!("\nRing Member 2:");
    println!(
        "  Public Key (hex): {}",
        nostr_key2.public_key().to_hex().cyan()
    );
    println!(
        "  Public Key (npub): {}",
        nostr_key2
            .public_key()
            .to_bech32()
            .expect("Public key to_bech32 should not fail")
            .cyan()
    );
    println!(
        "  Secret Key (hex): {}",
        nostr_key2.secret_key().to_secret_hex().yellow()
    );
    println!(
        "  Secret Key (nsec): {}",
        nostr_key2
            .secret_key()
            .to_bech32()
            .expect("Secret key to_bech32 should not fail")
            .yellow()
    );

    // Display Ring Member 3 keys in both formats
    println!("\nRing Member 3:");
    println!(
        "  Public Key (hex): {}",
        nostr_key3.public_key().to_hex().cyan()
    );
    println!(
        "  Public Key (npub): {}",
        nostr_key3
            .public_key()
            .to_bech32()
            .expect("Public key to_bech32 should not fail")
            .cyan()
    );
    println!(
        "  Secret Key (hex): {}",
        nostr_key3.secret_key().to_secret_hex().yellow()
    );
    println!(
        "  Secret Key (nsec): {}",
        nostr_key3
            .secret_key()
            .to_bech32()
            .expect("Secret key to_bech32 should not fail")
            .yellow()
    );

    // Create rings with different formats for the same members
    println!("\n{}", "2. Creating rings with different formats...".bold());

    // Create a ring with hex public keys
    let ring_hex = vec![
        nostr_key1.public_key().to_hex(),
        nostr_key2.public_key().to_hex(),
        nostr_key3.public_key().to_hex(),
    ];

    // Create a ring with npub public keys
    let ring_npub = vec![
        nostr_key1
            .public_key()
            .to_bech32()
            .expect("Public key to_bech32 should not fail"),
        nostr_key2
            .public_key()
            .to_bech32()
            .expect("Public key to_bech32 should not fail"),
        nostr_key3
            .public_key()
            .to_bech32()
            .expect("Public key to_bech32 should not fail"),
    ];

    println!("Created ring with {} members in hex format", ring_hex.len());
    println!(
        "Created ring with {} members in npub format",
        ring_npub.len()
    );

    // Create a message to sign
    println!("\n{}", "3. Creating a message to sign...".bold());
    let message = "This is a message signed by one of the ring members using Nostr keys";
    println!("Message: {}", message.green());

    // Sign the message with hex keys
    println!("\n{}", "4. Signing with hex keys...".bold());
    println!("Signing with Ring Member 2's private key in hex format...");

    let hex_signature = nostringer::sign(
        message.as_bytes(),
        &nostr_key2.secret_key().to_secret_hex(),
        &ring_hex,
        SignatureVariant::Sag,
    )
    .context("Failed to sign with hex keys")?;

    println!("\nSignature created with hex keys:");
    println!("{}", hex_signature.bright_magenta());

    // Verify signatures with different key formats
    println!(
        "\n{}",
        "5. Verifying signatures with different key formats...".bold()
    );

    // Verify hex signature with hex keys
    let is_valid_hex_hex = nostringer::verify(&hex_signature, message.as_bytes(), &ring_hex)
        .context("Failed to verify hex signature with hex keys")?;

    println!(
        "Hex signature verified with hex keys: {}",
        if is_valid_hex_hex {
            "Valid ✓".green().bold()
        } else {
            "Invalid ✗".red().bold()
        }
    );

    // Verify hex signature with npub keys
    let is_valid_hex_npub = nostringer::verify(&hex_signature, message.as_bytes(), &ring_npub)
        .context("Failed to verify hex signature with npub keys")?;

    println!(
        "Hex signature verified with npub keys: {}",
        if is_valid_hex_npub {
            "Valid ✓".green().bold()
        } else {
            "Invalid ✗".red().bold()
        }
    );

    // Cross-format mixing test
    println!(
        "\n{}",
        "6. Testing with mixed key formats in ring...".bold()
    );

    // Create a ring with mixed formats (hex and npub)
    let ring_mixed = vec![
        nostr_key1.public_key().to_hex(),
        nostr_key2
            .public_key()
            .to_bech32()
            .expect("Public key to_bech32 should not fail"),
        nostr_key3.public_key().to_hex(),
    ];

    println!(
        "Created mixed format ring with {} members",
        ring_mixed.len()
    );

    // Verify the mixed ring signature
    let is_valid_mixed = nostringer::verify(&hex_signature, message.as_bytes(), &ring_mixed)
        .context("Failed to verify signature with mixed format ring")?;

    println!(
        "Mixed format ring verification: {}",
        if is_valid_mixed {
            "Valid ✓".green().bold()
        } else {
            "Invalid ✗".red().bold()
        }
    );

    // Explanation section
    println!("\n{}", "ABOUT NOSTR INTEGRATION:".bold().yellow());
    println!("1. Key Format Support:");
    println!("   - nostringer now seamlessly supports Nostr's bech32 key formats:");
    println!("     * npub1... - Nostr public keys (bech32 encoded)");
    println!("     * nsec1... - Nostr private keys (bech32 encoded)");
    println!("   - Original hex format is still fully supported");
    println!("   - Mixed formats work in the same ring");

    println!("\n2. Benefits:");
    println!("   - Direct integration with Nostr applications");
    println!("   - No manual conversion between formats needed");
    println!("   - Human-friendly key format with error detection");
    println!("   - Compatible with existing Nostr tools and libraries");

    println!("\n3. Implementation Details:");
    println!("   - Automatic format detection based on prefix");
    println!("   - Transparent conversion between formats");
    println!("   - Error handling for invalid keys");
    println!("   - Compact signatures work with all key formats");

    println!("\n4. Use Cases:");
    println!("   - Anonymous group signatures for Nostr events");
    println!("   - Unlinkable voting systems on Nostr");
    println!("   - Privacy-preserving Nostr applications");
    println!("   - Group attestations with plausible deniability");

    println!(
        "\n{}",
        "=== NOSTR INTEGRATION DEMO COMPLETE ===".bold().green()
    );
    Ok(())
}

fn parse_keys_list(list: &str) -> Result<Vec<String>> {
    list.split(',')
        .map(|s| s.trim().to_string())
        .collect::<Vec<String>>()
        .into_iter()
        .filter(|s| !s.is_empty())
        .map(|s| {
            if s.len() < 64 {
                Err(anyhow!("Invalid key format: {} (too short)", s))
            } else {
                Ok(s)
            }
        })
        .collect()
}
