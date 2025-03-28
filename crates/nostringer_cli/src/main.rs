use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use nostringer::{
    generate_keypair_hex, generate_keypairs, get_public_keys, key_images_match, sign,
    sign_blsag_hex, types::KeyImage, verify, verify_blsag_hex, KeyPairHex, RingSignature,
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

        /// Optional: File path to save the signature to (as JSON)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Verify a ring signature
    Verify {
        /// The message that was signed (as a string)
        #[arg(short, long)]
        message: String,

        /// The c0 value from the signature
        #[arg(long)]
        c0: String,

        /// Comma-separated list of s values from the signature
        #[arg(short, long)]
        s_values: String,

        /// A comma-separated list of public keys in the ring
        #[arg(short, long)]
        ring: String,
    },

    /// Run a complete demo of the ring signature process
    Demo,

    /// Run a demo of the linkable bLSAG ring signature variant
    BlsagDemo,
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
            output,
        } => {
            let ring_pubkeys = parse_keys_list(ring)?;
            let signature = sign(message.as_bytes(), private_key, &ring_pubkeys)
                .context("Failed to create signature")?;

            display_signature(&signature, message, &ring_pubkeys);

            if let Some(output_path) = output {
                save_signature(&signature, output_path)?;
                println!(
                    "\n{} Signature saved to {}",
                    "✓".green().bold(),
                    output_path.display().to_string().cyan()
                );
            }
        }

        Commands::Verify {
            message,
            c0,
            s_values,
            ring,
        } => {
            let ring_pubkeys = parse_keys_list(ring)?;
            let s_values = parse_keys_list(s_values)?;
            let signature = RingSignature {
                c0: c0.clone(),
                s: s_values,
            };

            let is_valid = verify(&signature, message.as_bytes(), &ring_pubkeys)
                .context("Failed to verify signature")?;

            if is_valid {
                println!("\n{} {}", "✓".green().bold(), "Signature is valid!".green());
            } else {
                println!("\n{} {}", "✗".red().bold(), "Signature is invalid!".red());
            }
        }

        Commands::Demo => {
            run_demo()?;
        }

        Commands::BlsagDemo => {
            run_blsag_demo()?;
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

    let signature = sign(message.as_bytes(), &keypair2.private_key_hex, &ring_pubkeys)
        .context("Failed to create signature")?;

    println!("\nGenerated Signature:");
    println!("  c0: {}", signature.c0.bright_magenta());
    println!("  s values:");
    for (i, s) in signature.s.iter().enumerate() {
        println!("    [{}]: {}", i, s.bright_magenta());
    }

    println!("\n{}", "4. Verifying the signature...".bold());
    println!("Can we verify who signed it? No, just that it was someone in the ring.");

    let is_valid = verify(&signature, message.as_bytes(), &ring_pubkeys)
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

    let is_tampered_valid = verify(&signature, tampered_message.as_bytes(), &ring_pubkeys)
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
    let compromised_signature = sign(
        message.as_bytes(),
        &non_ring_member_keypair.private_key_hex,
        &compromised_ring,
    )
    .context("Failed to create compromised signature")?;

    println!(
        "\n{}",
        "7. Verifying the signature with the original ring (should fail)".bold()
    );
    let error_thrown = verify(&compromised_signature, message.as_bytes(), &ring_pubkeys).is_err();

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

    let (signature1, key_image1_hex) =
        sign_blsag_hex(message1.as_bytes(), &signer.private_key_hex, &ring_pubkeys)
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

    let (signature2, key_image2_hex) =
        sign_blsag_hex(message2.as_bytes(), &signer.private_key_hex, &ring_pubkeys)
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

fn display_signature(signature: &RingSignature, message: &str, ring: &[String]) {
    println!("\n{}", "Message:".bold());
    println!("  {}", message.green());

    println!("\n{}", "Ring Members:".bold());
    for (i, key) in ring.iter().enumerate() {
        println!("  [{}]: {}", i, key.cyan());
    }

    println!("\n{}", "Generated Signature:".bold());
    println!("  c0: {}", signature.c0.bright_magenta());
    println!("  s values:");
    for (i, s) in signature.s.iter().enumerate() {
        println!("    [{}]: {}", i, s.bright_magenta());
    }
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

fn save_signature(signature: &RingSignature, path: &Path) -> Result<()> {
    let json = serde_json::json!({
        "c0": signature.c0,
        "s": signature.s,
    });
    let content =
        serde_json::to_string_pretty(&json).context("Failed to serialize signature to JSON")?;
    fs::write(path, content).with_context(|| format!("Failed to write to {}", path.display()))?;
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
