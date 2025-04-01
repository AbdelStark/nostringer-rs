/// This example demonstrates how to use nostringer with the nostr crate
/// to create anonymous ring signatures that can be included in nostr events.
///
/// The example shows:
/// 1. Generating keys using both nostr and nostringer
/// 2. Creating a ring signature using nostringer's sign function
/// 3. Verifying a ring signature
/// 4. Including a ring signature in a nostr event
/// 5. Using both hex and bech32 (npub/nsec) formats
use nostr::prelude::*;
use nostringer::{sign, verify, SignatureVariant};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("=== NOSTRINGER WITH NOSTR INTEGRATION EXAMPLE ===\n");

    // 1. Generate keys using nostr crate first
    println!("Generating keys using nostr crate...");
    let nostr_key1 = Keys::generate();
    let nostr_key2 = Keys::generate();
    let nostr_key3 = Keys::generate();

    // Print public and secret keys in both formats (hex and bech32)
    println!("Nostr key formats available for signing and verification:");
    println!("  Key 1 Public (hex): {}", nostr_key1.public_key().to_hex());
    println!(
        "  Key 1 Public (npub): {}",
        nostr_key1.public_key().to_bech32()?
    );
    println!(
        "  Key 1 Secret (hex): {}",
        nostr_key1.secret_key().to_secret_hex()
    );
    println!(
        "  Key 1 Secret (nsec): {}",
        nostr_key1.secret_key().to_bech32()?
    );

    println!("  Key 2 Public (hex): {}", nostr_key2.public_key().to_hex());
    println!(
        "  Key 2 Public (npub): {}",
        nostr_key2.public_key().to_bech32()?
    );
    println!(
        "  Key 2 Secret (hex): {}",
        nostr_key2.secret_key().to_secret_hex()
    );
    println!(
        "  Key 2 Secret (nsec): {}",
        nostr_key2.secret_key().to_bech32()?
    );

    println!("  Key 3 Public (hex): {}", nostr_key3.public_key().to_hex());
    println!(
        "  Key 3 Public (npub): {}",
        nostr_key3.public_key().to_bech32()?
    );

    // 3. Create 2 rings: one with hex keys and one with npub keys
    println!("\nCreating two rings with the same members but different formats...");
    let ring_hex = vec![
        nostr_key1.public_key().to_hex(),
        nostr_key2.public_key().to_hex(),
        nostr_key3.public_key().to_hex(),
    ];

    let ring_npub = vec![
        nostr_key1.public_key().to_bech32()?,
        nostr_key2.public_key().to_bech32()?,
        nostr_key3.public_key().to_bech32()?,
    ];

    // 4. Create a message (could be a nostr event id or content)
    let message = "This is a message signed using nostringer integrated with nostr events";
    println!("\nMessage to sign: {}", message);

    // 5. Sign the message with key 2 (using hex secret key and hex public keys)
    println!("\nSigning message with key 2 using SAG variant (hex format)...");
    let signature_hex = sign(
        message.as_bytes(),
        &nostr_key2.secret_key().to_secret_hex(),
        &ring_hex,
        SignatureVariant::Sag,
    )?;

    println!("Generated signature using hex keys:");
    println!("{}", signature_hex);

    // 6. Sign the same message with key 2 (using nsec secret key and npub keys)
    println!("\nSigning message with key 2 using SAG variant (bech32 format)...");
    let signature_bech32 = sign(
        message.as_bytes(),
        &nostr_key2.secret_key().to_bech32()?,
        &ring_npub,
        SignatureVariant::Sag,
    )?;

    println!("Generated signature using bech32 keys:");
    println!("{}", signature_bech32);

    // 7. Verify both signatures
    println!("\nVerifying signatures...");
    let is_valid_hex = verify(&signature_hex, message.as_bytes(), &ring_hex)?;
    let is_valid_bech32 = verify(&signature_bech32, message.as_bytes(), &ring_npub)?;
    let is_valid_mixed = verify(&signature_hex, message.as_bytes(), &ring_npub)?;

    println!("Signature from hex keys valid: {}", is_valid_hex);
    println!("Signature from bech32 keys valid: {}", is_valid_bech32);
    println!(
        "Cross-format verification (hex signature with npub keys): {}",
        is_valid_mixed
    );

    assert!(is_valid_hex && is_valid_bech32 && is_valid_mixed);

    // 8. Create a Nostr event with the ring signature
    println!(
        "\nDemonstrating how to use with Nostr: Creating a Nostr event with the ring signature..."
    );
    let event_content = format!(
        r#"{{
        "message": "{}",
        "ring_members": [
            "{}",
            "{}",
            "{}"
        ],
        "ring_signature": "{}"
    }}"#,
        message,
        nostr_key1.public_key().to_bech32()?,
        nostr_key2.public_key().to_bech32()?,
        nostr_key3.public_key().to_bech32()?,
        signature_hex
    );

    let event: Event = EventBuilder::text_note(event_content).sign_with_keys(&nostr_key1)?;

    println!("Nostr event created with id: {}", event.id);

    // 9. Show how this could be used in a Nostr client
    println!("\nJSON representation for sending to a Nostr relay:");
    let client_message = ClientMessage::event(event);
    // Pretty print the JSON
    let pretty_json = serde_json::to_string_pretty(&client_message)?;
    println!("{}", pretty_json);

    // In a real application, you would now:
    println!("\nIn a real application, you would now:");
    println!(" 1. Send this event to Nostr relays");
    println!(" 2. Other users could verify the ring signature contained in the event");
    println!(" 3. They would know that one of the ring members signed it, but not which one");
    println!(
        " 4. Users could provide either hex or npub formats of the public keys for verification"
    );

    println!("\nExample completed successfully!");
    Ok(())
}
