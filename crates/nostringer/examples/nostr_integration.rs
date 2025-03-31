/// This example demonstrates how to use nostringer with the nostr crate
/// to create anonymous ring signatures that can be included in nostr events.
///
/// The example shows:
/// 1. Generating keys using both nostr and nostringer
/// 2. Creating a ring signature using nostringer's sign function
/// 3. Verifying a ring signature
/// 4. Including a ring signature in a nostr event
///
/// In a real application, you might want to implement proper conversion between
/// nostr keys and nostringer keys. For simplicity, this example uses separate keys.
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

    // Print public keys in bech32 format
    println!(
        "Nostr Public Key 1: {}",
        nostr_key1.public_key().to_bech32()?
    );
    println!(
        "Nostr Secret Key 1: {}",
        nostr_key1.secret_key().to_secret_hex()
    );
    println!(
        "Nostr Public Key 2: {}",
        nostr_key2.public_key().to_bech32()?
    );
    println!(
        "Nostr Secret Key 2: {}",
        nostr_key2.secret_key().to_secret_hex()
    );
    println!(
        "Nostr Public Key 3: {}",
        nostr_key3.public_key().to_bech32()?
    );
    println!(
        "Nostr Secret Key 3: {}",
        nostr_key3.secret_key().to_secret_hex()
    );

    // 3. Create a ring of public keys
    let ring_pubkeys = vec![
        nostr_key1.public_key().to_hex(),
        nostr_key2.public_key().to_hex(),
        nostr_key3.public_key().to_hex(),
    ];

    // 4. Create a message (could be a nostr event id or content)
    let message = "This is a message signed using nostringer integrated with nostr events";
    println!("\nMessage to sign: {}", message);

    // 5. Sign the message with one of the keys (using keypair2)
    println!("\nSigning message with key 2 using SAG variant...");
    let signature = sign(
        message.as_bytes(),
        nostr_key2.secret_key().to_secret_hex().as_str(),
        &ring_pubkeys,
        SignatureVariant::Sag,
    )?;

    println!("Generated compact signature:");
    println!("{}", signature);

    // 6. Verify the signature
    println!("\nVerifying signature...");
    let is_valid = verify(&signature, message.as_bytes(), &ring_pubkeys)?;

    println!("Signature valid: {}", is_valid);
    assert!(is_valid);

    // 7. Create a Nostr event with the ring signature
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
        nostr_key1.public_key().to_hex(),
        nostr_key2.public_key().to_hex(),
        nostr_key3.public_key().to_hex(),
        signature
    );

    let event: Event = EventBuilder::text_note(event_content).sign_with_keys(&nostr_key1)?;

    println!("Nostr event created with id: {}", event.id);

    // 8. Show how this could be used in a Nostr client
    println!("\nJSON representation for sending to a Nostr relay:");
    let client_message = ClientMessage::event(event);
    println!("{}", client_message.as_json());

    // In a real application, you would now:
    println!("\nIn a real application, you would now:");
    println!(" 1. Send this event to Nostr relays");
    println!(" 2. Other users could verify the ring signature contained in the event");
    println!(" 3. They would know that one of the ring members signed it, but not which one");
    println!(" 4. Applications could implement specialized UIs for ring signature verification");

    println!("\nExample completed successfully!");
    Ok(())
}
