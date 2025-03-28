use nostringer::{Error, generate_keypair_hex, generate_keypairs, get_public_keys, sign, verify};

#[test]
fn test_sign_verify_round_trip_xonly() {
    let keypairs = generate_keypairs(3, "xonly");
    let ring_pubkeys_hex = get_public_keys(&keypairs);
    let signer_index = 1; // Sign with the second key
    let signer_kp = &keypairs[signer_index];
    let message = b"Test message for xonly keys";

    // Sign
    let signature =
        sign(message, &signer_kp.private_key_hex, &ring_pubkeys_hex).expect("Signing failed");

    // Verify
    let is_valid = verify(&signature, message, &ring_pubkeys_hex).expect("Verification failed");
    assert!(is_valid, "Signature should be valid");
}

#[test]
fn test_sign_verify_round_trip_compressed() {
    let keypairs = generate_keypairs(5, "compressed"); // Use a different ring size
    let ring_pubkeys_hex = get_public_keys(&keypairs);
    let signer_index = 3; // Sign with the fourth key
    let signer_kp = &keypairs[signer_index];
    let message = b"Another test with compressed keys!";

    // Sign
    let signature =
        sign(message, &signer_kp.private_key_hex, &ring_pubkeys_hex).expect("Signing failed");

    // Verify
    let is_valid = verify(&signature, message, &ring_pubkeys_hex).expect("Verification failed");
    assert!(is_valid, "Signature should be valid");
}

#[test]
fn test_sign_verify_round_trip_uncompressed() {
    let keypairs = generate_keypairs(2, "uncompressed"); // Minimum ring size
    let ring_pubkeys_hex = get_public_keys(&keypairs);
    let signer_index = 0; // Sign with the first key
    let signer_kp = &keypairs[signer_index];
    let message = b"Testing uncompressed keys";

    // Sign
    let signature =
        sign(message, &signer_kp.private_key_hex, &ring_pubkeys_hex).expect("Signing failed");

    // Verify
    let is_valid = verify(&signature, message, &ring_pubkeys_hex).expect("Verification failed");
    assert!(is_valid, "Signature should be valid");
}

#[test]
fn test_sign_verify_mixed_key_formats() {
    // This might be less common but should work if hex_to_point handles all formats
    let kp1 = generate_keypair_hex("xonly");
    let kp2 = generate_keypair_hex("compressed");
    let kp3 = generate_keypair_hex("uncompressed");

    let keypairs = vec![kp1, kp2, kp3];
    let ring_pubkeys_hex = get_public_keys(&keypairs);
    let signer_index = 1; // Sign with compressed key
    let signer_kp = &keypairs[signer_index];
    let message = b"Mixing key formats in the ring";

    // Sign
    let signature =
        sign(message, &signer_kp.private_key_hex, &ring_pubkeys_hex).expect("Signing failed");

    // Verify
    let is_valid = verify(&signature, message, &ring_pubkeys_hex).expect("Verification failed");
    assert!(is_valid, "Signature should be valid with mixed formats");
}

#[test]
fn test_verification_fail_tampered_message() {
    let keypairs = generate_keypairs(3, "compressed");
    let ring_pubkeys_hex = get_public_keys(&keypairs);
    let signer_kp = &keypairs[0];
    let message = b"Original content";

    // Sign
    let signature =
        sign(message, &signer_kp.private_key_hex, &ring_pubkeys_hex).expect("Signing failed");

    // Verify with tampered message
    let tampered_message = b"Tampered content";
    let is_valid = verify(&signature, tampered_message, &ring_pubkeys_hex)
        .expect("Verification process completed");
    assert!(
        !is_valid,
        "Signature should be invalid for tampered message"
    );
}

#[test]
fn test_verification_fail_wrong_ring() {
    let keypairs1 = generate_keypairs(3, "xonly");
    let ring1 = get_public_keys(&keypairs1);
    let signer_kp = &keypairs1[0];
    let message = b"Message for ring 1";

    // Sign with ring 1
    let signature = sign(message, &signer_kp.private_key_hex, &ring1).expect("Signing failed");

    // Create a different ring
    let keypairs2 = generate_keypairs(3, "xonly"); // Different keys
    let ring2 = get_public_keys(&keypairs2);

    // Verify signature from ring 1 against ring 2 (should fail)
    let is_valid = verify(&signature, message, &ring2).expect("Verification process completed");
    assert!(!is_valid, "Signature should be invalid for the wrong ring");

    // Verify with a ring of different size (should error or return false)
    let keypairs3 = generate_keypairs(4, "xonly"); // Different keys
    let ring3 = get_public_keys(&keypairs3);
    let result = verify(&signature, message, &ring3);
    // Expect InvalidSignatureFormat because s.len() != ring.len()
    assert!(matches!(result, Err(Error::InvalidSignatureFormat)));
}

#[test]
fn test_sign_fail_signer_not_in_ring() {
    let keypairs = generate_keypairs(3, "compressed");
    let ring = get_public_keys(&keypairs);
    let outsider_kp = generate_keypair_hex("compressed"); // Key not in the ring
    let message = b"Attempt by outsider";

    // Try signing with the outsider key against the ring
    let result = sign(message, &outsider_kp.private_key_hex, &ring);
    assert!(matches!(result, Err(Error::SignerNotInRing)));
}

#[test]
fn test_sign_fail_small_ring() {
    let keypairs = generate_keypairs(1, "xonly"); // Only one member
    let ring = get_public_keys(&keypairs);
    let signer_kp = &keypairs[0];
    let message = b"Ring too small";

    let result = sign(message, &signer_kp.private_key_hex, &ring);
    assert!(matches!(result, Err(Error::RingTooSmall(1))));
}

#[test]
fn test_nostr_event_simulation() {
    // Mimic the structure of the TS test `Anonymous event creation`

    // 1. Setup ring
    let developers = generate_keypairs(3, "xonly");
    let developer_ring = get_public_keys(&developers);

    // 2. Choose author
    let author_index = 1;
    let author = &developers[author_index];

    // 3. Create simulated event data (just the parts needed for signing)
    let event_pubkey = "anonymous"; // Placeholder
    let created_at = 1711609836; // Example timestamp (replace with actual if needed: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs())
    let kind = 1001;
    let tags_vec = vec![
        vec!["g".to_string(), "reviews".to_string()],
        // In Rust, we'd construct the ring tag like this:
        vec!["ring".to_string()]
            .into_iter()
            .chain(developer_ring.iter().cloned())
            .collect::<Vec<String>>(),
    ];
    let content = "This app is great but has some privacy concerns.";

    // 4. Serialize message to sign (matching TS JSON stringify approach)
    // Using serde_json would be more robust, but for direct compatibility test:
    let tags_json_str = format!(
        "[{}]",
        tags_vec
            .iter()
            .map(|tag| format!(
                "[{}]",
                tag.iter()
                    .map(|s| format!("\"{}\"", s))
                    .collect::<Vec<_>>()
                    .join(",")
            ))
            .collect::<Vec<_>>()
            .join(",")
    );
    let message_str = format!(
        "[0,\"{}\",{},{},{},\"{}\"]",
        event_pubkey,
        created_at,
        kind,
        tags_json_str, // Serialize tags carefully
        content
    );
    let message_bytes = message_str.as_bytes();

    // 5. Sign
    let signature = sign(message_bytes, &author.private_key_hex, &developer_ring)
        .expect("Signing failed in Nostr sim");

    // 6. Verify (self-check)
    let is_valid = verify(&signature, message_bytes, &developer_ring)
        .expect("Verification failed in Nostr sim");
    assert!(is_valid);

    // 7. Tamper check (modify content)
    let tampered_content = "Modified content";
    let tampered_message_str = format!(
        "[0,\"{}\",{},{},{},\"{}\"]",
        event_pubkey,
        created_at,
        kind,
        tags_json_str, // Use same tags
        tampered_content
    );
    let tampered_message_bytes = tampered_message_str.as_bytes();
    let is_tampered_valid = verify(&signature, tampered_message_bytes, &developer_ring)
        .expect("Tampered verification process failed");
    assert!(!is_tampered_valid, "Tampered message should not verify");
}
