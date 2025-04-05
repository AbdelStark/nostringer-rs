use nostringer::{
    blsag::{key_images_match, sign_blsag_hex, verify_blsag_hex},
    generate_keypair_hex, generate_keypairs, get_public_keys,
    sag::{sign, verify},
    types::{Error, KeyImage},
};

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

#[test]
fn test_blsag_sign_verify_round_trip() {
    // 1. Setup Ring
    let ring_size = 3;
    let keypairs = generate_keypairs(ring_size, "compressed"); // Use any valid format
    let ring_pubkeys_hex = get_public_keys(&keypairs);
    let linkability_flag = None; // No linkability needed for this test

    // 2. Choose Signer & Message
    let signer_index = 1;
    let signer_kp = &keypairs[signer_index];
    let message = b"Test message for bLSAG round trip";

    // 3. Sign using bLSAG (hex version)
    let sign_result = sign_blsag_hex(
        message,
        &signer_kp.private_key_hex,
        &ring_pubkeys_hex,
        &linkability_flag,
    );
    assert!(
        sign_result.is_ok(),
        "bLSAG signing failed: {:?}",
        sign_result.err()
    );
    let (signature, key_image_hex) = sign_result.unwrap();

    // Basic structure checks
    assert_eq!(signature.s.len(), ring_size);

    // 4. Verify the valid signature
    let verification_result =
        verify_blsag_hex(&signature, &key_image_hex, message, &ring_pubkeys_hex);
    assert!(
        verification_result.is_ok(),
        "Verification result errored: {:?}",
        verification_result.err()
    );
    assert!(verification_result.unwrap(), "Valid bLSAG signature failed");
}

#[test]
fn test_blsag_global_linkability() {
    // 1. Setup
    let keypairs = generate_keypairs(4, "compressed");
    let ring = get_public_keys(&keypairs);
    let signer_kp = &keypairs[1]; // Choose a signer
    let message1 = b"First message";
    let message2 = b"Second message";
    let linkability_flag = None; // Enable global linkability

    // 2. Sign two different messages with the SAME key
    let (sig1, ki1_hex) = sign_blsag_hex(
        message1,
        &signer_kp.private_key_hex,
        &ring,
        &linkability_flag,
    )
    .unwrap();
    let (sig2, ki2_hex) = sign_blsag_hex(
        message2,
        &signer_kp.private_key_hex,
        &ring,
        &linkability_flag,
    )
    .unwrap();

    // 3. Verify both signatures are valid
    assert!(verify_blsag_hex(&sig1, &ki1_hex, message1, &ring).unwrap());
    assert!(verify_blsag_hex(&sig2, &ki2_hex, message2, &ring).unwrap());

    // 4. Check key images MATCH
    assert_eq!(
        ki1_hex, ki2_hex,
        "Key images should match for the same signer"
    );
    let ki1 = KeyImage::from_hex(&ki1_hex).unwrap();
    let ki2 = KeyImage::from_hex(&ki2_hex).unwrap();
    assert!(key_images_match(&ki1, &ki2));

    // 5. Sign message 1 with a DIFFERENT key
    let different_signer_kp = &keypairs[2];
    let (sig3, ki3_hex) = sign_blsag_hex(
        message1,
        &different_signer_kp.private_key_hex,
        &ring,
        &linkability_flag,
    )
    .unwrap();

    // 6. Verify this signature is also valid
    assert!(verify_blsag_hex(&sig3, &ki3_hex, message1, &ring).unwrap());

    // 7. Check key images DO NOT MATCH
    assert_ne!(
        ki1_hex, ki3_hex,
        "Key images should differ for different signers"
    );
    let ki3 = KeyImage::from_hex(&ki3_hex).unwrap();
    assert!(!key_images_match(&ki1, &ki3));
}

#[test]
fn test_blsag_local_linkability() {
    // 1. Setup
    let keypairs = generate_keypairs(4, "compressed");
    let ring = get_public_keys(&keypairs);
    let signer_kp = &keypairs[1]; // Choose a signer
    let message1 = b"First message";
    let message2 = b"Second message";
    let linkability_flag = Some("Some random flag".to_string()); // Enable local linkability

    // 2. Sign two different messages with the SAME key
    let (sig1, ki1_hex) = sign_blsag_hex(
        message1,
        &signer_kp.private_key_hex,
        &ring,
        &linkability_flag,
    )
    .unwrap();
    let (sig2, ki2_hex) = sign_blsag_hex(
        message2,
        &signer_kp.private_key_hex,
        &ring,
        &linkability_flag,
    )
    .unwrap();

    // 3. Verify both signatures are valid
    assert!(verify_blsag_hex(&sig1, &ki1_hex, message1, &ring).unwrap());
    assert!(verify_blsag_hex(&sig2, &ki2_hex, message2, &ring).unwrap());

    // 4. Check key images MATCH
    assert_eq!(
        ki1_hex, ki2_hex,
        "Key images should match for the same signer"
    );
    let ki1 = KeyImage::from_hex(&ki1_hex).unwrap();
    let ki2 = KeyImage::from_hex(&ki2_hex).unwrap();
    assert!(key_images_match(&ki1, &ki2));

    // 5. Sign message 1 with a DIFFERENT key
    let different_signer_kp = &keypairs[2];
    let (sig3, ki3_hex) = sign_blsag_hex(
        message1,
        &different_signer_kp.private_key_hex,
        &ring,
        &linkability_flag,
    )
    .unwrap();

    // 6. Verify this signature is also valid
    assert!(verify_blsag_hex(&sig3, &ki3_hex, message1, &ring).unwrap());

    // 7. Check key images DO NOT MATCH
    assert_ne!(
        ki1_hex, ki3_hex,
        "Key images should differ for different signers"
    );
    let ki3 = KeyImage::from_hex(&ki3_hex).unwrap();
    assert!(!key_images_match(&ki1, &ki3));
}

#[test]
fn test_blsag_verification_fail_tampered_message() {
    let keypairs = generate_keypairs(3, "xonly");
    let ring = get_public_keys(&keypairs);
    let signer_kp = &keypairs[0];
    let message = b"Original BLSAG message";
    let linkability_flag = None;

    // Sign
    let (sig, ki_hex) = sign_blsag_hex(
        message,
        &signer_kp.private_key_hex,
        &ring,
        &linkability_flag,
    )
    .unwrap();

    // Verify with tampered message
    let tampered_message = b"Tampered BLSAG message";
    let is_valid = verify_blsag_hex(&sig, &ki_hex, tampered_message, &ring)
        .expect("Verification process completed");
    assert!(
        !is_valid,
        "BLSAG signature should be invalid for tampered message"
    );
}

#[test]
fn test_blsag_verification_fail_wrong_key_image() {
    let keypairs = generate_keypairs(3, "compressed");
    let ring = get_public_keys(&keypairs);
    let signer_kp = &keypairs[0];
    let message = b"Message for key image test";
    let linkability_flag = None;

    // Sign
    let (sig, _ki_hex) = sign_blsag_hex(
        message,
        &signer_kp.private_key_hex,
        &ring,
        &linkability_flag,
    )
    .unwrap();

    // Generate a key image from a DIFFERENT key
    let different_kp = &keypairs[1];
    let (_, wrong_ki_hex) = sign_blsag_hex(
        message,
        &different_kp.private_key_hex,
        &ring,
        &linkability_flag,
    )
    .unwrap();

    // Verify with the wrong key image (should fail)
    let is_valid = verify_blsag_hex(&sig, &wrong_ki_hex, message, &ring)
        .expect("Verification process completed");
    assert!(
        !is_valid,
        "BLSAG signature should be invalid with wrong key image"
    );
}

#[test]
fn test_blsag_verification_fail_invalid_key_image_format() {
    let keypairs = generate_keypairs(3, "compressed");
    let ring = get_public_keys(&keypairs);
    let signer_kp = &keypairs[0];
    let message = b"Message for key image test";
    let linkability_flag = None;

    // Sign
    let (sig, _ki_hex) = sign_blsag_hex(
        message,
        &signer_kp.private_key_hex,
        &ring,
        &linkability_flag,
    )
    .unwrap();

    // Verify with an invalid hex string for key image
    let invalid_ki_hex = "invalid-hex-string";
    let result = verify_blsag_hex(&sig, invalid_ki_hex, message, &ring);
    // Should fail with HexDecode error from KeyImage::from_hex
    assert!(matches!(result, Err(Error::HexDecode(_))));

    // Verify with a valid hex but incorrect length
    let short_ki_hex = "02aabbcc";
    let result_short = verify_blsag_hex(&sig, short_ki_hex, message, &ring);
    // Should fail with PublicKeyFormat error from hex_to_point inside KeyImage::from_hex
    assert!(matches!(result_short, Err(Error::PublicKeyFormat(_))));
}

// TODO: Add test case for BLSAG verify failure if key image point is identity
// TODO: Add test case for BLSAG verify failure if key image is not torsion-free (when possible)
