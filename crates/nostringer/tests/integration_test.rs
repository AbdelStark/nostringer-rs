use k256::ProjectivePoint;
use nostringer::{
    generate_keypair_hex, generate_keypairs, get_public_keys, key_images_match, sign,
    sign_blsag_hex,
    types::{BlsagSignatureBinary, KeyImage},
    utils::hex_to_point,
    verify, verify_blsag_binary, verify_blsag_hex, Error,
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

    // 2. Choose Signer & Message
    let signer_index = 1;
    let signer_kp = &keypairs[signer_index];
    let message = b"Test message for bLSAG round trip";

    // 3. Sign using bLSAG (hex version)
    let sign_result = sign_blsag_hex(message, &signer_kp.private_key_hex, &ring_pubkeys_hex);
    assert!(
        sign_result.is_ok(),
        "bLSAG signing failed: {:?}",
        sign_result.err()
    );
    let (signature, key_image_hex) = sign_result.unwrap();

    // Basic structure checks
    assert_eq!(signature.c0.len(), 64, "c0 hex length mismatch");
    assert_eq!(signature.s.len(), ring_size, "s array length mismatch");
    signature.s.iter().for_each(|s_val| {
        assert_eq!(s_val.len(), 64, "s element hex length mismatch");
    });
    assert_eq!(
        key_image_hex.len(),
        66,
        "Key image hex length mismatch (should be compressed point)"
    ); // Key image is point -> compressed hex

    // 4. Verify using bLSAG (hex version)
    let verify_result = verify_blsag_hex(&signature, &key_image_hex, message, &ring_pubkeys_hex);
    assert!(
        verify_result.is_ok(),
        "bLSAG verification failed: {:?}",
        verify_result.err()
    );
    assert!(verify_result.unwrap(), "bLSAG signature failed to verify");

    // 5. Verification should fail with tampered message
    let tampered_message = b"This message has been tampered with";
    let verify_tampered_msg = verify_blsag_hex(
        &signature,
        &key_image_hex,
        tampered_message,
        &ring_pubkeys_hex,
    );
    assert!(
        verify_tampered_msg.is_ok(),
        "Tampered msg verification failed: {:?}",
        verify_tampered_msg.err()
    );
    assert!(
        !verify_tampered_msg.unwrap(),
        "bLSAG verification should fail for tampered message"
    );

    // 6. Verification should fail with wrong ring
    let other_keypairs = generate_keypairs(ring_size, "compressed");
    let wrong_ring = get_public_keys(&other_keypairs);
    let verify_wrong_ring = verify_blsag_hex(&signature, &key_image_hex, message, &wrong_ring);
    assert!(
        verify_wrong_ring.is_ok(),
        "Wrong ring verification failed: {:?}",
        verify_wrong_ring.err()
    );
    assert!(
        !verify_wrong_ring.unwrap(),
        "bLSAG verification should fail for wrong ring"
    );
}

#[test]
fn test_blsag_linkability_and_key_image_comparison() {
    // 1. Setup Ring
    let ring_size = 4; // Use a slightly larger ring
    let keypairs = generate_keypairs(ring_size, "xonly");
    let ring_pubkeys_hex = get_public_keys(&keypairs);

    // 2. Define Messages
    let message1 = b"First transaction approval";
    let message2 = b"Second transaction approval by same user";
    let message3 = b"Completely different action by another user";

    // 3. Choose Signers
    let signer1_index = 1;
    let signer1_kp = &keypairs[signer1_index]; // Signer for msg 1 & 2

    let signer2_index = 3;
    let signer2_kp = &keypairs[signer2_index]; // Signer for msg 3

    // --- Signature 1 (Signer 1, Message 1) ---
    let (sig1, ki1_hex) = sign_blsag_hex(message1, &signer1_kp.private_key_hex, &ring_pubkeys_hex)
        .expect("Signing 1 failed");
    let verify1 =
        verify_blsag_hex(&sig1, &ki1_hex, message1, &ring_pubkeys_hex).expect("Verifying 1 failed");
    assert!(verify1, "Signature 1 should be valid");
    // Convert hex to KeyImage struct for comparison using helper
    let ki1 = KeyImage::from_hex(&ki1_hex).expect("Parsing key image 1 failed");

    // --- Signature 2 (Signer 1, Message 2) ---
    // Use the SAME signer (signer1_kp) but DIFFERENT message
    let (sig2, ki2_hex) = sign_blsag_hex(message2, &signer1_kp.private_key_hex, &ring_pubkeys_hex)
        .expect("Signing 2 failed");
    let verify2 =
        verify_blsag_hex(&sig2, &ki2_hex, message2, &ring_pubkeys_hex).expect("Verifying 2 failed");
    assert!(verify2, "Signature 2 should be valid");
    let ki2 = KeyImage::from_hex(&ki2_hex).expect("Parsing key image 2 failed");

    // --- Signature 3 (Signer 2, Message 3) ---
    // Use a DIFFERENT signer (signer2_kp)
    let (sig3, ki3_hex) = sign_blsag_hex(message3, &signer2_kp.private_key_hex, &ring_pubkeys_hex)
        .expect("Signing 3 failed");
    let verify3 =
        verify_blsag_hex(&sig3, &ki3_hex, message3, &ring_pubkeys_hex).expect("Verifying 3 failed");
    assert!(verify3, "Signature 3 should be valid");
    let ki3 = KeyImage::from_hex(&ki3_hex).expect("Parsing key image 3 failed");

    // --- LINKABILITY CHECKS ---

    // A. Check if signatures from the SAME signer produce the SAME key image
    println!("Key Image 1 (Signer 1): {}", ki1_hex);
    println!("Key Image 2 (Signer 1): {}", ki2_hex);
    assert_eq!(
        ki1_hex, ki2_hex,
        "Key images from the same signer (sig1, sig2) should match"
    );
    // Alternatively, use the helper function on the structs:
    assert!(
        key_images_match(&ki1, &ki2),
        "key_images_match should return true for sig1 & sig2"
    );

    // B. Check if signatures from DIFFERENT signers produce DIFFERENT key images
    println!("Key Image 3 (Signer 2): {}", ki3_hex);
    assert_ne!(
        ki1_hex, ki3_hex,
        "Key images from different signers (sig1, sig3) should NOT match"
    );
    assert!(
        !key_images_match(&ki1, &ki3),
        "key_images_match should return false for sig1 & sig3"
    );
    assert_ne!(
        ki2_hex, ki3_hex,
        "Key images from different signers (sig2, sig3) should NOT match"
    );
    assert!(
        !key_images_match(&ki2, &ki3),
        "key_images_match should return false for sig2 & sig3"
    );

    // --- Negative Verification Check ---

    // C. Check that verifying sig1 with key image from sig3 FAILS
    let verify_mismatched_ki = verify_blsag_hex(&sig1, &ki3_hex, message1, &ring_pubkeys_hex);
    assert!(
        verify_mismatched_ki.is_ok(),
        "Verification with mismatched KI failed unexpectedly: {:?}",
        verify_mismatched_ki.err()
    );
    assert!(
        !verify_mismatched_ki.unwrap(),
        "Verification should fail when using wrong key image"
    );
}

#[test]
fn test_blsag_key_image_validation() {
    // More advanced: Test the internal key image checks in verify
    // Requires manually creating potentially invalid key images

    let ring_size = 3;
    let keypairs = generate_keypairs(ring_size, "compressed");
    let ring_pubkeys_hex = get_public_keys(&keypairs);
    let signer_kp = &keypairs[0];
    let message = b"Message for KI validation";

    // Create a valid signature and key image
    let (signature, valid_ki_hex) =
        sign_blsag_hex(message, &signer_kp.private_key_hex, &ring_pubkeys_hex)
            .expect("Signing failed");
    let valid_ki = KeyImage::from_hex(&valid_ki_hex).unwrap();

    // 1. Verify with the valid key image (should pass)
    assert!(verify_blsag_binary(
        &BlsagSignatureBinary::try_from(&signature).unwrap(),
        &valid_ki,
        message,
        &ring_pubkeys_hex
            .iter()
            .map(|s| hex_to_point(s))
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    )
    .unwrap());

    // 2. Create an invalid key image (Identity point)
    let identity_ki = KeyImage::from_point(ProjectivePoint::IDENTITY);
    let verify_identity = verify_blsag_binary(
        &BlsagSignatureBinary::try_from(&signature).unwrap(),
        &identity_ki,
        message,
        &ring_pubkeys_hex
            .iter()
            .map(|s| hex_to_point(s))
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
    );
    // Verification should return Ok(false) because identity KI is invalid
    assert!(verify_identity.is_ok());
    assert!(
        !verify_identity.unwrap(),
        "Verification should fail with identity key image"
    );
}
