use criterion::{Criterion, black_box, criterion_group, criterion_main};
use nostringer_rs::{sign, verify};
use rand_core::{OsRng, RngCore};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

fn bench_ecdsa_sign(c: &mut Criterion) {
    let secp = Secp256k1::new();
    let mut rng = OsRng;

    // Generate a key pair
    let mut key_bytes = [0u8; 32];
    rng.fill_bytes(&mut key_bytes);
    let secret_key = SecretKey::from_slice(&key_bytes).unwrap();
    let _public_key = PublicKey::from_secret_key(&secp, &secret_key);

    // Messages of different lengths
    let short_msg = b"Short message for testing";
    let medium_msg =
        b"This is a medium length message that will be used for ECDSA signature benchmarking";
    let long_msg = b"This is a much longer message that will be used to benchmark ECDSA signature generation and verification. \
                    When testing cryptographic operations, it's important to test with various input sizes to ensure \
                    consistent performance across different use cases. This message is significantly longer than the others.";

    // Benchmark signing with different message sizes
    let mut group = c.benchmark_group("ECDSA - Signing");

    group.bench_function("short message", |b| {
        b.iter(|| sign(black_box(short_msg), key_bytes))
    });

    group.bench_function("medium message", |b| {
        b.iter(|| sign(black_box(medium_msg), key_bytes))
    });

    group.bench_function("long message", |b| {
        b.iter(|| sign(black_box(long_msg), key_bytes))
    });

    group.finish();
}

fn bench_ecdsa_verify(c: &mut Criterion) {
    let secp = Secp256k1::new();
    let mut rng = OsRng;

    // Generate a key pair
    let mut key_bytes = [0u8; 32];
    rng.fill_bytes(&mut key_bytes);
    let secret_key = SecretKey::from_slice(&key_bytes).unwrap();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let public_key_bytes = public_key.serialize();

    // Messages of different lengths
    let short_msg = b"Short message for testing";
    let medium_msg =
        b"This is a medium length message that will be used for ECDSA signature benchmarking";
    let long_msg = b"This is a much longer message that will be used to benchmark ECDSA signature generation and verification. \
                    When testing cryptographic operations, it's important to test with various input sizes to ensure \
                    consistent performance across different use cases. This message is significantly longer than the others.";

    // Create signatures for each message
    let short_sig = sign(short_msg, key_bytes).unwrap().serialize_compact();
    let medium_sig = sign(medium_msg, key_bytes).unwrap().serialize_compact();
    let long_sig = sign(long_msg, key_bytes).unwrap().serialize_compact();

    // Benchmark verification with different message sizes
    let mut group = c.benchmark_group("ECDSA - Verification");

    group.bench_function("short message", |b| {
        b.iter(|| verify(black_box(short_msg), short_sig, public_key_bytes))
    });

    group.bench_function("medium message", |b| {
        b.iter(|| verify(black_box(medium_msg), medium_sig, public_key_bytes))
    });

    group.bench_function("long message", |b| {
        b.iter(|| verify(black_box(long_msg), long_sig, public_key_bytes))
    });

    group.finish();
}

criterion_group!(benches, bench_ecdsa_sign, bench_ecdsa_verify);
criterion_main!(benches);
