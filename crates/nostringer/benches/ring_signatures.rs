use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use nostringer::{
    blsag::{sign_blsag_hex, verify_blsag_hex},
    generate_keypairs, get_public_keys,
    sag::{sign, verify},
};

// ---- SAG Benchmarks (Standard Unlinkable Ring Signatures) ----

fn bench_sag_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("sag_signature_sign");

    // Benchmark signing with different ring sizes
    for ring_size in [2, 10, 100].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(ring_size),
            ring_size,
            |b, &size| {
                // Setup: Generate keypairs and prepare ring
                let keypairs = generate_keypairs(size, "xonly");
                let ring = get_public_keys(&keypairs);
                let signer_key = &keypairs[0].private_key_hex;
                let message = b"Benchmark signing with different ring sizes";

                // Benchmark the sign function
                b.iter(|| sign(message, signer_key, &ring).unwrap());
            },
        );
    }

    group.finish();
}

fn bench_sag_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("sag_signature_verify");

    // Benchmark verification with different ring sizes
    for ring_size in [2, 10, 100].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(ring_size),
            ring_size,
            |b, &size| {
                // Setup: Generate keypairs, prepare ring, and create signature
                let keypairs = generate_keypairs(size, "xonly");
                let ring = get_public_keys(&keypairs);
                let signer_key = &keypairs[0].private_key_hex;
                let message = b"Benchmark verification with different ring sizes";
                let signature = sign(message, signer_key, &ring).unwrap();

                // Benchmark the verify function
                b.iter(|| verify(&signature, message, &ring).unwrap());
            },
        );
    }

    group.finish();
}

fn bench_sag_sign_and_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("sag_signature_sign_and_verify");

    // Benchmark combined signing and verification with different ring sizes
    for ring_size in [2, 10, 100].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(ring_size),
            ring_size,
            |b, &size| {
                // Setup: Generate keypairs and prepare ring
                let keypairs = generate_keypairs(size, "xonly");
                let ring = get_public_keys(&keypairs);
                let signer_key = &keypairs[0].private_key_hex;
                let message = b"Benchmark combined signing and verification";

                // Benchmark both sign and verify
                b.iter(|| {
                    let signature = sign(message, signer_key, &ring).unwrap();
                    verify(&signature, message, &ring).unwrap()
                });
            },
        );
    }

    group.finish();
}

// ---- BLSAG Benchmarks (Linkable Ring Signatures) ----

fn bench_blsag_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("blsag_signature_sign");

    // Benchmark signing with different ring sizes
    for ring_size in [2, 10, 100].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(ring_size),
            ring_size,
            |b, &size| {
                // Setup: Generate keypairs and prepare ring
                let keypairs = generate_keypairs(size, "xonly");
                let ring = get_public_keys(&keypairs);
                let signer_key = &keypairs[0].private_key_hex;
                let message = b"Benchmark BLSAG signing with different ring sizes";

                // Benchmark the sign_blsag_hex function
                b.iter(|| sign_blsag_hex(message, signer_key, &ring, &None).unwrap());
            },
        );
    }

    group.finish();
}

fn bench_blsag_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("blsag_signature_verify");

    // Benchmark verification with different ring sizes
    for ring_size in [2, 10, 100].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(ring_size),
            ring_size,
            |b, &size| {
                // Setup: Generate keypairs, prepare ring, and create signature
                let keypairs = generate_keypairs(size, "xonly");
                let ring = get_public_keys(&keypairs);
                let signer_key = &keypairs[0].private_key_hex;
                let message = b"Benchmark BLSAG verification with different ring sizes";

                // Create a BLSAG signature and key image
                let (signature, key_image) =
                    sign_blsag_hex(message, signer_key, &ring, &None).unwrap();

                // Benchmark the verify_blsag_hex function
                b.iter(|| verify_blsag_hex(&signature, &key_image, message, &ring).unwrap());
            },
        );
    }

    group.finish();
}

fn bench_blsag_sign_and_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("blsag_signature_sign_and_verify");

    // Benchmark combined signing and verification with different ring sizes
    for ring_size in [2, 10, 100].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(ring_size),
            ring_size,
            |b, &size| {
                // Setup: Generate keypairs and prepare ring
                let keypairs = generate_keypairs(size, "xonly");
                let ring = get_public_keys(&keypairs);
                let signer_key = &keypairs[0].private_key_hex;
                let message = b"Benchmark combined BLSAG signing and verification";

                // Benchmark both sign_blsag_hex and verify_blsag_hex
                b.iter(|| {
                    let (signature, key_image) =
                        sign_blsag_hex(message, signer_key, &ring, &None).unwrap();
                    verify_blsag_hex(&signature, &key_image, message, &ring).unwrap()
                });
            },
        );
    }

    group.finish();
}

// ---- Comparison Benchmark ----

fn bench_sag_vs_blsag(c: &mut Criterion) {
    let mut group = c.benchmark_group("sag_vs_blsag_comparison");
    group.sample_size(50); // Use smaller sample size for this comparison benchmark

    // Use a fixed ring size for comparison
    let ring_size = 10;

    // Setup common test data
    let keypairs = generate_keypairs(ring_size, "xonly");
    let ring = get_public_keys(&keypairs);
    let signer_key = &keypairs[0].private_key_hex;
    let message = b"Comparing SAG vs BLSAG performance";

    // Benchmark SAG sign+verify
    group.bench_function("sag_full_process", |b| {
        b.iter(|| {
            let signature = sign(message, signer_key, &ring).unwrap();
            verify(&signature, message, &ring).unwrap()
        });
    });

    // Benchmark BLSAG sign+verify
    group.bench_function("blsag_full_process", |b| {
        b.iter(|| {
            let (signature, key_image) = sign_blsag_hex(message, signer_key, &ring, &None).unwrap();
            verify_blsag_hex(&signature, &key_image, message, &ring).unwrap()
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_sag_sign,
    bench_sag_verify,
    bench_sag_sign_and_verify,
    bench_blsag_sign,
    bench_blsag_verify,
    bench_blsag_sign_and_verify,
    bench_sag_vs_blsag,
);
criterion_main!(benches);
