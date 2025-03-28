use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use nostringer::{generate_keypairs, get_public_keys, sign, verify};

fn bench_ring_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_signature_sign");

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

fn bench_ring_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_signature_verify");

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

fn bench_ring_sign_and_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_signature_sign_and_verify");

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

criterion_group!(
    benches,
    bench_ring_sign,
    bench_ring_verify,
    bench_ring_sign_and_verify,
);
criterion_main!(benches);
