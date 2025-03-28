use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use nostringer::{generate_keypairs, get_public_keys, sign, verify};

fn bench_ring_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_signature_sign");

    // Benchmark signing with different ring sizes
    for ring_size in [3, 5, 10, 20].iter() {
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
    for ring_size in [3, 5, 10, 20].iter() {
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
    for ring_size in [3, 5, 10, 20].iter() {
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

// Benchmark different key formats
fn bench_key_formats(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_signature_key_formats");

    for format in ["xonly", "compressed", "uncompressed"].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(format), format, |b, &fmt| {
            // Setup: Generate keypairs with the specific format
            let ring_size = 5;
            let keypairs = generate_keypairs(ring_size, fmt);
            let ring = get_public_keys(&keypairs);
            let signer_key = &keypairs[0].private_key_hex;
            let message = b"Benchmark different key formats";

            // Benchmark both sign and verify with the specific format
            b.iter(|| {
                let signature = sign(message, signer_key, &ring).unwrap();
                verify(&signature, message, &ring).unwrap()
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_ring_sign,
    bench_ring_verify,
    bench_ring_sign_and_verify,
    bench_key_formats
);
criterion_main!(benches);
