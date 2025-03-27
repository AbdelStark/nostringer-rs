use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use nostringer_rs::ring_sign;
use rand_core::{OsRng, RngCore};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

fn bench_ring_sign(c: &mut Criterion) {
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let message = b"Test ring signature message";

    let mut group = c.benchmark_group("Ring Signatures - Signing");

    for size in [2, 3, 5, 10].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            // Generate a set of keys for the ring
            let mut secret_keys = Vec::with_capacity(size);
            let mut public_keys = Vec::with_capacity(size);

            for _ in 0..size {
                let mut key_bytes = [0u8; 32];
                rng.fill_bytes(&mut key_bytes);

                let secret_key = SecretKey::from_slice(&key_bytes).unwrap();
                let public_key = PublicKey::from_secret_key(&secp, &secret_key);

                secret_keys.push(secret_key);
                public_keys.push(public_key);
            }

            b.iter(|| ring_sign(black_box(message), &secret_keys[0], &public_keys).unwrap());
        });
    }
    group.finish();
}

fn bench_ring_verify(c: &mut Criterion) {
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let message = b"Test ring signature message";

    let mut group = c.benchmark_group("Ring Signatures - Verification");

    for size in [2, 3, 5, 10].iter() {
        // Generate a set of keys for the ring
        let mut secret_keys = Vec::with_capacity(*size);
        let mut public_keys = Vec::with_capacity(*size);

        for _ in 0..*size {
            let mut key_bytes = [0u8; 32];
            rng.fill_bytes(&mut key_bytes);

            let secret_key = SecretKey::from_slice(&key_bytes).unwrap();
            let public_key = PublicKey::from_secret_key(&secp, &secret_key);

            secret_keys.push(secret_key);
            public_keys.push(public_key);
        }

        // Create signature
        let signature = ring_sign(message, &secret_keys[0], &public_keys).unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| signature.verify(black_box(message), &public_keys).unwrap());
        });
    }
    group.finish();
}

criterion_group!(benches, bench_ring_sign, bench_ring_verify);
criterion_main!(benches);
