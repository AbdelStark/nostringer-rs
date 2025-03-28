use criterion::{Criterion, criterion_group, criterion_main};

fn bench_ring_sign(_c: &mut Criterion) {}

fn bench_ring_verify(_c: &mut Criterion) {}

fn bench_ring_sign_and_verify(_c: &mut Criterion) {}

criterion_group!(
    benches,
    bench_ring_sign,
    bench_ring_verify,
    bench_ring_sign_and_verify
);
criterion_main!(benches);
