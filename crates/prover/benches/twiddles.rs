use criterion::{black_box, criterion_group, criterion_main, Criterion};
use stwo_prover::core::backend::simd::SimdBackend;
use stwo_prover::core::poly::circle::{CanonicCoset, PolyOps};

fn twiddles_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("twiddles");
    group.bench_function("precompute_twiddles_64", |b| {
        b.iter(|| {
            let twiddles =
                SimdBackend::precompute_twiddles(CanonicCoset::new(27).circle_domain().half_coset);
            black_box(twiddles);
        });
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = twiddles_bench);
criterion_main!(benches);
