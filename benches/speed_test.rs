use blind_rsa_signatures::{DefaultRng, KeyPair, Options};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

pub fn protocol(c: &mut Criterion) {
    let mut group = c.benchmark_group("protocol");
    let msg = b"test";
    let options = Options::default();

    let key_sizes = [2048, 4096];
    for key_size in key_sizes {
        let kp = KeyPair::generate(&mut DefaultRng, key_size).unwrap();
        let (pk, sk) = (kp.pk, kp.sk);

        group.bench_function(BenchmarkId::new("blind", key_size), |b| {
            b.iter(|| {
                _ = pk.blind(&mut DefaultRng, msg, &options).unwrap();
            })
        });

        let blinding_result = pk.blind(&mut DefaultRng, msg, &options).unwrap();

        group.bench_function(BenchmarkId::new("blind_sign", key_size), |b| {
            b.iter(|| {
                _ = sk.blind_sign(&blinding_result.blind_msg).unwrap();
            })
        });

        let blind_sig = sk.blind_sign(&blinding_result.blind_msg).unwrap();

        group.bench_function(BenchmarkId::new("finalize", key_size), |b| {
            b.iter(|| {
                _ = pk
                    .finalize(&blind_sig, &blinding_result, msg, &options)
                    .unwrap();
            })
        });

        let sig = pk
            .finalize(&blind_sig, &blinding_result, msg, &options)
            .unwrap();

        group.bench_function(BenchmarkId::new("verify", key_size), |b| {
            b.iter(|| {
                sig.verify(&pk, blinding_result.msg_randomizer, msg, &options)
                    .unwrap();
            })
        });
    }

    group.finish();
}

criterion_group!(benches, protocol);
criterion_main!(benches);
