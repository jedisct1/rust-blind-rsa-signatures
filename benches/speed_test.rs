use blind_rsa_signatures::{DefaultRng, KeyPair, Randomized, Sha384, PSS};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

type MyKeyPair = KeyPair<Sha384, PSS, Randomized>;

pub fn protocol(c: &mut Criterion) {
    let mut group = c.benchmark_group("protocol");
    let msg = b"test";

    let key_sizes = [2048, 4096];
    for key_size in key_sizes {
        let kp = MyKeyPair::generate(&mut DefaultRng, key_size).unwrap();
        let (pk, sk) = (kp.pk, kp.sk);

        group.bench_function(BenchmarkId::new("blind", key_size), |b| {
            b.iter(|| {
                _ = pk.blind(&mut DefaultRng, msg).unwrap();
            })
        });

        let blinding_result = pk.blind(&mut DefaultRng, msg).unwrap();

        group.bench_function(BenchmarkId::new("blind_sign", key_size), |b| {
            b.iter(|| {
                _ = sk.blind_sign(&blinding_result.blind_message).unwrap();
            })
        });

        let blind_sig = sk.blind_sign(&blinding_result.blind_message).unwrap();

        group.bench_function(BenchmarkId::new("finalize", key_size), |b| {
            b.iter(|| {
                _ = pk.finalize(&blind_sig, &blinding_result, msg).unwrap();
            })
        });

        let sig = pk.finalize(&blind_sig, &blinding_result, msg).unwrap();

        group.bench_function(BenchmarkId::new("verify", key_size), |b| {
            b.iter(|| {
                pk.verify(&sig, blinding_result.msg_randomizer, msg)
                    .unwrap();
            })
        });
    }

    group.finish();
}

criterion_group!(benches, protocol);
criterion_main!(benches);
