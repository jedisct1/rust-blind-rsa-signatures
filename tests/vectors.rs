use blind_rsa_signatures::{Hash, Options, PSSMode, PrepareMode, SecretKey};
use core::convert::TryFrom;
use rsa::BoxedUint;
use serde::{de::Error, Deserialize, Deserializer};
use std::fs::File;

#[derive(Deserialize)]
struct Vector {
    name: String,
    #[serde(deserialize_with = "parse_uint")]
    p: BoxedUint,
    #[serde(deserialize_with = "parse_uint")]
    q: BoxedUint,
    #[serde(deserialize_with = "parse_uint")]
    n: BoxedUint,
    #[serde(deserialize_with = "parse_uint")]
    e: BoxedUint,
    #[serde(deserialize_with = "parse_uint")]
    d: BoxedUint,
    #[serde(deserialize_with = "parse_uint")]
    inv: BoxedUint,
    #[serde(deserialize_with = "parse_bytes")]
    msg: Vec<u8>,
    #[serde(deserialize_with = "parse_bytes")]
    msg_prefix: Vec<u8>,
    #[serde(deserialize_with = "parse_usize", rename = "sLen")]
    salt_len: usize,
    #[serde(deserialize_with = "parse_bytes")]
    salt: Vec<u8>,
    #[serde(deserialize_with = "parse_bool")]
    is_randomized: bool,
    #[serde(deserialize_with = "parse_bytes")]
    blinded_msg: Vec<u8>,
    #[serde(deserialize_with = "parse_bytes")]
    blind_sig: Vec<u8>,
    #[serde(deserialize_with = "parse_bytes")]
    sig: Vec<u8>,
}

fn parse_uint<'a, D: Deserializer<'a>>(d: D) -> Result<BoxedUint, D::Error> {
    let s: String = Deserialize::deserialize(d)?;
    BoxedUint::from_str_radix_vartime(&s[2..], 16).map_err(Error::custom)
}

fn parse_bool<'a, D: Deserializer<'a>>(d: D) -> Result<bool, D::Error> {
    parse_uint(d).map(|b| b.is_nonzero().to_bool())
}

fn parse_usize<'a, D: Deserializer<'a>>(d: D) -> Result<usize, D::Error> {
    parse_uint(d).map(|b| usize::try_from(b.to_words().first().copied().unwrap_or(0)).unwrap())
}

fn parse_bytes<'a, D: Deserializer<'a>>(d: D) -> Result<Vec<u8>, D::Error> {
    let mut s: String = Deserialize::deserialize(d)?;
    if s.is_empty() {
        s.push('0');
    }
    BoxedUint::from_str_radix_vartime(&s, 16)
        .map(|b| b.to_be_bytes().to_vec())
        .map_err(Error::custom)
}

struct MockRandom(Vec<Vec<u8>>);
impl rsa::rand_core::TryCryptoRng for MockRandom {}
impl rsa::rand_core::TryRng for MockRandom {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        unimplemented!()
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        unimplemented!()
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        dst.copy_from_slice(&self.0.remove(0));
        Ok(())
    }
}

#[test]
fn rfc9474() {
    const FILENAME: &str = "tests/test_vectors_rfc9474.json";
    let vectors: Vec<Vector> = serde_json::from_reader(File::open(FILENAME).unwrap()).unwrap();

    for vector in vectors {
        println!("Testing {}", vector.name);

        let options = Options::new(
            Hash::Sha384,
            if vector.salt_len == 0 {
                PSSMode::PSSZero
            } else {
                PSSMode::PSS
            },
            if vector.is_randomized {
                PrepareMode::Randomized
            } else {
                PrepareMode::Deterministic
            },
        );

        // Mock random number generator.
        let mut mock_rng = MockRandom({
            let r = vector
                .inv
                .invert_mod(&vector.n.to_nz().unwrap())
                .unwrap()
                .to_le_bytes()
                .to_vec();
            let mut out = Vec::with_capacity(3);
            if options.is_randomized() {
                out.push(vector.msg_prefix);
            }
            out.push(vector.salt);
            out.push(r);
            out
        });

        // Parse signing keys.
        let sk = SecretKey(
            rsa::RsaPrivateKey::from_components(
                vector.n,
                vector.e,
                vector.d,
                vec![vector.p, vector.q],
            )
            .unwrap(),
        );
        let pk = sk.public_key().unwrap();

        // Client blinds a message to be signed.
        let result = pk.blind(&mut mock_rng, &vector.msg, &options).unwrap();
        assert_eq!(result.secret.0, vector.inv.to_be_bytes().to_vec());
        assert_eq!(result.blind_msg.0, vector.blinded_msg);

        // Server signs a blinded message producing a blinded signature.
        let blinded_sig = sk.blind_sign(&result.blind_msg).unwrap();
        assert_eq!(blinded_sig.0, vector.blind_sig);

        // Client computes the final RSA signature.
        let signature = pk
            .finalize(&blinded_sig, &result, &vector.msg, &options)
            .unwrap();
        assert_eq!(signature.0, vector.sig);

        // RSA signature can be verified with the public key.
        assert!(signature
            .verify(&pk, result.msg_randomizer, vector.msg, &options)
            .is_ok());
    }
}
