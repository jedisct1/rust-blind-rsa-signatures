//! Author-blinded RSASSA-PSS RSAE signatures.
//!
//! This is an implementation of the [RSA Blind Signatures](https://chris-wood.github.io/draft-wood-cfrg-blind-signatures/draft-wood-cfrg-rsa-blind-signatures.html) proposal, based on [the Zig implementation](https://github.com/jedisct1/zig-rsa-blind-signatures).
//!
//! ```rust
//! use blind_rsa_signatures::{KeyPair, Options};
//!
//! let options = Options::default();
//!
//! // [SERVER]: Generate a RSA-2048 key pair
//! let kp = KeyPair::generate(2048)?;
//! let (pk, sk) = (kp.pk, kp.sk);
//!
//! // [CLIENT]: create a random message and blind it for the server whose public key is `pk`.
//! // The client must store the message and the secret.
//! let msg = b"test";
//! let blinding_result = pk.blind(msg, &options)?;
//!
//! // [SERVER]: compute a signature for a blind message, to be sent to the client.
//! // The client secret should not be sent to the server.
//! let blind_sig = sk.blind_sign(&blinding_result.blind_msg, &options)?;
//!
//! // [CLIENT]: later, when the client wants to redeem a signed blind message,
//! // using the blinding secret, it can locally compute the signature of the
//! // original message.
//! // The client then owns a new valid (message, signature) pair, and the
//! // server cannot link it to a previous(blinded message, blind signature) pair.
//! // Note that the finalization function also verifies that the new signature
//! // is correct for the server public key.
//! let sig = pk.finalize(&blind_sig, &blinding_result.secret, &msg, &options)?;
//!
//! // [SERVER]: a non-blind signature can be verified using the server's public key.
//! sig.verify(&pk, msg, &options)?;
//! # Ok::<(), blind_rsa_signatures::Error>(())
//! ```

#[macro_use]
extern crate derive_new;

use derive_more::*;
use digest::DynDigest;
use hmac_sha256::Hash as Sha256;
use hmac_sha512::sha384::Hash as Sha384;
use hmac_sha512::Hash as Sha512;
use rand::Rng;
use rsa::algorithms::mgf1_xor;
use rsa::internals as rsa_internals;
use rsa::{
    BigUint, PaddingScheme, PrivateKeyEncoding as _, PrivateKeyPemEncoding as _, PublicKey as _,
    PublicKeyEncoding as _, PublicKeyParts as _, PublicKeyPemEncoding as _, RSAPrivateKey,
    RSAPublicKey,
};
use std::convert::TryFrom;
use std::fmt::{self, Display};

pub mod reexports {
    pub use {digest, hmac_sha512, rand, rsa};
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    InternalError,
    UnsupportedParameters,
    VerificationFailed,
    EncodingError,
    InvalidKey,
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InternalError => write!(f, "Internal Error"),
            Error::UnsupportedParameters => write!(f, "Unsupported parameters"),
            Error::VerificationFailed => write!(f, "Verification failed"),
            Error::EncodingError => write!(f, "Encoding error"),
            Error::InvalidKey => write!(f, "Invalid key"),
        }
    }
}

/// Hash function for padding and message hashing
#[derive(Clone, Debug, Eq, PartialEq, From, new)]
pub enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

/// Options
#[derive(Clone, Debug, Eq, PartialEq, AsRef, From, Into, new)]
pub struct Options {
    /// Hash function to use for padding and for hashing the message
    hash: Hash,
    /// Use deterministic padding
    deterministic: bool,
    /// Salt length (ignored in deterministic mode)
    salt_len: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            hash: Hash::Sha384,
            deterministic: false,
            salt_len: hmac_sha512::sha384::Hash::new().output_size(),
        }
    }
}

impl Options {
    fn salt_len(&self) -> usize {
        if self.deterministic {
            0
        } else {
            self.salt_len
        }
    }
}

/// An RSA public key
#[derive(Clone, Debug, Eq, PartialEq, AsRef, Deref, From, Into, new)]
pub struct PublicKey(pub RSAPublicKey);

/// An RSA secret key
#[derive(Clone, Debug, AsRef, Deref, From, Into, new)]
pub struct SecretKey(pub RSAPrivateKey);

/// An RSA key pair
#[derive(Clone, Debug, From, Into, new)]
pub struct KeyPair {
    pub pk: PublicKey,
    pub sk: SecretKey,
}

/// A blinding secret factor
#[derive(Clone, Debug, AsRef, Deref, From, Into, new)]
pub struct Secret(pub Vec<u8>);

/// A blinded message
#[derive(Clone, Debug, AsRef, Deref, From, Into, new)]
pub struct BlindedMessage(pub Vec<u8>);

/// A blind signature
#[derive(Clone, Debug, AsRef, Deref, From, Into, new)]
pub struct BlindSignature(pub Vec<u8>);

/// A (non-blind) signature
#[derive(Clone, Debug, AsRef, Deref, From, Into, new)]
pub struct Signature(pub Vec<u8>);

/// Result of a blinding operation
#[derive(Clone, Debug)]
pub struct BlindingResult {
    pub blind_msg: BlindedMessage,
    pub secret: Secret,
}

impl AsRef<[u8]> for Secret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsRef<[u8]> for BlindedMessage {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsRef<[u8]> for BlindSignature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl KeyPair {
    /// Generate a new key pair
    pub fn generate(modulus_bits: usize) -> Result<KeyPair, Error> {
        let mut rng = rand::thread_rng();
        let mut sk =
            RSAPrivateKey::new(&mut rng, modulus_bits).map_err(|_| Error::UnsupportedParameters)?;
        sk.precompute().map_err(|_| Error::InternalError)?;
        let sk = SecretKey(sk);
        let pk = sk.public_key()?;
        Ok(KeyPair { sk, pk })
    }
}

impl Signature {
    /// Verify that the (non-blind) signature is valid for the given public key and original message
    pub fn verify(
        &self,
        pk: &PublicKey,
        msg: impl AsRef<[u8]>,
        options: &Options,
    ) -> Result<(), Error> {
        pk.verify(self, msg, options)
    }
}

fn emsa_pss_encode(
    m_hash: &[u8],
    em_bits: usize,
    salt: &[u8],
    hash: &mut dyn DynDigest,
) -> Result<Vec<u8>, Error> {
    let h_len = hash.output_size();
    let s_len = salt.len();
    let em_len = (em_bits + 7) / 8;
    if m_hash.len() != h_len {
        return Err(Error::InternalError);
    }
    if em_len < h_len + s_len + 2 {
        return Err(Error::InternalError);
    }
    let mut em = vec![0; em_len];
    let (db, h) = em.split_at_mut(em_len - h_len - 1);
    let h = &mut h[..(em_len - 1) - db.len()];
    let prefix = [0u8; 8];
    hash.update(&prefix);
    hash.update(m_hash);
    hash.update(salt);
    let hashed = hash.finalize_reset();
    h.copy_from_slice(&hashed);
    db[em_len - s_len - h_len - 2] = 0x01;
    db[em_len - s_len - h_len - 1..].copy_from_slice(salt);
    mgf1_xor(db, hash, h);
    db[0] &= 0xFF >> (8 * em_len - em_bits);
    em[em_len - 1] = 0xBC;
    Ok(em)
}

impl PublicKey {
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.as_ref().to_pkcs8().map_err(|_| Error::EncodingError)
    }

    fn check_rsa_parameters(&self) -> Result<(), Error> {
        let pk = self.as_ref();
        let modulus_bits = pk.size() * 8;
        if !(2048..=4096).contains(&modulus_bits) {
            return Err(Error::UnsupportedParameters);
        }
        let e = pk.e();
        let e3 = BigUint::from(3u32);
        let ef4 = BigUint::from(65537u32);
        if ![e3, ef4].contains(e) {
            return Err(Error::UnsupportedParameters);
        }
        Ok(())
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        if der.len() > 800 {
            return Err(Error::EncodingError);
        }
        let pk = PublicKey(RSAPublicKey::from_pkcs8(der).map_err(|_| Error::EncodingError)?);
        pk.check_rsa_parameters()?;
        Ok(pk)
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.as_ref()
            .to_pem_pkcs8()
            .map_err(|_| Error::EncodingError)
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        if pem.len() > 1000 {
            return Err(Error::EncodingError);
        }
        let parsed_pem = ::rsa::pem::parse(pem).map_err(|_| Error::EncodingError)?;
        Ok(RSAPublicKey::try_from(parsed_pem)
            .map_err(|_| Error::EncodingError)?
            .into())
    }

    /// Blind a message to be signed
    pub fn blind(&self, msg: impl AsRef<[u8]>, options: &Options) -> Result<BlindingResult, Error> {
        let msg = msg.as_ref();
        let mut rng = rand::thread_rng();
        let modulus_bytes = self.0.size();
        let modulus_bits = modulus_bytes * 8;
        let msg_hash = match options.hash {
            Hash::Sha256 => Sha256::hash(msg).to_vec(),
            Hash::Sha384 => Sha384::hash(msg).to_vec(),
            Hash::Sha512 => Sha512::hash(msg).to_vec(),
        };
        let salt_len = options.salt_len();
        let mut salt = vec![0u8; salt_len];
        rng.fill(&mut salt[..]);

        let padded = match options.hash {
            Hash::Sha256 => {
                emsa_pss_encode(&msg_hash, modulus_bits - 1, &salt, &mut Sha256::new())?
            }
            Hash::Sha384 => {
                emsa_pss_encode(&msg_hash, modulus_bits - 1, &salt, &mut Sha384::new())?
            }
            Hash::Sha512 => {
                emsa_pss_encode(&msg_hash, modulus_bits - 1, &salt, &mut Sha512::new())?
            }
        };
        let m = BigUint::from_bytes_be(&padded);

        let (blind_msg, secret) = rsa_internals::blind(&mut rng, self.as_ref(), &m);
        Ok(BlindingResult {
            blind_msg: BlindedMessage(blind_msg.to_bytes_be()),
            secret: Secret(secret.to_bytes_be()),
        })
    }

    /// Compute a valid signature for the original message given a blindly signed message
    pub fn finalize(
        &self,
        blind_sig: &BlindSignature,
        secret: &Secret,
        msg: impl AsRef<[u8]>,
        options: &Options,
    ) -> Result<Signature, Error> {
        let modulus_bytes = self.0.size();
        if blind_sig.len() != modulus_bytes || secret.len() != modulus_bytes {
            return Err(Error::UnsupportedParameters);
        }
        let blind_sig = BigUint::from_bytes_be(blind_sig);
        let secret = BigUint::from_bytes_be(secret);
        let sig =
            Signature(rsa_internals::unblind(self.as_ref(), &blind_sig, &secret).to_bytes_be());
        self.verify(&sig, msg, options)?;
        Ok(sig)
    }

    /// Verify a (non-blind) signature
    pub fn verify(
        &self,
        sig: &Signature,
        msg: impl AsRef<[u8]>,
        options: &Options,
    ) -> Result<(), Error> {
        let msg = msg.as_ref();
        let modulus_bytes = self.0.size();
        if sig.len() != modulus_bytes {
            return Err(Error::UnsupportedParameters);
        }
        let rng = rand::thread_rng();
        let (msg_hash, ps) = match options.hash {
            Hash::Sha256 => (
                Sha256::hash(msg).to_vec(),
                PaddingScheme::new_pss::<hmac_sha256::Hash, _>(rng),
            ),
            Hash::Sha384 => (
                Sha384::hash(msg).to_vec(),
                PaddingScheme::new_pss::<hmac_sha512::sha384::Hash, _>(rng),
            ),
            Hash::Sha512 => (
                Sha512::hash(msg).to_vec(),
                PaddingScheme::new_pss::<hmac_sha512::Hash, _>(rng),
            ),
        };
        self.as_ref()
            .verify(ps, &msg_hash, sig) // salt length is ignored
            .map_err(|_| Error::VerificationFailed)?;
        Ok(())
    }
}

impl SecretKey {
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.as_ref().to_pkcs8().map_err(|_| Error::EncodingError)
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let mut sk = RSAPrivateKey::from_pkcs8(der).map_err(|_| Error::EncodingError)?;
        sk.validate().map_err(|_| Error::InvalidKey)?;
        sk.precompute().map_err(|_| Error::InvalidKey)?;
        Ok(SecretKey(sk))
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.as_ref()
            .to_pem_pkcs8()
            .map_err(|_| Error::EncodingError)
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let parsed_pem = ::rsa::pem::parse(pem).map_err(|_| Error::EncodingError)?;
        let mut sk = RSAPrivateKey::try_from(parsed_pem).map_err(|_| Error::EncodingError)?;
        sk.validate().map_err(|_| Error::InvalidKey)?;
        sk.precompute().map_err(|_| Error::InvalidKey)?;
        Ok(SecretKey(sk))
    }

    pub fn public_key(&self) -> Result<PublicKey, Error> {
        Ok(PublicKey(RSAPublicKey::from(self.as_ref())))
    }

    /// Sign a blinded message
    pub fn blind_sign(
        &self,
        blind_msg: impl AsRef<[u8]>,
        _options: &Options,
    ) -> Result<BlindSignature, Error> {
        let modulus_bytes = self.0.size();
        if blind_msg.as_ref().len() != modulus_bytes {
            return Err(Error::UnsupportedParameters);
        }
        let mut rng = rand::thread_rng();
        let blind_msg = BigUint::from_bytes_be(blind_msg.as_ref());
        let blind_sig = rsa_internals::decrypt_and_check(Some(&mut rng), self.as_ref(), &blind_msg)
            .map_err(|_| Error::InternalError)?;
        Ok(BlindSignature(blind_sig.to_bytes_be()))
    }
}
