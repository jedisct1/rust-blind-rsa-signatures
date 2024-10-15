//! Author-blinded RSASSA-PSS RSAE signatures.
//!
//! This is an implementation of the [RSA Blind Signatures](https://cfrg.github.io/draft-irtf-cfrg-blind-signatures/draft-irtf-cfrg-rsa-blind-signatures.html) proposal, based on [the Zig implementation](https://github.com/jedisct1/zig-rsa-blind-signatures).
//!
//! ```rust
//! use blind_rsa_signatures::{KeyPair, Options};
//!
//! let options = Options::default();
//! let rng = &mut rand::thread_rng();
//!
//! // [SERVER]: Generate a RSA-2048 key pair
//! let kp = KeyPair::generate(rng, 2048)?;
//! let kd = KeyPair::generate_safe_prime_pair(2048)?;
//! 
//! let (pk, sk) = (kp.pk, kp.sk);
//! let (pd, ps) = (kd.pk, kd.sk);
//!
//! // [CLIENT]: create a random message and blind it for the server whose public key is `pk`.
//! // The client must store the message and the secret.
//! let msg = b"test";
//! let blinding_result = pk.blind(rng, msg, true, &options)?;
//!
//! // [SERVER]: compute a signature for a blind message, to be sent to the client.
//! // The client secret should not be sent to the server.
//! let blind_sig = sk.blind_sign(rng, &blinding_result.blind_msg, &options)?;
//!
//! // [CLIENT]: later, when the client wants to redeem a signed blind message,
//! // using the blinding secret, it can locally compute the signature of the
//! // original message.
//! // The client then owns a new valid (message, signature) pair, and the
//! // server cannot link it to a previous(blinded message, blind signature) pair.
//! // Note that the finalization function also verifies that the new signature
//! // is correct for the server public key.
//! let sig = pk.finalize(
//!     &blind_sig,
//!     &blinding_result.secret,
//!     blinding_result.msg_randomizer,
//!     &msg,
//!     &options,
//! )?;
//!
//! // [SERVER]: a non-blind signature can be verified using the server's public key.
//! sig.verify(&pk, blinding_result.msg_randomizer, msg, &options)?;
//! # Ok::<(), blind_rsa_signatures::Error>(())
//! ```

#[macro_use]
extern crate derive_new;

use std::convert::TryFrom;
use std::fmt::{self, Display};
use std::mem;

use derive_more::*;
use digest::DynDigest;
use digest::core_api::CoreWrapper;
use hkdf::Hkdf;  
use hmac_sha256::Hash as Sha256;
use hmac_sha512::sha384::Hash as Sha384;
use hmac_sha512::Hash as Sha512;
use num_bigint_dig::traits::ModInverse;
use num_integer::Integer;
use num_padding::ToBytesPadded;
use num_primes::{Generator, Verification};
use num_traits::One;
use rand::{CryptoRng, Rng, RngCore};
use rsa::algorithms::mgf1_xor;
use rsa::internals as rsa_internals;
use rsa::pkcs1::{DecodeRsaPrivateKey as _, DecodeRsaPublicKey as _};
use rsa::pkcs8::{
    DecodePrivateKey as _, DecodePublicKey as _, EncodePrivateKey as _, EncodePublicKey as _,
};
use rsa::signature::hazmat::PrehashVerifier;
use rsa::{BigUint, PublicKeyParts as _, RsaPrivateKey, RsaPublicKey};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub mod reexports {
    pub use {digest, hmac_sha512, rand, rsa};
}

mod num_padding;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    InternalError,
    UnsupportedParameters,
    VerificationFailed,
    EncodingError,
    InvalidKey,
    IncompatibleParameters,
    InvalidInput,
    BlindingError,
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
            Error::IncompatibleParameters => write!(f, "Incompatible parameters"),
            Error::InvalidInput => write!(f, "Invalid input"),
            Error::BlindingError => write!(f, "Blinding error")
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, Eq, PartialEq, AsRef, Deref, From, Into, new)]
pub struct PublicKey(pub RsaPublicKey);

/// An RSA secret key
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, AsRef, Deref, From, Into, new)]
pub struct SecretKey(pub RsaPrivateKey);

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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, AsRef, Deref, From, Into, new)]
pub struct BlindedMessage(pub Vec<u8>);

/// A blind signature
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, AsRef, Deref, From, Into, new)]
pub struct BlindSignature(pub Vec<u8>);

/// A (non-blind) signature
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, AsRef, Deref, From, Into, new)]
pub struct Signature(pub Vec<u8>);

/// A message randomizer (noise added as a prefix to the message)
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, AsRef, Deref, From, Into, new)]
pub struct MessageRandomizer(pub [u8; 32]);

/// Result of a blinding operation
#[derive(Clone, Debug)]
pub struct BlindingResult {
    pub blind_msg: BlindedMessage,
    pub secret: Secret,
    pub msg_randomizer: Option<MessageRandomizer>,
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
    pub fn generate<R: CryptoRng + RngCore>(
        rng: &mut R,
        modulus_bits: usize,
    ) -> Result<KeyPair, Error> {
        let mut sk =
            RsaPrivateKey::new(rng, modulus_bits).map_err(|_| Error::UnsupportedParameters)?;
        sk.precompute().map_err(|_| Error::InternalError)?;
        let sk = SecretKey(sk);
        let pk = sk.public_key()?;
        Ok(KeyPair { sk, pk })
    }

    // Generate a prime safe key pair used for Partial Blinding RSA
    pub fn generate_safe_prime_pair(modulus_bits: usize,) -> Result<KeyPair, Error> {
        if modulus_bits % 2 != 0 {
            return Err(Error::UnsupportedParameters); 
        }

        let p = Self::safe_prime(modulus_bits / 2);
        let mut q = Self::safe_prime(modulus_bits / 2); 

        while p == q {
            q = Self::safe_prime(modulus_bits / 2); 
        }

        let phi = (&p - BigUint::one()) * (&q - BigUint::one());
        let e = BigUint::from(65537u32);
        let d = e.clone().mod_inverse(phi.clone()).unwrap().to_biguint().unwrap(); 
        let n = &p * &q;

        let sk = RsaPrivateKey::from_components(n.clone(), phi, d, vec![p, q]).map_err(|_| Error::InvalidKey)?; 
        let pk = RsaPublicKey::new(n, e).map_err(|_| Error::UnsupportedParameters)?;

        Ok(KeyPair {
            pk: PublicKey(pk),
            sk: SecretKey(sk),
        })
    }
    
    fn safe_prime(bits: usize) -> BigUint {
        loop {
            let p_prime_num = Generator::new_prime(bits - 1);
            let p_prime = BigUint::from_bytes_be(&p_prime_num.to_bytes_be());
            let two = BigUint::from(2u32);
            let one = BigUint::from(1u32);
            let p = (two * p_prime) + one;

            if Verification::is_prime(&p_prime_num) {
                return p;
            }
        }
    }
}

impl Signature {
    /// Verify that the (non-blind) signature is valid for the given public key
    /// and original message
    pub fn verify(
        &self,
        pk: &PublicKey,
        msg_randomizer: Option<MessageRandomizer>,
        msg: impl AsRef<[u8]>,
        options: &Options,
    ) -> Result<(), Error> {
        pk.verify(self, msg_randomizer, msg, options)
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
    db[0] &= 0xff >> (8 * em_len - em_bits);
    em[em_len - 1] = 0xbc;
    Ok(em)
}

impl PublicKey {
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.as_ref()
            .to_public_key_der()
            .map_err(|_| Error::EncodingError)
            .map(|x| x.as_ref().to_vec())
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
        let pk = PublicKey(
            rsa::RsaPublicKey::from_public_key_der(der)
                .or_else(|_| rsa::RsaPublicKey::from_pkcs1_der(der))
                .map_err(|_| Error::EncodingError)?,
        );
        pk.check_rsa_parameters()?;
        Ok(pk)
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.as_ref()
            .to_public_key_pem(Default::default())
            .map_err(|_| Error::EncodingError)
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        if pem.len() > 1000 {
            return Err(Error::EncodingError);
        }
        let pem = pem.trim();
        Ok(rsa::RsaPublicKey::from_public_key_pem(pem)
            .or_else(|_| rsa::RsaPublicKey::from_pkcs1_pem(pem))
            .map_err(|_| Error::EncodingError)?
            .into())
    }

    const fn spki_tpl() -> &'static [u8] {
        const SEQ: u8 = 0x30;
        const EXT: u8 = 0x80;
        const CON: u8 = 0xa0;
        const INT: u8 = 0x02;
        const BIT: u8 = 0x03;
        const OBJ: u8 = 0x06;
        const TPL: &[u8] = &[
            SEQ,
            EXT | 2,
            0,
            0, // container length - offset 2
            SEQ,
            61, // Algorithm sequence
            OBJ,
            9,
            0x2a,
            0x86,
            0x48,
            0x86,
            0xf7,
            0x0d,
            0x01,
            0x01,
            0x0a, // Signature algorithm (RSASSA-PSS)
            SEQ,
            48, // RSASSA-PSS parameters sequence
            CON | 0,
            2 + 2 + 9,
            SEQ,
            2 + 9,
            OBJ,
            9,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0, // Hash function - offset 21
            CON | 1,
            2 + 24,
            SEQ,
            24,
            OBJ,
            9,
            0x2a,
            0x86,
            0x48,
            0x86,
            0xf7,
            0x0d,
            0x01,
            0x01,
            0x08, // Padding function (MGF1) and parameters
            SEQ,
            2 + 9,
            OBJ,
            9,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0, // MGF1 hash function - offset 49
            CON | 2,
            2 + 1,
            INT,
            1,
            0, // Salt length - offset 66
            BIT,
            EXT | 2,
            0,
            0, // Public key length - Bit string - offset 69
            0, // No partial bytes
        ];
        TPL
    }

    pub fn to_spki(&self, options: Option<&Options>) -> Result<Vec<u8>, Error> {
        let tpl = Self::spki_tpl();
        let default_options = Options::default();
        let options = options.unwrap_or(&default_options);
        let der = self.to_der()?;
        if der.len() <= 24 {
            return Err(Error::EncodingError);
        }
        let raw = &der[24..];
        let container_len = tpl.len() - 4 + raw.len();
        let out_len = tpl.len() + raw.len();
        let mut out = Vec::with_capacity(out_len);
        out.extend_from_slice(tpl);
        out.extend_from_slice(raw);
        out[2..4].copy_from_slice(&(container_len as u16).to_be_bytes());
        out[66] = options.salt_len() as u8;
        out[69..71].copy_from_slice(&(1 + raw.len() as u16).to_be_bytes());
        let mut mgf1_s: [u8; 13] = [48, 11, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 0];
        mgf1_s[12] = match options.hash {
            Hash::Sha256 => 1,
            Hash::Sha384 => 2,
            Hash::Sha512 => 3,
        };
        out[21..][..mgf1_s.len()].copy_from_slice(&mgf1_s);
        out[49..][..mgf1_s.len()].copy_from_slice(&mgf1_s);
        Ok(out)
    }

    pub fn from_spki(spki: &[u8], _options: Option<&Options>) -> Result<Self, Error> {
        if spki.len() > 800 {
            return Err(Error::EncodingError);
        }
        let tpl = Self::spki_tpl();
        if spki.len() <= tpl.len() {
            return Err(Error::EncodingError);
        }
        if spki[6..18] != tpl[6..18] {
            return Err(Error::EncodingError);
        }
        let alg_len = spki[5] as usize;
        if spki.len() <= alg_len + 10 {
            return Err(Error::EncodingError);
        }
        let raw = &spki[alg_len + 10..];
        let der_seq: &mut [u8] = &mut [
            0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
            0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f,
        ];
        der_seq[2..][..2].copy_from_slice(&(raw.len() as u16 + 19).to_be_bytes());
        der_seq[21..][..2].copy_from_slice(&(raw.len() as u16).to_be_bytes());
        let mut der = Vec::with_capacity(der_seq.len() + raw.len());
        der.extend_from_slice(der_seq);
        der.extend_from_slice(raw);
        Self::from_der(&der)
    }

    /// Blind a message (after optional randomization) to be signed
    pub fn blind<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        msg: impl AsRef<[u8]>,
        randomize_message: bool,
        options: &Options,
    ) -> Result<BlindingResult, Error> {
        let msg = msg.as_ref();
        let modulus_bytes = self.0.size();
        let modulus_bits = modulus_bytes * 8;
        let msg_randomizer = if randomize_message {
            let mut noise = [0u8; 32];
            rng.fill(&mut noise[..]);
            Some(MessageRandomizer(noise))
        } else {
            None
        };
        let msg_hash = match options.hash {
            Hash::Sha256 => {
                let mut h = Sha256::new();
                if let Some(p) = msg_randomizer.as_ref() {
                    h.update(p.0);
                }
                h.update(msg);
                h.finalize().to_vec()
            }
            Hash::Sha384 => {
                let mut h = Sha384::new();
                if let Some(p) = msg_randomizer.as_ref() {
                    h.update(p.0);
                }
                h.update(msg);
                h.finalize().to_vec()
            }
            Hash::Sha512 => {
                let mut h = Sha512::new();
                if let Some(p) = msg_randomizer.as_ref() {
                    h.update(p.0);
                }
                h.update(msg);
                h.finalize().to_vec()
            }
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
        if m.gcd(self.0.n()) != BigUint::one() {
            return Err(Error::UnsupportedParameters);
        }

        let (blind_msg, secret) = rsa_internals::blind(rng, self.as_ref(), &m);
        Ok(BlindingResult {
            blind_msg: BlindedMessage(blind_msg.to_bytes_be_padded(modulus_bytes)),
            secret: Secret(secret.to_bytes_be_padded(modulus_bytes)),
            msg_randomizer,
        })
    }

     // Partially Blind a message to be signed
     pub fn partial_blind<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        msg: impl AsRef<[u8]>,
        info: &[u8],
        randomize_message: bool,
        options: &Options,
    ) -> Result<BlindingResult, Error> {
        let msg = msg.as_ref();
        let modulus_bytes = self.0.size();
        let modulus_bits = modulus_bytes * 8;
        let info_len_bytes = (info.len() as u32).to_be_bytes();
        let mut msg_prime = Vec::with_capacity(4 + 4 + info.len() + msg.as_ref().len());
        msg_prime.extend_from_slice(b"msg");
        msg_prime.extend_from_slice(&info_len_bytes);
        msg_prime.extend_from_slice(info);
        msg_prime.extend_from_slice(msg.as_ref());
        let msg_randomizer = if randomize_message {
            let mut noise = [0u8; 32];
            rng.fill(&mut noise[..]);
            Some(MessageRandomizer(noise))
        } else {
            None
        };
        let msg_hash = match options.hash {
            Hash::Sha256 => {
                let mut h = Sha256::new();
                if let Some(p) = msg_randomizer.as_ref() {
                    h.update(p.0);
                }
                h.update(msg_prime);
                h.finalize().to_vec()
            }
            Hash::Sha384 => {
                let mut h = Sha384::new();
                if let Some(p) = msg_randomizer.as_ref() {
                    h.update(p.0);
                }
                h.update(msg_prime);
                h.finalize().to_vec()
            }
            Hash::Sha512 => {
                let mut h = Sha512::new();
                if let Some(p) = msg_randomizer.as_ref() {
                    h.update(p.0);
                }
                h.update(msg_prime);
                h.finalize().to_vec()
            }
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
        if m.gcd(self.0.n()) != BigUint::one() {
            return Err(Error::UnsupportedParameters);
        }
        
        let pk_derived = PublicKey::derive_public_key(self.0.n(),info, options.hash.clone())?;
        let (blind_msg, secret) = rsa_internals::blind(rng, pk_derived.as_ref(), &m);
        Ok(BlindingResult {
            blind_msg: BlindedMessage(blind_msg.to_bytes_be_padded(modulus_bytes)),
            secret: Secret(secret.to_bytes_be_padded(modulus_bytes)),
            msg_randomizer,
        })
    }

    /// Compute a valid signature for the original message given a blindly
    /// signed message
    pub fn finalize(
        &self,
        blind_sig: &BlindSignature,
        secret: &Secret,
        msg_randomizer: Option<MessageRandomizer>,
        msg: impl AsRef<[u8]>,
        options: &Options,
    ) -> Result<Signature, Error> {
        let modulus_bytes = self.0.size();
        if blind_sig.len() != modulus_bytes || secret.len() != modulus_bytes {
            return Err(Error::UnsupportedParameters);
        }
        let blind_sig = BigUint::from_bytes_be(blind_sig);
        let secret = BigUint::from_bytes_be(secret);
        let sig = Signature(
            rsa_internals::unblind(self.as_ref(), &blind_sig, &secret)
                .to_bytes_be_padded(modulus_bytes),
        );
        self.verify(&sig, msg_randomizer, msg, options)?;
        Ok(sig)
    }

    pub fn partial_blind_finalize(
        &self,
        blind_sig: &BlindSignature,
        secret: &Secret,
        msg_randomizer: Option<MessageRandomizer>,
        msg: impl AsRef<[u8]>,
        info: &[u8],
        options: &Options,
    ) -> Result<Signature, Error> {

        let modulus_bytes = self.0.size();
        if blind_sig.len() != modulus_bytes || secret.len() != modulus_bytes {
            return Err(Error::UnsupportedParameters);
        }
        let info_len_bytes = (info.len() as u32).to_be_bytes();
        let mut msg_prime = Vec::with_capacity(4 + 4 + info.len() + msg.as_ref().len());
        msg_prime.extend_from_slice(b"msg");
        msg_prime.extend_from_slice(&info_len_bytes);
        msg_prime.extend_from_slice(info);
        msg_prime.extend_from_slice(msg.as_ref());
        let blind_sig = BigUint::from_bytes_be(blind_sig);
        let secret = BigUint::from_bytes_be(secret);
        let pk_derived = PublicKey::derive_public_key(self.0.n(),info, options.hash.clone())?;
        let sig = Signature(
            rsa_internals::unblind(pk_derived.as_ref(), &blind_sig, &secret)
                .to_bytes_be_padded(modulus_bytes),
        );
        PublicKey::partial_blind_verify(pk_derived,&sig, msg_randomizer, msg_prime, info, options)?;
        Ok(sig)
    }

    /// Verify a (non-blind) signature
    pub fn verify(
        &self,
        sig: &Signature,
        msg_randomizer: Option<MessageRandomizer>,
        msg: impl AsRef<[u8]>,
        options: &Options,
    ) -> Result<(), Error> {
        let msg = msg.as_ref();
        let modulus_bytes = self.0.size();
        if sig.len() != modulus_bytes {
            return Err(Error::UnsupportedParameters);
        }
        let sig_ =
            rsa::pss::Signature::try_from(sig.as_ref()).map_err(|_| Error::VerificationFailed)?;
        let verified = match options.hash {
            Hash::Sha256 => {
                let mut h = Sha256::new();
                if let Some(p) = msg_randomizer.as_ref() {
                    h.update(p.0);
                }
                h.update(msg);
                let h = h.finalize().to_vec();
                rsa::pss::VerifyingKey::<Sha256>::new(self.0.clone()).verify_prehash(&h, &sig_)
            }
            Hash::Sha384 => {
                let mut h = Sha384::new();
                if let Some(p) = msg_randomizer.as_ref() {
                    h.update(p.0);
                }
                h.update(msg);
                let h = h.finalize().to_vec();
                rsa::pss::VerifyingKey::<Sha384>::new(self.0.clone()).verify_prehash(&h, &sig_)
            }
            Hash::Sha512 => {
                let mut h = Sha512::new();
                if let Some(p) = msg_randomizer.as_ref() {
                    h.update(p.0);
                }
                h.update(msg);
                let h = h.finalize().to_vec();
                rsa::pss::VerifyingKey::<Sha512>::new(self.0.clone()).verify_prehash(&h, &sig_)
            }
        };
        verified.map_err(|_| Error::VerificationFailed)?;
        Ok(())
    }

    pub fn partial_blind_verify(
        pk_derived: PublicKey,
        sig: &Signature,
        msg_randomizer: Option<MessageRandomizer>,
        msg_prime: impl AsRef<[u8]>,
        _info: &[u8],
        options: &Options,
    ) -> Result<(), Error> {
        let msg_prime = msg_prime.as_ref();
        let modulus_bytes = pk_derived.0.size();
        if sig.len() != modulus_bytes {
            return Err(Error::UnsupportedParameters);
        }
        let sig_ =
            rsa::pss::Signature::try_from(sig.as_ref()).map_err(|_| Error::VerificationFailed)?;
        let verified = match options.hash {
            Hash::Sha256 => {
                let mut h = Sha256::new();
                if let Some(p) = msg_randomizer.as_ref() {
                    h.update(p.0);
                }
                h.update(msg_prime);
                let h = h.finalize().to_vec();
                rsa::pss::VerifyingKey::<Sha256>::new(pk_derived.0.clone()).verify_prehash(&h, &sig_)
            }
            Hash::Sha384 => {
                let mut h = Sha384::new();
                if let Some(p) = msg_randomizer.as_ref() {
                    h.update(p.0);
                }
                h.update(msg_prime);
                let h = h.finalize().to_vec();
                rsa::pss::VerifyingKey::<Sha384>::new(pk_derived.0.clone()).verify_prehash(&h, &sig_)
            }
            Hash::Sha512 => {
                let mut h = Sha512::new();
                if let Some(p) = msg_randomizer.as_ref() {
                    h.update(p.0);
                }
                h.update(msg_prime);
                let h = h.finalize().to_vec();
                rsa::pss::VerifyingKey::<Sha512>::new(pk_derived.0.clone()).verify_prehash(&h, &sig_)
            }
        };
        verified.map_err(|_| Error::VerificationFailed)?;
        Ok(())
    }
    
    pub fn derive_public_key(
        n: &BigUint,
        info: &[u8],
        hash: Hash,
    ) -> Result<PublicKey, Error> {
        let modulus_len = n.to_bytes_be().len();
        let lambda_len = modulus_len / 2;
        let hkdf_len = lambda_len + 16;

        // hkdf_input = concat("key", info, 0x00)
        let mut hkdf_input = Vec::with_capacity(4 + info.len() + 1);
        hkdf_input.extend_from_slice(b"key");
        hkdf_input.extend_from_slice(info);
        hkdf_input.push(0x00);

        // hkdf_salt = int_to_bytes(n, modulus_len)
        let hkdf_salt = n.to_bytes_be_padded(modulus_len);

        // expanded_bytes = HKDF(IKM=hkdf_input, salt=hkdf_salt, info="PBRSA", L=hkdf_len)
        let mut expanded_bytes = vec![0u8; hkdf_len];
        match hash {
            Hash::Sha256 => {
                let hmac_impl = Hkdf::<CoreWrapper<Sha256>>::new(Some(&hkdf_salt), &hkdf_input);
                hmac_impl.expand(b"PBRSA", &mut expanded_bytes).unwrap();
            }
            Hash::Sha384 => {
                let hmac_impl = Hkdf::<CoreWrapper<Sha384>>::new(Some(&hkdf_salt), &hkdf_input);
                hmac_impl.expand(b"PBRSA", &mut expanded_bytes).unwrap();
            }
            Hash::Sha512 => {
                let hmac_impl = Hkdf::<CoreWrapper<Sha512>>::new(Some(&hkdf_salt), &hkdf_input);
                hmac_impl.expand(b"PBRSA", &mut expanded_bytes).unwrap();
            }
        }
        // expanded_bytes[0] &= 0x3F
        expanded_bytes[0] &= 0x3F;
        // expanded_bytes[lambda_len-1] |= 0x01
        expanded_bytes[lambda_len - 1] |= 0x01;
        // e' = bytes_to_int(slice(expanded_bytes, 0, lambda_len))
        let e_prime = BigUint::from_bytes_be(&expanded_bytes[0..lambda_len]);
        
        let pk_derived = RsaPublicKey::new(n.clone(), e_prime)
            .map_err(|_| Error::UnsupportedParameters)?;
        Ok(PublicKey(pk_derived))
    }

}

impl SecretKey {
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.as_ref()
            .to_pkcs8_der()
            .map_err(|_| Error::EncodingError)
            .map(|x| mem::take(x.to_bytes().as_mut()))
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let mut sk = rsa::RsaPrivateKey::from_pkcs8_der(der)
            .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_der(der))
            .map_err(|_| Error::EncodingError)?;
        sk.validate().map_err(|_| Error::InvalidKey)?;
        sk.precompute().map_err(|_| Error::InvalidKey)?;
        Ok(SecretKey(sk))
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.as_ref()
            .to_pkcs8_pem(Default::default())
            .map_err(|_| Error::EncodingError)
            .map(|x| x.to_string())
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let mut sk = rsa::RsaPrivateKey::from_pkcs8_pem(pem)
            .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(pem))
            .map_err(|_| Error::EncodingError)?;
        sk.validate().map_err(|_| Error::InvalidKey)?;
        sk.precompute().map_err(|_| Error::InvalidKey)?;
        Ok(SecretKey(sk))
    }

    pub fn public_key(&self) -> Result<PublicKey, Error> {
        Ok(PublicKey(RsaPublicKey::from(self.as_ref())))
    }

    /// Sign a blinded message
    pub fn blind_sign<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        blind_msg: impl AsRef<[u8]>,
        _options: &Options,
    ) -> Result<BlindSignature, Error> {
        let modulus_bytes = self.0.size();
        if blind_msg.as_ref().len() != modulus_bytes {
            return Err(Error::UnsupportedParameters);
        }
        let blind_msg = BigUint::from_bytes_be(blind_msg.as_ref());
        if &blind_msg >= self.0.n() {
            return Err(Error::UnsupportedParameters);
        }
        let blind_sig = rsa_internals::decrypt_and_check(Some(rng), self.as_ref(), &blind_msg)
            .map_err(|_| Error::InternalError)?;
        Ok(BlindSignature(blind_sig.to_bytes_be_padded(modulus_bytes)))
    }

    pub fn partial_blind_sign<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        blind_msg: impl AsRef<[u8]>,
        info: &[u8],
        options: &Options,
    ) -> Result<BlindSignature, Error> {
        let modulus_bytes = self.0.size();
        if blind_msg.as_ref().len() != modulus_bytes {
            return Err(Error::UnsupportedParameters);
        }
        let blind_msg = BigUint::from_bytes_be(blind_msg.as_ref());
        if &blind_msg >= self.0.n() {
            return Err(Error::UnsupportedParameters);
        }
        let (sk_derived, _pk_derived) = self.derive_key_pair(info, options.hash.clone())?; 
        let blind_sig = rsa_internals::decrypt_and_check(Some(rng), sk_derived.as_ref(), &blind_msg)
            .map_err(|_| Error::InternalError)?;
        Ok(BlindSignature(blind_sig.to_bytes_be_padded(modulus_bytes)))
    }

    pub fn derive_key_pair(
        &self,
        info: &[u8],
        hash: Hash,
    ) -> Result<(SecretKey, PublicKey), Error> {
        // (n, e') = DerivePublicKey(n, info)
        let pk_derived = PublicKey::derive_public_key(self.0.n(), info, hash)?;

        let p = self.0.primes().to_vec()[0].clone();
        let q = self.0.primes().to_vec()[1].clone();
        let phi = (&p - BigUint::one()) * (&q - BigUint::one());

        // inverse_mod(e', phi)
        let e_prime = pk_derived.0.e();
        let d_prime = e_prime.clone().mod_inverse(phi.clone()).unwrap().to_biguint().unwrap(); 

        let sk_derived = RsaPrivateKey::from_components(
            self.0.n().clone(),
           phi,
            d_prime.clone(),
            vec![p,q]
        )
        .map_err(|_| Error::InternalError)?;

        Ok((SecretKey(sk_derived), pk_derived))
    }

}
