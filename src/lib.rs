//! Author-blinded RSASSA-PSS RSAE signatures.
//!
//! This is an implementation of the [RSA Blind Signatures](https://cfrg.github.io/draft-irtf-cfrg-blind-signatures/draft-irtf-cfrg-rsa-blind-signatures.html) proposal, based on [the Zig implementation](https://github.com/jedisct1/zig-rsa-blind-signatures).
//!
//! ```rust
//! use blind_rsa_signatures::{KeyPair, DefaultRng, Options};
//!
//! let options = Options::default();
//!
//! // [SERVER]: Generate a RSA-2048 key pair
//! let kp = KeyPair::generate(&mut DefaultRng, 2048)?;
//! let (pk, sk) = (kp.pk, kp.sk);
//!
//! // [CLIENT]: create a random message and blind it for the server whose public key is `pk`.
//! // The client must store the message and the secret.
//! let msg = b"test";
//! let blinding_result = pk.blind(&mut DefaultRng, msg, &options)?;
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
//! let sig = pk.finalize(
//!     &blind_sig,
//!     &blinding_result,
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

use std::convert::{Infallible, TryFrom};
use std::fmt::{self, Display};
use std::mem;

use crypto_bigint::{BoxedUint, Gcd};
use derive_more::{AsRef, Debug, Deref, From, Into};

use digest::{typenum::Unsigned, DynDigest, OutputSizeUser};
use hmac_sha256::Hash as Sha256;
use hmac_sha512::sha384::Hash as Sha384;
use hmac_sha512::Hash as Sha512;
use rsa::pkcs1::{DecodeRsaPrivateKey as _, DecodeRsaPublicKey as _};
use rsa::pkcs8::{
    DecodePrivateKey as _, DecodePublicKey as _, EncodePrivateKey as _, EncodePublicKey as _,
};
use rsa::rand_core::{CryptoRng, RngCore, TryCryptoRng, TryRngCore};
use rsa::signature::hazmat::PrehashVerifier;
use rsa::traits::PublicKeyParts as _;
use rsa::{RsaPrivateKey, RsaPublicKey};

mod blind_rsa;
mod mgf1;

use blind_rsa::{blind as rsa_blind, rsa_decrypt_and_check, unblind as rsa_unblind};
use mgf1::mgf1_xor;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub mod reexports {
    pub use {crypto_bigint, digest, hmac_sha256, hmac_sha512, rand, rsa};
}

/// Returns the byte representation of a BoxedUint in big-endian byte order,
/// left-padding the number with zeroes to the specified length.
fn to_bytes_be_padded(n: &BoxedUint, len: usize) -> Vec<u8> {
    let bytes = n.to_be_bytes();
    if len > bytes.len() {
        let mut result = vec![0u8; len];
        result[len - bytes.len()..].copy_from_slice(&bytes);
        result
    } else {
        bytes.to_vec()
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    InternalError,
    UnsupportedParameters,
    VerificationFailed,
    EncodingError,
    InvalidKey,
    IncompatibleParameters,
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

/// PSS mode to specify the use of salt
#[derive(Clone, Debug, Eq, PartialEq, From, new)]
pub enum PSSMode {
    PSS,
    PSSZero,
}

/// Prepare mode to specify whether or not to randomize the message
#[derive(Clone, Debug, Eq, PartialEq, From, new)]
pub enum PrepareMode {
    Randomized,
    Deterministic,
}

/// Options
#[derive(Clone, Debug, Eq, PartialEq, AsRef, From, Into, new)]
pub struct Options {
    /// Hash function to use for padding and for hashing the message
    hash: Hash,
    /// Either `PSSMode::PSS` to use salt, or `PSSMode::PSSZero` for empty salt
    pss_mode: PSSMode,
    /// Use deterministic or randomized message padding
    prepare: PrepareMode,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            hash: Hash::Sha384,
            pss_mode: PSSMode::PSS,
            prepare: PrepareMode::Randomized,
        }
    }
}

impl Options {
    pub const fn salt_len(&self) -> usize {
        match self.pss_mode {
            PSSMode::PSS => match self.hash {
                Hash::Sha256 => <<Sha256 as OutputSizeUser>::OutputSize as Unsigned>::USIZE,
                Hash::Sha384 => <<Sha384 as OutputSizeUser>::OutputSize as Unsigned>::USIZE,
                Hash::Sha512 => <<Sha512 as OutputSizeUser>::OutputSize as Unsigned>::USIZE,
            },
            PSSMode::PSSZero => 0,
        }
    }

    pub const fn is_randomized(&self) -> bool {
        match self.prepare {
            PrepareMode::Deterministic => false,
            PrepareMode::Randomized => true,
        }
    }
}

/// Default random number generator
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub struct DefaultRng;

impl TryRngCore for DefaultRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(rand::random())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(rand::random())
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        rand::fill(dest);
        Ok(())
    }
}

impl TryCryptoRng for DefaultRng {}

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

impl AsRef<[u8]> for MessageRandomizer {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsRef<[u8]> for Options {
    fn as_ref(&self) -> &[u8] {
        self.hash.as_ref()
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        match self {
            Hash::Sha256 => b"sha256",
            Hash::Sha384 => b"sha384",
            Hash::Sha512 => b"sha512",
        }
    }
}

impl AsRef<[u8]> for BlindingResult {
    fn as_ref(&self) -> &[u8] {
        self.blind_msg.as_ref()
    }
}

impl AsRef<[u8]> for Error {
    fn as_ref(&self) -> &[u8] {
        match self {
            Error::InternalError => b"Internal Error",
            Error::UnsupportedParameters => b"Unsupported parameters",
            Error::VerificationFailed => b"Verification failed",
            Error::EncodingError => b"Encoding error",
            Error::InvalidKey => b"Invalid key",
            Error::IncompatibleParameters => b"Incompatible parameters",
        }
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
    let em_len = em_bits.div_ceil(8);
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
        let e3 = BoxedUint::from(3u32);
        let ef4 = BoxedUint::from(65537u32);
        if e != &e3 && e != &ef4 {
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
        options: &Options,
    ) -> Result<BlindingResult, Error> {
        let msg = msg.as_ref();
        let modulus_bytes = self.0.size();
        let modulus_bits = modulus_bytes * 8;
        let msg_randomizer = if options.is_randomized() {
            let mut noise = [0u8; 32];
            rng.fill_bytes(&mut noise[..]);
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
        rng.fill_bytes(&mut salt[..]);

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
        let n = self.0.n();
        let n_bits = n.bits_precision();
        let m = BoxedUint::from_be_slice(&padded, n_bits).map_err(|_| Error::InternalError)?;
        let one = BoxedUint::one_with_precision(n_bits);
        if m.gcd(n.as_ref()) != one {
            return Err(Error::UnsupportedParameters);
        }

        let (blind_msg, secret) = rsa_blind(rng, self.as_ref(), &m);
        Ok(BlindingResult {
            blind_msg: BlindedMessage(to_bytes_be_padded(&blind_msg, modulus_bytes)),
            secret: Secret(to_bytes_be_padded(&secret, modulus_bytes)),
            msg_randomizer,
        })
    }

    /// Compute a valid signature for the original message given a blindly
    /// signed message
    pub fn finalize(
        &self,
        blind_sig: &BlindSignature,
        result: &BlindingResult,
        msg: impl AsRef<[u8]>,
        options: &Options,
    ) -> Result<Signature, Error> {
        let modulus_bytes = self.0.size();
        if blind_sig.len() != modulus_bytes || result.secret.len() != modulus_bytes {
            return Err(Error::UnsupportedParameters);
        }
        let n_bits = self.0.n().bits_precision();
        let blind_sig_uint =
            BoxedUint::from_be_slice(blind_sig, n_bits).map_err(|_| Error::InternalError)?;
        let secret_uint =
            BoxedUint::from_be_slice(&result.secret, n_bits).map_err(|_| Error::InternalError)?;
        let sig = Signature(to_bytes_be_padded(
            &rsa_unblind(self.as_ref(), &blind_sig_uint, &secret_uint),
            modulus_bytes,
        ));
        self.verify(&sig, result.msg_randomizer, msg, options)?;
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
        let salt_len = options.salt_len();
        let verified = match options.hash {
            Hash::Sha256 => {
                let mut h = Sha256::new();
                if let Some(p) = msg_randomizer.as_ref() {
                    h.update(p.0);
                }
                h.update(msg);
                let h = h.finalize().to_vec();
                rsa::pss::VerifyingKey::<Sha256>::new_with_salt_len(self.0.clone(), salt_len)
                    .verify_prehash(&h, &sig_)
            }
            Hash::Sha384 => {
                let mut h = Sha384::new();
                if let Some(p) = msg_randomizer.as_ref() {
                    h.update(p.0);
                }
                h.update(msg);
                let h = h.finalize().to_vec();
                rsa::pss::VerifyingKey::<Sha384>::new_with_salt_len(self.0.clone(), salt_len)
                    .verify_prehash(&h, &sig_)
            }
            Hash::Sha512 => {
                let mut h = Sha512::new();
                if let Some(p) = msg_randomizer.as_ref() {
                    h.update(p.0);
                }
                h.update(msg);
                let h = h.finalize().to_vec();
                rsa::pss::VerifyingKey::<Sha512>::new_with_salt_len(self.0.clone(), salt_len)
                    .verify_prehash(&h, &sig_)
            }
        };
        verified.map_err(|_| Error::VerificationFailed)?;
        Ok(())
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
    pub fn blind_sign(
        &self,
        blind_msg: impl AsRef<[u8]>,
        _options: &Options,
    ) -> Result<BlindSignature, Error> {
        let modulus_bytes = self.0.size();
        if blind_msg.as_ref().len() != modulus_bytes {
            return Err(Error::UnsupportedParameters);
        }
        let n_bits = self.0.n().bits_precision();
        let blind_msg_uint = BoxedUint::from_be_slice(blind_msg.as_ref(), n_bits)
            .map_err(|_| Error::InternalError)?;
        if &blind_msg_uint >= self.0.n().as_ref() {
            return Err(Error::UnsupportedParameters);
        }
        let blind_sig = rsa_decrypt_and_check(self.as_ref(), &blind_msg_uint)
            .map_err(|_| Error::InternalError)?;
        Ok(BlindSignature(to_bytes_be_padded(
            &blind_sig,
            modulus_bytes,
        )))
    }
}
