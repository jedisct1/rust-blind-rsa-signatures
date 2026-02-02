//! Author-blinded RSASSA-PSS RSAE signatures.
//!
//! This is an implementation of the [RSA Blind Signatures](https://www.rfc-editor.org/rfc/rfc9474.html) (RFC 9474), based on [the Zig implementation](https://github.com/jedisct1/zig-rsa-blind-signatures).
//!
//! ```rust
//! use blind_rsa_signatures::{KeyPair, Sha384, PSS, Randomized, DefaultRng};
//!
//! // [SERVER]: Generate a RSA-2048 key pair
//! let kp = KeyPair::<Sha384, PSS, Randomized>::generate(&mut DefaultRng, 2048)?;
//! let (pk, sk) = (kp.pk, kp.sk);
//!
//! // [CLIENT]: create a random message and blind it for the server whose public key is `pk`.
//! // The client must store the message and the secret.
//! let msg = b"test";
//! let blinding_result = pk.blind(&mut DefaultRng, msg)?;
//!
//! // [SERVER]: compute a signature for a blind message, to be sent to the client.
//! // The client secret should not be sent to the server.
//! let blind_sig = sk.blind_sign(&blinding_result.blind_message)?;
//!
//! // [CLIENT]: later, when the client wants to redeem a signed blind message,
//! // using the blinding secret, it can locally compute the signature of the
//! // original message.
//! // The client then owns a new valid (message, signature) pair, and the
//! // server cannot link it to a previous (blinded message, blind signature) pair.
//! // Note that the finalization function also verifies that the new signature
//! // is correct for the server public key.
//! let sig = pk.finalize(&blind_sig, &blinding_result, msg)?;
//!
//! // [SERVER]: a non-blind signature can be verified using the server's public key.
//! pk.verify(&sig, blinding_result.msg_randomizer, msg)?;
//! # Ok::<(), blind_rsa_signatures::Error>(())
//! ```

#[macro_use]
extern crate derive_new;

use std::convert::{Infallible, TryFrom};
use std::fmt::{self, Display};
use std::marker::PhantomData;
use std::mem;

use crypto_bigint::{BoxedUint, Gcd};
use derive_more::{AsRef, Debug, Deref, From, Into};

use digest::{typenum::Unsigned, DynDigest, OutputSizeUser};
use hmac_sha256::Hash as Sha256Hash;
use hmac_sha512::sha384::Hash as Sha384Hash;
use hmac_sha512::Hash as Sha512Hash;
use rsa::hazmat::rsa_decrypt_and_check;
use rsa::pkcs1::{DecodeRsaPrivateKey as _, DecodeRsaPublicKey as _};
use rsa::pkcs8::{
    DecodePrivateKey as _, DecodePublicKey as _, EncodePrivateKey as _, EncodePublicKey as _,
};
use rsa::rand_core::{CryptoRng, TryCryptoRng, TryRng};
use rsa::signature::hazmat::PrehashVerifier;
use rsa::traits::PublicKeyParts as _;
use rsa::{RsaPrivateKey, RsaPublicKey};

mod brsa;
mod mgf1;
pub mod pbrsa;

mod private {
    pub trait Sealed {}
}

use brsa::{blind as rsa_blind, unblind as rsa_unblind};
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

pub trait HashAlgorithm: Clone + Default {
    /// Salt length for PSS padding (equals hash output length)
    const SALT_LEN: usize;
    /// OID byte for SPKI encoding (1=SHA256, 2=SHA384, 3=SHA512)
    const OID_BYTE: u8;
    /// Algorithm name as bytes
    const NAME: &'static [u8];

    /// Create a new boxed hasher
    fn new_hasher() -> Box<dyn DynDigest>;

    /// Hash a message with an optional prefix
    fn hash_message(prefix: Option<&[u8]>, msg: &[u8]) -> Vec<u8> {
        let mut h = Self::new_hasher();
        if let Some(p) = prefix {
            h.update(p);
        }
        h.update(msg);
        h.finalize().to_vec()
    }

    /// Verify a prehashed signature
    fn verify_prehash(
        pk: &RsaPublicKey,
        salt_len: usize,
        msg_hash: &[u8],
        sig: &rsa::pss::Signature,
    ) -> Result<(), rsa::signature::Error>;

    /// HKDF key derivation for PBRSA
    fn hkdf_expand(out: &mut [u8], salt: &[u8], ikm: &[u8], info: &[u8]);
}

/// SHA-256 hash algorithm
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Sha256;

impl HashAlgorithm for Sha256 {
    const SALT_LEN: usize = <<Sha256Hash as OutputSizeUser>::OutputSize as Unsigned>::USIZE;
    const OID_BYTE: u8 = 1;
    const NAME: &'static [u8] = b"sha256";

    fn new_hasher() -> Box<dyn DynDigest> {
        Box::new(Sha256Hash::new())
    }

    fn verify_prehash(
        pk: &RsaPublicKey,
        salt_len: usize,
        msg_hash: &[u8],
        sig: &rsa::pss::Signature,
    ) -> Result<(), rsa::signature::Error> {
        rsa::pss::VerifyingKey::<Sha256Hash>::new_with_salt_len(pk.clone(), salt_len)
            .verify_prehash(msg_hash, sig)
    }

    fn hkdf_expand(out: &mut [u8], salt: &[u8], ikm: &[u8], info: &[u8]) {
        let prk = hmac_sha256::HKDF::extract(salt, ikm);
        hmac_sha256::HKDF::expand(out, prk, info);
    }
}

/// SHA-384 hash algorithm
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Sha384;

impl HashAlgorithm for Sha384 {
    const SALT_LEN: usize = <<Sha384Hash as OutputSizeUser>::OutputSize as Unsigned>::USIZE;
    const OID_BYTE: u8 = 2;
    const NAME: &'static [u8] = b"sha384";

    fn new_hasher() -> Box<dyn DynDigest> {
        Box::new(Sha384Hash::new())
    }

    fn verify_prehash(
        pk: &RsaPublicKey,
        salt_len: usize,
        msg_hash: &[u8],
        sig: &rsa::pss::Signature,
    ) -> Result<(), rsa::signature::Error> {
        rsa::pss::VerifyingKey::<Sha384Hash>::new_with_salt_len(pk.clone(), salt_len)
            .verify_prehash(msg_hash, sig)
    }

    fn hkdf_expand(out: &mut [u8], salt: &[u8], ikm: &[u8], info: &[u8]) {
        let prk = hmac_sha512::sha384::HKDF::extract(salt, ikm);
        hmac_sha512::sha384::HKDF::expand(out, prk, info);
    }
}

/// SHA-512 hash algorithm
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Sha512;

impl HashAlgorithm for Sha512 {
    const SALT_LEN: usize = <<Sha512Hash as OutputSizeUser>::OutputSize as Unsigned>::USIZE;
    const OID_BYTE: u8 = 3;
    const NAME: &'static [u8] = b"sha512";

    fn new_hasher() -> Box<dyn DynDigest> {
        Box::new(Sha512Hash::new())
    }

    fn verify_prehash(
        pk: &RsaPublicKey,
        salt_len: usize,
        msg_hash: &[u8],
        sig: &rsa::pss::Signature,
    ) -> Result<(), rsa::signature::Error> {
        rsa::pss::VerifyingKey::<Sha512Hash>::new_with_salt_len(pk.clone(), salt_len)
            .verify_prehash(msg_hash, sig)
    }

    fn hkdf_expand(out: &mut [u8], salt: &[u8], ikm: &[u8], info: &[u8]) {
        let prk = hmac_sha512::HKDF::extract(salt, ikm);
        hmac_sha512::HKDF::expand(out, prk, info);
    }
}

/// Trait for PSS salt mode (compile-time parameter)
/// The only valid implementations are [`PSS`] and [`PSSZero`].
pub trait SaltMode: Clone + Default + private::Sealed {
    /// Whether salt is used
    const USE_SALT: bool;

    /// Get salt length for a given hash algorithm
    fn salt_len<H: HashAlgorithm>() -> usize {
        if Self::USE_SALT {
            H::SALT_LEN
        } else {
            0
        }
    }
}

/// PSS mode with salt (salt length = hash output length)
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PSS;

impl private::Sealed for PSS {}

impl SaltMode for PSS {
    const USE_SALT: bool = true;
}

/// PSS mode without salt (salt length = 0)
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PSSZero;

impl private::Sealed for PSSZero {}

impl SaltMode for PSSZero {
    const USE_SALT: bool = false;
}

/// Trait for message preparation mode (compile-time parameter)
/// The only valid implementations are [`Randomized`] and [`Deterministic`].
pub trait MessagePrepare: Clone + Default + private::Sealed {
    /// Whether to randomize the message with a 32-byte prefix
    const RANDOMIZE: bool;
}

/// Randomized message preparation
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Randomized;

impl private::Sealed for Randomized {}

impl MessagePrepare for Randomized {
    const RANDOMIZE: bool = true;
}

/// Deterministic message preparation
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Deterministic;

impl private::Sealed for Deterministic {}

impl MessagePrepare for Deterministic {
    const RANDOMIZE: bool = false;
}

/// Default random number generator
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub struct DefaultRng;

impl TryRng for DefaultRng {
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

/// A blinding secret factor
#[derive(Clone, Debug, AsRef, Deref, From, Into, new)]
pub struct Secret(pub Vec<u8>);

impl Eq for Secret {}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        ct_codecs::verify(&self.0, &other.0)
    }
}

/// A blind message
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, Eq, PartialEq, AsRef, Deref, From, Into, new)]
pub struct BlindMessage(pub Vec<u8>);

/// A blind signature
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, Eq, PartialEq, AsRef, Deref, From, Into, new)]
pub struct BlindSignature(pub Vec<u8>);

/// A (non-blind) signature
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, Eq, PartialEq, AsRef, Deref, From, Into, new)]
pub struct Signature(pub Vec<u8>);

/// A message randomizer (noise added as a prefix to the message)
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, AsRef, Deref, From, Into, new)]
pub struct MessageRandomizer(pub [u8; 32]);

/// Result of a blinding operation
#[derive(Clone, Debug)]
pub struct BlindingResult {
    pub blind_message: BlindMessage,
    pub secret: Secret,
    pub msg_randomizer: Option<MessageRandomizer>,
}

impl Eq for BlindingResult {}

impl PartialEq for BlindingResult {
    fn eq(&self, other: &Self) -> bool {
        self.blind_message == other.blind_message
            && self.secret == other.secret
            && self.msg_randomizer == other.msg_randomizer
    }
}

impl AsRef<[u8]> for Secret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsRef<[u8]> for BlindMessage {
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

impl AsRef<[u8]> for BlindingResult {
    fn as_ref(&self) -> &[u8] {
        self.blind_message.as_ref()
    }
}

fn check_rsa_parameters(pk: &RsaPublicKey) -> Result<(), Error> {
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

#[allow(clippy::identity_op)]
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
    let h = &mut h[..h_len];
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

/// Blind RSA signatures with compile-time parameters.
///
/// This mirrors the Zig API where `BlindRsa` returns a type containing
/// `PublicKey`, `SecretKey`, and `KeyPair` with methods for the protocol.
///
/// Type parameters:
/// - `H`: Hash algorithm ([`Sha256`], [`Sha384`], [`Sha512`])
/// - `S`: Salt mode ([`PSS`], [`PSSZero`])
/// - `M`: Message preparation mode ([`Randomized`], [`Deterministic`])
///
/// # Example
///
/// ```rust
/// use blind_rsa_signatures::{BlindRsa, Sha384, PSS, Randomized};
///
/// type BRsa = BlindRsa<Sha384, PSS, Randomized>;
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlindRsa<H: HashAlgorithm, S: SaltMode, M: MessagePrepare> {
    _phantom: PhantomData<(H, S, M)>,
}

impl<H: HashAlgorithm, S: SaltMode, M: MessagePrepare> BlindRsa<H, S, M> {
    /// Get the salt length for this configuration
    pub const fn salt_len() -> usize {
        if S::USE_SALT {
            H::SALT_LEN
        } else {
            0
        }
    }

    /// Check if this configuration uses randomized message preparation
    pub const fn is_randomized() -> bool {
        M::RANDOMIZE
    }
}

/// Type alias for PublicKey with the same parameters as BlindRsa
pub type BlindRsaPublicKey<H, S, M> = PublicKey<H, S, M>;

/// Type alias for SecretKey with the same parameters as BlindRsa
pub type BlindRsaSecretKey<H, S, M> = SecretKey<H, S, M>;

/// Type alias for KeyPair with the same parameters as BlindRsa
pub type BlindRsaKeyPair<H, S, M> = KeyPair<H, S, M>;

/// An RSA public key
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey<H: HashAlgorithm, S: SaltMode, M: MessagePrepare> {
    inner: RsaPublicKey,
    _phantom: PhantomData<(H, S, M)>,
}

/// Provides access to the raw RSA public key components.
pub struct PublicKeyComponents<'a> {
    inner: &'a RsaPublicKey,
}

impl PublicKeyComponents<'_> {
    /// Returns the modulus (n) as big-endian bytes.
    pub fn n(&self) -> Vec<u8> {
        use rsa::traits::PublicKeyParts;
        self.inner.n().as_ref().to_be_bytes().into_vec()
    }

    /// Returns the public exponent (e) as big-endian bytes.
    pub fn e(&self) -> Vec<u8> {
        use rsa::traits::PublicKeyParts;
        self.inner.e().to_be_bytes().into_vec()
    }
}

impl<H: HashAlgorithm, S: SaltMode, M: MessagePrepare> PublicKey<H, S, M> {
    pub fn new(inner: RsaPublicKey) -> Self {
        Self {
            inner,
            _phantom: PhantomData,
        }
    }

    /// Returns an accessor for the raw RSA key components.
    pub fn components(&self) -> PublicKeyComponents<'_> {
        PublicKeyComponents { inner: &self.inner }
    }

    fn salt_len() -> usize {
        if S::USE_SALT {
            H::SALT_LEN
        } else {
            0
        }
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.inner
            .to_public_key_der()
            .map_err(|_| Error::EncodingError)
            .map(|x| x.as_ref().to_vec())
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        if der.len() > 800 {
            return Err(Error::EncodingError);
        }
        let inner = rsa::RsaPublicKey::from_public_key_der(der)
            .or_else(|_| rsa::RsaPublicKey::from_pkcs1_der(der))
            .map_err(|_| Error::EncodingError)?;
        check_rsa_parameters(&inner)?;
        Ok(Self::new(inner))
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.inner
            .to_public_key_pem(Default::default())
            .map_err(|_| Error::EncodingError)
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        if pem.len() > 1000 {
            return Err(Error::EncodingError);
        }
        let pem = pem.trim();
        let inner = rsa::RsaPublicKey::from_public_key_pem(pem)
            .or_else(|_| rsa::RsaPublicKey::from_pkcs1_pem(pem))
            .map_err(|_| Error::EncodingError)?;
        check_rsa_parameters(&inner)?;
        Ok(Self::new(inner))
    }

    pub fn to_spki(&self) -> Result<Vec<u8>, Error> {
        let tpl = spki_tpl();
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
        out[66] = Self::salt_len() as u8;
        out[69..71].copy_from_slice(&(1 + raw.len() as u16).to_be_bytes());
        let mut mgf1_s: [u8; 13] = [48, 11, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 0];
        mgf1_s[12] = H::OID_BYTE;
        out[21..][..mgf1_s.len()].copy_from_slice(&mgf1_s);
        out[49..][..mgf1_s.len()].copy_from_slice(&mgf1_s);
        Ok(out)
    }

    pub fn from_spki(spki: &[u8]) -> Result<Self, Error> {
        if spki.len() > 800 {
            return Err(Error::EncodingError);
        }
        let tpl = spki_tpl();
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

    /// Blind a message to be signed
    pub fn blind<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: impl AsRef<[u8]>,
    ) -> Result<BlindingResult, Error> {
        let msg = msg.as_ref();
        let modulus_bytes = self.inner.size();
        let modulus_bits = self.inner.n().as_ref().bits() as usize;
        let msg_randomizer = if M::RANDOMIZE {
            let mut noise = [0u8; 32];
            rng.fill_bytes(&mut noise[..]);
            Some(MessageRandomizer(noise))
        } else {
            None
        };
        let msg_hash = H::hash_message(msg_randomizer.as_ref().map(|r| r.0.as_slice()), msg);
        let salt_len = Self::salt_len();
        let mut salt = vec![0u8; salt_len];
        rng.fill_bytes(&mut salt[..]);

        let padded = emsa_pss_encode(&msg_hash, modulus_bits - 1, &salt, &mut *H::new_hasher())?;
        let n = self.inner.n();
        let n_bits = n.bits_precision();
        let m = BoxedUint::from_be_slice(&padded, n_bits).map_err(|_| Error::InternalError)?;
        let one = BoxedUint::one_with_precision(n_bits);
        if m.gcd(n.as_ref()) != one {
            return Err(Error::UnsupportedParameters);
        }

        let (blind_msg, secret) = rsa_blind(rng, &self.inner, &m);
        Ok(BlindingResult {
            blind_message: BlindMessage(to_bytes_be_padded(&blind_msg, modulus_bytes)),
            secret: Secret(to_bytes_be_padded(&secret, modulus_bytes)),
            msg_randomizer,
        })
    }

    /// Finalize a blind signature to obtain the actual signature
    pub fn finalize(
        &self,
        blind_sig: &BlindSignature,
        result: &BlindingResult,
        msg: impl AsRef<[u8]>,
    ) -> Result<Signature, Error> {
        let modulus_bytes = self.inner.size();
        if blind_sig.len() != modulus_bytes || result.secret.len() != modulus_bytes {
            return Err(Error::UnsupportedParameters);
        }
        let n_bits = self.inner.n().bits_precision();
        let blind_sig_uint =
            BoxedUint::from_be_slice(blind_sig, n_bits).map_err(|_| Error::InternalError)?;
        let secret_uint =
            BoxedUint::from_be_slice(&result.secret, n_bits).map_err(|_| Error::InternalError)?;
        let sig = Signature(to_bytes_be_padded(
            &rsa_unblind(&self.inner, &blind_sig_uint, &secret_uint),
            modulus_bytes,
        ));
        self.verify(&sig, result.msg_randomizer, msg)?;
        Ok(sig)
    }

    /// Verify a signature
    pub fn verify(
        &self,
        sig: &Signature,
        msg_randomizer: Option<MessageRandomizer>,
        msg: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let msg = msg.as_ref();
        let modulus_bytes = self.inner.size();
        if sig.len() != modulus_bytes {
            return Err(Error::UnsupportedParameters);
        }
        let sig_ =
            rsa::pss::Signature::try_from(sig.as_ref()).map_err(|_| Error::VerificationFailed)?;
        let salt_len = Self::salt_len();
        let msg_hash = H::hash_message(msg_randomizer.as_ref().map(|r| r.0.as_slice()), msg);
        H::verify_prehash(&self.inner, salt_len, &msg_hash, &sig_)
            .map_err(|_| Error::VerificationFailed)
    }
}

impl<H: HashAlgorithm, S: SaltMode, M: MessagePrepare> AsRef<RsaPublicKey> for PublicKey<H, S, M> {
    fn as_ref(&self) -> &RsaPublicKey {
        &self.inner
    }
}

/// An RSA secret key
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct SecretKey<H: HashAlgorithm, S: SaltMode, M: MessagePrepare> {
    inner: RsaPrivateKey,
    _phantom: PhantomData<(H, S, M)>,
}

/// Provides access to the raw RSA secret key components.
pub struct SecretKeyComponents<'a> {
    inner: &'a RsaPrivateKey,
}

impl SecretKeyComponents<'_> {
    /// Returns the modulus (n) as big-endian bytes.
    pub fn n(&self) -> Vec<u8> {
        use rsa::traits::PublicKeyParts;
        self.inner.n().as_ref().to_be_bytes().into_vec()
    }

    /// Returns the public exponent (e) as big-endian bytes.
    pub fn e(&self) -> Vec<u8> {
        use rsa::traits::PublicKeyParts;
        self.inner.e().to_be_bytes().into_vec()
    }

    /// Returns the private exponent (d) as big-endian bytes.
    pub fn d(&self) -> Vec<u8> {
        use rsa::traits::PrivateKeyParts;
        self.inner.d().to_be_bytes().into_vec()
    }

    /// Returns the prime factors (p, q, ...) as big-endian bytes.
    pub fn primes(&self) -> Vec<Vec<u8>> {
        use rsa::traits::PrivateKeyParts;
        self.inner
            .primes()
            .iter()
            .map(|p| p.to_be_bytes().into_vec())
            .collect()
    }
}

impl<H: HashAlgorithm, S: SaltMode, M: MessagePrepare> SecretKey<H, S, M> {
    pub fn new(inner: RsaPrivateKey) -> Self {
        Self {
            inner,
            _phantom: PhantomData,
        }
    }

    /// Returns an accessor for the raw RSA key components.
    pub fn components(&self) -> SecretKeyComponents<'_> {
        SecretKeyComponents { inner: &self.inner }
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.inner
            .to_pkcs8_der()
            .map_err(|_| Error::EncodingError)
            .map(|x| mem::take(x.to_bytes().as_mut()))
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let mut inner = rsa::RsaPrivateKey::from_pkcs8_der(der)
            .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_der(der))
            .map_err(|_| Error::EncodingError)?;
        inner.validate().map_err(|_| Error::InvalidKey)?;
        inner.precompute().map_err(|_| Error::InvalidKey)?;
        let sk = Self::new(inner);
        sk.public_key()?;
        Ok(sk)
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.inner
            .to_pkcs8_pem(Default::default())
            .map_err(|_| Error::EncodingError)
            .map(|x| x.to_string())
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let mut inner = rsa::RsaPrivateKey::from_pkcs8_pem(pem)
            .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(pem))
            .map_err(|_| Error::EncodingError)?;
        inner.validate().map_err(|_| Error::InvalidKey)?;
        inner.precompute().map_err(|_| Error::InvalidKey)?;
        let sk = Self::new(inner);
        sk.public_key()?;
        Ok(sk)
    }

    /// Recover the public key
    pub fn public_key(&self) -> Result<PublicKey<H, S, M>, Error> {
        let inner = RsaPublicKey::from(&self.inner);
        check_rsa_parameters(&inner)?;
        Ok(PublicKey::new(inner))
    }

    /// Sign a blinded message
    pub fn blind_sign(&self, blind_msg: impl AsRef<[u8]>) -> Result<BlindSignature, Error> {
        let mut rng = DefaultRng;
        self.blind_sign_with_rng(&mut rng, blind_msg)
    }

    /// Sign a blinded message using the provided RNG for RSA blinding
    pub fn blind_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        blind_msg: impl AsRef<[u8]>,
    ) -> Result<BlindSignature, Error> {
        let modulus_bytes = self.inner.size();
        if blind_msg.as_ref().len() != modulus_bytes {
            return Err(Error::UnsupportedParameters);
        }
        let n_bits = self.inner.n().bits_precision();
        let blind_msg_uint = BoxedUint::from_be_slice(blind_msg.as_ref(), n_bits)
            .map_err(|_| Error::InternalError)?;
        if &blind_msg_uint >= self.inner.n().as_ref() {
            return Err(Error::UnsupportedParameters);
        }
        let blind_sig = rsa_decrypt_and_check(&self.inner, Some(rng), &blind_msg_uint)
            .map_err(|_| Error::InternalError)?;
        Ok(BlindSignature(to_bytes_be_padded(
            &blind_sig,
            modulus_bytes,
        )))
    }
}

impl<H: HashAlgorithm, S: SaltMode, M: MessagePrepare> AsRef<RsaPrivateKey> for SecretKey<H, S, M> {
    fn as_ref(&self) -> &RsaPrivateKey {
        &self.inner
    }
}

impl<H: HashAlgorithm, S: SaltMode, M: MessagePrepare> Eq for SecretKey<H, S, M> {}

impl<H: HashAlgorithm, S: SaltMode, M: MessagePrepare> PartialEq for SecretKey<H, S, M> {
    fn eq(&self, other: &Self) -> bool {
        // RsaPrivateKey currently uses BoxedUint internally, which implements
        // constant-time comparison when the moduli are the same.
        self.inner == other.inner
    }
}

/// An RSA key pair
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyPair<H: HashAlgorithm, S: SaltMode, M: MessagePrepare> {
    pub pk: PublicKey<H, S, M>,
    pub sk: SecretKey<H, S, M>,
}

impl<H: HashAlgorithm, S: SaltMode, M: MessagePrepare> KeyPair<H, S, M> {
    /// Generate a new key pair
    pub fn generate<R: CryptoRng + ?Sized>(
        rng: &mut R,
        modulus_bits: usize,
    ) -> Result<Self, Error> {
        if !(2048..=4096).contains(&modulus_bits) {
            return Err(Error::UnsupportedParameters);
        }
        let mut inner =
            RsaPrivateKey::new(rng, modulus_bits).map_err(|_| Error::UnsupportedParameters)?;
        inner.precompute().map_err(|_| Error::InternalError)?;
        let sk = SecretKey::new(inner);
        let pk = sk.public_key()?;
        Ok(Self { pk, sk })
    }
}

/// RSABSSA-SHA384-PSS-Randomized (RFC 9474 recommended)
pub type BlindRsaSha384PSSRandomized = BlindRsa<Sha384, PSS, Randomized>;

/// RSABSSA-SHA384-PSSZERO-Randomized
pub type BlindRsaSha384PSSZeroRandomized = BlindRsa<Sha384, PSSZero, Randomized>;

/// RSABSSA-SHA384-PSS-Deterministic
pub type BlindRsaSha384PSSDeterministic = BlindRsa<Sha384, PSS, Deterministic>;

/// RSABSSA-SHA384-PSSZERO-Deterministic
pub type BlindRsaSha384PSSZeroDeterministic = BlindRsa<Sha384, PSSZero, Deterministic>;

/// Public key for RSABSSA-SHA384-PSS-Randomized (RFC 9474 recommended)
pub type PublicKeySha384PSSRandomized = PublicKey<Sha384, PSS, Randomized>;

/// Secret key for RSABSSA-SHA384-PSS-Randomized (RFC 9474 recommended)
pub type SecretKeySha384PSSRandomized = SecretKey<Sha384, PSS, Randomized>;

/// Key pair for RSABSSA-SHA384-PSS-Randomized (RFC 9474 recommended)
pub type KeyPairSha384PSSRandomized = KeyPair<Sha384, PSS, Randomized>;

/// Public key for RSABSSA-SHA384-PSSZERO-Randomized
pub type PublicKeySha384PSSZeroRandomized = PublicKey<Sha384, PSSZero, Randomized>;

/// Secret key for RSABSSA-SHA384-PSSZERO-Randomized
pub type SecretKeySha384PSSZeroRandomized = SecretKey<Sha384, PSSZero, Randomized>;

/// Key pair for RSABSSA-SHA384-PSSZERO-Randomized
pub type KeyPairSha384PSSZeroRandomized = KeyPair<Sha384, PSSZero, Randomized>;

/// Public key for RSABSSA-SHA384-PSS-Deterministic
pub type PublicKeySha384PSSDeterministic = PublicKey<Sha384, PSS, Deterministic>;

/// Secret key for RSABSSA-SHA384-PSS-Deterministic
pub type SecretKeySha384PSSDeterministic = SecretKey<Sha384, PSS, Deterministic>;

/// Key pair for RSABSSA-SHA384-PSS-Deterministic
pub type KeyPairSha384PSSDeterministic = KeyPair<Sha384, PSS, Deterministic>;

/// Public key for RSABSSA-SHA384-PSSZERO-Deterministic
pub type PublicKeySha384PSSZeroDeterministic = PublicKey<Sha384, PSSZero, Deterministic>;

/// Secret key for RSABSSA-SHA384-PSSZERO-Deterministic
pub type SecretKeySha384PSSZeroDeterministic = SecretKey<Sha384, PSSZero, Deterministic>;

/// Key pair for RSABSSA-SHA384-PSSZERO-Deterministic
pub type KeyPairSha384PSSZeroDeterministic = KeyPair<Sha384, PSSZero, Deterministic>;
