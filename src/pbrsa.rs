//! Partially Blind RSA Signatures (Draft IRTF CFRG)
//!
//! This module implements partially blind RSA signatures, which allow a signer to bind
//! signatures to public metadata while maintaining blindness of the message content.
//!
//! The main difference from regular blind RSA signatures is that:
//! - Keys can be derived for specific metadata values
//! - The message hash includes the metadata
//! - Keys must use safe primes (p and q where (p-1)/2 and (q-1)/2 are also prime)
//!
//! # Example
//!
//! ```rust,no_run
//! use blind_rsa_signatures::pbrsa::{PartiallyBlindKeyPair, DefaultRng};
//! use blind_rsa_signatures::{Sha384, PSS, Randomized};
//!
//! // [SERVER]: Generate a RSA-2048 key pair with safe primes
//! let kp = PartiallyBlindKeyPair::<Sha384, PSS, Randomized>::generate(&mut DefaultRng, 2048).unwrap();
//!
//! // [SERVER]: Derive a key pair for specific metadata
//! let metadata = b"payment-id-12345";
//! let derived_kp = kp.derive_key_pair_for_metadata(metadata).unwrap();
//!
//! // [CLIENT]: Blind a message with metadata
//! let msg = b"transaction data";
//! let blinding_result = derived_kp.pk.blind(&mut DefaultRng, msg, Some(metadata)).unwrap();
//!
//! // [SERVER]: Sign the blinded message
//! let blind_sig = derived_kp.sk.blind_sign(&blinding_result.blind_message).unwrap();
//!
//! // [CLIENT]: Finalize to get the actual signature
//! let sig = derived_kp.pk.finalize(&blind_sig, &blinding_result, msg, Some(metadata)).unwrap();
//!
//! // [ANYONE]: Verify the signature with metadata
//! derived_kp.pk.verify(&sig, blinding_result.msg_randomizer, msg, Some(metadata)).unwrap();
//! ```

use std::convert::TryFrom;
use std::marker::PhantomData;

use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BoxedUint, Gcd, Integer, NonZero, Odd, Resize};
use digest::DynDigest;
use rsa::hazmat::rsa_decrypt_and_check;
use rsa::pkcs1::{DecodeRsaPrivateKey as _, DecodeRsaPublicKey as _};
use rsa::pkcs8::{
    DecodePrivateKey as _, DecodePublicKey as _, EncodePrivateKey as _, EncodePublicKey as _,
};
use rsa::rand_core::CryptoRng;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::CrtValue;
use rsa::{RsaPrivateKey, RsaPublicKey};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::brsa::{blind as rsa_blind, unblind as rsa_unblind};
use crate::mgf1::mgf1_xor;
use crate::{
    to_bytes_be_padded, BlindMessage, BlindSignature, BlindingResult, Deterministic, Error,
    HashAlgorithm, MessagePrepare, MessageRandomizer, PSS, PSSZero, Randomized, SaltMode, Secret,
    Sha384, Signature,
};

pub use crate::DefaultRng;

/// Small primes for trial division
const SMALL_PRIMES: [u32; 100] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
    311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
    431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
];

/// Quick trial division check
fn passes_trial_division(n: &BoxedUint) -> bool {
    let n_bits = n.bits_precision();
    for &p in &SMALL_PRIMES[1..] {
        // Skip 2, we already know n is odd
        let p_uint = Resize::resize(BoxedUint::from(p), n_bits);
        if n == &p_uint {
            return true;
        }
        let p_nz: NonZero<BoxedUint> = match NonZero::new(p_uint).into() {
            Some(nz) => nz,
            None => continue,
        };
        if n.rem(&p_nz).is_zero().into() {
            return false;
        }
    }
    true
}

/// Check if a number is a Miller-Rabin probable prime
fn is_probable_prime(n: &BoxedUint, iterations: usize) -> bool {
    use crypto_bigint::modular::BoxedMontyForm;

    let n_bits = n.bits_precision();
    let one = BoxedUint::one_with_precision(n_bits);
    let two = Resize::resize(BoxedUint::from(2u32), n_bits);

    if n <= &two {
        return n == &two;
    }
    if n.is_even().into() {
        return false;
    }

    if !passes_trial_division(n) {
        return false;
    }

    // Write n-1 as 2^r * d where d is odd
    let n_minus_1 = n.wrapping_sub(&one);
    let mut d = n_minus_1.clone();
    let mut r = 0usize;
    while d.is_even().into() {
        d = d.shr(1);
        r += 1;
    }

    let n_odd: Odd<BoxedUint> = match Odd::<BoxedUint>::new(n.clone()).into() {
        Some(o) => o,
        None => return false,
    };
    let params = crypto_bigint::modular::BoxedMontyParams::new(n_odd);

    // Miller-Rabin test with fixed small bases first (deterministic for small numbers)
    let small_bases: [u32; 7] = [2, 3, 5, 7, 11, 13, 17];

    for &base in &small_bases[..iterations.min(small_bases.len())] {
        let a = Resize::resize(BoxedUint::from(base), n_bits);
        if a >= *n {
            continue;
        }

        let a_monty = BoxedMontyForm::new(a, &params);
        let mut x = a_monty.pow(&d);
        let mut x_val = x.retrieve();

        if x_val == one || x_val == n_minus_1 {
            continue;
        }

        let mut composite = true;
        for _ in 0..r.saturating_sub(1) {
            x = x.square();
            x_val = x.retrieve();
            if x_val == n_minus_1 {
                composite = false;
                break;
            }
            if x_val == one {
                return false;
            }
        }

        if composite {
            return false;
        }
    }

    true
}

/// Check if a prime is a "safe prime" (i.e., (p-1)/2 is also prime)
fn is_safe_prime(p: &BoxedUint) -> bool {
    let one = BoxedUint::one_with_precision(p.bits_precision());
    let q = p.wrapping_sub(&one).shr(1);
    is_probable_prime(&q, 7)
}

/// Generate a safe prime of the given bit length
/// Uses the approach: generate q, check if p = 2q + 1 is also prime
fn generate_safe_prime<R: CryptoRng + ?Sized>(rng: &mut R, bits: usize) -> BoxedUint {
    let q_bits = bits - 1;

    loop {
        let byte_len = (q_bits + 7) / 8;
        let mut bytes = vec![0u8; byte_len];
        rng.fill_bytes(&mut bytes);

        if q_bits % 8 != 0 {
            bytes[0] &= (1u8 << (q_bits % 8)) - 1;
        }

        let mut q = BoxedUint::from_be_slice(&bytes, q_bits as u32)
            .unwrap_or_else(|_| BoxedUint::zero_with_precision(q_bits as u32));

        q = q.bitor(&BoxedUint::one_with_precision(q.bits_precision()));

        let high_bit = BoxedUint::one_with_precision(q.bits_precision()).shl(q_bits as u32 - 1);
        q = q.bitor(&high_bit);

        // Quick check: for p = 2q + 1 to be prime, q mod 3 must not be 1
        // (otherwise p = 2q + 1 ≡ 2*1 + 1 ≡ 0 mod 3)
        let three = Resize::resize(BoxedUint::from(3u32), q.bits_precision());
        let three_nz: NonZero<BoxedUint> = match NonZero::new(three).into() {
            Some(nz) => nz,
            None => continue,
        };
        let q_mod_3 = q.rem(&three_nz);
        let one_q = BoxedUint::one_with_precision(q.bits_precision());
        if q_mod_3 == one_q {
            continue;
        }

        if !is_probable_prime(&q, 5) {
            continue;
        }

        let q_wide = Resize::resize(q.clone(), bits as u32);
        let one = BoxedUint::one_with_precision(bits as u32);
        let p = q_wide.shl(1).wrapping_add(&one);

        if is_probable_prime(&p, 7) {
            return p;
        }
    }
}

/// Hash a message with optional metadata and prefix (for PBRSA)
fn hash_with_metadata<H: HashAlgorithm>(
    prefix: Option<&[u8]>,
    msg: &[u8],
    metadata: Option<&[u8]>,
) -> Vec<u8> {
    let mut h = H::new_hasher();

    // If metadata is present, include "msg" || len(metadata) || metadata
    if let Some(meta) = metadata {
        h.update(b"msg");
        let len_bytes = (meta.len() as u32).to_be_bytes();
        h.update(&len_bytes);
        h.update(meta);
    }

    if let Some(p) = prefix {
        h.update(p);
    }

    h.update(msg);

    h.finalize().to_vec()
}

/// EMSA-PSS-ENCODE for PBRSA
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

fn derive_exponent_for_metadata<H: HashAlgorithm>(
    n: &BoxedUint,
    metadata: &[u8],
    lambda_len: usize,
) -> Result<BoxedUint, Error> {
    let mut hkdf_input = Vec::with_capacity(3 + metadata.len() + 1);
    hkdf_input.extend_from_slice(b"key");
    hkdf_input.extend_from_slice(metadata);
    hkdf_input.push(0);

    let n_bytes = n.to_be_bytes();
    let hkdf_len = lambda_len + 16;
    let mut exp_bytes = vec![0u8; hkdf_len];

    H::hkdf_expand(&mut exp_bytes, &n_bytes, &hkdf_input, b"PBRSA");

    exp_bytes[0] &= 0x3f;
    exp_bytes[lambda_len - 1] |= 0x01;

    let e2 = BoxedUint::from_be_slice(&exp_bytes[..lambda_len], (lambda_len * 8) as u32)
        .map_err(|_| Error::InternalError)?;

    Ok(e2)
}


fn compute_phi(p: &BoxedUint, q: &BoxedUint) -> BoxedUint {
    let one_p = BoxedUint::one_with_precision(p.bits_precision());
    let one_q = BoxedUint::one_with_precision(q.bits_precision());
    let p_minus_1 = p.wrapping_sub(&one_p);
    let q_minus_1 = q.wrapping_sub(&one_q);

    // Widen both to accommodate the product
    let target_bits = p.bits_precision() + q.bits_precision();
    let p_wide = Resize::resize(p_minus_1, target_bits);
    let q_wide = Resize::resize(q_minus_1, target_bits);

    p_wide.wrapping_mul(&q_wide)
}

fn mod_inverse(a: &BoxedUint, m: &BoxedUint) -> Option<BoxedUint> {
    let m_nz_opt: Option<NonZero<BoxedUint>> = NonZero::new(m.clone()).into();
    let m_nz = m_nz_opt?;
    let result: Option<BoxedUint> = a.invert_mod(&m_nz).into();
    result
}

/// Internal RSA key for PBRSA that allows large exponents.
/// This bypasses the standard RSA library's exponent size validation
/// which limits e to ~33 bits, but PBRSA requires ~1024 bit exponents.
struct PbrsaRawKey {
    n: NonZero<BoxedUint>,
    e: BoxedUint,
    d: BoxedUint,
    primes: Vec<BoxedUint>,
    n_params: BoxedMontyParams,
}

impl PbrsaRawKey {
    fn new(n: BoxedUint, e: BoxedUint, d: BoxedUint, primes: Vec<BoxedUint>) -> Result<Self, Error> {
        let n_odd = Odd::new(n.clone())
            .into_option()
            .ok_or(Error::InternalError)?;
        let n_params = BoxedMontyParams::new(n_odd);
        let n = NonZero::new(n).into_option().ok_or(Error::InternalError)?;
        Ok(Self {
            n,
            e,
            d,
            primes,
            n_params,
        })
    }
}

impl PublicKeyParts for PbrsaRawKey {
    fn n(&self) -> &NonZero<BoxedUint> {
        &self.n
    }

    fn e(&self) -> &BoxedUint {
        &self.e
    }

    fn n_params(&self) -> &BoxedMontyParams {
        &self.n_params
    }
}

impl PrivateKeyParts for PbrsaRawKey {
    fn d(&self) -> &BoxedUint {
        &self.d
    }

    fn primes(&self) -> &[BoxedUint] {
        &self.primes
    }

    fn dp(&self) -> Option<&BoxedUint> {
        None
    }

    fn dq(&self) -> Option<&BoxedUint> {
        None
    }

    fn qinv(&self) -> Option<&BoxedMontyForm> {
        None
    }

    fn crt_values(&self) -> Option<&[CrtValue]> {
        None
    }

    fn p_params(&self) -> Option<&BoxedMontyParams> {
        None
    }

    fn q_params(&self) -> Option<&BoxedMontyParams> {
        None
    }
}

/// Partially Blind RSA configuration (compile-time parameters)
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PartiallyBlindRsa<H: HashAlgorithm, S: SaltMode, M: MessagePrepare> {
    _phantom: PhantomData<(H, S, M)>,
}

impl<H: HashAlgorithm, S: SaltMode, M: MessagePrepare> PartiallyBlindRsa<H, S, M> {
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

/// An RSA public key for partially blind signatures
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartiallyBlindPublicKey<H: HashAlgorithm, S: SaltMode, M: MessagePrepare> {
    inner: RsaPublicKey,
    _phantom: PhantomData<(H, S, M)>,
}

/// Provides access to the raw RSA public key components for PBRSA
pub struct PartiallyBlindPublicKeyComponents<'a> {
    inner: &'a RsaPublicKey,
}

impl PartiallyBlindPublicKeyComponents<'_> {
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

impl<H: HashAlgorithm, S: SaltMode, M: MessagePrepare> PartiallyBlindPublicKey<H, S, M> {
    pub fn new(inner: RsaPublicKey) -> Self {
        Self {
            inner,
            _phantom: PhantomData,
        }
    }

    /// Returns an accessor for the raw RSA key components.
    pub fn components(&self) -> PartiallyBlindPublicKeyComponents<'_> {
        PartiallyBlindPublicKeyComponents { inner: &self.inner }
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
        // For PBRSA public keys, we allow non-standard exponents
        let modulus_bits = inner.size() * 8;
        if !(1024..=4096).contains(&modulus_bits) {
            return Err(Error::UnsupportedParameters);
        }
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
        let modulus_bits = inner.size() * 8;
        if !(1024..=4096).contains(&modulus_bits) {
            return Err(Error::UnsupportedParameters);
        }
        Ok(Self::new(inner))
    }

    /// Derive a per-metadata public key from this master public key
    pub fn derive_public_key_for_metadata(
        &self,
        metadata: &[u8],
    ) -> Result<PartiallyBlindPublicKey<H, S, M>, Error> {
        let modulus_bytes = self.inner.size();
        let lambda_len = modulus_bytes / 2;

        let n = self.inner.n();
        let e2 = derive_exponent_for_metadata::<H>(n.as_ref(), metadata, lambda_len)?;
        let inner = RsaPublicKey::new_unchecked(n.as_ref().clone(), e2);

        Ok(PartiallyBlindPublicKey::new(inner))
    }

    /// Blind a message to be signed, with optional metadata
    pub fn blind<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: impl AsRef<[u8]>,
        metadata: Option<&[u8]>,
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

        let msg_hash = hash_with_metadata::<H>(
            msg_randomizer.as_ref().map(|r| r.0.as_slice()),
            msg,
            metadata,
        );

        let salt_len = Self::salt_len();
        let mut salt = vec![0u8; salt_len];
        rng.fill_bytes(&mut salt[..]);

        let padded = emsa_pss_encode(&msg_hash, modulus_bits - 1, &salt, &mut *H::new_hasher())?;

        let n = self.inner.n();
        let n_bits = n.bits_precision();
        let m = BoxedUint::from_be_slice(&padded, n_bits).map_err(|_| Error::InternalError)?;
        let one = BoxedUint::one_with_precision(n_bits);
        if Gcd::gcd(&m, n.as_ref()) != one {
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
        metadata: Option<&[u8]>,
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
        self.verify(&sig, result.msg_randomizer, msg, metadata)?;
        Ok(sig)
    }

    /// Verify a signature with optional metadata
    pub fn verify(
        &self,
        sig: &Signature,
        msg_randomizer: Option<MessageRandomizer>,
        msg: impl AsRef<[u8]>,
        metadata: Option<&[u8]>,
    ) -> Result<(), Error> {
        let msg = msg.as_ref();
        let modulus_bytes = self.inner.size();
        if sig.len() != modulus_bytes {
            return Err(Error::UnsupportedParameters);
        }
        let sig_ =
            rsa::pss::Signature::try_from(sig.as_ref()).map_err(|_| Error::VerificationFailed)?;
        let salt_len = Self::salt_len();
        let msg_hash = hash_with_metadata::<H>(
            msg_randomizer.as_ref().map(|r| r.0.as_slice()),
            msg,
            metadata,
        );
        H::verify_prehash(&self.inner, salt_len, &msg_hash, &sig_)
            .map_err(|_| Error::VerificationFailed)
    }
}

impl<H: HashAlgorithm, S: SaltMode, M: MessagePrepare> AsRef<RsaPublicKey>
    for PartiallyBlindPublicKey<H, S, M>
{
    fn as_ref(&self) -> &RsaPublicKey {
        &self.inner
    }
}

/// Inner representation for PBRSA secret keys.
/// Master keys use standard RsaPrivateKey, derived keys use raw components.
#[derive(Clone)]
enum SecretKeyInner {
    /// Master key with standard exponent (e=65537)
    Master(RsaPrivateKey),
    /// Derived key with large exponent (~1024 bits)
    Derived {
        n: BoxedUint,
        e: BoxedUint,
        d: BoxedUint,
        primes: Vec<BoxedUint>,
    },
}

impl std::fmt::Debug for SecretKeyInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretKeyInner::Master(k) => f.debug_tuple("Master").field(k).finish(),
            SecretKeyInner::Derived { .. } => f.debug_struct("Derived").finish_non_exhaustive(),
        }
    }
}

/// An RSA secret key for partially blind signatures
#[derive(Clone, Debug)]
pub struct PartiallyBlindSecretKey<H: HashAlgorithm, S: SaltMode, M: MessagePrepare> {
    inner: SecretKeyInner,
    _phantom: PhantomData<(H, S, M)>,
}

/// Provides access to the raw RSA secret key components for PBRSA (master keys only)
pub struct PartiallyBlindSecretKeyComponents<'a> {
    inner: &'a RsaPrivateKey,
}

impl PartiallyBlindSecretKeyComponents<'_> {
    /// Returns the modulus (n) as big-endian bytes.
    pub fn n(&self) -> Vec<u8> {
        self.inner.n().as_ref().to_be_bytes().into_vec()
    }

    /// Returns the public exponent (e) as big-endian bytes.
    pub fn e(&self) -> Vec<u8> {
        self.inner.e().to_be_bytes().into_vec()
    }

    /// Returns the private exponent (d) as big-endian bytes.
    pub fn d(&self) -> Vec<u8> {
        self.inner.d().to_be_bytes().into_vec()
    }

    /// Returns the prime factors (p, q, ...) as big-endian bytes.
    pub fn primes(&self) -> Vec<Vec<u8>> {
        self.inner
            .primes()
            .iter()
            .map(|p| p.to_be_bytes().into_vec())
            .collect()
    }
}

impl<H: HashAlgorithm, S: SaltMode, M: MessagePrepare> PartiallyBlindSecretKey<H, S, M> {
    pub fn new(inner: RsaPrivateKey) -> Self {
        Self {
            inner: SecretKeyInner::Master(inner),
            _phantom: PhantomData,
        }
    }

    fn new_derived(n: BoxedUint, e: BoxedUint, d: BoxedUint, primes: Vec<BoxedUint>) -> Self {
        Self {
            inner: SecretKeyInner::Derived { n, e, d, primes },
            _phantom: PhantomData,
        }
    }

    fn n(&self) -> &BoxedUint {
        match &self.inner {
            SecretKeyInner::Master(k) => k.n().as_ref(),
            SecretKeyInner::Derived { n, .. } => n,
        }
    }

    fn primes(&self) -> &[BoxedUint] {
        match &self.inner {
            SecretKeyInner::Master(k) => {
                use rsa::traits::PrivateKeyParts as _;
                k.primes()
            }
            SecretKeyInner::Derived { primes, .. } => primes,
        }
    }

    fn size(&self) -> usize {
        (self.n().bits() as usize).div_ceil(8)
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        match &self.inner {
            SecretKeyInner::Master(inner) => inner
                .to_pkcs8_der()
                .map_err(|_| Error::EncodingError)
                .map(|x| std::mem::take(x.to_bytes().as_mut())),
            SecretKeyInner::Derived { .. } => {
                // Derived keys cannot be serialized to standard formats
                Err(Error::EncodingError)
            }
        }
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let mut inner = rsa::RsaPrivateKey::from_pkcs8_der(der)
            .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_der(der))
            .map_err(|_| Error::EncodingError)?;
        inner.validate().map_err(|_| Error::InvalidKey)?;
        inner.precompute().map_err(|_| Error::InvalidKey)?;

        // For PBRSA, verify that the primes are safe primes
        let primes = inner.primes();
        if primes.len() < 2 {
            return Err(Error::InvalidKey);
        }

        let p = &primes[0];
        let q = &primes[1];

        if !is_safe_prime(p) || !is_safe_prime(q) {
            return Err(Error::InvalidKey);
        }

        let sk = Self::new(inner);
        sk.public_key()?;
        Ok(sk)
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        match &self.inner {
            SecretKeyInner::Master(inner) => inner
                .to_pkcs8_pem(Default::default())
                .map_err(|_| Error::EncodingError)
                .map(|x| x.to_string()),
            SecretKeyInner::Derived { .. } => {
                // Derived keys cannot be serialized to standard formats
                Err(Error::EncodingError)
            }
        }
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let mut inner = rsa::RsaPrivateKey::from_pkcs8_pem(pem)
            .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(pem))
            .map_err(|_| Error::EncodingError)?;
        inner.validate().map_err(|_| Error::InvalidKey)?;
        inner.precompute().map_err(|_| Error::InvalidKey)?;

        // For PBRSA, verify that the primes are safe primes
        let primes = inner.primes();
        if primes.len() < 2 {
            return Err(Error::InvalidKey);
        }

        let p = &primes[0];
        let q = &primes[1];

        if !is_safe_prime(p) || !is_safe_prime(q) {
            return Err(Error::InvalidKey);
        }

        let sk = Self::new(inner);
        sk.public_key()?;
        Ok(sk)
    }

    /// Recover the public key
    pub fn public_key(&self) -> Result<PartiallyBlindPublicKey<H, S, M>, Error> {
        match &self.inner {
            SecretKeyInner::Master(k) => {
                let inner = RsaPublicKey::from(k);
                let modulus_bits = inner.size() * 8;
                if !(1024..=4096).contains(&modulus_bits) {
                    return Err(Error::UnsupportedParameters);
                }
                Ok(PartiallyBlindPublicKey::new(inner))
            }
            SecretKeyInner::Derived { n, e, .. } => {
                // Use new_unchecked for derived keys with large exponents
                let inner = RsaPublicKey::new_unchecked(n.clone(), e.clone());
                Ok(PartiallyBlindPublicKey::new(inner))
            }
        }
    }

    /// Sign a blinded message
    pub fn blind_sign(&self, blind_msg: impl AsRef<[u8]>) -> Result<BlindSignature, Error> {
        let mut rng = crate::DefaultRng;
        self.blind_sign_with_rng(&mut rng, blind_msg)
    }

    /// Sign a blinded message using the provided RNG for RSA blinding
    pub fn blind_sign_with_rng<R: rsa::rand_core::TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        blind_msg: impl AsRef<[u8]>,
    ) -> Result<BlindSignature, Error> {
        let modulus_bytes = self.size();
        if blind_msg.as_ref().len() != modulus_bytes {
            return Err(Error::UnsupportedParameters);
        }
        let n_bits = self.n().bits_precision();
        let blind_msg_uint = BoxedUint::from_be_slice(blind_msg.as_ref(), n_bits)
            .map_err(|_| Error::InternalError)?;
        if &blind_msg_uint >= self.n() {
            return Err(Error::UnsupportedParameters);
        }

        match &self.inner {
            SecretKeyInner::Master(k) => {
                let blind_sig = rsa_decrypt_and_check(k, Some(rng), &blind_msg_uint)
                    .map_err(|_| Error::InternalError)?;
                Ok(BlindSignature(to_bytes_be_padded(&blind_sig, modulus_bytes)))
            }
            SecretKeyInner::Derived { n, e, d, primes } => {
                // Use PbrsaRawKey for derived keys to bypass exponent validation
                let raw_key = PbrsaRawKey::new(n.clone(), e.clone(), d.clone(), primes.clone())?;
                let blind_sig = rsa_decrypt_and_check(&raw_key, Some(rng), &blind_msg_uint)
                    .map_err(|_| Error::InternalError)?;
                Ok(BlindSignature(to_bytes_be_padded(&blind_sig, modulus_bytes)))
            }
        }
    }
}

impl<H: HashAlgorithm, S: SaltMode, M: MessagePrepare> Eq for PartiallyBlindSecretKey<H, S, M> {}

impl<H: HashAlgorithm, S: SaltMode, M: MessagePrepare> PartialEq
    for PartiallyBlindSecretKey<H, S, M>
{
    fn eq(&self, other: &Self) -> bool {
        match (&self.inner, &other.inner) {
            (SecretKeyInner::Master(a), SecretKeyInner::Master(b)) => a == b,
            (SecretKeyInner::Derived { n: n1, e: e1, d: d1, primes: p1 },
             SecretKeyInner::Derived { n: n2, e: e2, d: d2, primes: p2 }) => {
                n1 == n2 && e1 == e2 && d1 == d2 && p1 == p2
            }
            _ => false,
        }
    }
}

/// An RSA key pair for partially blind signatures
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartiallyBlindKeyPair<H: HashAlgorithm, S: SaltMode, M: MessagePrepare> {
    pub pk: PartiallyBlindPublicKey<H, S, M>,
    pub sk: PartiallyBlindSecretKey<H, S, M>,
}

impl<H: HashAlgorithm, S: SaltMode, M: MessagePrepare> PartiallyBlindKeyPair<H, S, M> {
    /// Generate a new key pair with safe primes
    pub fn generate<R: CryptoRng + ?Sized>(
        rng: &mut R,
        modulus_bits: usize,
    ) -> Result<Self, Error> {
        if !(1024..=4096).contains(&modulus_bits) || modulus_bits % 16 != 0 {
            return Err(Error::UnsupportedParameters);
        }

        let prime_bits = modulus_bits / 2;
        let p = generate_safe_prime(rng, prime_bits);
        let q = loop {
            let candidate = generate_safe_prime(rng, prime_bits);
            if candidate != p {
                break candidate;
            }
        };

        let n_bits = (modulus_bits as u32) + 64;
        let p_wide = Resize::resize(p.clone(), n_bits);
        let q_wide = Resize::resize(q.clone(), n_bits);
        let n = p_wide.wrapping_mul(&q_wide);

        let phi = compute_phi(&p, &q);
        let e = Resize::resize(BoxedUint::from(65537u32), phi.bits_precision());
        let d = mod_inverse(&e, &phi).ok_or(Error::InternalError)?;

        let inner = RsaPrivateKey::from_components(n, e, d, vec![p, q])
            .map_err(|_| Error::InternalError)?;

        let mut inner = inner;
        inner.precompute().map_err(|_| Error::InternalError)?;

        let sk = PartiallyBlindSecretKey::new(inner);
        let pk = sk.public_key()?;

        Ok(Self { pk, sk })
    }

    /// Derive a per-metadata key pair from this master key pair
    pub fn derive_key_pair_for_metadata(
        &self,
        metadata: &[u8],
    ) -> Result<PartiallyBlindKeyPair<H, S, M>, Error> {
        let primes = self.sk.primes();
        if primes.len() < 2 {
            return Err(Error::InvalidKey);
        }
        let p = &primes[0];
        let q = &primes[1];

        let phi = compute_phi(p, q);

        let n = self.sk.n();
        let modulus_bytes = self.sk.size();
        let lambda_len = modulus_bytes / 2;

        let e2 = derive_exponent_for_metadata::<H>(n, metadata, lambda_len)?;

        let one = BoxedUint::one_with_precision(phi.bits_precision());
        let e2_wide = Resize::resize(e2.clone(), phi.bits_precision());
        if Gcd::gcd(&e2_wide, &phi) != one {
            return Err(Error::InternalError);
        }

        let pk = self.pk.derive_public_key_for_metadata(metadata)?;
        let d2 = mod_inverse(&e2_wide, &phi).ok_or(Error::InternalError)?;

        let sk = PartiallyBlindSecretKey::new_derived(
            n.clone(),
            e2,
            d2,
            vec![p.clone(), q.clone()],
        );

        Ok(PartiallyBlindKeyPair { pk, sk })
    }

    /// Derive only the secret key for the given metadata
    pub fn derive_secret_key_for_metadata(
        &self,
        metadata: &[u8],
    ) -> Result<PartiallyBlindSecretKey<H, S, M>, Error> {
        let kp = self.derive_key_pair_for_metadata(metadata)?;
        Ok(kp.sk)
    }
}

// Type aliases for common configurations

/// RSAPBSSA-SHA384-PSS-Randomized (recommended)
pub type PartiallyBlindRsaSha384PSSRandomized = PartiallyBlindRsa<Sha384, PSS, Randomized>;

/// RSAPBSSA-SHA384-PSSZERO-Randomized
pub type PartiallyBlindRsaSha384PSSZeroRandomized = PartiallyBlindRsa<Sha384, PSSZero, Randomized>;

/// RSAPBSSA-SHA384-PSS-Deterministic
pub type PartiallyBlindRsaSha384PSSDeterministic = PartiallyBlindRsa<Sha384, PSS, Deterministic>;

/// RSAPBSSA-SHA384-PSSZERO-Deterministic
pub type PartiallyBlindRsaSha384PSSZeroDeterministic =
    PartiallyBlindRsa<Sha384, PSSZero, Deterministic>;

/// Public key for RSAPBSSA-SHA384-PSS-Randomized (recommended)
pub type PartiallyBlindPublicKeySha384PSSRandomized =
    PartiallyBlindPublicKey<Sha384, PSS, Randomized>;

/// Secret key for RSAPBSSA-SHA384-PSS-Randomized (recommended)
pub type PartiallyBlindSecretKeySha384PSSRandomized =
    PartiallyBlindSecretKey<Sha384, PSS, Randomized>;

/// Key pair for RSAPBSSA-SHA384-PSS-Randomized (recommended)
pub type PartiallyBlindKeyPairSha384PSSRandomized = PartiallyBlindKeyPair<Sha384, PSS, Randomized>;

/// Public key for RSAPBSSA-SHA384-PSSZERO-Randomized
pub type PartiallyBlindPublicKeySha384PSSZeroRandomized =
    PartiallyBlindPublicKey<Sha384, PSSZero, Randomized>;

/// Secret key for RSAPBSSA-SHA384-PSSZERO-Randomized
pub type PartiallyBlindSecretKeySha384PSSZeroRandomized =
    PartiallyBlindSecretKey<Sha384, PSSZero, Randomized>;

/// Key pair for RSAPBSSA-SHA384-PSSZERO-Randomized
pub type PartiallyBlindKeyPairSha384PSSZeroRandomized =
    PartiallyBlindKeyPair<Sha384, PSSZero, Randomized>;

/// Public key for RSAPBSSA-SHA384-PSS-Deterministic
pub type PartiallyBlindPublicKeySha384PSSDeterministic =
    PartiallyBlindPublicKey<Sha384, PSS, Deterministic>;

/// Secret key for RSAPBSSA-SHA384-PSS-Deterministic
pub type PartiallyBlindSecretKeySha384PSSDeterministic =
    PartiallyBlindSecretKey<Sha384, PSS, Deterministic>;

/// Key pair for RSAPBSSA-SHA384-PSS-Deterministic
pub type PartiallyBlindKeyPairSha384PSSDeterministic =
    PartiallyBlindKeyPair<Sha384, PSS, Deterministic>;

/// Public key for RSAPBSSA-SHA384-PSSZERO-Deterministic
pub type PartiallyBlindPublicKeySha384PSSZeroDeterministic =
    PartiallyBlindPublicKey<Sha384, PSSZero, Deterministic>;

/// Secret key for RSAPBSSA-SHA384-PSSZERO-Deterministic
pub type PartiallyBlindSecretKeySha384PSSZeroDeterministic =
    PartiallyBlindSecretKey<Sha384, PSSZero, Deterministic>;

/// Key pair for RSAPBSSA-SHA384-PSSZERO-Deterministic
pub type PartiallyBlindKeyPairSha384PSSZeroDeterministic =
    PartiallyBlindKeyPair<Sha384, PSSZero, Deterministic>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::to_bytes_be_padded;

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_vector_zig_compatibility() {
        let p_hex = "dcd90af1be463632c0d5ea555256a20605af3db667475e190e3af12a34a3324c46a3094062c59fb4b249e0ee6afba8bee14e0276d126c99f4784b23009bf6168ff628ac1486e5ae8e23ce4d362889de4df63109cbd90ef93db5ae64372bfe1c55f832766f21e94ea3322eb2182f10a891546536ba907ad74b8d72469bea396f3";
        let q_hex = "f8ba5c89bd068f57234a3cf54a1c89d5b4cd0194f2633ca7c60b91a795a56fa8c8686c0e37b1c4498b851e3420d08bea29f71d195cfbd3671c6ddc49cf4c1db5b478231ea9d91377ffa98fe95685fca20ba4623212b2f2def4da5b281ed0100b651f6db32112e4017d831c0da668768afa7141d45bbc279f1e0f8735d74395b3";
        let n_hex = "d6930820f71fe517bf3259d14d40209b02a5c0d3d61991c731dd7da39f8d69821552e2318d6c9ad897e603887a476ea3162c1205da9ac96f02edf31df049bd55f142134c17d4382a0e78e275345f165fbe8e49cdca6cf5c726c599dd39e09e75e0f330a33121e73976e4facba9cfa001c28b7c96f8134f9981db6750b43a41710f51da4240fe03106c12acb1e7bb53d75ec7256da3fddd0718b89c365410fce61bc7c99b115fb4c3c318081fa7e1b65a37774e8e50c96e8ce2b2cc6b3b367982366a2bf9924c4bafdb3ff5e722258ab705c76d43e5f1f121b984814e98ea2b2b8725cd9bc905c0bc3d75c2a8db70a7153213c39ae371b2b5dc1dafcb19d6fae9";
        let e_hex = "010001";
        let d_hex = "4e21356983722aa1adedb084a483401c1127b781aac89eab103e1cfc52215494981d18dd8028566d9d499469c25476358de23821c78a6ae43005e26b394e3051b5ca206aa9968d68cae23b5affd9cbb4cb16d64ac7754b3cdba241b72ad6ddfc000facdb0f0dd03abd4efcfee1730748fcc47b7621182ef8af2eeb7c985349f62ce96ab373d2689baeaea0e28ea7d45f2d605451920ca4ea1f0c08b0f1f6711eaa4b7cca66d58a6b916f9985480f90aca97210685ac7b12d2ec3e30a1c7b97b65a18d38a93189258aa346bf2bc572cd7e7359605c20221b8909d599ed9d38164c9c4abf396f897b9993c1e805e574d704649985b600fa0ced8e5427071d7049d";
        let expected_e2_hex = "30581b1adab07ac00a5057e2986f37caaa68ae963ffbc4d36c16ea5f3689d6f00db79a5bee56053adc53c8d0414d4b754b58c7cc4abef99d4f0d0b2e29cbddf746c7d0f4ae2690d82a2757b088820c0d086a40d180b2524687060d768ad5e431732102f4bc3572d97e01dcd6301368f255faae4606399f91fa913a6d699d6ef1";
        let expected_d2_hex = "29c25948b214276527434f7d289385098ada0d30866e40eaf56cbe1ffb3ed5881c2df0bd42ea9925d7715fc98767d48e3ee4dae03335e4903fe984c863e1a2f27990fa6999308d7b6515fe0f7da7bb6a979b63f483618b0e2bce2c67daf8dfc099c7f6a0a1292118f35b3133358a200b67f9a0a3c17ceb678095da143d2264327fff5a9fcf280e83421ba398e62965b48628307794e326d57b9f98ce098d88d3e40360e7d5c567fbdce22413e279a7814bc6bab4a5bd35f4bcf3295d68f6d47505fd47aee64f7797f1061342b826db508ba9a62d948c6ee8ec05756267f4a97576d97b773037af601bea110defbd89fb4111c7257b500ad9d1212c849fd355d1";
        let metadata = b"metadata";

        let n = BoxedUint::from_be_slice(&hex_to_bytes(n_hex), 2048).unwrap();
        let e = BoxedUint::from_be_slice(&hex_to_bytes(e_hex), 32).unwrap();
        let d = BoxedUint::from_be_slice(&hex_to_bytes(d_hex), 2048).unwrap();
        let p = BoxedUint::from_be_slice(&hex_to_bytes(p_hex), 1024).unwrap();
        let q = BoxedUint::from_be_slice(&hex_to_bytes(q_hex), 1024).unwrap();

        let inner = RsaPrivateKey::from_components(n.clone(), e, d, vec![p, q]).unwrap();
        let sk = PartiallyBlindSecretKey::<Sha384, PSS, Randomized>::new(inner);
        let pk = sk.public_key().unwrap();
        let kp = PartiallyBlindKeyPair { pk, sk };

        let derived_kp = kp.derive_key_pair_for_metadata(metadata).unwrap();

        let derived_e2 = derived_kp.pk.components().e();
        let expected_e2 = hex_to_bytes(expected_e2_hex);
        assert_eq!(derived_e2, expected_e2, "Derived e2 does not match Zig test vector");

        match &derived_kp.sk.inner {
            SecretKeyInner::Derived { d, .. } => {
                let derived_d2 = to_bytes_be_padded(d, 256);
                let expected_d2 = hex_to_bytes(expected_d2_hex);
                assert_eq!(derived_d2, expected_d2, "Derived d2 does not match Zig test vector");
            }
            _ => panic!("Expected derived key"),
        }

        let msg = b"hello world";
        let blinding_result = derived_kp.pk.blind(&mut DefaultRng, msg, Some(metadata)).unwrap();
        let blind_sig = derived_kp.sk.blind_sign(&blinding_result.blind_message).unwrap();
        let sig = derived_kp.pk.finalize(&blind_sig, &blinding_result, msg, Some(metadata)).unwrap();
        derived_kp.pk.verify(&sig, blinding_result.msg_randomizer, msg, Some(metadata)).unwrap();
    }

    #[test]
    fn test_derive_keypair() {
        let kp = PartiallyBlindKeyPair::<Sha384, PSS, Randomized>::generate(&mut DefaultRng, 1024)
            .unwrap();

        let metadata = b"test-metadata";
        let derived_kp = kp.derive_key_pair_for_metadata(metadata).unwrap();

        let msg = b"test message";
        let blinding_result = derived_kp.pk.blind(&mut DefaultRng, msg, Some(metadata)).unwrap();
        let blind_sig = derived_kp.sk.blind_sign(&blinding_result.blind_message).unwrap();
        let sig = derived_kp.pk.finalize(&blind_sig, &blinding_result, msg, Some(metadata)).unwrap();
        derived_kp.pk.verify(&sig, blinding_result.msg_randomizer, msg, Some(metadata)).unwrap();
    }

    #[test]
    fn test_pbrsa_basic() {
        let kp = PartiallyBlindKeyPair::<Sha384, PSS, Randomized>::generate(&mut DefaultRng, 1024)
            .unwrap();

        let metadata = b"test-metadata";
        let derived_kp = kp.derive_key_pair_for_metadata(metadata).unwrap();

        let msg = b"hello world";
        let blinding_result = derived_kp
            .pk
            .blind(&mut DefaultRng, msg, Some(metadata))
            .unwrap();

        let blind_sig = derived_kp
            .sk
            .blind_sign(&blinding_result.blind_message)
            .unwrap();

        let sig = derived_kp
            .pk
            .finalize(&blind_sig, &blinding_result, msg, Some(metadata))
            .unwrap();

        derived_kp
            .pk
            .verify(&sig, blinding_result.msg_randomizer, msg, Some(metadata))
            .unwrap();
    }

    #[test]
    fn test_pbrsa_deterministic() {
        let kp =
            PartiallyBlindKeyPair::<Sha384, PSSZero, Deterministic>::generate(&mut DefaultRng, 1024)
                .unwrap();

        let metadata = b"metadata";
        let derived_kp = kp.derive_key_pair_for_metadata(metadata).unwrap();

        let msg = b"test message";
        let blinding_result = derived_kp
            .pk
            .blind(&mut DefaultRng, msg, Some(metadata))
            .unwrap();

        assert!(blinding_result.msg_randomizer.is_none());

        let blind_sig = derived_kp
            .sk
            .blind_sign(&blinding_result.blind_message)
            .unwrap();

        let sig = derived_kp
            .pk
            .finalize(&blind_sig, &blinding_result, msg, Some(metadata))
            .unwrap();

        derived_kp
            .pk
            .verify(&sig, None, msg, Some(metadata))
            .unwrap();
    }

    #[test]
    fn test_pbrsa_no_metadata() {
        let kp = PartiallyBlindKeyPair::<Sha384, PSS, Randomized>::generate(&mut DefaultRng, 1024)
            .unwrap();

        // Use master key directly without metadata derivation
        let msg = b"hello world";
        let blinding_result = kp.pk.blind(&mut DefaultRng, msg, None).unwrap();

        let blind_sig = kp.sk.blind_sign(&blinding_result.blind_message).unwrap();

        let sig = kp
            .pk
            .finalize(&blind_sig, &blinding_result, msg, None)
            .unwrap();

        kp.pk
            .verify(&sig, blinding_result.msg_randomizer, msg, None)
            .unwrap();
    }
}
