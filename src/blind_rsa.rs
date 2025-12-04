use num_traits::Zero;
use rsa::rand_core::{CryptoRng, RngCore};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BigUint, RsaPrivateKey};

/// Blinds a message using the server's public key and a random factor.
///
/// # Arguments
///
/// * `rng` - A cryptographically secure random number generator
/// * `key` - The public key to use for blinding
/// * `c` - The message to blind, as a BigUint
///
/// # Returns
///
/// A tuple containing the blinded message and the secret factor
pub fn blind<R: CryptoRng + RngCore, K: PublicKeyParts>(
    rng: &mut R,
    key: &K,
    c: &BigUint,
) -> (BigUint, BigUint) {
    // Blinding involves multiplying c by r^e.
    // Then the decryption operation performs (m^e * r^e)^d mod n
    // which equals mr mod n. The factor of r can then be removed
    // by multiplying by the multiplicative inverse of r.

    let mut r: BigUint;
    let unblinder;
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        r = BigUint::from_bytes_be(&bytes) % key.n();
        if r.is_zero() {
            r = BigUint::from(1u8);
        }
        if let Some(ir) = mod_inverse(&r, key.n()) {
            unblinder = ir;
            break;
        }
    }

    let blind_factor = r.modpow(key.e(), key.n());
    let blind_msg = (c * &blind_factor) % key.n();

    (blind_msg, unblinder)
}

/// Unblinds a blinded signature using the server's public key and the secret factor.
///
/// # Arguments
///
/// * `key` - The public key to use for unblinding
/// * `m` - The blinded signature, as a BigUint
/// * `unblinder` - The secret factor used for blinding
///
/// # Returns
///
/// The unblinded signature as a BigUint
pub fn unblind(key: &impl PublicKeyParts, m: &BigUint, unblinder: &BigUint) -> BigUint {
    (m * unblinder) % key.n()
}

/// Decrypts a message using the private key, with additional checks.
///
/// # Arguments
///
/// * `rng` - A cryptographically secure random number generator (optional)
/// * `key` - The private key to use for decryption
/// * `c` - The message to decrypt, as a BigUint
///
/// # Returns
///
/// The decrypted message as a BigUint, or an error if decryption failed
pub fn rsa_decrypt_and_check<R: CryptoRng + RngCore>(
    _rng: Option<&mut R>,
    key: &RsaPrivateKey,
    c: &BigUint,
) -> Result<BigUint, rsa::errors::Error> {
    if c >= key.n() {
        return Err(rsa::errors::Error::Decryption);
    }

    // In RSA, c^d mod n = m
    let m = c.modpow(key.d(), key.n());

    Ok(m)
}

/// Compute modular inverse using extended Euclidean algorithm
fn mod_inverse(a: &BigUint, n: &BigUint) -> Option<BigUint> {
    use num_traits::One;

    // Extended GCD
    let mut t = BigUint::zero();
    let mut new_t = BigUint::one();
    let mut r = n.clone();
    let mut new_r = a.clone();

    // Track signs separately since we're using unsigned integers
    let mut t_neg = false;
    let mut new_t_neg = false;

    while !new_r.is_zero() {
        let quotient = &r / &new_r;

        // t, new_t = new_t, t - quotient * new_t
        let qt = &quotient * &new_t;
        let (next_t, next_t_neg) = if t_neg == new_t_neg {
            if t >= qt {
                (t - &qt, t_neg)
            } else {
                (&qt - t, !t_neg)
            }
        } else {
            (t + &qt, t_neg)
        };
        t = new_t;
        t_neg = new_t_neg;
        new_t = next_t;
        new_t_neg = next_t_neg;

        // r, new_r = new_r, r - quotient * new_r
        let qr = &quotient * &new_r;
        let next_r = &r - &qr;
        r = new_r;
        new_r = next_r;
    }

    if r > BigUint::one() {
        return None; // No inverse exists
    }

    if t_neg {
        Some(n - &t)
    } else {
        Some(t)
    }
}
