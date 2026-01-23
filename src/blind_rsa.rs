use crypto_bigint::{BoxedUint, NonZero, RandomMod};
use rsa::rand_core::CryptoRng;
use rsa::traits::PublicKeyParts;

/// Blinds a message using the server's public key and a random factor.
///
/// # Arguments
///
/// * `rng` - A cryptographically secure random number generator
/// * `key` - The public key to use for blinding
/// * `c` - The message to blind, as a BoxedUint
///
/// # Returns
///
/// A tuple containing the blinded message and the secret factor
pub fn blind<R: CryptoRng + ?Sized, K: PublicKeyParts>(
    rng: &mut R,
    key: &K,
    c: &BoxedUint,
) -> (BoxedUint, BoxedUint) {
    // Blinding involves multiplying c by r^e.
    // Then the decryption operation performs (m^e * r^e)^d mod n
    // which equals mr mod n. The factor of r can then be removed
    // by multiplying by the multiplicative inverse of r.

    let n = key.n();
    let n_bits = n.bits_precision();
    let n_params = key.n_params();

    let mut r: BoxedUint;
    let unblinder;
    loop {
        // Generate random r in range [1, n)
        r = BoxedUint::random_mod_vartime(rng, n);
        if r.is_zero().into() {
            r = BoxedUint::one_with_precision(n_bits);
        }
        if let Some(ir) = r.invert_mod(n).into() {
            unblinder = ir;
            break;
        }
    }

    // r^e (mod n)
    let r_monty = crypto_bigint::modular::BoxedMontyForm::new(r, n_params);
    let blind_factor = r_monty.pow(key.e()).retrieve();

    // c * r^e (mod n)
    let n_nz = NonZero::new(n.as_ref().clone()).expect("modulus is non-zero");
    let blind_msg = c.mul_mod(&blind_factor, &n_nz);

    (blind_msg, unblinder)
}

/// Unblinds a blinded signature using the server's public key and the secret factor.
///
/// # Arguments
///
/// * `key` - The public key to use for unblinding
/// * `m` - The blinded signature, as a BoxedUint
/// * `unblinder` - The secret factor used for blinding
///
/// # Returns
///
/// The unblinded signature as a BoxedUint
pub fn unblind(key: &impl PublicKeyParts, m: &BoxedUint, unblinder: &BoxedUint) -> BoxedUint {
    let n = key.n();
    let n_nz = NonZero::new(n.as_ref().clone()).expect("modulus is non-zero");
    m.mul_mod(unblinder, &n_nz)
}
