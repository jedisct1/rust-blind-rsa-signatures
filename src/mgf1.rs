use digest::DynDigest;

/// MGF1 XOR operation used in PSS padding
///
/// # Arguments
///
/// * `dst` - The destination buffer to XOR into
/// * `hash` - The hash function to use
/// * `src` - The source data
pub fn mgf1_xor(dst: &mut [u8], hash: &mut dyn DynDigest, src: &[u8]) {
    let mut counter: u32 = 0;
    let mut i = 0;
    while i < dst.len() {
        let mut h = hash.box_clone();
        h.update(src);
        h.update(&counter.to_be_bytes());
        let digest = h.finalize_reset();

        let chunk_len = digest.len().min(dst.len() - i);
        for (d, s) in dst[i..][..chunk_len].iter_mut().zip(&*digest) {
            *d ^= s;
        }

        i += digest.len();
        counter = counter.wrapping_add(1);
    }
}
