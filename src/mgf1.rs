use digest::DynDigest;

/// MGF1 XOR operation used in PSS padding
///
/// # Arguments
///
/// * `dst` - The destination buffer to XOR into
/// * `hash` - The hash function to use
/// * `src` - The source data
pub fn mgf1_xor(dst: &mut [u8], hash: &mut dyn DynDigest, src: &[u8]) {
    let mut counter = [0u8; 4];
    let mut i = 0;
    while i < dst.len() {
        let mut h = hash.box_clone();
        h.update(src);
        h.update(&counter);
        let digest = h.finalize_reset();

        let j_max = if i + digest.len() <= dst.len() {
            digest.len()
        } else {
            dst.len() - i
        };

        for j in 0..j_max {
            dst[i + j] ^= digest[j];
        }

        i += digest.len();

        // Increment counter
        for k in (0..4).rev() {
            counter[k] = counter[k].wrapping_add(1);
            if counter[k] != 0 {
                break;
            }
        }
    }
}
