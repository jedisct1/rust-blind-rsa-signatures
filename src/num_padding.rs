use std::iter;

use rsa::BigUint;

pub trait ToBytesPadded {
    /// Returns the byte representation of `self` in big-endian byte order,
    /// left-padding the number with zeroes to the specified length.
    ///
    /// If `len` is less than or equal to the length of the byte representation
    /// of `self`, no padding will be added.
    fn to_bytes_be_padded(&self, len: usize) -> Vec<u8>;
}

impl ToBytesPadded for BigUint {
    fn to_bytes_be_padded(&self, len: usize) -> Vec<u8> {
        let v = self.to_bytes_be();
        if len > v.len() {
            iter::repeat(0)
                .take(len - v.len())
                .chain(v.into_iter())
                .collect()
        } else {
            v
        }
    }
}
