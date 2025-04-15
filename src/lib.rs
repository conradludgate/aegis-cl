// *  C0: an AES block built from the following bytes in hexadecimal
// format: { 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15,
// 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 }.
const C0: [u8; 16] = [
    0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
];

// *  C1: an AES block built from the following bytes in hexadecimal
// format: { 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20,
// 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd }.
const C1: [u8; 16] = [
    0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd,
];

mod aegis128;
mod util;

pub use aegis128::{Aegis128X, AegisMac128X};
use hybrid_array::Array;

mod arch {
    use hybrid_array::{Array, ArraySize};
    use std::ops::{BitAnd, BitXor, BitXorAssign, IndexMut};

    pub trait IAesBlock:
        Default
        + Copy
        + From<AesBlock>
        + BitXor<Output = Self>
        + BitXorAssign
        + BitAnd<Output = Self>
        + IndexMut<usize, Output = AesBlock>
    {
        type Size: ArraySize;
        fn aes(self, key: Self) -> Self;
        fn fold_xor(self) -> AesBlock;
        fn into_array(self) -> Array<u8, Self::Size>;
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
    mod aarch64;

    #[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
    pub(crate) use aarch64::AesBlock;
}

pub trait AegisParallel: hybrid_array::ArraySize {
    type Aegis128BlockSize: hybrid_array::ArraySize;
    type Aegis256BlockSize: hybrid_array::ArraySize;

    #[doc(hidden)]
    fn split_block128(a: Array<u8, Self::Aegis128BlockSize>) -> (Self::AesBlock, Self::AesBlock);
    #[doc(hidden)]
    fn split_block256(a: Array<u8, Self::Aegis256BlockSize>) -> Self::AesBlock;

    #[doc(hidden)]
    type AesBlock: arch::IAesBlock<Size = Self::Aegis256BlockSize>
        + From<Array<arch::AesBlock, Self>>;
}

pub type Aegis128L<T> = Aegis128X<hybrid_array::sizes::U1, T>;
pub type Aegis128X2<T> = Aegis128X<hybrid_array::sizes::U2, T>;
pub type Aegis128X4<T> = Aegis128X<hybrid_array::sizes::U4, T>;

pub type AegisMac128L<T> = AegisMac128X<hybrid_array::sizes::U1, T>;
pub type AegisMac128X2<T> = AegisMac128X<hybrid_array::sizes::U2, T>;
pub type AegisMac128X4<T> = AegisMac128X<hybrid_array::sizes::U4, T>;

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use hybrid_array::Array;

    use crate::arch::{AesBlock, IAesBlock};

    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.1>
    #[test]
    fn aes_round() {
        // in   : 000102030405060708090a0b0c0d0e0f
        // rk   : 101112131415161718191a1b1c1d1e1f
        // out  : 7a7b4e5638782546a8c0477a3b813f43

        let in_ = AesBlock::from_bytes(&hex!("000102030405060708090a0b0c0d0e0f"));
        let rk = AesBlock::from_bytes(&hex!("101112131415161718191a1b1c1d1e1f"));
        let out = Array(hex!("7a7b4e5638782546a8c0477a3b813f43"));

        assert_eq!(in_.aes(rk).into_array(), out);
    }
}
