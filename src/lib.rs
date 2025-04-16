#![cfg_attr(target_arch="x86_64", feature(stdarch_x86_avx512))]

// *  C0: an AES block built from the following bytes in hexadecimal
// format: { 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15,
// 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 }.
const C0: Array<u8, hybrid_array::sizes::U16> = Array([
    0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
]);

// *  C1: an AES block built from the following bytes in hexadecimal
// format: { 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20,
// 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd }.
const C1: Array<u8, hybrid_array::sizes::U16> = Array([
    0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd,
]);

use std::ops::{Add, Sub};

use hybrid_array::Array;

mod low {
    use hybrid_array::{Array, ArraySize};
    use std::ops::{BitAnd, BitXor, BitXorAssign};

    pub trait IAesBlock:
        Default
        + Copy
        + From<AesBlock>
        + BitXor<Output = Self>
        + BitXorAssign
        + BitAnd<Output = Self>
    {
        type Size: ArraySize;
        fn aes(self, key: Self) -> Self;
        fn xor3(self, mid: Self, rhs: Self) -> Self;
        fn fold_xor(self) -> AesBlock;
        fn into_array(self) -> Array<u8, Self::Size>;
        fn first(&self) -> AesBlock;
    }

    cfg_if::cfg_if! {
        if #[cfg(all(target_arch = "aarch64", target_feature = "aes"))] {
            mod aarch64;
            pub use aarch64::AesBlock;
        } else if #[cfg(all(target_arch = "x86_64", target_feature = "aes"))] {
            mod x86_64;
            pub use x86_64::AesBlock;
        }
    }
}

mod mid {
    pub mod aegis128;
    pub mod util;
}

mod high {
    pub mod aegis128;
}

pub trait AegisParallel: hybrid_array::ArraySize {
    type Aegis128BlockSize: hybrid_array::ArraySize
        + Sub<Self::Aegis256BlockSize, Output = Self::Aegis256BlockSize>;
    type Aegis256BlockSize: hybrid_array::ArraySize
        + Add<Self::Aegis256BlockSize, Output = Self::Aegis128BlockSize>;

    #[doc(hidden)]
    fn split_blocks(a: &Array<u8, Self::Aegis128BlockSize>) -> (Self::AesBlock, Self::AesBlock);
    #[doc(hidden)]
    fn from_block(a: &Array<u8, Self::Aegis256BlockSize>) -> Self::AesBlock;

    #[doc(hidden)]
    type AesBlock: low::IAesBlock<Size = Self::Aegis256BlockSize>
        + From<Array<low::AesBlock, Self>>
        + Into<Array<low::AesBlock, Self>>;
}

pub use high::aegis128::{Aegis128X, AegisMac128X};
pub type Aegis128L<T> = Aegis128X<hybrid_array::sizes::U1, T>;
pub type Aegis128X2<T> = Aegis128X<hybrid_array::sizes::U2, T>;
pub type Aegis128X4<T> = Aegis128X<hybrid_array::sizes::U4, T>;

pub type AegisMac128L<T> = AegisMac128X<hybrid_array::sizes::U1, T>;
pub type AegisMac128X2<T> = AegisMac128X<hybrid_array::sizes::U2, T>;
pub type AegisMac128X4<T> = AegisMac128X<hybrid_array::sizes::U4, T>;

#[cfg(test)]
mod tests {
    use aead::consts::U1;
    use hex_literal::hex;
    use hybrid_array::Array;

    use crate::AegisParallel;
    use crate::low::IAesBlock;

    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.1>
    #[test]
    fn aes_round() {
        // in   : 000102030405060708090a0b0c0d0e0f
        // rk   : 101112131415161718191a1b1c1d1e1f
        // out  : 7a7b4e5638782546a8c0477a3b813f43

        let in_ = U1::from_block(&Array(hex!("000102030405060708090a0b0c0d0e0f")));
        let rk = U1::from_block(&Array(hex!("101112131415161718191a1b1c1d1e1f")));
        let out = Array(hex!("7a7b4e5638782546a8c0477a3b813f43"));

        assert_eq!(in_.aes(rk).into_array(), out);
    }
}
