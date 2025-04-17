#![cfg_attr(target_arch = "x86_64", feature(stdarch_x86_avx512))]

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

use hybrid_array::Array;

mod low;

mod mid {
    pub mod aegis128;
    pub mod util;
}

mod high {
    pub mod aegis128;
}

pub use low::AegisParallel;

pub use high::aegis128::{Aegis128X, AegisMac128X};
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
    use hybrid_array::sizes::{U1, U16};

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

        let res: Array<u8, U16> = in_.aes(rk).into();
        assert_eq!(res, out);
    }
}
