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

#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
mod aarch64 {
    use std::arch::aarch64::*;
    use std::ops::{BitAnd, BitXor, BitXorAssign};

    #[derive(Clone, Copy)]
    pub struct AesBlock(pub uint8x16_t);

    impl Default for AesBlock {
        fn default() -> Self {
            Self(unsafe { vmovq_n_u8(0) })
        }
    }

    impl AesBlock {
        pub fn from_bytes(b: &[u8; 16]) -> Self {
            // Safety: b has 16 bytes available. It does not need any special alignment.
            Self(unsafe { vld1q_u8(b.as_ptr()) })
        }

        pub fn into_bytes(self) -> [u8; 16] {
            let mut out = [0; 16];
            unsafe { vst1q_u8(out.as_mut_ptr(), self.0) }
            out
        }

        pub fn aes(self, key: Self) -> Self {
            Self(unsafe { vaesmcq_u8(vaeseq_u8(self.0, vmovq_n_u8(0))) }) ^ key
        }
    }

    impl BitXor for AesBlock {
        type Output = Self;

        fn bitxor(self, rhs: Self) -> Self::Output {
            Self(unsafe { veorq_u8(self.0, rhs.0) })
        }
    }

    impl BitXorAssign for AesBlock {
        fn bitxor_assign(&mut self, rhs: Self) {
            *self = *self ^ rhs;
        }
    }

    impl BitAnd for AesBlock {
        type Output = Self;

        fn bitand(self, rhs: Self) -> Self::Output {
            Self(unsafe { vandq_u8(self.0, rhs.0) })
        }
    }
}

pub trait AegisParallel: hybrid_array::ArraySize {
    type Aegis128BlockSize: hybrid_array::ArraySize;
    type Aegis256BlockSize: hybrid_array::ArraySize;
}

impl AegisParallel for hybrid_array::sizes::U1 {
    type Aegis128BlockSize = hybrid_array::sizes::U32;
    type Aegis256BlockSize = hybrid_array::sizes::U16;
}

impl AegisParallel for hybrid_array::sizes::U2 {
    type Aegis128BlockSize = hybrid_array::sizes::U64;
    type Aegis256BlockSize = hybrid_array::sizes::U32;
}

impl AegisParallel for hybrid_array::sizes::U4 {
    type Aegis128BlockSize = hybrid_array::sizes::U128;
    type Aegis256BlockSize = hybrid_array::sizes::U64;
}

mod aegis128;
mod util;

pub use aegis128::{Aegis128L, Aegis128X, AegisMac128L, AegisMac128X};

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::aarch64::AesBlock;

    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.1>
    #[test]
    fn aes_round() {
        // in   : 000102030405060708090a0b0c0d0e0f
        // rk   : 101112131415161718191a1b1c1d1e1f
        // out  : 7a7b4e5638782546a8c0477a3b813f43

        let in_ = AesBlock::from_bytes(&hex!("000102030405060708090a0b0c0d0e0f"));
        let rk = AesBlock::from_bytes(&hex!("101112131415161718191a1b1c1d1e1f"));
        let out = hex!("7a7b4e5638782546a8c0477a3b813f43");

        assert_eq!(in_.aes(rk).into_bytes(), out);
    }
}
