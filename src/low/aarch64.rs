use std::arch::aarch64::*;
use std::ops::{BitAnd, BitXor};

use hybrid_array::Array;
use hybrid_array::sizes::{U1, U16, U32};

use super::AesBlockArray;

#[derive(Clone, Copy)]
pub struct AesBlock(uint8x16_t);

impl From<Array<AesBlock, U1>> for AesBlock {
    #[inline(always)]
    fn from(value: Array<AesBlock, U1>) -> Self {
        let Array([AesBlock(a)]) = value;
        AesBlock(a)
    }
}

impl From<AesBlock> for Array<AesBlock, U1> {
    fn from(value: AesBlock) -> Self {
        Array([value])
    }
}

impl From<AesBlock> for Array<u8, U16> {
    #[inline(always)]
    fn from(val: AesBlock) -> Self {
        Array(val.into())
    }
}

impl From<AesBlock> for [u8; 16] {
    #[inline(always)]
    fn from(val: AesBlock) -> Self {
        let mut out = [0; 16];
        // Safety: we require target_feature = "aes".
        // I think this implies neon.
        unsafe { vst1q_u8(out.as_mut_ptr(), val.0) }
        out
    }
}

impl AesBlockArray for AesBlock {
    type Block = U16;
    type Block2 = U32;

    #[inline(always)]
    fn aes(self, key: Self) -> Self {
        // Safety: we require target_feature = "aes".
        // I think this implies neon.
        let zero = unsafe { vmovq_n_u8(0) };
        // Safety: we require target_feature = "aes".
        let enc = unsafe { vaeseq_u8(self.0, zero) };
        // Safety: we require target_feature = "aes".
        let mixed = unsafe { vaesmcq_u8(enc) };
        Self(mixed) ^ key
    }

    #[inline(always)]
    fn first(&self) -> AesBlock {
        *self
    }

    #[inline(always)]
    fn reduce_xor(self) -> AesBlock {
        self
    }

    #[inline(always)]
    fn from_block(a: &Array<u8, Self::Block>) -> Self {
        // Safety: both types are equivalent, and transmute does not care about alignment.
        AesBlock(unsafe { core::mem::transmute::<[u8; 16], uint8x16_t>(a.0) })
    }
}

impl BitXor for AesBlock {
    type Output = Self;

    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self::Output {
        // Safety: we require target_feature = "aes".
        // I think this implies neon.
        Self(unsafe { veorq_u8(self.0, rhs.0) })
    }
}

impl BitAnd for AesBlock {
    type Output = Self;

    #[inline(always)]
    fn bitand(self, rhs: Self) -> Self::Output {
        // Safety: we require target_feature = "aes".
        // I think this implies neon.
        Self(unsafe { vandq_u8(self.0, rhs.0) })
    }
}

mod polyfill_x2 {
    include!("generic/polyfill_x2.rs");
}

pub use polyfill_x2::AesBlock2;

mod polyfill_x4 {
    include!("generic/polyfill_x4.rs");
}

pub use polyfill_x4::AesBlock4;
