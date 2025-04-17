use std::arch::aarch64::*;
use std::ops::{BitAnd, BitXor, BitXorAssign};

use hybrid_array::Array;
use hybrid_array::sizes::{U1, U16, U32};

use crate::AegisParallel;

use super::IAesBlock;

impl AegisParallel for U1 {
    type Block2 = U32;
    type Block = U16;

    type AesBlock = AesBlock;
}

#[derive(Clone, Copy)]
pub struct AesBlock(uint8x16_t);

impl Default for AesBlock {
    #[inline(always)]
    fn default() -> Self {
        Self(unsafe { vmovq_n_u8(0) })
    }
}

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
        let mut out = Array([0; 16]);
        unsafe { vst1q_u8(out.as_mut_ptr(), val.0) }
        out
    }
}

impl IAesBlock for AesBlock {
    type Size = U16;

    #[inline(always)]
    fn aes(self, key: Self) -> Self {
        Self(unsafe { vaesmcq_u8(vaeseq_u8(self.0, vmovq_n_u8(0))) }) ^ key
    }

    #[inline(always)]
    fn xor3(self, mid: Self, rhs: Self) -> Self {
        Self(unsafe { veor3q_u8(self.0, mid.0, rhs.0) })
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
    fn from_block(a: &Array<u8, Self::Size>) -> Self {
        AesBlock(unsafe { vld1q_u8(a.as_ptr()) })
    }
}

impl BitXor for AesBlock {
    type Output = Self;

    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(unsafe { veorq_u8(self.0, rhs.0) })
    }
}

impl BitXorAssign for AesBlock {
    #[inline(always)]
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl BitAnd for AesBlock {
    type Output = Self;

    #[inline(always)]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(unsafe { vandq_u8(self.0, rhs.0) })
    }
}

mod polyfill_x2 {
    include!("generic/polyfill_x2.rs");
}

use polyfill_x2::AesBlock2;

mod polyfill_x4 {
    include!("generic/polyfill_x4.rs");
}
