use std::arch::x86_64::*;
use std::ops::{BitAnd, BitXor};

use hybrid_array::Array;
use hybrid_array::sizes::{U1, U16, U32};

use crate::AegisParallel;
use crate::low::IAesBlock;

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct AesBlock(pub(super) __m128i);

impl AegisParallel for U1 {
    type Block2 = U32;
    type Block = U16;

    type AesBlock = AesBlock;
}

impl From<Array<AesBlock, U1>> for AesBlock {
    #[inline(always)]
    fn from(value: Array<AesBlock, U1>) -> Self {
        let Array([AesBlock(a)]) = value;
        AesBlock(a)
    }
}

impl From<AesBlock> for Array<AesBlock, U1> {
    #[inline(always)]
    fn from(val: AesBlock) -> Self {
        Array([val])
    }
}

impl From<AesBlock> for Array<u8, U16> {
    #[inline(always)]
    fn from(val: AesBlock) -> Self {
        // Safety: both types are equivalent, and transmute does not care about alignment.
        Array(unsafe { core::mem::transmute::<__m128i, [u8; 16]>(val.0) })
    }
}

impl IAesBlock for AesBlock {
    type Size = U16;

    #[inline(always)]
    fn aes(self, key: Self) -> Self {
        // Safety: we require target_feature = "aes".
        Self(unsafe { _mm_aesenc_si128(self.0, key.0) })
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
        // Safety: both types are equivalent, and transmute does not care about alignment.
        AesBlock(unsafe { core::mem::transmute::<[u8; 16], __m128i>(a.0) })
    }
}

impl BitXor for AesBlock {
    type Output = Self;

    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self::Output {
        // Safety: we require target_feature = "aes".
        // I think aes implies sse2???
        Self(unsafe { _mm_xor_si128(self.0, rhs.0) })
    }
}

impl BitAnd for AesBlock {
    type Output = Self;

    #[inline(always)]
    fn bitand(self, rhs: Self) -> Self::Output {
        // Safety: we require target_feature = "aes".
        // I think aes implies sse2???
        Self(unsafe { _mm_and_si128(self.0, rhs.0) })
    }
}
