use std::arch::x86_64::*;
use std::ops::{BitAnd, BitXor, BitXorAssign};

use hybrid_array::Array;
use hybrid_array::sizes::{U1, U16, U32};

use crate::AegisParallel;
use crate::low::IAesBlock;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct AesBlock(pub(super) __m128i);

impl AegisParallel for U1 {
    type Aegis128BlockSize = U32;
    type Aegis256BlockSize = U16;

    type AesBlock = AesBlock;

    #[inline(always)]
    fn split_blocks(a: &Array<u8, Self::Aegis128BlockSize>) -> (Self::AesBlock, Self::AesBlock) {
        let (a0, a1) = a.split_ref::<U16>();
        (Self::from_block(a0), Self::from_block(a1))
    }

    #[inline(always)]
    fn from_block(a: &Array<u8, Self::Aegis256BlockSize>) -> Self::AesBlock {
        AesBlock(unsafe { _mm_loadu_epi8(a.as_ptr().cast()) })
    }
}

impl Default for AesBlock {
    #[inline(always)]
    fn default() -> Self {
        Self(unsafe { _mm_setzero_si128() })
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
    #[inline(always)]
    fn from(val: AesBlock) -> Self {
        Array([val])
    }
}

impl IAesBlock for AesBlock {
    type Size = U16;

    #[inline(always)]
    fn aes(self, key: Self) -> Self {
        Self(unsafe { _mm_aesenc_si128(self.0, key.0) })
    }

    #[inline(always)]
    fn xor3(self, mid: Self, rhs: Self) -> Self {
        self ^ mid ^ rhs
    }

    #[inline(always)]
    fn first(&self) -> AesBlock {
        *self
    }

    #[inline(always)]
    fn fold_xor(self) -> AesBlock {
        self
    }

    #[inline(always)]
    fn into_array(self) -> Array<u8, U16> {
        let mut out = Array::<u8, U16>::default();
        unsafe { _mm_storeu_epi8(out.as_mut_ptr().cast(), self.0) }
        out
    }
}

impl BitXor for AesBlock {
    type Output = Self;

    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(unsafe { _mm_xor_si128(self.0, rhs.0) })
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
        Self(unsafe { _mm_and_si128(self.0, rhs.0) })
    }
}
