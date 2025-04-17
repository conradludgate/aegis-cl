use std::arch::x86_64::*;
use std::ops::{BitAnd, BitXor};

use hybrid_array::Array;
use hybrid_array::sizes::{U2, U32, U64};

use crate::AegisParallel;
use crate::low::IAesBlock;

use super::AesBlock;

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct AesBlock2(__m256i);

impl AegisParallel for U2 {
    type Block2 = U64;
    type Block = U32;

    type AesBlock = AesBlock2;
}

impl Default for AesBlock2 {
    #[inline(always)]
    fn default() -> Self {
        Self(unsafe { _mm256_setzero_si256() })
    }
}

impl From<AesBlock> for AesBlock2 {
    #[inline(always)]
    fn from(a: AesBlock) -> Self {
        Self(unsafe { _mm256_broadcastsi128_si256(a.0) })
    }
}

impl From<Array<AesBlock, U2>> for AesBlock2 {
    #[inline(always)]
    fn from(value: Array<AesBlock, U2>) -> Self {
        let Array([a, b]) = value;

        unsafe {
            let a = _mm256_zextsi128_si256(a.0);
            let ab = _mm256_inserti64x2::<1>(a, b.0);
            AesBlock2(ab)
        }
    }
}

impl From<AesBlock2> for Array<AesBlock, U2> {
    #[inline(always)]
    fn from(val: AesBlock2) -> Self {
        unsafe {
            let a = AesBlock(_mm256_extracti128_si256::<0>(val.0));
            let b = AesBlock(_mm256_extracti128_si256::<1>(val.0));
            Array([a, b])
        }
    }
}

impl From<AesBlock2> for Array<u8, U32> {
    #[inline(always)]
    fn from(val: AesBlock2) -> Self {
        let mut out = Array::<u8, U32>::default();
        unsafe { _mm256_storeu_epi8(out.as_mut_ptr().cast(), val.0) }
        out
    }
}

impl IAesBlock for AesBlock2 {
    type Size = U32;

    #[inline(always)]
    fn aes(self, key: Self) -> Self {
        Self(unsafe { _mm256_aesenc_epi128(self.0, key.0) })
    }

    #[inline(always)]
    fn xor3(self, mid: Self, rhs: Self) -> Self {
        self ^ mid ^ rhs
    }

    #[inline(always)]
    fn reduce_xor(self) -> AesBlock {
        unsafe {
            let a = _mm_xor_si128(
                _mm256_extracti128_si256::<0>(self.0),
                _mm256_extracti128_si256::<1>(self.0),
            );
            AesBlock(a)
        }
    }

    #[inline(always)]
    fn first(&self) -> AesBlock {
        AesBlock(unsafe { _mm256_extracti128_si256::<0>(self.0) })
    }

    #[inline(always)]
    fn from_block(a: &Array<u8, Self::Size>) -> Self {
        AesBlock2(unsafe { _mm256_loadu_epi8(a.as_ptr().cast()) })
    }
}

impl BitXor for AesBlock2 {
    type Output = Self;

    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(unsafe { _mm256_xor_si256(self.0, rhs.0) })
    }
}

impl BitAnd for AesBlock2 {
    type Output = Self;

    #[inline(always)]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(unsafe { _mm256_and_si256(self.0, rhs.0) })
    }
}
