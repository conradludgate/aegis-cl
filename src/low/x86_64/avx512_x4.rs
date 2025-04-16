use std::arch::x86_64::*;
use std::mem::transmute;
use std::ops::{BitAnd, BitXor, BitXorAssign};

use hybrid_array::Array;
use hybrid_array::sizes::{U4, U64, U128};

use crate::AegisParallel;
use crate::low::IAesBlock;

use super::AesBlock;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct AesBlock4(__m512i);

impl AegisParallel for U4 {
    type Aegis128BlockSize = U128;
    type Aegis256BlockSize = U64;

    type AesBlock = AesBlock4;

    #[inline(always)]
    fn split_blocks(a: &Array<u8, Self::Aegis128BlockSize>) -> (Self::AesBlock, Self::AesBlock) {
        let (a03, a47) = a.split_ref::<U64>();
        (Self::from_block(a03), Self::from_block(a47))
    }

    #[inline(always)]
    fn from_block(a: &Array<u8, Self::Aegis256BlockSize>) -> Self::AesBlock {
        AesBlock4(unsafe { _mm512_loadu_epi8(a.as_ptr().cast()) })
    }
}

impl Default for AesBlock4 {
    #[inline(always)]
    fn default() -> Self {
        Self(unsafe { _mm512_setzero_si512() })
    }
}

impl From<AesBlock> for AesBlock4 {
    #[inline(always)]
    fn from(v: AesBlock) -> Self {
        Self::from(Array([v, v, v, v]))
    }
}

impl From<Array<AesBlock, U4>> for AesBlock4 {
    #[inline(always)]
    fn from(value: Array<AesBlock, U4>) -> Self {
        unsafe { transmute(value) }
    }
}

impl From<AesBlock4> for Array<AesBlock, U4> {
    #[inline(always)]
    fn from(val: AesBlock4) -> Self {
        unsafe { transmute(val) }
    }
}

impl IAesBlock for AesBlock4 {
    type Size = U64;

    #[inline(always)]
    fn aes(self, key: Self) -> Self {
        Self(unsafe { _mm512_aesenc_epi128(self.0, key.0) })
    }

    #[inline(always)]
    fn xor3(self, mid: Self, rhs: Self) -> Self {
        self ^ mid ^ rhs
    }

    #[inline(always)]
    fn first(&self) -> AesBlock {
        unsafe { AesBlock(_mm512_extracti64x2_epi64::<0>(self.0)) }
    }

    #[inline(always)]
    fn fold_xor(self) -> AesBlock {
        unsafe {
            let a = _mm256_xor_si256(
                _mm512_extracti64x4_epi64::<0>(self.0),
                _mm512_extracti64x4_epi64::<1>(self.0),
            );
            let a = _mm_xor_si128(
                _mm256_extracti128_si256::<0>(a),
                _mm256_extracti128_si256::<1>(a),
            );
            AesBlock(a)
        }
    }

    #[inline(always)]
    fn into_array(self) -> Array<u8, U64> {
        let mut out = Array::<u8, U64>::default();
        unsafe { _mm512_storeu_epi8(out.as_mut_ptr().cast(), self.0) }
        out
    }
}

impl BitXor for AesBlock4 {
    type Output = Self;

    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(unsafe { _mm512_xor_si512(self.0, rhs.0) })
    }
}

impl BitXorAssign for AesBlock4 {
    #[inline(always)]
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl BitAnd for AesBlock4 {
    type Output = Self;

    #[inline(always)]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(unsafe { _mm512_and_si512(self.0, rhs.0) })
    }
}
