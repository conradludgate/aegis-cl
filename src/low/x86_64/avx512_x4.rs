#![cfg(all(target_feature = "avx512f", target_feature = "vaes"))]

use std::arch::x86_64::*;
use std::ops::{BitAnd, BitXor};

use hybrid_array::Array;
use hybrid_array::sizes::{U2, U4, U64, U128};

use crate::low::IAesBlock;

use super::AesBlock;
use super::avx2_x2::AesBlock2;

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct AesBlock4(__m512i);

impl From<AesBlock> for AesBlock4 {
    #[inline(always)]
    fn from(v: AesBlock) -> Self {
        let vv = AesBlock2::from([v, v]);
        // Safety: we require target_feature = "avx512f".
        let r = unsafe { _mm512_castsi256_si512(vv.0) };
        // Safety: we require target_feature = "avx512f".
        let r = unsafe { _mm512_inserti64x4::<1>(r, vv.0) };
        Self(r)
    }
}

impl From<AesBlock4> for Array<AesBlock, U4> {
    #[inline(never)]
    fn from(val: AesBlock4) -> Self {
        // Safety: we require target_feature = "avx512f".
        let ab = AesBlock2(unsafe { _mm512_extracti64x4_epi64::<0>(val.0) });
        // Safety: we require target_feature = "avx512f".
        let cd = AesBlock2(unsafe { _mm512_extracti64x4_epi64::<1>(val.0) });

        let Array([a, b]): Array<AesBlock, U2> = ab.into();
        let Array([c, d]): Array<AesBlock, U2> = cd.into();
        Array([a, b, c, d])
    }
}

impl From<AesBlock4> for Array<u8, U64> {
    #[inline(always)]
    fn from(val: AesBlock4) -> Self {
        // Safety: both types are equivalent, and transmute does not care about alignment.
        Array(unsafe { core::mem::transmute::<__m512i, [u8; 64]>(val.0) })
    }
}

impl IAesBlock for AesBlock4 {
    type Block = U64;
    type Block2 = U128;

    #[inline(always)]
    fn aes(self, key: Self) -> Self {
        // Safety: we require target_feature = "vaes" and target_feature = "aes512f".
        Self(unsafe { _mm512_aesenc_epi128(self.0, key.0) })
    }

    #[inline(always)]
    fn first(&self) -> AesBlock {
        // Safety: we require target_feature = "avx512f".
        let ab = AesBlock2(unsafe { _mm512_extracti64x4_epi64::<0>(self.0) });
        ab.first()
    }

    #[inline(always)]
    fn reduce_xor(self) -> AesBlock {
        // Safety: we require target_feature = "avx512f".
        let ab = AesBlock2(unsafe { _mm512_extracti64x4_epi64::<0>(self.0) });
        // Safety: we require target_feature = "avx512f".
        let cd = AesBlock2(unsafe { _mm512_extracti64x4_epi64::<1>(self.0) });

        (ab ^ cd).reduce_xor()
    }

    #[inline(always)]
    fn from_block(a: &Array<u8, Self::Block>) -> Self {
        // Safety: both types are equivalent, and transmute does not care about alignment.
        Self(unsafe { core::mem::transmute::<[u8; 64], __m512i>(a.0) })
    }
}

impl BitXor for AesBlock4 {
    type Output = Self;

    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self::Output {
        // Safety: we require target_feature = "aes512f".
        Self(unsafe { _mm512_xor_si512(self.0, rhs.0) })
    }
}

impl BitAnd for AesBlock4 {
    type Output = Self;

    #[inline(always)]
    fn bitand(self, rhs: Self) -> Self::Output {
        // Safety: we require target_feature = "aes512f".
        Self(unsafe { _mm512_and_si512(self.0, rhs.0) })
    }
}
