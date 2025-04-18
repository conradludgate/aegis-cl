use std::arch::x86_64::*;
use std::ops::{BitAnd, BitXor};

use hybrid_array::Array;
use hybrid_array::sizes::{U2, U32, U64};

use crate::low::IAesBlock;

use super::AesBlock;

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct AesBlock2(pub(super) __m256i);

impl From<AesBlock> for AesBlock2 {
    #[inline(always)]
    fn from(a: AesBlock) -> Self {
        // Safety: we require target_feature = "avx2".
        Self(unsafe { _mm256_broadcastsi128_si256(a.0) })
    }
}

impl From<[AesBlock; 2]> for AesBlock2 {
    #[inline(always)]
    fn from(value: [AesBlock; 2]) -> Self {
        let [a, b] = value;
        // Safety: we require target_feature = "avx2".
        // I think avx2 implies avx???
        unsafe { Self(_mm256_setr_m128i(a.0, b.0)) }
    }
}

impl From<AesBlock2> for Array<AesBlock, U2> {
    #[inline(always)]
    fn from(val: AesBlock2) -> Self {
        // Safety: we require target_feature = "avx2".
        let a = AesBlock(unsafe { _mm256_extracti128_si256::<0>(val.0) });
        // Safety: we require target_feature = "avx2".
        let b = AesBlock(unsafe { _mm256_extracti128_si256::<1>(val.0) });
        Array([a, b])
    }
}

impl From<AesBlock2> for Array<u8, U32> {
    #[inline(always)]
    fn from(val: AesBlock2) -> Self {
        // Safety: both types are equivalent, and transmute does not care about alignment.
        Array(unsafe { core::mem::transmute::<__m256i, [u8; 32]>(val.0) })
    }
}

impl IAesBlock for AesBlock2 {
    type Block = U32;
    type Block2 = U64;

    #[inline(always)]
    fn aes(self, key: Self) -> Self {
        // Safety: we require target_feature = "vaes".
        Self(unsafe { _mm256_aesenc_epi128(self.0, key.0) })
    }

    #[inline(always)]
    fn reduce_xor(self) -> AesBlock {
        // Safety: we require target_feature = "avx2".
        let a = AesBlock(unsafe { _mm256_extracti128_si256::<0>(self.0) });
        // Safety: we require target_feature = "avx2".
        let b = AesBlock(unsafe { _mm256_extracti128_si256::<1>(self.0) });
        a ^ b
    }

    #[inline(always)]
    fn first(&self) -> AesBlock {
        // Safety: we require target_feature = "avx2".
        AesBlock(unsafe { _mm256_extracti128_si256::<0>(self.0) })
    }

    #[inline(always)]
    fn from_block(a: &Array<u8, Self::Block>) -> Self {
        // Safety: both types are equivalent, and transmute does not care about alignment.
        Self(unsafe { core::mem::transmute::<[u8; 32], __m256i>(a.0) })
    }
}

impl BitXor for AesBlock2 {
    type Output = Self;

    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self::Output {
        // Safety: we require target_feature = "avx2".
        Self(unsafe { _mm256_xor_si256(self.0, rhs.0) })
    }
}

impl BitAnd for AesBlock2 {
    type Output = Self;

    #[inline(always)]
    fn bitand(self, rhs: Self) -> Self::Output {
        // Safety: we require target_feature = "avx2".
        Self(unsafe { _mm256_and_si256(self.0, rhs.0) })
    }
}
