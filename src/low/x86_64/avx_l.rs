//! Instruction preconditions: AES. This representation is used
//! only below a checked runtime entry or through compile-time aliases that
//! require these features globally; see the enclosing module's invariant.
use std::arch::x86_64::*;
use std::ops::{BitAnd, BitXor};

use hybrid_array::Array;
use hybrid_array::sizes::{U1, U16, U32};

use crate::low::AesBlockArray;

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct AesBlock(pub(super) __m128i);

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
        Array(val.into())
    }
}

impl From<AesBlock> for [u8; 16] {
    #[inline(always)]
    fn from(val: AesBlock) -> Self {
        // SAFETY: these equally sized integer vectors/byte arrays have no invalid
        // bit patterns. All source bytes are initialized; this by-value conversion
        // creates no references and transfers no allocation ownership.
        unsafe { core::mem::transmute::<__m128i, [u8; 16]>(val.0) }
    }
}

impl AesBlockArray<AesBlock> for AesBlock {
    type Block = U16;
    type Block2 = U32;

    #[inline(always)]
    fn aes(self, key: Self) -> Self {
        // SAFETY: the module's native-backend boundary establishes aes.
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
    fn from_block(a: &Array<u8, Self::Block>) -> Self {
        // SAFETY: these equally sized integer vectors/byte arrays have no invalid
        // bit patterns. All source bytes are initialized; this by-value conversion
        // creates no references and transfers no allocation ownership.
        AesBlock(unsafe { core::mem::transmute::<[u8; 16], __m128i>(a.0) })
    }
}

impl BitXor for AesBlock {
    type Output = Self;

    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self::Output {
        // SAFETY: SSE2 is part of the x86_64 baseline.
        Self(unsafe { _mm_xor_si128(self.0, rhs.0) })
    }
}

impl BitAnd for AesBlock {
    type Output = Self;

    #[inline(always)]
    fn bitand(self, rhs: Self) -> Self::Output {
        // SAFETY: SSE2 is part of the x86_64 baseline.
        Self(unsafe { _mm_and_si128(self.0, rhs.0) })
    }
}
