use std::mem::{transmute, transmute_copy};
use std::ops::{BitAnd, BitXor, BitXorAssign};

use hybrid_array::Array;
use hybrid_array::sizes::{U2, U32, U64};

use crate::AegisParallel;
use crate::low::IAesBlock;

use super::AesBlock;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct AesBlock2(AesBlock, AesBlock);

impl AegisParallel for U2 {
    type Aegis128BlockSize = U64;
    type Aegis256BlockSize = U32;

    type AesBlock = AesBlock2;

    #[inline(always)]
    fn split_blocks(a: &Array<u8, Self::Aegis128BlockSize>) -> (Self::AesBlock, Self::AesBlock) {
        let (a01, a23) = a.split_ref::<U32>();
        (Self::from_block(a01), Self::from_block(a23))
    }

    #[inline(always)]
    fn from_block(a: &Array<u8, Self::Aegis256BlockSize>) -> Self::AesBlock {
        unsafe { transmute_copy(a) }
    }
}

impl Default for AesBlock2 {
    #[inline(always)]
    fn default() -> Self {
        Self(AesBlock::default(), AesBlock::default())
    }
}

impl From<AesBlock> for AesBlock2 {
    #[inline(always)]
    fn from(a: AesBlock) -> Self {
        Self(a, a)
    }
}

impl From<Array<AesBlock, U2>> for AesBlock2 {
    #[inline(always)]
    fn from(value: Array<AesBlock, U2>) -> Self {
        let Array([a, b]) = value;
        Self(a, b)
    }
}

impl From<AesBlock2> for Array<AesBlock, U2> {
    #[inline(always)]
    fn from(value: AesBlock2) -> Self {
        Array([value.0, value.1])
    }
}

impl IAesBlock for AesBlock2 {
    type Size = U32;

    #[inline(always)]
    fn aes(self, key: Self) -> Self {
        let Self(m0, m1) = self;
        let Self(k0, k1) = key;

        Self(m0.aes(k0), m1.aes(k1))
    }

    #[inline(always)]
    fn xor3(self, mid: Self, rhs: Self) -> Self {
        self ^ mid ^ rhs
    }

    #[inline(always)]
    fn fold_xor(self) -> AesBlock {
        let Self(a, b) = self;
        a ^ b
    }

    #[inline(always)]
    fn first(&self) -> AesBlock {
        self.0
    }

    #[inline(always)]
    fn into_array(self) -> Array<u8, U32> {
        unsafe { transmute(self) }
    }
}

impl BitXor for AesBlock2 {
    type Output = Self;

    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self::Output {
        let Self(l0, l1) = self;
        let Self(r0, r1) = rhs;
        Self(l0 ^ r0, l1 ^ r1)
    }
}

impl BitXorAssign for AesBlock2 {
    #[inline(always)]
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl BitAnd for AesBlock2 {
    type Output = Self;

    #[inline(always)]
    fn bitand(self, rhs: Self) -> Self::Output {
        let Self(l0, l1) = self;
        let Self(r0, r1) = rhs;
        Self(l0 & r0, l1 & r1)
    }
}
