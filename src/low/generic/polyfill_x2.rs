use std::ops::{BitAnd, BitXor};

use hybrid_array::Array;
use hybrid_array::sizes::{U2, U16, U32, U64};

use crate::low::AesBlockArray;

use super::AesBlock;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct AesBlock2(AesBlock, AesBlock);

impl From<AesBlock> for AesBlock2 {
    #[inline(always)]
    fn from(a: AesBlock) -> Self {
        Self(a, a)
    }
}

impl From<AesBlock2> for Array<AesBlock, U2> {
    #[inline(always)]
    fn from(value: AesBlock2) -> Self {
        Array([value.0, value.1])
    }
}

impl From<AesBlock2> for Array<u8, U32> {
    #[inline(always)]
    fn from(val: AesBlock2) -> Self {
        let a: Array<u8, U16> = val.0.into();
        let b: Array<u8, U16> = val.1.into();
        a.concat(b)
    }
}

impl AesBlockArray for AesBlock2 {
    type Block = U32;
    type Block2 = U64;

    #[inline(always)]
    fn aes(self, key: Self) -> Self {
        let Self(m0, m1) = self;
        let Self(k0, k1) = key;

        Self(m0.aes(k0), m1.aes(k1))
    }

    #[inline(always)]
    fn reduce_xor(self) -> AesBlock {
        let Self(a, b) = self;
        a ^ b
    }

    #[inline(always)]
    fn first(&self) -> AesBlock {
        self.0
    }

    #[inline(always)]
    fn from_block(a: &Array<u8, Self::Block>) -> Self {
        let (a0, a1) = a.split_ref::<U16>();
        AesBlock2(AesBlock::from_block(a0), AesBlock::from_block(a1))
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

impl BitAnd for AesBlock2 {
    type Output = Self;

    #[inline(always)]
    fn bitand(self, rhs: Self) -> Self::Output {
        let Self(l0, l1) = self;
        let Self(r0, r1) = rhs;
        Self(l0 & r0, l1 & r1)
    }
}
