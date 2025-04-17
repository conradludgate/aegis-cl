use std::ops::{BitAnd, BitXor, BitXorAssign};

use hybrid_array::Array;
use hybrid_array::sizes::{U2, U4, U32, U64, U128};

use crate::AegisParallel;
use crate::low::IAesBlock;

use super::AesBlock;
use super::AesBlock2;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct AesBlock4(AesBlock2, AesBlock2);

impl AegisParallel for U4 {
    type Block2 = U128;
    type Block = U64;

    type AesBlock = AesBlock4;

}

impl Default for AesBlock4 {
    #[inline(always)]
    fn default() -> Self {
        Self(AesBlock2::default(), AesBlock2::default())
    }
}

impl From<AesBlock> for AesBlock4 {
    #[inline(always)]
    fn from(v: AesBlock) -> Self {
        Self(AesBlock2::from(v), AesBlock2::from(v))
    }
}

impl From<Array<AesBlock, U4>> for AesBlock4 {
    #[inline(always)]
    fn from(value: Array<AesBlock, U4>) -> Self {
        let Array([v0, v1, v2, v3]) = value;
        Self(
            AesBlock2::from(Array([v0, v1])),
            AesBlock2::from(Array([v2, v3])),
        )
    }
}

impl From<AesBlock4> for Array<AesBlock, U4> {
    #[inline(always)]
    fn from(value: AesBlock4) -> Self {
        let Array([a, b]): Array<AesBlock, U2> = value.0.into();
        let Array([c, d]): Array<AesBlock, U2> = value.1.into();
        Array([a, b, c, d])
    }
}

impl From<AesBlock4> for Array<u8, U64> {
    #[inline(always)]
    fn from(val: AesBlock4) -> Self {
        let a: Array<u8, U32> = val.0.into();
        let b: Array<u8, U32> = val.1.into();
        a.concat(b)
    }
}

impl IAesBlock for AesBlock4 {
    type Size = U64;

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
    fn first(&self) -> AesBlock {
        self.0.first()
    }

    #[inline(always)]
    fn reduce_xor(self) -> AesBlock {
        let Self(a, b) = self;
        a.reduce_xor() ^ b.reduce_xor()
    }

    #[inline(always)]
    fn from_block(a: &Array<u8, Self::Size>) -> Self {
        let (a0, a1) = a.split_ref::<U32>();
        AesBlock4(AesBlock2::from_block(a0), AesBlock2::from_block(a1))
    }
}

impl BitXor for AesBlock4 {
    type Output = Self;

    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self::Output {
        let Self(l0, l1) = self;
        let Self(r0, r1) = rhs;
        Self(l0 ^ r0, l1 ^ r1)
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
        let Self(l0, l1) = self;
        let Self(r0, r1) = rhs;
        Self(l0 & r0, l1 & r1)
    }
}
