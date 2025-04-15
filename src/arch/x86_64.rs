use std::arch::x86_64::*;
use std::mem::{transmute, transmute_copy};
use std::ops::{BitAnd, BitXor, BitXorAssign, Index, IndexMut};

use hybrid_array::Array;
use hybrid_array::sizes::{U1, U2, U4, U16, U32, U64, U128};

use crate::AegisParallel;

use super::IAesBlock;

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
        AesBlock(unsafe { transmute_copy(a) })
    }
}

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
        unsafe { transmute_copy(a) }
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct AesBlock(__m128i);

#[derive(Clone, Copy)]
#[repr(C)]
pub struct AesBlock2(AesBlock, AesBlock);

#[derive(Clone, Copy)]
#[repr(C)]
pub struct AesBlock4(AesBlock, AesBlock, AesBlock, AesBlock);

impl Default for AesBlock {
    #[inline(always)]
    fn default() -> Self {
        Self(unsafe { _mm_setzero_si128() })
    }
}

impl Index<usize> for AesBlock {
    type Output = AesBlock;

    #[inline(always)]
    fn index(&self, index: usize) -> &Self::Output {
        match index {
            0 => self,
            _ => unreachable!(),
        }
    }
}

impl IndexMut<usize> for AesBlock {
    #[inline(always)]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        match index {
            0 => self,
            _ => unreachable!(),
        }
    }
}

impl From<Array<AesBlock, U1>> for AesBlock {
    #[inline(always)]
    fn from(value: Array<AesBlock, U1>) -> Self {
        let Array([AesBlock(a)]) = value;
        AesBlock(a)
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
    fn fold_xor(self) -> AesBlock {
        self
    }

    #[inline(always)]
    fn into_array(self) -> Array<u8, U16> {
        unsafe { transmute(self.0) }
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

impl Default for AesBlock2 {
    #[inline(always)]
    fn default() -> Self {
        Self(AesBlock::default(), AesBlock::default())
    }
}

impl Index<usize> for AesBlock2 {
    type Output = AesBlock;

    #[inline(always)]
    fn index(&self, index: usize) -> &Self::Output {
        match index {
            0 => &self.0,
            1 => &self.1,
            _ => unreachable!(),
        }
    }
}

impl IndexMut<usize> for AesBlock2 {
    #[inline(always)]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        match index {
            0 => &mut self.0,
            1 => &mut self.1,
            _ => unreachable!(),
        }
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
    fn into_array(self) -> Array<u8, U32> {
        self[0].into_array().concat(self[1].into_array())
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

impl Default for AesBlock4 {
    #[inline(always)]
    fn default() -> Self {
        Self(
            AesBlock::default(),
            AesBlock::default(),
            AesBlock::default(),
            AesBlock::default(),
        )
    }
}

impl Index<usize> for AesBlock4 {
    type Output = AesBlock;

    #[inline(always)]
    fn index(&self, index: usize) -> &Self::Output {
        match index {
            0 => &self.0,
            1 => &self.1,
            2 => &self.2,
            3 => &self.3,
            _ => unreachable!(),
        }
    }
}

impl IndexMut<usize> for AesBlock4 {
    #[inline(always)]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        match index {
            0 => &mut self.0,
            1 => &mut self.1,
            2 => &mut self.2,
            3 => &mut self.3,
            _ => unreachable!(),
        }
    }
}

impl From<AesBlock> for AesBlock4 {
    #[inline(always)]
    fn from(v: AesBlock) -> Self {
        Self(v, v, v, v)
    }
}

impl From<Array<AesBlock, U4>> for AesBlock4 {
    #[inline(always)]
    fn from(value: Array<AesBlock, U4>) -> Self {
        let Array([v0, v1, v2, v3]) = value;
        Self(v0, v1, v2, v3)
    }
}

impl IAesBlock for AesBlock4 {
    type Size = U64;

    #[inline(always)]
    fn aes(self, key: Self) -> Self {
        let Self(m0, m1, m2, m3) = self;
        let Self(k0, k1, k2, k3) = key;

        Self(m0.aes(k0), m1.aes(k1), m2.aes(k2), m3.aes(k3))
    }

    #[inline(always)]
    fn xor3(self, mid: Self, rhs: Self) -> Self {
        self ^ mid ^ rhs
    }

    #[inline(always)]
    fn fold_xor(self) -> AesBlock {
        let Self(a, b, c, d) = self;
        a ^ b ^ c ^ d
    }

    #[inline(always)]
    fn into_array(self) -> Array<u8, U64> {
        self[0]
            .into_array()
            .concat(self[1].into_array())
            .concat(self[2].into_array().concat(self[3].into_array()))
    }
}

impl BitXor for AesBlock4 {
    type Output = Self;

    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self::Output {
        let Self(l0, l1, l2, l3) = self;
        let Self(r0, r1, r2, r3) = rhs;
        Self(l0 ^ r0, l1 ^ r1, l2 ^ r2, l3 ^ r3)
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
        let Self(l0, l1, l2, l3) = self;
        let Self(r0, r1, r2, r3) = rhs;
        Self(l0 & r0, l1 & r1, l2 & r2, l3 & r3)
    }
}
