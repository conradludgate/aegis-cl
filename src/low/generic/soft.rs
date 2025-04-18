use std::ops::{BitAnd, BitXor};

use hybrid_array::Array;
use hybrid_array::sizes::{U1, U16, U32};

use crate::AegisParallel;
use crate::low::AesBlockArray;

impl AegisParallel for U1 {
    type Block2 = U32;
    type Block = U16;

    type AesBlock = AesBlock;
}

#[derive(Clone, Copy)]
pub struct AesBlock(aes::Block);

impl From<Array<AesBlock, U1>> for AesBlock {
    #[inline(always)]
    fn from(value: Array<AesBlock, U1>) -> Self {
        let Array([AesBlock(a)]) = value;
        AesBlock(a)
    }
}

impl From<AesBlock> for Array<AesBlock, U1> {
    fn from(value: AesBlock) -> Self {
        Array([value])
    }
}

impl From<AesBlock> for Array<u8, U16> {
    #[inline(always)]
    fn from(val: AesBlock) -> Self {
        val.0
    }
}

impl AesBlockArray for AesBlock {
    type Size = U16;

    #[inline(always)]
    fn aes(mut self, key: Self) -> Self {
        aes::hazmat::cipher_round(&mut self.0, &key.0);
        self
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
    fn from_block(a: &Array<u8, Self::Size>) -> Self {
        Self(*a)
    }
}

impl BitXor for AesBlock {
    type Output = Self;

    #[inline(always)]
    fn bitxor(mut self, rhs: Self) -> Self::Output {
        for i in 0..16 {
            self.0[i] ^= rhs.0[i];
        }
        self
    }
}

impl BitAnd for AesBlock {
    type Output = Self;

    #[inline(always)]
    fn bitand(mut self, rhs: Self) -> Self::Output {
        for i in 0..16 {
            self.0[i] &= rhs.0[i];
        }
        self
    }
}
