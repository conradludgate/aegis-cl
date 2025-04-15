use std::arch::aarch64::*;
use std::ops::{BitAnd, BitXor, BitXorAssign, Index, IndexMut};

use hybrid_array::Array;
use hybrid_array::sizes::{U1, U2, U4, U16, U32, U64, U128};

use crate::AegisParallel;

use super::IAesBlock;

impl AegisParallel for U1 {
    type Aegis128BlockSize = U32;
    type Aegis256BlockSize = U16;

    type AesBlock = AesBlock;

    fn split_block128(a: Array<u8, Self::Aegis128BlockSize>) -> (Self::AesBlock, Self::AesBlock) {
        let (a0, a1) = a.split::<U16>();
        (AesBlock::from_bytes(&a0.0), AesBlock::from_bytes(&a1.0))
    }

    fn split_block256(a: Array<u8, Self::Aegis256BlockSize>) -> Self::AesBlock {
        AesBlock::from_bytes(&a.0)
    }
}

impl AegisParallel for U2 {
    type Aegis128BlockSize = U64;
    type Aegis256BlockSize = U32;

    type AesBlock = AesBlock2;

    fn split_block128(a: Array<u8, Self::Aegis128BlockSize>) -> (Self::AesBlock, Self::AesBlock) {
        let (a0, a123) = a.split::<U16>();
        let (a1, a23) = a123.split::<U16>();
        let (a2, a3) = a23.split::<U16>();

        (
            AesBlock2::from(Array([
                AesBlock::from_bytes(&a0.0),
                AesBlock::from_bytes(&a1.0),
            ])),
            AesBlock2::from(Array([
                AesBlock::from_bytes(&a2.0),
                AesBlock::from_bytes(&a3.0),
            ])),
        )
    }

    fn split_block256(a: Array<u8, Self::Aegis256BlockSize>) -> Self::AesBlock {
        let (a0, a1) = a.split::<U16>();
        AesBlock2::from(Array([
            AesBlock::from_bytes(&a0.0),
            AesBlock::from_bytes(&a1.0),
        ]))
    }
}

impl AegisParallel for U4 {
    type Aegis128BlockSize = U128;
    type Aegis256BlockSize = U64;

    type AesBlock = AesBlock4;

    fn split_block128(a: Array<u8, Self::Aegis128BlockSize>) -> (Self::AesBlock, Self::AesBlock) {
        let (a03, a47) = a.split::<U64>();
        let (a01, a23) = a03.split::<U32>();
        let (a45, a67) = a47.split::<U32>();
        let (a0, a1) = a01.split::<U16>();
        let (a2, a3) = a23.split::<U16>();
        let (a4, a5) = a45.split::<U16>();
        let (a6, a7) = a67.split::<U16>();

        (
            AesBlock4::from(Array([
                AesBlock::from_bytes(&a0.0),
                AesBlock::from_bytes(&a1.0),
                AesBlock::from_bytes(&a2.0),
                AesBlock::from_bytes(&a3.0),
            ])),
            AesBlock4::from(Array([
                AesBlock::from_bytes(&a4.0),
                AesBlock::from_bytes(&a5.0),
                AesBlock::from_bytes(&a6.0),
                AesBlock::from_bytes(&a7.0),
            ])),
        )
    }

    fn split_block256(a: Array<u8, Self::Aegis256BlockSize>) -> Self::AesBlock {
        let (a0, a123) = a.split::<U16>();
        let (a1, a23) = a123.split::<U16>();
        let (a2, a3) = a23.split::<U16>();

        AesBlock4::from(Array([
            AesBlock::from_bytes(&a0.0),
            AesBlock::from_bytes(&a1.0),
            AesBlock::from_bytes(&a2.0),
            AesBlock::from_bytes(&a3.0),
        ]))
    }
}

#[derive(Clone, Copy)]
pub struct AesBlock(uint8x16_t);

#[derive(Clone, Copy)]
pub struct AesBlock2(uint8x16x2_t);

#[derive(Clone, Copy)]
pub struct AesBlock4(uint8x16x4_t);

impl Default for AesBlock {
    fn default() -> Self {
        Self(unsafe { vmovq_n_u8(0) })
    }
}

impl AesBlock {
    pub fn from_bytes(b: &[u8; 16]) -> Self {
        // Safety: b has 16 bytes available. It does not need any special alignment.
        Self(unsafe { vld1q_u8(b.as_ptr()) })
    }

    fn into_bytes(self) -> [u8; 16] {
        let mut out = [0; 16];
        unsafe { vst1q_u8(out.as_mut_ptr(), self.0) }
        out
    }
}

impl Index<usize> for AesBlock {
    type Output = AesBlock;

    fn index(&self, index: usize) -> &Self::Output {
        match index {
            0 => self,
            _ => unreachable!(),
        }
    }
}

impl IndexMut<usize> for AesBlock {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        match index {
            0 => self,
            _ => unreachable!(),
        }
    }
}

impl From<Array<AesBlock, U1>> for AesBlock {
    fn from(value: Array<AesBlock, U1>) -> Self {
        let Array([AesBlock(a)]) = value;
        AesBlock(a)
    }
}

impl IAesBlock for AesBlock {
    type Size = U16;

    fn aes(self, key: Self) -> Self {
        Self(unsafe { vaesmcq_u8(vaeseq_u8(self.0, vmovq_n_u8(0))) }) ^ key
    }

    fn fold_xor(self) -> AesBlock {
        self
    }

    fn into_array(self) -> Array<u8, U16> {
        Array(self.into_bytes())
    }
}

impl BitXor for AesBlock {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(unsafe { veorq_u8(self.0, rhs.0) })
    }
}

impl BitXorAssign for AesBlock {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl BitAnd for AesBlock {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(unsafe { vandq_u8(self.0, rhs.0) })
    }
}

impl Default for AesBlock2 {
    fn default() -> Self {
        Self::from(Array([AesBlock::default(), AesBlock::default()]))
    }
}

impl Index<usize> for AesBlock2 {
    type Output = AesBlock;

    fn index(&self, index: usize) -> &Self::Output {
        match index {
            // same repr.
            0 => unsafe { std::mem::transmute(&self.0.0) },
            1 => unsafe { std::mem::transmute(&self.0.1) },
            _ => unreachable!(),
        }
    }
}

impl IndexMut<usize> for AesBlock2 {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        match index {
            // same repr.
            0 => unsafe { std::mem::transmute(&mut self.0.0) },
            1 => unsafe { std::mem::transmute(&mut self.0.1) },
            _ => unreachable!(),
        }
    }
}

impl From<AesBlock> for AesBlock2 {
    fn from(value: AesBlock) -> Self {
        let AesBlock(a) = value;
        Self(uint8x16x2_t(a, a))
    }
}

impl From<Array<AesBlock, U2>> for AesBlock2 {
    fn from(value: Array<AesBlock, U2>) -> Self {
        let Array([AesBlock(a), AesBlock(b)]) = value;
        Self(uint8x16x2_t(a, b))
    }
}

impl IAesBlock for AesBlock2 {
    type Size = U32;

    fn aes(self, key: Self) -> Self {
        let Self(uint8x16x2_t(m0, m1)) = self;

        Self(unsafe {
            uint8x16x2_t(
                vaesmcq_u8(vaeseq_u8(m0, vmovq_n_u8(0))),
                vaesmcq_u8(vaeseq_u8(m1, vmovq_n_u8(0))),
            )
        }) ^ key
    }

    fn fold_xor(self) -> AesBlock {
        self[0] ^ self[1]
    }

    fn into_array(self) -> Array<u8, U32> {
        self[0].into_array().concat(self[1].into_array())
    }
}

impl BitXor for AesBlock2 {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        let Self(uint8x16x2_t(l0, l1)) = self;
        let Self(uint8x16x2_t(r0, r1)) = rhs;
        Self(unsafe { uint8x16x2_t(veorq_u8(l0, r0), veorq_u8(l1, r1)) })
    }
}

impl BitXorAssign for AesBlock2 {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl BitAnd for AesBlock2 {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        let Self(uint8x16x2_t(l0, l1)) = self;
        let Self(uint8x16x2_t(r0, r1)) = rhs;
        Self(unsafe { uint8x16x2_t(vandq_u8(l0, r0), vandq_u8(l1, r1)) })
    }
}

impl Default for AesBlock4 {
    fn default() -> Self {
        Self::from(Array([
            AesBlock::default(),
            AesBlock::default(),
            AesBlock::default(),
            AesBlock::default(),
        ]))
    }
}

impl Index<usize> for AesBlock4 {
    type Output = AesBlock;

    fn index(&self, index: usize) -> &Self::Output {
        match index {
            // same repr.
            0 => unsafe { std::mem::transmute(&self.0.0) },
            1 => unsafe { std::mem::transmute(&self.0.1) },
            2 => unsafe { std::mem::transmute(&self.0.2) },
            3 => unsafe { std::mem::transmute(&self.0.3) },
            _ => unreachable!(),
        }
    }
}

impl IndexMut<usize> for AesBlock4 {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        match index {
            // same repr.
            0 => unsafe { std::mem::transmute(&mut self.0.0) },
            1 => unsafe { std::mem::transmute(&mut self.0.1) },
            2 => unsafe { std::mem::transmute(&mut self.0.2) },
            3 => unsafe { std::mem::transmute(&mut self.0.3) },
            _ => unreachable!(),
        }
    }
}

impl From<AesBlock> for AesBlock4 {
    fn from(value: AesBlock) -> Self {
        let AesBlock(a) = value;
        Self(uint8x16x4_t(a, a, a, a))
    }
}

impl From<Array<AesBlock, U4>> for AesBlock4 {
    fn from(value: Array<AesBlock, U4>) -> Self {
        let Array([AesBlock(a), AesBlock(b), AesBlock(c), AesBlock(d)]) = value;
        Self(uint8x16x4_t(a, b, c, d))
    }
}

impl IAesBlock for AesBlock4 {
    type Size = U64;

    fn aes(self, key: Self) -> Self {
        let Self(uint8x16x4_t(m0, m1, m2, m3)) = self;

        Self(unsafe {
            uint8x16x4_t(
                vaesmcq_u8(vaeseq_u8(m0, vmovq_n_u8(0))),
                vaesmcq_u8(vaeseq_u8(m1, vmovq_n_u8(0))),
                vaesmcq_u8(vaeseq_u8(m2, vmovq_n_u8(0))),
                vaesmcq_u8(vaeseq_u8(m3, vmovq_n_u8(0))),
            )
        }) ^ key
    }

    fn fold_xor(self) -> AesBlock {
        self[0] ^ self[1] ^ self[2] ^ self[3]
    }

    fn into_array(self) -> Array<u8, U64> {
        self[0]
            .into_array()
            .concat(self[1].into_array())
            .concat(self[2].into_array().concat(self[3].into_array()))
    }
}

impl BitXor for AesBlock4 {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        let Self(uint8x16x4_t(l0, l1, l2, l3)) = self;
        let Self(uint8x16x4_t(r0, r1, r2, r3)) = rhs;
        Self(unsafe {
            uint8x16x4_t(
                veorq_u8(l0, r0),
                veorq_u8(l1, r1),
                veorq_u8(l2, r2),
                veorq_u8(l3, r3),
            )
        })
    }
}

impl BitXorAssign for AesBlock4 {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl BitAnd for AesBlock4 {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        let Self(uint8x16x4_t(l0, l1, l2, l3)) = self;
        let Self(uint8x16x4_t(r0, r1, r2, r3)) = rhs;
        Self(unsafe {
            uint8x16x4_t(
                vandq_u8(l0, r0),
                vandq_u8(l1, r1),
                vandq_u8(l2, r2),
                vandq_u8(l3, r3),
            )
        })
    }
}
