use hybrid_array::Array;

use crate::{
    AegisParallel,
    low::{AesBlock, IAesBlock},
};

#[inline(always)]
pub fn join_blocks<D: AegisParallel>(a: D::AesBlock, b: D::AesBlock) -> Array<u8, D::Block2> {
    let a: Array<u8, D::Block> = a.into();
    let b: Array<u8, D::Block> = b.into();
    a.concat(b)
}

#[inline(always)]
pub fn split_blocks<D: AegisParallel>(a: &Array<u8, D::Block2>) -> (D::AesBlock, D::AesBlock) {
    let (a0, a1) = a.split_ref::<D::Block>();
    (
        <D::AesBlock as IAesBlock>::from_block(a0),
        <D::AesBlock as IAesBlock>::from_block(a1),
    )
}

pub fn ctx<D: AegisParallel>() -> D::AesBlock {
    Array::from_fn(|i| {
        let mut a = Array([0; 16]);
        a[0] = i as u8;
        a[1] = D::U8 - 1;
        AesBlock::from_block(&a)
    })
    .into()
}

#[inline(always)]
pub fn concatu64(x: u64, y: u64) -> AesBlock {
    let mut u = Array([0; 16]);
    u[..8].copy_from_slice(&x.to_le_bytes());
    u[8..].copy_from_slice(&y.to_le_bytes());
    AesBlock::from_block(&u)
}
