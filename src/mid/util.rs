use hybrid_array::Array;

use crate::low::AesBlockArray;
use hybrid_array::sizes::U16;

#[inline(always)]
pub fn join_block<S: Into<[u8; 16]>>(a: S, b: S) -> [u8; 32] {
    let a: [u8; 16] = a.into();
    let b: [u8; 16] = b.into();
    let mut ab = [0; 32];
    ab[..16].copy_from_slice(&a);
    ab[16..].copy_from_slice(&b);
    ab
}

#[inline(always)]
pub fn split_blocks<D: AesBlockArray<S>, S>(a: &Array<u8, D::Block2>) -> (D, D) {
    let (a0, a1) = a.split_ref::<D::Block>();
    (D::from_block(a0), D::from_block(a1))
}

#[inline(always)]
pub fn concatu64<S: AesBlockArray<S, Block = U16>>(x: u64, y: u64) -> S {
    let mut u = Array([0; 16]);
    u[..8].copy_from_slice(&x.to_le_bytes());
    u[8..].copy_from_slice(&y.to_le_bytes());
    S::from_block(&u)
}
