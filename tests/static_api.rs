//! Downstream-style uses of the original low-level API remain valid.
use aegis_cl::{
    X1, X2, X4,
    hybrid_array::Array,
    low::AesBlock,
    mid::{AegisCore, AegisParallel, State128X, State256X},
};

fn generic<D: AegisParallel>() {
    let _: D::AesBlock = D::ctx();
    let state = State128X::<D>::new(&Array([0; 16]), &Array([1; 16]));
    let _: &D::AesBlock = &state[0];
    let state = State256X::<D>::new(&Array([0; 32]), &Array([1; 32]));
    let _: &D::AesBlock = &state[0];
}

#[test]
fn original_parallel_api() {
    let _: AesBlock = X1::ctx();
    generic::<X1>();
    generic::<X2>();
    generic::<X4>();
}
