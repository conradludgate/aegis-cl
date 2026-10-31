//! Statically selected block representations, independent of algorithm lanes.
use super::AesBlockArray;
use hybrid_array::{
    Array,
    sizes::{U1, U2, U4, U16, U32, U64, U128},
};

mod sealed {
    pub trait Sealed {}
}

/// A closed family of scalar, two-lane and four-lane AES block representations.
pub trait Backend: sealed::Sealed + Copy {
    type Scalar: AesBlockArray<Self::Scalar, Block = U16, Block2 = U32>
        + Into<[u8; 16]>
        + Into<Array<Self::Scalar, U1>>;
    type Pair: AesBlockArray<Self::Scalar, Block = U32, Block2 = U64>
        + Into<Array<Self::Scalar, U2>>;
    type Quad: AesBlockArray<Self::Scalar, Block = U64, Block2 = U128>
        + Into<Array<Self::Scalar, U4>>;
}

/// The original backend chosen by the build's target features.
#[derive(Clone, Copy)]
pub struct Static;
impl sealed::Sealed for Static {}
impl Backend for Static {
    type Scalar = super::AesBlock;
    type Pair = super::AesBlock2;
    type Quad = super::AesBlock4;
}
