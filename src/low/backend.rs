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
    /// Default cores may select a faster backend for a complete AEAD operation.
    /// Concrete runtime backends keep their representation and never redispatch.
    #[doc(hidden)]
    const AUTO_DETECT: bool = false;
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
    const AUTO_DETECT: bool = true;
    type Scalar = super::AesBlock;
    type Pair = super::AesBlock2;
    type Quad = super::AesBlock4;
}

#[derive(Clone, Copy)]
pub(crate) struct Portable;
impl sealed::Sealed for Portable {}
impl Backend for Portable {
    type Scalar = super::generic::AesBlock;
    type Pair = super::generic::AesBlock2;
    type Quad = super::generic::AesBlock4;
}

#[cfg(target_arch = "x86_64")]
mod native {
    use super::*;
    use crate::low::x86_64 as x86;
    #[derive(Clone, Copy)]
    pub(crate) struct Aesni;
    #[derive(Clone, Copy)]
    pub(crate) struct Vaes256;
    #[derive(Clone, Copy)]
    pub(crate) struct Vaes512;
    impl sealed::Sealed for Aesni {}
    impl sealed::Sealed for Vaes256 {}
    impl sealed::Sealed for Vaes512 {}
    impl Backend for Aesni {
        type Scalar = x86::AesBlock;
        type Pair = x86::aesni::AesBlock2;
        type Quad = x86::aesni::AesBlock4;
    }
    impl Backend for Vaes256 {
        type Scalar = x86::AesBlock;
        type Pair = x86::avx2_x2::AesBlock2;
        type Quad = x86::vaes::AesBlock4;
    }
    impl Backend for Vaes512 {
        type Scalar = x86::AesBlock;
        type Pair = x86::avx2_x2::AesBlock2;
        type Quad = x86::avx512_x4::AesBlock4;
    }
}
#[cfg(target_arch = "x86_64")]
pub(crate) use native::{Aesni, Vaes256, Vaes512};
