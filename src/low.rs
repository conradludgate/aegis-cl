use hybrid_array::{Array, ArraySize};
use std::ops::{Add, BitAnd, BitXor, BitXorAssign, Sub};

pub trait AegisParallel: hybrid_array::ArraySize {
    type Block2: hybrid_array::ArraySize + Sub<Self::Block, Output = Self::Block>;
    type Block: hybrid_array::ArraySize + Add<Self::Block, Output = Self::Block2>;

    #[doc(hidden)]
    #[inline(always)]
    fn split_blocks(a: &Array<u8, Self::Block2>) -> (Self::AesBlock, Self::AesBlock) {
        let (a0, a1) = a.split_ref::<Self::Block>();
        (Self::from_block(a0), Self::from_block(a1))
    }

    #[doc(hidden)]
    fn from_block(a: &Array<u8, Self::Block>) -> Self::AesBlock;

    #[doc(hidden)]
    type AesBlock: IAesBlock<Size = Self::Block>
        + From<Array<AesBlock, Self>>
        + Into<Array<AesBlock, Self>>;
}

pub trait IAesBlock:
    Default
    + Copy
    + From<AesBlock>
    + BitXor<Output = Self>
    + BitXorAssign
    + BitAnd<Output = Self>
    + Into<Array<u8, Self::Size>>
{
    type Size: ArraySize;
    fn aes(self, key: Self) -> Self;
    fn xor3(self, mid: Self, rhs: Self) -> Self;
    fn reduce_xor(self) -> AesBlock;
    fn first(&self) -> AesBlock;
}

cfg_if::cfg_if! {
    if #[cfg(all(target_arch = "aarch64", target_feature = "aes"))] {
        mod aarch64;
        pub use aarch64::AesBlock;
    } else if #[cfg(all(target_arch = "x86_64", target_feature = "aes"))] {
        mod x86_64;
        pub use x86_64::AesBlock;
    }
}
