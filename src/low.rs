use hybrid_array::{Array, ArraySize};
use std::ops::{Add, BitAnd, BitXor, Sub};

pub trait AegisParallel: hybrid_array::ArraySize {
    type Block2: hybrid_array::ArraySize + Sub<Self::Block, Output = Self::Block>;
    type Block: hybrid_array::ArraySize + Add<Self::Block, Output = Self::Block2>;

    #[doc(hidden)]
    type AesBlock: IAesBlock<Size = Self::Block>
        + From<Array<AesBlock, Self>>
        + Into<Array<AesBlock, Self>>;
}

pub trait IAesBlock:
    Copy + From<AesBlock> + BitXor<Output = Self> + BitAnd<Output = Self> + Into<Array<u8, Self::Size>>
{
    type Size: ArraySize;
    fn aes(self, key: Self) -> Self;
    fn reduce_xor(self) -> AesBlock;
    fn first(&self) -> AesBlock;

    fn from_block(a: &Array<u8, Self::Size>) -> Self;
}

cfg_if::cfg_if! {
    if #[cfg(all(target_arch = "aarch64", target_feature = "aes"))] {
        mod aarch64;
        pub use aarch64::AesBlock;
    } else if #[cfg(all(target_arch = "x86_64", target_feature = "aes"))] {
        mod x86_64;
        pub use x86_64::AesBlock;
    } else {
        mod generic;
        pub use generic::AesBlock;
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use hybrid_array::Array;
    use hybrid_array::sizes::U16;

    use crate::low::{AesBlock, IAesBlock};

    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.1>
    #[test]
    fn aes_round() {
        // in   : 000102030405060708090a0b0c0d0e0f
        // rk   : 101112131415161718191a1b1c1d1e1f
        // out  : 7a7b4e5638782546a8c0477a3b813f43

        let in_ = AesBlock::from_block(&Array(hex!("000102030405060708090a0b0c0d0e0f")));
        let rk = AesBlock::from_block(&Array(hex!("101112131415161718191a1b1c1d1e1f")));
        let out = Array(hex!("7a7b4e5638782546a8c0477a3b813f43"));

        let res: Array<u8, U16> = in_.aes(rk).into();
        assert_eq!(res, out);
    }
}
