use aead::inout::InOut;
use cipher::crypto_common::BlockSizes;
use hybrid_array::{Array, ArraySize};

use crate::low::{AesBlock, AesBlock2, AesBlock4, IAesBlock};

pub mod aegis128;
pub mod aegis256;
mod util;

mod sealed {
    pub trait Sealed {}
}

pub trait AegisParallel: sealed::Sealed {
    type Blocks: ArraySize;

    #[doc(hidden)]
    type AesBlock: IAesBlock + Into<Array<AesBlock, Self::Blocks>>;

    #[doc(hidden)]
    fn ctx() -> Self::AesBlock;
}

impl sealed::Sealed for crate::X1 {}
impl AegisParallel for crate::X1 {
    type Blocks = hybrid_array::sizes::U1;
    type AesBlock = AesBlock;

    fn ctx() -> Self::AesBlock {
        AesBlock::from_block(&Array([0; 16]))
    }
}

impl sealed::Sealed for crate::X2 {}
impl AegisParallel for crate::X2 {
    type Blocks = hybrid_array::sizes::U2;
    type AesBlock = AesBlock2;

    fn ctx() -> Self::AesBlock {
        let mut a = Array([0; 32]);
        a[16] = 1;
        a[1] = 1;
        a[17] = 1;

        AesBlock2::from_block(&a)
    }
}

impl sealed::Sealed for crate::X4 {}
impl AegisParallel for crate::X4 {
    type Blocks = hybrid_array::sizes::U4;
    type AesBlock = AesBlock4;

    fn ctx() -> Self::AesBlock {
        let mut a = Array([0; 64]);
        a[16] = 1;
        a[32] = 2;
        a[48] = 3;
        a[1] = 3;
        a[17] = 3;
        a[33] = 3;
        a[49] = 3;

        AesBlock4::from_block(&a)
    }
}

pub trait AegisCore {
    type Key: ArraySize;
    type Block: BlockSizes;

    fn new(key: &Array<u8, Self::Key>, iv: &Array<u8, Self::Key>) -> Self;

    fn encrypt_emtpy_block(&mut self, block: &mut Array<u8, Self::Block>);

    fn encrypt_block(&mut self, block: InOut<'_, '_, Array<u8, Self::Block>>);
    fn decrypt_block(&mut self, block: InOut<'_, '_, Array<u8, Self::Block>>);

    fn decrypt_partial_block(
        &mut self,
        padded_block: InOut<'_, '_, Array<u8, Self::Block>>,
        len: usize,
    );

    fn finalize128(self, ad_len_bits: u64, msg_len_bits: u64) -> [u8; 16];
    fn finalize_mac128(self, data_len_bits: u64) -> [u8; 16];
    fn finalize256(self, ad_len_bits: u64, msg_len_bits: u64) -> [u8; 32];
    fn finalize_mac256(self, data_len_bits: u64) -> [u8; 32];

    fn absorb(&mut self, ad: &Array<u8, Self::Block>);
}
